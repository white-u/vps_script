// Real public Worker entry point; all database state and outbound requests stay in memory.
import assert from 'node:assert/strict';
import {createHmac, webcrypto} from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

globalThis.crypto ||= webcrypto;
const source = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
const {default: worker} = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));

// Implement only SQL used by these workflows. Unexpected queries fail the test.
// batch() models D1's atomic commit; this does not replace a real D1 integration test.
class MemoryD1 {
  nodes = new Map();
  users = new Map();
  updates = new Set();
  writes = [];
  reads = 0;
  failNextBatch = false;

  prepare(rawSql) {
    const sql = rawSql.replace(/\s+/g, ' ').trim();
    const db = this;
    return {
      sql, args: [],
      bind(...args) { this.args = args; return this; },
      async first() { return db.select(sql, this.args)[0] ?? null; },
      async all() { return {results: db.select(sql, this.args)}; },
      async run() { return db.write(sql, this.args); },
    };
  }

  select(sql, args) {
    this.reads++;
    if (sql.startsWith('SELECT 1 AS processed FROM telegram_updates ')) {
      return this.updates.has(args[0]) ? [{processed: 1}] : [];
    }
    if (sql.includes('FROM users u JOIN nodes n ON n.node_key = u.node_key')) {
      return [...this.users.values()]
        .filter(row => row.user_id === args[0] && (args.length === 1 || row.node_key === args[1]))
        .sort((a, b) => a.node_key.localeCompare(b.node_key))
        .flatMap(row => this.nodes.has(row.node_key)
          ? [{...this.nodes.get(row.node_key), allowed_ports: row.ports}] : []);
    }
    if (sql === 'SELECT ports, comment FROM users WHERE user_id = ?1 AND node_key = ?2') {
      const row = this.users.get(`${args[0]}:${args[1]}`);
      return row ? [{...row}] : [];
    }
    if (/^SELECT (\*|node_key, config_json) FROM nodes WHERE node_key = \?1$/.test(sql)) {
      const row = this.nodes.get(args[0]);
      return row ? [{...row}] : [];
    }
    if (sql === 'SELECT * FROM nodes ORDER BY node_key' ||
        sql === 'SELECT node_key, node_id, updated_at FROM nodes ORDER BY node_key') {
      return [...this.nodes.values()].sort((a, b) => a.node_key.localeCompare(b.node_key));
    }
    throw new Error(`Unexpected SQL read: ${sql}`);
  }

  write(sql, args) {
    if (sql.startsWith('INSERT INTO nodes ')) {
      const [node_key, node_id, config_json, updated_at] = args;
      this.nodes.set(node_key, {node_key, node_id, config_json, updated_at});
    } else if (sql.startsWith('INSERT INTO users ')) {
      const [user_id, node_key, ports, comment] = args;
      this.users.set(`${user_id}:${node_key}`, {user_id, node_key, ports, comment});
    } else if (sql.startsWith('INSERT INTO telegram_updates ')) {
      assert(!this.updates.has(args[0]), 'Duplicate update_id');
      this.updates.add(args[0]);
    } else {
      throw new Error(`Unexpected SQL write: ${sql}`);
    }
    this.writes.push({sql, args: [...args]});
    return {success: true, meta: {changes: 1}};
  }

  async batch(statements) {
    if (this.failNextBatch) {
      this.failNextBatch = false;
      throw new Error('Injected D1 transaction failure');
    }
    const previous = {nodes: new Map(this.nodes), users: new Map(this.users),
                      updates: new Set(this.updates), writes: this.writes.length};
    try {
      return statements.map(statement => this.write(statement.sql, statement.args));
    } catch (error) {
      Object.assign(this, {nodes: previous.nodes, users: previous.users, updates: previous.updates});
      this.writes.length = previous.writes;
      throw error;
    }
  }
}

async function fixture(run) {
  const nativeFetch = globalThis.fetch;
  const outbound = [];
  const env = {DB: new MemoryD1(), SHARED_SECRET: 'test-signing-secret',
               TELEGRAM_WEBHOOK_SECRET: 'test-webhook-secret', BOT_TOKEN: 'test-bot', ADMIN_ID: '1'};
  globalThis.fetch = async (url, options) => {
    const target = new URL(url);
    assert.equal(target.origin, 'https://api.telegram.org', 'No real network requests are allowed');
    assert.match(target.pathname, /^\/bottest-bot\/(sendMessage|editMessageText|answerCallbackQuery)$/);
    outbound.push({method: target.pathname.split('/').at(-1), ...JSON.parse(options.body)});
    return new Response('{"ok":true}', {headers: {'Content-Type': 'application/json'}});
  };
  try { await run({env, db: env.DB, outbound}); }
  finally { globalThis.fetch = nativeFetch; }
}

function push(env, nodeKey, payload, overrides = {}) {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const headers = {'X-Node': nodeKey, 'X-Timestamp': timestamp,
                   'X-Signature': createHmac('sha256', env.SHARED_SECRET || 'unused')
                     .update(`${nodeKey}\n${timestamp}\n${body}`).digest('hex'), ...overrides};
  return worker.fetch(new Request('https://worker.test/api/push', {method: 'PUT', headers, body}), env);
}

function webhook(env, payload, secret = env.TELEGRAM_WEBHOOK_SECRET) {
  return worker.fetch(new Request('https://worker.test/webhook', {
    method: 'POST', headers: {'X-Telegram-Bot-Api-Secret-Token': secret},
    body: typeof payload === 'string' ? payload : JSON.stringify(payload),
  }), env);
}

function message(text, userId = 101, updateId = 10) {
  return {update_id: updateId, message: {text, from: {id: userId}, chat: {id: -700}}};
}

function payload(name, visibleComment, hiddenComment = 'HIDDEN-PORT') {
  return {node_id: name, ports: {
    443: {quota_gb: 100, quota_mode: 'in_out', comment: visibleComment,
          stats: {acc_in: 1024, acc_out: 2048}, online: {ip_count: 0}},
    8443: {quota_gb: 100, quota_mode: 'in_out', comment: hiddenComment,
           stats: {acc_in: 4096, acc_out: 8192}, online: {ip_count: 0}},
  }};
}

async function seed({env, db}) {
  assert.equal((await push(env, 'alpha', payload('Alpha Node', 'ALICE-VISIBLE'))).status, 200);
  assert.equal((await push(env, 'beta', payload('Beta Node', 'BOB-PRIVATE'))).status, 200);
  db.users.set('101:alpha', {user_id: '101', node_key: 'alpha', ports: '[443]', comment: 'Alice'});
  db.users.set('202:beta', {user_id: '202', node_key: 'beta', ports: '[443]', comment: 'Bob'});
}

test('signed VPS push creates and replaces one node without touching grants', () => fixture(async ({env, db, outbound}) => {
  const initial = payload('First Name', 'first');
  assert.equal((await push(env, 'alpha', initial)).status, 200);
  assert.deepEqual(JSON.parse(db.nodes.get('alpha').config_json), initial);
  db.users.set('101:alpha', {user_id: '101', node_key: 'alpha', ports: '[443]'});
  const replacement = payload('Renamed Node', 'new usage');
  assert.equal((await push(env, 'alpha', replacement)).status, 200);
  assert.equal(db.nodes.size, 1);
  assert.equal(db.nodes.get('alpha').node_id, 'Renamed Node');
  assert.deepEqual(JSON.parse(db.nodes.get('alpha').config_json), replacement);
  assert.equal(db.users.get('101:alpha').ports, '[443]');
  assert.equal(outbound.length, 0);
}));

test('invalid signature, replay window and tampered node headers never overwrite snapshots', () => fixture(async ({env, db}) => {
  await push(env, 'alpha', payload('Original', 'saved'));
  const before = JSON.stringify([...db.nodes]);
  const writes = db.writes.length;
  const candidates = [
    {'X-Signature': '0'.repeat(64)}, {'X-Signature': ''}, {'X-Node': ''},
    {'X-Timestamp': 'not-a-time'}, {'X-Timestamp': String(Math.floor(Date.now() / 1000) - 121)},
    {'X-Timestamp': String(Math.floor(Date.now() / 1000) + 600)}, {'X-Node': 'beta'},
  ];
  for (const headers of candidates) {
    const response = await push(env, 'alpha', payload('Malicious', 'bad'), headers);
    assert([400, 403].includes(response.status), JSON.stringify(headers));
  }
  assert.equal(JSON.stringify([...db.nodes]), before);
  assert.equal(db.writes.length, writes);
}));

test('authenticated push still rejects invalid JSON, node key and payload shape', () => fixture(async ({env, db}) => {
  for (const body of ['{broken', 'null', '[]', '{}', '{"ports":[]}', '{"ports":null}']) {
    assert.equal((await push(env, 'alpha', body)).status, 400, body);
  }
  for (const key of ['Bad-Key', '../alpha', 'a'.repeat(65)]) {
    assert.equal((await push(env, key, {ports: {}})).status, 400, key);
  }
  assert.equal(db.writes.length, 0);
  const missingSecret = {...env, SHARED_SECRET: ''};
  assert.equal((await push(missingSecret, 'alpha', {ports: {}})).status, 500);
}));

test('untrusted webhook cannot read the database, send messages or grant access', () => fixture(async ({env, db, outbound}) => {
  for (const secret of ['', 'wrong-secret']) {
    assert.equal((await webhook(env, message('/add 101 alpha 443', 1), secret)).status, 403);
    assert.equal((await webhook(env, message('/ll', 101), secret)).status, 403);
  }
  assert.equal((await webhook({...env, TELEGRAM_WEBHOOK_SECRET: ''}, message('/ll'), 'any')).status, 500);
  assert.equal(db.reads, 0);
  assert.equal(db.writes.length, 0);
  assert.equal(outbound.length, 0);
}));

test('query menu and reports use sender grants within a shared Telegram chat', () => fixture(async (f) => {
  const {env, outbound} = f;
  await seed(f);
  assert.equal((await webhook(env, message('/ll@ExampleBot', 101))).status, 200);
  const menu = JSON.stringify(outbound.at(-1));
  assert.match(menu, /Alpha Node/);
  assert.doesNotMatch(menu, /Beta Node|BOB-PRIVATE/);
  assert.equal((await webhook(env, message('/ll all', 101))).status, 200);
  const report = outbound.at(-1).text;
  assert.match(report, /ALICE-VISIBLE/);
  assert.doesNotMatch(report, /HIDDEN-PORT|BOB-PRIVATE|Beta Node/);
  assert.equal(outbound.at(-1).chat_id, -700);
  assert.equal((await webhook(env, message('/ll all', 202))).status, 200);
  assert.match(outbound.at(-1).text, /BOB-PRIVATE/);
  assert.doesNotMatch(outbound.at(-1).text, /ALICE-VISIBLE|Alpha Node/);
  await webhook(env, message('/ll', 303));
  assert.match(outbound.at(-1).text, /暂无授权节点/);
  await webhook(env, message('/ll all', 1));
  assert.match(outbound.at(-1).text, /ALICE-VISIBLE/);
  assert.match(outbound.at(-1).text, /BOB-PRIVATE/);
  assert.match(outbound.at(-1).text, /HIDDEN-PORT/);
}));

test('typed foreign node and forged report buttons recheck the clicking user permissions', () => fixture(async (f) => {
  const {env, outbound} = f;
  await seed(f);
  await webhook(env, message('/ll beta', 101));
  assert.match(outbound.at(-1).text, /没有访问权限/);
  assert.doesNotMatch(outbound.at(-1).text, /Beta Node|BOB-PRIVATE/);
  for (const data of ['alpha', '!r:0:alpha']) {
    const response = await webhook(env, {callback_query: {id: 'click', data, from: {id: 202},
      message: {message_id: 55, chat: {id: -700}, from: {id: 101}}}});
    assert.equal(response.status, 200);
    assert.equal(outbound.at(-2).method, 'answerCallbackQuery');
    assert.equal(outbound.at(-1).method, 'editMessageText');
    assert.match(outbound.at(-1).text, /没有访问权限/);
    assert.doesNotMatch(outbound.at(-1).text, /ALICE-VISIBLE|Alpha Node/);
  }
}));

test('ordinary users cannot issue admin writes and missing update IDs reject before commit', () => fixture(async (f) => {
  const {env, db, outbound} = f;
  await seed(f);
  const before = db.writes.length;
  for (const text of ['/add 303 alpha 443', '/del 101 alpha --yes', '/delnode alpha']) {
    assert.equal((await webhook(env, message(text, 101))).status, 200);
  }
  assert.equal(outbound.length, 0);
  for (const updateId of [undefined, -1, '10', 1.5]) {
    const update = message('/add 303 alpha 443', 1, updateId);
    if (updateId === undefined) delete update.update_id;
    assert.equal((await webhook(env, update)).status, 400);
  }
  assert.equal(db.writes.length, before);
  assert.equal(db.updates.size, 0);
}));

test('admin grant rejects any unknown port and duplicate events do not rewrite permissions', () => fixture(async (f) => {
  const {env, db, outbound} = f;
  await seed(f);
  assert.equal((await webhook(env, message('/add 303 alpha 443,9999', 1, 100))).status, 200);
  assert.match(outbound.at(-1).text, /端口未被监控/);
  assert(!db.users.has('303:alpha'));
  assert(!db.updates.has(100), 'Validation failure must allow a corrected command to be retried');
  assert.equal((await webhook(env, message('/add 303 alpha 443,443 New User', 1, 100))).status, 200);
  assert.equal(db.users.get('303:alpha').ports, '[443]');
  assert.equal(db.users.get('303:alpha').comment, 'New User');
  assert(db.updates.has(100));
  const calls = outbound.length;
  const writes = db.writes.length;
  await webhook(env, message('/add 303 alpha 8443 Changed', 1, 100));
  assert.equal(db.users.get('303:alpha').ports, '[443]');
  assert.equal(outbound.length, calls, 'A duplicate update sends no second grant receipt');
  assert.equal(db.writes.length, writes);
  await webhook(env, message('/ll all', 303));
  assert.match(outbound.at(-1).text, /ALICE-VISIBLE/);
  assert.doesNotMatch(outbound.at(-1).text, /HIDDEN-PORT|BOB-PRIVATE/);
}));

test('database commit failure returns a diagnostic error and permits retrying the same update', () => fixture(async (f) => {
  const {env, db, outbound} = f;
  await seed(f);
  db.failNextBatch = true;
  const nativeError = console.error;
  const errors = [];
  console.error = (...args) => errors.push(args.join(' '));
  let response;
  try { response = await webhook(env, message('/add 303 alpha 443', 1, 200)); }
  finally { console.error = nativeError; }
  assert.equal(response.status, 500);
  assert(response.headers.get('X-Request-ID'));
  assert.match(await response.text(), /Request ID:/);
  assert(errors.some(line => line.includes('Injected D1 transaction failure')));
  assert(!db.users.has('303:alpha'));
  assert(!db.updates.has(200));
  assert.equal(outbound.length, 0);
  assert.equal((await webhook(env, message('/add 303 alpha 443', 1, 200))).status, 200);
  assert.equal(db.users.get('303:alpha').ports, '[443]');
  assert(db.updates.has(200));
  assert.equal(outbound.length, 1);
}));
