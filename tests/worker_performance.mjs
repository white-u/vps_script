// No Cloudflare/Telegram calls. Real Worker functions with deterministic clocks/fetch fixtures.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'worker-performance-'));
try {
  const source = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
  const moduleFile = path.join(directory, 'worker.mjs');
  fs.writeFileSync(moduleFile, source + `
export { lookupIpGeos, fetchTelegramApi, handleCallbackQuery, generateReports, paginateReportSections };
export function resetGeo() { geoCache.clear(); geoRateLimitedUntil = 0; }
`);
  const worker = await import(pathToFileURL(moduleFile));
  const nativeNow = Date.now;
  const nativeTimeout = AbortSignal.timeout;
  const nativeFetch = globalThis.fetch;
  try {
    let now = nativeNow();
    Date.now = () => now;
    let calls = 0;
    const ips = Array.from({length: 210}, (_, i) => `11.1.${Math.floor(i/250)}.${i%250+1}`);
    globalThis.fetch = async () => { calls++; return new Response('', {status:503}); };
    assert.deepEqual(await worker.lookupIpGeos(ips), {});
    assert.deepEqual(await worker.lookupIpGeos(ips), {});
    assert.equal(calls, 1, 'An outage must stop subsequent batches and back off repeated queries');
    now += 30_001;
    await worker.lookupIpGeos(ips);
    assert.equal(calls, 2, 'Queries resume after short service backoff');

    worker.resetGeo(); calls = 0;
    const budgets=[];
    AbortSignal.timeout = ms => { budgets.push(ms); return new AbortController().signal; };
    globalThis.fetch = async (url, options) => {
      calls++;
      now += 1400;
      const batch = JSON.parse(options.body);
      return new Response(JSON.stringify(batch.map(query => ({status:'success',query,country:'Test'}))));
    };
    const partial = await worker.lookupIpGeos(ips);
    assert.equal(calls, 2);
    assert.deepEqual(budgets, [2500,1100], 'Each batch must share the same overall deadline');
    assert.equal(Object.keys(partial).length, 200);
    globalThis.fetch = async () => { throw new Error('Cached result should avoid requests'); };
    assert.equal(Object.keys(await worker.lookupIpGeos(ips.slice(0,100))).length,100);

    // Cached and uncached reports keep the same functional content/permissions/pagination.
    worker.resetGeo();
    globalThis.fetch = async (url, options) => new Response(JSON.stringify(
      JSON.parse(options.body).map(query => ({status:'success',query,country:'Test'}))));
    const input = [{nodeKey:'n',nodeId:'Node',updatedAt:Math.floor(now/1000),allowedPorts:[443],
      configJson:JSON.stringify({ports:{443:{quota_gb:100,quota_mode:'in_out',stats:{acc_out:1024},
        online:{ip_count:1,ips:['11.1.1.1']}},8443:{quota_gb:100,comment:'PRIVATE PORT'}}})}];
    const first = await worker.generateReports(input);
    const cached = await worker.generateReports(input);
    assert.deepEqual(first,cached);
    assert.deepEqual(worker.paginateReportSections(first,3500),worker.paginateReportSections(cached,3500));
    assert(!JSON.stringify(first).includes('PRIVATE PORT'));

    const timeouts=[];
    AbortSignal.timeout = ms => {
      timeouts.push(ms);
      const controller=new AbortController();
      setTimeout(()=>controller.abort(new Error('Injected timeout')),5);
      return controller.signal;
    };
    globalThis.fetch = (url, options) => new Promise((resolve,reject)=>
      options.signal.addEventListener('abort',()=>reject(options.signal.reason),{once:true}));
    await assert.rejects(worker.fetchTelegramApi('test-token','sendMessage',{}),/Injected timeout/);
    assert.equal(timeouts.at(-1),8000);

    let reads=0;
    globalThis.fetch = async (url,options) => {
      if(url.includes('answerCallbackQuery')) return new Promise((resolve,reject)=>
        options.signal.addEventListener('abort',()=>reject(options.signal.reason),{once:true}));
      return new Response('{"ok":true}');
    };
    const env={BOT_TOKEN:'test-token',ADMIN_ID:'1',DB:{prepare(){return {async all(){reads++;return {results:[]};}};}}};
    const result=await worker.handleCallbackQuery(env,{id:'test',data:'!all',from:{id:1},message:{message_id:1,chat:{id:1}}});
    assert.equal(result.status,200);
    assert.equal(reads,1,'A callback confirmation timeout must allow the report query to proceed');
    assert(timeouts.includes(2500));

    // Existing short retry handling and message-not-modified behavior stay in the API caller.
    calls=0;
    globalThis.fetch=async()=>++calls===1
      ? new Response('{"parameters":{"retry_after":0}}',{status:429}) : new Response('{"ok":true}');
    await worker.fetchTelegramApi('test-token','sendMessage',{});
    assert.equal(calls,2);
  } finally {
    Date.now=nativeNow;
    AbortSignal.timeout=nativeTimeout;
    globalThis.fetch=nativeFetch;
  }
  console.log('PASS: geo deadline/backoff/cache, report permissions/pagination, callback/message timeouts and 429 retry');
} finally {
  fs.rmSync(directory,{recursive:true,force:true});
}
