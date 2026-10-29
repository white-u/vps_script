/**
 * ============================================================
 * Cloudflare Worker - 端口流量查询中控 v1.0.0
 * 
 * 绑定要求 (Worker Settings -> Bindings):
 *   - D1 Database: 变量名 DB
 *
 * 环境变量 (Worker Settings -> Variables):
 *   - SHARED_SECRET  : VPS 推送签名密钥
 *   - BOT_TOKEN      : Telegram Bot Token
 *   - ADMIN_ID       : 管理员 Telegram ID (字符串)
 *   - TELEGRAM_WEBHOOK_SECRET : Telegram Webhook secret_token
 *
 * D1 表: nodes 保存节点快照，users 保存查询权限，telegram_updates 保存管理员写操作去重记录。
 *
 * 首版职责: 接收签名推送、按权限查询、分页展示流量及固定突发限速状态。
 * 管理员写操作按 update_id 去重，删除用户权限需先预览并追加 --yes 确认。
 * 用户到期提醒由 PM 本机 Telegram 发送，Worker 仅展示到期状态。
 * 大批量授权回执与删除预览采用摘要；完整权限通过 /users 分页查看。
 * ============================================================
 */

const GEO_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const GEO_CACHE_MAX_ENTRIES = 500;
const GEO_LOOKUP_BUDGET_MS = 2500;
const GEO_FAILURE_BACKOFF_MS = 30_000;
const TELEGRAM_TIMEOUT_MS = 8000;
const TG_DIVIDER = "━━━━━━━━━━━━━━";
const geoCache = new Map();
let geoRateLimitedUntil = 0;

export default {
  async fetch(request, env) {
    const requestId = request.headers.get("CF-Ray") ||
      globalThis.crypto?.randomUUID?.() ||
      `req-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    try {
      const url = new URL(request.url);

      if (url.pathname === "/api/push" && request.method === "PUT") {
        return await handlePush(request, env);
      }

      if (request.method === "POST" && url.pathname === "/webhook") {
        return await handleTelegram(request, env);
      }

      return new Response("OK");
    } catch (error) {
      console.error(`[${requestId}] Unhandled worker error`, error?.stack || error);
      return new Response(`Internal Server Error\nRequest ID: ${requestId}`, {
        status: 500,
        headers: { "X-Request-ID": requestId }
      });
    }
  }
};

// ==============================================================
// 1. 接收并验证 VPS 签名推送
// ==============================================================
async function handlePush(request, env) {
  const secret = env.SHARED_SECRET;
  if (!secret) return new Response("Server not configured", { status: 500 });

  const nodeKey = request.headers.get("X-Node");
  const ts      = request.headers.get("X-Timestamp");
  const sig     = request.headers.get("X-Signature");
  const body    = await request.text();

  if (!nodeKey || !ts || !sig || !body) {
    return new Response("Bad Request", { status: 400 });
  }

  if (!/^\d+$/.test(ts)) {
    return new Response("Invalid timestamp", { status: 400 });
  }

  const timestamp = Number(ts);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(timestamp) || Math.abs(now - timestamp) > 120) {
    return new Response("Timestamp expired", { status: 403 });
  }

  const expected = await hmacSHA256(secret, `${nodeKey}\n${ts}\n${body}`);
  if (!secureEqual(sig, expected)) {
    return new Response("Forbidden", { status: 403 });
  }

  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(nodeKey)) {
    return new Response("Invalid node key", { status: 400 });
  }

  let parsed;
  try { parsed = JSON.parse(body); } catch {
    return new Response("Invalid JSON", { status: 400 });
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) ||
      !parsed.ports || typeof parsed.ports !== "object" || Array.isArray(parsed.ports)) {
    return new Response("Invalid payload", { status: 400 });
  }
  const nodeId = typeof parsed.node_id === "string" && parsed.node_id ? parsed.node_id : nodeKey;

  await env.DB.prepare(
    `INSERT INTO nodes (node_key, node_id, config_json, updated_at)
     VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT(node_key) DO UPDATE SET
       node_id = ?2, config_json = ?3, updated_at = ?4`
  ).bind(nodeKey, nodeId, body, now).run();

  return new Response("OK");
}

function parseIsoDateDay(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const [year, month, day] = value.split("-").map(Number);
  const timestamp = Date.UTC(year, month - 1, day);
  const parsed = new Date(timestamp);
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    return null;
  }
  return Math.floor(timestamp / 86400000);
}

// ==============================================================
// 2. Telegram 指令处理
// ==============================================================
async function handleTelegram(request, env) {
  const webhookSecret = env.TELEGRAM_WEBHOOK_SECRET;
  if (!webhookSecret) {
    return new Response("Webhook secret not configured", { status: 500 });
  }
  const providedSecret = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
  if (!secureEqual(providedSecret, webhookSecret)) {
    return new Response("Forbidden", { status: 403 });
  }

  let payload;
  try { payload = await request.json(); } catch { return new Response("OK"); }
  if (payload.callback_query) {
    return handleCallbackQuery(env, payload.callback_query);
  }
  if (!payload.message?.text) return new Response("OK");

  const chatId  = payload.message.chat.id;
  const userId  = String(payload.message.from.id);
  const text    = payload.message.text.trim();
  const isAdmin = (userId === env.ADMIN_ID);

  // 指令路由
  const cmd = text.split(/\s+/)[0].toLowerCase().replace(/@\w+$/, ""); // 去掉 @botname
  const args = text.split(/\s+/);
  const updateId = payload.update_id;
  const requiresUpdateId = isAdmin && (
    (cmd === "/add" && args.length >= 4) ||
    (cmd === "/del" && args.at(-1)?.toLowerCase() === "--yes") ||
    (cmd === "/delnode" && args.length >= 2)
  );
  if (requiresUpdateId && (!Number.isSafeInteger(updateId) || updateId < 0)) {
    console.error("拒绝处理缺少有效 update_id 的管理员写操作");
    return new Response("Invalid Telegram update", { status: 400 });
  }
  if (requiresUpdateId) {
    const processed = await env.DB.prepare(
      "SELECT 1 AS processed FROM telegram_updates WHERE update_id = ?1"
    ).bind(updateId).first();
    if (processed) return new Response("OK");
  }

  switch (cmd) {
    case "/ll":
      return handleQuery(env, chatId, userId, text, isAdmin);
    case "/add":
      return isAdmin ? handleAdd(env, chatId, text, null, requiresUpdateId ? updateId : null) : new Response("OK");
    case "/del":
      return isAdmin ? handleDel(env, chatId, text, null, requiresUpdateId ? updateId : null) : new Response("OK");
    case "/delnode":
      return isAdmin ? handleDelNode(env, chatId, text, requiresUpdateId ? updateId : null) : new Response("OK");
    case "/users":
      return isAdmin ? handleUsers(env, chatId) : new Response("OK");
    case "/id":
      return handleId(env, chatId, userId, isAdmin);
    case "/help":
    case "/start":
      return handleHelp(env, chatId, isAdmin);
    default:
      return new Response("OK");
  }
}

// 将去重标记与本次业务修改放在同一个 D1 batch 中。
// D1 batch 任一语句失败会整体回滚；重复 update_id 时只在确认标记已存在后按已处理返回。
async function commitTelegramUpdate(env, updateId, statements) {
  const batch = [
    env.DB.prepare(
      "INSERT INTO telegram_updates (update_id, processed_at) VALUES (?1, ?2)"
    ).bind(updateId, Math.floor(Date.now() / 1000)),
    ...statements
  ];
  try {
    return { committed: true, results: await env.DB.batch(batch) };
  } catch (error) {
    let seen;
    try {
      seen = await env.DB.prepare(
        "SELECT 1 AS processed FROM telegram_updates WHERE update_id = ?1"
      ).bind(updateId).first();
    } catch {
      throw error;
    }
    if (seen) return { committed: false, results: [] };
    throw error;
  }
}

// ==============================================================
// 3. /ll - 流量查询
// ==============================================================
async function handleQuery(env, chatId, userId, text, isAdmin) {
  const args = text.split(/\s+/);
  const target = args[1]?.toLowerCase();
  const requestedPage = /^\d+$/.test(args[2] || "") ? Number(args[2]) : 1;
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage - 1 : 0;

  if (!target) return showNodeMenu(env, chatId, userId, isAdmin);
  return showNodeReport(env, chatId, userId, isAdmin, target, null, page);
}

async function handleCallbackQuery(env, callbackQuery) {
  const chatId = callbackQuery.message?.chat?.id;
  const messageId = callbackQuery.message?.message_id;
  const userId = String(callbackQuery.from?.id || "");
  const isAdmin = userId === env.ADMIN_ID;
  const data = String(callbackQuery.data || "");
  await tgAnswerCallback(env, callbackQuery.id);
  if (!chatId || !messageId) return new Response("OK");

  if (data === "!list") {
    return showNodeMenu(env, chatId, userId, isAdmin, messageId);
  }
  if (data === "!all") {
    return showNodeReport(env, chatId, userId, isAdmin, "all", messageId);
  }
  if (data === "!help") {
    return handleHelp(env, chatId, isAdmin, messageId);
  }
  if (data === "!users") {
    return isAdmin
      ? handleUsers(env, chatId, messageId)
      : handleHelp(env, chatId, false, messageId);
  }
  const usersPageMatch = data.match(/^!users:(\d+)$/);
  if (usersPageMatch) {
    return isAdmin
      ? handleUsers(env, chatId, messageId, Number(usersPageMatch[1]))
      : handleHelp(env, chatId, false, messageId);
  }
  const reportPageMatch = data.match(/^!r:(\d+):([a-z0-9][a-z0-9_-]{0,63})$/);
  if (reportPageMatch) {
    const page = Number(reportPageMatch[1]);
    const target = reportPageMatch[2];
    if (Number.isSafeInteger(page)) return showNodeReport(env, chatId, userId, isAdmin, target, messageId, page);
  }
  if (data === "!addhelp") {
    return isAdmin
      ? handleAdd(env, chatId, "/add", messageId)
      : handleHelp(env, chatId, false, messageId);
  }
  if (data === "!delhelp") {
    return isAdmin
      ? handleDel(env, chatId, "/del", messageId)
      : handleHelp(env, chatId, false, messageId);
  }
  if (data === "!id") {
    return handleId(env, chatId, userId, isAdmin, messageId);
  }
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(data)) {
    return deliverTelegram(env, chatId, messageId,
      formatNotice("❌", "按钮已失效", ["请返回节点列表后重新选择。"]),
      backKeyboard());
  }
  return showNodeReport(env, chatId, userId, isAdmin, data, messageId);
}

async function showNodeMenu(env, chatId, userId, isAdmin, messageId = null) {
  const rows = isAdmin
    ? await env.DB.prepare("SELECT node_key, node_id, updated_at FROM nodes ORDER BY node_key").all()
    : await env.DB.prepare(
      `SELECT n.node_key, n.node_id, n.updated_at
       FROM users u
       JOIN nodes n ON n.node_key = u.node_key
       WHERE u.user_id = ?1
       ORDER BY u.node_key`
    ).bind(userId).all();

  const nodes = rows.results || [];
  if (!nodes.length) {
    const message = isAdmin
      ? formatNotice("📭", "暂无节点", ["当前还没有云端节点数据。"], "请确认 VPS 已开启 Cloudflare 推送。")
      : formatNotice("📭", "暂无授权节点", ["你当前没有可查询的节点。"]);
    return deliverTelegram(env, chatId, messageId, message, helpKeyboard(isAdmin));
  }

  const now = Math.floor(Date.now() / 1000);
  let onlineCount = 0;
  let offlineCount = 0;
  let message = `📊 *流量查询*\n${TG_DIVIDER}`;
  for (const node of nodes) {
    const age = now - node.updated_at;
    const isOnline = age < 180;
    if (isOnline) onlineCount++; else offlineCount++;
  }
  message += `\n🟢 在线 ${onlineCount}  ·  🔴 离线 ${offlineCount}`;
  message += `\n${TG_DIVIDER}\n请选择节点：`;

  return deliverTelegram(env, chatId, messageId, message, nodeMenuKeyboard(nodes, isAdmin));
}

async function showNodeReport(env, chatId, userId, isAdmin, target, messageId = null, pageIndex = 0) {
  let reportInputs = [];
  if (isAdmin) {
    if (target === "all") {
      const rows = await env.DB.prepare("SELECT * FROM nodes ORDER BY node_key").all();
      reportInputs = (rows.results || []).map(row => reportInputFromRow(row, "all"));
    } else {
      const row = await env.DB.prepare("SELECT * FROM nodes WHERE node_key = ?1").bind(target).first();
      if (row) reportInputs.push(reportInputFromRow(row, "all"));
    }
  } else {
    const baseSql = `SELECT u.ports AS allowed_ports, n.node_key, n.node_id, n.config_json, n.updated_at
                     FROM users u JOIN nodes n ON n.node_key = u.node_key
                     WHERE u.user_id = ?1`;
    if (target === "all") {
      const rows = await env.DB.prepare(`${baseSql} ORDER BY u.node_key`).bind(userId).all();
      reportInputs = (rows.results || []).map(row => reportInputFromRow(row, parseAllowedPorts(row.allowed_ports)));
    } else {
      const row = await env.DB.prepare(`${baseSql} AND u.node_key = ?2`).bind(userId, target).first();
      if (row) reportInputs.push(reportInputFromRow(row, parseAllowedPorts(row.allowed_ports)));
    }
  }

  if (!reportInputs.length) {
    return deliverTelegram(env, chatId, messageId,
      formatNotice("❌", "节点不可用", ["节点不存在，或你没有访问权限。"]),
      backKeyboard());
  }
  const reports = await generateReports(reportInputs);
  const pages = paginateReportSections(reports, 3500);
  const currentPage = Math.min(Math.max(0, pageIndex), pages.length - 1);
  let message = `${pages[currentPage]}\n\n${TG_DIVIDER}\n第 ${currentPage + 1} / ${pages.length} 页`;
  let commandPage = null;
  if (pages.length > 1 && target !== "all") {
    if (currentPage + 1 < pages.length && !reportPageCallback(target, currentPage + 1)) commandPage = currentPage + 1;
    else if (currentPage > 0 && !reportPageCallback(target, currentPage - 1)) commandPage = currentPage - 1;
  }
  if (commandPage !== null) {
    message += `\n长节点 Key 翻页：\`/ll ${target} ${commandPage + 1}\``;
  }
  return deliverTelegram(env, chatId, messageId, message, reportKeyboard(target, currentPage, pages.length));
}

function reportInputFromRow(row, allowedPorts) {
  return {
    nodeKey: row.node_key,
    nodeId: row.node_id,
    configJson: row.config_json,
    updatedAt: row.updated_at,
    allowedPorts
  };
}

function parseAllowedPorts(value) {
  try {
    const ports = JSON.parse(value);
    return Array.isArray(ports) ? ports : [];
  } catch {
    return [];
  }
}

function formatPortSummary(ports, maxShown = 12) {
  if (!ports.length) return "无";
  const shown = ports.slice(0, maxShown).join(", ");
  const suffix = ports.length > maxShown ? ", …" : "";
  return `共 ${ports.length} 个：\`${shown}${suffix}\``;
}

// ==============================================================
// 4. /add - 添加/更新用户权限 (仅管理员)
//    格式: /add <tg_id> <node> <port1,port2,...> [用户]
//    示例: /add 987654321 hk 8080,8081 小王
// ==============================================================
async function handleAdd(env, chatId, text, messageId = null, updateId = null) {
  const args = text.split(/\s+/);
  // args[0]=/add, [1]=tg_id, [2]=node, [3]=ports, [4...]=comment

  if (args.length < 4) {
    return deliverTelegram(env, chatId, messageId, formatNotice(
      "➕", "添加或更新权限",
      [
        "`/add TG-ID 节点Key 端口 [用户名称]`",
        "",
        "示例 `/add 987654321 hk 8080,8081 小王`",
        "",
        "`TG-ID`  用户发送 /id 获取",
        "`节点Key` 通过 /ll 查看",
        "`端口`    多个端口用英文逗号分隔",
        "`用户名称` 可省略；更新时省略会保留原名称"
      ],
      "重复添加会替换该用户在此节点的原端口列表。"
    ), helpKeyboard(true));
  }

  const targetId = args[1];
  const nodeKey  = args[2].toLowerCase();
  const portsStr = args[3];
  const requestedComment = args.slice(4).join(" ").trim();

  // 校验用户 ID
  if (!/^\d{1,20}$/.test(targetId)) {
    return deliverTelegram(env, chatId, messageId,
      formatNotice("❌", "TG-ID 无效", ["TG-ID 必须是 1–20 位数字。", "用户可发送 /id 获取。"]),
      helpKeyboard(true));
  }
  if (requestedComment.length > 64) {
    return deliverTelegram(env, chatId, messageId,
      formatNotice("❌", "用户名称过长", ["用户名称最多允许 64 个字符。"]),
      helpKeyboard(true));
  }
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(nodeKey)) {
    return deliverTelegram(env, chatId, messageId,
      formatNotice("❌", "节点 Key 无效", ["请通过 /ll 查看可用节点 Key。"]),
      helpKeyboard(true));
  }

  // 校验节点存在
  const node = await env.DB.prepare(
    "SELECT node_key, config_json FROM nodes WHERE node_key = ?1"
  ).bind(nodeKey).first();
  if (!node) {
    return deliverTelegram(env, chatId, messageId, formatNotice(
      "❌", "节点不存在", [`节点 \`${nodeKey}\` 尚未推送数据。`], "发送 /ll 查看可用节点。"
    ), helpKeyboard(true));
  }

  // 严格解析并去重，避免把部分错误输入静默丢弃后仍然授权。
  const rawPorts = portsStr.split(",").map(port => port.trim());
  const parsedPorts = rawPorts.map(port => /^\d+$/.test(port) ? Number(port) : NaN);
  if (parsedPorts.some(port => !Number.isSafeInteger(port) || port < 1 || port > 65535)) {
    return deliverTelegram(env, chatId, messageId, formatNotice(
      "❌", "端口格式错误",
      ["每个端口必须是 1–65535 的整数。", "多个端口请使用英文逗号分隔。"],
      "示例 `8080,8081,443`"
    ), helpKeyboard(true));
  }
  const ports = [...new Set(parsedPorts)].sort((a, b) => a - b);

  let nodeConfig;
  try {
    nodeConfig = JSON.parse(node.config_json);
  } catch {
    return deliverTelegram(env, chatId, messageId,
      formatNotice("❌", "节点数据异常", [`节点 \`${nodeKey}\` 的上报数据无法解析。`]),
      helpKeyboard(true));
  }
  const configuredPorts = Object.keys(
    nodeConfig?.ports && typeof nodeConfig.ports === "object" && !Array.isArray(nodeConfig.ports)
      ? nodeConfig.ports
      : {}
  ).filter(port => /^\d+$/.test(port)).map(Number)
    .filter(port => Number.isSafeInteger(port) && port >= 1 && port <= 65535)
    .sort((a, b) => a - b);
  const configuredPortSet = new Set(configuredPorts);
  const missingPorts = ports.filter(port => !configuredPortSet.has(port));
  if (missingPorts.length) {
    const shownPorts = configuredPorts.slice(0, 30).join(", ") || "无";
    const suffix = configuredPorts.length > 30 ? " …" : "";
    return deliverTelegram(env, chatId, messageId, formatNotice(
      "❌", "端口未被监控",
      [
        `无效端口  \`${missingPorts.join(", ")}\``,
        `可用端口  \`${shownPorts}${suffix}\``
      ],
      "请先在对应 VPS 的 PM 中添加端口，并等待下一次云端上报。"
    ), helpKeyboard(true));
  }

  const existing = await env.DB.prepare(
    "SELECT ports, comment FROM users WHERE user_id = ?1 AND node_key = ?2"
  ).bind(targetId, nodeKey).first();
  const comment = requestedComment || existing?.comment || "";
  const portsJson = JSON.stringify(ports);

  // 写入 D1 (UPSERT)
  const commit = await commitTelegramUpdate(env, updateId, [env.DB.prepare(
    `INSERT INTO users (user_id, node_key, ports, comment)
     VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT(user_id, node_key) DO UPDATE SET
       ports = ?3, comment = ?4`
  ).bind(targetId, nodeKey, portsJson, comment)]);
  if (!commit.committed) return new Response("OK");

  const lines = [
    `👤 TG-ID  \`${targetId}\``,
    `🖥 节点  \`${nodeKey}\``
  ];
  if (existing) {
    const oldPorts = parseAllowedPorts(existing.ports)
      .map(Number).filter(port => Number.isSafeInteger(port) && port >= 1 && port <= 65535)
      .sort((a, b) => a - b);
    lines.push(`↩️ 原端口  ${formatPortSummary(oldPorts)}`);
    lines.push(`🔌 新端口  ${formatPortSummary(ports)}`);
  } else {
    lines.push(`🔌 端口  ${formatPortSummary(ports)}`);
  }
  if (comment) lines.push(`🏷 用户  ${escMd(displayLabel(comment))}`);
  return deliverTelegram(env, chatId, messageId,
    formatNotice("✅", existing ? "权限已更新" : "权限已添加", lines,
      "端口较多时仅显示部分示例；完整授权列表请发送 /users。"),
    helpKeyboard(true));
}

// ==============================================================
// 5. /del - 删除用户权限 (仅管理员)
//    /del <tg_id> --yes        → 删除该用户全部权限
//    /del <tg_id> <node> --yes → 仅删除该用户对指定节点的权限
// ==============================================================
async function handleDel(env, chatId, text, messageId = null, updateId = null) {
  const args = text.split(/\s+/);

  if (args.length < 2) {
    return deliverTelegram(env, chatId, messageId, formatNotice(
      "➖", "删除用户权限",
      [
        "删除指定节点：",
        "`/del 987654321 hk`",
        "",
        "删除全部节点：",
        "`/del 987654321`"
      ],
      "命令会先显示删除范围，追加 --yes 后才会执行。"
    ), helpKeyboard(true));
  }

  const targetId = args[1];
  if (!/^\d{1,20}$/.test(targetId)) {
    return deliverTelegram(env, chatId, messageId,
      formatNotice("❌", "TG-ID 无效", ["TG-ID 必须是 1–20 位数字。"]),
      helpKeyboard(true));
  }

  const confirmed = args[args.length - 1]?.toLowerCase() === "--yes";
  if (confirmed) args.pop();
  if (args.length > 3) {
    return deliverTelegram(env, chatId, messageId,
      formatNotice("❌", "删除命令无效", ["请发送 /del 查看正确格式。"]),
      helpKeyboard(true));
  }

  const nodeKey = args[2]?.toLowerCase() || "";
  if (nodeKey && !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(nodeKey)) {
    return deliverTelegram(env, chatId, messageId,
      formatNotice("❌", "节点 Key 无效", ["请发送 /del 查看正确格式。"]),
      helpKeyboard(true));
  }

  if (!confirmed) {
    if (nodeKey) {
      const permission = await env.DB.prepare(
        "SELECT ports FROM users WHERE user_id = ?1 AND node_key = ?2"
      ).bind(targetId, nodeKey).first();
      if (!permission) {
        return deliverTelegram(env, chatId, messageId, formatNotice(
          "⚠️", "未找到权限", [`用户 \`${targetId}\` 没有节点 \`${nodeKey}\` 的权限。`]
        ), helpKeyboard(true));
      }
      const ports = parseAllowedPorts(permission.ports);
      return deliverTelegram(env, chatId, messageId, formatNotice(
        "⚠️", "确认删除权限",
        [
          `👤 TG-ID  \`${targetId}\``,
          `🖥 节点  \`${nodeKey}\``,
          `🔌 端口  ${formatPortSummary(ports)}`,
          "",
          `确认命令 \`/del ${targetId} ${nodeKey} --yes\``
        ],
        "当前尚未删除。端口较多时仅显示部分示例；发送 /users 查看完整授权列表。"
      ), helpKeyboard(true));
    }

    const permissions = await env.DB.prepare(
      "SELECT node_key FROM users WHERE user_id = ?1 ORDER BY node_key"
    ).bind(targetId).all();
    const rows = permissions.results || [];
    if (!rows.length) {
      return deliverTelegram(env, chatId, messageId,
        formatNotice("⚠️", "暂无权限", [`用户 \`${targetId}\` 没有权限记录。`]),
        helpKeyboard(true));
    }
    const nodeList = rows.slice(0, 12).map(row => row.node_key).join(", ");
    const nodeSuffix = rows.length > 12 ? " …" : "";
    return deliverTelegram(env, chatId, messageId, formatNotice(
      "⚠️", "确认清空权限",
      [
        `👤 TG-ID  \`${targetId}\``,
        `🖥 节点  ${rows.length} 个`,
        `📋 范围  \`${nodeList}${nodeSuffix}\``,
        "",
        `确认命令 \`/del ${targetId} --yes\``
      ],
      "当前尚未删除。"
    ), helpKeyboard(true));
  }

  if (nodeKey) {
    const commit = await commitTelegramUpdate(env, updateId, [env.DB.prepare(
      "DELETE FROM users WHERE user_id = ?1 AND node_key = ?2"
    ).bind(targetId, nodeKey)]);
    if (!commit.committed) return new Response("OK");
    const result = commit.results[1];

    if ((result.meta?.changes || 0) > 0) {
      return deliverTelegram(env, chatId, messageId, formatNotice(
        "✅", "权限已删除", [`👤 TG-ID  \`${targetId}\``, `🖥 节点  \`${nodeKey}\``]
      ), helpKeyboard(true));
    }
    return deliverTelegram(env, chatId, messageId, formatNotice(
      "⚠️", "未找到权限", [`用户 \`${targetId}\` 没有节点 \`${nodeKey}\` 的权限。`]
    ), helpKeyboard(true));
  }

  const commit = await commitTelegramUpdate(env, updateId, [env.DB.prepare(
    "DELETE FROM users WHERE user_id = ?1"
  ).bind(targetId)]);
  if (!commit.committed) return new Response("OK");
  const result = commit.results[1];
  const deletedCount = result.meta?.changes || 0;
  if (deletedCount > 0) {
    return deliverTelegram(env, chatId, messageId, formatNotice(
      "✅", "权限已清空", [`👤 TG-ID  \`${targetId}\``, `🗑 删除  ${deletedCount} 条权限`]
    ), helpKeyboard(true));
  }
  return deliverTelegram(env, chatId, messageId,
    formatNotice("⚠️", "暂无权限", [`用户 \`${targetId}\` 没有权限记录。`]),
    helpKeyboard(true));
}

// ==============================================================
// 5.5. /delnode - 删除云端节点数据 (仅管理员)
//    /delnode <node>          → 删除节点 + 关联的用户权限
//    /delnode <node> --keep   → 仅删除节点数据，保留用户权限
// ==============================================================
async function handleDelNode(env, chatId, text, updateId = null) {
  const args = text.split(/\s+/);

  if (args.length < 2) {
    return tgReply(env, chatId, formatNotice(
      "🧭", "删除节点",
      ["`/delnode hk`  删除节点和关联权限", "`/delnode hk --keep`  仅删除节点数据"]
    ));
  }

  const nodeKey = args[1].toLowerCase();
  const keepUsers = args[2]?.toLowerCase() === "--keep";

  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(nodeKey)) {
    return tgReply(env, chatId, formatNotice("❌", "节点 Key 无效", ["节点 Key 格式错误。"]));
  }

  // 读取名称用于回执；节点不存在时仍继续清理孤立权限。
  const node = await env.DB.prepare(
    "SELECT node_key, node_id FROM nodes WHERE node_key = ?1"
  ).bind(nodeKey).first();

  const statements = [];
  if (!keepUsers) {
    statements.push(env.DB.prepare(
      "DELETE FROM users WHERE node_key = ?1"
    ).bind(nodeKey));
  }
  statements.push(env.DB.prepare("DELETE FROM nodes WHERE node_key = ?1").bind(nodeKey));
  const commit = await commitTelegramUpdate(env, updateId, statements);
  if (!commit.committed) return new Response("OK");

  if (!node && keepUsers) {
    return tgReply(env, chatId, formatNotice("⚠️", "节点不存在", [`未找到节点 \`${nodeKey}\`。`, "权限记录已保留。"]));
  }
  const lines = [`🖥 节点  \`${nodeKey}\``];
  if (node) lines.push(`🏷 名称  ${escMd(displayLabel(node.node_id))}`);
  else lines.push("ℹ️ 节点记录已不存在");

  if (!keepUsers) {
    const userResult = commit.results[1];
    const userCount = userResult.meta?.changes || 0;
    if (userCount > 0) {
      lines.push(`🗑 权限  已清理 ${userCount} 条`);
    } else {
      lines.push("🗑 权限  无残留记录");
    }
  } else {
    lines.push("📌 权限  已保留");
  }

  return tgReply(env, chatId, formatNotice("✅", "节点已删除", lines));
}

// ==============================================================
// 6. /users - 列出所有用户权限 (仅管理员)
// ==============================================================
async function handleUsers(env, chatId, messageId = null, pageIndex = 0) {
  const rows = await env.DB.prepare(
    "SELECT user_id, node_key, ports, comment FROM users ORDER BY user_id, node_key"
  ).all();

  if (!rows.results?.length) {
    return deliverTelegram(env, chatId, messageId, formatNotice(
      "📭", "暂无授权用户", ["当前没有普通用户权限记录。"], "使用 /add 添加用户。"
    ), helpKeyboard(true));
  }

  // 按 user_id 汇总显示名，再按权限记录分页，端口只在完整值之间换行。
  const grouped = {};
  for (const r of rows.results) {
    if (!grouped[r.user_id]) grouped[r.user_id] = { comment: r.comment || "", entries: [] };
    if (r.comment && !grouped[r.user_id].comment) grouped[r.user_id].comment = r.comment;
    const ports = parseAllowedPorts(r.ports);
    grouped[r.user_id].entries.push({ node: r.node_key, ports });
  }

  const heading = `👥 *用户权限*\n${TG_DIVIDER}`;
  const cards = [];
  for (const [uid, info] of Object.entries(grouped)) {
    const label = info.comment ? ` · ${escMd(displayLabel(info.comment))}` : "";
    for (const entry of info.entries) {
      const cardHeader = `👤 *用户* \`${uid}\`${label}\n└ 节点 \`${entry.node}\``;
      const portLines = packPortValues(entry.ports, 2400);
      for (let index = 0; index < portLines.length; index++) {
        cards.push(`${cardHeader}\n🔌 端口${index ? "（续）" : ""}  \`${portLines[index]}\``);
      }
    }
  }

  const pages = paginateTextCards(heading, cards, 3500);
  const currentPage = Math.min(Math.max(0, pageIndex), pages.length - 1);
  const message = `${pages[currentPage]}\n\n${TG_DIVIDER}\n共 ${Object.keys(grouped).length} 位授权用户 · 第 ${currentPage + 1} / ${pages.length} 页`;
  return deliverTelegram(env, chatId, messageId, message, usersKeyboard(currentPage, pages.length));
}

function packPortValues(ports, maxLength) {
  if (!ports.length) return ["无"];
  const chunks = [];
  let current = "";
  for (const value of ports) {
    const token = String(value);
    const next = current ? `${current}, ${token}` : token;
    if (current && next.length > maxLength) {
      chunks.push(current);
      current = token;
    } else {
      current = next;
    }
  }
  if (current) chunks.push(current);
  return chunks;
}

function paginateTextCards(heading, cards, maxLength) {
  const pages = [];
  let current = heading;
  for (const card of cards) {
    const addition = `\n\n${card}`;
    if (current.length + addition.length <= maxLength) {
      current += addition;
    } else {
      pages.push(current);
      current = `${heading}\n\n${card}`;
    }
  }
  if (current) pages.push(current);
  return pages.length ? pages : [heading];
}

function usersKeyboard(pageIndex, pageCount) {
  const rows = [];
  const navigation = [];
  if (pageIndex > 0) navigation.push({ text: "⬅️ 上一页", callback_data: `!users:${pageIndex - 1}` });
  if (pageIndex + 1 < pageCount) navigation.push({ text: "下一页 ➡️", callback_data: `!users:${pageIndex + 1}` });
  if (navigation.length) rows.push(navigation);
  rows.push(...helpKeyboard(true).inline_keyboard);
  return { inline_keyboard: rows };
}

// ==============================================================
// 7. /id 与 /help
// ==============================================================
async function handleId(env, chatId, userId, isAdmin, messageId = null) {
  return deliverTelegram(env, chatId, messageId, formatNotice(
    "👤", "你的 Telegram ID",
    [`\`${userId}\``],
    "请将此 ID 发送给管理员申请流量查询权限。"
  ), helpKeyboard(isAdmin));
}

async function handleHelp(env, chatId, isAdmin, messageId = null) {
  let msg = `🧭 *命令菜单*\n${TG_DIVIDER}`;
  if (isAdmin) {
    msg += "\n📊 `/ll`  流量查询";
    msg += "\n👥 `/users`  用户权限";
    msg += "\n➕ `/add`  添加说明";
    msg += "\n➖ `/del`  删除说明";
    msg += "\n🖥 `/delnode`  节点管理";
  } else {
    msg += "\n📊 `/ll`  查询授权流量";
    msg += "\n👤 `/id`  查看你的 TG-ID";
  }
  msg += `\n${TG_DIVIDER}\n请选择功能：`;
  return deliverTelegram(env, chatId, messageId, msg, helpKeyboard(isAdmin));
}

// ==============================================================
// 报告生成
// ==============================================================
async function generateReports(inputs) {
  const prepared = inputs.map(input => {
    try {
      const parsed = JSON.parse(input.configJson);
      const ports = parsed?.ports && typeof parsed.ports === "object" && !Array.isArray(parsed.ports)
        ? parsed.ports
        : {};
      const sortedPorts = Object.keys(ports).sort((a, b) => parseInt(a) - parseInt(b));
      const allowedPorts = normalizeAllowedPorts(input.allowedPorts);
      return { ...input, ports, sortedPorts, allowedPorts };
    } catch {
      return { ...input, error: `❌ 节点 \`${input.nodeKey}\` 数据异常` };
    }
  });

  const seenIps = new Set();
  const visibleIps = [];
  for (const item of prepared) {
    if (item.error) continue;
    for (const ip of collectVisibleOnlineIps(item.sortedPorts, item.ports, item.allowedPorts)) {
      if (seenIps.has(ip)) continue;
      seenIps.add(ip);
      visibleIps.push(ip);
    }
  }
  const geoMap = await lookupIpGeos(visibleIps);

  return prepared.map(item => item.error
    ? { header: "", blocks: [item.error] }
    : renderReport(item, geoMap));
}

function paginateReportSections(sections, maxLength) {
  const pages = [];
  let current = "";
  const flush = () => {
    if (current) pages.push(current);
    current = "";
  };

  for (const section of sections) {
    const header = section.header || "";
    if (header) {
      if (!current) current = header;
      else if (current.length + 2 + header.length > maxLength) {
        flush();
        current = header;
      } else {
        current += `\n\n${header}`;
      }
    }
    for (const block of section.blocks) {
      const pieces = splitLongReportBlock(block, Math.max(500, maxLength - header.length - 2));
      for (const piece of pieces) {
        const separator = current ? "\n\n" : "";
        if (current.length + separator.length + piece.length <= maxLength) {
          current += separator + piece;
          continue;
        }
        flush();
        current = header ? `${header}\n\n${piece}` : piece;
      }
    }
  }
  flush();
  return pages.length ? pages : ["📭 暂无报告数据。"];
}

function splitLongReportBlock(block, maxLength) {
  if (block.length <= maxLength) return [block];
  const lines = block.split("\n");
  const pieces = [];
  const title = lines.shift() || "📄 端口详情";
  let current = title;
  for (const line of lines) {
    const next = `${current}\n${line}`;
    if (next.length <= maxLength) {
      current = next;
      continue;
    }
    pieces.push(current);
    current = `${title}（续）`;
    let remaining = line;
    const room = Math.max(1, maxLength - current.length - 1);
    while (remaining.length > room) {
      pieces.push(`${current}\n${remaining.slice(0, room)}`);
      remaining = remaining.slice(room);
      current = `${title}（续）`;
    }
    current += `\n${remaining}`;
  }
  if (current) pieces.push(current);
  return pieces;
}

function reportKeyboard(target, pageIndex, pageCount) {
  const rows = [];
  const navigation = [];
  const callbackFor = page => {
    return reportPageCallback(target, page);
  };
  if (pageIndex > 0) {
    const data = callbackFor(pageIndex - 1);
    if (data) navigation.push({ text: "⬅️ 上一页", callback_data: data });
  }
  if (pageIndex + 1 < pageCount) {
    const data = callbackFor(pageIndex + 1);
    if (data) navigation.push({ text: "下一页 ➡️", callback_data: data });
  }
  if (navigation.length) rows.push(navigation);

  const refreshTarget = pageIndex > 0
    ? reportPageCallback(target, pageIndex) || (target === "all" ? "!all" : target)
    : (target === "all" ? "!all" : target);
  rows.push([
    { text: "⬅️ 返回节点列表", callback_data: "!list" },
    { text: "🔄 刷新", callback_data: refreshTarget }
  ]);
  return { inline_keyboard: rows };
}

function reportPageCallback(target, pageIndex) {
  const data = `!r:${pageIndex}:${target}`;
  return new TextEncoder().encode(data).length <= 64 ? data : null;
}

function renderReport(input, geoMap) {
  const { nodeKey, nodeId, updatedAt, ports, sortedPorts, allowedPorts } = input;

  const now = Math.floor(Date.now() / 1000);
  const freshness = now - updatedAt;
  const freshIcon = freshness < 180 ? "🟢" : "🔴";
  const freshStr = fmtAge(freshness);

  // Legacy Markdown cannot escape special characters inside a bold entity.
  let report = `📊 ${escMd(displayLabel(nodeId))}`;
  report += `\n├ 节点 \`${nodeKey}\``;
  report += `\n└ 状态 ${freshIcon} ${freshStr}`;
  report += `\n${TG_DIVIDER}`;
  const header = report;
  const blocks = [];
  let hasData = false;

  // PM 的分组配额按组内所有端口的合计流量执行，报告必须使用同一口径。
  const groupUsage = new Map();
  for (const p of Object.values(ports)) {
    const groupId = p?.group_id || "";
    if (!groupId) continue;
    const accIn = Math.floor(p.stats?.acc_in || 0);
    const accOut = Math.floor(p.stats?.acc_out || 0);
    const used = (p.quota_mode || "in_out") === "out_only" ? accOut : accIn + accOut;
    groupUsage.set(groupId, (groupUsage.get(groupId) || 0) + used);
  }

  for (const port of sortedPorts) {
    if (!canAccessPort(allowedPorts, port)) continue;

    const p = ports[port];
    const comment   = p.comment || "";
    const quotaGb   = p.quota_gb || 0;
    const mode      = p.quota_mode || "in_out";
    const accIn     = Math.floor(p.stats?.acc_in || 0);
    const accOut    = Math.floor(p.stats?.acc_out || 0);
    const resetDay  = p.reset_day || 0;
    const expiryDate = typeof p.expiry_date === "string" ? p.expiry_date : "";
    const groupId   = p.group_id || "";
    const burstEnabled = p.dyn_limit?.enable === true;
    const isPunished = burstEnabled && p.dyn_limit?.is_punished === true;
    const burstLimitMbps = p.dyn_limit?.punish_mbps || 50;
    const online = p.online || {};
    const onlineIps = Array.isArray(online.ips) ? online.ips : [];
    const parsedOnlineCount = Number(online.ip_count);
    const onlineCount = Number.isFinite(parsedOnlineCount) ? Math.max(0, Math.floor(parsedOnlineCount)) : onlineIps.length;
    const onlineTruncated = online.truncated === true;

    const ownUsed = mode === "out_only" ? accOut : (accIn + accOut);
    const totalUsed = groupId ? (groupUsage.get(groupId) || 0) : ownUsed;
    const quotaBytes = quotaGb * 1024 * 1024 * 1024;
    const pct = quotaBytes > 0 ? (totalUsed * 100 / quotaBytes) : 0;
    const isBlocked = quotaBytes > 0 && totalUsed > quotaBytes;

    let statusIcon = "✅";
    if (isBlocked)       statusIcon = "🚫";
    else if (isPunished) statusIcon = "⚡";
    else if (pct >= 80)  statusIcon = "⚠️";

    const safeComment = comment ? ` · ${escMd(displayLabel(comment))}` : "";
    const modeText = mode === "out_only" ? "仅出站" : "双向";
    const policyParts = [modeText];
    if (groupId) policyParts.push(`分组 ${escMd(displayLabel(groupId))}`);
    if (resetDay > 0) policyParts.push(`${resetDay} 日重置`);
    if (burstEnabled) policyParts.push("突发保护");
    const expiryText = formatExpiryStatus(expiryDate, now);

    let block = `${statusIcon} \`${port}\`${safeComment}`;
    block += `\n├ 📦 ${fmtBytes(totalUsed)} / ${quotaGb} GB · ${formatPercent(pct)}`;
    block += `\n├ ⚙️ ${policyParts.join(" · ")}`;
    if (expiryText) {
      block += `\n├ 📅 ${expiryText}`;
    }
    if (isPunished) {
      block += `\n├ ⚡ 突发限速 ${burstLimitMbps} Mbps`;
    }

    const shownIps = onlineIps.slice(0, 8).map(ip => String(ip || "").trim()).filter(Boolean);
    const hasMore = onlineTruncated || onlineCount > shownIps.length;
    block += `\n└ 👥 在线 ${onlineCount} IP`;
    for (let index = 0; index < shownIps.length; index++) {
      const branch = index === shownIps.length - 1 && !hasMore ? "└" : "├";
      block += `\n   ${branch} ${formatIpWithGeo(shownIps[index], geoMap)}`;
    }
    if (hasMore) block += "\n   └ 其余 IP 已折叠";
    blocks.push(block);
    hasData = true;
  }

  if (!hasData) {
    blocks.push("📭 暂无监控端口或无权访问。");
  }

  return { header, blocks };
}

// ==============================================================
// 工具函数
// ==============================================================

function collectVisibleOnlineIps(sortedPorts, ports, allowedPorts) {
  const seen = new Set();
  const ips = [];
  for (const port of sortedPorts) {
    if (!canAccessPort(allowedPorts, port)) continue;
    const onlineIps = Array.isArray(ports[port]?.online?.ips) ? ports[port].online.ips : [];
    for (const ip of onlineIps.slice(0, 8)) {
      const normalized = String(ip || "").trim();
      if (!normalized || seen.has(normalized) || !isLikelyPublicIp(normalized)) continue;
      seen.add(normalized);
      ips.push(normalized);
      if (ips.length >= 20) return ips;
    }
  }
  return ips;
}

function normalizeAllowedPorts(allowedPorts) {
  if (allowedPorts === "all") return "all";
  const normalized = new Set();
  if (!Array.isArray(allowedPorts)) return normalized;
  for (const port of allowedPorts) {
    const parsed = Number.parseInt(port, 10);
    if (parsed > 0 && parsed <= 65535) normalized.add(parsed);
  }
  return normalized;
}

function canAccessPort(allowedPorts, port) {
  return allowedPorts === "all" || allowedPorts.has(Number.parseInt(port, 10));
}

function formatNotice(icon, title, lines = [], footer = "") {
  let message = `${icon} *${escMd(title)}*\n${TG_DIVIDER}`;
  for (const line of lines) message += `\n${line}`;
  if (footer) message += `\n${TG_DIVIDER}\nℹ️ ${footer}`;
  return message;
}

function formatPercent(percent) {
  const value = Number(percent);
  if (!Number.isFinite(value) || value <= 0) return "0.0%";
  if (value < 0.1) return "<0.1%";
  return `${value.toFixed(1)}%`;
}

function formatExpiryStatus(expiryDate, nowSeconds = Math.floor(Date.now() / 1000)) {
  const expiryDay = parseIsoDateDay(expiryDate);
  if (expiryDay === null) return "";
  const remaining = expiryDay - Math.floor(nowSeconds / 86400);
  if (remaining > 0) return `到期 ${expiryDate} · 剩 ${remaining} 天`;
  if (remaining === 0) return `到期 ${expiryDate} · 今天`;
  return `到期 ${expiryDate} · 已过 ${Math.abs(remaining)} 天`;
}

async function lookupIpGeos(ips) {
  if (!ips.length) return {};
  const geoMap = {};
  const uniqueIps = [...new Set(ips)];
  const missingIps = [];
  const now = Date.now();
  const deadline = now + GEO_LOOKUP_BUDGET_MS;

  for (const ip of uniqueIps) {
    const cached = geoCache.get(ip);
    if (cached && cached.expiresAt > now) {
      geoMap[ip] = cached.label;
    } else {
      if (cached) geoCache.delete(ip);
      missingIps.push(ip);
    }
  }

  // ip-api batch 单次最多接受 100 项；顺序分批避免多节点查询产生瞬时并发峰值。
  for (let offset = 0; offset < missingIps.length; offset += 100) {
    if (Date.now() < geoRateLimitedUntil) break;
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) break;
    const batch = missingIps.slice(offset, offset + 100);
    try {
      const timeoutSignal = AbortSignal.timeout(remainingMs);
      const response = await fetch("http://ip-api.com/batch?fields=status,country,regionName,city,isp,query&lang=zh-CN", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(batch),
        signal: timeoutSignal
      });
      const remaining = Number.parseInt(response.headers.get("X-Rl") || "", 10);
      const ttlSeconds = Number.parseInt(response.headers.get("X-Ttl") || "", 10);
      const isRateLimited = response.status === 429 || remaining === 0;
      if (isRateLimited) {
        const retryMs = Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? ttlSeconds * 1000 : 60_000;
        geoRateLimitedUntil = Date.now() + retryMs;
      }
      if (!response.ok) {
        if (isRateLimited) break;
        geoRateLimitedUntil = Date.now() + GEO_FAILURE_BACKOFF_MS;
        break;
      }
      const rows = await response.json();
      if (!Array.isArray(rows)) {
        geoRateLimitedUntil = Math.max(geoRateLimitedUntil, Date.now() + GEO_FAILURE_BACKOFF_MS);
        break;
      }
      for (let index = 0; index < rows.length; index++) {
        const row = rows[index];
        if (row?.status !== "success" || !row.query) continue;
        const requestedIp = batch[index] || row.query;
        const location = [...new Set([row.country, row.regionName, row.city].filter(Boolean))].join(" ");
        const isp = row.isp || "";
        const label = [location, isp].filter(Boolean).join(" / ");
        if (label) {
          geoMap[requestedIp] = label;
          geoCache.delete(requestedIp);
          geoCache.set(requestedIp, { label, expiresAt: now + GEO_CACHE_TTL_MS });
        }
      }
      if (isRateLimited) break;
    } catch {
      // 服务故障时停止本轮查询并短暂退避，报告仍显示 IP，缓存的成功结果继续使用。
      geoRateLimitedUntil = Math.max(geoRateLimitedUntil, Date.now() + GEO_FAILURE_BACKOFF_MS);
      break;
    }
  }
  while (geoCache.size > GEO_CACHE_MAX_ENTRIES) {
    geoCache.delete(geoCache.keys().next().value);
  }
  return geoMap;
}

function formatIpWithGeo(ip, geoMap) {
  const safeIp = escMd(displayLabel(ip, 64));
  const geo = geoMap[ip];
  if (!geo) return `\`${safeIp}\``;
  return `\`${safeIp}\` · ${escMd(displayLabel(geo, 160))}`;
}

function isLikelyPublicIp(ip) {
  if (/^(10|127|169\.254)\./.test(ip)) return false;
  if (/^192\.168\./.test(ip)) return false;
  const v4 = ip.match(/^172\.(\d{1,3})\./);
  if (v4 && Number(v4[1]) >= 16 && Number(v4[1]) <= 31) return false;
  if (/^(::1|fc|fd|fe80:)/i.test(ip)) return false;
  return true;
}

async function hmacSHA256(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function secureEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Only shorten display labels; stored identifiers, permissions and statistics stay intact.
// Truncate before Markdown escaping so an escape pair is never split by pagination.
function displayLabel(value, maxLength = 120) {
  const chars = Array.from(String(value ?? "").replace(/[\r\n]+/g, " "));
  return chars.length > maxLength ? `${chars.slice(0, maxLength - 1).join("")}…` : chars.join("");
}

function escMd(s) {
  if (!s) return "";
  return String(s).replace(/[_*`\[]/g, "\\$&");
}

function fmtBytes(bytes) {
  if (bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, val = bytes;
  while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function fmtAge(seconds) {
  if (seconds < 60) return "刚刚";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}小时前`;
  return `${Math.floor(seconds / 86400)}天前`;
}

function nodeMenuKeyboard(nodes, isAdmin) {
  const now = Math.floor(Date.now() / 1000);
  const inlineKeyboard = nodes.map(node => {
    const nodeKey = String(node.node_key);
    const nodeName = String(node.node_id || nodeKey);
    const label = nodeName === nodeKey ? nodeName : `${nodeName} · ${nodeKey}`;
    return [{
      text: `${now - node.updated_at < 180 ? "🟢" : "🔴"} ${label.slice(0, 48)}`,
      callback_data: nodeKey
    }];
  });
  if (nodes.length > 1) {
    inlineKeyboard.push([{
      text: isAdmin ? "📚 查看全部节点" : "📚 查看全部授权节点",
      callback_data: "!all"
    }]);
  }
  inlineKeyboard.push([{ text: "🧭 命令帮助", callback_data: "!help" }]);
  return { inline_keyboard: inlineKeyboard };
}

function helpKeyboard(isAdmin) {
  if (!isAdmin) {
    return { inline_keyboard: [[
      { text: "📊 流量查询", callback_data: "!list" },
      { text: "👤 我的 ID", callback_data: "!id" }
    ]] };
  }
  return { inline_keyboard: [
    [
      { text: "📊 流量查询", callback_data: "!list" },
      { text: "👥 用户权限", callback_data: "!users" }
    ],
    [
      { text: "➕ 添加说明", callback_data: "!addhelp" },
      { text: "➖ 删除说明", callback_data: "!delhelp" }
    ]
  ] };
}

function backKeyboard() {
  return { inline_keyboard: [[{ text: "⬅️ 返回节点列表", callback_data: "!list" }]] };
}

async function deliverTelegram(env, chatId, messageId, text, replyMarkup = null) {
  if (messageId && text.length <= 4096) {
    try {
      return await tgEdit(env, chatId, messageId, text, replyMarkup);
    } catch (error) {
      if (error?.telegramStatus === 429) throw error;
      console.error("Telegram edit failed; falling back to sendMessage", error?.message || error);
    }
  }
  return tgReply(env, chatId, text, replyMarkup);
}

async function tgAnswerCallback(env, callbackQueryId) {
  const token = env.BOT_TOKEN;
  if (!token || !callbackQueryId) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callback_query_id: callbackQueryId }),
      signal: AbortSignal.timeout(2500)
    });
  } catch {
    // 回调确认失败不影响后续详情查询。
  }
}

async function tgEdit(env, chatId, messageId, text, replyMarkup = null) {
  const token = env.BOT_TOKEN;
  if (!token) return new Response("BOT_TOKEN not set", { status: 500 });
  try {
    await fetchTelegramApi(token, "editMessageText", {
      chat_id: chatId,
      message_id: messageId,
      text,
      parse_mode: "Markdown",
      reply_markup: replyMarkup || { inline_keyboard: [] }
    });
  } catch (error) {
    if (error?.telegramStatus === 400 && error.message.includes("message is not modified")) {
      return new Response("OK");
    }
    throw error;
  }
  return new Response("OK");
}

async function tgReply(env, chatId, text, replyMarkup = null) {
  const token = env.BOT_TOKEN;
  if (!token) return new Response("BOT_TOKEN not set", { status: 500 });
  if (text.length > 4096) throw new Error("Telegram message exceeds 4096 characters; split it into paginated messages before sending");
  const payload = { chat_id: chatId, text, parse_mode: "Markdown" };
  if (replyMarkup) payload.reply_markup = replyMarkup;
  await fetchTelegramApi(token, "sendMessage", payload);
  return new Response("OK");
}

async function fetchTelegramApi(token, method, payload) {
  const url = `https://api.telegram.org/bot${token}/${method}`;
  for (let attempt = 0; attempt < 2; attempt++) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(TELEGRAM_TIMEOUT_MS)
    });
    if (response.ok) return response;

    const errorBody = (await response.text()).slice(0, 300);
    if (response.status === 429) {
      let retryAfter = NaN;
      try {
        const value = JSON.parse(errorBody).parameters?.retry_after;
        if (typeof value === "number" && Number.isFinite(value)) retryAfter = value;
      } catch {}
      const retryBoundSeconds = 2;
      if (attempt === 0 && Number.isFinite(retryAfter) && retryAfter >= 0 && retryAfter <= retryBoundSeconds) {
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        continue;
      }
      const error = new Error(`Telegram API rate limited (HTTP 429, retry_after=${Number.isFinite(retryAfter) ? retryAfter : "unknown"}s): ${errorBody}`);
      error.telegramStatus = 429;
      throw error;
    }
    const error = new Error(`Telegram API failed with HTTP ${response.status}: ${errorBody}`);
    error.telegramStatus = response.status;
    throw error;
  }
  throw new Error("Telegram API retry loop ended unexpectedly");
}
