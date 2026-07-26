/**
 * ============================================================
 * Cloudflare Worker - 端口流量查询中控 v2.7
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
 * 注意: USERS_JSON 已废弃，用户权限现在存储在 D1 的 users 表中
 *
 * v2.7 变更: /ll 使用节点选择菜单，支持详情、返回与刷新
 * ============================================================
 */

const GEO_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const GEO_CACHE_MAX_ENTRIES = 500;
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
// 1. 接收 VPS 推送 (不变)
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

  switch (cmd) {
    case "/ll":
      return handleQuery(env, chatId, userId, text, isAdmin);
    case "/add":
      return isAdmin ? handleAdd(env, chatId, text) : new Response("OK");
    case "/del":
      return isAdmin ? handleDel(env, chatId, text) : new Response("OK");
    case "/delnode":
      return isAdmin ? handleDelNode(env, chatId, text) : new Response("OK");
    case "/users":
      return isAdmin ? handleUsers(env, chatId) : new Response("OK");
    case "/help":
    case "/start":
      return handleHelp(env, chatId, isAdmin);
    default:
      return new Response("OK");
  }
}

// ==============================================================
// 3. /ll - 流量查询
// ==============================================================
async function handleQuery(env, chatId, userId, text, isAdmin) {
  const args = text.split(/\s+/);
  const target = args[1]?.toLowerCase();

  if (!target) return showNodeMenu(env, chatId, userId, isAdmin);
  return showNodeReport(env, chatId, userId, isAdmin, target);
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
    return deliverTelegram(env, chatId, messageId, message);
  }

  const now = Math.floor(Date.now() / 1000);
  let onlineCount = 0;
  let offlineCount = 0;
  let message = `📡 *节点中心*\n${TG_DIVIDER}`;
  for (const node of nodes) {
    const age = now - node.updated_at;
    const isOnline = age < 180;
    if (isOnline) onlineCount++; else offlineCount++;
    message += `\n${isOnline ? "🟢" : "🔴"} \`${node.node_key}\` · ${escMd(node.node_id)} · ${fmtAge(age)}`;
  }
  message += `\n${TG_DIVIDER}`;
  message += `\n🟢 在线 ${onlineCount}  ·  🔴 离线 ${offlineCount}`;
  message += "\n\n👇 请选择要查看的节点";

  return deliverTelegram(env, chatId, messageId, message, nodeMenuKeyboard(nodes, isAdmin));
}

async function showNodeReport(env, chatId, userId, isAdmin, target, messageId = null) {
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
  const refreshTarget = target === "all" ? "!all" : target;
  return deliverTelegram(env, chatId, messageId, reports.join("\n\n").trim(), detailKeyboard(refreshTarget));
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
  try { return JSON.parse(value); } catch { return []; }
}

// ==============================================================
// 4. /add - 添加/更新用户权限 (仅管理员)
//    格式: /add <tg_id> <node> <port1,port2,...> [备注]
//    示例: /add 987654321 hk 8080,8081 小王
// ==============================================================
async function handleAdd(env, chatId, text) {
  const args = text.split(/\s+/);
  // args[0]=/add, [1]=tg_id, [2]=node, [3]=ports, [4...]=comment

  if (args.length < 4) {
    return tgReply(env, chatId, formatNotice(
      "🧭", "添加用户权限",
      ["命令 `/add 用户ID 节点 端口 [备注]`", "示例 `/add 987654321 hk 8080,8081 小王`"],
      "多个端口使用英文逗号分隔。"
    ));
  }

  const targetId = args[1];
  const nodeKey  = args[2].toLowerCase();
  const portsStr = args[3];
  const comment  = args.slice(4).join(" ") || "";

  // 校验用户 ID
  if (!/^\d+$/.test(targetId)) {
    return tgReply(env, chatId, formatNotice("❌", "用户 ID 无效", ["用户 ID 必须是纯数字。"]));
  }

  // 校验节点存在
  const node = await env.DB.prepare("SELECT node_key FROM nodes WHERE node_key = ?1").bind(nodeKey).first();
  if (!node) {
    return tgReply(env, chatId, formatNotice(
      "❌", "节点不存在", [`节点 \`${nodeKey}\` 尚未推送数据。`], "发送 /ll 查看可用节点。"
    ));
  }

  // 解析端口
  const ports = portsStr.split(",")
    .map(p => parseInt(p.trim()))
    .filter(p => p > 0 && p <= 65535);

  if (ports.length === 0) {
    return tgReply(env, chatId, formatNotice(
      "❌", "端口格式错误", ["端口范围必须是 1–65535。"], "示例 `8080,8081,443`"
    ));
  }

  const portsJson = JSON.stringify(ports);

  // 写入 D1 (UPSERT)
  await env.DB.prepare(
    `INSERT INTO users (user_id, node_key, ports, comment)
     VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT(user_id, node_key) DO UPDATE SET
       ports = ?3, comment = ?4`
  ).bind(targetId, nodeKey, portsJson, comment).run();

  const lines = [
    `👤 用户  \`${targetId}\``,
    `🖥 节点  \`${nodeKey}\``,
    `🔌 端口  \`${ports.join(", ")}\``
  ];
  if (comment) lines.push(`📝 备注  ${escMd(comment)}`);
  return tgReply(env, chatId, formatNotice("✅", "权限已保存", lines));
}

// ==============================================================
// 5. /del - 删除用户权限 (仅管理员)
//    /del <tg_id>         → 删除该用户全部权限
//    /del <tg_id> <node>  → 仅删除该用户对指定节点的权限
// ==============================================================
async function handleDel(env, chatId, text) {
  const args = text.split(/\s+/);

  if (args.length < 2) {
    return tgReply(env, chatId, formatNotice(
      "🧭", "删除用户权限",
      ["`/del 987654321`  删除全部权限", "`/del 987654321 hk`  删除指定节点权限"]
    ));
  }

  const targetId = args[1];
  if (!/^\d+$/.test(targetId)) {
    return tgReply(env, chatId, formatNotice("❌", "用户 ID 无效", ["用户 ID 必须是纯数字。"]));
  }

  if (args.length >= 3) {
    // 删除指定节点
    const nodeKey = args[2].toLowerCase();
    const result = await env.DB.prepare(
      "DELETE FROM users WHERE user_id = ?1 AND node_key = ?2"
    ).bind(targetId, nodeKey).run();

    if (result.meta.changes > 0) {
      return tgReply(env, chatId, formatNotice(
        "✅", "权限已删除", [`👤 用户  \`${targetId}\``, `🖥 节点  \`${nodeKey}\``]
      ));
    } else {
      return tgReply(env, chatId, formatNotice(
        "⚠️", "未找到权限", [`用户 \`${targetId}\` 没有节点 \`${nodeKey}\` 的权限。`]
      ));
    }
  } else {
    // 删除全部
    const result = await env.DB.prepare(
      "DELETE FROM users WHERE user_id = ?1"
    ).bind(targetId).run();

    if (result.meta.changes > 0) {
      return tgReply(env, chatId, formatNotice(
        "✅", "权限已清空", [`👤 用户  \`${targetId}\``, `🗑 删除  ${result.meta.changes} 条权限`]
      ));
    } else {
      return tgReply(env, chatId, formatNotice("⚠️", "暂无权限", [`用户 \`${targetId}\` 没有权限记录。`]));
    }
  }
}

// ==============================================================
// 5.5. /delnode - 删除云端节点数据 (仅管理员)
//    /delnode <node>          → 删除节点 + 关联的用户权限
//    /delnode <node> --keep   → 仅删除节点数据，保留用户权限
// ==============================================================
async function handleDelNode(env, chatId, text) {
  const args = text.split(/\s+/);

  if (args.length < 2) {
    return tgReply(env, chatId, formatNotice(
      "🧭", "删除节点",
      ["`/delnode hk`  删除节点和关联权限", "`/delnode hk --keep`  仅删除节点数据"]
    ));
  }

  const nodeKey = args[1].toLowerCase();
  const keepUsers = args[2]?.toLowerCase() === "--keep";

  // 检查节点是否存在
  const node = await env.DB.prepare(
    "SELECT node_key, node_id FROM nodes WHERE node_key = ?1"
  ).bind(nodeKey).first();

  if (!node) {
    return tgReply(env, chatId, formatNotice("⚠️", "节点不存在", [`未找到节点 \`${nodeKey}\`。`]));
  }

  // 删除节点数据
  await env.DB.prepare("DELETE FROM nodes WHERE node_key = ?1").bind(nodeKey).run();

  const lines = [`🖥 节点  \`${nodeKey}\``, `🏷 名称  ${escMd(node.node_id)}`];

  if (!keepUsers) {
    // 同时删除关联的用户权限
    const userResult = await env.DB.prepare(
      "DELETE FROM users WHERE node_key = ?1"
    ).bind(nodeKey).run();

    const userCount = userResult.meta.changes || 0;
    if (userCount > 0) {
      lines.push(`🗑 权限  已清理 ${userCount} 条`);
    } else {
      lines.push("🗑 权限  无关联记录");
    }
  } else {
    lines.push("📌 权限  已保留");
  }

  return tgReply(env, chatId, formatNotice("✅", "节点已删除", lines));
}

// ==============================================================
// 6. /users - 列出所有用户权限 (仅管理员)
// ==============================================================
async function handleUsers(env, chatId) {
  const rows = await env.DB.prepare(
    "SELECT user_id, node_key, ports, comment FROM users ORDER BY user_id, node_key"
  ).all();

  if (!rows.results?.length) {
    return tgReply(env, chatId, formatNotice(
      "📭", "暂无授权用户", ["当前没有普通用户权限记录。"], "使用 /add 添加用户。"
    ));
  }

  // 按 user_id 分组
  const grouped = {};
  for (const r of rows.results) {
    if (!grouped[r.user_id]) grouped[r.user_id] = { comment: r.comment || "", nodes: [] };
    // 取最新的非空备注
    if (r.comment && !grouped[r.user_id].comment) grouped[r.user_id].comment = r.comment;
    let ports;
    try { ports = JSON.parse(r.ports); } catch { ports = []; }
    grouped[r.user_id].nodes.push({ node: r.node_key, ports });
  }

  let msg = `👥 *用户权限*\n${TG_DIVIDER}`;
  for (const [uid, info] of Object.entries(grouped)) {
    const label = info.comment ? ` · ${escMd(info.comment)}` : "";
    msg += `\n\n👤 *用户* \`${uid}\`${label}`;
    for (let index = 0; index < info.nodes.length; index++) {
      const n = info.nodes[index];
      const branch = index === info.nodes.length - 1 ? "└" : "├";
      msg += `\n${branch} \`${n.node}\`  ·  \`${n.ports.join(", ")}\``;
    }
  }
  msg += `\n${TG_DIVIDER}\n共 ${Object.keys(grouped).length} 位授权用户`;

  return tgReply(env, chatId, msg);
}

// ==============================================================
// 7. /help
// ==============================================================
async function handleHelp(env, chatId, isAdmin) {
  let msg = `🧭 *命令中心*\n${TG_DIVIDER}\n`;
  if (isAdmin) {
    msg += "\n📊 *流量查询*\n";
    msg += "├ `/ll`  打开节点选择菜单\n";
    msg += "├ `/ll hk`  指定节点\n";
    msg += "└ `/ll all`  全部详情\n\n";
    msg += "👥 *用户权限*\n";
    msg += "├ `/users`  权限列表\n";
    msg += "├ `/add ID 节点 端口 [备注]`\n";
    msg += "└ `/del ID [节点]`\n\n";
    msg += "🖥 *节点管理*\n";
    msg += "├ `/delnode 节点`  删除节点及权限\n";
    msg += "└ `/delnode 节点 --keep`  保留权限\n";
  } else {
    msg += "\n📊 `/ll`  打开你的授权节点菜单\n";
  }
  msg += `\n${TG_DIVIDER}\n所有数据均来自 VPS 最近一次推送。`;
  return tgReply(env, chatId, msg);
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

  return prepared.map(item => item.error || renderReport(item, geoMap));
}

function renderReport(input, geoMap) {
  const { nodeKey, nodeId, updatedAt, ports, sortedPorts, allowedPorts } = input;

  const now = Math.floor(Date.now() / 1000);
  const freshness = now - updatedAt;
  const freshIcon = freshness < 180 ? "🟢" : "🔴";
  const freshStr = fmtAge(freshness);

  let report = `📊 *流量详情*\n${TG_DIVIDER}`;
  report += `\n🖥 *${escMd(nodeId)}*`;
  report += `\n├ 节点 \`${nodeKey}\``;
  report += `\n└ 状态 ${freshIcon} ${freshStr}`;
  let hasData = false;

  // PM 的分组配额按组内所有端口的合计流量执行，报告必须使用同一口径。
  const groupUsage = {};
  for (const p of Object.values(ports)) {
    const groupId = p?.group_id || "";
    if (!groupId) continue;
    const accIn = Math.floor(p.stats?.acc_in || 0);
    const accOut = Math.floor(p.stats?.acc_out || 0);
    const used = (p.quota_mode || "in_out") === "out_only" ? accOut : accIn + accOut;
    groupUsage[groupId] = (groupUsage[groupId] || 0) + used;
  }

  for (const port of sortedPorts) {
    if (!canAccessPort(allowedPorts, port)) continue;

    const p = ports[port];
    const comment   = p.comment || "";
    const quotaGb   = p.quota_gb || 0;
    const mode      = p.quota_mode || "in_out";
    const limitMbps = p.limit_mbps || 0;
    const accIn     = Math.floor(p.stats?.acc_in || 0);
    const accOut    = Math.floor(p.stats?.acc_out || 0);
    const resetDay  = p.reset_day || 0;
    const groupId   = p.group_id || "";
    const isPunished = p.dyn_limit?.is_punished === true;
    const punishMbps = p.dyn_limit?.punish_mbps || 0;
    const online = p.online || {};
    const onlineIps = Array.isArray(online.ips) ? online.ips : [];
    const parsedOnlineCount = Number(online.ip_count);
    const onlineCount = Number.isFinite(parsedOnlineCount) ? Math.max(0, Math.floor(parsedOnlineCount)) : onlineIps.length;
    const onlineTruncated = online.truncated === true;

    const ownUsed = mode === "out_only" ? accOut : (accIn + accOut);
    const totalUsed = groupId ? (groupUsage[groupId] || 0) : ownUsed;
    const quotaBytes = quotaGb * 1024 * 1024 * 1024;
    const pct = quotaBytes > 0 ? (totalUsed * 100 / quotaBytes) : 0;
    const isBlocked = quotaBytes > 0 && totalUsed > quotaBytes;

    let statusIcon = "✅";
    if (isBlocked)       statusIcon = "🚫";
    else if (isPunished) statusIcon = "⚡";
    else if (pct >= 80)  statusIcon = "⚠️";

    const safeComment = comment ? ` · ${escMd(comment)}` : "";
    const modeText = mode === "out_only" ? "仅出站" : "双向统计";
    const policyParts = [modeText];
    if (groupId) policyParts.push(`分组 ${escMd(groupId)}`);
    if (resetDay > 0) policyParts.push(`每月 ${resetDay} 日重置`);

    report += `\n\n${statusIcon} *端口* \`${port}\`${safeComment}`;
    report += `\n├ 📦 ${fmtBytes(totalUsed)} / ${quotaGb}GB`;
    report += `\n├ ${formatProgressBar(pct)}  ${pct.toFixed(1)}%`;
    report += `\n├ ⚙️ ${policyParts.join(" · ")}`;
    if (isPunished) {
      report += `\n├ ⚡ 动态限速 ${punishMbps} Mbps`;
    } else if (limitMbps > 0) {
      report += `\n├ 🔒 出站限速 ${limitMbps} Mbps`;
    }

    const shownIps = onlineIps.slice(0, 8).map(ip => String(ip || "").trim()).filter(Boolean);
    const hasMore = onlineTruncated || onlineCount > shownIps.length;
    report += `\n└ 👥 在线 *${onlineCount} IP*`;
    for (let index = 0; index < shownIps.length; index++) {
      const branch = index === shownIps.length - 1 && !hasMore ? "└" : "├";
      report += `\n   ${branch} ${formatIpWithGeo(shownIps[index], geoMap)}`;
    }
    if (hasMore) report += "\n   └ 其余 IP 已折叠";
    hasData = true;
  }

  if (!hasData) {
    report += `\n${TG_DIVIDER}\n📭 暂无监控端口或无权访问。`;
  }

  return report;
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

function formatProgressBar(percent) {
  const normalized = Math.max(0, Math.min(100, Number(percent) || 0));
  const filled = normalized > 0 ? Math.ceil(normalized / 12.5) : 0;
  return `\`${"█".repeat(filled)}${"░".repeat(8 - filled)}\``;
}

async function lookupIpGeos(ips) {
  if (!ips.length) return {};
  const geoMap = {};
  const uniqueIps = [...new Set(ips)];
  const missingIps = [];
  const now = Date.now();

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
    const batch = missingIps.slice(offset, offset + 100);
    try {
      const timeoutSignal = typeof AbortSignal !== "undefined" && AbortSignal.timeout
        ? AbortSignal.timeout(2500)
        : undefined;
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
        continue;
      }
      const rows = await response.json();
      if (!Array.isArray(rows)) {
        if (isRateLimited) break;
        continue;
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
      // 单批失败仅降级该批 IP，不影响其他节点和 Telegram 主报告。
    }
  }
  while (geoCache.size > GEO_CACHE_MAX_ENTRIES) {
    geoCache.delete(geoCache.keys().next().value);
  }
  return geoMap;
}

function formatIpWithGeo(ip, geoMap) {
  const safeIp = escMd(ip);
  const geo = geoMap[ip];
  if (!geo) return `\`${safeIp}\``;
  return `\`${safeIp}\` · ${escMd(geo)}`;
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

function escMd(s) {
  if (!s) return "";
  return String(s).replace(/[_*`\[]/g, "\\$&");
}

function fmtBytes(bytes) {
  if (bytes <= 0) return "0B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, val = bytes;
  while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
  return val.toFixed(i === 0 ? 0 : 1) + units[i];
}

function fmtAge(seconds) {
  if (seconds < 60) return "刚刚";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}小时前`;
  return `${Math.floor(seconds / 86400)}天前`;
}

function nodeMenuKeyboard(nodes, isAdmin) {
  const now = Math.floor(Date.now() / 1000);
  const inlineKeyboard = nodes.map(node => [{
    text: `${now - node.updated_at < 180 ? "🟢" : "🔴"} ${String(node.node_id || node.node_key).slice(0, 36)}`,
    callback_data: node.node_key
  }]);
  if (nodes.length > 1) {
    inlineKeyboard.push([{
      text: isAdmin ? "📚 查看全部节点" : "📚 查看全部授权节点",
      callback_data: "!all"
    }]);
  }
  return { inline_keyboard: inlineKeyboard };
}

function detailKeyboard(refreshTarget) {
  return {
    inline_keyboard: [[
      { text: "⬅️ 返回节点列表", callback_data: "!list" },
      { text: "🔄 刷新", callback_data: refreshTarget }
    ]]
  };
}

function backKeyboard() {
  return { inline_keyboard: [[{ text: "⬅️ 返回节点列表", callback_data: "!list" }]] };
}

async function deliverTelegram(env, chatId, messageId, text, replyMarkup = null) {
  if (messageId && text.length <= 4096) {
    try {
      return await tgEdit(env, chatId, messageId, text, replyMarkup);
    } catch (error) {
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
      body: JSON.stringify({ callback_query_id: callbackQueryId })
    });
  } catch {
    // 回调确认失败不影响后续详情查询。
  }
}

async function tgEdit(env, chatId, messageId, text, replyMarkup = null) {
  const token = env.BOT_TOKEN;
  if (!token) return new Response("BOT_TOKEN not set", { status: 500 });
  const response = await fetch(`https://api.telegram.org/bot${token}/editMessageText`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      message_id: messageId,
      text,
      parse_mode: "Markdown",
      reply_markup: replyMarkup || { inline_keyboard: [] }
    })
  });
  if (!response.ok) {
    const errorBody = (await response.text()).slice(0, 300);
    if (response.status === 400 && errorBody.includes("message is not modified")) {
      return new Response("OK");
    }
    throw new Error(`Telegram edit failed with HTTP ${response.status}: ${errorBody}`);
  }
  return new Response("OK");
}

async function tgReply(env, chatId, text, replyMarkup = null) {
  const token = env.BOT_TOKEN;
  if (!token) return new Response("BOT_TOKEN not set", { status: 500 });

  const chunks = [];
  if (text.length <= 4096) {
    chunks.push(text);
  } else {
    let remaining = text;
    while (remaining.length > 0) {
      if (remaining.length <= 4096) { chunks.push(remaining); break; }
      let cut = remaining.lastIndexOf("\n", 4096);
      if (cut <= 0) cut = 4096;
      chunks.push(remaining.substring(0, cut));
      remaining = remaining.substring(cut);
    }
  }

  for (let index = 0; index < chunks.length; index++) {
    const payload = { chat_id: chatId, text: chunks[index], parse_mode: "Markdown" };
    if (replyMarkup && index === chunks.length - 1) payload.reply_markup = replyMarkup;
    const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      const errorBody = (await response.text()).slice(0, 200);
      throw new Error(`Telegram API failed with HTTP ${response.status}: ${errorBody}`);
    }
  }

  return new Response("OK");
}
