/**
 * ============================================================
 * Cloudflare Worker - 端口流量查询中控 v2.1
 * 
 * 绑定要求 (Worker Settings -> Bindings):
 *   - D1 Database: 变量名 DB
 *
 * 环境变量 (Worker Settings -> Variables):
 *   - SHARED_SECRET  : VPS 推送签名密钥
 *   - BOT_TOKEN      : Telegram Bot Token
 *   - ADMIN_ID       : 管理员 Telegram ID (字符串)
 *
 * 注意: USERS_JSON 已废弃，用户权限现在存储在 D1 的 users 表中
 *
 * v2.1 变更: 新增 /delnode 命令，支持删除云端节点数据
 * ============================================================
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/push" && request.method === "PUT") {
      return handlePush(request, env);
    }

    if (request.method === "POST" && url.pathname === "/webhook") {
      return handleTelegram(request, env);
    }

    return new Response("OK");
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

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(ts)) > 120) {
    return new Response("Timestamp expired", { status: 403 });
  }

  const expected = await hmacSHA256(secret, ts + body);
  if (sig !== expected) {
    return new Response("Forbidden", { status: 403 });
  }

  let nodeId = nodeKey;
  try { nodeId = JSON.parse(body).node_id || nodeKey; } catch {}

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
  let payload;
  try { payload = await request.json(); } catch { return new Response("OK"); }
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

  if (isAdmin) {
    const target = args[1]?.toLowerCase();

    if (!target) {
      // 列出所有节点
      const rows = await env.DB.prepare("SELECT node_key, node_id, updated_at FROM nodes ORDER BY node_key").all();
      if (!rows.results?.length) return tgReply(env, chatId, "暂无节点数据。");
      const now = Math.floor(Date.now() / 1000);
      let msg = "📡 *可用节点*\n";
      for (const r of rows.results) {
        const age = now - r.updated_at;
        const online = age < 180 ? "🟢" : "🔴";
        const ago = fmtAge(age);
        msg += `\n${online} \`${r.node_key}\` (${escMd(r.node_id)}) - ${ago}`;
      }
      msg += "\n\n用法: `/ll hk` 或 `/ll all`";
      return tgReply(env, chatId, msg);
    }

    if (target === "all") {
      const rows = await env.DB.prepare("SELECT * FROM nodes ORDER BY node_key").all();
      if (!rows.results?.length) return tgReply(env, chatId, "暂无节点数据。");
      let fullMsg = "";
      for (const r of rows.results) {
        fullMsg += generateReport(r.node_key, r.node_id, r.config_json, r.updated_at, "all") + "\n";
      }
      return tgReply(env, chatId, fullMsg.trim());
    }

    const row = await env.DB.prepare("SELECT * FROM nodes WHERE node_key = ?1").bind(target).first();
    if (!row) return tgReply(env, chatId, `❌ 节点 \`${target}\` 未找到`);
    return tgReply(env, chatId, generateReport(row.node_key, row.node_id, row.config_json, row.updated_at, "all"));

  } else {
    // 普通用户: 从 D1 读取权限
    const perms = await env.DB.prepare("SELECT node_key, ports FROM users WHERE user_id = ?1").bind(userId).all();
    if (!perms.results?.length) return new Response("OK"); // 无权限，静默

    let fullMsg = "";
    for (const perm of perms.results) {
      let ports;
      try { ports = JSON.parse(perm.ports); } catch { ports = []; }
      const row = await env.DB.prepare("SELECT * FROM nodes WHERE node_key = ?1").bind(perm.node_key).first();
      if (row) {
        fullMsg += generateReport(row.node_key, row.node_id, row.config_json, row.updated_at, ports) + "\n";
      }
    }
    if (!fullMsg) return tgReply(env, chatId, "暂无可查询的数据。");
    return tgReply(env, chatId, fullMsg.trim());
  }
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
    return tgReply(env, chatId,
      "用法: `/add <用户ID> <节点> <端口>`\n" +
      "示例: `/add 987654321 hk 8080,8081 小王`\n\n" +
      "端口用逗号分隔，备注可选");
  }

  const targetId = args[1];
  const nodeKey  = args[2].toLowerCase();
  const portsStr = args[3];
  const comment  = args.slice(4).join(" ") || "";

  // 校验用户 ID
  if (!/^\d+$/.test(targetId)) {
    return tgReply(env, chatId, "❌ 用户 ID 必须是纯数字");
  }

  // 校验节点存在
  const node = await env.DB.prepare("SELECT node_key FROM nodes WHERE node_key = ?1").bind(nodeKey).first();
  if (!node) {
    return tgReply(env, chatId, `❌ 节点 \`${nodeKey}\` 不存在，请先确认 VPS 已推送数据`);
  }

  // 解析端口
  const ports = portsStr.split(",")
    .map(p => parseInt(p.trim()))
    .filter(p => p > 0 && p <= 65535);

  if (ports.length === 0) {
    return tgReply(env, chatId, "❌ 端口格式错误，示例: `8080,8081,443`");
  }

  const portsJson = JSON.stringify(ports);

  // 写入 D1 (UPSERT)
  await env.DB.prepare(
    `INSERT INTO users (user_id, node_key, ports, comment)
     VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT(user_id, node_key) DO UPDATE SET
       ports = ?3, comment = ?4`
  ).bind(targetId, nodeKey, portsJson, comment).run();

  const label = comment ? ` (${escMd(comment)})` : "";
  return tgReply(env, chatId,
    `✅ 已设置用户权限\n\n` +
    `👤 用户: \`${targetId}\`${label}\n` +
    `📍 节点: \`${nodeKey}\`\n` +
    `🔌 端口: \`${ports.join(", ")}\``
  );
}

// ==============================================================
// 5. /del - 删除用户权限 (仅管理员)
//    /del <tg_id>         → 删除该用户全部权限
//    /del <tg_id> <node>  → 仅删除该用户对指定节点的权限
// ==============================================================
async function handleDel(env, chatId, text) {
  const args = text.split(/\s+/);

  if (args.length < 2) {
    return tgReply(env, chatId,
      "用法:\n" +
      "`/del 987654321` — 删除该用户全部权限\n" +
      "`/del 987654321 hk` — 仅删除 hk 节点权限");
  }

  const targetId = args[1];
  if (!/^\d+$/.test(targetId)) {
    return tgReply(env, chatId, "❌ 用户 ID 必须是纯数字");
  }

  if (args.length >= 3) {
    // 删除指定节点
    const nodeKey = args[2].toLowerCase();
    const result = await env.DB.prepare(
      "DELETE FROM users WHERE user_id = ?1 AND node_key = ?2"
    ).bind(targetId, nodeKey).run();

    if (result.meta.changes > 0) {
      return tgReply(env, chatId, `✅ 已删除用户 \`${targetId}\` 的 \`${nodeKey}\` 节点权限`);
    } else {
      return tgReply(env, chatId, `⚠️ 未找到用户 \`${targetId}\` 的 \`${nodeKey}\` 节点权限`);
    }
  } else {
    // 删除全部
    const result = await env.DB.prepare(
      "DELETE FROM users WHERE user_id = ?1"
    ).bind(targetId).run();

    if (result.meta.changes > 0) {
      return tgReply(env, chatId, `✅ 已删除用户 \`${targetId}\` 的全部权限 (${result.meta.changes} 条)`);
    } else {
      return tgReply(env, chatId, `⚠️ 用户 \`${targetId}\` 无任何权限记录`);
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
    return tgReply(env, chatId,
      "用法:\n" +
      "`/delnode hk` — 删除节点及关联用户权限\n" +
      "`/delnode hk --keep` — 仅删除节点数据，保留用户权限");
  }

  const nodeKey = args[1].toLowerCase();
  const keepUsers = args[2]?.toLowerCase() === "--keep";

  // 检查节点是否存在
  const node = await env.DB.prepare(
    "SELECT node_key, node_id FROM nodes WHERE node_key = ?1"
  ).bind(nodeKey).first();

  if (!node) {
    return tgReply(env, chatId, `⚠️ 节点 \`${nodeKey}\` 不存在`);
  }

  // 删除节点数据
  await env.DB.prepare("DELETE FROM nodes WHERE node_key = ?1").bind(nodeKey).run();

  let msg = `🗑 已删除节点 \`${nodeKey}\` (${escMd(node.node_id)})`;

  if (!keepUsers) {
    // 同时删除关联的用户权限
    const userResult = await env.DB.prepare(
      "DELETE FROM users WHERE node_key = ?1"
    ).bind(nodeKey).run();

    const userCount = userResult.meta.changes || 0;
    if (userCount > 0) {
      msg += `\n📋 同时清理了 ${userCount} 条用户权限`;
    }
  } else {
    msg += "\n📋 用户权限已保留";
  }

  return tgReply(env, chatId, msg);
}

// ==============================================================
// 6. /users - 列出所有用户权限 (仅管理员)
// ==============================================================
async function handleUsers(env, chatId) {
  const rows = await env.DB.prepare(
    "SELECT user_id, node_key, ports, comment FROM users ORDER BY user_id, node_key"
  ).all();

  if (!rows.results?.length) {
    return tgReply(env, chatId, "暂无普通用户。\n\n使用 `/add` 添加用户。");
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

  let msg = "👥 *用户权限列表*\n";
  for (const [uid, info] of Object.entries(grouped)) {
    const label = info.comment ? ` (${escMd(info.comment)})` : "";
    msg += `\n👤 \`${uid}\`${label}`;
    for (const n of info.nodes) {
      msg += `\n   📍 ${n.node} → \`${n.ports.join(", ")}\``;
    }
    msg += "\n";
  }

  return tgReply(env, chatId, msg);
}

// ==============================================================
// 7. /help
// ==============================================================
async function handleHelp(env, chatId, isAdmin) {
  let msg = "📋 *端口流量查询*\n\n";
  if (isAdmin) {
    msg += "*查询指令*\n";
    msg += "`/ll` — 查看可用节点\n";
    msg += "`/ll hk` — 查看指定节点\n";
    msg += "`/ll all` — 查看所有节点\n\n";
    msg += "*用户管理*\n";
    msg += "`/users` — 列出所有用户\n";
    msg += "`/add ID 节点 端口 备注`\n";
    msg += "  例: `/add 123456 hk 8080,443 小王`\n";
    msg += "`/del ID [节点]`\n";
    msg += "  例: `/del 123456` 删全部\n";
    msg += "  例: `/del 123456 hk` 删单节点\n\n";
    msg += "*节点管理*\n";
    msg += "`/delnode 节点` — 删除节点及权限\n";
    msg += "`/delnode 节点 --keep` — 仅删节点\n";
  } else {
    msg += "`/ll` — 查看你的流量\n";
  }
  return tgReply(env, chatId, msg);
}

// ==============================================================
// 报告生成 (不变)
// ==============================================================
function generateReport(nodeKey, nodeId, configJson, updatedAt, allowedPorts) {
  let conf;
  try { conf = JSON.parse(configJson); } catch { return `❌ 节点 \`${nodeKey}\` 数据异常`; }

  const ports = conf.ports || {};
  const sortedPorts = Object.keys(ports).sort((a, b) => parseInt(a) - parseInt(b));
  const now = Math.floor(Date.now() / 1000);
  const freshness = now - updatedAt;
  const freshIcon = freshness < 180 ? "🟢" : "🔴";
  const freshStr = fmtAge(freshness);

  let report = `📊 *${escMd(nodeId)}* (${nodeKey}) ${freshIcon} ${freshStr}\n`;
  let hasData = false;

  for (const port of sortedPorts) {
    if (allowedPorts !== "all") {
      if (!allowedPorts.includes(parseInt(port))) continue;
    }

    const p = ports[port];
    const comment   = p.comment || "";
    const quotaGb   = p.quota_gb || 0;
    const mode      = p.quota_mode || "in_out";
    const limitMbps = p.limit_mbps || 0;
    const accIn     = Math.floor(p.stats?.acc_in || 0);
    const accOut    = Math.floor(p.stats?.acc_out || 0);
    const resetDay  = p.reset_day || 0;
    const isPunished = p.dyn_limit?.is_punished === true;
    const punishMbps = p.dyn_limit?.punish_mbps || 0;

    const totalUsed = mode === "out_only" ? accOut : (accIn + accOut);
    const quotaBytes = quotaGb * 1024 * 1024 * 1024;
    const pct = quotaBytes > 0 ? (totalUsed * 100 / quotaBytes) : 0;
    const isBlocked = quotaBytes > 0 && totalUsed > quotaBytes;

    let statusIcon = "✅";
    if (isBlocked)       statusIcon = "🚫";
    else if (isPunished) statusIcon = "⚡";
    else if (pct >= 80)  statusIcon = "⚠️";

    const safeComment = comment ? ` ${escMd(comment)}` : "";
    const resetStr = resetDay > 0 ? ` R${resetDay}` : "";

    let speedInfo = "";
    if (isPunished) {
      speedInfo = ` ⚡${punishMbps}M`;
    } else if (limitMbps > 0) {
      speedInfo = ` 🔒${limitMbps}M`;
    }

    report += `\n${statusIcon} \`${port}\`${safeComment}${resetStr}`;
    report += `\n   ${fmtBytes(totalUsed)} / ${quotaGb}GB (${pct.toFixed(1)}%)${speedInfo}\n`;
    hasData = true;
  }

  if (!hasData) {
    report += "\n暂无监控端口或无权访问。\n";
  }

  return report;
}

// ==============================================================
// 工具函数
// ==============================================================

async function hmacSHA256(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
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

async function tgReply(env, chatId, text) {
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

  for (const chunk of chunks) {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: chunk, parse_mode: "Markdown" })
    });
  }

  return new Response("OK");
}
