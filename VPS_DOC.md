# Linux 端口流量管理脚本 (Port Monitor & Shaper)

**版本**: v4.3 Stable | **快捷命令**: `pm` | **安装路径**: `/usr/local/bin/pm`

---

## 1. 概述

vps.sh 是一个基于 Nftables + TC 的端口级流量管理工具，适用于多用户 VPS 场景（如代理节点分发）。核心能力：按端口独立计量流量、设定配额并自动封禁、出站限速、动态突发惩罚（DynQoS）、Telegram 实时通知。

### 1.1 适用场景

- 多用户共享 VPS，每人分配独立端口和流量配额
- 代理节点（Snell / SS / VMess / Trojan 等）流量管控
- 端口级出站限速 + 突发流量自动惩罚

### 1.2 系统要求

| 依赖 | 用途 |
|------|------|
| nftables (nft) | 流量计数 + 端口封禁 |
| iproute2 (tc) | 出站限速 (HTB) |
| jq | JSON 配置读写 |
| bc | 浮点数运算 |
| curl | 脚本更新 + Telegram 通知 |
| flock | 并发安全（原子写入 + cron 单例锁） |
| stat / numfmt | 文件锁龄检测 / 流量格式化 |

脚本会在首次运行时自动检测并安装缺失依赖（apt / yum / apk）。

---

## 2. 安装与使用

### 2.1 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/vps.sh)
```

安装流程：下载到临时文件 → 校验完整性 → `mv` 到 `/usr/local/bin/pm` → `exec` 启动。如果网络不通，会尝试本地复制降级。

### 2.2 命令行

| 命令 | 说明 |
|------|------|
| `pm` | 进入交互式管理菜单 |
| `pm update` | 检查并更新到最新版本 |
| `pm --monitor` | Cron 内部调用，手动执行无意义 |

### 2.3 主菜单

```
=========================================================================================
   Linux 端口流量管理 (v4.3) - 后台每分钟刷新
=========================================================================================
 ID   端口         模式       已用流量 / 总配额             出站限速        备注
-----------------------------------------------------------------------------------------
 1    10086        [双向]     4.2 GB / 10 GB [R1]          100 Mbps        Snell
 2    20000        [仅出站]   [已阻断] / 5 GB              无限制          SS
 3    30000        [双向]     6.5 GB / 10 GB               5Mbps(惩罚中)   VMess
=========================================================================================
 1. 添加 监控端口 (服务扫描)
 2. 配置 端口 (修改/动态QoS/重置)
 3. 删除 监控端口
 4. 通知设置 (Telegram)
 5. 更新 脚本
 6. 卸载 脚本
 0. 退出
```

面板字段说明：

| 字段 | 含义 |
|------|------|
| 模式 | `[双向]` 入站+出站合计 / `[仅出站]` 只计出站 |
| `[已阻断]` | 配额耗尽，端口已被 nft drop |
| `[R1]` | 每月 1 日自动重置配额 |
| `(惩罚中)` | DynQoS 触发，临时降速 |

---

## 3. 核心架构

### 3.1 模块划分

```
vps.sh (1540 行)
├── 模块 1: 基础架构 (安装/依赖/配置初始化)
│   ├── check_root()          # root 权限检查
│   ├── install_shortcut()    # 安装快捷命令 (mktemp → 校验 → mv)
│   ├── install_deps()        # 依赖安装 + config.json 初始化
│   └── get_iface()           # 获取主网卡接口
│
├── 模块 2: 网络引擎 (Nftables + TC)
│   ├── init_nft_table()      # 初始化 nft 表/链/集合
│   ├── init_tc_root()        # 初始化 TC HTB 根队列
│   ├── apply_port_rules()    # 为端口创建计数器 + 限速规则
│   ├── reload_all_rules()    # 销毁并重建所有规则 (自愈)
│   ├── safe_write_config()   # flock 原子写入 JSON
│   └── safe_write_config_from_file()  # 文件→config 原子写入
│
├── 模块 2.5: Telegram 通知引擎
│   ├── get_host_label()      # 生成标识: hostname (备注)
│   ├── tg_send()             # 异步发送 (后台 curl &)
│   ├── tg_notify_quota()     # 配额阈值预警
│   ├── tg_notify_blocked()   # 端口封禁通知
│   ├── tg_notify_punish()    # DynQoS 惩罚触发
│   ├── tg_notify_recover()   # 惩罚恢复通知
│   ├── tg_notify_reset()     # 配额自动重置通知
│   └── tg_notify_report()    # 定时流量汇总报告
│
├── 模块 3: 守护进程 (Cron Writer)
│   ├── cron_task()           # 每分钟执行: 流量采集/DynQoS/阈值通知
│   └── setup_cron()          # 注册 crontab
│
├── 模块 4: UI (Reader)
│   ├── show_main_menu()      # 主菜单面板
│   ├── add_port_flow()       # 添加端口 (扫描活跃服务)
│   ├── config_port_menu()    # 端口配置子菜单
│   ├── configure_dyn_qos()   # DynQoS 参数设置
│   ├── configure_telegram()  # Telegram 通知配置
│   ├── delete_port_flow()    # 删除端口监控
│   ├── update_script()       # 更新脚本
│   └── uninstall_script()    # 卸载脚本
│
└── 入口
    ├── --monitor  → cron_task()
    ├── update     → update_script()
    └── (默认)     → while show_main_menu
```

### 3.2 Reader-Writer 分离

脚本采用**读写分离**设计，同一份代码的不同入口承担不同角色：

| 角色 | 触发方式 | 职责 | 写 config |
|------|---------|------|-----------|
| **Writer** | `pm --monitor` (Cron 每分钟) | 采集内核计数器、计算流量、DynQoS 判定、阈值通知 | ✅ |
| **Reader** | `pm` (用户交互) | 读取 config 展示面板、接收用户配置操作 | ✅ (用户修改时) |

### 3.3 并发安全

| 冲突场景 | 保护机制 |
|----------|---------|
| Cron vs 菜单 | `USER_EDIT_LOCK` 文件锁，菜单开启时 Cron 避让 |
| Cron vs Cron | `CRON_LOCK_FILE` + `flock -n` 单例锁，上一轮未完成则跳过 |
| JSON 写入竞争 | `LOCK_FILE` + `flock -x` 排他锁保护原子写入 |
| 死锁防护 | `USER_EDIT_LOCK` 超过 10 分钟自动强制清除 |

---

## 4. 数据结构

### 4.1 config.json

存储路径: `/etc/port_monitor/config.json`

```json
{
  "interface": "eth0",
  "ports": {
    "10086": {
      "quota_gb": 10,
      "quota_mode": "both",
      "limit_mbps": 100,
      "reset_day": 1,
      "last_reset_ts": 1700000000,
      "comment": "Snell",
      "stats": {
        "acc_in": 1073741824,
        "acc_out": 2147483648,
        "last_kernel_in": 50000000,
        "last_kernel_out": 80000000
      },
      "dyn_limit": {
        "enable": true,
        "trigger_mbps": 100,
        "trigger_time": 5,
        "punish_mbps": 5,
        "punish_time": 60,
        "is_punished": false,
        "strike_count": 0,
        "punish_end_ts": 0
      },
      "notify_state": {
        "quota_level": 50,
        "punish_notified": false,
        "recover_notified": true
      }
    }
  },
  "telegram": {
    "enable": true,
    "bot_token": "123456789:ABC...",
    "chat_id": "-1001234567890",
    "api_url": "https://api.telegram.org",
    "thresholds": [50, 80, 100],
    "report_interval_hours": 6,
    "last_report_ts": 1700000000
  }
}
```

### 4.2 字段说明

**端口配置 (ports.\<port\>)**

| 字段 | 类型 | 说明 |
|------|------|------|
| `quota_gb` | number | 流量配额 (GB) |
| `quota_mode` | string | `"both"` 双向 / `"out_only"` 仅出站 |
| `limit_mbps` | number | 基础出站限速 (Mbps)，0 = 无限制 |
| `reset_day` | number | 每月自动重置日 (1-31)，0 = 不自动重置 |
| `last_reset_ts` | number | 上次重置的 Unix 时间戳 |
| `comment` | string | 备注信息 |

**流量统计 (stats)**

| 字段 | 类型 | 说明 |
|------|------|------|
| `acc_in` | number | 累计入站流量 (字节) |
| `acc_out` | number | 累计出站流量 (字节) |
| `last_kernel_in` | number | 上次采集的内核计数器值 (入站) |
| `last_kernel_out` | number | 上次采集的内核计数器值 (出站) |

**动态 QoS (dyn_limit)**

| 字段 | 类型 | 说明 |
|------|------|------|
| `enable` | boolean | 是否启用 DynQoS |
| `trigger_mbps` | number | 触发阈值 (Mbps) |
| `trigger_time` | number | 连续超标分钟数才触发 |
| `punish_mbps` | number | 惩罚期限速值 (Mbps) |
| `punish_time` | number | 惩罚持续时间 (分钟) |
| `is_punished` | boolean | 当前是否在惩罚期 |
| `strike_count` | number | 连续超标次数计数器 |
| `punish_end_ts` | number | 惩罚结束时间戳 |

**通知状态 (notify_state)**

| 字段 | 类型 | 说明 |
|------|------|------|
| `quota_level` | number | 已通知的最高阈值 (如 50/80/100) |
| `punish_notified` | boolean | 本轮惩罚是否已通知 |
| `recover_notified` | boolean | 本轮恢复是否已通知 |

**Telegram 配置 (telegram)**

| 字段 | 类型 | 说明 |
|------|------|------|
| `enable` | boolean | 通知总开关 |
| `bot_token` | string | Bot Token |
| `chat_id` | string | 目标 Chat ID |
| `api_url` | string | API 地址，支持国内反代 |
| `thresholds` | number[] | 配额预警阈值 (%) |
| `report_interval_hours` | number | 定时报告间隔 (小时)，0 = 关闭 |
| `last_report_ts` | number | 上次报告时间戳 |

---

## 5. 网络引擎

### 5.1 Nftables 规则结构

```
table inet port_monitor {
    set blocked_ports { type inet_service; }     # 封禁端口集合

    chain input  { type filter hook input priority -5; }   # 先于 UFW
    chain output { type filter hook output priority -5; }

    # 每端口规则 (以 10086 为例):
    counter cnt_in_10086                          # 入站计数器
    counter cnt_out_10086                         # 出站计数器

    # input 链:
    tcp dport 10086 counter name "cnt_in_10086"   # TCP 入站计数
    udp dport 10086 counter name "cnt_in_10086"   # UDP 入站计数

    # output 链:
    tcp sport 10086 counter name "cnt_out_10086" meta mark set 10086  # 计数+打标
    udp sport 10086 counter name "cnt_out_10086" meta mark set 10086

    # 封禁规则 (优先):
    input  tcp dport @blocked_ports drop
    input  udp dport @blocked_ports drop
    output tcp sport @blocked_ports drop
    output udp sport @blocked_ports drop
}
```

**优先级 -5**：确保在 UFW / firewalld (优先级 0) 之前计数。

### 5.2 TC 限速结构

```
qdisc: HTB root handle 1: (default fffe)
├── class 1:fffe  htb rate 1000mbit    # 默认通道 (不限速)
├── class 1:276e  htb rate 100mbit     # 端口 10086 (hex=276e) → 100Mbps
│   └── filter: fw handle 0x276e → flowid 1:276e   # IPv4
│   └── filter: fw handle 0x276e → flowid 1:276e   # IPv6
└── class 1:4e20  htb rate 5mbit       # 端口 20000 (hex=4e20) → 5Mbps (惩罚)
```

**工作原理**：NFT output 链对匹配端口打 mark → TC fw filter 识别 mark → 转入对应 class → HTB 限速。

**默认 class ID**：使用 `0xfffe`（端口 65534），避免与实际监控端口的 hex 值冲突。

---

## 6. Cron 守护进程

### 6.1 执行流程

每分钟 Cron 触发 `pm --monitor`，执行 `cron_task()`：

```
cron_task()
├── flock -n 单例锁 (防并发堆积)
├── 检查 USER_EDIT_LOCK (避让菜单操作)
├── 规则自愈 (nft 表不存在则重建)
├── 遍历所有端口:
│   ├── 读取内核计数器 (nft -j)
│   ├── 计算 delta = 当前值 - 上次值
│   ├── 累加到 acc_in / acc_out
│   ├── DynQoS 判定:
│   │   ├── 惩罚中 → 检查是否到期 → 恢复
│   │   └── 未惩罚 → 检查速率 → 累计 strike → 触发惩罚
│   ├── 配额自动重置 (到期日检测)
│   └── 配额阈值通知 (逐级: 50% → 80% → 100% → 封禁)
├── 写回 config.json (flock 原子写入)
└── 定时流量报告 (检查间隔是否到达)
```

### 6.2 流量采集原理

```
                    Cron T=0             Cron T=1             Cron T=2
内核计数器:          1000                 1500                 1800
last_kernel:        (初始化=1000)         1000                 1500
delta:              0                    500                  300
acc (累计):         0                    500                  800
```

- 内核计数器是**单调递增**的绝对值
- 每次 Cron 计算 `delta = 当前值 - last_kernel`
- delta 累加到 `acc_in` / `acc_out`
- 更新 `last_kernel` 为当前值
- **nft 计数器重置**（如重启）：delta 为负数时按 0 处理

### 6.3 DynQoS 状态机

```
        ┌──────────────┐
        │   正常状态    │
        │ strike_count │
        └──────┬───────┘
               │ 速率 > trigger_mbps
               │ (连续 trigger_time 分钟)
               ▼
        ┌──────────────┐
        │   惩罚状态    │ → 应用 punish_mbps 限速
        │ is_punished  │ → 发送 tg_notify_punish
        └──────┬───────┘
               │ 到达 punish_end_ts
               ▼
        ┌──────────────┐
        │   恢复状态    │ → 恢复原始限速
        │ strike=0     │ → 发送 tg_notify_recover
        └──────────────┘
```

---

## 7. Telegram 通知

### 7.1 通知类型

| # | 类型 | 图标 | 触发条件 | 发送模式 |
|---|------|------|---------|---------|
| 1 | 配额预警 | ⚠️/🔴 | 流量达到阈值 (默认 50%/80%/100%) | 逐级，每级只发一次 |
| 2 | 端口封禁 | 🚫 | 流量超 100%，端口被 drop | 封禁时发一次 |
| 3 | 惩罚触发 | ⚡ | DynQoS 连续超标达标 | 每轮惩罚发一次 |
| 4 | 惩罚恢复 | ✅ | 惩罚期到期 | 恢复时发一次 |
| 5 | 配额重置 | 🔄 | 到达每月重置日 | 重置时发一次 |
| 6 | 定时报告 | 📋 | 用户设置的间隔到达 | 每 N 小时 |
| 7 | 测试消息 | 🔔 | 用户手动发送 | 手动 |

### 7.2 通知标识格式

标识字段优先级：`hostname + (端口备注)` → `hostname` → `公网 IP`

```
有备注:  HK-Node1 (Snell)
无备注:  HK-Node1
hostname=localhost 且无备注:  1.2.3.4
```

### 7.3 通知模板示例

**配额预警** (阈值 80%):
```
⚠️ *端口流量预警*
🏷 标识: *HK-Node1 (Snell)*
🔌 端口: `10086`
📊 已用: 8.1GB / 10GB (*81.0%*)
📋 模式: 双向
⏰ 状态: 已超过 *80%* 阈值
```

**端口封禁**:
```
🚫 *端口已封禁*
🏷 标识: *HK-Node1 (Snell)*
🔌 端口: `10086`
📊 流量配额已耗尽，端口已被封禁
🔄 重置策略: 每月 1 日自动重置
```

**DynQoS 惩罚触发**:
```
⚡ *动态限速触发*
🏷 标识: *HK-Node1 (Snell)*
🔌 端口: `10086`
📈 平均速率: 120.50 Mbps (阈值 100 Mbps)
📉 已降速至: *5 Mbps*
⏱ 持续时间: 60 分钟
```

**定时流量报告**:
```
📋 *定时流量报告*
🖥 主机: `HK-Node1`
⏰ 2026-02-10 14:00

✅ `10086` Snell
   4.2GB / 10GB (42.0%)

⚠️ `20000` SS
   8.1GB / 10GB (81.0%) 🔒100M

⚡ `30000` VMess
   6.5GB / 10GB (65.0%) ⚡5M

🚫 `40000` Trojan
   10.2GB / 10GB (102.0%)
```

报告状态图标：✅ 正常 (<80%) / ⚠️ 警告 (≥80%) / ⚡ DynQoS 惩罚中 / 🚫 已封禁。限速标记：🔒100M 基础限速 / ⚡5M 惩罚限速。

### 7.4 Telegram 配置菜单

```
========================================
   Telegram 通知配置
========================================
 状态:   ✅ 已启用
 Token:  123456...wxyz
 ChatID: -1001234567890
 API:    https://api.telegram.org
 阈值:   50, 80, 100 (%)
 定时报告: 每 6 小时
========================================
 1. 配置 Bot Token
 2. 配置 Chat ID
 3. 发送测试消息
 4. 开启/关闭 通知
 5. 修改 通知阈值
 6. 修改 API 地址 (国内反代)
 7. 配置 定时流量报告
 0. 返回主菜单
========================================
```

---

## 8. 文件与路径

| 路径 | 用途 | 持久性 |
|------|------|--------|
| `/usr/local/bin/pm` | 脚本主体 + 快捷命令 | 永久 |
| `/etc/port_monitor/config.json` | 所有配置和运行状态 | 永久 |
| `/var/run/pm.lock` | flock 写入锁 (FD 200) | 运行时 |
| `/var/run/pm_cron.lock` | flock cron 单例锁 (FD 9) | 运行时 |
| `/tmp/pm_user_editing` | 菜单编辑锁 (文件存在即生效) | 运行时 |

---

## 9. 安全机制

### 9.1 安装更新安全

`install_shortcut` 和 `update_script` 均使用**临时文件安全模式**：

```
curl → mktemp 临时文件 → 校验非空(-s) → mv 覆盖 → exec 重载
```

中途断网时：临时文件被截断，但 `/usr/local/bin/pm` 不受影响，Cron 继续正常运行。

### 9.2 卸载保护

卸载需输入完整的 `yes`（非 `y`），防止误触。卸载操作：清 crontab → 删 TC/NFT 规则 → 删配置目录 → 删脚本。

### 9.3 临时文件清理

全局 `_global_cleanup` trap 在 EXIT/INT/TERM 时自动清理所有注册的临时文件。菜单模式额外清理 `USER_EDIT_LOCK`，Cron 模式不删（防止误删菜单进程的锁）。

---