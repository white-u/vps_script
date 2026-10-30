# 项目导览

[文档索引](INDEX.md) · [使用入口](README.md) · [开发与验证](DEVELOPMENT.md)

## 运行模型

本项目没有常驻 Web 面板，也没有统一的配置数据库。各 Bash 管理脚本独立安装、生成服务配置并管理自己的文件。`vt` 是交互调度入口：首次下载缺少的组件脚本，校验后执行，展示状态并提供统一卸载。

`vt` 调度 Snell、sing-box、PM、FW。`x-sb.sh`、`init.sh`、`network_audit.sh` 独立运行，不属于工具箱统一管理与卸载范围。不要直接 source 管理脚本做库调用：脚本包含安装、检查及菜单入口。

典型流程是先初始化 VPS，再按需安装代理或转发服务；PM 可扫描已有服务，也可手动指定端口监控。PM 的云端推送是可选能力，未部署 Worker 不影响本地配额管理。

## 文件与职责

| 文件 | 职责 | 持久化或服务位置 |
| --- | --- | --- |
| [vt.sh](vt.sh) | 下载、派发、状态、跨组件卸载 | `/usr/local/bin/vt` 及组件快捷命令 |
| [snell.sh](snell.sh) | 多端口实例、核心版本发现、更新事务与恢复 | `/etc/snell/`、`/usr/local/bin/snell-server`、`snell@.service` |
| [sb.sh](sb.sh) | sing-box Reality / SS2022、元数据、核心检查与回滚 | `/usr/local/etc/sing-box/`、`/var/lib/sing-box/`；systemd 或 OpenRC |
| [x-sb.sh](x-sb.sh) | 独立 Xray 节点和链式代理 | `/usr/local/etc/xray/`、`/usr/local/share/xray/`、`xray.service` |
| [fw.sh](fw.sh) | Realm 转发、规则元数据、监听检查、失败恢复 | `/etc/realm/config.toml`、`/etc/realm/fw.json`、`realm.service` |
| [pm.sh](pm.sh) | 端口计数、配额、分组、TC、Cron、通知和推送 | `/etc/port_monitor/`、`/var/log/port_monitor.log` |
| [worker.js](worker.js) | 签名接收、Telegram 查询授权和写操作去重 | Cloudflare D1：`nodes`、`users`、`telegram_updates` |
| [init.sh](init.sh) | APT、时区和校时、地址优先级、BBR、SSH 事务 | `/etc/gai.conf`、`/etc/sysctl.d/99-vps-init-bbr.conf`、SSH 配置与备份 |
| [network_audit.sh](network_audit.sh) | 地址查询、延迟和大包检测、iperf3 双向带宽与重传、回程命令 | 交互诊断脚本；下载外部工具前校验输入和脚本 |

sing-box 的 `nodes_meta.json` 在核心配置外保存管理所需元数据；备份时不能只保存 `config.json`。各组件的完整路径和恢复操作以对应手册为准。

## PM 数据与规则链路

1. 交互入口安装依赖，并在后台锁保护下初始化配置、恢复规则。后台 `--monitor` 和查询 `--ipl` 入口复用已安装依赖，拒绝缺失、损坏或不支持的配置。
2. nftables 的 `inet port_monitor` 表保存端口计数和配额封禁规则。后台按完整内核快照计算增量，将累计和基线写到独立状态文件。
3. `cron_task` 处理周期重置、分组配额、封禁、突发策略、IP 告警和到期提醒，并按配置发送本机 Telegram 通知、推送 Worker。
4. 连续有效采样中的出站速率严格超过 300 Mbps，累计达到 20 分钟后，限制为 50 Mbps、持续 5 分钟；无效或不连续采样会打断高流量累计。具体判定见 `_update_burst_state` 和 [PM 手册](PM_DOC.md)。仅在限速期创建自有 TC 队列；归属文件 `tc_root_owned` 用于恢复和卸载，不能随意删除。

配置版本为 `6`，端口状态版本为 `2`。`1.0.0` 是脚本发行版本，不等于数据格式版本。旧格式保留原文件并报错，不静默迁移或重置为零。

`/var/run/pm_cron.lock` 的 flock 负责后台与编辑互斥；`/tmp/pm_user_editing` 只是编辑标记。统一卸载保留空的后台锁文件，避免重装和已启动任务锁住不同文件。修改锁逻辑须同时检查菜单、Cron、卸载和重装路径。

## Worker 通信与权限

`PM → PUT /api/push → D1 → Telegram 查询`。请求携带 `X-Node`、`X-Timestamp`、`X-Signature`；签名内容是 `nodeKey + 换行 + timestamp + 换行 + 原始 body`，算法为 HMAC-SHA256，时间容差为 120 秒。HMAC 用于认证和完整性，传输保密依赖 HTTPS。

`POST /webhook` 验证 Telegram 的 `X-Telegram-Bot-Api-Secret-Token`。管理员权限来自 `ADMIN_ID`，普通用户按 D1 的节点和端口授权查询。`telegram_updates` 保存管理员写操作的去重记录，部署时必须建表。Worker 不是 PM 调度器，只接收快照和响应查询；到期前提醒由 VPS 上的 PM 发送。

所需绑定与变量为 `DB`、`SHARED_SECRET`、`BOT_TOKEN`、`ADMIN_ID`、`TELEGRAM_WEBHOOK_SECRET`，部署及 SQL 见 [中控部署](部署教程.md)。仓库没有 Wrangler 工程或自动部署配置。

## 修改时需要一起看的位置

| 修改内容 | 关联位置 |
| --- | --- |
| 安装路径、服务名、防火墙或账户归属 | 对应组件 + vt 的状态与卸载分支 |
| PM 配置、状态或突发策略 | 读写校验、交互编辑、cron_task、规则恢复、Worker 展示、PM_DOC |
| Worker 上报字段或签名 | pm.sh 的 push_to_worker + worker.js 的 handlePush + 部署 SQL |
| 管理脚本更新与核心更新 | 分别检查下载校验、版本比较、备份恢复；两条更新链路不能混用 |
| SSH 初始化 | 生效配置解析、公钥验证、重载、新连接确认、信号与回滚路径 |

服务更新成功应由配置检查和实际运行状态确认。卸载失败保留诊断及重试资源；FW 不自动修改防火墙。当前平台支持及实机验证边界见 [README](README.md)，不要从通用兼容性列表推断所有模块均已通过同等验收。
