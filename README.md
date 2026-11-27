# VPS Toolbox

面向 Linux VPS 的管理脚本集，涵盖代理服务、端口转发、流量配额、系统初始化和网络检测。

## 快速开始

在 VPS 上以 root 打开 Bash。Debian/Ubuntu 如缺少 `curl`，先运行 `apt-get update && apt-get install -y curl ca-certificates`。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/vt.sh)
```

运行 `vt`，按需选择 Snell、sing-box、PM 或 FW。首次进入组件会安装缺少的核心或依赖。

## 功能与文档

| 功能 | 入口 | 说明 |
| --- | --- | --- |
| 工具箱 | [vt.sh](vt.sh) · `vt` | 安装和启动组件、查看运行状态、统一卸载。 |
| Snell | [snell.sh](snell.sh) · `snell` | 基于 systemd 管理多个 Snell 实例。[使用手册](SNELL_DOC.md) |
| sing-box | [sb.sh](sb.sh) · `sb` | 管理 Reality 和 Shadowsocks-2022 节点，支持核心更新和回滚。[使用手册](SB_DOC.md) |
| 端口流量管理 | [pm.sh](pm.sh) · `pm` | 端口流量统计、共享配额、封禁、突发限速、IP 告警和用户到期提醒。[使用手册](PM_DOC.md) |
| TCP/UDP 转发 | [fw.sh](fw.sh) · `fw` | 使用 Realm 管理转发规则，提供连通性检测。[使用手册](FW_DOC.md) |
| Xray | [x-sb.sh](x-sb.sh) · `x-sb` | 管理 Reality、Shadowsocks-2022 和链式代理。[使用手册](X-SB_DOC.md) |
| 每日流量调节 | [tb.sh](tb.sh) · `tb` | 根据 vnStat 当天统计按比例限额补充入站下载。[安装与配置](TRAFFIC_BALANCE_DOC.md) |
| 系统初始化 | [init.sh](init.sh) | 安装基础工具，配置校时、时区、地址优先级、BBR 和 SSH。[系统初始化](#系统初始化) |
| 网络检测 | [network_audit.sh](network_audit.sh) | 测量延迟、丢包和双向吞吐，分析去程并生成回程检测命令。[网络检测](#网络检测) |
| 云端中控 | [worker.js](worker.js) | 接收多台 VPS 的 PM 上报，通过 Telegram Bot 按授权查询。[Cloudflare 部署指南](部署教程.md) |

Snell、sing-box、PM 和 FW 也可直接安装和运行。Xray、每日流量调节、系统初始化、网络检测及云端中控各有独立入口。

## 系统初始化

在使用 systemd 的 Debian/Ubuntu VPS 上，以 root 在 Bash 4+ 中运行。精简系统如缺少 `curl`，先按[快速开始](#快速开始)安装。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/init.sh)
```

- 优先复用现有 chrony/NTP 服务，缺少时安装 `systemd-timesyncd`。时区按出口公网 IP 推断，查询失败则保留原时区。
- 地址优先级可选 IPv4 或 IPv6，默认 IPv4。脚本仅调整 glibc 地址排序，修改前备份 `/etc/gai.conf`。
- BBR 设置写入 `/etc/sysctl.d/99-vps-init-bbr.conf`，脚本会检查内核实际运行参数。
- SSH 可修改端口、导入 root 公钥并选择禁用密码。禁用密码需要有效公钥，SSH socket 激活模式暂不支持修改端口。脚本检查 SSH 生效配置及监听状态，备份位于 `/etc/ssh/init-backup.*`。修改后请先保留当前会话，再从另一终端确认新连接。

## 网络检测

在中转机的 Bash 中运行，然后输入落地机 IP 或域名。路由检测需要 NextTrace 或 `traceroute`。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/network_audit.sh)
```

脚本显示延迟、丢包和去程路由，并输出回程检测命令。测吞吐时，中转机需安装 `iperf3`，落地机需运行 `iperf3 -s`。

## 平台与卸载

- 常用平台为 Debian 10+ 和 Ubuntu 20.04+，架构为 amd64 和 arm64。各组件的系统、服务管理器及核心版本要求见对应手册。
- sing-box 支持 Alpine 3.21 和 OpenRC。精简 Alpine 系统需先安装 Bash 和 curl。
- `vt` 的“全部卸载”只处理 Snell、sing-box、PM、FW 和工具箱自身，需要输入 `yes` 确认。某个组件清理失败时会继续处理其他组件，并保留工具箱供重试。
- 卸载前请备份需要保留的配置、节点密钥和流量记录。
