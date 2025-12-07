# VPS 代理服务统一管理平台

> 一键安装、配置和管理代理服务的 Shell 脚本集合，支持 Snell、sing-box 和流量监控。

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-bash-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://www.linux.org/)

---

## 📖 目录

- [项目简介](#项目简介)
- [快速开始](#快速开始)
- [VPS 统一管理平台](#vps-统一管理平台-vpssh)
- [Snell Server 管理](#snell-server-管理-snellsh)
- [sing-box 管理](#sing-box-管理-sing-boxsh)
- [流量监控](#流量监控-port-managesh)
- [自动流量监控集成](#自动流量监控集成)
- [常见问题](#常见问题)
- [版本历史](#版本历史)

---

## 🎯 项目简介

本项目提供了一套完整的 VPS 代理服务管理解决方案，整合了多个独立脚本，实现了：

- 🎯 **统一管理入口** - 一个命令管理所有服务
- 📊 **实时状态监控** - 查看所有服务状态和流量统计
- 🔄 **自动流量统计** - 创建代理时自动添加流量监控
- 🔍 **健康检查** - 自动检测端口监听和规则完整性
- 📦 **组件化设计** - 各模块独立运行，也可统一管理

### 📦 核心组件

| 组件 | 功能 | 主要用途 |
|------|------|----------|
| **vps.sh** | 统一管理平台 | 整合所有功能的统一入口 |
| **Snell.sh** | Snell Server 管理 | Surge 专用代理协议 |
| **sing-box.sh** | sing-box 管理 | 多协议代理平台（VLESS-Reality / Shadowsocks） |
| **port-manage.sh** | 流量监控 | 端口流量统计、限速、告警 |

### ✨ 核心特性

- ✅ **自动流量监控** - 创建代理时自动添加到流量统计（无限制模式）
- ✅ **智能联动** - 修改/删除代理时自动同步流量监控
- ✅ **状态总览** - 一屏查看所有服务状态和流量
- ✅ **健康检查** - 自动检测端口监听和 nftables 规则
- ✅ **防火墙自动化** - 自动配置 ufw/firewalld
- ✅ **BBR + TFO** - 自动启用网络优化
- ✅ **完整文档** - 详细的使用说明和故障排查

---

## 🚀 快速开始

### 推荐方式：统一管理平台

```bash
# 安装 VPS 统一管理平台（会自动引导安装其他组件）
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/vps.sh)

# 安装后可用命令
vps              # 主菜单（交互式）
vps status       # 查看所有服务状态
vps health       # 健康检查
```

### 传统方式：独立安装

```bash
# 1. 安装流量监控（可选，但推荐先安装）
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/port-manage.sh)

# 2. 安装 Snell Server
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/Snell.sh)

# 3. 安装 sing-box
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh)

# 4. 使用统一管理（可选）
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/vps.sh)
```

### 系统要求

- **操作系统**: Ubuntu 20.04+ / Debian 10+ / CentOS 7+
- **权限**: root 或 sudo
- **内核**: Linux 4.9+（建议，用于 BBR）
- **依赖**: curl, wget, jq（自动安装）

---

## 🎛️ VPS 统一管理平台 (vps.sh)

### 功能介绍

`vps.sh` 是整合所有功能的统一管理入口，提供：

- 📊 **状态总览** - 实时查看所有服务状态、端口、流量
- 🔍 **健康检查** - 自动检测服务和端口监听状态
- 🚀 **快捷命令** - 直接跳转到各个管理模块
- 📦 **组件安装** - 一键安装缺失的组件
- 🗑️ **一键卸载** - 完整清理所有组件和配置
- 🎯 **智能检测** - 自动识别已安装的服务

### 命令列表

#### 主菜单模式

```bash
vps              # 显示主菜单（交互式）
```

**菜单选项：**
- `[1]` Snell 管理
- `[2]` sing-box 管理
- `[3]` 流量监控
- `[4]` 刷新状态
- `[5]` 健康检查
- `[6]` 安装缺失组件
- `[7]` 一键卸载所有组件
- `[0]` 退出

#### 快捷命令

```bash
vps status       # 显示所有服务状态总览（别名: s）
vps health       # 执行健康检查（别名: h）
vps snell        # 直接进入 Snell 管理
vps sb           # 直接进入 sing-box 管理（别名: singbox）
vps traffic      # 直接进入流量监控（别名: ptm）
vps install      # 安装缺失的组件
vps uninstall    # 一键卸载所有组件
vps version      # 显示版本（别名: v）
vps help         # 显示帮助
```

### 使用示例

#### 查看状态总览

```bash
vps status
```

**输出示例：**
```
════════════════════════════════════════════════════════
          VPS 代理统一管理平台 v1.0.0
════════════════════════════════════════════════════════

📡 Snell Server
  状态: ● 运行中
  端口: 30001
  流量: 2.5GB

🚀 sing-box
  状态: ● 运行中
  配置:
    443     (vless)              流量: 1.8GB
    8388    (shadowsocks)        流量: 0.9GB

📊 流量监控
  状态: 已安装
  监控端口数: 3
```

#### 健康检查

```bash
vps health
```

**输出示例：**
```
🔍 系统健康检查

✓ Snell 端口 30001 正常监听
✓ sing-box 端口 443 (vless) 正常监听
✓ sing-box 端口 8388 (shadowsocks) 正常监听
✓ 流量监控 nftables 规则正常

✓ 所有检查通过！
```

#### 一键卸载

```bash
vps uninstall
```

**功能说明：**
- 卸载所有已安装的组件（Snell、sing-box、port-manage、vps）
- 清理所有配置文件、服务、防火墙规则
- 清理 nftables 规则、tc 规则、流量统计数据
- 移除网络优化设置（sysctl）
- 删除定时任务（crontab）

**安全机制：**
- 需要输入 `YES`（区分大小写）确认
- 显示所有将被卸载的组件
- 详细的警告提示，防止误操作

**清理范围：**
```
Snell Server:
  - systemd 服务
  - 二进制文件和配置
  - 防火墙规则（ufw + firewalld）
  - 网络优化设置

sing-box:
  - systemd 服务
  - 所有配置和日志
  - 所有端口的防火墙规则
  - 网络优化设置

port-manage:
  - crontab 定时任务
  - nftables 规则表
  - tc 流控规则
  - ifb0 虚拟网卡
  - 所有配置文件

VPS 管理平台:
  - /usr/local/bin/vps 命令
```

---

## 📡 Snell Server 管理 (Snell.sh)

### 功能特性

#### 核心功能

- ✅ **一键安装** - 自动检测最新版 Snell v5.x
- ✅ **架构支持** - amd64, i386, aarch64, armv7l
- ✅ **自动配置** - 节点名称、端口、PSK
- ✅ **版本管理** - 检测更新、一键升级、回滚支持
- ✅ **配置修改** - 端口、节点名、PSK 在线修改
- ✅ **防火墙自动化** - ufw/firewalld 自动配置
- ✅ **网络优化** - TCP Fast Open + BBR
- ✅ **日志管理** - 查看、跟踪、清空日志
- ✅ **备份回滚** - 自动备份配置和二进制
- ✅ **快捷命令** - 25+ 命令支持

#### 自动流量监控

- ✅ **安装时自动添加** - 端口自动注册到流量监控
- ✅ **修改时自动同步** - 旧端口移除，新端口添加
- ✅ **卸载时自动清理** - 自动移除流量监控配置

### 安装使用

```bash
# 安装 Snell
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/Snell.sh)

# 快捷命令（安装后可用）
snell                # 进入菜单
snell status         # 查看状态
snell install        # 安装
snell uninstall      # 卸载
snell update         # 更新
snell restart        # 重启
```

### 命令参考

#### 服务控制

```bash
snell start          # 启动服务
snell stop           # 停止服务
snell restart        # 重启服务
snell status         # 查看状态
```

#### 配置管理

```bash
snell change-port    # 修改端口
snell change-name    # 修改节点名称
snell change-psk     # 修改 PSK
snell info           # 显示配置信息
snell config         # 显示 Surge 配置
```

#### 版本管理

```bash
snell update         # 更新到最新版
snell version        # 显示版本
snell reinstall      # 重新安装
```

#### 日志管理

```bash
snell log            # 查看最近 50 行日志
snell log 100        # 查看最近 100 行日志
snell log-f          # 实时跟踪日志
snell log-clear      # 清空日志
```

#### 系统优化

```bash
snell enable-tfo     # 启用 TCP Fast Open
snell disable-tfo    # 禁用 TCP Fast Open
```

### 配置文件位置

```
/etc/snell/
├── snell-server.conf    # 主配置文件
├── config.txt           # Surge 配置
├── ver.txt              # 版本记录
└── node_name.txt        # 节点名称

/usr/local/bin/
├── snell-server         # Snell 二进制
└── snell-manager.sh     # 管理脚本

/var/backups/snell-manager/  # 备份目录
```

---

## 🚀 sing-box 管理 (sing-box.sh)

### 功能特性

#### 核心功能

- ✅ **多协议支持** - VLESS-Reality, Shadowsocks
- ✅ **一键安装** - 自动下载最新版
- ✅ **配置管理** - 添加、删除、修改配置
- ✅ **在线修改** - 端口、UUID、密码、SNI
- ✅ **防火墙自动化** - 自动配置规则
- ✅ **版本缓存** - 1 小时缓存，减少请求
- ✅ **重启验证** - 启动失败自动提示
- ✅ **快捷命令** - 简化日常操作

#### 自动流量监控

- ✅ **创建配置时自动添加** - 新端口自动监控
- ✅ **删除配置时自动移除** - 自动清理监控
- ✅ **修改端口时自动同步** - 旧端口移除，新端口添加

### 支持协议

#### VLESS-Reality

- ✅ 自动生成密钥对（公钥/私钥）
- ✅ 自动生成 Short ID
- ✅ 可自定义 SNI（默认 www.time.is）
- ✅ 支持在线修改 SNI

#### Shadowsocks

- ✅ 支持加密方式：
  - 2022-blake3-aes-128-gcm
  - 2022-blake3-aes-256-gcm
  - 2022-blake3-chacha20-poly1305
- ✅ 自动生成密码
- ✅ 支持在线修改密码

### 安装使用

```bash
# 安装 sing-box
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh)

# 快捷命令（安装后可用）
sing-box             # 进入菜单
sing-box add         # 添加配置
sing-box del         # 删除配置
sing-box info        # 查看配置信息
sing-box change      # 修改配置
```

### 命令参考

#### 配置管理

```bash
sing-box add         # 添加配置（交互式选择协议）
sing-box add vless   # 直接添加 VLESS-Reality 配置
sing-box add ss      # 直接添加 Shadowsocks 配置
sing-box del         # 删除配置
sing-box info        # 查看配置信息
sing-box change      # 修改配置
```

#### 服务控制

```bash
sing-box start       # 启动服务
sing-box stop        # 停止服务
sing-box restart     # 重启服务
sing-box status      # 查看状态
sing-box log         # 查看日志
```

#### 修改选项

进入 `sing-box change` 后可修改：

- `[1]` 修改端口
- `[2]` 修改凭证（UUID / 密码）
- `[3]` 修改 SNI（仅 VLESS-Reality）

### 配置文件位置

```
/etc/sing-box/
├── config.json          # 主配置文件
└── conf/                # 配置文件目录
    ├── vless-001.json   # VLESS 配置
    └── ss-001.json      # Shadowsocks 配置

/etc/sing-box/bin/
└── sing-box             # sing-box 二进制

/var/log/sing-box/       # 日志目录
```

---

## 📊 流量监控 (port-manage.sh)

### 功能介绍

`port-manage.sh` 提供端口级别的流量监控和管理功能。

#### 核心能力

- ✅ **流量统计** - 基于 nftables 的精确统计
- ✅ **带宽限制** - 基于 tc 的速率控制（Kbps/Mbps/Gbps）
- ✅ **流量配额** - 月度/总量配额管理
- ✅ **计费模式** - 单向（仅出站）或双向（入站+出站）
- ✅ **突发保护** - 检测异常流量并自动限速
- ✅ **Telegram 通知** - 多级阈值告警（30% / 50% / 80% / 100%）
- ✅ **定时任务** - 自动流量检查和告警
- ✅ **历史记录** - 流量数据持久化

### 使用方法

```bash
# 安装流量监控
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/port-manage.sh)

# 快捷命令（安装后可用）
ptm                  # 进入菜单
ptm --reset 8443     # 重置端口流量
ptm --notify         # 发送状态通知
ptm --check-alert    # 检查阈值告警
```

### 主要功能

#### 1. 添加端口监控

```bash
ptm  # 进入菜单，选择 [1] 添加端口监控
```

**配置选项：**
- 端口号（支持单个、多个、范围）
- 计费模式（单向/双向）
- 流量配额（如 100GB，留空为无限制）
- 每月重置日（1-31 日）
- 带宽限制（如 100Mbps，留空为无限制）
- 备注说明

#### 2. 带宽限制

支持的速率单位：
- Kbps - 如 `5000Kbps`
- Mbps - 如 `100Mbps`
- Gbps - 如 `1Gbps`

#### 3. 流量配额

支持的流量单位：
- KB, MB, GB, TB - 如 `1TB`, `500GB`
- 自动补全单位（输入 `100` 默认为 `100GB`）

#### 4. Telegram 通知

配置 Telegram Bot 后可实现：
- 流量阈值告警（30% / 50% / 80% / 100%）
- 每日流量报告
- 突发流量警告
- 配额耗尽通知

**配置方式：**
```bash
ptm  # 进入菜单，选择 [8] Telegram 通知设置
```

需要提供：
- Bot Token（从 @BotFather 获取）
- Chat ID（从 @userinfobot 获取）
- 服务器名称（可选）

#### 5. 突发保护

自动检测异常流量并限速：

```bash
ptm  # 进入菜单，选择 [7] 突发速率保护
```

**配置选项：**
- 突发阈值（如 `1Gbps`）
- 检测窗口（秒，如 `30`）
- 限速速率（如 `10Mbps`）
- 限速时长（分钟，如 `10`）

### 配置文件位置

```
/etc/port-traffic-monitor/
├── config.json          # 主配置文件
├── traffic_data.json    # 流量数据
├── alert_state.json     # 告警状态
├── burst_state.json     # 突发保护状态
└── traffic_history/     # 历史记录目录

快捷命令: /usr/local/bin/ptm
```

---

## 🔄 自动流量监控集成

### 工作原理

当安装了 `port-manage.sh` 后，`Snell.sh` 和 `sing-box.sh` 会**自动**将代理端口添加到流量监控。

```
创建代理 (Snell/sing-box)
         │
         ▼
    检测 port-manage.sh
         │
         ├─→ 未安装 → 静默跳过
         │
         └─→ 已安装
             │
             ▼
        添加到配置文件
        /etc/port-traffic-monitor/config.json
             │
             ▼
        添加 nftables 计数器规则
        - port_XXXXX_in  (入站流量)
        - port_XXXXX_out (出站流量)
             │
             ▼
        ✓ 完成，开始统计流量
```

### 支持场景

| 操作 | Snell.sh | sing-box.sh | port-manage.sh |
|------|----------|-------------|----------------|
| **安装/创建配置** | ✅ 自动添加 | ✅ 自动添加 | - |
| **修改端口** | ✅ 自动同步 | ✅ 自动同步 | - |
| **删除配置** | - | ✅ 自动移除 | - |
| **卸载** | ✅ 自动移除 | - | - |

### 配置说明

**默认配置：**
- **计费模式**: `single`（仅统计出站流量）
- **流量配额**: `unlimited`（不限制）
- **带宽限速**: `unlimited`（不限制）
- **备注**: 自动生成（如 "Snell Server", "sing-box (VLESS-Reality)"）

**查看监控：**
```bash
# 方式 1: 使用 vps 统一平台
vps status       # 自动显示流量统计

# 方式 2: 使用 ptm 详细查看
ptm              # 进入流量监控菜单
```

**手动配置限制：**

如果需要设置配额或限速，在 `ptm` 菜单中：
1. 选择 `[4] 设置带宽限制` 或 `[5] 设置流量配额`
2. 选择端口
3. 输入限制值

### 验证流量监控

```bash
# 查看 nftables 规则
nft list table inet port_monitor

# 查看配置文件
cat /etc/port-traffic-monitor/config.json | jq .

# 查看流量统计
ptm
```

---

## ❓ 常见问题

### 安装相关

#### Q1: 提示 "command not found"

**原因**: 脚本未安装或未在 PATH 中

**解决**:
```bash
# 重新安装
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/vps.sh)

# 或手动检查
which vps
which snell
which sing-box
which ptm
```

#### Q2: 安装失败

**解决**:
```bash
# 检查网络
curl -I https://github.com

# 检查权限
whoami  # 应该显示 root

# 查看详细错误
bash -x <(curl -sL URL)
```

### 流量监控相关

#### Q3: 流量显示 "N/A"

**原因**: port-manage 未安装或未添加端口

**解决**:
```bash
# 1. 安装 port-manage
vps install
# 选择流量监控

# 2. 重新创建代理（会自动添加监控）
# 或修改端口触发自动添加
snell change-port
```

#### Q4: 自动添加监控不工作

**检查**:
```bash
# 1. 检查 jq 是否安装
which jq
# 如果没有，安装：
apt install jq -y    # Debian/Ubuntu
yum install jq -y    # CentOS

# 2. 检查 port-manage 配置文件
ls /etc/port-traffic-monitor/config.json

# 3. 手动测试
snell change-port    # 修改端口触发自动添加
```

### 服务相关

#### Q5: 服务无法启动

**解决**:
```bash
# 查看服务状态
systemctl status snell
systemctl status sing-box

# 查看日志
journalctl -u snell -n 50
journalctl -u sing-box -n 50

# 检查端口占用
ss -tuln | grep 端口号

# 重启服务
systemctl restart snell
systemctl restart sing-box
```

#### Q6: 端口无法访问

**检查**:
```bash
# 1. 检查服务状态
vps health

# 2. 检查防火墙
ufw status
firewall-cmd --list-ports

# 3. 检查端口监听
ss -tuln | grep 端口号

# 4. 手动放行端口
ufw allow 端口号
firewall-cmd --permanent --add-port=端口号/tcp
firewall-cmd --reload
```

### 其他问题

#### Q7: 如何卸载

**推荐方式：一键卸载所有组件**

```bash
vps uninstall
```

这将完整卸载所有已安装的组件（Snell、sing-box、port-manage、vps），并清理所有配置文件、防火墙规则、网络优化设置。

**传统方式：单独卸载**

```bash
# 卸载 Snell
snell uninstall

# 卸载 sing-box
sing-box  # 进入菜单，选择卸载

# 卸载 port-manage
ptm  # 进入菜单，选择 [10] 卸载

# 删除 vps.sh
rm -f /usr/local/bin/vps
```

#### Q8: 如何更新

```bash
# 更新 Snell
snell update

# 更新 sing-box
sing-box  # 进入菜单，选择更新

# 重新下载脚本
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/Snell.sh)
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh)
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/port-manage.sh)
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/vps.sh)
```

---

## 📝 版本历史

### v2.1.0 (2025-12-07)

**新增功能：**
- ✅ 一键卸载所有组件功能
  - 主菜单新增选项 [7] 一键卸载所有组件
  - 命令行支持 `vps uninstall`
  - YES 确认机制（区分大小写，防止误操作）
  - 完整清理所有服务、配置、防火墙规则
  - 清理 nftables 规则、tc 规则、流量统计数据
  - 移除网络优化设置（sysctl）
  - 删除定时任务（crontab）

**文档更新：**
- ✅ README.md 添加一键卸载使用说明
- ✅ 更新快捷命令列表
- ✅ 更新常见问题 Q7（推荐使用一键卸载）

### v2.0.0 (2025-12-07)

**新增功能：**
- ✅ VPS 统一管理平台（vps.sh）
  - 状态总览
  - 健康检查
  - 快捷命令
  - 组件管理

**自动流量监控集成：**
- ✅ Snell.sh 自动添加/移除流量监控
- ✅ sing-box.sh 自动添加/移除流量监控
- ✅ 默认仅统计，不限制（quota/rate = unlimited）
- ✅ 静默失败（未安装 port-manage 时自动跳过）

**优化改进：**
- ✅ Snell.sh 快捷命令修复
- ✅ sing-box.sh SNI 修改功能
- ✅ 完整的测试脚本和文档

### v1.0.0 (早期版本)

- ✅ Snell.sh 基础功能
- ✅ sing-box.sh 基础功能
- ✅ port-manage.sh 流量监控

---

## 📄 许可证

MIT License

---

## 🔗 相关链接

- [Snell Server 官网](https://manual.nssurge.com/others/snell.html)
- [sing-box 官网](https://sing-box.sagernet.org/)
- [nftables 文档](https://wiki.nftables.org/)

---

## 🙏 致谢

感谢所有开源项目和贡献者。

---

**享受便捷的 VPS 管理体验！** 🚀
