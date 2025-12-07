# VPS 代理服务管理脚本

一键安装、配置和管理代理服务及端口流量监控的 Shell 脚本集合。

---

## 📦 包含脚本

- **Snell.sh** - Snell Server 管理脚本（Surge 专用）
- **sing-box.sh** - sing-box 多协议代理管理脚本（VLESS-Reality / Shadowsocks）
- **port-manage.sh** - 端口流量监控与管理脚本（流量统计 / 限速 / 告警）

---

## 🚀 Snell.sh - 功能特性

### 核心功能

#### 📥 安装与卸载
- ✅ 一键安装最新版 Snell Server（自动检测 v5.x）
- ✅ 支持架构：`amd64`, `i386`, `aarch64`, `armv7l`
- ✅ 自动从官网检测最新版本（带 1 小时缓存）
- ✅ 完整卸载（清理二进制、配置、服务、防火墙规则）

#### ⚙️ 配置管理
- ✅ 交互式配置（节点名称、端口、PSK）
- ✅ 端口设置：手动输入或自动随机（30000-65000）
- ✅ PSK 管理：随机生成或手动指定
- ✅ 自动生成 Surge 配置格式
- ✅ 配置修改支持：
  - 修改端口（自动处理防火墙规则）
  - 修改节点名称
  - 修改 PSK（支持随机生成）

#### 🔄 版本管理
- ✅ 自动检测官网最新版本
- ✅ 版本缓存机制（1 小时有效期）
- ✅ 一键更新到最新版
- ✅ 更新前自动备份
- ✅ 更新失败自动回滚
- ✅ 强制重装选项

#### 🔥 防火墙自动化
- ✅ 自动识别并配置 `ufw` / `firewalld`
- ✅ 安装时自动放行端口
- ✅ 修改端口时自动回收旧端口并放行新端口
- ✅ 卸载时自动清理防火墙规则

#### 🌐 网络优化
- ✅ TCP Fast Open 自动启用（内核 3.x+）
- ✅ BBR 拥塞控制（内核 4.9+）
- ✅ 完整的 sysctl 网络参数优化：
  - 文件句柄优化（`fs.file-max = 51200`）
  - TCP 缓冲区优化
  - 连接队列优化
  - MTU 探测
- ✅ 专用配置文件：`/etc/sysctl.d/99-snell.conf`
- ✅ 一键启用/禁用网络优化

#### 📊 日志管理
- ✅ 查看最近 N 行日志（可指定行数）
- ✅ 实时查看日志（`tail -f` 模式）
- ✅ 清空日志
- ✅ 日志文件：`/var/log/snell.log`
- ✅ Fallback：`journalctl -u snell`

#### 💻 命令行界面
- ✅ **交互式菜单模式**（无参数运行）
- ✅ **命令行快捷模式**（支持所有操作）
- ✅ 快捷命令：`snell <command>`
- ✅ 软链接自动创建：`/usr/local/bin/snell`

#### 🛡️ 安全与稳定
- ✅ systemd 服务管理
- ✅ 非特权用户运行（`snell:snell`）
- ✅ Capability 限制（`CAP_NET_BIND_SERVICE` 等）
- ✅ 自动重启（失败后 5 秒重试）
- ✅ 配置备份与回滚
- ✅ 操作验证与错误处理

---

### 📋 Snell.sh 命令列表

#### 服务管理
```bash
snell start          # 启动 Snell 服务
snell stop           # 停止 Snell 服务
snell restart        # 重启 Snell 服务
snell status         # 查看服务状态
```

#### 配置管理
```bash
snell install        # 安装 Snell
snell uninstall      # 卸载 Snell
snell update         # 更新 Snell
snell info           # 查看配置信息
snell config         # 显示 Surge 配置
```

#### 修改配置
```bash
snell change-port    # 修改端口
snell change-name    # 修改节点名称
snell change-psk     # 修改 PSK
```

#### 日志管理
```bash
snell log [n]        # 查看最近 n 行日志（默认 50）
snell log-f          # 实时查看日志
snell log-clear      # 清空日志
```

#### 系统设置
```bash
snell enable-tfo     # 启用 TCP Fast Open + BBR
snell disable-tfo    # 禁用网络优化
snell update-script  # 更新脚本
```

#### 其他
```bash
snell version        # 显示版本信息
snell help           # 显示帮助
```

---

## 🔧 sing-box.sh - 功能特性

### 核心功能

#### 📥 安装与卸载
- ✅ 一键安装最新版 sing-box（GitHub Releases）
- ✅ 自动架构检测
- ✅ 完整卸载（可选清理网络优化配置）

#### 🌍 多协议支持
- ✅ **VLESS-Reality**（支持 Vision 传输）
  - 自动生成密钥对（PublicKey / PrivateKey）
  - ShortID 生成
  - SNI 伪装配置
  - 支持修改 SNI
- ✅ **Shadowsocks 2022**
  - 新协议支持
  - 多种加密方式

#### ⚙️ 配置管理
- ✅ 多配置文件管理（独立 JSON）
- ✅ 添加/修改/删除配置
- ✅ 配置验证和检查
- ✅ 自动生成分享链接（`vless://`、`ss://`）
- ✅ 修改支持：
  - 修改端口（自动防火墙调整）
  - 修改 UUID/密码
  - 修改 SNI（仅 VLESS-Reality）

#### 🔥 防火墙自动化（新增）
- ✅ 自动识别并配置 `ufw` / `firewalld`
- ✅ 添加配置时自动放行端口
- ✅ 删除配置时自动回收端口
- ✅ 修改端口时自动更新防火墙规则

#### 🌐 网络优化（新增）
- ✅ TCP Fast Open + BBR 一键启用
- ✅ 完整的 sysctl 网络参数优化
- ✅ 专用配置文件：`/etc/sysctl.d/99-singbox.conf`
- ✅ 安装时自动启用
- ✅ 一键启用/禁用

#### 🔄 版本管理（增强）
- ✅ 自动检测 GitHub 最新版本
- ✅ 版本缓存机制（1 小时有效期）
- ✅ 一键更新核心

#### 📊 日志管理
- ✅ 查看最近 N 行日志
- ✅ 实时查看日志
- ✅ 清空日志

#### 🛡️ 安全增强（新增）
- ✅ 重启验证（修改配置后自动检查服务状态）
- ✅ 失败时显示错误日志
- ✅ 配置验证（jq + sing-box check）

#### 💻 命令行界面
- ✅ 交互式菜单模式
- ✅ 命令行快捷模式
- ✅ 快捷命令：`sb <command>`
- ✅ 支持管道执行：`curl | bash`

---

### 📋 sing-box.sh 命令列表

#### 服务管理
```bash
sb start             # 启动 sing-box
sb stop              # 停止 sing-box
sb restart           # 重启 sing-box
sb status            # 查看状态
```

#### 配置管理
```bash
sb install           # 安装 sing-box
sb uninstall         # 卸载 sing-box
sb add [r|s]         # 添加配置（r=Reality, s=Shadowsocks）
sb del [配置名]      # 删除配置
sb change [配置名]   # 修改配置（端口/凭证/SNI）
sb info [配置名]     # 查看配置详情
sb url [配置名]      # 生成分享链接
sb qr [配置名]       # 生成二维码
```

#### 日志管理
```bash
sb log [n]           # 查看最近 n 行日志（默认 50）
sb log-f             # 实时查看日志
sb log-clear         # 清空日志
```

#### 系统优化
```bash
sb dns               # 查看 DNS
sb set-dns           # 设置 DNS
sb bbr               # 查看 BBR 状态
sb set-bbr           # 启用 BBR
sb tfo               # 启用 TCP Fast Open + BBR
sb tfo-off           # 禁用网络优化
```

#### 更新管理
```bash
sb update            # 更新核心
sb update sh         # 更新脚本
```

---

## 📊 port-manage.sh - 功能特性

### 核心功能

#### 🎯 端口管理
- ✅ 添加端口监控
- ✅ 删除端口监控
- ✅ 修改端口备注
- ✅ 支持多端口同时监控

#### 📈 流量监控
- ✅ **实时流量统计**（上传/下载/总计）
- ✅ **流量速率显示**（实时速度）
- ✅ **流量历史记录**（自动保存）
- ✅ 基于 nftables 的精确统计
- ✅ 流量数据持久化存储

#### 🚦 带宽限制
- ✅ **入站限速**（下载速度限制）
- ✅ **出站限速**（上传速度限制）
- ✅ 基于 TC (traffic control) 实现
- ✅ 灵活的速率单位（KB/s, MB/s, GB/s）
- ✅ 动态调整不影响现有连接

#### 📦 流量配额
- ✅ **月流量配额**（每月自动重置）
- ✅ **总流量配额**（永久累计）
- ✅ **配额用尽自动告警**
- ✅ **手动重置流量**
- ✅ 多端口独立配额管理

#### 🛡️ 突发保护
- ✅ **异常流量检测**（防止流量突增）
- ✅ **自定义检测周期**（默认 5 分钟）
- ✅ **自定义阈值**（默认 1GB）
- ✅ **自动告警通知**
- ✅ 定时任务自动检查

#### 📱 Telegram 通知
- ✅ **多级阈值告警**（30%, 50%, 80%, 100%）
- ✅ **自定义服务器名称**
- ✅ **配额用尽提醒**
- ✅ **突发流量告警**
- ✅ **自定义通知间隔**（防止频繁推送）
- ✅ **手动推送状态**
- ✅ 美观的格式化消息

#### 🔧 系统功能
- ✅ **智能锁机制**（防止并发操作冲突）
- ✅ **自动依赖安装**（nftables, tc, jq, bc, curl）
- ✅ **快捷命令**（`ptm`）
- ✅ **定时任务管理**（告警检查、突发保护）
- ✅ **完整卸载**（清理所有配置和规则）
- ✅ **支持远程安装**（curl | bash）

#### 🌐 系统兼容
- ✅ Debian / Ubuntu / Linux Mint
- ✅ CentOS / RHEL / Fedora / Rocky / AlmaLinux
- ✅ Arch / Manjaro
- ✅ Alpine Linux

---

### 📋 port-manage.sh 命令列表

#### 快捷命令
```bash
ptm                      # 进入交互式菜单
ptm --reset <port>       # 重置指定端口流量
ptm --notify             # 发送状态通知
ptm --check-alert        # 检查阈值告警
ptm --check-burst        # 检查突发速率保护
ptm --version            # 显示版本
ptm --help               # 显示帮助
```

#### 交互式菜单选项
```
── 端口管理 ──
  1. 添加端口    2. 删除端口    3. 修改备注
── 流量设置 ──
  4. 带宽限制    5. 流量配额    6. 重置流量
── 保护设置 ──
  7. 突发保护
── 通知设置 ──
  8. Telegram    9. 立即推送
── 系统 ──
  10. 卸载       0. 退出
```

---

### 🎨 界面展示

#### 流量监控界面
```
=== 端口流量监控 v2.3.2 ===
Telegram: ✓ 已启用 | 服务器: VPS-HK-01

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
端口     备注          上传     下载     总计     速率
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
8388   Shadowsocks   1.2GB    3.4GB    4.6GB   ↑50KB/s ↓120KB/s
       限速: ↑1MB/s ↓5MB/s | 配额: 4.6GB/50GB (9%)

10443  VLESS-Reality 890MB    2.1GB    2.99GB  ↑30KB/s ↓80KB/s
       限速: 无 | 配额: 无
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### 💡 使用示例

#### 1. 添加端口监控
```bash
ptm
# 选择 1 (添加端口)
# 输入端口号: 8388
# 输入备注: Shadowsocks
```

#### 2. 设置带宽限制
```bash
ptm
# 选择 4 (带宽限制)
# 选择端口: 8388
# 上传限速: 1MB/s
# 下载限速: 5MB/s
```

#### 3. 设置流量配额
```bash
ptm
# 选择 5 (流量配额)
# 选择端口: 8388
# 月配额: 50GB
# 总配额: 无限制
```

#### 4. 配置 Telegram 通知
```bash
ptm
# 选择 8 (Telegram)
# Bot Token: 123456:ABC-DEF...
# Chat ID: 123456789
# 服务器名称: VPS-HK-01
# 通知间隔: 1h (小时) / 30m (分钟)
```

#### 5. 设置突发保护
```bash
ptm
# 选择 7 (突发保护)
# 检测周期: 5 (分钟)
# 流量阈值: 1GB
```

---

## 📊 功能对比表

| 功能 | Snell.sh | sing-box.sh | port-manage.sh |
|------|----------|-------------|----------------|
| **主要用途** | 代理服务器 | 代理服务器 | 流量监控管理 |
| **核心功能** | Snell Server | VLESS / SS | 端口流量统计 |
| **命令行快捷** | ✅ `snell` | ✅ `sb` | ✅ `ptm` |
| **交互式菜单** | ✅ | ✅ | ✅ |
| **流量监控** | ❌ | ❌ | ✅ |
| **带宽限制** | ❌ | ❌ | ✅ |
| **流量配额** | ❌ | ❌ | ✅ |
| **突发保护** | ❌ | ❌ | ✅ |
| **Telegram 通知** | ❌ | ❌ | ✅ |
| **多阈值告警** | ❌ | ❌ | ✅ (30/50/80/100%) |
| **自动检测版本** | ✅（官网）| ✅（GitHub API）| ❌ |
| **备份与回滚** | ✅ | ❌ | ❌ |
| **防火墙管理** | ✅ | ✅ | ❌ |
| **网络优化** | ✅（BBR + TFO）| ✅（BBR + TFO）| ❌ |
| **配置文件** | 单一 | 多配置 | JSON |
| **依赖工具** | wget, unzip | jq | nftables, tc, jq |

---

## 🎯 使用场景

### Snell.sh 适合：
- ✅ Surge 用户
- ✅ 追求稳定性和简单配置
- ✅ 需要备份和回滚功能
- ✅ 单节点使用场景

### sing-box.sh 适合：
- ✅ 需要多协议支持
- ✅ 需要多配置管理
- ✅ 使用 Reality 协议抗审查
- ✅ 支持多种客户端

### port-manage.sh 适合：
- ✅ 需要监控端口流量
- ✅ 需要限制带宽速率
- ✅ 需要设置流量配额
- ✅ 需要 Telegram 实时告警
- ✅ 多端口流量管理
- ✅ 防止流量异常暴涨

---

## 📥 安装方法

### Snell.sh

#### 方法 1：直接运行（推荐）
```bash
# 下载并运行
wget https://raw.githubusercontent.com/white-u/vps_script/main/Snell.sh
chmod +x Snell.sh
sudo ./Snell.sh
```

#### 方法 2：一键安装
```bash
curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/Snell.sh | sudo bash
```

#### 安装后使用快捷命令
```bash
# 脚本会自动创建软链接
snell          # 进入菜单
snell install  # 安装
snell status   # 查看状态
```

---

### sing-box.sh

#### 方法 1：直接运行（推荐）
```bash
# 下载并运行
wget https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh
chmod +x sing-box.sh
sudo ./sing-box.sh
```

#### 方法 2：一键安装
```bash
curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh | sudo bash
```

#### 安装后使用快捷命令
```bash
sb             # 进入菜单
sb add r       # 添加 Reality 配置
sb status      # 查看状态
```

---

## 🔧 系统要求

- **操作系统**：Debian / Ubuntu / CentOS / RHEL
- **权限**：Root 或 sudo
- **依赖**：`wget`, `curl`, `unzip`, `jq`（脚本会自动安装）
- **内核**：
  - TCP Fast Open：Linux 3.x+
  - BBR：Linux 4.9+

---

## 📝 配置文件位置

### Snell.sh
```
/usr/local/bin/snell-server         # 二进制文件
/etc/snell/snell-server.conf        # 主配置文件
/etc/snell/config.txt                # Surge 配置（可直接复制）
/etc/snell/node_name.txt             # 节点名称
/var/log/snell.log                   # 日志文件
/etc/systemd/system/snell.service    # systemd 服务
/etc/sysctl.d/99-snell.conf          # 网络优化配置
```

### sing-box.sh
```
/usr/local/bin/sing-box              # 二进制文件
/usr/local/etc/sing-box/config.json  # 主配置文件
/usr/local/etc/sing-box/conf/*.json  # 独立配置文件
/var/log/sing-box/sing-box.log       # 日志文件
/etc/systemd/system/sing-box.service # systemd 服务
/etc/sysctl.d/99-singbox.conf        # 网络优化配置
```

---

## 🛡️ 安全建议

1. **定期更新**
   ```bash
   snell update     # 更新 Snell
   sb update        # 更新 sing-box
   ```

2. **备份配置**
   ```bash
   # Snell 自动备份到
   /var/backups/snell-manager/

   # sing-box 手动备份
   cp -r /usr/local/etc/sing-box /root/backup/
   ```

3. **查看日志**
   ```bash
   snell log 100    # 查看 Snell 日志
   sb log 100       # 查看 sing-box 日志
   ```

4. **防火墙检查**
   ```bash
   # ufw
   sudo ufw status

   # firewalld
   sudo firewall-cmd --list-all
   ```

---

## 🐛 故障排查

### Snell.sh

#### 服务无法启动
```bash
# 查看日志
snell log 100
journalctl -u snell -n 100

# 检查配置
cat /etc/snell/snell-server.conf

# 检查端口占用
ss -lntp | grep <端口>
```

#### 更新失败
```bash
# 强制刷新版本缓存
rm -f /tmp/snell_version_cache

# 查看可用版本
curl -s https://dl.nssurge.com/snell/
```

---

### sing-box.sh

#### 服务无法启动
```bash
# 查看日志
sb log 100
journalctl -u sing-box -n 100

# 验证配置
sing-box check -c /usr/local/etc/sing-box/config.json

# 检查端口占用
ss -lntp | grep <端口>
```

#### 配置验证失败
```bash
# 手动检查 JSON 格式
jq . /usr/local/etc/sing-box/conf/<配置文件>.json

# 使用 sing-box 验证
sing-box check -c /usr/local/etc/sing-box/config.json -C /usr/local/etc/sing-box/conf
```

---

## 📄 许可证

MIT License

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📮 联系方式

- GitHub: [white-u/vps_script](https://github.com/white-u/vps_script)
- Issues: [提交问题](https://github.com/white-u/vps_script/issues)

---

## ⭐ 致谢

- [Snell](https://nssurge.com/) - Surge 官方代理协议
- [sing-box](https://github.com/SagerNet/sing-box) - 通用代理平台

---

**最后更新：2025-12-07**
