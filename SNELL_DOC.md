# Snell 多实例管理脚本 v5.0

> 单机多端口 Snell 代理一键部署工具，支持 Systemd 模板化管理。

---

## 一、快速开始

### 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh)
```

首次运行后自动安装快捷命令，后续直接使用：

```bash
snell
```

### 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Ubuntu / Debian / CentOS / RHEL / Alpine |
| 架构 | x86_64 (amd64) 或 aarch64 (ARM64) |
| 权限 | root |
| 依赖 | curl, wget, unzip（脚本自动安装） |

---

## 二、功能菜单

```
=========================================================================================
   Snell 多实例管理脚本 (v5.0)
=========================================================================================
 核心状态: v5.0.1    架构: x86_64
-----------------------------------------------------------------------------------------
 序号   端口       状态         IPv6     混淆     PSK
 ─────────────────────────────────────────────────────────────────────────────────────
 [1]    10086      运行中       true     off      aB3kLm9x...
 [2]    20000      已停止       true     off      Xz7pQw2n...
=========================================================================================

 1. 安装 / 更新 Snell 核心
 2. 添加实例 (新端口)
 3. 删除实例
 4. 查看客户端配置
 5. 更新管理脚本
 6. 卸载全部
 0. 退出
=========================================================================================
```

### [1] 安装 / 更新 Snell 核心

- 自动从 Surge 官网抓取最新版本号（失败则使用兜底版本 5.0.1）
- 下载到临时目录解压，仅提取 `snell-server` 二进制文件
- 安装 Systemd 模板服务 `snell@.service`
- 创建专用系统用户 `snell`（非登录用户）
- 更新期间自动停止所有实例，完成后自动恢复

### [2] 添加实例

- 输入端口号（1-65535），自动校验范围和占用
- 自动生成 25 位随机 PSK
- 写入配置文件到 `/etc/snell/端口.conf`
- 自动放行防火墙端口（ufw / firewalld / iptables）
- 启动实例并输出客户端配置

### [3] 删除实例

- 列出所有实例及运行状态
- 按序号选择删除
- 自动停止服务、清理配置文件、关闭防火墙端口

### [4] 查看客户端配置

- 获取服务器公网 IP
- 读取每个实例的 PSK 和版本号
- 输出可直接复制到 Surge / Stash / Shadowrocket 的配置行

### [5] 更新管理脚本

- 从 GitHub 下载最新版
- 对比版本号，相同则跳过
- 覆盖快捷命令后 `exec` 重新加载

### [6] 卸载全部

- 停止并禁用所有实例
- 删除核心二进制、配置目录、Systemd 服务、快捷命令
- 删除系统用户 `snell`
- 需输入 `yes` 确认（防误触）

---

## 三、命令行参数

除交互式菜单外，支持直接命令行调用：

```bash
snell install   # 安装/更新核心
snell add       # 添加新实例
snell update    # 更新管理脚本
```

---

## 四、文件布局

| 路径 | 说明 |
|------|------|
| `/usr/local/bin/snell` | 管理脚本（快捷命令） |
| `/usr/local/bin/snell-server` | Snell 核心二进制 |
| `/etc/snell/` | 配置目录 |
| `/etc/snell/端口.conf` | 各实例配置文件 |
| `/etc/snell/.version` | 已安装的核心版本号 |
| `/etc/systemd/system/snell@.service` | Systemd 模板服务 |

---

## 五、配置文件格式

每个实例对应一个 `/etc/snell/端口.conf`：

```ini
[snell-server]
listen = ::0:10086
psk = aB3kLm9xPqW2nR7yT5vU8
ipv6 = true
tfo = true
obfs = off
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `listen` | 监听地址和端口，`::0` 表示同时监听 IPv4/IPv6 | — |
| `psk` | 预共享密钥，25 位随机字母数字 | 自动生成 |
| `ipv6` | 是否启用 IPv6 | `true` |
| `tfo` | TCP Fast Open | `true` |
| `obfs` | 流量混淆：`off` / `http` | `off` |

---

## 六、Systemd 服务管理

脚本使用 Systemd 模板化服务 `snell@.service`，`%i` 对应端口号：

```bash
# 查看实例状态
systemctl status snell@10086

# 手动重启某个实例
systemctl restart snell@10086

# 查看日志
journalctl -u snell@10086 -n 50

# 查看所有 snell 实例
systemctl list-units 'snell@*'
```

---

## 七、客户端配置

添加实例后脚本会自动输出，格式如下：

```
snell-10086 = snell, 1.2.3.4, 10086, psk=aB3kLm9xPqW2nR7yT5vU8, version=5, tfo=true, reuse=true
```

直接复制到以下客户端使用：

| 客户端 | 配置位置 |
|--------|---------|
| Surge (iOS/Mac) | 配置文件 `[Proxy]` 段 |
| Stash (iOS) | 代理 → 添加 → Snell |
| Shadowrocket (iOS) | 添加节点 → 类型 Snell |

---

## 八、防火墙处理

脚本自动检测并适配三种防火墙：

| 防火墙 | 添加实例时 | 删除实例时 | 持久化 |
|--------|-----------|-----------|--------|
| ufw | `ufw allow 端口` | `ufw delete allow 端口` | ✅ 自动 |
| firewalld | `--permanent --add-port` | `--permanent --remove-port` | ✅ 自动 |
| iptables | `-I INPUT -j ACCEPT` | `-D INPUT -j ACCEPT` | ⚠️ 尝试 `iptables-save` |

**注意**：纯 iptables 环境下持久化依赖 `iptables-save`，部分系统可能不支持。建议安装 `iptables-persistent` 或使用 ufw。

---

## 九、更新方式

### 更新管理脚本

```bash
# 方式一：菜单中选 [5]
snell

# 方式二：命令行
snell update

# 方式三：重新运行安装命令（自动同步快捷命令）
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh)
```

### 更新 Snell 核心

菜单中选 [1]，脚本会自动获取最新版本、停止实例、替换二进制、恢复实例。

---

## 十、安全加固

| 措施 | 说明 |
|------|------|
| 专用用户 | 以 `snell` 用户运行，非 root |
| 配置权限 | `chmod 600`，仅 snell 用户可读 |
| 无 shell | `snell` 用户 shell 为 `/usr/sbin/nologin` |
| 最小能力 | 仅授予 `CAP_NET_BIND_SERVICE`（绑定低端口） |
| PSK 强度 | 25 位大小写字母+数字，来源 `/dev/urandom` |

---

## 十一、故障排查

### 实例启动失败

```bash
journalctl -u snell@端口 -n 20 --no-pager
```

常见原因：
- 端口被占用：`ss -tuln | grep :端口`
- 配置格式错误：`cat /etc/snell/端口.conf`
- 二进制损坏：重新执行菜单 [1] 安装核心

### 快捷命令版本不一致

```bash
# 重新同步
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh)
# 或
snell update
```

---

## 十二、技术架构

```
snell.sh (管理脚本)
  │
  ├── 入口层
  │   ├── check_root()         # 权限校验
  │   ├── sync_script()        # 快捷命令同步
  │   └── 参数路由 / 菜单循环
  │
  ├── 核心逻辑
  │   ├── install_core()       # 安装/更新 Snell 核心
  │   ├── add_instance()       # 添加实例
  │   ├── del_instance()       # 删除实例
  │   ├── show_all_configs()   # 查看配置
  │   ├── update_script()      # 更新脚本
  │   └── uninstall_all()      # 彻底卸载
  │
  ├── 基础设施
  │   ├── get_latest_version() # 版本爬取 + 兜底
  │   ├── open_port()          # 防火墙放行
  │   ├── close_port()         # 防火墙关闭
  │   ├── map_arch()           # 架构检测
  │   └── check_deps()         # 依赖安装
  │
  └── 安全机制
      ├── set -euo pipefail    # 严格模式
      ├── trap cleanup EXIT    # 临时资源清理
      ├── strip_cr()           # 输入清理
      ├── || true              # systemctl 容错 (28处)
      └── mktemp               # 临时文件隔离
```
