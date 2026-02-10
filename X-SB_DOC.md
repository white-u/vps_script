# x-sb.sh 技术文档

**Xray 多协议管理脚本**
Version: 1.3.0 | 801 行 | 2026-02-10

---

## 1. 概述

x-sb.sh 是一个 Bash 交互式管理脚本，用于在 Linux VPS 上一键部署和管理 Xray 代理节点。支持 VLESS-Reality 和 Shadowsocks-2022 双协议，提供链式代理、路由分流等进阶功能。

**核心特性**

- VLESS-Vision-Reality（推荐）和 Shadowsocks-2022 双协议
- 配置安全：写前校验 → 语义验证 → 自动备份 → 失败回滚
- 链式代理（Chain Proxy）：通过上游 SOCKS5 转发流量
- 路由分流：屏蔽广告、回国流量、局域网
- 分享链接 + 二维码输出，IPv6 自动方括号
- 脚本自更新、快捷命令安装

**环境要求**

| 项目 | 要求 |
|------|------|
| 操作系统 | Debian/Ubuntu, CentOS/RHEL, Alpine Linux |
| 权限 | root |
| 依赖 | curl, wget, unzip, jq, openssl, qrencode |
| Xray | 自动安装/更新，已验证兼容 v26.2.6 |

---

## 2. 快速开始

**安装并运行**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/x-sb.sh)
```

**后续使用**

```bash
x-sb          # 快捷命令（自动安装到 /usr/local/bin）
```

**推荐流程**

```
菜单 1 → 安装 Xray 核心
菜单 2 → 添加 VLESS-Reality 节点
菜单 4 → 查看分享链接/二维码 → 导入客户端
```

---

## 3. 主菜单

```
================================================================
   Xray 多协议管理脚本 (v1.3.0)
================================================================
 核心状态: ✅ 运行中 (26.2.6)
 配置文件: /usr/local/etc/xray/config.json
----------------------------------------------------------------
  1. 安装 / 更新 Xray 核心
  2. 添加 VLESS-Vision-Reality 节点 (⭐ 推荐)
  3. 添加 Shadowsocks-2022 节点 (🚀 性能)
  4. 查看节点配置 / 分享链接
  5. 删除节点
  6. 进阶配置 (链式代理 / 路由)
  7. 更新脚本
  8. 卸载脚本
  0. 退出
================================================================
```

| 选项 | 功能 | 对应函数 |
|------|------|---------|
| 1 | 下载/更新 Xray 核心 + geoip/geosite + systemd 服务 | `install_xray` |
| 2 | 交互式创建 VLESS-Reality 节点 | `add_reality` |
| 3 | 交互式创建 SS-2022 节点 | `add_ss2022` |
| 4 | 列出所有节点 → 选择查看详情/链接/二维码 | `list_nodes` → `show_node_info` |
| 5 | 删除指定节点（含路由规则清理） | `delete_node` |
| 6 | 链式代理 / 路由分流子菜单 | `configure_advanced` |
| 7 | 从 GitHub 下载最新脚本替换 | `update_script` |
| 8 | 彻底卸载 Xray + 配置 + 日志 + 快捷命令 | `uninstall_script` |

---

## 4. 文件布局

```
/usr/local/bin/xray              # Xray 二进制
/usr/local/bin/x-sb              # 脚本快捷命令
/usr/local/etc/xray/config.json  # 主配置文件 (chmod 640)
/usr/local/share/xray/           # geoip.dat, geosite.dat
/etc/systemd/system/xray.service # systemd 服务单元
/var/log/xray/                   # 访问日志、错误日志
```

---

## 5. 函数架构

### 5.1 启动与依赖

| 函数 | 行号 | 说明 |
|------|------|------|
| `check_root` | 57 | 检查 root 权限 |
| `map_arch` | 61 | 检测 CPU 架构 (x86_64/arm64) |
| `check_deps` | 69 | 安装缺失依赖，Alpine 特殊处理 qrencode |
| `cleanup` | 46 | EXIT trap，清理所有注册的临时文件 |
| `strip_cr` | 54 | 清洗 Windows 换行符 `\r` |

### 5.2 Xray 核心管理

| 函数 | 行号 | 说明 |
|------|------|------|
| `install_xray` | 91 | 核心安装/更新全流程 |
| `install_shortcut_cmd` | 156 | 安装 `/usr/local/bin/x-sb` 快捷命令 |
| `init_config_if_missing` | 173 | 初始化默认配置（含 `domainStrategy: UseIPv4v6`） |

**install_xray 流程**

```
GitHub API 获取最新版本 → 比较当前版本（去 v 前缀）
  → 相同: 跳过
  → 不同: 下载 zip (--max-time 120) → 解压 → 停服 → 替换二进制 → 启动
→ 写入 systemd 服务单元 → daemon-reload
→ init_config_if_missing → install_shortcut_cmd
```

### 5.3 配置安全写入

**`safe_save_config(tmp_json)` — 核心安全函数**（L215-268）

```
┌─────────────────────────────┐
│ 1. jq 语法校验              │ → 失败: return 1, 不动现有配置
├─────────────────────────────┤
│ 2. xray run -test -c 校验   │ → 失败: 显示错误, return 1
├─────────────────────────────┤
│ 3. 备份 config.json → .bak  │
├─────────────────────────────┤
│ 4. cp 新配置 + chmod 640     │
│    systemctl restart xray   │
├─────────────────────────────┤
│ 5. 健康检查                  │
│    ├─ 成功: 删除备份, 完成   │
│    └─ 失败: 显示日志错误     │
│           恢复 .bak → 重启   │
│           return 1           │
└─────────────────────────────┘
```

**设计原则**：任何路径下，现有可用配置永远不会被损坏。

### 5.4 节点管理

| 函数 | 行号 | 说明 |
|------|------|------|
| `add_reality` | 302 | 创建 VLESS-Reality 节点 |
| `add_ss2022` | 404 | 创建 SS-2022 节点 |
| `delete_node` | 679 | 删除节点 + 关联路由规则 |
| `list_nodes` | 545 | 列出所有节点（设置 `_NODE_COUNT`） |
| `get_node_tag_by_id` | 571 | 按编号获取 tag（与显示对齐） |

**add_reality 流程**

```
输入端口 → is_port_available 三重校验
→ SNI 连通性测试 → 用户选择/手动输入
→ xray x25519 生成密钥对
  ├─ 26.x: PrivateKey: / Password: (=PublicKey)
  └─ 旧版 fallback: Private key: / Public key:
→ 构建 inbound JSON (含 sniffing + publicKey)
→ 可选链式代理路由
→ safe_save_config → show_node_info
```

### 5.5 节点查看与分享

**`show_node_info(tag)`**（L613-677）

```
获取公网 IP (多源 IPv4 + IPv6 fallback)
→ IPv6 自动加方括号 [::1]
→ 从配置读取节点参数
→ publicKey: 优先读配置字段, 降级 openssl 计算 (兼容旧配置)
→ 生成分享链接 + 二维码
```

**分享链接格式**

| 协议 | 格式 |
|------|------|
| VLESS | `vless://UUID@IP:PORT?flow=...&security=reality&sni=...&pbk=...&sid=...#TAG` |
| SS-2022 | `ss://BASE64(method:password)@IP:PORT#TAG` (SIP002) |

### 5.6 进阶功能

**`configure_advanced`** 子菜单：

| 选项 | 功能 |
|------|------|
| 1 | 配置/清除全局 SOCKS5 链式代理 |
| 2 | 启用路由规则：屏蔽广告(geosite:category-ads-all) + 回国(geosite:cn, geoip:cn) + 局域网(geoip:private) |

**链式代理原理**

```
客户端 → [Xray inbound] → routing rules → chain_proxy outbound → 上游 SOCKS5 → 目标
```

- 添加节点时可选择是否绑定链式代理
- 清除链式代理时同时删除 outbound + routing rules（幂等）

### 5.7 辅助函数

| 函数 | 行号 | 说明 |
|------|------|------|
| `get_random_port` | 270 | 随机生成可用端口 (10000-65000) |
| `is_port_available` | 282 | 端口三重校验：范围 + 系统占用 + Xray 配置冲突 |
| `get_x25519_pubkey` | 593 | 用 openssl 从私钥推算公钥（RFC 8410 DER 编码） |
| `update_script` | 701 | 脚本自更新（原子替换） |
| `uninstall_script` | 726 | 彻底卸载（需输入 yes 确认） |

---

## 6. 生成的配置结构

### 6.1 初始配置模板

```json
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "settings": { "domainStrategy": "UseIPv4v6" }
    },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
    ]
  }
}
```

### 6.2 VLESS-Reality inbound 结构

```json
{
  "tag": "reality_443",
  "port": 443,
  "protocol": "vless",
  "settings": {
    "clients": [{ "id": "UUID", "flow": "xtls-rprx-vision" }],
    "decryption": "none"
  },
  "sniffing": {
    "enabled": true,
    "destOverride": ["http", "tls", "quic"]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "show": false,
      "dest": "addons.mozilla.org:443",
      "xver": 0,
      "serverNames": ["addons.mozilla.org"],
      "privateKey": "...",
      "publicKey": "...",
      "shortIds": ["abcd1234"]
    }
  }
}
```

> **注**: `publicKey` 不是 Xray 标准 schema 字段，但 Xray 会忽略未知字段。存入配置是为了查看时直接读取，避免运行时计算。

### 6.3 Shadowsocks-2022 inbound 结构

```json
{
  "tag": "ss_8388",
  "port": 8388,
  "protocol": "shadowsocks",
  "settings": {
    "method": "2022-blake3-aes-128-gcm",
    "password": "BASE64_KEY",
    "network": "tcp,udp"
  }
}
```

> SS 协议自带目标地址信息，不需要 sniffing。

---

## 7. Xray 26.x 兼容性

Xray 26.x 引入了多个破坏性变更，脚本均已适配：

| 变更 | 影响 | 适配方案 |
|------|------|---------|
| `x25519` 输出格式改变：`PrivateKey:` / `Password:` / `Hash32:` | 旧的 `grep "Public key"` 匹配不到 | 先匹配 `PrivateKey:/Password:`，fallback 匹配 `Private/Public` |
| `Password` = 原 `PublicKey` | 字段改名 | `awk '/Password:/{print $2}'` 提取公钥 |
| `xray run -test -c` 要求文件扩展名 `.json` | `mktemp` 默认无扩展名 → 格式检测失败 | 所有配置临时文件改为 `mktemp /tmp/xray_XXXXXX.json` |
| 无 `x25519 -i` 的 PublicKey 输出 | 无法从私钥反推公钥 | `get_x25519_pubkey()` 用 openssl DER 编码计算（向后兼容降级方案） |

---

## 8. 安全机制

| 机制 | 实现 |
|------|------|
| 配置文件权限 | `chmod 640` — 仅 root 可读写 |
| 配置写入保护 | `safe_save_config`: jq 校验 → xray -test → 备份 → 写入 → 健康检查 → 失败回滚 |
| 临时文件清理 | 所有 `mktemp` 注册到 `_CLEANUP_FILES`，EXIT/INT/TERM trap 自动清理 |
| 卸载确认 | 需输入 `yes`（非 `y`）确认 |
| 下载超时 | Xray zip `--max-time 120`，脚本更新 `--max-time 15` |
| 端口校验 | 范围(1-65535) + 系统占用(ss -tuln) + 配置冲突(jq 查询) |
| 密钥生成验证 | 双字段非空检查 + 错误时输出原始 x25519 内容辅助排查 |

---

## 9. 版本历史

### v1.3.0 (2026-02-10)

v2.9.1 参考对比后的改进：

- **publicKey 存入配置 JSON**：生成时提取并写入 `realitySettings.publicKey`，查看时直接读取，降级 openssl 计算兼容旧配置
- **Xray 26.x 密钥字段适配**：`PrivateKey:` + `Password:` 双提取，旧版 fallback
- **freedom outbound 加 `domainStrategy: UseIPv4v6`**：修复部分站点不通
- **SS inbound 移除 sniffing**：SS 协议自带目标信息，无需嗅探
- **配置文件 `chmod 640` 权限保护**
- **端口三重校验**：范围 + 系统占用 + Xray 配置冲突
- **多源 IP 获取 + IPv6 fallback**：ipify → ip.sb → checkip，IPv6 降级
- **分享链接 IPv6 方括号**：`display_ip` 自动处理

---

## 10. 已知限制

| 限制 | 说明 | 建议 |
|------|------|------|
| 服务以 root 运行 | systemd `User=root`，`CAP_NET_BIND_SERVICE` 无实际作用 | 如需安全加固，可改为 nobody 用户 + 单独版本处理 |
| 路由规则幂等过滤器激进 | 删除所有含 `geosite:*/geoip:*` 的规则 | 手动编辑的自定义 geosite 规则可能被误删 |
| tag 固定格式 | `reality_PORT` / `ss_PORT` | 不支持自定义命名 |
| 无 DNS 配置 | 依赖 VPS 系统 `/etc/resolv.conf` | 用户需自行确保系统 DNS 可用 |
| 链式代理为全局 | 所有绑定节点共享同一个 chain_proxy outbound | 如需 per-node 独立代理，需改架构 |

---

## 11. 故障排查

**Xray 启动失败**

```bash
journalctl -u xray -n 20          # 查看日志
xray run -test -c /usr/local/etc/xray/config.json   # 手动校验配置
```

**节点有延迟无网络**

1. 确认 config.json 中 inbound 包含 `sniffing`（VLESS 需要）
2. 确认 `publicKey` 字段非空
3. 确认 freedom outbound 包含 `"domainStrategy": "UseIPv4v6"`
4. 客户端重新导入分享链接

**公钥为空**

```bash
# 验证 Xray x25519 输出
/usr/local/bin/xray x25519
# 26.x 应输出: PrivateKey: / Password: / Hash32:
# 旧版应输出: Private key: / Public key:
```
