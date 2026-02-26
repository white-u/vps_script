# Sing-Box 多协议管理脚本 (sb.sh)

**版本**: v1.0.4 | **快捷命令**: `sb` | **安装路径**: `/usr/local/bin/sb`

---

## 1. 概述

`sb.sh` 是一个专为 **Sing-Box** 内核设计的现代化代理管理脚本。它利用 Sing-Box 的最新特性 (Reality, Shadowsocks-2022)，提供了一套高性能、配置简洁的解决方案。

**与 Xray 版本的区别:**
*   Sing-Box 内核更轻量，更适合低配 VPS。
*   配置文件结构更加现代化 (JSON)，支持更多新特性。
*   **元数据分离:** 脚本创新性地将 Public Key 等元数据存储在 `nodes_meta.json` 中，避免直接读写复杂的 Sing-Box Config 导致出错。

### 1.1 核心特性

*   **协议支持:**
    *   **VLESS Vision REALITY:** 目前最强抗封锁协议，无需域名证书。
    *   **Shadowsocks-2022:** 极速轻量加密协议。
*   **安全机制:**
    *   **配置回滚:** 每次修改配置前，先调用 `sing-box check` 校验。如果配置有误，自动回滚。
    *   **原子写入:** 使用 `mktemp` + `mv` 确保配置文件写入的原子性。
*   **进阶功能:**
    *   **链式代理 (Chain Proxy):** 支持配置上游 SOCKS5 代理。
    *   **二维码分享:** 内置 `qrencode`，直接在终端生成配置二维码。

---

## 2. 安装与使用

### 2.1 一键安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/sb.sh)
```

### 2.2 常用命令

| 命令 | 说明 |
|------|------|
| `sb` | 进入交互式管理菜单 (主入口) |
| `sb add` | 快速添加一个新节点 |
| `sb list` | 列出所有节点信息 |
| `sb update` | 更新管理脚本自身 |
| `sb install` | 强制重新安装/更新 Sing-Box 核心 |

### 2.3 交互菜单

运行 `sb` 后可以看到如下界面：

```text
================================================================================
  sb (sing-box)  v1.0.4
================================================================================
 核心状态: ✅ 运行中 (core 1.8.11)
 配置文件: /usr/local/etc/sing-box/config.json
--------------------------------------------------------------------------------
 1) 安装/更新 sing-box 核心
 2) 添加 VLESS-Vision-REALITY 节点
 3) 添加 Shadowsocks-2022 节点
 4) 查看节点/导出分享链接
 5) 删除节点
 6) 进阶配置(链式代理/路由)
 7) 更新脚本
 8) 卸载 sing-box + 删除全部配置
 0) 退出
================================================================================
```

---

## 3. 配置文件结构

### 3.1 路径说明

*   **核心二进制:** `/usr/local/bin/sing-box`
*   **主配置文件:** `/usr/local/etc/sing-box/config.json`
*   **元数据文件:** `/usr/local/etc/sing-box/nodes_meta.json` (存放 Public Key 等)
*   **Systemd 服务:** `/etc/systemd/system/sing-box.service`
*   **工作目录:** `/var/lib/sing-box`

### 3.2 为什么需要 nodes_meta.json?

Sing-Box 的配置文件只存储 **Private Key**。为了生成分享链接 (vless://...)，我们需要 **Public Key**。
*   传统脚本通常每次都重新计算 Public Key，这依赖 `openssl` 或特定工具，容易出错且慢。
*   `sb.sh` 在生成节点时，将 Public Key 存入 `nodes_meta.json`，查看节点信息时直接读取，速度极快且稳定。

**注意:** 请勿手动修改 `nodes_meta.json`，除非你知道自己在做什么。

---

## 4. 进阶玩法

### 4.1 链式代理 (Chain Proxy)

与 Xray 版本类似，支持配置上游 SOCKS5 代理。
*   配置方法: 菜单 `6) 进阶配置` -> `1) 配置上游 SOCKS5 链式代理`。
*   应用场景: 解锁流媒体、隐藏 VPS IP。

### 4.2 路由规则

默认路由规则:
*   **block-private:** 拒绝访问私有 IP (防滥用)。
*   **sniff:** 开启流量嗅探，优化分流体验。

---

## 5. 卸载

在菜单中选择 `8) 卸载 sing-box`。
卸载会自动清理：
*   停止并禁用 Sing-Box 服务。
*   删除 Systemd 服务文件。
*   删除配置文件目录 `/usr/local/etc/sing-box`。
*   删除工作目录 `/var/lib/sing-box`。
*   删除脚本自身。
