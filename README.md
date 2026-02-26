# VPS Toolbox (vps_script)

一个轻量、模块化的 Linux VPS 管理脚本集。专注于代理服务管理、流量监控与端口转发。

核心理念：**最小依赖、配置安全、功能单一**。拒绝臃肿的面板，回归 Shell 的简洁。

---

## 🚀 快速开始

推荐使用 **VPS Toolbox (`vt`)** 总控脚本，它可以自动下载并管理所有子组件。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/vt.sh)
```

运行后，输入 `vt` 即可唤出主菜单。

---

## 🛠️ 组件列表

所有脚本均可单独使用，互不依赖。

| 脚本 | 功能 | 快捷命令 | 说明 |
| :--- | :--- | :--- | :--- |
| **[vt.sh](vt.sh)** | **总控工具箱** | `vt` | 统一管理入口，查看组件状态，一键清理环境。 |
| **[pm.sh](PM_DOC.md)** | **流量监控** | `pm` | 端口级流量统计、配额封禁、**动态 QoS 限速**、Telegram 通知。 |
| **[snell.sh](SNELL_DOC.md)** | **Snell 管理** | `snell` | 专为 Snell 协议设计，支持 **Systemd 模板化多实例**。 |
| **[x-sb.sh](X-SB_DOC.md)** | **Xray 管理** | `x-sb` | 支持 VLESS-Vision-REALITY 和 Shadowsocks-2022，配置回滚保护。 |
| **[sb.sh](SB_DOC.md)** | **Sing-Box 管理** | `sb` | Sing-Box 内核专用，支持 Reality 和链式代理，元数据分离设计。 |
| **[fw.sh](vps_script/fw.sh)** | **端口转发** | `fw` | 基于 **realm** 的轻量级端口转发，支持 TCP/UDP。 |

---

## ☁️ 云端中控 (Cloudflare)

本工具箱支持将多台 VPS 的流量数据推送到 Cloudflare Worker，实现集中监控和多租户权限管理。

*   👉 **[点击查看 Cloudflare 部署指南](部署教程.md)**

---

## 📦 兼容性

*   **架构:** amd64 (x86_64), arm64 (aarch64)
*   **系统:** Debian 10+, Ubuntu 20.04+ (推荐)
    *   *CentOS/Alpine 部分脚本支持，但未经充分测试。*

## ⚠️ 免责声明

本项目仅供学习与技术研究使用。请遵守当地法律法规，切勿用于非法用途。
