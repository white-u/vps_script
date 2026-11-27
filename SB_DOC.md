# sing-box 多协议管理

`sb` 管理 VLESS Vision REALITY（TCP）和 Shadowsocks 2022（TCP/UDP），支持节点分享、核心更新、状态及日志查看。

## 安装

支持 Debian/Ubuntu 等 systemd 系统，以及 Alpine 3.21（OpenRC）。Alpine 如缺少 Bash 和 curl，以 root 运行 `apk add --no-cache bash curl`。安装时以 root 打开 Bash，或从 `vt` 进入 sing-box。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/sb.sh)
```

首次进入会自动安装缺少的核心。

## 使用

运行 `sb` 打开交互菜单。

1. 选择 **2. 添加 Reality 节点**或 **3. 添加 SS2022 节点**，按提示填写端口。添加 Reality 节点时，从列表选取目标域名或手动输入支持 TLS 1.3 和 HTTP/2 的 HTTPS 域名。
2. 选择 **4. 查看节点详情与分享**，复制配置或分享链接到客户端。
3. 需要删除节点时选 **5**。查看服务状态、配置检查和日志时选 **8**。如使用云安全组，Reality 放行 TCP，SS2022 放行 TCP 和 UDP。

菜单 **1** 安装或更新 sing-box 核心，**6** 更新管理脚本，**7** 输入 `yes` 后卸载。备份节点时，请一并保存 `/usr/local/etc/sing-box/config.json` 和 `/usr/local/etc/sing-box/nodes_meta.json`，后者用于导出分享配置。
