# Xray 多协议管理

`x-sb` 管理 VLESS Vision REALITY、Shadowsocks 2022 节点，支持分享链接、SOCKS5 链式代理及路由设置。适用于使用 systemd 的 Debian/Ubuntu（amd64、arm64）。

## 安装

以 root 在 Bash 中运行（需 `curl`）。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/x-sb.sh)
```

运行 `x-sb` 后选择 **1. 安装 / 更新 Xray 核心**。也可运行 `x-sb install`。

## 使用

1. 选择 **2. 添加 VLESS-Vision-Reality 节点**或 **3. 添加 Shadowsocks-2022 节点**，按提示配置端口和协议参数。REALITY 节点需选择目标域名。
2. 选择 **4. 查看节点配置 / 分享链接**，将配置导入客户端。
3. 使用 **6. 进阶配置** → **1. 配置上游 SOCKS5 代理**可设置上游地址，例如 `127.0.0.1:40000`。添加节点时选择启用链式转发即可。

选择 **5** 删除节点，**7** 更新管理脚本，**8** 卸载。保存配置会重启 Xray，现有连接可能短暂中断。卸载前可备份 `/usr/local/etc/xray/`。
