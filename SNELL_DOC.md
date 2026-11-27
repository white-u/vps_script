# Snell 多实例管理

`snell` 管理 Snell v6 多端口实例，支持独立 PSK、导出 Surge 客户端配置，以及查看各实例的服务状态和日志。适用于使用 systemd 和 glibc 的 amd64、arm64 Linux，包括 Debian、Ubuntu 和 RHEL 系发行版。

## 安装

以 root 在 Bash 中运行（需 `curl`），或从 `vt` 进入 Snell。首次进入会安装缺少的 v6 核心。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh)
```

## 使用

1. 运行 `snell`，选择 **2. 添加实例**并填写端口。脚本会生成 PSK，覆盖已有实例会更换 PSK。
2. 选择 **4. 查看客户端配置**或运行 `snell list`，将生成的配置复制到支持 Snell v6 的 Surge 客户端。
3. 如使用云安全组，请放行该端口的 TCP 和 UDP。主机防火墙可由脚本通过 UFW、firewalld 或 iptables 放行。

```bash
snell install     # 安装或更新 v6 核心
snell add         # 添加实例
snell list        # 查看客户端配置
snell status      # 查看状态和日志
snell delete      # 删除实例
snell update      # 更新管理脚本
snell uninstall   # 卸载全部
```

更新核心会短暂中断运行中的实例。切换实例模式时，请让服务端与客户端使用相同设置。卸载前可备份 `/etc/snell/` 中的实例配置和 PSK。
