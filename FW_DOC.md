# FW 端口转发

FW 使用 Realm 转发 TCP 和 UDP，支持查看服务状态、日志和规则连通性。目标须为 IPv4 地址。支持 Debian 10+、Ubuntu 20.04+ 及其他使用 systemd 和 glibc 2.28+ 的 Linux，架构为 amd64、arm64 和 armv7。

## 安装

以 root 在 Bash 中运行（需 `curl`），或从 `vt` 进入 FW。首次进入会安装 Realm。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/fw.sh)
```

## 使用

运行 `fw` 后选择 **2. 添加转发规则**，填写本机监听端口、目标 IPv4、目标端口及可选备注。目标端口留空时与本机监听端口相同。请在主机防火墙和云安全组放行所需的 TCP/UDP 监听端口。添加或删除规则会短暂中断已有连接。

菜单 **3. 测试转发规则**检查本机 TCP/UDP 监听和目标 TCP 连接。公网访问和 UDP 转发可通过外部客户端验证。菜单 **4. 服务状态与日志**可查看 Realm 状态和日志。

```bash
fw install                  # 安装或更新 Realm
fw list                     # 查看规则
fw add 44111 192.0.2.1 443 HK
fw del 44111
fw status
fw update                   # 更新管理脚本
fw uninstall                # 卸载并删除规则
```

运行示例前请将 `192.0.2.1` 换成实际目标。卸载前可备份 `/etc/realm/`。手动添加的防火墙规则由管理员清理。
