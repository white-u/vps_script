# FW 端口转发

`fw.sh` 是基于 [Realm](https://github.com/zhboner/realm) 的轻量端口转发管理脚本，默认同时转发 TCP 和 UDP。

**脚本版本**：v2.3.1　|　**快捷命令**：`fw`

## 支持范围

- 系统：Debian 10+ / Ubuntu 20.04+ 及其他使用 systemd、glibc 2.28+ 的 Linux。
- 架构：amd64、arm64、armv7。
- 目标：IPv4 地址。
- Realm：[v2.9.6](https://github.com/zhboner/realm/releases/tag/v2.9.6)，安装时校验官方 SHA256 和二进制版本。

Alpine/OpenRC 暂不支持。

## 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/fw.sh)
```

安装后使用 `fw` 打开交互菜单。

菜单顺序与 SB 模块保持一致：

```text
1. 安装 Realm / 更新或重装 Realm
2. 添加转发规则
3. 测试转发规则
4. 服务状态与日志
5. 删除转发规则
6. 更新 FW 脚本
7. 卸载全部
0. 退出
```

## 常用命令

```bash
fw                         # 交互菜单
fw install                 # 安装或更新 Realm
fw list                    # 查看规则
fw add 44111 1.2.3.4 443 HK
fw del 44111
fw status
fw update                  # 更新 FW 脚本
fw uninstall
```

## 内置连通性测试

通过交互菜单添加规则成功后，脚本会询问是否立即测试；之后也可以选择“测试转发规则”重新检测。脚本会检查：

- Realm 服务是否运行。
- 该源端口是否由 Realm 监听 TCP 和 UDP。
- 本机能否在 4 秒内连接目标 TCP 端口。

该检查不会修改规则或防火墙，也不会把本机监听误报为公网端到端成功。云安全组、UFW/firewalld、外部客户端入口以及 UDP 应用层通信仍需按实际协议验证。

## 防火墙

FW **不会自动修改** UFW、firewalld、nftables 或 iptables。如外部无法连接，请按当前系统策略手动放行监听端口的 TCP/UDP。

旧版 FW 曾自动放行端口。更新或卸载新版时不会冒险删除这些无法确认归属的规则，请自行检查。

## 运行说明

- Realm 是端口转发器，不提供额外的认证或加密。目标服务应自身具有安全机制，例如 Reality 或 SS2022。
- 所有规则由一个 Realm 进程承载。添加或删除规则会重启 Realm，已有连接会短暂中断。
- Realm 更新会先备份旧二进制和 systemd 服务；新版启动失败时自动回滚。
- 运行警告输出到 systemd journal，可使用 `journalctl -u realm -n 50 --no-pager` 查看。

## 文件位置

- 快捷命令：`/usr/local/bin/fw`
- Realm 二进制：`/usr/local/bin/realm`
- Realm 配置：`/etc/realm/config.toml`
- FW 规则：`/etc/realm/fw.json`
- systemd 服务：`/etc/systemd/system/realm.service`
