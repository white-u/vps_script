# FW 端口转发

`fw.sh` 是基于 [Realm](https://github.com/zhboner/realm) 的轻量端口转发管理脚本，默认同时转发 TCP 和 UDP。

**脚本版本**：v2.3.6　|　**快捷命令**：`fw`

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

Realm 安装包下载时显示进度条，下载完成后依次提示校验、解压和服务检查阶段。

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

添加规则时逐项检查本机监听端口、目标 IPv4 地址和目标端口，输错只重填当前项，保留已填写内容；本机端口已配置或被占用时也可直接重填。上述各项输入 `0` 返回，目标端口回车默认与本机监听端口相同，备注回车留空。

删除和测试规则时，序号输错可重新选择，输入 `0` 直接返回主菜单，无需再次按回车。添加、删除在最终确认前展示完整转发地址、TCP/UDP 和备注，并提示对现有连接的影响；添加默认确认，删除默认取消，确认处也可输入 `0` 返回。操作或测试完成后保留结果，按回车返回。

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

通过 `vt` 统一卸载 FW 时同样保留防火墙规则；Realm 停止失败或仍在运行时，会报告清理失败并保留 FW 文件和配置。如果确认服务尚未安装且处于未运行状态，则允许清理初次打开或下载失败留下的文件；状态查询失败时仍保留文件。

## 运行说明

- Realm 是端口转发器，不提供额外的认证或加密。目标服务应自身具有安全机制，例如 Reality 或 SS2022。
- 所有规则由一个 Realm 进程承载。添加或删除规则会重启 Realm，已有连接会短暂中断。
- 启动或重启后最多等待 5 秒，核对全部规则的 TCP/UDP 端口是否由 Realm 服务主进程监听；检查失败会触发现有回滚流程。目标服务器暂时不可达不会因此回滚规则。
- Realm 更新会先备份旧二进制和 systemd 服务；新版启动失败时自动回滚。
- 增删规则或更新 Realm 期间收到中断信号时，会先尝试回滚再退出；恢复期间忽略重复中断。回滚未完成时保留 `/etc/realm/` 下的恢复备份，并显示具体路径，不随退出清理删除。
- 运行警告输出到 systemd journal，可使用 `journalctl -u realm -n 50 --no-pager` 查看。

## 文件位置

- 快捷命令：`/usr/local/bin/fw`
- Realm 二进制：`/usr/local/bin/realm`
- Realm 配置：`/etc/realm/config.toml`
- FW 规则：`/etc/realm/fw.json`
- systemd 服务：`/etc/systemd/system/realm.service`

## 开发验证

在项目根目录运行（需要 Python 3、jq、curl 和 Bash 4+）：

```bash
python3 -m unittest discover -s tests -v
```

可用 `BASH_BIN` 指定 Bash 路径。测试在临时目录中模拟服务和监听状态，并使用本地 HTTP 服务与真实 curl 验证下载进度、下载失败和校验失败；同时覆盖更新、删除序号、监听失败回滚、中断恢复、回滚失败备份保留，以及 `vt` 在安装完整或未完成时的 FW 卸载，不操作宿主机服务和防火墙。真实 Linux/systemd 与公网转发仍需在目标环境验证。
