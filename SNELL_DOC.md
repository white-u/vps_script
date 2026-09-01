# Snell 多实例管理

`snell.sh` 用一个 systemd 模板服务管理多个 Snell v5 实例，每个端口拥有独立配置和 PSK。

**脚本版本**：v5.3.1　|　**稳定核心**：v5.0.1　|　**快捷命令**：`snell`

## 版本策略

脚本固定使用 Surge 官方稳定版 Snell v5.0.1，不会自动安装 v6 Beta/RC。发行包和二进制均校验固定 SHA256，校验失败时拒绝替换现有核心。

- [Snell 官方发布说明](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell)
- [Surge Snell 配置手册](https://manual.nssurge.com/policies/snell.html)

## 支持范围

- Linux、systemd、glibc。
- amd64、arm64。
- Debian/Ubuntu 和使用 yum/dnf 的 RHEL 系发行版。
- Alpine/OpenRC、i386、armv7 暂不支持。

## 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh)
```

安装后运行 `snell`：

```text
1. 安装 Snell / 检查或更新 Snell
2. 添加实例 (新端口)
3. 服务状态与日志
4. 查看客户端配置
5. 删除实例
6. 更新 Snell 脚本
7. 卸载全部
0. 退出
```

## 常用命令

```bash
snell                 # 交互菜单
snell install         # 检查、安装或修复稳定版核心
snell add             # 添加实例
snell list            # 查看 Surge 客户端配置
snell status          # 查看实例状态和最近日志
snell delete          # 删除实例
snell update          # 更新管理脚本
snell uninstall       # 卸载全部
snell help
```

## 实例配置

新增实例会生成 32 字符随机 PSK，配置示例：

```ini
[snell-server]
listen = ::0:10086
psk = <32 字符随机 PSK>
ipv6 = true
tfo = true
obfs = off
dns = 1.1.1.1, 8.8.8.8, 2001:4860:4860::8888
```

对应的 Surge 配置：

```text
snell-10086 = snell, 1.2.3.4, 10086, psk=<PSK>, version=5, tfo=true, reuse=true
```

如手动将服务端改为 `obfs = http`，脚本会在客户端配置中追加 `obfs=http`。Snell v5 不支持 TLS 混淆。

## 更新与失败恢复

核心更新按以下顺序执行：

1. 下载并验证官方稳定版发行包。
2. 备份核心、systemd 服务和版本记录。
3. 记录当前正在运行的实例并短暂停止它们。
4. 原子替换文件，仅恢复更新前处于运行状态的实例。
5. 新核心启动失败时自动恢复旧核心及原运行状态。

已经停止的实例不会因为更新而被自动启动。核心已是正确的 v5.0.1 时只检查配置权限，不产生停机。

覆盖现有端口会生成新 PSK。新配置启动失败时会恢复旧配置、旧 PSK 及原来的启用/运行状态。

## 防火墙

脚本不会修改 UFW、firewalld、nftables、iptables 或云安全组。公网使用时请根据实际策略自行放行实例端口的 TCP 和 UDP。

旧版脚本可能添加过无法确认归属的通用放行规则。新版更新或卸载不会冒险删除这些规则，请按服务器当前防火墙策略人工检查。

## 安全说明

Snell 优先追求性能。官方明确说明它不提供前向保密，也没有专用重放保护机制；PSK 派生参数同样偏向低开销。需要更强安全保证时，应优先选择基于 TLS 的代理协议。

脚本使用官方建议长度的 32 字符随机 PSK，并使用独立的 `snell` 用户运行服务。配置由 `root:snell` 持有，普通 Snell 进程只能读取，不能修改其他实例的 PSK。

配置目录、实例配置、版本文件或用户归属标记若被替换为符号链接，涉及权限迁移或卸载的操作会拒绝继续，避免越过 `/etc/snell` 的文件边界。

## 文件与权限

- 管理脚本：`/usr/local/bin/snell`
- Snell 核心：`/usr/local/bin/snell-server`
- 配置目录：`/etc/snell`，权限 `750 root:snell`
- 实例配置：`/etc/snell/<端口>.conf`，权限 `640 root:snell`
- systemd 模板：`/etc/systemd/system/snell@.service`
- 日志：`journalctl -u 'snell@*' -n 50 --no-pager`

## 卸载

卸载前会先确认所有实例均已停止并取消开机启动；任一步失败时不会继续删除文件。完成后会验证核心、配置、服务和快捷命令是否残留。

脚本只删除带有归属标记、能够确认由本版本创建的 `snell` 用户。升级前已经存在且归属不明的同名用户会被保留并明确提示。
