# Snell 多实例管理

`snell.sh` 用一个 systemd 模板服务管理多个 Snell v6 实例，每个端口拥有独立配置和 PSK。

**脚本版本**：v1.0.0　|　**核心基线**：v6（动态检测官方最新下载版本）　|　**快捷命令**：`snell`

## 版本策略

执行 `snell install` 或菜单 1 时，脚本读取 Surge 官方发布页，按当前架构选择版本号最高的纯数字下载版本（例如 v6.0.0），不选择带 Beta/RC 后缀的下载包。官方当前的 v6.0.0 虽然没有版本后缀，发布说明仍标注为测试阶段；此策略跟随官方实际下载版本，不承诺它是稳定版。

安装和更新以 v6 为基线，不再安装 v5。以后 v6.x 的纯数字新版本无需修改脚本即可检测和安装；检测到其他主版本时停止并提示先适配管理脚本，避免未经兼容处理直接替换。不会后台定时检查。官方页面请求失败、缺少当前架构的有效链接时直接失败，不回退固定版本。

已知的 v6.0.0 发行包和二进制使用脚本内固定 SHA256 校验。未来未预置校验值的版本通过官方 HTTPS 下载、检查 ZIP 完整性，再运行 `--version` 核对版本与可执行性，并明确提示没有预置 SHA256；这些检查不等同于发行方签名验证。成功安装后记录核心 SHA256，用于后续本地完整性检查。

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
snell install         # 检测、安装或修复官方最新 v6 核心
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
listen = 0.0.0.0:10086,[::]:10086
psk = <32 字符随机 PSK>
ipv6 = true
tfo = true
mode = default
dns-ip-preference = default
dns = 1.1.1.1, 8.8.8.8, 2001:4860:4860::8888
```

对应的 Surge 配置：

```text
snell-10086 = snell, 1.2.3.4, 10086, psk=<PSK>, version=6, tfo=true, reuse=true, mode=default
```

v6 不支持旧 `obfs` 参数，也不支持 v5 的 QUIC Proxy Mode；普通 UDP 转发仍支持。升级旧实例时删除 `obfs`、`obfs-host`、`obfs-uri`，缺少 `mode` 时补入 `mode=default`，保留原端口、监听地址、PSK 和 DNS。新建实例显式监听 IPv4/IPv6。

`mode=default` 启用加密和基于 PSK 的流量整形。手动设置 `unshaped` 时保留加密、关闭整形；`unsafe-raw` 关闭加密及整形。客户端导出会同步实际模式，客户端与服务端必须一致。

`dns-ip-preference` 支持 `default`、`prefer-ipv4`、`prefer-ipv6`、`ipv4-only`、`ipv6-only`，新建实例默认使用 `default`。客户端需支持 Snell v6（官方手册标注 Surge iOS 5.20.0+、Mac 6.7.0+），并使用 `version=6`。跨主版本升级前会要求确认，升级后通过 `snell list` 获取新配置；PSK 不变。

## 更新与失败恢复

核心更新按以下顺序执行：

1. 检测并下载官方最新 v6 发行包，显示进度条；完成后提示校验、解压和核心检查阶段。
2. 备份核心、systemd 服务、版本记录和待迁移的实例配置。
3. 记录当前正在运行的实例并短暂停止它们。
4. 原子替换文件，仅恢复更新前处于运行状态的实例。
5. 新核心启动失败或停服/替换期间收到 Ctrl+C、TERM 时，自动恢复旧核心、实例配置及原运行状态。恢复期间忽略重复中断；回滚不完整时保留备份并输出路径，供人工恢复。

已经停止的实例不会因为更新而被自动启动。本地版本、核心 SHA256、服务文件及配置均符合预期时，只整理配置权限，不重新下载或停机。

覆盖现有端口会生成新 PSK。新配置启动失败时会恢复旧配置、旧 PSK 及原来的启用/运行状态。

## 防火墙

创建实例时默认放行对应端口的 TCP 和 UDP。脚本依次检测 UFW、firewalld、iptables，使用第一个可用工具；没有检测到这些工具时直接跳过。规则添加失败不会停止已经正常运行的实例，但命令会返回失败并明确提示手动处理。

删除实例或完整卸载时会清理对应端口的 TCP、UDP 规则。脚本不处理云厂商安全组，也不会直接管理纯 nftables 规则集。

## 安全说明

Snell 优先追求性能。官方明确说明它不提供前向保密，也没有专用重放保护机制；PSK 派生参数同样偏向低开销。需要更强安全保证时，应优先选择基于 TLS 的代理协议。

脚本使用官方建议长度的 32 字符随机 PSK，并使用独立的 `snell` 用户运行服务。配置由 `root:snell` 持有，普通 Snell 进程只能读取，不能修改其他实例的 PSK。

配置目录、实例配置、版本文件或用户归属标记若被替换为符号链接，涉及权限整理或卸载的操作会拒绝继续，避免越过 `/etc/snell` 的文件边界。

## 文件与权限

- 管理脚本：`/usr/local/bin/snell`
- Snell 核心：`/usr/local/bin/snell-server`
- 配置目录：`/etc/snell`，权限 `750 root:snell`
- 实例配置：`/etc/snell/<端口>.conf`，权限 `640 root:snell`
- systemd 模板：`/etc/systemd/system/snell@.service`
- 日志：`journalctl -u 'snell@*' -n 50 --no-pager`

## 卸载

卸载前会先确认所有实例均已停止并取消开机启动；任一步失败时不会继续删除文件。完成后会验证核心、配置、服务和快捷命令是否残留。

脚本只删除带有归属标记、能够确认由脚本创建的 `snell` 用户。安装前已经存在且归属不明的同名用户会被保留并明确提示。
