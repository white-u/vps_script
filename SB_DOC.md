# sing-box 多协议管理脚本（sb.sh）

**脚本版本**：v1.4.1　|　**快捷命令**：`sb`　|　**安装路径**：`/usr/local/bin/sb`

本文档及脚本生成的配置已按 sing-box **1.14.0** 官方配置结构核对（2026-08-31）。脚本只使用稳定版发布，不自动安装预发布版本。

## 1. 当前支持范围

脚本管理以下入站协议：

- **VLESS Vision REALITY（TCP）**
  - `flow` 使用官方支持的 `xtls-rprx-vision`。
  - Reality 密钥由 `sing-box generate reality-keypair` 生成。
  - `short_id` 为 8 位十六进制字符串，符合官方 0–8 位要求。
- **Shadowsocks 2022（TCP/UDP）**
  - 方法为 `2022-blake3-aes-128-gcm`。
  - 密钥由 `sing-box generate rand --base64 16` 生成。
  - 不设置 `network`，按官方定义同时启用 TCP 和 UDP。

Reality 只开放 TCP 防火墙端口；Shadowsocks 2022 同时开放 TCP 和 UDP。

## 2. 安装与菜单

Debian、Ubuntu 等已带 Bash 的系统：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/sb.sh)
```

Alpine Linux 3.21 的最小系统通常未预装 Bash，首次运行使用：

```bash
apk add --no-cache bash curl
bash -c "$(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/sb.sh)"
```

脚本在 Alpine 上自动安装其余依赖并使用 OpenRC 管理服务；在 systemd 系统上保持原有管理方式。

安装后运行：

```bash
sb
```

当前脚本只提供交互式菜单，不支持 `sb add`、`sb list` 等命令行子命令。

```text
1. 安装、检查或更新 sing-box
2. 添加 Reality 节点
3. 添加 SS2022 节点
4. 查看节点详情与分享
5. 删除节点
6. 更新 SB 脚本
7. 卸载全部
0. 退出
```

主页面会直接显示 sing-box 的安装/运行状态、核心版本、节点数量和节点概览；密钥、分享链接及内部文件路径只在对应功能中显示。

## 3. 文件位置

| 内容 | 路径 |
|---|---|
| sing-box 核心 | `/usr/local/bin/sing-box` |
| 管理脚本 | `/usr/local/bin/sb` |
| 主配置 | `/usr/local/etc/sing-box/config.json` |
| 节点元数据 | `/usr/local/etc/sing-box/nodes_meta.json` |
| systemd 服务 | `/etc/systemd/system/sing-box.service` |
| Alpine OpenRC 服务 | `/etc/init.d/sing-box` |
| Alpine OpenRC 日志 | `/var/log/sing-box.log` |
| 工作目录 | `/var/lib/sing-box` |

Reality 服务端配置只需要保存私钥；导出 `vless://` 分享链接还需要公钥。因此脚本把公钥按节点标签保存在权限为 `600` 的 `nodes_meta.json` 中，不把非 sing-box 配置字段混入主配置。

## 4. 核心更新保护

菜单 1 获取 GitHub `releases/latest` 指向的稳定版，并按以下顺序更新：

1. 下载候选核心。
2. 如果 GitHub 提供发布摘要，校验下载文件的 SHA-256。
3. 验证候选核心报告的版本与目标版本一致。
4. 使用候选核心对现有配置执行 `sing-box check`。
5. 备份旧核心并原子替换二进制。
6. 根据系统重写 systemd 或 OpenRC 服务，设置开机自启，重启后检查运行状态。
7. 新核心失败时恢复旧核心并再次启动。

配置不兼容时旧核心不会被覆盖；启动失败会打印服务日志并返回失败，不会显示为更新成功。
未设置固定版本时，脚本也会拒绝把已经安装的更高稳定版本降级。

## 5. 旧跨机出口配置迁移

v1.3.0 已移除 SS2022 跨机出口中继、节点链式出站和旧 SOCKS5 上游兼容模块。普通 Shadowsocks-2022 节点的创建、查看、分享和删除功能不受影响。

更新后首次运行脚本时，如果检测到旧模块配置，会删除：

- 标签以 `relay_` 开头的专用中继入站。
- 标签为 `chain_proxy` 的 SS2022 或 SOCKS5 出站。
- 所有指向 `chain_proxy` 的节点路由规则。

普通 `reality_*` 和 `ss_*` 节点会保留并恢复使用本机直连出口。迁移前会生成候选配置并执行 `sing-box check`；服务运行时应用失败会恢复原配置，服务停止时只更新配置文件而不会自动启动服务。
旧中继端口从未由该模块修改防火墙，迁移清理也不会打开或关闭任何防火墙规则。

## 6. 配置安全

- 每次变更先执行 JSON 校验和 `sing-box check`。
- 主配置通过同目录临时文件原子替换。
- 服务重启失败时恢复上一份配置。
- 默认拒绝客户端直接访问私网 IP，也拒绝解析后落入私网的域名。
- SS2022 密钥和 Reality 公私钥不会写入日志；`config.json` 权限为 `640`，元数据文件权限为 `600`。
- VLESS 分享链接使用 Reality 常用参数；Shadowsocks 2022 分享链接遵循 SIP002 对 AEAD-2022 明文、百分号编码 `userinfo` 的要求。

## 7. 卸载

菜单 7 会通过 systemd 或 OpenRC 停止并禁用服务，按节点协议清理防火墙端口，并删除核心、配置、工作目录、OpenRC 日志和管理脚本。该操作需要输入 `yes` 确认。

## 8. Alpine 3.21 支持范围

- 支持 `x86_64` 与 `aarch64`；Alpine 自动选择 sing-box 官方 `-musl` 发布文件，避免通用 glibc 构建无法启动。
- 使用 `apk` 安装 Bash、curl、tar、jq、OpenSSL、qrencode、iproute2 与 OpenRC。
- OpenRC 服务使用 `supervise-daemon` 保持前台核心运行，异常退出后自动重启，并加入 `default` runlevel。
- 安装、配置更新、运行状态检查、核心回滚和卸载均通过统一服务接口执行。
- 菜单运行状态同时检查 OpenRC 和实际核心子进程，避免将“等待重启”误报为运行中；启动失败会打印日志并回滚。检查仅在菜单操作时执行，不新增后台轮询。
- 临时文件兼容 Alpine 自带 BusyBox，无需额外安装 GNU coreutils。卸载会先停止服务（包括等待重启状态），停止失败则保留文件。
- 如果系统没有启用 UFW、firewalld 或 iptables，脚本不会自行创建一套新防火墙；云厂商安全组仍需用户自行放行。

OpenRC 环境查看状态与日志：

```bash
rc-service sing-box status
tail -n 30 /var/log/sing-box.log
```

## 9. 官方参考

- [VLESS 入站](https://sing-box.sagernet.org/configuration/inbound/vless/)
- [TLS / Reality](https://sing-box.sagernet.org/configuration/shared/tls/#reality-fields)
- [Shadowsocks 入站](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/)
- [路由规则动作](https://sing-box.sagernet.org/configuration/route/rule_action/)
- [1.14.0 迁移说明](https://sing-box.sagernet.org/migration/#1140)
- [SIP002 URI Scheme](https://github.com/shadowsocks/shadowsocks-org/wiki/SIP002-URI-Scheme)
- [Alpine OpenRC](https://wiki.alpinelinux.org/wiki/OpenRC)
- [OpenRC 服务脚本指南](https://github.com/OpenRC/openrc/blob/master/service-script-guide.md)
