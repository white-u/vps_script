# sing-box 多协议管理脚本（sb.sh）

**脚本版本**：v1.2.1　|　**快捷命令**：`sb`　|　**安装路径**：`/usr/local/bin/sb`

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
- **SS2022 加密出口中继（推荐）**
  - B 机可以创建独立中继端口和密钥。
  - A 机可以将任意 Reality/SS2022 入站节点单独路由到 B 机出口。
  - A→B 默认同时支持 TCP/UDP，失败时不会回落到 A 机直连。
  - 创建、删除中继不会修改 UFW、firewalld 或 iptables；端口策略由用户自行管理。
- **SOCKS5 上游流量转发（旧配置兼容）**
  - 支持 IPv4、域名、`[IPv6]:端口`。
  - 支持无认证或用户名/密码认证。
  - 可以为每个已有节点单独启用或关闭。

Reality 只开放 TCP 防火墙端口；Shadowsocks 2022 同时开放 TCP 和 UDP。

## 2. 安装与菜单

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/sb.sh)
```

安装后运行：

```bash
sb
```

当前脚本只提供交互式菜单，不支持 `sb add`、`sb list` 等命令行子命令。

```text
1) 安装/更新 sing-box 核心
2) 添加 VLESS-Vision-REALITY 节点
3) 添加 Shadowsocks-2022 节点
4) 查看节点/导出分享链接
5) 删除节点
6) SS2022 加密出口/路由
7) 更新脚本
8) 卸载 sing-box + 删除全部配置
0) 退出
```

## 3. 文件位置

| 内容 | 路径 |
|---|---|
| sing-box 核心 | `/usr/local/bin/sing-box` |
| 管理脚本 | `/usr/local/bin/sb` |
| 主配置 | `/usr/local/etc/sing-box/config.json` |
| 节点元数据 | `/usr/local/etc/sing-box/nodes_meta.json` |
| systemd 服务 | `/etc/systemd/system/sing-box.service` |
| 工作目录 | `/var/lib/sing-box` |

Reality 服务端配置只需要保存私钥；导出 `vless://` 分享链接还需要公钥。因此脚本把公钥按节点标签保存在权限为 `600` 的 `nodes_meta.json` 中，不把非 sing-box 配置字段混入主配置。

## 4. 核心更新保护

菜单 1 获取 GitHub `releases/latest` 指向的稳定版，并按以下顺序更新：

1. 下载候选核心。
2. 如果 GitHub 提供发布摘要，校验下载文件的 SHA-256。
3. 验证候选核心报告的版本与目标版本一致。
4. 使用候选核心对现有配置执行 `sing-box check`。
5. 备份旧核心并原子替换二进制。
6. 重写并重载 systemd 服务，重启后检查运行状态。
7. 新核心失败时恢复旧核心并再次启动。

配置不兼容时旧核心不会被覆盖；启动失败会打印服务日志并返回失败，不会显示为更新成功。
未设置固定版本时，脚本也会拒绝把已经安装的更高稳定版本降级。

## 5. 流量转发功能

推荐结构是 **sing-box 应用层 SS2022 加密链式出站**：

```text
用户 → A机 Reality/SS2022 入站
     → A机 chain_proxy（SS2022 加密出站）
     → B机 relay_端口（专用 SS2022 入站）
     → B机 direct
     → 最终网站或服务
```

用户客户端始终连接 A 机，不需要配置或知道 B 机。目标网站看到 B 机公网 IP。

未启用转发时，路径为：

```text
客户端 → 本机 sing-box → direct → 最终目标
```

### 5.1 配置和启用

进入菜单 `6) SS2022 加密出口/路由`。

在 B 机：

1. 选择 `B机：创建 SS2022 专用出口中继`。
2. 输入独立中继端口，脚本生成独立 SS2022 密钥并输出 A 机所需参数。
3. 脚本不会修改任何本机防火墙规则；根据现有策略自行放行该 TCP/UDP 端口。
4. 如需进一步缩小暴露面，可在云厂商安全组中将该端口来源限制为 A 机 IP/32。

在 A 机：

1. 选择 `A机：配置/替换/删除 SS2022 加密上游`。
2. 填写 B 机输出的地址和密钥。
3. 选择 `A机：设置现有节点是否走 B 机`，为指定节点启用转发。
4. 新建 Reality/SS2022 节点时，如果已经配置上游，脚本也会询问是否启用。

上游使用固定标签 `chain_proxy`。从旧 SOCKS5 切换到 SS2022 时，已选择节点的路由规则继续有效，节点和客户端配置无需重建。

每个节点的路由使用官方新式规则动作：

```json
{
  "inbound": ["reality_443"],
  "action": "route",
  "outbound": "chain_proxy"
}
```

脚本先解析目标域名，再执行私网地址拒绝，最后才匹配链式转发，避免域名或直接 IP 绕过本机的私网访问保护。旧配置会自动校验并原子迁移；服务正在运行时迁移失败会恢复原配置，停止状态下则只更新配置、不启动服务。

### 5.2 功能边界

- 它不是 `iptables`、NAT 或端口映射，不会把一个监听端口原样转发到另一台服务器。
- B 机看到的是 A 机发起的 SS2022 会话，不保留原始客户端源 IP。
- 为执行私网保护，目标域名会先在入口机解析，再交给 `direct` 或 `chain_proxy`。
- Reality 入站当前只有 TCP；SS2022 入站和 SS2022 加密中继默认同时启用 TCP/UDP。
- B 机中继不可用时，已选择转发的节点会连接失败；不会自动回落到 A 机直连，避免出口策略被静默绕过。
- 链式转发增加一段网络路径，延迟取决于“本机 → 上游 → 目标”，吞吐上限取决于两段链路中较慢的一段。
- `fw.sh` 的端口转发解决的是“端口 A → 地址 B:端口 C”；本功能解决的是“某个代理节点的所有出站请求改走 B 机出口”。仅使用该代理链路时无需部署 `fw.sh`。
- 普通 SOCKS5 没有传输加密，只保留用于本机、可信私网或旧配置兼容；不建议作为公网 A→B 链路。

## 6. 配置安全

- 每次变更先执行 JSON 校验和 `sing-box check`。
- 主配置通过同目录临时文件原子替换。
- 服务重启失败时恢复上一份配置。
- 默认拒绝客户端直接访问私网 IP，也拒绝解析后落入私网的域名。
- 专用中继使用独立随机密钥，但脚本不接管服务器的防火墙；创建、删除和卸载均不会改动该中继端口的防火墙规则。
- 中继密钥和 Reality 公私钥不会写入日志；`config.json` 权限为 `640`，元数据文件权限为 `600`。
- VLESS 分享链接使用 Reality 常用参数；Shadowsocks 2022 分享链接遵循 SIP002 对 AEAD-2022 明文、百分号编码 `userinfo` 的要求。

## 7. 卸载

菜单 8 会停止并禁用服务，按节点协议清理防火墙端口，并删除核心、配置、工作目录和管理脚本。该操作需要输入 `yes` 确认。

## 8. 官方参考

- [VLESS 入站](https://sing-box.sagernet.org/configuration/inbound/vless/)
- [TLS / Reality](https://sing-box.sagernet.org/configuration/shared/tls/#reality-fields)
- [Shadowsocks 入站](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/)
- [Shadowsocks 出站](https://sing-box.sagernet.org/configuration/outbound/shadowsocks/)
- [SOCKS 出站](https://sing-box.sagernet.org/configuration/outbound/socks/)
- [路由规则动作](https://sing-box.sagernet.org/configuration/route/rule_action/)
- [1.14.0 迁移说明](https://sing-box.sagernet.org/migration/#1140)
- [SIP002 URI Scheme](https://github.com/shadowsocks/shadowsocks-org/wiki/SIP002-URI-Scheme)
