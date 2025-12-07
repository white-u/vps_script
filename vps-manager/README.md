# VPS Manager

统一的 VPS 代理服务管理工具。

## 功能

- **Snell** - 安装/更新/配置管理，版本自动检测
- **sing-box** - 多协议支持 (VLESS-Reality, Shadowsocks)
- **流量监控** - nftables 计数，配额限制，带宽限速，阈值告警
- **系统优化** - BBR + TCP Fast Open + 内核参数优化
- **Telegram 通知** - 安装/更新/流量告警推送

## 安装

```bash
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/vps-manager/install.sh)
```

## 使用

```bash
vps              # 主菜单
vps snell        # Snell 管理
vps sb           # sing-box 管理
vps traffic      # 流量监控
vps help         # 查看帮助
```

## 文件结构

```
/usr/local/lib/vps-manager/
├── vps.sh              # 主入口
└── modules/
    ├── common.sh       # 公共函数
    ├── snell.sh        # Snell 模块
    ├── singbox.sh      # sing-box 模块
    └── traffic.sh      # 流量监控模块

/etc/vps-manager/
├── config.json         # 全局配置
├── snell/              # Snell 配置
├── sing-box/           # sing-box 配置
└── traffic/            # 流量数据
```

## 命令速查

| 命令 | 说明 |
|------|------|
| `vps snell install` | 安装 Snell |
| `vps snell update` | 更新 Snell |
| `vps sb add r` | 添加 VLESS-Reality |
| `vps sb add ss` | 添加 Shadowsocks |
| `vps sb list` | 配置列表 |
| `vps traffic status` | 流量状态 |
| `vps traffic reset 8080` | 重置端口流量 |
| `vps telegram` | Telegram 设置 |
| `vps set-bbr` | 启用 BBR |
