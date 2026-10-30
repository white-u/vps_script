# 项目与文档索引

本仓库是 Linux VPS 管理脚本集。初次使用从 [README](README.md) 开始，维护代码先读 [项目导览](PROJECT.md)，验证修改查 [开发与验证](DEVELOPMENT.md)。本文与导览描述源码行为；平台支持和实机验收范围以 README 及组件手册为准。

## 按任务查找

| 任务 | 文档 | 实现入口 |
| --- | --- | --- |
| 安装工具箱、了解兼容性、统一卸载 | [README](README.md) | [vt.sh](vt.sh) |
| Snell 多实例、更新与恢复 | [Snell 手册](SNELL_DOC.md) | [snell.sh](snell.sh) |
| sing-box 节点、路由、Alpine 支持 | [sing-box 手册](SB_DOC.md) | [sb.sh](sb.sh) |
| 独立 Xray 与链式代理 | [Xray 手册](X-SB_DOC.md) | [x-sb.sh](x-sb.sh) |
| 端口流量、配额、突发限速、接入与到期告警 | [PM 手册](PM_DOC.md) | [pm.sh](pm.sh) |
| TCP/UDP 转发、连通性与回滚 | [FW 手册](FW_DOC.md) | [fw.sh](fw.sh) |
| Cloudflare D1、Worker、Telegram 权限 | [中控部署](部署教程.md) | [worker.js](worker.js) |
| 初始化、时间、BBR、SSH 安全边界 | [README 中的初始化说明](README.md) | [init.sh](init.sh) |
| 公网地址、延迟、双向带宽和回程检测 | [项目导览](PROJECT.md) | [network_audit.sh](network_audit.sh) |
| 修改代码、选测试、故障注入与 Linux 集成验证 | [开发与验证](DEVELOPMENT.md) | [tests](tests/) |

## 两个项目的关系

| 维度 | vps_script | monitor |
| --- | --- | --- |
| 核心对象 | 代理实例、转发规则、服务端口 | 主机节点、主机指标、探测任务 |
| 流量来源 | PM 的 nftables 端口计数 | 外部 agent 的主机网卡累计计数 |
| 控制能力 | 安装服务、配额封禁、TC 突发限速 | 监控展示、历史记录、通知 |
| 中控 | Cloudflare Worker + D1 + Telegram | 自托管 Rust hub + SQLite + Web 后台 |

两者可部署在同一 VPS，但当前源码没有直接互调、共享数据库或数据同步协议。PM 端口流量与 monitor 主机流量的统计范围不同，不能直接当作同一账本。

同级检出时可打开 [monitor 文档索引](../monitor/INDEX.md)。此链接是本地工作区导航，单独克隆本仓库时请访问 [monitor 仓库](https://github.com/white-u/monitor)。

## 文档维护

用户操作与配置细节放在各组件手册；源码职责和关联关系放在 PROJECT.md；测试入口和验证约束放在 DEVELOPMENT.md。修改路径、命令、数据格式或更新策略时同步相应文档，并维护此索引。避免把同一份完整配置示例复制到多处。
