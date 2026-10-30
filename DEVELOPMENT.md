# 开发与验证

[文档索引](INDEX.md) · [项目导览](PROJECT.md)

## 本地检查

从仓库根目录运行。需要 Python 3、Bash 4+、jq、curl 和 Node.js。macOS 系统自带 Bash 通常不足 4，先选择已安装的新版 Bash，并通过 `BASH_BIN` 告知测试。

```bash
bash --version
for script in *.sh; do bash -n "$script" || exit; done
python3 -m unittest discover -s tests -v
```

例如安装在 `/opt/homebrew/bin/bash` 时：

```bash
BASH_BIN=/opt/homebrew/bin/bash python3 -m unittest discover -s tests -v
```

Shell 语法检查同样应使用 Bash 4+。不要以 root 在开发机直接执行安装脚本验证，也不要 source 整个脚本：其入口可能安装依赖或改写系统。

## 按改动选择测试

下表文件均在 [tests](tests/) 下。可用 `python3 -m unittest discover -s tests -p 'test_pm.py' -v` 运行单个测试文件；共享流程改动应扩大到关联文件。

| 范围 | 测试文件 | 重点 |
| --- | --- | --- |
| 工具箱菜单、下载、统一卸载 | `test_vt.py`、`test_vt_cleanup.py`、`test_downloads.py` | EOF、子进程失败、残留保护、重试、脚本候选校验 |
| PM | `test_pm.py`、`test_user_flows.py`、`test_performance.py` | 格式拒绝、计数基线、规则恢复、分组编辑、告警重试、批量查询 |
| Realm / FW | `test_fw.py` | 规则校验、监听、事务回滚、中断与卸载 |
| Snell | `test_snell.py` | 版本发现、多实例迁移、回滚、客户端导出 |
| sing-box / Xray 与错误反馈 | `test_user_flows.py`、`test_prompt_errors.py` | 节点增删、保存和恢复失败、OpenRC 清理、状态未知 |
| 初始化与网络 | `test_init_setup.py`、`test_init_network_security.py`、`test_prompt_errors.py` | SSH 生效配置、DNS 超时、公钥、下载安全、时区、BBR |
| Worker | `test_worker.py`、`test_worker_flows.py`、`test_performance.py` | 请求入口、签名、授权隔离、去重、分页和超时预算 |
| FW 集成测试自身的资源回收 | `test_integration_cleanup.py` | 测试资源归属、停服/禁用失败与清理保护 |

Worker 的 `.mjs` 场景由 Python 测试调用，使用内存数据库和模拟 Telegram 请求，不需要真实 Cloudflare 账号或 Bot。Shell 测试通过临时目录和模拟系统命令隔离宿主系统。

SSH 生效配置测试额外需要 `sshd`、`ssh-keygen`；DNS 超时测试需要 GNU `timeout`，原生解析阻塞场景需要 C 编译器。缺少依赖的部分会跳过；某些基础依赖检查会直接失败。交付时分别报告通过、跳过及受阻项，不将模拟测试视作实机验证。

## Linux 集成验证

以下测试会创建真实系统资源，须在具备相应能力的测试 VPS 上以 root 单独运行，不包含在普通 unittest 自动发现中。

```bash
python3 tests/integration_pm.py
python3 tests/integration_fw.py
```

PM 需要 systemd、Cron、nftables、TC 和网络命名空间；验证真实计数、分类映射、规则恢复、锁与 Cron。FW 下载并校验 Realm，使用独立目录、唯一 systemd 服务和回环地址验证 TCP/UDP 转发及交互流程。两者清理自身资源，清理失败应保留恢复线索并停止进一步破坏。

这些测试不等于公网吞吐、云安全组、真实 Telegram / D1 或完整发行验收。SSH 的真实新连接确认也不能用静态解析测试代替。完整边界见 [README 回归测试](README.md#回归测试)。

## 交付自查

- 保留已有配置和流量，明确区分当前格式、旧格式和损坏数据。
- 检查失败和可捕获中断时是否保留备份，恢复失败是否给出路径。
- 涉及安装资源时同步检查 vt 统一卸载、独立卸载和重试。
- 涉及提示时同时检查无效输入、取消、EOF 和非交互入口。
- 更新组件手册与索引；仅文档变更回读内容、检查链接和差异即可，无需运行系统集成测试。
