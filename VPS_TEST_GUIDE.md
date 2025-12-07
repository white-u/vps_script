# VPS 实际测试指南

## 🎯 测试目标

验证 Snell.sh 和 sing-box.sh 的自动流量监控功能是否正常工作。

---

## 📋 测试准备

### 1. 推送代码到 GitHub

```bash
cd /Users/hy/Documents/GitHub/vps_script

# 查看修改内容
git status

# 提交代码
git add .
git commit -m "feat: 自动流量监控集成

- Snell.sh 和 sing-box.sh 在创建/修改/删除配置时自动同步 port-manage
- 默认只统计流量，不设置限制（quota=unlimited, rate=unlimited）
- 静默失败：未安装 port-manage.sh 时自动跳过
- 支持场景：安装、端口修改、卸载
"

# 推送到远程仓库
git push
```

### 2. 准备测试 VPS

- 系统：Ubuntu 20.04+ / Debian 11+ / CentOS 7+
- 权限：root 或 sudo
- 网络：可访问 GitHub

---

## 🧪 测试场景

### 场景 1：先装代理，后装监控（最常见）

**目的**：验证已有代理可以通过端口修改自动添加监控

```bash
# 步骤 1: 安装 Snell
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/Snell.sh)
# 输入端口：30001 (或直接回车使用随机端口)

# 验证 Snell 运行
snell status
# 预期输出：✓ Snell 运行中

# 步骤 2: 安装 port-manage.sh
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/port-manage.sh)

# 步骤 3: 修改 Snell 端口（触发自动添加监控）
snell change-port
# 输入新端口：30002

# 预期输出：
# ✓ 端口修改成功：30001 -> 30002
# 自动移除端口 30001 的流量监控...
# ✓ 已移除端口 30001 的流量监控
# 自动添加端口 30002 到流量监控...
# ✓ 已自动添加端口 30002 到流量监控（仅统计，无限制）
#   使用 'ptm' 命令查看流量统计

# 步骤 4: 验证监控已添加
ptm
# 预期看到：端口 30002 已在列表中，配额和限速都是 unlimited
```

**✅ 通过条件**：
- [x] Snell 端口修改成功
- [x] 自动添加流量监控
- [x] `ptm` 中可以看到端口 30002
- [x] quota 显示为 unlimited
- [x] rate 显示为 unlimited

---

### 场景 2：先装监控，后装代理（推荐流程）

**目的**：验证新安装的代理自动添加监控

```bash
# 步骤 1: 安装 port-manage.sh
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/port-manage.sh)

# 步骤 2: 安装 sing-box（创建 VLESS-Reality 配置）
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh)
# 选择：安装 sing-box
# 添加配置 -> 选择 VLESS-Reality
# 端口：443
# UUID：回车使用默认
# SNI：回车使用默认 (www.time.is)

# 预期输出（在配置保存成功后）：
# 自动添加端口 443 到流量监控...
# ✓ 已自动添加端口 443 到流量监控（仅统计，无限制）
#   使用 'ptm' 命令查看流量统计

# 步骤 3: 验证监控已添加
ptm
# 预期看到：端口 443 已在列表中，备注为 "sing-box (VLESS-Reality)"

# 步骤 4: 添加第二个配置（Shadowsocks）
sing-box add ss
# 端口：8388
# 密码：回车使用默认

# 预期输出：
# ✓ 已自动添加端口 8388 到流量监控（仅统计，无限制）

# 步骤 5: 验证两个端口都被监控
ptm
# 预期看到：
# - 端口 443  (sing-box (VLESS-Reality))
# - 端口 8388 (sing-box (Shadowsocks))
```

**✅ 通过条件**：
- [x] VLESS-Reality 配置创建成功
- [x] 端口 443 自动添加到监控
- [x] Shadowsocks 配置创建成功
- [x] 端口 8388 自动添加到监控
- [x] 两个端口都可以在 `ptm` 中看到

---

### 场景 3：删除代理自动移除监控

**目的**：验证删除配置时自动清理监控

```bash
# 前提：已有场景 2 的两个配置（端口 443 和 8388）

# 步骤 1: 删除 Shadowsocks 配置
sing-box del
# 选择 Shadowsocks 配置
# 确认删除：y

# 预期输出：
# 已删除: shadowsocks-xxx.json
# 自动移除端口 8388 的流量监控...
# ✓ 已移除端口 8388 的流量监控

# 步骤 2: 验证监控已移除
ptm
# 预期看到：只剩下端口 443，端口 8388 已不在列表中
```

**✅ 通过条件**：
- [x] sing-box 配置删除成功
- [x] 端口 8388 自动从监控中移除
- [x] 端口 443 仍在监控中（未被误删）

---

### 场景 4：端口修改自动同步监控

**目的**：验证修改端口时自动更新监控

```bash
# 前提：已有端口 443 的 VLESS 配置

# 步骤 1: 修改 sing-box 端口
sing-box change
# 选择 VLESS 配置
# 选择：修改端口
# 新端口：8443

# 预期输出：
# 端口已修改: 443 -> 8443
# 自动移除端口 443 的流量监控...
# ✓ 已移除端口 443 的流量监控
# 自动添加端口 8443 到流量监控...
# ✓ 已自动添加端口 8443 到流量监控（仅统计，无限制）

# 步骤 2: 验证监控已更新
ptm
# 预期看到：端口 8443（443 已不存在）
```

**✅ 通过条件**：
- [x] 端口修改成功
- [x] 旧端口 443 从监控中移除
- [x] 新端口 8443 添加到监控
- [x] 配置和监控数据一致

---

### 场景 5：卸载代理自动移除监控

**目的**：验证卸载时自动清理监控

```bash
# 步骤 1: 卸载 Snell
snell uninstall
# 确认：y

# 预期输出（在卸载过程中）：
# 自动移除端口 30002 的流量监控...
# ✓ 已移除端口 30002 的流量监控
# 卸载完成

# 步骤 2: 验证监控已移除
ptm
# 预期看到：端口 30002 已不在列表中
```

**✅ 通过条件**：
- [x] Snell 卸载成功
- [x] 端口 30002 自动从监控中移除

---

### 场景 6：未安装 port-manage.sh 时静默跳过

**目的**：验证未安装监控时不影响代理正常使用

```bash
# 前提：未安装 port-manage.sh

# 步骤 1: 确保未安装 port-manage.sh
ls /etc/port-traffic-monitor/
# 预期输出：No such file or directory

# 步骤 2: 安装 Snell
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/Snell.sh)
# 输入端口：40001

# 预期输出：
# 安装完成！（没有流量监控相关的输出，静默跳过）

# 步骤 3: 验证 Snell 正常运行
snell status
# 预期输出：✓ Snell 运行中

# 步骤 4: 后续安装 port-manage.sh
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/port-manage.sh)

# 步骤 5: 通过端口修改触发添加监控
snell change-port
# 输入新端口：40002
# 预期输出：✓ 已自动添加端口 40002 到流量监控
```

**✅ 通过条件**：
- [x] 未安装监控时，Snell 安装成功
- [x] 没有错误提示
- [x] 后续安装监控后可以正常联动

---

## 🔍 验证检查点

### 1. 配置文件验证

```bash
# 查看 port-manage 配置文件
cat /etc/port-traffic-monitor/config.json | jq .

# 预期结构：
# {
#   "ports": {
#     "30002": {
#       "billing": "single",
#       "quota": {"limit": "unlimited", "reset_day": null},
#       "bandwidth": {"rate": "unlimited"},
#       "remark": "Snell Server",
#       "created": "2025-12-07T..."
#     },
#     "8443": {
#       "billing": "single",
#       "quota": {"limit": "unlimited", "reset_day": null},
#       "bandwidth": {"rate": "unlimited"},
#       "remark": "sing-box (VLESS-Reality)",
#       "created": "2025-12-07T..."
#     }
#   }
# }
```

### 2. nftables 规则验证

```bash
# 查看 nftables 表
nft list table inet port_monitor

# 预期看到：
# - counter port_30002_in
# - counter port_30002_out
# - counter port_8443_in
# - counter port_8443_out
# - 对应的规则：tcp dport 30002 counter name "port_30002_in"
```

### 3. 流量统计验证

```bash
# 生成一些流量（使用代理发送请求）

# 查看流量统计
ptm

# 或直接查看 nftables 计数器
nft list counter inet port_monitor port_30002_out
# 预期看到：bytes > 0 (有流量统计)
```

---

## 🐛 故障排查

### 问题 1：自动添加监控没有输出

**可能原因：**
- port-manage.sh 未安装（预期行为，静默跳过）
- jq 命令未安装

**解决：**
```bash
# 检查 port-manage.sh
ls /etc/port-traffic-monitor/

# 检查 jq
which jq
# 如果没有，安装：
apt install jq -y   # Debian/Ubuntu
yum install jq -y   # CentOS
```

### 问题 2：提示 "缺少 jq 命令"

**解决：**
```bash
apt install jq -y   # Debian/Ubuntu
yum install jq -y   # CentOS
```

### 问题 3：配置文件写入失败

**检查：**
```bash
# 检查配置文件权限
ls -la /etc/port-traffic-monitor/

# 检查 JSON 格式
cat /etc/port-traffic-monitor/config.json | jq .
```

### 问题 4：nftables 规则未添加

**检查：**
```bash
# 检查 nftables 是否运行
systemctl status nftables

# 检查表是否存在
nft list tables
# 应该看到：table inet port_monitor
```

---

## 📊 测试报告模板

完成测试后，请填写此报告：

```
# 自动流量监控功能测试报告

测试日期：____________________
测试系统：____________________ (Ubuntu 22.04 / Debian 11 / CentOS 7 等)
测试人员：____________________

## 测试结果

场景 1：先装代理，后装监控
- [ ] 通过  [ ] 失败  备注：__________

场景 2：先装监控，后装代理
- [ ] 通过  [ ] 失败  备注：__________

场景 3：删除代理自动移除监控
- [ ] 通过  [ ] 失败  备注：__________

场景 4：端口修改自动同步监控
- [ ] 通过  [ ] 失败  备注：__________

场景 5：卸载代理自动移除监控
- [ ] 通过  [ ] 失败  备注：__________

场景 6：未安装 port-manage.sh 时静默跳过
- [ ] 通过  [ ] 失败  备注：__________

## 发现的问题

1. __________________________________
2. __________________________________
3. __________________________________

## 建议改进

1. __________________________________
2. __________________________________
3. __________________________________

## 总体评价

- [ ] 功能完全正常，可以发布
- [ ] 有小问题，需要修复
- [ ] 有严重问题，需要重大修改
```

---

## ✅ 测试完成标准

所有场景测试通过后，即可认为功能验证完成：

- [x] 代码测试通过（本地）
- [ ] 场景 1 测试通过（VPS）
- [ ] 场景 2 测试通过（VPS）
- [ ] 场景 3 测试通过（VPS）
- [ ] 场景 4 测试通过（VPS）
- [ ] 场景 5 测试通过（VPS）
- [ ] 场景 6 测试通过（VPS）

**祝测试顺利！** 🚀
