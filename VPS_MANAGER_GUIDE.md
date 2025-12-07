# VPS 统一管理平台使用指南

## 📖 简介

`vps.sh` 是一个统一管理脚本，整合了 Snell、sing-box 和 port-manage 三个独立脚本，提供：

- 🎯 **统一入口**：一个命令管理所有服务
- 📊 **状态总览**：实时查看所有代理和流量统计
- 🔍 **健康检查**：自动检测端口监听状态
- 🚀 **快捷命令**：支持直接跳转到各个模块
- 📦 **组件安装**：一键安装缺失的组件

---

## 🚀 快速开始

### 安装

```bash
# 方式 1: 一键安装（推荐）
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/vps.sh)

# 方式 2: 下载后安装
wget https://raw.githubusercontent.com/white-u/vps_script/main/vps.sh
chmod +x vps.sh
sudo ./vps.sh
```

### 首次使用

```bash
# 启动主菜单
vps

# 如果看到未安装的组件，选择 [6] 安装缺失组件
```

---

## 💻 命令列表

### 主菜单模式

```bash
vps              # 显示主菜单（交互式）
```

**主菜单选项：**
- `[1]` Snell 管理
- `[2]` sing-box 管理
- `[3]` 流量监控
- `[4]` 刷新状态
- `[5]` 健康检查
- `[6]` 安装缺失组件
- `[0]` 退出

### 快捷命令模式

```bash
vps status       # 显示所有服务状态总览（别名: s）
vps health       # 执行健康检查（别名: h）
vps snell        # 直接进入 Snell 管理
vps sb           # 直接进入 sing-box 管理（别名: singbox, sing-box）
vps traffic      # 直接进入流量监控（别名: ptm）
vps install      # 安装缺失的组件
vps version      # 显示版本（别名: v）
vps help         # 显示帮助
```

---

## 📊 功能详解

### 1. 状态总览 (`vps status`)

显示所有服务的实时状态：

```
════════════════════════════════════════════════════════
          VPS 代理统一管理平台 v1.0.0
════════════════════════════════════════════════════════

📡 Snell Server
  状态: ● 运行中
  端口: 30001
  流量: 2.5GB

🚀 sing-box
  状态: ● 运行中
  配置:
    443     (vless)              流量: 1.8GB
    8388    (shadowsocks)        流量: 0.9GB

📊 流量监控
  状态: 已安装
  监控端口数: 3

────────────────────────────────────────────────────────
```

**功能：**
- ✅ 实时服务状态（运行/停止/未安装）
- ✅ 端口信息
- ✅ 流量统计（需要 port-manage）
- ✅ 协议类型显示

### 2. 健康检查 (`vps health`)

检查所有服务的运行状况：

```
🔍 系统健康检查

✓ Snell 端口 30001 正常监听
✓ sing-box 端口 443 (vless) 正常监听
✓ sing-box 端口 8388 (shadowsocks) 正常监听
✓ 流量监控 nftables 规则正常

✓ 所有检查通过！
```

**检查项目：**
- Snell 服务状态 + 端口监听
- sing-box 服务状态 + 所有端口监听
- port-manage nftables 规则完整性

### 3. 组件管理

#### 查看已安装组件

```bash
vps status
# 未安装的组件会显示 "未安装"
```

#### 安装缺失组件

```bash
vps install
# 或在主菜单选择 [6]
```

**可安装的组件：**
- Snell Server
- sing-box
- 流量监控 (port-manage)

#### 直接跳转到各模块

```bash
# 进入 Snell 管理
vps snell

# 进入 sing-box 管理
vps sb

# 进入流量监控
vps traffic
```

---

## 🎯 使用场景

### 场景 1：查看所有服务状态

```bash
# 方式 1: 快速查看
vps status

# 方式 2: 进入主菜单（会自动显示状态）
vps
```

### 场景 2：检查服务健康

```bash
# 执行健康检查
vps health

# 如果发现问题，查看对应服务日志
journalctl -u snell -n 50       # Snell 日志
journalctl -u sing-box -n 50    # sing-box 日志
```

### 场景 3：管理 Snell

```bash
# 方式 1: 直接跳转
vps snell

# 方式 2: 主菜单
vps
# 选择 [1] Snell 管理
```

### 场景 4：安装新组件

```bash
# 查看当前状态
vps status

# 如果有未安装的组件
vps install
# 选择要安装的组件
```

### 场景 5：监控流量

```bash
# 查看流量总览
vps status

# 进入详细监控
vps traffic
```

---

## 🔧 高级功能

### 自动流量监控集成

当安装了 port-manage 后，`vps status` 会自动显示每个端口的流量统计：

- **自动检测**：无需手动配置
- **实时更新**：每次查看都是最新数据
- **统一展示**：所有代理的流量一目了然

### 智能服务检测

脚本会自动检测：
- ✅ 服务是否已安装
- ✅ 服务是否正在运行
- ✅ 端口是否正常监听
- ✅ nftables 规则是否完整

### 错误处理

如果某个服务未安装，会提示：

```bash
$ vps snell
[ERROR] Snell 未安装，请先安装
运行: vps 并选择 [6] 安装缺失组件
```

---

## 📋 常见问题

### Q1: 执行 `vps` 提示 "command not found"

**原因**：脚本未安装或未在 PATH 中

**解决**：
```bash
# 重新安装
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/vps.sh)

# 或手动创建软链接
sudo ln -sf /path/to/vps.sh /usr/local/bin/vps
```

### Q2: 状态总览中流量显示 "N/A"

**原因**：port-manage 未安装或未添加端口监控

**解决**：
```bash
# 1. 安装 port-manage
vps install
# 选择流量监控

# 2. 端口会自动添加到监控
# 如果是旧端口，修改一次端口即可触发自动添加
snell change-port
```

### Q3: 健康检查失败

**原因**：服务未运行或端口被占用

**解决**：
```bash
# 查看服务状态
systemctl status snell
systemctl status sing-box

# 查看端口占用
ss -tuln | grep 端口号

# 重启服务
systemctl restart snell
systemctl restart sing-box
```

### Q4: 无法进入子模块（snell, sing-box, ptm）

**原因**：对应的脚本未安装快捷命令

**解决**：
```bash
# 重新安装对应脚本
# Snell
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/Snell.sh)

# sing-box
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh)

# port-manage
bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/port-manage.sh)
```

---

## 🎨 界面预览

### 主菜单

```
════════════════════════════════════════════════════════
          VPS 代理统一管理平台 v1.0.0
════════════════════════════════════════════════════════

📡 Snell Server
  状态: ● 运行中
  端口: 30001
  流量: 2.5GB

🚀 sing-box
  状态: ● 运行中
  配置:
    443     (vless)              流量: 1.8GB
    8388    (shadowsocks)        流量: 0.9GB

📊 流量监控
  状态: 已安装
  监控端口数: 3

────────────────────────────────────────────────────────

主菜单

  [1] Snell 管理
  [2] sing-box 管理
  [3] 流量监控

  [4] 刷新状态
  [5] 健康检查
  [6] 安装缺失组件

  [0] 退出

────────────────────────────────────────────────────────

请选择 [0-6]:
```

---

## 🔗 相关链接

- **Snell.sh 文档**：独立的 Snell Server 管理脚本
- **sing-box.sh 文档**：独立的 sing-box 管理脚本
- **port-manage.sh 文档**：独立的流量监控脚本
- **VPS_TEST_GUIDE.md**：自动流量监控测试指南

---

## 📝 版本历史

### v1.0.0 (2025-12-07)

- ✅ 初始版本发布
- ✅ 整合 Snell、sing-box、port-manage
- ✅ 状态总览功能
- ✅ 健康检查功能
- ✅ 快捷命令支持
- ✅ 自动流量统计显示
- ✅ 组件安装功能

---

## 💡 提示

1. **定期检查**：建议每天运行 `vps health` 检查系统健康
2. **流量监控**：安装 port-manage 后可以查看详细流量统计
3. **快捷命令**：使用 `vps status` 比进入主菜单更快
4. **自动更新**：暂不支持，需要手动重新下载脚本

---

**享受统一管理的便利！** 🚀
