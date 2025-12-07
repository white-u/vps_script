#!/bin/bash
# 自动流量监控功能测试脚本

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

test_count=0
pass_count=0
fail_count=0

log_test() {
    echo -e "${BLUE}[TEST $((++test_count))]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}  ✓ PASS${NC} $1"
    ((pass_count++))
}

log_fail() {
    echo -e "${RED}  ✗ FAIL${NC} $1"
    ((fail_count++))
}

log_info() {
    echo -e "${YELLOW}  ℹ INFO${NC} $1"
}

echo "========================================"
echo "  自动流量监控功能测试"
echo "========================================"
echo ""

# ============================================================================
# 测试 1: 检查函数是否存在
# ============================================================================
log_test "检查 Snell.sh 中的函数定义"

if grep -q "auto_add_traffic_monitor()" Snell.sh; then
    log_pass "auto_add_traffic_monitor() 函数存在"
else
    log_fail "auto_add_traffic_monitor() 函数未找到"
fi

if grep -q "auto_remove_traffic_monitor()" Snell.sh; then
    log_pass "auto_remove_traffic_monitor() 函数存在"
else
    log_fail "auto_remove_traffic_monitor() 函数未找到"
fi

# ============================================================================
# 测试 2: 检查 sing-box.sh 中的函数定义
# ============================================================================
log_test "检查 sing-box.sh 中的函数定义"

if grep -q "auto_add_traffic_monitor()" sing-box.sh; then
    log_pass "auto_add_traffic_monitor() 函数存在"
else
    log_fail "auto_add_traffic_monitor() 函数未找到"
fi

if grep -q "auto_remove_traffic_monitor()" sing-box.sh; then
    log_pass "auto_remove_traffic_monitor() 函数存在"
else
    log_fail "auto_remove_traffic_monitor() 函数未找到"
fi

# ============================================================================
# 测试 3: 检查调用点
# ============================================================================
log_test "检查 Snell.sh 中的函数调用点"

if grep -q 'auto_add_traffic_monitor.*"Snell Server"' Snell.sh; then
    log_pass "install_snell() 中存在调用"
else
    log_fail "install_snell() 中未找到调用"
fi

if grep -q 'auto_remove_traffic_monitor.*cur_port' Snell.sh; then
    log_pass "modify_port() 中存在移除调用"
else
    log_fail "modify_port() 中未找到移除调用"
fi

if grep -q 'auto_remove_traffic_monitor.*cur_port' Snell.sh; then
    log_pass "uninstall_snell() 中存在移除调用"
else
    log_fail "uninstall_snell() 中未找到移除调用"
fi

# ============================================================================
# 测试 4: 检查 sing-box.sh 调用点
# ============================================================================
log_test "检查 sing-box.sh 中的函数调用点"

if grep -q 'auto_add_traffic_monitor.*sing-box' sing-box.sh; then
    log_pass "add() 中存在调用"
else
    log_fail "add() 中未找到调用"
fi

if grep -q 'auto_remove_traffic_monitor.*port' sing-box.sh; then
    log_pass "del() 和 change_port() 中存在移除调用"
else
    log_fail "del() 或 change_port() 中未找到移除调用"
fi

# ============================================================================
# 测试 5: 检查关键逻辑
# ============================================================================
log_test "检查关键逻辑实现"

# 检查是否有 port-manage.sh 配置文件路径检测
if grep -q '/etc/port-traffic-monitor/config.json' Snell.sh; then
    log_pass "Snell.sh 正确引用配置文件路径"
else
    log_fail "Snell.sh 配置文件路径有误"
fi

if grep -q '/etc/port-traffic-monitor/config.json' sing-box.sh; then
    log_pass "sing-box.sh 正确引用配置文件路径"
else
    log_fail "sing-box.sh 配置文件路径有误"
fi

# 检查是否有 unlimited 配置
if grep -q '"limit": "unlimited"' Snell.sh; then
    log_pass "Snell.sh 默认配额为 unlimited"
else
    log_fail "Snell.sh 配额配置有误"
fi

if grep -q '"rate": "unlimited"' sing-box.sh; then
    log_pass "sing-box.sh 默认限速为 unlimited"
else
    log_fail "sing-box.sh 限速配置有误"
fi

# 检查是否有静默跳过逻辑
if grep -q 'return 0.*未安装.*跳过' Snell.sh; then
    log_pass "Snell.sh 有静默跳过逻辑"
else
    log_fail "Snell.sh 缺少静默跳过逻辑"
fi

# ============================================================================
# 测试 6: 检查 nftables 规则生成
# ============================================================================
log_test "检查 nftables 规则生成逻辑"

if grep -q 'nft add counter.*port_.*_in' Snell.sh; then
    log_pass "Snell.sh 包含添加入站计数器逻辑"
else
    log_fail "Snell.sh 缺少入站计数器逻辑"
fi

if grep -q 'nft add rule.*counter name' sing-box.sh; then
    log_pass "sing-box.sh 包含添加规则逻辑"
else
    log_fail "sing-box.sh 缺少规则添加逻辑"
fi

if grep -q 'nft delete counter' Snell.sh; then
    log_pass "Snell.sh 包含删除计数器逻辑"
else
    log_fail "Snell.sh 缺少删除计数器逻辑"
fi

# ============================================================================
# 测试 7: 语法检查
# ============================================================================
log_test "Bash 语法检查"

if bash -n Snell.sh 2>/dev/null; then
    log_pass "Snell.sh 语法正确"
else
    log_fail "Snell.sh 语法错误"
    bash -n Snell.sh 2>&1 | sed 's/^/    /'
fi

if bash -n sing-box.sh 2>/dev/null; then
    log_pass "sing-box.sh 语法正确"
else
    log_fail "sing-box.sh 语法错误"
    bash -n sing-box.sh 2>&1 | sed 's/^/    /'
fi

# ============================================================================
# 测试总结
# ============================================================================
echo ""
echo "========================================"
echo "  测试总结"
echo "========================================"
echo "  总计: $test_count 个测试"
echo -e "  ${GREEN}通过: $pass_count${NC}"
echo -e "  ${RED}失败: $fail_count${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}✓ 所有测试通过！${NC}"
    echo ""
    echo "下一步："
    echo "  1. 提交代码: git add . && git commit -m 'feat: 自动流量监控集成'"
    echo "  2. 推送代码: git push"
    echo "  3. 在 VPS 上测试实际功能"
    exit 0
else
    echo -e "${RED}✗ 部分测试失败，请检查代码${NC}"
    exit 1
fi
