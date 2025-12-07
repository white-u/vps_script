#!/bin/bash
# 重构验证测试脚本

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

echo "=========================================="
echo "  重构验证测试"
echo "=========================================="
echo ""

# ============================================================================
# 测试 1: 语法检查
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
# 测试 2: 检查模块加载函数存在
# ============================================================================
log_test "检查模块加载函数"

if grep -q "^load_system_optimize_module()" Snell.sh; then
    log_pass "Snell.sh 有模块加载函数"
else
    log_fail "Snell.sh 缺少模块加载函数"
fi

if grep -q "^load_system_optimize_module()" sing-box.sh; then
    log_pass "sing-box.sh 有模块加载函数"
else
    log_fail "sing-box.sh 缺少模块加载函数"
fi

# ============================================================================
# 测试 3: 检查模块调用
# ============================================================================
log_test "检查 Snell.sh 中的模块调用"

if grep -q "load_system_optimize_module" Snell.sh | grep -q "enable_network_optimization"; then
    log_pass "Snell.sh 调用了 enable_network_optimization"
else
    log_info "Snell.sh 可能使用内置实现作为后备"
fi

if grep -q "load_system_optimize_module" Snell.sh | grep -q "remove_network_optimization"; then
    log_pass "Snell.sh 调用了 remove_network_optimization"
else
    log_info "Snell.sh 可能使用内置实现作为后备"
fi

log_test "检查 sing-box.sh 中的模块调用"

if grep -q "check_bbr_status" sing-box.sh; then
    log_pass "sing-box.sh 调用了 check_bbr_status"
else
    log_info "sing-box.sh 使用内置实现"
fi

if grep -q "enable_network_optimization" sing-box.sh; then
    log_pass "sing-box.sh 调用了 enable_network_optimization"
else
    log_info "sing-box.sh 可能使用内置实现作为后备"
fi

# ============================================================================
# 测试 4: 检查向后兼容性
# ============================================================================
log_test "检查向后兼容性（内置实现保留）"

# Snell.sh 应该保留内置实现作为后备
if grep -A 50 "enable_tcp_fastopen()" Snell.sh | grep -q "模块加载失败，使用内置实现"; then
    log_pass "Snell.sh 保留了内置实现作为后备"
else
    log_fail "Snell.sh 可能没有后备实现"
fi

# sing-box.sh 应该保留内置实现作为后备
if grep -A 50 "enable_bbr()" sing-box.sh | grep -q "模块加载失败，使用内置实现"; then
    log_pass "sing-box.sh 保留了内置实现作为后备"
else
    log_fail "sing-box.sh 可能没有后备实现"
fi

# ============================================================================
# 测试 5: 检查模块文件存在
# ============================================================================
log_test "检查依赖的模块文件"

if [ -f system-optimize.sh ]; then
    log_pass "system-optimize.sh 存在"
else
    log_fail "system-optimize.sh 不存在"
fi

if [ -f telegram-notify.sh ]; then
    log_pass "telegram-notify.sh 存在"
else
    log_fail "telegram-notify.sh 不存在"
fi

# ============================================================================
# 测试 6: 模拟模块加载测试
# ============================================================================
log_test "模拟模块加载功能"

# 测试 system-optimize.sh 可以被 source
if source system-optimize.sh 2>/dev/null; then
    log_pass "system-optimize.sh 可以被 source"

    # 测试关键函数是否可用
    if type enable_network_optimization >/dev/null 2>&1; then
        log_pass "enable_network_optimization 函数可用"
    else
        log_fail "enable_network_optimization 函数不可用"
    fi

    if type check_bbr_status >/dev/null 2>&1; then
        log_pass "check_bbr_status 函数可用"
    else
        log_fail "check_bbr_status 函数不可用"
    fi
else
    log_fail "system-optimize.sh 无法被 source"
fi

# ============================================================================
# 测试 7: 代码重复检查
# ============================================================================
log_test "检查代码重复情况"

# 虽然保留了内置实现，但应该优先使用模块
snell_module_calls=$(grep -c "load_system_optimize_module" Snell.sh)
singbox_module_calls=$(grep -c "load_system_optimize_module" sing-box.sh)

if [ "$snell_module_calls" -ge 2 ]; then
    log_pass "Snell.sh 有 $snell_module_calls 处模块调用"
else
    log_fail "Snell.sh 模块调用次数不足: $snell_module_calls"
fi

if [ "$singbox_module_calls" -ge 3 ]; then
    log_pass "sing-box.sh 有 $singbox_module_calls 处模块调用"
else
    log_fail "sing-box.sh 模块调用次数不足: $singbox_module_calls"
fi

# ============================================================================
# 测试 8: 检查自动下载机制
# ============================================================================
log_test "检查模块自动下载机制"

if grep -q "curl.*system-optimize.sh" Snell.sh; then
    log_pass "Snell.sh 有模块自动下载功能"
else
    log_fail "Snell.sh 缺少模块自动下载功能"
fi

if grep -q "curl.*system-optimize.sh" sing-box.sh; then
    log_pass "sing-box.sh 有模块自动下载功能"
else
    log_fail "sing-box.sh 缺少模块自动下载功能"
fi

# ============================================================================
# 测试 9: 检查模块 URL 配置
# ============================================================================
log_test "检查模块仓库 URL 配置"

if grep -q "REPO_URL.*raw.githubusercontent.com" Snell.sh; then
    log_pass "Snell.sh 配置了正确的仓库 URL"
else
    log_fail "Snell.sh 仓库 URL 配置有误"
fi

if grep -q "REPO_URL.*raw.githubusercontent.com" sing-box.sh; then
    log_pass "sing-box.sh 配置了正确的仓库 URL"
else
    log_fail "sing-box.sh 仓库 URL 配置有误"
fi

# ============================================================================
# 测试总结
# ============================================================================
echo ""
echo "=========================================="
echo "  测试总结"
echo "=========================================="
echo "  总计: $test_count 个测试"
echo -e "  ${GREEN}通过: $pass_count${NC}"
echo -e "  ${RED}失败: $fail_count${NC}"
echo ""

# 统计代码变化
echo "=========================================="
echo "  代码统计"
echo "=========================================="
echo "Snell.sh:"
snell_lines=$(wc -l < Snell.sh)
snell_module_func=$(grep -c "load_system_optimize_module" Snell.sh || echo 0)
echo "  总行数: $snell_lines"
echo "  模块调用处: $snell_module_func"
echo ""
echo "sing-box.sh:"
singbox_lines=$(wc -l < sing-box.sh)
singbox_module_func=$(grep -c "load_system_optimize_module" sing-box.sh || echo 0)
echo "  总行数: $singbox_lines"
echo "  模块调用处: $singbox_module_func"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}✓ 所有测试通过！重构成功。${NC}"
    echo ""
    echo "重构成果："
    echo "  ✓ 添加了模块自动加载机制"
    echo "  ✓ 优先使用 system-optimize.sh 模块"
    echo "  ✓ 保留内置实现作为后备（向后兼容）"
    echo "  ✓ 支持模块自动下载"
    echo "  ✓ 语法检查全部通过"
    echo ""
    echo "下一步："
    echo "  1. git add Snell.sh sing-box.sh"
    echo "  2. git commit -m 'refactor: 重构脚本使用 system-optimize.sh 模块'"
    echo "  3. git push"
    exit 0
else
    echo -e "${RED}✗ 部分测试失败，请检查重构代码${NC}"
    exit 1
fi
