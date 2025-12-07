#!/bin/bash
# 模块功能测试脚本

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
echo "  模块功能测试"
echo "========================================"
echo ""

# ============================================================================
# 测试 1: 检查模块文件存在
# ============================================================================
log_test "检查模块文件"

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
# 测试 2: 语法检查
# ============================================================================
log_test "Bash 语法检查"

if bash -n system-optimize.sh 2>/dev/null; then
    log_pass "system-optimize.sh 语法正确"
else
    log_fail "system-optimize.sh 语法错误"
    bash -n system-optimize.sh 2>&1 | sed 's/^/    /'
fi

if bash -n telegram-notify.sh 2>/dev/null; then
    log_pass "telegram-notify.sh 语法正确"
else
    log_fail "telegram-notify.sh 语法错误"
    bash -n telegram-notify.sh 2>&1 | sed 's/^/    /'
fi

# ============================================================================
# 测试 3: 检查 system-optimize.sh 核心函数
# ============================================================================
log_test "检查 system-optimize.sh 核心函数"

functions=(
    "check_kernel_version"
    "check_bbr_status"
    "is_bbr_available"
    "is_bbr_enabled"
    "enable_bbr"
    "disable_bbr"
    "enable_tcp_fastopen"
    "disable_tcp_fastopen"
    "enable_network_optimization"
    "remove_network_optimization"
    "configure_dns"
    "restore_dns"
)

for func in "${functions[@]}"; do
    if grep -q "^${func}()" system-optimize.sh; then
        log_pass "函数 $func() 存在"
    else
        log_fail "函数 $func() 未找到"
    fi
done

# ============================================================================
# 测试 4: 检查 telegram-notify.sh 核心函数
# ============================================================================
log_test "检查 telegram-notify.sh 核心函数"

functions=(
    "telegram_send"
    "telegram_send_html"
    "telegram_send_markdown"
    "telegram_test"
    "validate_bot_token"
    "validate_chat_id"
    "telegram_get_me"
    "telegram_send_with_retry"
    "telegram_send_alert"
    "format_alert_message"
)

for func in "${functions[@]}"; do
    if grep -q "^${func}()" telegram-notify.sh; then
        log_pass "函数 $func() 存在"
    else
        log_fail "函数 $func() 未找到"
    fi
done

# ============================================================================
# 测试 5: 测试 system-optimize.sh 可以被 source
# ============================================================================
log_test "测试 system-optimize.sh 可以被 source"

if source system-optimize.sh 2>/dev/null; then
    log_pass "system-optimize.sh 可以被 source"

    # 测试函数是否可调用
    if type check_bbr_status &>/dev/null; then
        log_pass "check_bbr_status 函数可调用"
    else
        log_fail "check_bbr_status 函数不可调用"
    fi
else
    log_fail "system-optimize.sh 无法被 source"
fi

# ============================================================================
# 测试 6: 测试 telegram-notify.sh 可以被 source
# ============================================================================
log_test "测试 telegram-notify.sh 可以被 source"

if source telegram-notify.sh 2>/dev/null; then
    log_pass "telegram-notify.sh 可以被 source"

    # 测试函数是否可调用
    if type telegram_send &>/dev/null; then
        log_pass "telegram_send 函数可调用"
    else
        log_fail "telegram_send 函数不可调用"
    fi
else
    log_fail "telegram-notify.sh 无法被 source"
fi

# ============================================================================
# 测试 7: 测试 validate 函数
# ============================================================================
log_test "测试 Telegram 验证函数"

# 测试有效的 Bot Token
if validate_bot_token "123456789:ABCdefGHIjklMNOpqrsTUVwxyz" &>/dev/null; then
    log_pass "有效 Bot Token 验证通过"
else
    log_fail "有效 Bot Token 验证失败"
fi

# 测试无效的 Bot Token
if ! validate_bot_token "invalid_token" &>/dev/null; then
    log_pass "无效 Bot Token 被正确拒绝"
else
    log_fail "无效 Bot Token 未被拒绝"
fi

# 测试有效的 Chat ID (正数)
if validate_chat_id "123456789" &>/dev/null; then
    log_pass "有效 Chat ID (正数) 验证通过"
else
    log_fail "有效 Chat ID (正数) 验证失败"
fi

# 测试有效的 Chat ID (负数-群组)
if validate_chat_id "-100123456789" &>/dev/null; then
    log_pass "有效 Chat ID (负数) 验证通过"
else
    log_fail "有效 Chat ID (负数) 验证失败"
fi

# 测试有效的 Chat ID (@频道)
if validate_chat_id "@mychannel" &>/dev/null; then
    log_pass "有效 Chat ID (@频道) 验证通过"
else
    log_fail "有效 Chat ID (@频道) 验证失败"
fi

# ============================================================================
# 测试 8: 测试内核版本检查函数
# ============================================================================
log_test "测试内核版本检查函数"

# 获取当前内核版本
kernel_version=$(uname -r)
kernel_major=$(echo "$kernel_version" | cut -d. -f1)
kernel_minor=$(echo "$kernel_version" | cut -d. -f2)

log_info "当前内核版本: $kernel_version ($kernel_major.$kernel_minor)"

# 测试应该通过的版本检查
if check_kernel_version 3 0 &>/dev/null; then
    log_pass "内核版本检查 (>= 3.0) 通过"
else
    log_fail "内核版本检查 (>= 3.0) 失败"
fi

# ============================================================================
# 测试 9: 检查帮助信息
# ============================================================================
log_test "检查帮助信息"

if ./system-optimize.sh help 2>&1 | grep -q "系统网络优化模块"; then
    log_pass "system-optimize.sh 帮助信息完整"
else
    log_fail "system-optimize.sh 帮助信息缺失"
fi

if ./telegram-notify.sh help 2>&1 | grep -q "Telegram 通知统一模块"; then
    log_pass "telegram-notify.sh 帮助信息完整"
else
    log_fail "telegram-notify.sh 帮助信息缺失"
fi

# ============================================================================
# 测试 10: 检查可执行权限
# ============================================================================
log_test "检查可执行权限"

if [ -x system-optimize.sh ]; then
    log_pass "system-optimize.sh 有执行权限"
else
    log_fail "system-optimize.sh 缺少执行权限"
fi

if [ -x telegram-notify.sh ]; then
    log_pass "telegram-notify.sh 有执行权限"
else
    log_fail "telegram-notify.sh 缺少执行权限"
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
    echo "两个模块功能完整，可以提交。"
    echo ""
    echo "下一步："
    echo "  1. 更新 Snell.sh 使用 system-optimize.sh"
    echo "  2. 更新 sing-box.sh 使用 system-optimize.sh"
    echo "  3. 提交代码"
    exit 0
else
    echo -e "${RED}✗ 部分测试失败，请检查代码${NC}"
    exit 1
fi
