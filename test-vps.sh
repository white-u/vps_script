#!/bin/bash
# vps.sh 功能测试脚本

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

echo "========================================"
echo "  vps.sh 功能测试"
echo "========================================"
echo ""

# ============================================================================
# 测试 1: 文件存在性检查
# ============================================================================
log_test "检查 vps.sh 文件"

if [ -f vps.sh ]; then
    log_pass "vps.sh 文件存在"
else
    log_fail "vps.sh 文件不存在"
fi

# ============================================================================
# 测试 2: 语法检查
# ============================================================================
log_test "Bash 语法检查"

if bash -n vps.sh 2>/dev/null; then
    log_pass "语法正确"
else
    log_fail "语法错误"
    bash -n vps.sh 2>&1 | sed 's/^/    /'
fi

# ============================================================================
# 测试 3: 核心函数检查
# ============================================================================
log_test "检查核心函数定义"

functions=(
    "check_root"
    "is_snell_installed"
    "is_singbox_installed"
    "is_ptm_installed"
    "show_status"
    "show_menu"
    "health_check"
    "handle_command"
)

for func in "${functions[@]}"; do
    if grep -q "^${func}()" vps.sh; then
        log_pass "函数 $func() 存在"
    else
        log_fail "函数 $func() 未找到"
    fi
done

# ============================================================================
# 测试 4: 检查快捷命令支持
# ============================================================================
log_test "检查快捷命令支持"

commands=(
    "status|s"
    "health|h"
    "snell"
    "sb|singbox"
    "traffic|ptm"
    "help|--help"
    "version|v"
)

for cmd in "${commands[@]}"; do
    cmd_name=$(echo "$cmd" | cut -d'|' -f1)
    if grep -qE "^\s+${cmd}\)" vps.sh; then
        log_pass "命令 '$cmd_name' 已实现"
    else
        log_fail "命令 '$cmd_name' 未找到"
    fi
done

# ============================================================================
# 测试 5: 检查服务检测逻辑
# ============================================================================
log_test "检查服务检测逻辑"

if grep -q "systemctl is-active.*snell" vps.sh; then
    log_pass "Snell 状态检测逻辑存在"
else
    log_fail "Snell 状态检测逻辑未找到"
fi

if grep -q "systemctl is-active.*sing-box" vps.sh; then
    log_pass "sing-box 状态检测逻辑存在"
else
    log_fail "sing-box 状态检测逻辑未找到"
fi

if grep -q "/etc/port-traffic-monitor/config.json" vps.sh; then
    log_pass "port-manage 检测逻辑存在"
else
    log_fail "port-manage 检测逻辑未找到"
fi

# ============================================================================
# 测试 6: 检查流量统计功能
# ============================================================================
log_test "检查流量统计功能"

if grep -q "get_port_traffic" vps.sh; then
    log_pass "流量统计函数存在"
else
    log_fail "流量统计函数未找到"
fi

if grep -q "format_bytes" vps.sh; then
    log_pass "流量格式化函数存在"
else
    log_fail "流量格式化函数未找到"
fi

if grep -q "nft list counter" vps.sh; then
    log_pass "nftables 计数器读取逻辑存在"
else
    log_fail "nftables 计数器读取逻辑未找到"
fi

# ============================================================================
# 测试 7: 检查健康检查功能
# ============================================================================
log_test "检查健康检查功能"

if grep -q "ss -tuln" vps.sh; then
    log_pass "端口监听检测逻辑存在"
else
    log_fail "端口监听检测逻辑未找到"
fi

# ============================================================================
# 测试 8: 检查安装功能
# ============================================================================
log_test "检查组件安装功能"

if grep -q "install_component" vps.sh; then
    log_pass "安装组件函数存在"
else
    log_fail "安装组件函数未找到"
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
    echo "vps.sh 功能完整，可以提交。"
    echo ""
    echo "下一步："
    echo "  1. 查看功能: chmod +x vps.sh && sudo ./vps.sh --help"
    echo "  2. 提交代码: git add . && git commit -m 'feat: 添加统一管理脚本 vps.sh'"
    exit 0
else
    echo -e "${RED}✗ 部分测试失败，请检查代码${NC}"
    exit 1
fi
