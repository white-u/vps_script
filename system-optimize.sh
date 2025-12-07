#!/usr/bin/env bash
#
# 系统网络优化统一模块
# 提供 BBR、TCP Fast Open、DNS 等网络优化功能
# 供 Snell.sh、sing-box.sh 等脚本调用
#
# 使用方式:
#   source system-optimize.sh
#   enable_bbr_optimization
#   check_bbr_status
#

set -e

# =====================================
# 颜色定义
# =====================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# =====================================
# 日志函数
# =====================================
_log()    { echo -e "${GREEN}[INFO]${NC} $*"; }
_warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
_error()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
_green()  { echo -e "${GREEN}$*${NC}"; }
_yellow() { echo -e "${YELLOW}$*${NC}"; }
_red()    { echo -e "${RED}$*${NC}"; }

# =====================================
# 内核版本检查
# =====================================
check_kernel_version() {
    local required_major=$1
    local required_minor=${2:-0}

    local kernel_major=$(uname -r | cut -d. -f1)
    local kernel_minor=$(uname -r | cut -d. -f2)

    if [[ $kernel_major -gt $required_major ]] || \
       [[ $kernel_major -eq $required_major && $kernel_minor -ge $required_minor ]]; then
        return 0
    else
        return 1
    fi
}

# =====================================
# BBR 状态检查
# =====================================
check_bbr_status() {
    local current=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    local available=$(sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | awk -F'=' '{print $2}' | xargs)

    echo ""
    echo "BBR 状态:"
    echo "  当前算法: ${current:-未知}"
    echo "  可用算法: ${available:-未知}"

    if [[ "$current" == "bbr" ]]; then
        echo ""
        _green "✓ BBR 已启用"
        return 0
    else
        echo ""
        _yellow "○ BBR 未启用"
        return 1
    fi
}

# =====================================
# 检查 BBR 是否可用
# =====================================
is_bbr_available() {
    # 检查内核版本 (需要 4.9+)
    if ! check_kernel_version 4 9; then
        return 1
    fi

    # 检查是否在可用列表中
    if grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# =====================================
# 检查 BBR 是否已启用
# =====================================
is_bbr_enabled() {
    local current=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    [[ "$current" == "bbr" ]]
}

# =====================================
# 启用 BBR
# =====================================
enable_bbr() {
    local sysctl_conf="${1:-/etc/sysctl.conf}"

    # 检查内核版本
    if ! check_kernel_version 4 9; then
        _error "BBR 需要 Linux 4.9+ 内核，当前: $(uname -r)"
        return 1
    fi

    # 检查 BBR 是否可用
    if ! is_bbr_available; then
        _error "内核不支持 BBR"
        return 1
    fi

    # 检查是否已启用
    if is_bbr_enabled; then
        _green "BBR 已经启用"
        return 0
    fi

    # 删除旧配置
    sed -i '/net.core.default_qdisc/d' "$sysctl_conf" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_congestion_control/d' "$sysctl_conf" 2>/dev/null || true

    # 添加新配置
    cat >> "$sysctl_conf" <<'EOF'

# BBR 拥塞控制
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    # 应用配置
    sysctl -p "$sysctl_conf" &>/dev/null || sysctl --system &>/dev/null

    # 验证
    if is_bbr_enabled; then
        _green "✓ BBR 启用成功"
        return 0
    else
        _error "BBR 启用失败"
        return 1
    fi
}

# =====================================
# 禁用 BBR
# =====================================
disable_bbr() {
    local sysctl_conf="${1:-/etc/sysctl.conf}"

    if [ ! -f "$sysctl_conf" ]; then
        _warn "配置文件不存在: $sysctl_conf"
        return 0
    fi

    # 删除 BBR 配置
    sed -i '/net.core.default_qdisc/d' "$sysctl_conf" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_congestion_control/d' "$sysctl_conf" 2>/dev/null || true

    # 删除注释行（如果紧挨着）
    sed -i '/^# BBR/d' "$sysctl_conf" 2>/dev/null || true

    # 应用配置
    sysctl --system &>/dev/null || true

    _log "BBR 配置已移除"
}

# =====================================
# 启用 TCP Fast Open
# =====================================
enable_tcp_fastopen() {
    local sysctl_conf="${1:-/etc/sysctl.conf}"

    # 检查内核版本 (需要 3.7+)
    if ! check_kernel_version 3 7; then
        _warn "TCP Fast Open 需要 Linux 3.7+ 内核，当前: $(uname -r)"
        return 1
    fi

    # 立即启用
    echo 3 > /proc/sys/net/ipv4/tcp_fastopen 2>/dev/null || {
        _error "无法启用 TCP Fast Open"
        return 1
    }

    # 删除旧配置
    sed -i '/net.ipv4.tcp_fastopen/d' "$sysctl_conf" 2>/dev/null || true

    # 添加到配置文件
    cat >> "$sysctl_conf" <<'EOF'

# TCP Fast Open
net.ipv4.tcp_fastopen=3
EOF

    _green "✓ TCP Fast Open 已启用"
    return 0
}

# =====================================
# 禁用 TCP Fast Open
# =====================================
disable_tcp_fastopen() {
    local sysctl_conf="${1:-/etc/sysctl.conf}"

    if [ ! -f "$sysctl_conf" ]; then
        return 0
    fi

    # 删除 TFO 配置
    sed -i '/net.ipv4.tcp_fastopen/d' "$sysctl_conf" 2>/dev/null || true
    sed -i '/^# TCP Fast Open/d' "$sysctl_conf" 2>/dev/null || true

    # 禁用
    echo 0 > /proc/sys/net/ipv4/tcp_fastopen 2>/dev/null || true

    _log "TCP Fast Open 已禁用"
}

# =====================================
# 启用完整的网络优化（BBR + TFO）
# =====================================
enable_network_optimization() {
    local sysctl_conf="${1:-/etc/sysctl.d/99-network-optimize.conf}"
    local enable_bbr="${2:-true}"
    local enable_tfo="${3:-true}"

    _log "正在配置网络优化..."

    local success=0

    # 启用 TCP Fast Open
    if [[ "$enable_tfo" == "true" ]]; then
        if enable_tcp_fastopen "$sysctl_conf"; then
            ((success++))
        fi
    fi

    # 启用 BBR
    if [[ "$enable_bbr" == "true" ]]; then
        if is_bbr_available; then
            if enable_bbr "$sysctl_conf"; then
                ((success++))
            fi
        else
            _warn "BBR 不可用 (内核版本需要 >= 4.9)"
        fi
    fi

    # 应用所有配置
    sysctl -p "$sysctl_conf" &>/dev/null || sysctl --system &>/dev/null

    if [ $success -gt 0 ]; then
        _green "✓ 网络优化配置完成"
        return 0
    else
        _warn "网络优化配置未完全成功"
        return 1
    fi
}

# =====================================
# 移除网络优化配置
# =====================================
remove_network_optimization() {
    local sysctl_conf="${1:-/etc/sysctl.d/99-network-optimize.conf}"

    if [ -f "$sysctl_conf" ]; then
        rm -f "$sysctl_conf"
        _log "已删除网络优化配置文件: $sysctl_conf"
    fi

    # 从主配置文件中删除（兼容旧版本）
    if [ -f /etc/sysctl.conf ]; then
        disable_bbr /etc/sysctl.conf
        disable_tcp_fastopen /etc/sysctl.conf
    fi

    sysctl --system &>/dev/null || true
    _green "✓ 网络优化配置已移除"
}

# =====================================
# DNS 配置
# =====================================
configure_dns() {
    local dns1="${1:-1.1.1.1}"
    local dns2="${2:-8.8.8.8}"

    # 备份原有 DNS 配置
    if [ -f /etc/resolv.conf ]; then
        cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%s)
    fi

    # 写入新 DNS
    cat > /etc/resolv.conf <<EOF
nameserver $dns1
nameserver $dns2
EOF

    _green "✓ DNS 已配置: $dns1, $dns2"
}

# =====================================
# 恢复 DNS 配置
# =====================================
restore_dns() {
    local backup=$(ls -t /etc/resolv.conf.backup.* 2>/dev/null | head -1)

    if [ -n "$backup" ]; then
        mv "$backup" /etc/resolv.conf
        _log "DNS 配置已恢复"
    else
        _warn "未找到 DNS 备份文件"
    fi
}

# =====================================
# 显示帮助信息
# =====================================
show_optimize_help() {
    cat << EOF
系统网络优化模块

使用方式:
  source system-optimize.sh

函数列表:
  check_bbr_status              - 检查 BBR 状态
  is_bbr_available              - 检查 BBR 是否可用
  is_bbr_enabled                - 检查 BBR 是否已启用
  enable_bbr [conf]             - 启用 BBR
  disable_bbr [conf]            - 禁用 BBR
  enable_tcp_fastopen [conf]    - 启用 TCP Fast Open
  disable_tcp_fastopen [conf]   - 禁用 TCP Fast Open
  enable_network_optimization   - 启用完整网络优化
  remove_network_optimization   - 移除网络优化
  configure_dns [dns1] [dns2]   - 配置 DNS
  restore_dns                   - 恢复 DNS

示例:
  # 启用 BBR
  enable_bbr /etc/sysctl.d/99-bbr.conf

  # 启用完整优化
  enable_network_optimization /etc/sysctl.d/99-network.conf

  # 检查状态
  check_bbr_status
EOF
}

# =====================================
# 主函数（命令行模式）
# =====================================
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    # 直接执行脚本时的行为
    case "${1:-help}" in
        check|status)
            check_bbr_status
            ;;
        enable)
            enable_network_optimization "${2:-/etc/sysctl.d/99-network-optimize.conf}"
            ;;
        disable|remove)
            remove_network_optimization "${2:-/etc/sysctl.d/99-network-optimize.conf}"
            ;;
        help|--help|-h)
            show_optimize_help
            ;;
        *)
            echo "用法: $0 {check|enable|disable|help}"
            exit 1
            ;;
    esac
fi
