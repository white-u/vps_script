#!/bin/bash
# ============================================================================
# VPS Manager - 主入口
# https://github.com/white-u/vps_script
# ============================================================================

set -eo pipefail

# ============================================================================
# 脚本目录检测
# ============================================================================
if [[ -d "/usr/local/lib/vps-manager/modules" ]]; then
    MODULES_DIR="/usr/local/lib/vps-manager/modules"
elif [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -d "$SCRIPT_DIR/modules" ]]; then
        MODULES_DIR="$SCRIPT_DIR/modules"
    fi
fi

if [[ -z "${MODULES_DIR:-}" || ! -d "${MODULES_DIR:-}" ]]; then
    echo "错误: 找不到模块目录" >&2
    exit 1
fi

# ============================================================================
# 加载模块
# ============================================================================
source "$MODULES_DIR/common.sh"
source "$MODULES_DIR/snell.sh"
source "$MODULES_DIR/singbox.sh"
source "$MODULES_DIR/traffic.sh"

# ============================================================================
# 初始化
# ============================================================================
check_root
common_init

# ============================================================================
# 主菜单
# ============================================================================
main_menu() {
    while true; do
        local snell_status singbox_status traffic_count
        snell_status=$(snell_get_status 2>/dev/null || echo "not_installed")
        singbox_status=$(singbox_get_status 2>/dev/null || echo "not_installed")
        traffic_count=$(traffic_get_port_count 2>/dev/null || echo "0")
        
        clear
        echo
        echo "╔══════════════════════════════════════════════════════════════════╗"
        echo "║                    VPS Manager v${VPS_VERSION}                           ║"
        echo "╠══════════════════════════════════════════════════════════════════╣"
        printf "║  服务器: %-56s ║\n" "${SERVER_IP:-未知}"
        printf "║  系统:   %-56s ║\n" "${OS_ID:-未知} (${ARCH:-未知})"
        echo "╠══════════════════════════════════════════════════════════════════╣"
        echo "║                           服务状态                               ║"
        echo "╠══════════════════════════════════════════════════════════════════╣"
        
        # Snell 状态
        case "$snell_status" in
            running)
                printf "║  Snell:     \033[32m运行中\033[0m  端口: %-36s ║\n" "$(snell_get_port 2>/dev/null || echo '?')"
                ;;
            stopped)
                printf "║  Snell:     \033[33m已停止\033[0m                                          ║\n"
                ;;
            *)
                printf "║  Snell:     \033[31m未安装\033[0m                                          ║\n"
                ;;
        esac
        
        # sing-box 状态
        case "$singbox_status" in
            running)
                local singbox_ver conf_count
                singbox_ver=$(singbox_get_version 2>/dev/null || echo "?")
                conf_count=$(singbox_get_conf_count 2>/dev/null || echo "0")
                printf "║  sing-box:  \033[32m运行中\033[0m  v%-8s 配置: %-2s 个               ║\n" "$singbox_ver" "$conf_count"
                ;;
            stopped)
                printf "║  sing-box:  \033[33m已停止\033[0m                                          ║\n"
                ;;
            *)
                printf "║  sing-box:  \033[31m未安装\033[0m                                          ║\n"
                ;;
        esac
        
        printf "║  流量监控: %-3s 个端口                                           ║\n" "$traffic_count"
        
        echo "╠══════════════════════════════════════════════════════════════════╣"
        echo "║                           功能菜单                               ║"
        echo "╠══════════════════════════════════════════════════════════════════╣"
        echo "║  1. Snell 管理                                                   ║"
        echo "║  2. sing-box 管理                                                ║"
        echo "║  3. 流量监控                                                     ║"
        echo "║  ---                                                             ║"
        echo "║  4. Telegram 通知设置                                            ║"
        echo "║  5. 网络优化 (BBR/TFO)                                           ║"
        echo "║  6. 检查更新                                                     ║"
        echo "║  ---                                                             ║"
        echo "║  0. 退出                                                         ║"
        echo "╚══════════════════════════════════════════════════════════════════╝"
        echo
        read -rp "请选择: " choice || choice=""
        
        case "$choice" in
            1) snell_menu ;;
            2) singbox_menu ;;
            3) traffic_menu ;;
            4) telegram_setup; pause ;;
            5) network_optimize_menu ;;
            6) self_update; pause ;;
            0|q|Q) echo; echo "再见!"; exit 0 ;;
            "") ;;
            *) echo -e "\033[33m无效选择\033[0m"; sleep 0.5 ;;
        esac
    done
}

# ============================================================================
# 网络优化菜单
# ============================================================================
network_optimize_menu() {
    echo
    echo -e "\033[36m=== 网络优化 ===\033[0m"
    echo
    
    local bbr_status tfo_status
    bbr_status=$(check_bbr 2>/dev/null || echo "unknown")
    tfo_status=$(check_tfo 2>/dev/null || echo "disabled")
    
    echo "当前状态:"
    if [[ "$bbr_status" == "bbr" ]]; then
        echo -e "  BBR: \033[32m已启用\033[0m"
    else
        echo -e "  BBR: \033[33m未启用\033[0m ($bbr_status)"
    fi
    if [[ "$tfo_status" == "enabled" ]]; then
        echo -e "  TFO: \033[32m已启用\033[0m"
    else
        echo -e "  TFO: \033[33m未启用\033[0m"
    fi
    echo
    echo "1. 启用 BBR"
    echo "2. 启用 TFO"
    echo "3. 一键优化 (BBR + TFO + 内核参数)"
    echo "0. 返回"
    echo
    read -rp "选择: " choice || choice=""
    
    case "$choice" in
        1) enable_bbr ;;
        2) enable_tfo ;;
        3) optimize_network ;;
    esac
    
    pause
}

# ============================================================================
# 命令行参数
# ============================================================================
case "${1:-}" in
    snell) snell_menu ;;
    sb|singbox|sing-box) singbox_menu ;;
    traffic|tr) traffic_menu ;;
    tg|telegram) telegram_setup ;;
    update) self_update ;;
    version|-v|--version) echo "VPS Manager v$VPS_VERSION" ;;
    help|-h|--help)
        echo "VPS Manager v$VPS_VERSION"
        echo
        echo "用法: vps [命令]"
        echo
        echo "命令:"
        echo "  snell       Snell 管理"
        echo "  sb          sing-box 管理"
        echo "  traffic     流量监控"
        echo "  tg          Telegram 设置"
        echo "  update      检查更新"
        echo "  version     显示版本"
        echo "  help        显示帮助"
        ;;
    "") main_menu ;;
    *)
        echo "未知命令: $1"
        echo "使用 'vps help' 查看帮助"
        exit 1
        ;;
esac
