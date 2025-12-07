#!/bin/bash
# ============================================================================
# VPS Manager - 主入口
# ============================================================================

set -euo pipefail

# 脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 如果是安装后的运行，模块在 /usr/local/lib/vps-manager
if [[ -d "/usr/local/lib/vps-manager/modules" ]]; then
    MODULES_DIR="/usr/local/lib/vps-manager/modules"
elif [[ -d "$SCRIPT_DIR/modules" ]]; then
    MODULES_DIR="$SCRIPT_DIR/modules"
else
    echo "错误: 找不到模块目录"
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
        local snell_status=$(snell_get_status)
        local singbox_status=$(singbox_get_status)
        
        clear
        echo
        echo "╔══════════════════════════════════════════════════════════════════╗"
        echo "║                                                                  ║"
        echo "║                    VPS Manager v$VPS_VERSION                         ║"
        echo "║                                                                  ║"
        echo "╠══════════════════════════════════════════════════════════════════╣"
        echo "║                                                                  ║"
        printf "║    服务器: %-52s  ║\n" "$SERVER_IP"
        printf "║    系统:   %-52s  ║\n" "${OS_NAME:-$OS_ID}"
        echo "║                                                                  ║"
        echo "╠══════════════════════════════════════════════════════════════════╣"
        echo "║                          服务状态                                ║"
        echo "╠══════════════════════════════════════════════════════════════════╣"
        
        # Snell 状态
        case $snell_status in
            running)
                local snell_port=$(snell_get_port)
                printf "║    Snell:     $(_green "运行中")  端口: %-32s  ║\n" "$snell_port"
                ;;
            stopped)
                printf "║    Snell:     $(_yellow "已停止")                                        ║\n"
                ;;
            *)
                printf "║    Snell:     $(_red "未安装")                                        ║\n"
                ;;
        esac
        
        # sing-box 状态
        case $singbox_status in
            running)
                local singbox_ver=$(singbox_get_version)
                local conf_count=$(ls "$SINGBOX_CONF_DIR"/*.json 2>/dev/null | wc -l)
                printf "║    sing-box:  $(_green "运行中")  版本: %-10s 配置: %-2s 个       ║\n" "$singbox_ver" "$conf_count"
                ;;
            stopped)
                printf "║    sing-box:  $(_yellow "已停止")                                        ║\n"
                ;;
            *)
                printf "║    sing-box:  $(_red "未安装")                                        ║\n"
                ;;
        esac
        
        # 流量监控状态
        local traffic_count=$(traffic_get_ports | wc -l)
        printf "║    流量监控: %-3d 个端口                                         ║\n" "$traffic_count"
        
        echo "║                                                                  ║"
        echo "╠══════════════════════════════════════════════════════════════════╣"
        echo "║                          功能菜单                                ║"
        echo "╠══════════════════════════════════════════════════════════════════╣"
        echo "║                                                                  ║"
        echo "║    1. Snell 管理                                                 ║"
        echo "║    2. sing-box 管理                                              ║"
        echo "║    3. 流量监控                                                   ║"
        echo "║    ---                                                           ║"
        echo "║    4. Telegram 通知设置                                          ║"
        echo "║    5. 网络优化 (BBR/TFO)                                         ║"
        echo "║    6. 检查更新                                                   ║"
        echo "║    ---                                                           ║"
        echo "║    0. 退出                                                       ║"
        echo "║                                                                  ║"
        echo "╚══════════════════════════════════════════════════════════════════╝"
        echo
        read -rp "请选择: " choice
        
        case $choice in
            1) snell_menu ;;
            2) singbox_menu ;;
            3) traffic_menu ;;
            4) telegram_setup; pause ;;
            5) network_optimize_menu ;;
            6) self_update; pause ;;
            0) exit 0 ;;
        esac
    done
}

# ============================================================================
# 网络优化菜单
# ============================================================================
network_optimize_menu() {
    echo
    _cyan "=== 网络优化 ==="
    echo
    
    local bbr_status=$(check_bbr)
    local tfo_status=$(check_tfo)
    
    echo "当前状态:"
    echo "  BBR: $([ "$bbr_status" = "bbr" ] && _green "已启用" || _yellow "未启用") ($bbr_status)"
    echo "  TFO: $([ "$tfo_status" = "enabled" ] && _green "已启用" || _yellow "未启用")"
    echo
    echo "1. 启用 BBR"
    echo "2. 启用 TFO"
    echo "3. 一键优化 (BBR + TFO + 内核参数)"
    echo "0. 返回"
    echo
    read -rp "选择: " choice
    
    case $choice in
        1) enable_bbr ;;
        2) enable_tfo ;;
        3) optimize_network ;;
    esac
    
    pause
}

# ============================================================================
# 命令行参数处理
# ============================================================================
case "${1:-}" in
    snell)
        snell_menu
        ;;
    sb|singbox|sing-box)
        singbox_menu
        ;;
    traffic|tr)
        traffic_menu
        ;;
    tg|telegram)
        telegram_setup
        ;;
    update)
        self_update
        ;;
    version|-v|--version)
        echo "VPS Manager v$VPS_VERSION"
        ;;
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
        echo
        echo "无参数时进入主菜单"
        ;;
    "")
        main_menu
        ;;
    *)
        echo "未知命令: $1"
        echo "使用 'vps help' 查看帮助"
        exit 1
        ;;
esac
