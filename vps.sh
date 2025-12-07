#!/usr/bin/env bash
#
# VPS 代理统一管理平台
# 整合 Snell、sing-box、port-manage 三个脚本
# 提供统一入口和状态总览
#
# 使用方式:
#   vps              # 主菜单
#   vps status       # 状态总览
#   vps snell        # Snell 管理
#   vps sb           # sing-box 管理
#   vps traffic      # 流量监控
#   vps health       # 健康检查
#

set -euo pipefail

# =====================================
# 版本和配置
# =====================================
SCRIPT_VERSION="1.0.0"
SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/vps.sh"
SNELL_SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/Snell.sh"
SINGBOX_SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh"
PTM_SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/port-manage.sh"

# =====================================
# 颜色定义
# =====================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# =====================================
# 日志函数
# =====================================
log()     { echo -e "${GREEN}[INFO]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
success() { echo -e "${GREEN}✓${RESET} $*"; }
fail()    { echo -e "${RED}✗${RESET} $*"; }

# =====================================
# 系统检查
# =====================================
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "请以 root 身份运行此脚本"
        exit 1
    fi
}

# =====================================
# 服务检测
# =====================================
is_snell_installed() {
    [ -f /usr/local/bin/snell-server ] && [ -f /etc/systemd/system/snell.service ]
}

is_snell_running() {
    systemctl is-active --quiet snell 2>/dev/null
}

get_snell_port() {
    if [ -f /etc/snell/snell-server.conf ]; then
        grep -E '^listen' /etc/snell/snell-server.conf 2>/dev/null | sed -E 's/.*:([0-9]+)$/\1/' || echo ""
    fi
}

is_singbox_installed() {
    [ -d /etc/sing-box ] && [ -f /usr/local/bin/sing-box ]
}

is_singbox_running() {
    systemctl is-active --quiet sing-box 2>/dev/null
}

get_singbox_ports() {
    if [ -d /etc/sing-box/conf ]; then
        find /etc/sing-box/conf -name "*.json" -type f 2>/dev/null | while read conf; do
            local port=$(jq -r '.inbounds[0].listen_port' "$conf" 2>/dev/null)
            local proto=$(jq -r '.inbounds[0].type' "$conf" 2>/dev/null)
            [ -n "$port" ] && echo "$port|$proto"
        done
    fi
}

is_ptm_installed() {
    [ -f /etc/port-traffic-monitor/config.json ]
}

get_ptm_ports() {
    if [ -f /etc/port-traffic-monitor/config.json ]; then
        jq -r '.ports | keys[]' /etc/port-traffic-monitor/config.json 2>/dev/null || true
    fi
}

# =====================================
# 流量统计
# =====================================
get_port_traffic() {
    local port=$1
    local ptm_config="/etc/port-traffic-monitor/config.json"

    if [ ! -f "$ptm_config" ]; then
        echo "N/A"
        return
    fi

    # 读取 nftables 配置
    local nft_table=$(jq -r '.nftables.table_name // "port_monitor"' "$ptm_config")
    local nft_family=$(jq -r '.nftables.family // "inet"' "$ptm_config")
    local port_safe=$(echo "$port" | tr '-' '_')

    # 获取流量统计
    local output_bytes=$(nft list counter "$nft_family" "$nft_table" "port_${port_safe}_out" 2>/dev/null | grep -oE 'bytes [0-9]+' | awk '{print $2}')

    if [ -z "$output_bytes" ] || [ "$output_bytes" -eq 0 ]; then
        echo "0B"
    else
        format_bytes "$output_bytes"
    fi
}

format_bytes() {
    local bytes=${1:-0}
    if [ "$bytes" -ge 1099511627776 ]; then
        printf "%.2fTB" "$(echo "scale=2; $bytes / 1099511627776" | bc)"
    elif [ "$bytes" -ge 1073741824 ]; then
        printf "%.2fGB" "$(echo "scale=2; $bytes / 1073741824" | bc)"
    elif [ "$bytes" -ge 1048576 ]; then
        printf "%.2fMB" "$(echo "scale=2; $bytes / 1048576" | bc)"
    elif [ "$bytes" -ge 1024 ]; then
        printf "%.2fKB" "$(echo "scale=2; $bytes / 1024" | bc)"
    else
        echo "${bytes}B"
    fi
}

# =====================================
# 状态总览
# =====================================
show_status() {
    clear
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN}          VPS 代理统一管理平台 v${SCRIPT_VERSION}${RESET}"
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════${RESET}"
    echo ""

    # Snell 状态
    echo -e "${BOLD}📡 Snell Server${RESET}"
    if is_snell_installed; then
        local port=$(get_snell_port)
        if is_snell_running; then
            local traffic=$(get_port_traffic "$port")
            echo -e "  状态: ${GREEN}● 运行中${RESET}"
            echo -e "  端口: ${CYAN}$port${RESET}"
            echo -e "  流量: ${YELLOW}$traffic${RESET}"
        else
            echo -e "  状态: ${RED}● 已停止${RESET}"
        fi
    else
        echo -e "  状态: ${YELLOW}未安装${RESET}"
    fi
    echo ""

    # sing-box 状态
    echo -e "${BOLD}🚀 sing-box${RESET}"
    if is_singbox_installed; then
        if is_singbox_running; then
            echo -e "  状态: ${GREEN}● 运行中${RESET}"
            local configs=$(get_singbox_ports)
            if [ -n "$configs" ]; then
                echo -e "  配置:"
                echo "$configs" | while IFS='|' read port proto; do
                    local traffic=$(get_port_traffic "$port")
                    printf "    ${CYAN}%-6s${RESET} %-20s 流量: ${YELLOW}%s${RESET}\n" "$port" "($proto)" "$traffic"
                done
            else
                echo -e "  配置: ${YELLOW}无${RESET}"
            fi
        else
            echo -e "  状态: ${RED}● 已停止${RESET}"
        fi
    else
        echo -e "  状态: ${YELLOW}未安装${RESET}"
    fi
    echo ""

    # 流量监控状态
    echo -e "${BOLD}📊 流量监控${RESET}"
    if is_ptm_installed; then
        local port_count=$(get_ptm_ports | wc -l | tr -d ' ')
        echo -e "  状态: ${GREEN}已安装${RESET}"
        echo -e "  监控端口数: ${CYAN}$port_count${RESET}"
    else
        echo -e "  状态: ${YELLOW}未安装${RESET}"
    fi
    echo ""

    echo -e "${CYAN}────────────────────────────────────────────────────────${RESET}"
}

# =====================================
# 健康检查
# =====================================
health_check() {
    echo -e "\n${BOLD}${CYAN}🔍 系统健康检查${RESET}\n"

    local failed=0
    local total=0

    # 检查 Snell
    if is_snell_installed; then
        ((total++))
        local port=$(get_snell_port)
        if is_snell_running; then
            if ss -tuln 2>/dev/null | grep -q ":$port "; then
                success "Snell 端口 $port 正常监听"
            else
                fail "Snell 端口 $port 监听失败"
                ((failed++))
            fi
        else
            fail "Snell 服务未运行"
            ((failed++))
        fi
    fi

    # 检查 sing-box
    if is_singbox_installed; then
        if is_singbox_running; then
            local configs=$(get_singbox_ports)
            if [ -n "$configs" ]; then
                echo "$configs" | while IFS='|' read port proto; do
                    if ss -tuln 2>/dev/null | grep -q ":$port "; then
                        success "sing-box 端口 $port ($proto) 正常监听"
                    else
                        fail "sing-box 端口 $port ($proto) 监听失败"
                    fi
                done
            fi
        else
            ((total++))
            fail "sing-box 服务未运行"
            ((failed++))
        fi
    fi

    # 检查流量监控
    if is_ptm_installed; then
        ((total++))
        if command -v nft >/dev/null 2>&1; then
            if nft list tables 2>/dev/null | grep -q port_monitor; then
                success "流量监控 nftables 规则正常"
            else
                fail "流量监控 nftables 规则缺失"
                ((failed++))
            fi
        else
            fail "nftables 未安装"
            ((failed++))
        fi
    fi

    echo ""
    if [ $total -eq 0 ]; then
        warn "未检测到已安装的服务"
    elif [ $failed -eq 0 ]; then
        echo -e "${GREEN}${BOLD}✓ 所有检查通过！${RESET}"
    else
        echo -e "${RED}${BOLD}✗ 发现 $failed 个问题${RESET}"
    fi
    echo ""
}

# =====================================
# 主菜单
# =====================================
show_menu() {
    show_status

    echo -e "${BOLD}主菜单${RESET}"
    echo ""
    echo "  ${CYAN}[1]${RESET} Snell 管理"
    echo "  ${CYAN}[2]${RESET} sing-box 管理"
    echo "  ${CYAN}[3]${RESET} 流量监控"
    echo ""
    echo "  ${CYAN}[4]${RESET} 刷新状态"
    echo "  ${CYAN}[5]${RESET} 健康检查"
    echo "  ${CYAN}[6]${RESET} 安装缺失组件"
    echo ""
    echo "  ${CYAN}[0]${RESET} 退出"
    echo ""
    echo -e "${CYAN}────────────────────────────────────────────────────────${RESET}"
    echo ""
}

# =====================================
# 安装组件
# =====================================
install_component() {
    echo -e "\n${BOLD}${CYAN}📦 安装组件${RESET}\n"

    local choices=()

    if ! is_snell_installed; then
        choices+=("1. Snell Server")
    fi

    if ! is_singbox_installed; then
        choices+=("2. sing-box")
    fi

    if ! is_ptm_installed; then
        choices+=("3. 流量监控 (port-manage)")
    fi

    if [ ${#choices[@]} -eq 0 ]; then
        success "所有组件都已安装"
        read -rp "按回车返回..." _
        return
    fi

    echo "可安装的组件："
    echo ""
    for choice in "${choices[@]}"; do
        echo "  $choice"
    done
    echo ""
    echo "  0. 返回"
    echo ""

    read -rp "请选择要安装的组件: " pick

    case "$pick" in
        1)
            if ! is_snell_installed; then
                log "开始安装 Snell..."
                bash <(curl -sL "$SNELL_SCRIPT_URL")
            fi
            ;;
        2)
            if ! is_singbox_installed; then
                log "开始安装 sing-box..."
                bash <(curl -sL "$SINGBOX_SCRIPT_URL")
            fi
            ;;
        3)
            if ! is_ptm_installed; then
                log "开始安装 port-manage..."
                bash <(curl -sL "$PTM_SCRIPT_URL")
            fi
            ;;
        0)
            return
            ;;
        *)
            warn "无效选择"
            sleep 1
            ;;
    esac
}

# =====================================
# 快捷命令处理
# =====================================
handle_command() {
    case "${1:-}" in
        status|s)
            show_status
            echo ""
            exit 0
            ;;
        health|h)
            health_check
            exit 0
            ;;
        snell)
            if is_snell_installed; then
                snell
            else
                error "Snell 未安装，请先安装"
                echo "运行: vps 并选择 [6] 安装缺失组件"
                exit 1
            fi
            ;;
        sb|singbox|sing-box)
            if is_singbox_installed; then
                sing-box
            else
                error "sing-box 未安装，请先安装"
                echo "运行: vps 并选择 [6] 安装缺失组件"
                exit 1
            fi
            ;;
        traffic|ptm)
            if is_ptm_installed; then
                ptm
            else
                error "port-manage 未安装，请先安装"
                echo "运行: vps 并选择 [6] 安装缺失组件"
                exit 1
            fi
            ;;
        install)
            install_component
            ;;
        version|v|-v|--version)
            echo "VPS 代理统一管理平台 v${SCRIPT_VERSION}"
            exit 0
            ;;
        help|--help|-h)
            show_help
            exit 0
            ;;
        *)
            if [ -n "${1:-}" ]; then
                error "未知命令: $1"
                echo ""
                show_help
                exit 1
            fi
            ;;
    esac
}

# =====================================
# 帮助信息
# =====================================
show_help() {
    cat << EOF
VPS 代理统一管理平台 v${SCRIPT_VERSION}

用法:
  vps [命令]

命令:
  (无)          显示主菜单
  status, s     显示状态总览
  health, h     执行健康检查
  snell         进入 Snell 管理
  sb            进入 sing-box 管理
  traffic, ptm  进入流量监控
  install       安装缺失组件
  version, v    显示版本
  help          显示此帮助

示例:
  vps              # 进入主菜单
  vps status       # 查看所有服务状态
  vps health       # 健康检查
  vps snell        # 管理 Snell
  vps sb           # 管理 sing-box
  vps traffic      # 管理流量监控

EOF
}

# =====================================
# 主循环
# =====================================
main() {
    check_root

    # 处理命令行参数
    if [ $# -gt 0 ]; then
        handle_command "$@"
        return
    fi

    # 主菜单循环
    while true; do
        show_menu
        read -rp "请选择 [0-6]: " choice

        case "$choice" in
            1)
                if is_snell_installed; then
                    snell
                else
                    error "Snell 未安装"
                    read -rp "是否现在安装? [y/N]: " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        bash <(curl -sL "$SNELL_SCRIPT_URL")
                    fi
                fi
                ;;
            2)
                if is_singbox_installed; then
                    sing-box
                else
                    error "sing-box 未安装"
                    read -rp "是否现在安装? [y/N]: " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        bash <(curl -sL "$SINGBOX_SCRIPT_URL")
                    fi
                fi
                ;;
            3)
                if is_ptm_installed; then
                    ptm
                else
                    error "port-manage 未安装"
                    read -rp "是否现在安装? [y/N]: " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        bash <(curl -sL "$PTM_SCRIPT_URL")
                    fi
                fi
                ;;
            4)
                # 刷新状态（重新显示菜单）
                continue
                ;;
            5)
                health_check
                read -rp "按回车返回..." _
                ;;
            6)
                install_component
                ;;
            0)
                echo ""
                log "退出"
                exit 0
                ;;
            *)
                warn "无效选择"
                sleep 1
                ;;
        esac
    done
}

# 运行主程序
main "$@"
