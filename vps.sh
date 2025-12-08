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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

check_dependencies() {
    local missing=()
    local optional_missing=()

    # 检查必需工具
    command -v jq >/dev/null 2>&1 || missing+=("jq")

    # 检查可选工具（缺失时会影响功能但不会完全无法使用）
    command -v bc >/dev/null 2>&1 || optional_missing+=("bc")
    command -v awk >/dev/null 2>&1 || optional_missing+=("awk")
    command -v nft >/dev/null 2>&1 || optional_missing+=("nftables")
    command -v ss >/dev/null 2>&1 || optional_missing+=("iproute2")

    if [ ${#missing[@]} -gt 0 ]; then
        warn "缺少必需工具: ${missing[*]}"
        log "正在安装依赖工具..."
        echo ""

        # 检测包管理器并自动安装
        if command -v apt >/dev/null 2>&1; then
            apt update -qq && apt install -y ${missing[*]}
        elif command -v yum >/dev/null 2>&1; then
            yum install -y ${missing[*]}
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y ${missing[*]}
        elif command -v apk >/dev/null 2>&1; then
            apk add ${missing[*]}
        elif command -v brew >/dev/null 2>&1; then
            brew install ${missing[*]}
        else
            error "未检测到支持的包管理器"
            echo ""
            error "请手动安装缺失的工具："
            echo "  Debian/Ubuntu: apt install ${missing[*]}"
            echo "  CentOS/RHEL:   yum install ${missing[*]}"
            echo "  Alpine:        apk add ${missing[*]}"
            echo "  macOS:         brew install ${missing[*]}"
            echo ""
            exit 1
        fi

        # 验证安装
        local install_failed=()
        for tool in "${missing[@]}"; do
            if ! command -v "$tool" >/dev/null 2>&1; then
                install_failed+=("$tool")
            fi
        done

        if [ ${#install_failed[@]} -gt 0 ]; then
            error "安装失败: ${install_failed[*]}"
            echo ""
            error "请手动安装后重试："
            echo "  Debian/Ubuntu: apt install ${install_failed[*]}"
            echo "  CentOS/RHEL:   yum install ${install_failed[*]}"
            echo "  Alpine:        apk add ${install_failed[*]}"
            echo "  macOS:         brew install ${install_failed[*]}"
            echo ""
            exit 1
        fi

        success "依赖工具安装成功"
        echo ""
    fi

    if [ ${#optional_missing[@]} -gt 0 ]; then
        warn "缺少可选工具: ${optional_missing[*]}"
        warn "部分功能可能受限（流量统计、端口检查等）"
        echo ""

        # 询问是否安装可选工具
        read -rp "是否安装可选工具以启用完整功能? [y/N]: " install_optional
        if [[ "$install_optional" =~ ^[Yy]$ ]]; then
            log "正在安装可选工具..."

            if command -v apt >/dev/null 2>&1; then
                apt install -y ${optional_missing[*]} 2>/dev/null || warn "部分可选工具安装失败（不影响核心功能）"
            elif command -v yum >/dev/null 2>&1; then
                yum install -y ${optional_missing[*]} 2>/dev/null || warn "部分可选工具安装失败（不影响核心功能）"
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y ${optional_missing[*]} 2>/dev/null || warn "部分可选工具安装失败（不影响核心功能）"
            elif command -v apk >/dev/null 2>&1; then
                apk add ${optional_missing[*]} 2>/dev/null || warn "部分可选工具安装失败（不影响核心功能）"
            fi

            echo ""
        else
            warn "已跳过可选工具安装，建议稍后手动安装以启用完整功能"
            echo ""
        fi
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
        while read -r conf; do
            local port=$(jq -r '.inbounds[0].listen_port' "$conf" 2>/dev/null)
            local proto=$(jq -r '.inbounds[0].type' "$conf" 2>/dev/null)
            [ -n "$port" ] && echo "$port|$proto"
        done < <(find /etc/sing-box/conf -name "*.json" -type f 2>/dev/null)
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
        awk "BEGIN {printf \"%.2fTB\", $bytes/1099511627776}"
    elif [ "$bytes" -ge 1073741824 ]; then
        awk "BEGIN {printf \"%.2fGB\", $bytes/1073741824}"
    elif [ "$bytes" -ge 1048576 ]; then
        awk "BEGIN {printf \"%.2fMB\", $bytes/1048576}"
    elif [ "$bytes" -ge 1024 ]; then
        awk "BEGIN {printf \"%.2fKB\", $bytes/1024}"
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
                while IFS='|' read -r port proto; do
                    local traffic=$(get_port_traffic "$port")
                    printf "    ${CYAN}%-6s${RESET} %-20s 流量: ${YELLOW}%s${RESET}\n" "$port" "($proto)" "$traffic"
                done < <(echo "$configs")
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
                while IFS='|' read -r port proto; do
                    ((total++))
                    if ss -tuln 2>/dev/null | grep -q ":$port "; then
                        success "sing-box 端口 $port ($proto) 正常监听"
                    else
                        fail "sing-box 端口 $port ($proto) 监听失败"
                        ((failed++))
                    fi
                done < <(echo "$configs")
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
    echo -e "  ${CYAN}[1]${RESET} Snell 管理"
    echo -e "  ${CYAN}[2]${RESET} sing-box 管理"
    echo -e "  ${CYAN}[3]${RESET} 流量监控"
    echo ""
    echo -e "  ${CYAN}[4]${RESET} 刷新状态"
    echo -e "  ${CYAN}[5]${RESET} 健康检查"
    echo -e "  ${CYAN}[6]${RESET} 安装缺失组件"
    echo ""
    echo -e "  ${RED}[7]${RESET} 一键卸载所有组件"
    echo ""
    echo -e "  ${CYAN}[0]${RESET} 退出"
    echo ""
    echo -e "${CYAN}────────────────────────────────────────────────────────${RESET}"
    echo ""
}

# =====================================
# 一键卸载所有组件
# =====================================
uninstall_all() {
    clear
    echo -e "${BOLD}${RED}════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${RED}          ⚠️  一键卸载所有组件  ⚠️${RESET}"
    echo -e "${BOLD}${RED}════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "${YELLOW}此操作将卸载以下所有组件：${RESET}"
    echo ""

    local to_uninstall=()

    if is_snell_installed; then
        echo "  ✓ Snell Server"
        to_uninstall+=("snell")
    fi

    if is_singbox_installed; then
        echo "  ✓ sing-box"
        to_uninstall+=("singbox")
    fi

    if is_ptm_installed; then
        echo "  ✓ 流量监控 (port-manage)"
        to_uninstall+=("ptm")
    fi

    echo "  ✓ VPS 统一管理平台"

    echo ""

    if [ ${#to_uninstall[@]} -eq 0 ]; then
        warn "未检测到已安装的组件"
        read -rp "按回车返回..." _
        return
    fi

    echo -e "${RED}${BOLD}警告：此操作将：${RESET}"
    echo "  • 停止并卸载所有代理服务"
    echo "  • 删除所有配置文件和数据"
    echo "  • 清理防火墙规则"
    echo "  • 移除网络优化设置"
    echo "  • 删除所有安装的脚本和二进制文件"
    echo "  • 清理流量统计数据"
    echo ""
    echo -e "${RED}${BOLD}此操作不可逆！${RESET}"
    echo ""

    read -rp "确认要卸载所有组件吗？请输入 YES 继续: " confirm

    if [ "$confirm" != "YES" ]; then
        warn "已取消卸载"
        sleep 1
        return
    fi

    echo ""
    echo -e "${CYAN}开始卸载...${RESET}"
    echo ""

    # 卸载 Snell
    if is_snell_installed; then
        log "正在卸载 Snell Server..."

        # 停止服务
        systemctl stop snell 2>/dev/null || true
        systemctl disable snell 2>/dev/null || true

        # 获取端口用于清理防火墙
        local snell_port=""
        if [ -f /etc/snell/snell-server.conf ]; then
            snell_port=$(grep -E '^listen' /etc/snell/snell-server.conf 2>/dev/null | sed -E 's/.*:([0-9]+)$/\1/' || echo "")
        fi

        # 删除文件
        rm -f /etc/systemd/system/snell.service
        rm -f /usr/local/bin/snell-server
        rm -rf /etc/snell
        rm -rf /var/backups/snell-manager
        rm -f /usr/local/bin/snell-manager.sh
        rm -f /usr/local/bin/snell
        rm -f /tmp/snell_version_cache

        # 清理防火墙
        if [ -n "$snell_port" ]; then
            ufw delete allow "$snell_port"/tcp 2>/dev/null || true
            ufw delete allow "$snell_port"/udp 2>/dev/null || true
            firewall-cmd --permanent --remove-port="${snell_port}"/tcp 2>/dev/null || true
            firewall-cmd --permanent --remove-port="${snell_port}"/udp 2>/dev/null || true
        fi

        # 清理网络优化
        rm -f /etc/sysctl.d/99-snell.conf

        systemctl daemon-reload 2>/dev/null || true
        success "Snell Server 已卸载"
    fi

    # 卸载 sing-box
    if is_singbox_installed; then
        log "正在卸载 sing-box..."

        # 停止服务
        systemctl stop sing-box 2>/dev/null || true
        systemctl disable sing-box 2>/dev/null || true

        # 获取所有端口用于清理防火墙
        if [ -d /etc/sing-box/conf ]; then
            while read -r conf; do
                local port=$(jq -r '.inbounds[0].listen_port' "$conf" 2>/dev/null)
                if [ -n "$port" ]; then
                    ufw delete allow "$port"/tcp 2>/dev/null || true
                    ufw delete allow "$port"/udp 2>/dev/null || true
                    firewall-cmd --permanent --remove-port="${port}"/tcp 2>/dev/null || true
                    firewall-cmd --permanent --remove-port="${port}"/udp 2>/dev/null || true
                fi
            done < <(find /etc/sing-box/conf -name "*.json" -type f 2>/dev/null)
        fi

        # 删除文件
        rm -f /etc/systemd/system/sing-box.service
        rm -rf /etc/sing-box
        rm -rf /var/log/sing-box
        rm -f /usr/local/bin/sing-box
        rm -f /tmp/singbox_version_cache

        # 清理网络优化
        rm -f /etc/sysctl.d/99-singbox.conf

        systemctl daemon-reload 2>/dev/null || true
        success "sing-box 已卸载"
    fi

    # 卸载 port-manage
    if is_ptm_installed; then
        log "正在卸载流量监控..."

        # 删除定时任务
        crontab -l 2>/dev/null | grep -v port-traffic-monitor | crontab - 2>/dev/null || true

        # 删除 nftables 规则
        nft delete table inet port_monitor 2>/dev/null || true

        # 删除 tc 规则
        local interface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
        if [ -n "$interface" ]; then
            tc qdisc del dev "$interface" handle ffff: ingress 2>/dev/null || true
        fi
        tc qdisc del dev ifb0 root 2>/dev/null || true
        ip link set ifb0 down 2>/dev/null || true

        # 删除文件
        rm -rf /etc/port-traffic-monitor
        rm -f /usr/local/bin/ptm
        rm -f /usr/local/bin/port-traffic-monitor.sh

        success "流量监控已卸载"
    fi

    # 卸载 VPS 统一管理平台
    log "正在卸载 VPS 统一管理平台..."
    rm -f /usr/local/bin/vps
    success "VPS 统一管理平台已卸载"

    # 重新加载防火墙
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --reload 2>/dev/null || true
    fi

    # 重新加载 sysctl
    sysctl -p 2>/dev/null || true

    echo ""
    echo -e "${GREEN}${BOLD}✓ 所有组件已卸载完成！${RESET}"
    echo ""
    echo -e "${YELLOW}已清理的内容：${RESET}"
    echo "  • 所有服务和二进制文件"
    echo "  • 所有配置文件和数据"
    echo "  • 防火墙规则"
    echo "  • 网络优化设置"
    echo "  • 定时任务"
    echo "  • 流量统计规则"
    echo ""
    echo -e "${CYAN}感谢使用 VPS 代理管理平台！${RESET}"
    echo ""

    read -rp "按回车退出..." _
    exit 0
}

# =====================================
# 自更新功能
# =====================================
update_self() {
    echo -e "\n${BOLD}${CYAN}🔄 检查 vps.sh 更新${RESET}\n"

    local current_version="$SCRIPT_VERSION"
    local temp_file="/tmp/vps_new.sh"
    local backup_file="/tmp/vps_backup_$(date +%Y%m%d_%H%M%S).sh"

    # 备份当前脚本
    local script_path
    if readlink -f "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
        script_path="$(readlink -f "${BASH_SOURCE[0]}")"
    else
        script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    fi

    if [ -f "$script_path" ]; then
        cp "$script_path" "$backup_file"
        log "已备份当前版本到: $backup_file"
    fi

    # 下载最新版本
    log "正在从 GitHub 下载最新版本..."
    if curl -fsSL "$SCRIPT_URL" -o "$temp_file" 2>/dev/null; then
        log "下载成功，正在验证..."
    elif wget -q "$SCRIPT_URL" -O "$temp_file" 2>/dev/null; then
        log "下载成功（使用 wget），正在验证..."
    else
        error "下载失败，请检查网络连接"
        rm -f "$temp_file"
        read -rp "按回车返回..." _
        return 1
    fi

    # 验证语法
    if ! bash -n "$temp_file" 2>/dev/null; then
        error "下载的文件语法错误，更新已取消"
        rm -f "$temp_file"
        warn "如需恢复，备份文件位于: $backup_file"
        read -rp "按回车返回..." _
        return 1
    fi

    # 获取新版本号
    local new_version=$(grep '^SCRIPT_VERSION=' "$temp_file" | head -1 | cut -d'"' -f2)

    echo ""
    echo -e "${CYAN}当前版本:${RESET} $current_version"
    echo -e "${CYAN}最新版本:${RESET} $new_version"
    echo ""

    # 版本比较
    if [ "$current_version" = "$new_version" ]; then
        success "已是最新版本，无需更新"
        rm -f "$temp_file"
        read -rp "按回车返回..." _
        return 0
    fi

    # 确认更新
    read -rp "确认更新到 v$new_version? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        warn "已取消更新"
        rm -f "$temp_file"
        read -rp "按回车返回..." _
        return 0
    fi

    # 执行更新
    log "正在更新..."
    chmod +x "$temp_file"

    if mv "$temp_file" "$script_path" 2>/dev/null; then
        success "✓ 更新成功！"
        echo ""
        echo -e "${GREEN}版本已更新: $current_version → $new_version${RESET}"
        echo -e "${CYAN}备份文件: $backup_file${RESET}"
        echo ""
        warn "请重新运行 vps 命令以使用新版本"
        echo ""
        read -rp "按回车退出..." _
        exit 0
    else
        error "更新失败，可能需要 root 权限"
        warn "请尝试: sudo bash $temp_file"
        warn "或手动复制: sudo mv $temp_file $script_path"
        read -rp "按回车返回..." _
        return 1
    fi
}

# =====================================
# 安装组件
# =====================================
install_component() {
    echo -e "\n${BOLD}${CYAN}📦 安装组件${RESET}\n"

    local choices=()
    local has_missing=0

    if ! is_snell_installed; then
        choices+=("1. Snell Server")
        has_missing=1
    fi

    if ! is_singbox_installed; then
        choices+=("2. sing-box")
        has_missing=1
    fi

    if ! is_ptm_installed; then
        choices+=("3. 流量监控 (port-manage)")
        has_missing=1
    fi

    # 检查模块是否存在
    if [ ! -f "${SCRIPT_DIR}/system-optimize.sh" ] || [ ! -f "${SCRIPT_DIR}/telegram-notify.sh" ]; then
        choices+=("4. 系统优化模块 (system-optimize.sh, telegram-notify.sh)")
        has_missing=1
    fi

    if [ $has_missing -eq 0 ]; then
        success "所有组件和模块都已安装"
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
                bash <(curl -fsSL "$SNELL_SCRIPT_URL")
            fi
            ;;
        2)
            if ! is_singbox_installed; then
                log "开始安装 sing-box..."
                bash <(curl -fsSL "$SINGBOX_SCRIPT_URL")
            fi
            ;;
        3)
            if ! is_ptm_installed; then
                log "开始安装 port-manage..."
                bash <(curl -fsSL "$PTM_SCRIPT_URL")
            fi
            ;;
        4)
            log "开始下载系统优化模块..."
            local success_count=0

            # 下载 system-optimize.sh
            if curl -fsSL "${SCRIPT_URL%/*}/system-optimize.sh" -o "${SCRIPT_DIR}/system-optimize.sh" 2>/dev/null || \
               wget -q "${SCRIPT_URL%/*}/system-optimize.sh" -O "${SCRIPT_DIR}/system-optimize.sh" 2>/dev/null; then
                # 验证语法
                if bash -n "${SCRIPT_DIR}/system-optimize.sh" 2>/dev/null; then
                    chmod +x "${SCRIPT_DIR}/system-optimize.sh"
                    success "system-optimize.sh 下载并验证成功"
                    ((success_count++))
                else
                    rm -f "${SCRIPT_DIR}/system-optimize.sh"
                    error "system-optimize.sh 语法错误，已删除"
                fi
            else
                error "system-optimize.sh 下载失败"
            fi

            # 下载 telegram-notify.sh
            if curl -fsSL "${SCRIPT_URL%/*}/telegram-notify.sh" -o "${SCRIPT_DIR}/telegram-notify.sh" 2>/dev/null || \
               wget -q "${SCRIPT_URL%/*}/telegram-notify.sh" -O "${SCRIPT_DIR}/telegram-notify.sh" 2>/dev/null; then
                # 验证语法
                if bash -n "${SCRIPT_DIR}/telegram-notify.sh" 2>/dev/null; then
                    chmod +x "${SCRIPT_DIR}/telegram-notify.sh"
                    success "telegram-notify.sh 下载并验证成功"
                    ((success_count++))
                else
                    rm -f "${SCRIPT_DIR}/telegram-notify.sh"
                    error "telegram-notify.sh 语法错误，已删除"
                fi
            else
                error "telegram-notify.sh 下载失败"
            fi

            if [ $success_count -eq 2 ]; then
                success "所有模块下载完成"
            elif [ $success_count -gt 0 ]; then
                warn "部分模块下载成功 ($success_count/2)"
            else
                error "所有模块下载失败，请检查网络连接"
            fi

            read -rp "按回车返回..." _
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
        uninstall)
            uninstall_all
            ;;
        update|upgrade)
            update_self
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
  uninstall     一键卸载所有组件
  update        更新 vps.sh 到最新版本
  version, v    显示版本
  help          显示此帮助

示例:
  vps              # 进入主菜单
  vps status       # 查看所有服务状态
  vps health       # 健康检查
  vps snell        # 管理 Snell
  vps sb           # 管理 sing-box
  vps traffic      # 管理流量监控
  vps update       # 更新到最新版本

EOF
}

# =====================================
# 主循环
# =====================================
main() {
    check_root
    check_dependencies

    # 创建快捷命令（如果不存在）
    local script_path
    if readlink -f "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
        script_path="$(readlink -f "${BASH_SOURCE[0]}")"
    else
        # macOS 兼容性：readlink 不支持 -f
        script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    fi

    if [ ! -L /usr/local/bin/vps ] && [ -f "$script_path" ]; then
        ln -sf "$script_path" /usr/local/bin/vps 2>/dev/null && \
            log "已创建快捷命令：vps" || true
    fi

    # 处理命令行参数
    if [ $# -gt 0 ]; then
        handle_command "$@"
        return
    fi

    # 主菜单循环
    while true; do
        show_menu
        read -rp "请选择 [0-7]: " choice

        case "$choice" in
            1)
                if is_snell_installed; then
                    snell
                else
                    error "Snell 未安装"
                    read -rp "是否现在安装? [y/N]: " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        bash <(curl -fsSL "$SNELL_SCRIPT_URL")
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
                        bash <(curl -fsSL "$SINGBOX_SCRIPT_URL")
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
                        bash <(curl -fsSL "$PTM_SCRIPT_URL")
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
            7)
                uninstall_all
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
