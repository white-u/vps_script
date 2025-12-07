#!/bin/bash
# ============================================================================
# VPS Manager - 流量监控模块
# ============================================================================

[[ "${TRAFFIC_LOADED:-}" == "true" ]] && return 0
TRAFFIC_LOADED=true

# ============================================================================
# 流量监控配置
# ============================================================================
readonly TRAFFIC_DIR="${VPS_DIR:-/etc/vps-manager}/traffic"
readonly TRAFFIC_DATA="$TRAFFIC_DIR/data.json"
readonly NFT_TABLE="vps_traffic"
readonly NFT_FAMILY="inet"

# ============================================================================
# 初始化
# ============================================================================
traffic_init() {
    mkdir -p "$TRAFFIC_DIR"
    
    if [[ ! -f "$TRAFFIC_DATA" ]]; then
        echo '{"ports":{}}' > "$TRAFFIC_DATA"
    fi
    
    # 初始化 nftables 表
    if command -v nft &>/dev/null; then
        nft list table $NFT_FAMILY $NFT_TABLE &>/dev/null 2>&1 || {
            nft add table $NFT_FAMILY $NFT_TABLE 2>/dev/null || true
            nft add chain $NFT_FAMILY $NFT_TABLE input "{ type filter hook input priority 0; policy accept; }" 2>/dev/null || true
            nft add chain $NFT_FAMILY $NFT_TABLE output "{ type filter hook output priority 0; policy accept; }" 2>/dev/null || true
        }
    fi
}

# ============================================================================
# 工具函数
# ============================================================================
traffic_get_port_safe() {
    echo "$1" | tr '-' '_'
}

traffic_get_port_count() {
    if [[ -f "$TRAFFIC_DATA" ]] && command -v jq &>/dev/null; then
        jq -r '.ports | keys | length' "$TRAFFIC_DATA" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

traffic_get_ports() {
    if [[ -f "$TRAFFIC_DATA" ]] && command -v jq &>/dev/null; then
        jq -r '.ports | keys[]' "$TRAFFIC_DATA" 2>/dev/null | sort -n
    fi
}

traffic_format_bytes() {
    local bytes="${1:-0}"
    
    if [[ ! "$bytes" =~ ^[0-9]+$ ]]; then
        echo "0B"
        return
    fi
    
    if [[ $bytes -ge 1099511627776 ]]; then
        echo "$(echo "scale=2; $bytes / 1099511627776" | bc)TB"
    elif [[ $bytes -ge 1073741824 ]]; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc)GB"
    elif [[ $bytes -ge 1048576 ]]; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc)MB"
    elif [[ $bytes -ge 1024 ]]; then
        echo "$(echo "scale=2; $bytes / 1024" | bc)KB"
    else
        echo "${bytes}B"
    fi
}

# ============================================================================
# nftables 规则管理
# ============================================================================
traffic_add_nft_rules() {
    local port="$1"
    local port_safe
    port_safe=$(traffic_get_port_safe "$port")
    
    command -v nft &>/dev/null || return 1
    
    # 创建计数器
    nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" &>/dev/null 2>&1 || \
        nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null || true
    nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" &>/dev/null 2>&1 || \
        nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null || true
    
    # 添加规则
    local proto
    for proto in tcp udp; do
        nft add rule $NFT_FAMILY $NFT_TABLE input $proto dport "$port" counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE output $proto sport "$port" counter name "port_${port_safe}_out" 2>/dev/null || true
    done
}

traffic_remove_nft_rules() {
    local port="$1"
    local port_safe
    port_safe=$(traffic_get_port_safe "$port")
    
    command -v nft &>/dev/null || return 1
    
    # 删除规则（多次尝试清理所有相关规则）
    local count=0
    while [[ $count -lt 20 ]]; do
        local handle
        handle=$(nft -a list table $NFT_FAMILY $NFT_TABLE 2>/dev/null | \
            grep -E "port_${port_safe}_" | head -n1 | sed -n 's/.*# handle \([0-9]\+\)$/\1/p')
        [[ -z "$handle" ]] && break
        
        local chain
        for chain in input output; do
            nft delete rule $NFT_FAMILY $NFT_TABLE $chain handle "$handle" 2>/dev/null && break
        done
        ((count++))
    done
    
    # 删除计数器
    nft delete counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null || true
    nft delete counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null || true
}

# ============================================================================
# 流量读取
# ============================================================================
traffic_get_port_bytes() {
    local port="$1"
    local port_safe
    port_safe=$(traffic_get_port_safe "$port")
    
    local input_bytes output_bytes
    input_bytes=$(nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null | \
                  grep -oE 'bytes [0-9]+' | awk '{print $2}' || echo "0")
    output_bytes=$(nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null | \
                  grep -oE 'bytes [0-9]+' | awk '{print $2}' || echo "0")
    
    echo "${input_bytes:-0} ${output_bytes:-0}"
}

traffic_reset_port_counter() {
    local port="$1"
    local port_safe
    port_safe=$(traffic_get_port_safe "$port")
    
    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" &>/dev/null || true
    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" &>/dev/null || true
}

# ============================================================================
# 端口管理 (供外部模块调用)
# ============================================================================
traffic_add_port() {
    local port="$1"
    local remark="${2:-}"
    
    traffic_init
    
    # 检查是否已存在
    if jq -e ".ports.\"$port\"" "$TRAFFIC_DATA" &>/dev/null 2>&1; then
        return 0
    fi
    
    # 添加 nftables 规则
    traffic_add_nft_rules "$port"
    
    # 更新配置
    local tmp="${TRAFFIC_DATA}.tmp.$$"
    local escaped_remark
    escaped_remark=$(echo "$remark" | sed 's/"/\\"/g')
    
    if jq ".ports.\"$port\" = {\"remark\": \"$escaped_remark\", \"created\": \"$(date -Iseconds)\"}" "$TRAFFIC_DATA" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$TRAFFIC_DATA"
    else
        rm -f "$tmp"
    fi
    
    log_info "流量监控: 已添加端口 $port${remark:+ ($remark)}"
}

traffic_remove_port() {
    local port="$1"
    
    # 删除规则
    traffic_remove_nft_rules "$port"
    
    # 更新配置
    local tmp="${TRAFFIC_DATA}.tmp.$$"
    if jq "del(.ports.\"$port\")" "$TRAFFIC_DATA" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$TRAFFIC_DATA"
    else
        rm -f "$tmp"
    fi
    
    log_info "流量监控: 已移除端口 $port"
}

# ============================================================================
# 显示状态
# ============================================================================
traffic_show_status() {
    traffic_init
    
    local -a ports
    mapfile -t ports < <(traffic_get_ports)
    
    local total=0
    
    echo
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                     端口流量监控                             ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    
    if [[ ${#ports[@]} -eq 0 ]]; then
        echo "║  暂无监控端口                                                ║"
    else
        for port in "${ports[@]}"; do
            local bytes_info input_bytes output_bytes total_bytes remark
            bytes_info=$(traffic_get_port_bytes "$port")
            input_bytes=$(echo "$bytes_info" | awk '{print $1}')
            output_bytes=$(echo "$bytes_info" | awk '{print $2}')
            total_bytes=$((input_bytes + output_bytes))
            total=$((total + total_bytes))
            
            remark=$(jq -r ".ports.\"$port\".remark // empty" "$TRAFFIC_DATA" 2>/dev/null)
            
            printf "║  \033[32m%-8s\033[0m ↑%-10s ↓%-10s 计:%-12s ║\n" \
                "$port" \
                "$(traffic_format_bytes "$input_bytes")" \
                "$(traffic_format_bytes "$output_bytes")" \
                "$(traffic_format_bytes "$total_bytes")"
            
            [[ -n "$remark" ]] && printf "║    \033[33m%-56s\033[0m ║\n" "[$remark]"
        done
    fi
    
    echo "╠══════════════════════════════════════════════════════════════╣"
    printf "║  监控: \033[32m%-2d\033[0m 个端口    总流量: \033[32m%-16s\033[0m          ║\n" "${#ports[@]}" "$(traffic_format_bytes "$total")"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo
}

# ============================================================================
# 交互式添加端口
# ============================================================================
traffic_add_port_interactive() {
    traffic_init
    
    echo
    _cyan "=== 添加端口监控 ==="
    echo
    
    # 显示系统监听端口
    echo "当前系统监听端口:"
    local ports_list
    ports_list=$(ss -tuln 2>/dev/null | grep -E "LISTEN|UNCONN" | awk '{print $5}' | \
        grep -oE '[0-9]+$' | sort -nu | grep -vE "^(22|25|53|80|443|3306)$" | head -20 | tr '\n' ' ')
    echo "${ports_list:-无}"
    echo
    
    read -rp "端口号 (多个用逗号分隔): " port_input || port_input=""
    [[ -z "$port_input" ]] && return
    
    read -rp "备注 (可选): " remark || remark=""
    
    IFS=',' read -ra parts <<< "$port_input"
    for part in "${parts[@]}"; do
        part=$(echo "$part" | tr -d ' ')
        
        if ! is_valid_port "$part"; then
            _yellow "无效端口: $part"
            continue
        fi
        
        if jq -e ".ports.\"$part\"" "$TRAFFIC_DATA" &>/dev/null 2>&1; then
            _yellow "端口 $part 已存在"
            continue
        fi
        
        traffic_add_port "$part" "$remark"
        _green "✓ 端口 $part 添加成功"
    done
}

# ============================================================================
# 交互式移除端口
# ============================================================================
traffic_remove_port_interactive() {
    local -a ports
    mapfile -t ports < <(traffic_get_ports)
    
    if [[ ${#ports[@]} -eq 0 ]]; then
        _yellow "没有监控的端口"
        return
    fi
    
    echo
    _cyan "=== 移除端口监控 ==="
    echo
    
    local i=0
    for port in "${ports[@]}"; do
        ((i++))
        local remark
        remark=$(jq -r ".ports.\"$port\".remark // empty" "$TRAFFIC_DATA" 2>/dev/null)
        echo "  $i. 端口 $port${remark:+ ($remark)}"
    done
    echo
    echo "  0. 返回"
    echo
    
    read -rp "选择: " choice || choice=""
    [[ -z "$choice" || "$choice" == "0" ]] && return
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#ports[@]} ]]; then
        local port="${ports[$((choice-1))]}"
        confirm "确认删除端口 $port?" || return
        traffic_remove_port "$port"
        _green "✓ 端口 $port 已删除"
    fi
}

# ============================================================================
# 重置流量
# ============================================================================
traffic_reset_interactive() {
    local -a ports
    mapfile -t ports < <(traffic_get_ports)
    
    if [[ ${#ports[@]} -eq 0 ]]; then
        _yellow "没有监控的端口"
        return
    fi
    
    echo
    _cyan "=== 重置流量统计 ==="
    echo
    
    local i=0
    for port in "${ports[@]}"; do
        ((i++))
        local bytes_info total_bytes
        bytes_info=$(traffic_get_port_bytes "$port")
        total_bytes=$(($(echo "$bytes_info" | awk '{print $1}') + $(echo "$bytes_info" | awk '{print $2}')))
        echo "  $i. 端口 $port [$(traffic_format_bytes "$total_bytes")]"
    done
    echo "  0. 全部重置"
    echo
    
    read -rp "选择: " sel || sel=""
    
    if [[ "$sel" == "0" ]]; then
        confirm "确认重置所有端口?" || return
        for port in "${ports[@]}"; do
            traffic_reset_port_counter "$port"
        done
        _green "✓ 已重置所有端口"
    elif [[ "$sel" =~ ^[0-9]+$ ]] && [[ $sel -ge 1 ]] && [[ $sel -le ${#ports[@]} ]]; then
        local port="${ports[$((sel-1))]}"
        confirm "确认重置端口 $port?" || return
        traffic_reset_port_counter "$port"
        _green "✓ 已重置端口 $port"
    fi
}

# ============================================================================
# 修改备注
# ============================================================================
traffic_set_remark() {
    local -a ports
    mapfile -t ports < <(traffic_get_ports)
    
    if [[ ${#ports[@]} -eq 0 ]]; then
        _yellow "没有监控的端口"
        return
    fi
    
    echo
    _cyan "=== 修改端口备注 ==="
    echo
    
    local i=0
    for port in "${ports[@]}"; do
        ((i++))
        local remark
        remark=$(jq -r ".ports.\"$port\".remark // empty" "$TRAFFIC_DATA" 2>/dev/null)
        echo "  $i. 端口 $port [备注: ${remark:-(无)}]"
    done
    echo
    
    read -rp "选择端口: " sel || sel=""
    [[ ! "$sel" =~ ^[0-9]+$ ]] && return
    [[ $sel -lt 1 || $sel -gt ${#ports[@]} ]] && return
    
    local port="${ports[$((sel-1))]}"
    read -rp "新备注 (留空清除): " new_remark || new_remark=""
    
    local escaped_remark
    escaped_remark=$(echo "$new_remark" | sed 's/"/\\"/g')
    
    local tmp="${TRAFFIC_DATA}.tmp.$$"
    if jq ".ports.\"$port\".remark = \"$escaped_remark\"" "$TRAFFIC_DATA" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$TRAFFIC_DATA"
        _green "✓ 备注已更新"
    else
        rm -f "$tmp"
    fi
}

# ============================================================================
# 菜单
# ============================================================================
traffic_menu() {
    while true; do
        traffic_init
        
        clear
        traffic_show_status
        
        echo "--- 端口管理 ---"
        echo "  1. 添加端口        2. 删除端口        3. 修改备注"
        echo "--- 流量管理 ---"
        echo "  4. 重置流量        5. 刷新状态"
        echo
        echo "  0. 返回主菜单"
        echo
        echo "============================================"
        echo
        read -rp "选择: " choice || choice=""
        
        case "$choice" in
            1) traffic_add_port_interactive; pause ;;
            2) traffic_remove_port_interactive; pause ;;
            3) traffic_set_remark; pause ;;
            4) traffic_reset_interactive; pause ;;
            5) continue ;;
            0|"") return ;;
            *) _yellow "无效选择"; sleep 0.5 ;;
        esac
    done
}
