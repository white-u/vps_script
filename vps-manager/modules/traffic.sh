#!/bin/bash
# ============================================================================
# VPS Manager - 流量监控模块 (完整版)
# ============================================================================

# 防止重复加载
[[ "${XXX_LOADED:-}" == "true" ]] && return 0
XXX_LOADED=true

# ============================================================================
# 流量监控配置
# ============================================================================
readonly TRAFFIC_DIR="$VPS_DIR/traffic"
readonly TRAFFIC_DATA="$TRAFFIC_DIR/data.json"
readonly TRAFFIC_ALERT_STATE="$TRAFFIC_DIR/alert_state.json"
readonly NFT_TABLE="vps_traffic"
readonly NFT_FAMILY="inet"

# ============================================================================
# 初始化
# ============================================================================
traffic_init() {
    mkdir -p "$TRAFFIC_DIR"
    
    if [[ ! -f "$TRAFFIC_DATA" ]]; then
        cat > "$TRAFFIC_DATA" <<'EOF'
{
  "ports": {},
  "settings": {
    "reset_day": 1,
    "billing": "single"
  }
}
EOF
    fi
    
    [[ ! -f "$TRAFFIC_ALERT_STATE" ]] && echo '{}' > "$TRAFFIC_ALERT_STATE"
    
    # 确保依赖
    ensure_deps nft bc jq
    
    # 初始化 nftables 表
    if ! nft list table $NFT_FAMILY $NFT_TABLE &>/dev/null; then
        nft add table $NFT_FAMILY $NFT_TABLE
        nft add chain $NFT_FAMILY $NFT_TABLE input "{ type filter hook input priority 0; policy accept; }"
        nft add chain $NFT_FAMILY $NFT_TABLE output "{ type filter hook output priority 0; policy accept; }"
    fi
}

# ============================================================================
# 流量读取
# ============================================================================
traffic_get_port_bytes() {
    local port=$1
    local port_safe=$(echo "$port" | tr '-' '_')
    
    local input_bytes=$(nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null | \
                        grep -oE 'bytes [0-9]+' | awk '{print $2}')
    local output_bytes=$(nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null | \
                        grep -oE 'bytes [0-9]+' | awk '{print $2}')
    
    echo "${input_bytes:-0} ${output_bytes:-0}"
}

traffic_format_bytes() {
    local bytes=${1:-0}
    
    if [[ $bytes -ge 1099511627776 ]]; then
        printf "%.2fTB" $(echo "scale=2; $bytes / 1099511627776" | bc)
    elif [[ $bytes -ge 1073741824 ]]; then
        printf "%.2fGB" $(echo "scale=2; $bytes / 1073741824" | bc)
    elif [[ $bytes -ge 1048576 ]]; then
        printf "%.2fMB" $(echo "scale=2; $bytes / 1048576" | bc)
    elif [[ $bytes -ge 1024 ]]; then
        printf "%.2fKB" $(echo "scale=2; $bytes / 1024" | bc)
    else
        echo "${bytes}B"
    fi
}

# 解析流量字符串 (如 "100G", "1.5T", "500M") 为字节
traffic_parse_to_bytes() {
    local input="${1:-0}"
    local number unit bytes
    
    number=$(echo "$input" | grep -oE '^[0-9.]+')
    unit=$(echo "$input" | grep -oE '[A-Za-z]+$' | tr '[:lower:]' '[:upper:]')
    
    [[ -z "$number" ]] && number=0
    [[ -z "$unit" ]] && unit="GB"  # 默认 GB
    
    case $unit in
        T|TB) bytes=$(echo "$number * 1099511627776" | bc | cut -d. -f1) ;;
        G|GB) bytes=$(echo "$number * 1073741824" | bc | cut -d. -f1) ;;
        M|MB) bytes=$(echo "$number * 1048576" | bc | cut -d. -f1) ;;
        K|KB) bytes=$(echo "$number * 1024" | bc | cut -d. -f1) ;;
        *)    bytes=$(echo "$number * 1073741824" | bc | cut -d. -f1) ;;  # 默认 GB
    esac
    
    echo "${bytes:-0}"
}

# ============================================================================
# 添加端口监控 (供其他模块调用)
# ============================================================================
traffic_add_port() {
    local port=$1
    local remark=${2:-""}
    local port_safe=$(echo "$port" | tr '-' '_')
    
    traffic_init
    
    # 检查是否已存在
    if jq -e ".ports.\"$port\"" "$TRAFFIC_DATA" &>/dev/null; then
        log_warn "端口 $port 已在监控中"
        return 0
    fi
    
    # 添加 nftables 计数器
    nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null || true
    nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null || true
    
    # 添加规则 (TCP/UDP)
    for proto in tcp udp; do
        nft add rule $NFT_FAMILY $NFT_TABLE input $proto dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE output $proto sport $port counter name "port_${port_safe}_out" 2>/dev/null || true
    done
    
    # 更新配置
    local tmp="${TRAFFIC_DATA}.tmp"
    jq ".ports.\"$port\" = {
        \"remark\": \"$remark\",
        \"created\": \"$(date -Iseconds)\",
        \"quota\": {\"enabled\": false, \"limit\": 0},
        \"rate_limit\": {\"enabled\": false, \"rate\": 0},
        \"billing\": \"single\"
    }" "$TRAFFIC_DATA" > "$tmp" && mv "$tmp" "$TRAFFIC_DATA"
    
    log_info "流量监控: 已添加端口 $port${remark:+ ($remark)}"
}

# ============================================================================
# 移除端口监控 (供其他模块调用)
# ============================================================================
traffic_remove_port() {
    local port=$1
    local port_safe=$(echo "$port" | tr '-' '_')
    
    [[ ! -f "$TRAFFIC_DATA" ]] && return 0
    
    # 删除 nftables 规则
    local handles
    handles=$(nft -a list table $NFT_FAMILY $NFT_TABLE 2>/dev/null | \
              grep "port_${port_safe}_" | \
              sed -n 's/.*# handle \([0-9]\+\)$/\1/p')
    
    for handle in $handles; do
        for chain in input output; do
            nft delete rule $NFT_FAMILY $NFT_TABLE $chain handle $handle 2>/dev/null || true
        done
    done
    
    # 删除计数器
    nft delete counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null || true
    nft delete counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null || true
    
    # 删除限速规则
    traffic_remove_rate_limit "$port"
    
    # 更新配置
    local tmp="${TRAFFIC_DATA}.tmp"
    jq "del(.ports.\"$port\")" "$TRAFFIC_DATA" > "$tmp" && mv "$tmp" "$TRAFFIC_DATA"
    
    # 清除告警状态
    tmp="${TRAFFIC_ALERT_STATE}.tmp"
    jq "del(.\"$port\")" "$TRAFFIC_ALERT_STATE" > "$tmp" 2>/dev/null && mv "$tmp" "$TRAFFIC_ALERT_STATE"
    
    log_info "流量监控: 已移除端口 $port"
}

# ============================================================================
# 获取监控的端口列表
# ============================================================================
traffic_get_ports() {
    [[ -f "$TRAFFIC_DATA" ]] && jq -r '.ports | keys[]' "$TRAFFIC_DATA" 2>/dev/null | sort -n
}

# ============================================================================
# 限速功能 (TC + HTB)
# ============================================================================
traffic_get_main_interface() {
    ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1
}

traffic_set_rate_limit() {
    local port=$1
    local rate_kbps=$2
    local iface=$(traffic_get_main_interface)
    
    [[ -z "$iface" ]] && { log_error "无法获取网络接口"; return 1; }
    
    # 确保 tc 可用
    ensure_deps tc
    
    local class_id=$((port % 9999 + 1))
    local rate="${rate_kbps}kbit"
    
    # 检查并创建根 qdisc
    if ! tc qdisc show dev "$iface" | grep -q "htb 1:"; then
        tc qdisc add dev "$iface" root handle 1: htb default 9999 2>/dev/null || true
    fi
    
    # 删除旧规则
    tc class del dev "$iface" classid 1:$class_id 2>/dev/null || true
    tc filter del dev "$iface" protocol ip prio $class_id 2>/dev/null || true
    
    # 添加新规则
    tc class add dev "$iface" parent 1: classid 1:$class_id htb rate $rate ceil $rate
    tc filter add dev "$iface" protocol ip parent 1:0 prio $class_id u32 match ip sport $port 0xffff flowid 1:$class_id
    
    # 更新配置
    local tmp="${TRAFFIC_DATA}.tmp"
    jq ".ports.\"$port\".rate_limit = {\"enabled\": true, \"rate\": $rate_kbps}" "$TRAFFIC_DATA" > "$tmp" && mv "$tmp" "$TRAFFIC_DATA"
    
    log_info "已设置端口 $port 限速: ${rate_kbps}Kbps"
}

traffic_remove_rate_limit() {
    local port=$1
    local iface=$(traffic_get_main_interface)
    
    [[ -z "$iface" ]] && return 0
    
    local class_id=$((port % 9999 + 1))
    
    tc filter del dev "$iface" protocol ip prio $class_id 2>/dev/null || true
    tc class del dev "$iface" classid 1:$class_id 2>/dev/null || true
    
    # 更新配置
    local tmp="${TRAFFIC_DATA}.tmp"
    jq ".ports.\"$port\".rate_limit = {\"enabled\": false, \"rate\": 0}" "$TRAFFIC_DATA" > "$tmp" 2>/dev/null && mv "$tmp" "$TRAFFIC_DATA"
}

# ============================================================================
# 流量配额
# ============================================================================
traffic_set_quota() {
    local port=$1
    local limit_bytes=$2
    
    local tmp="${TRAFFIC_DATA}.tmp"
    jq ".ports.\"$port\".quota = {\"enabled\": true, \"limit\": $limit_bytes}" "$TRAFFIC_DATA" > "$tmp" && mv "$tmp" "$TRAFFIC_DATA"
    
    log_info "已设置端口 $port 配额: $(traffic_format_bytes $limit_bytes)"
}

traffic_check_quota() {
    local ports=($(traffic_get_ports))
    
    for port in "${ports[@]}"; do
        local quota_enabled=$(jq -r ".ports.\"$port\".quota.enabled // false" "$TRAFFIC_DATA")
        [[ "$quota_enabled" != "true" ]] && continue
        
        local limit=$(jq -r ".ports.\"$port\".quota.limit // 0" "$TRAFFIC_DATA")
        local billing=$(jq -r ".ports.\"$port\".billing // \"single\"" "$TRAFFIC_DATA")
        
        local traffic=($(traffic_get_port_bytes "$port"))
        local input=${traffic[0]}
        local output=${traffic[1]}
        local used
        
        if [[ "$billing" == "both" ]]; then
            used=$((input + output))
        else
            used=$output  # 默认单向（出站）
        fi
        
        if [[ $used -ge $limit ]]; then
            log_warn "端口 $port 超出配额，执行阻断..."
            
            # 使用 nftables 阻断
            local port_safe=$(echo "$port" | tr '-' '_')
            nft add rule $NFT_FAMILY $NFT_TABLE input tcp dport $port drop 2>/dev/null || true
            nft add rule $NFT_FAMILY $NFT_TABLE input udp dport $port drop 2>/dev/null || true
            
            # Telegram 通知
            if [[ $(config_get '.telegram.enabled' 'false') == "true" ]]; then
                local server_name=$(config_get '.telegram.server_name' "$(hostname)")
                local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$TRAFFIC_DATA")
                telegram_send "⚠️ <b>流量配额超限</b>
服务器: $server_name
端口: $port${remark:+ ($remark)}
已用: $(traffic_format_bytes $used)
配额: $(traffic_format_bytes $limit)"
            fi
        fi
    done
}

# ============================================================================
# 告警功能
# ============================================================================
traffic_check_alerts() {
    local ports=($(traffic_get_ports))
    local thresholds=(30 50 80 100)
    
    for port in "${ports[@]}"; do
        local quota_enabled=$(jq -r ".ports.\"$port\".quota.enabled // false" "$TRAFFIC_DATA")
        [[ "$quota_enabled" != "true" ]] && continue
        
        local limit=$(jq -r ".ports.\"$port\".quota.limit // 0" "$TRAFFIC_DATA")
        [[ $limit -eq 0 ]] && continue
        
        local traffic=($(traffic_get_port_bytes "$port"))
        local output=${traffic[1]}
        local percent=$((output * 100 / limit))
        
        local last_alert=$(jq -r ".\"$port\" // 0" "$TRAFFIC_ALERT_STATE")
        
        for threshold in "${thresholds[@]}"; do
            if [[ $percent -ge $threshold && $last_alert -lt $threshold ]]; then
                log_info "端口 $port 流量达到 ${threshold}%"
                
                # 更新告警状态
                local tmp="${TRAFFIC_ALERT_STATE}.tmp"
                jq ".\"$port\" = $threshold" "$TRAFFIC_ALERT_STATE" > "$tmp" && mv "$tmp" "$TRAFFIC_ALERT_STATE"
                
                # Telegram 通知
                if [[ $(config_get '.telegram.enabled' 'false') == "true" ]]; then
                    local server_name=$(config_get '.telegram.server_name' "$(hostname)")
                    local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$TRAFFIC_DATA")
                    telegram_send "📊 <b>流量告警</b>
服务器: $server_name
端口: $port${remark:+ ($remark)}
使用率: ${percent}%
已用: $(traffic_format_bytes $output)
配额: $(traffic_format_bytes $limit)"
                fi
                
                break
            fi
        done
    done
}

# ============================================================================
# 重置流量
# ============================================================================
traffic_reset_port() {
    local port=$1
    local port_safe=$(echo "$port" | tr '-' '_')
    
    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" &>/dev/null
    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" &>/dev/null
    
    # 重置告警状态
    local tmp="${TRAFFIC_ALERT_STATE}.tmp"
    jq ".\"$port\" = 0" "$TRAFFIC_ALERT_STATE" > "$tmp" 2>/dev/null && mv "$tmp" "$TRAFFIC_ALERT_STATE"
    
    # 移除阻断规则 (如果有)
    local handles
    handles=$(nft -a list table $NFT_FAMILY $NFT_TABLE 2>/dev/null | \
              grep "dport $port drop" | \
              sed -n 's/.*# handle \([0-9]\+\)$/\1/p')
    
    for handle in $handles; do
        nft delete rule $NFT_FAMILY $NFT_TABLE input handle $handle 2>/dev/null || true
    done
    
    log_info "已重置端口 $port 流量"
}

traffic_reset_all() {
    local ports=($(traffic_get_ports))
    for port in "${ports[@]}"; do
        traffic_reset_port "$port"
    done
    _green "已重置所有端口流量"
}

# ============================================================================
# 显示状态
# ============================================================================
traffic_show_status() {
    traffic_init
    
    local ports=($(traffic_get_ports))
    local total_in=0 total_out=0
    
    echo
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                     端口流量监控                                 ║"
    echo "╠══════════════════════════════════════════════════════════════════╣"
    
    if [[ ${#ports[@]} -eq 0 ]]; then
        echo "║  暂无监控端口                                                    ║"
    else
        printf "║  %-8s %-12s %-12s %-12s %-10s  ║\n" "端口" "↑上传" "↓下载" "配额" "限速"
        echo "║  ----------------------------------------------------------------  ║"
        
        for port in "${ports[@]}"; do
            local traffic=($(traffic_get_port_bytes "$port"))
            local input=${traffic[0]}
            local output=${traffic[1]}
            total_in=$((total_in + input))
            total_out=$((total_out + output))
            
            local quota_enabled=$(jq -r ".ports.\"$port\".quota.enabled // false" "$TRAFFIC_DATA")
            local quota_limit=$(jq -r ".ports.\"$port\".quota.limit // 0" "$TRAFFIC_DATA")
            local quota_str="-"
            if [[ "$quota_enabled" == "true" && $quota_limit -gt 0 ]]; then
                local percent=$((output * 100 / quota_limit))
                quota_str="[${percent}%]"
            fi
            
            local rate_enabled=$(jq -r ".ports.\"$port\".rate_limit.enabled // false" "$TRAFFIC_DATA")
            local rate_kbps=$(jq -r ".ports.\"$port\".rate_limit.rate // 0" "$TRAFFIC_DATA")
            local rate_str="-"
            if [[ "$rate_enabled" == "true" && $rate_kbps -gt 0 ]]; then
                if [[ $rate_kbps -ge 1000 ]]; then
                    rate_str="$((rate_kbps/1000))M"
                else
                    rate_str="${rate_kbps}K"
                fi
            fi
            
            printf "║  %-8s %-12s %-12s %-12s %-10s  ║\n" \
                "$port" "$(traffic_format_bytes $input)" "$(traffic_format_bytes $output)" "$quota_str" "$rate_str"
            
            local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$TRAFFIC_DATA")
            [[ -n "$remark" && "$remark" != "null" ]] && \
                printf "║    └─ %-58s  ║\n" "$remark"
        done
    fi
    
    echo "╠══════════════════════════════════════════════════════════════════╣"
    printf "║  监控: %-3d 个   上传: %-12s  下载: %-12s      ║\n" \
        "${#ports[@]}" "$(traffic_format_bytes $total_in)" "$(traffic_format_bytes $total_out)"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo
}

# ============================================================================
# 交互式操作
# ============================================================================
traffic_add_port_interactive() {
    echo
    _cyan "=== 添加端口监控 ==="
    echo
    
    read -rp "端口号: " port
    [[ -z "$port" ]] && return 0
    
    if ! is_valid_port "$port"; then
        _red "无效端口"
        return 1
    fi
    
    read -rp "备注 (可选): " remark
    
    traffic_add_port "$port" "$remark"
    _green "✓ 已添加端口 $port"
}

traffic_remove_port_interactive() {
    local ports=($(traffic_get_ports))
    
    if [[ ${#ports[@]} -eq 0 ]]; then
        _yellow "没有监控的端口"
        return 0
    fi
    
    echo
    _cyan "=== 移除端口监控 ==="
    echo
    
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$TRAFFIC_DATA")
        echo "  $((i+1)). 端口 $port${remark:+ ($remark)}"
    done
    echo "  0. 返回"
    echo
    
    read -rp "选择: " choice
    [[ -z "$choice" || "$choice" == "0" ]] && return 0
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 && $choice -le ${#ports[@]} ]]; then
        local port=${ports[$((choice-1))]}
        confirm "确认移除端口 $port?" && traffic_remove_port "$port"
    fi
}

traffic_set_quota_interactive() {
    local ports=($(traffic_get_ports))
    
    if [[ ${#ports[@]} -eq 0 ]]; then
        _yellow "没有监控的端口"
        return 0
    fi
    
    echo
    _cyan "=== 设置流量配额 ==="
    echo
    
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$TRAFFIC_DATA")
        local quota=$(jq -r ".ports.\"$port\".quota.limit // 0" "$TRAFFIC_DATA")
        local quota_str="-"
        [[ $quota -gt 0 ]] && quota_str=$(traffic_format_bytes $quota)
        echo "  $((i+1)). 端口 $port [配额: $quota_str]${remark:+ ($remark)}"
    done
    echo "  0. 返回"
    echo
    
    read -rp "选择端口: " choice
    [[ -z "$choice" || "$choice" == "0" ]] && return 0
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 && $choice -le ${#ports[@]} ]]; then
        local port=${ports[$((choice-1))]}
        echo
        echo "输入配额 (示例: 100G, 1.5T, 500M)，输入 0 取消配额"
        read -rp "配额: " quota_input
        
        [[ -z "$quota_input" ]] && return 0
        
        if [[ "$quota_input" == "0" ]]; then
            local tmp="${TRAFFIC_DATA}.tmp"
            jq ".ports.\"$port\".quota = {\"enabled\": false, \"limit\": 0}" "$TRAFFIC_DATA" > "$tmp" && mv "$tmp" "$TRAFFIC_DATA"
            _green "已取消端口 $port 配额"
        else
            local bytes=$(traffic_parse_to_bytes "$quota_input")
            traffic_set_quota "$port" "$bytes"
            _green "已设置端口 $port 配额: $(traffic_format_bytes $bytes)"
        fi
    fi
}

traffic_set_rate_limit_interactive() {
    local ports=($(traffic_get_ports))
    
    if [[ ${#ports[@]} -eq 0 ]]; then
        _yellow "没有监控的端口"
        return 0
    fi
    
    echo
    _cyan "=== 设置带宽限制 ==="
    echo
    
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$TRAFFIC_DATA")
        local rate=$(jq -r ".ports.\"$port\".rate_limit.rate // 0" "$TRAFFIC_DATA")
        local rate_str="-"
        [[ $rate -gt 0 ]] && rate_str="${rate}Kbps"
        echo "  $((i+1)). 端口 $port [限速: $rate_str]${remark:+ ($remark)}"
    done
    echo "  0. 返回"
    echo
    
    read -rp "选择端口: " choice
    [[ -z "$choice" || "$choice" == "0" ]] && return 0
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 && $choice -le ${#ports[@]} ]]; then
        local port=${ports[$((choice-1))]}
        echo
        echo "输入限速 (示例: 100 = 100Mbps, 500K, 1G)，输入 0 取消限速"
        read -rp "限速: " rate_input
        
        [[ -z "$rate_input" ]] && return 0
        
        if [[ "$rate_input" == "0" ]]; then
            traffic_remove_rate_limit "$port"
            _green "已取消端口 $port 限速"
        else
            local rate_kbps
            local number=$(echo "$rate_input" | grep -oE '^[0-9.]+')
            local unit=$(echo "$rate_input" | grep -oE '[A-Za-z]+$' | tr '[:lower:]' '[:upper:]')
            
            case $unit in
                G|GBPS) rate_kbps=$((number * 1000000)) ;;
                M|MBPS) rate_kbps=$((number * 1000)) ;;
                K|KBPS) rate_kbps=$number ;;
                *)      rate_kbps=$((number * 1000)) ;;  # 默认 Mbps
            esac
            
            traffic_set_rate_limit "$port" "$rate_kbps"
        fi
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
        
        echo "--------------------------------------------"
        echo
        echo "  1. 添加端口监控"
        echo "  2. 移除端口监控"
        echo "  3. 设置流量配额"
        echo "  4. 设置带宽限制"
        echo "  5. 重置单个端口流量"
        echo "  6. 重置所有流量"
        echo "  7. 刷新状态"
        echo
        echo "  0. 返回主菜单"
        echo
        echo "============================================"
        echo
        read -rp "请选择: " choice
        
        case $choice in
            1) traffic_add_port_interactive; pause ;;
            2) traffic_remove_port_interactive; pause ;;
            3) traffic_set_quota_interactive; pause ;;
            4) traffic_set_rate_limit_interactive; pause ;;
            5)
                local ports=($(traffic_get_ports))
                if [[ ${#ports[@]} -gt 0 ]]; then
                    echo
                    for i in "${!ports[@]}"; do
                        echo "  $((i+1)). ${ports[$i]}"
                    done
                    echo
                    read -rp "选择端口: " idx
                    if [[ "$idx" =~ ^[0-9]+$ ]] && [[ $idx -ge 1 && $idx -le ${#ports[@]} ]]; then
                        traffic_reset_port "${ports[$((idx-1))]}"
                    fi
                fi
                pause
                ;;
            6) confirm "确认重置所有流量?" && traffic_reset_all; pause ;;
            7) continue ;;
            0) return ;;
        esac
    done
}

log_debug "流量监控模块已加载"
