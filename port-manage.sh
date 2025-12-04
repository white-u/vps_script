#!/bin/bash

set -euo pipefail

# ============================================================================
# 端口流量监控脚本 v2.3.0
# 功能: 流量监控、速率限制、流量配额、阈值告警、Telegram通知、突发速率保护
# ============================================================================

readonly SCRIPT_VERSION="2.3.0"
readonly SCRIPT_NAME="端口流量监控"
readonly SCRIPT_PATH="$(realpath "$0" 2>/dev/null || echo "$0")"
readonly CONFIG_DIR="/etc/port-traffic-monitor"
readonly CONFIG_FILE="$CONFIG_DIR/config.json"
readonly TRAFFIC_DATA_FILE="$CONFIG_DIR/traffic_data.json"
readonly ALERT_STATE_FILE="$CONFIG_DIR/alert_state.json"
readonly BURST_STATE_FILE="$CONFIG_DIR/burst_state.json"      # 突发速率状态
readonly TRAFFIC_HISTORY_DIR="$CONFIG_DIR/traffic_history"    # 流量历史记录

readonly RED='\033[0;31m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly GREEN='\033[0;32m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

readonly CONNECT_TIMEOUT=10
readonly MAX_TIMEOUT=30
readonly SHORTCUT_COMMAND="ptm"
readonly ALERT_THRESHOLDS=(30 50 80 100)

# 缓存配置 (避免重复读取)
NFT_TABLE=""
NFT_FAMILY=""

# ============================================================================
# 系统检测与依赖
# ============================================================================

detect_system() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|linuxmint) echo "debian" ;;
            centos|rhel|fedora|rocky|almalinux) echo "centos" ;;
            arch|manjaro) echo "arch" ;;
            *) echo "unknown" ;;
        esac
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "centos"
    else
        echo "unknown"
    fi
}

install_missing_tools() {
    local missing_tools=("$@")
    local system_type=$(detect_system)

    echo -e "${YELLOW}检测到缺少工具: ${missing_tools[*]}${NC}"
    echo "正在自动安装..."

    case $system_type in
        "debian")
            apt-get update -qq
            for tool in "${missing_tools[@]}"; do
                case $tool in
                    "nft") apt-get install -y nftables ;;
                    "tc"|"ss") apt-get install -y iproute2 ;;
                    "jq") apt-get install -y jq ;;
                    "bc") apt-get install -y bc ;;
                    "conntrack") apt-get install -y conntrack ;;
                    "curl") apt-get install -y curl ;;
                    *) apt-get install -y "$tool" ;;
                esac
            done
            ;;
        "centos")
            yum install -y epel-release 2>/dev/null || true
            for tool in "${missing_tools[@]}"; do
                case $tool in
                    "nft") yum install -y nftables ;;
                    "tc"|"ss") yum install -y iproute ;;
                    "jq") yum install -y jq ;;
                    "bc") yum install -y bc ;;
                    "conntrack") yum install -y conntrack-tools ;;
                    "curl") yum install -y curl ;;
                    *) yum install -y "$tool" ;;
                esac
            done
            ;;
        "arch")
            for tool in "${missing_tools[@]}"; do
                case $tool in
                    "nft") pacman -S --noconfirm nftables ;;
                    "tc"|"ss") pacman -S --noconfirm iproute2 ;;
                    *) pacman -S --noconfirm "$tool" ;;
                esac
            done
            ;;
        *)
            echo -e "${RED}不支持的系统类型，请手动安装: ${missing_tools[*]}${NC}"
            exit 1
            ;;
    esac
    echo -e "${GREEN}依赖安装完成${NC}"
}

check_dependencies() {
    local missing_tools=()
    local required_tools=("nft" "tc" "ss" "jq" "bc" "curl")

    for tool in "${required_tools[@]}"; do
        command -v "$tool" >/dev/null 2>&1 || missing_tools+=("$tool")
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        install_missing_tools "${missing_tools[@]}"
    fi
}

check_root() {
    [ "$EUID" -ne 0 ] && echo -e "${RED}错误：需要 root 权限${NC}" && exit 1
}

# ============================================================================
# 配置管理
# ============================================================================

load_nft_config() {
    [ -n "$NFT_TABLE" ] && return
    NFT_TABLE=$(jq -r '.nftables.table_name // "port_monitor"' "$CONFIG_FILE" 2>/dev/null)
    NFT_FAMILY=$(jq -r '.nftables.family // "inet"' "$CONFIG_FILE" 2>/dev/null)
}

init_config() {
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$TRAFFIC_HISTORY_DIR"

    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" << 'EOF'
{
  "ports": {},
  "nftables": {"table_name": "port_monitor", "family": "inet"},
  "telegram": {"enabled": false, "bot_token": "", "chat_id": "", "server_name": "", "notify_interval": "", "alert_enabled": true}
}
EOF
    fi

    [ ! -f "$ALERT_STATE_FILE" ] && echo '{}' > "$ALERT_STATE_FILE"
    [ ! -f "$BURST_STATE_FILE" ] && echo '{}' > "$BURST_STATE_FILE"

    load_nft_config
    init_nftables
    setup_exit_hooks
    restore_monitoring_if_needed
}

init_nftables() {
    nft add table $NFT_FAMILY $NFT_TABLE 2>/dev/null || true
    nft add chain $NFT_FAMILY $NFT_TABLE input "{ type filter hook input priority 0; }" 2>/dev/null || true
    nft add chain $NFT_FAMILY $NFT_TABLE output "{ type filter hook output priority 0; }" 2>/dev/null || true
    nft add chain $NFT_FAMILY $NFT_TABLE forward "{ type filter hook forward priority 0; }" 2>/dev/null || true
}

# ============================================================================
# 工具函数
# ============================================================================

get_default_interface() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

format_bytes() {
    local bytes=${1:-0}
    [[ ! "$bytes" =~ ^[0-9]+$ ]] && bytes=0

    if [ $bytes -ge 1099511627776 ]; then
        printf "%.2fTB" "$(echo "scale=2; $bytes / 1099511627776" | bc)"
    elif [ $bytes -ge 1073741824 ]; then
        printf "%.2fGB" "$(echo "scale=2; $bytes / 1073741824" | bc)"
    elif [ $bytes -ge 1048576 ]; then
        printf "%.2fMB" "$(echo "scale=2; $bytes / 1048576" | bc)"
    elif [ $bytes -ge 1024 ]; then
        printf "%.2fKB" "$(echo "scale=2; $bytes / 1024" | bc)"
    else
        echo "${bytes}B"
    fi
}

# 格式化速率显示
format_rate() {
    local kbps=${1:-0}
    if [ $kbps -ge 1000000 ]; then
        printf "%.2fGbps" "$(echo "scale=2; $kbps / 1000000" | bc)"
    elif [ $kbps -ge 1000 ]; then
        printf "%.2fMbps" "$(echo "scale=2; $kbps / 1000" | bc)"
    else
        echo "${kbps}Kbps"
    fi
}

parse_size_to_bytes() {
    local size_str=$1
    local number=$(echo "$size_str" | grep -oE '^[0-9]+\.?[0-9]*')
    local unit=$(echo "$size_str" | grep -oE '[A-Za-z]+$' | tr '[:lower:]' '[:upper:]')
    
    [ -z "$number" ] && echo "0" && return 1
    
    local multiplier=0
    case $unit in
        "KB"|"K") multiplier=1024 ;;
        "MB"|"M") multiplier=1048576 ;;
        "GB"|"G") multiplier=1073741824 ;;
        "TB"|"T") multiplier=1099511627776 ;;
        *) echo "0" && return 1 ;;
    esac
    
    echo "scale=0; $number * $multiplier / 1" | bc
}

parse_rate_to_kbps() {
    local rate=$1
    local rate_lower=$(echo "$rate" | tr '[:upper:]' '[:lower:]')
    local number=$(echo "$rate_lower" | grep -oE '^[0-9]+')
    
    if [[ "$rate_lower" =~ kbps$ ]]; then echo "$number"
    elif [[ "$rate_lower" =~ mbps$ ]]; then echo $((number * 1000))
    elif [[ "$rate_lower" =~ gbps$ ]]; then echo $((number * 1000000))
    else echo "0"; fi
}

# 解析时间到分钟
parse_time_to_minutes() {
    local time_str=$1
    local time_lower=$(echo "$time_str" | tr '[:upper:]' '[:lower:]')
    local number=$(echo "$time_lower" | grep -oE '^[0-9]+')
    
    [ -z "$number" ] && echo "0" && return 1
    
    if [[ "$time_lower" =~ m$ ]] || [[ "$time_lower" =~ min ]]; then
        echo "$number"
    elif [[ "$time_lower" =~ h$ ]] || [[ "$time_lower" =~ hour ]]; then
        echo $((number * 60))
    else
        echo "$number"  # 默认分钟
    fi
}

get_beijing_time() { TZ='Asia/Shanghai' date "$@"; }

get_timestamp() { date +%s; }

update_config() {
    local tmp="${CONFIG_FILE}.tmp.$$"
    if jq "$1" "$CONFIG_FILE" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$CONFIG_FILE"
    else
        rm -f "$tmp"
        return 1
    fi
}

get_active_ports() {
    jq -r '.ports | keys[]' "$CONFIG_FILE" 2>/dev/null | while read -r port; do
        if [[ "$port" =~ ^[0-9]+-[0-9]+$ ]]; then
            local start=$(echo "$port" | cut -d'-' -f1)
            printf "%05d-%s\n" "$start" "$port"
        else
            printf "%05d-%s\n" "$port" "$port"
        fi
    done | sort -n | cut -d'-' -f2-
}

is_port_range() { [[ "$1" =~ ^[0-9]+-[0-9]+$ ]]; }

validate_port_range() {
    local port=$1
    if is_port_range "$port"; then
        local start=$(echo "$port" | cut -d'-' -f1)
        local end=$(echo "$port" | cut -d'-' -f2)
        [ "$start" -ge 1 ] && [ "$end" -le 65535 ] && [ "$start" -lt "$end" ]
    else
        [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
    fi
}

escape_json() {
    local str=$1
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\t'/\\t}"
    echo "$str"
}

get_port_safe() { echo "$1" | tr '-' '_'; }

# ============================================================================
# 流量数据管理
# ============================================================================

get_port_traffic() {
    local port=$1
    local port_safe=$(get_port_safe "$port")

    local input_bytes=$(nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null | grep -oE 'bytes [0-9]+' | awk '{print $2}')
    local output_bytes=$(nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null | grep -oE 'bytes [0-9]+' | awk '{print $2}')
    echo "${input_bytes:-0} ${output_bytes:-0}"
}

calculate_total_traffic() {
    local input=$1 output=$2 mode=${3:-"single"}
    [ "$mode" = "double" ] && echo $((input + output)) || echo $output
}

save_traffic_data() {
    local active_ports=($(get_active_ports 2>/dev/null || true))
    [ ${#active_ports[@]} -eq 0 ] && return 0

    local json_data="{"
    local first=true
    
    for port in "${active_ports[@]}"; do
        local traffic=($(get_port_traffic "$port"))
        if [ "${traffic[0]:-0}" -gt 0 ] || [ "${traffic[1]:-0}" -gt 0 ]; then
            [ "$first" = true ] && first=false || json_data+=","
            json_data+="\"$port\":{\"input\":${traffic[0]},\"output\":${traffic[1]},\"time\":\"$(get_beijing_time -Iseconds)\"}"
        fi
    done
    json_data+="}"
    
    [ "$json_data" != "{}" ] && echo "$json_data" > "$TRAFFIC_DATA_FILE"
}

setup_exit_hooks() {
    trap 'save_traffic_data >/dev/null 2>&1' EXIT
    trap 'save_traffic_data >/dev/null 2>&1; exit 1' INT TERM
}

restore_monitoring_if_needed() {
    local active_ports=($(get_active_ports 2>/dev/null || true))
    [ ${#active_ports[@]} -eq 0 ] && return 0

    for port in "${active_ports[@]}"; do
        local port_safe=$(get_port_safe "$port")
        if ! nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" >/dev/null 2>&1; then
            restore_traffic_from_backup
            restore_all_rules
            return
        fi
    done
}

restore_traffic_from_backup() {
    [ ! -f "$TRAFFIC_DATA_FILE" ] && return 0

    for port in $(jq -r 'keys[]' "$TRAFFIC_DATA_FILE" 2>/dev/null); do
        local input=$(jq -r ".\"$port\".input // 0" "$TRAFFIC_DATA_FILE")
        local output=$(jq -r ".\"$port\".output // 0" "$TRAFFIC_DATA_FILE")
        local port_safe=$(get_port_safe "$port")
        nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" "{ packets 0 bytes $input }" 2>/dev/null || true
        nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" "{ packets 0 bytes $output }" 2>/dev/null || true
    done
    rm -f "$TRAFFIC_DATA_FILE"
}

restore_all_rules() {
    for port in $(get_active_ports); do
        add_nftables_rules "$port"
        local quota=$(jq -r ".ports.\"$port\".quota.limit // \"unlimited\"" "$CONFIG_FILE")
        [ "$quota" != "unlimited" ] && [ "$quota" != "null" ] && apply_quota "$port" "$quota"
        
        # 检查是否处于突发限速状态
        local throttled=$(jq -r ".\"$port\".throttled // false" "$BURST_STATE_FILE" 2>/dev/null)
        if [ "$throttled" = "true" ]; then
            local throttle_rate=$(jq -r ".\"$port\".throttle_rate // \"\"" "$BURST_STATE_FILE")
            [ -n "$throttle_rate" ] && apply_tc_limit "$port" "$throttle_rate"
        else
            local rate=$(jq -r ".ports.\"$port\".bandwidth.rate // \"unlimited\"" "$CONFIG_FILE")
            [ "$rate" != "unlimited" ] && [ "$rate" != "null" ] && apply_tc_limit "$port" "$rate"
        fi
        
        setup_reset_cron "$port"
    done
}

# ============================================================================
# 流量历史记录 (用于突发速率检测)
# ============================================================================

# 记录当前流量快照
record_traffic_snapshot() {
    local port=$1
    local port_safe=$(get_port_safe "$port")
    local history_file="$TRAFFIC_HISTORY_DIR/${port_safe}.log"
    
    local traffic=($(get_port_traffic "$port"))
    local timestamp=$(get_timestamp)
    local total=$((${traffic[0]} + ${traffic[1]}))
    
    # 追加记录: timestamp total_bytes
    echo "$timestamp $total" >> "$history_file"
    
    # 只保留最近 120 条记录 (2小时，每分钟1条)
    if [ -f "$history_file" ]; then
        tail -n 120 "$history_file" > "${history_file}.tmp"
        mv "${history_file}.tmp" "$history_file"
    fi
}

# 计算指定时间窗口内的平均速率 (Kbps)
calculate_avg_rate() {
    local port=$1
    local window_minutes=$2
    local port_safe=$(get_port_safe "$port")
    local history_file="$TRAFFIC_HISTORY_DIR/${port_safe}.log"
    
    [ ! -f "$history_file" ] && echo "0" && return
    
    local now=$(get_timestamp)
    local window_start=$((now - window_minutes * 60))
    
    # 获取窗口内的第一条和最后一条记录
    local first_record=""
    local last_record=""
    
    while read -r ts bytes; do
        [ "$ts" -ge "$window_start" ] || continue
        [ -z "$first_record" ] && first_record="$ts $bytes"
        last_record="$ts $bytes"
    done < "$history_file"
    
    [ -z "$first_record" ] || [ -z "$last_record" ] && echo "0" && return
    
    local first_ts=$(echo "$first_record" | awk '{print $1}')
    local first_bytes=$(echo "$first_record" | awk '{print $2}')
    local last_ts=$(echo "$last_record" | awk '{print $1}')
    local last_bytes=$(echo "$last_record" | awk '{print $2}')
    
    local time_diff=$((last_ts - first_ts))
    [ "$time_diff" -le 0 ] && echo "0" && return
    
    local bytes_diff=$((last_bytes - first_bytes))
    [ "$bytes_diff" -lt 0 ] && bytes_diff=0  # 流量重置后可能为负
    
    # 计算 Kbps: (bytes * 8) / (seconds * 1000)
    local kbps=$(echo "scale=0; $bytes_diff * 8 / $time_diff / 1000" | bc)
    echo "${kbps:-0}"
}

# 获取最近 N 分钟内持续高速率的时长
get_high_rate_duration() {
    local port=$1
    local threshold_kbps=$2
    local port_safe=$(get_port_safe "$port")
    local history_file="$TRAFFIC_HISTORY_DIR/${port_safe}.log"
    
    [ ! -f "$history_file" ] && echo "0" && return
    
    local records=()
    while read -r ts bytes; do
        records+=("$ts:$bytes")
    done < "$history_file"
    
    local count=${#records[@]}
    [ "$count" -lt 2 ] && echo "0" && return
    
    # 从最新记录向前检查，找到连续高速率的起始点
    local high_rate_start=0
    local i=$((count - 1))
    
    while [ $i -gt 0 ]; do
        local curr_ts=$(echo "${records[$i]}" | cut -d: -f1)
        local curr_bytes=$(echo "${records[$i]}" | cut -d: -f2)
        local prev_ts=$(echo "${records[$((i-1))]}" | cut -d: -f1)
        local prev_bytes=$(echo "${records[$((i-1))]}" | cut -d: -f2)
        
        local time_diff=$((curr_ts - prev_ts))
        [ "$time_diff" -le 0 ] && break
        
        local bytes_diff=$((curr_bytes - prev_bytes))
        [ "$bytes_diff" -lt 0 ] && break
        
        local rate_kbps=$(echo "scale=0; $bytes_diff * 8 / $time_diff / 1000" | bc)
        
        if [ "$rate_kbps" -ge "$threshold_kbps" ]; then
            high_rate_start=$prev_ts
        else
            break
        fi
        
        i=$((i - 1))
    done
    
    if [ "$high_rate_start" -gt 0 ]; then
        local now=$(get_timestamp)
        local duration=$(( (now - high_rate_start) / 60 ))
        echo "$duration"
    else
        echo "0"
    fi
}

# ============================================================================
# nftables 规则管理
# ============================================================================

add_nftables_rules() {
    local port=$1
    local port_safe=$(get_port_safe "$port")

    nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" >/dev/null 2>&1 || \
        nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null || true
    nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" >/dev/null 2>&1 || \
        nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null || true

    for proto in tcp udp; do
        nft add rule $NFT_FAMILY $NFT_TABLE input $proto dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE forward $proto dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE output $proto sport $port counter name "port_${port_safe}_out" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE forward $proto sport $port counter name "port_${port_safe}_out" 2>/dev/null || true
    done
}

remove_nftables_rules() {
    local port=$1
    local port_safe=$(get_port_safe "$port")

    local deleted=0
    while [ $deleted -lt 50 ]; do
        local handle=$(nft -a list table $NFT_FAMILY $NFT_TABLE 2>/dev/null | \
            grep -E "port_${port_safe}_" | head -n1 | sed -n 's/.*# handle \([0-9]\+\)$/\1/p')
        [ -z "$handle" ] && break
        for chain in input output forward; do
            nft delete rule $NFT_FAMILY $NFT_TABLE $chain handle $handle 2>/dev/null && break
        done
        deleted=$((deleted + 1))
    done

    nft delete counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null || true
    nft delete counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null || true
}

# ============================================================================
# 配额管理
# ============================================================================

apply_quota() {
    local port=$1 limit=$2
    local port_safe=$(get_port_safe "$port")
    local billing=$(jq -r ".ports.\"$port\".billing // \"single\"" "$CONFIG_FILE")

    local quota_bytes=$(parse_size_to_bytes "$limit")
    [ "$quota_bytes" -eq 0 ] && return 1
    
    local traffic=($(get_port_traffic "$port"))
    local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
    local quota_name="port_${port_safe}_quota"

    nft add quota $NFT_FAMILY $NFT_TABLE $quota_name "{ over $quota_bytes bytes used $used bytes }" 2>/dev/null || true

    if [ "$billing" = "double" ]; then
        for proto in tcp udp; do
            nft insert rule $NFT_FAMILY $NFT_TABLE input $proto dport $port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $NFT_FAMILY $NFT_TABLE output $proto sport $port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $NFT_FAMILY $NFT_TABLE forward $proto dport $port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $NFT_FAMILY $NFT_TABLE forward $proto sport $port quota name "$quota_name" drop 2>/dev/null || true
        done
    else
        for proto in tcp udp; do
            nft insert rule $NFT_FAMILY $NFT_TABLE output $proto sport $port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $NFT_FAMILY $NFT_TABLE forward $proto sport $port quota name "$quota_name" drop 2>/dev/null || true
        done
    fi
}

remove_quota() {
    local port=$1
    local port_safe=$(get_port_safe "$port")
    local quota_name="port_${port_safe}_quota"

    local deleted=0
    while [ $deleted -lt 50 ]; do
        local handle=$(nft -a list table $NFT_FAMILY $NFT_TABLE 2>/dev/null | \
            grep "quota name \"$quota_name\"" | head -n1 | sed -n 's/.*# handle \([0-9]\+\)$/\1/p')
        [ -z "$handle" ] && break
        for chain in input output forward; do
            nft delete rule $NFT_FAMILY $NFT_TABLE $chain handle $handle 2>/dev/null && break
        done
        deleted=$((deleted + 1))
    done
    nft delete quota $NFT_FAMILY $NFT_TABLE "$quota_name" 2>/dev/null || true
}

# ============================================================================
# TC 带宽限制 (含突发速率处理 + 入站限速)
# ============================================================================

calculate_burst() {
    local rate_kbps=$1
    local burst_bytes=$(( rate_kbps * 1000 / 8 / 20 ))
    [ $burst_bytes -lt 3000 ] && burst_bytes=3000
    
    if [ $burst_bytes -ge 1048576 ]; then echo "$((burst_bytes / 1048576))m"
    elif [ $burst_bytes -ge 1024 ]; then echo "$((burst_bytes / 1024))k"
    else echo "$burst_bytes"; fi
}

get_tc_class_id() {
    local port=$1
    local hash
    
    if is_port_range "$port"; then
        local start=$(echo "$port" | cut -d'-' -f1)
        local end=$(echo "$port" | cut -d'-' -f2)
        hash=$(( (start * 65536 + end) % 0xFFF + 0x100 ))
    else
        hash=$(( port % 0xFFF + 0x100 ))
    fi
    
    printf "1:%x" $hash
}

setup_ifb() {
    local interface=$1
    
    modprobe ifb numifbs=1 2>/dev/null || true
    ip link set ifb0 up 2>/dev/null || true
    tc qdisc add dev $interface handle ffff: ingress 2>/dev/null || true
    tc filter add dev $interface parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0 2>/dev/null || true
    tc qdisc add dev ifb0 root handle 1: htb default 30 2>/dev/null || true
    tc class add dev ifb0 parent 1: classid 1:1 htb rate 10gbit 2>/dev/null || true
}

apply_tc_limit() {
    local port=$1 rate=$2
    local interface=$(get_default_interface)
    [ -z "$interface" ] && interface="eth0"

    local tc_rate rate_lower=$(echo "$rate" | tr '[:upper:]' '[:lower:]')
    if [[ "$rate_lower" =~ kbps$ ]]; then tc_rate=$(echo "$rate_lower" | sed 's/kbps$/kbit/')
    elif [[ "$rate_lower" =~ mbps$ ]]; then tc_rate=$(echo "$rate_lower" | sed 's/mbps$/mbit/')
    elif [[ "$rate_lower" =~ gbps$ ]]; then tc_rate=$(echo "$rate_lower" | sed 's/gbps$/gbit/')
    else return 1; fi

    local rate_kbps=$(parse_rate_to_kbps "$rate")
    local burst=$(calculate_burst $rate_kbps)
    local class_id=$(get_tc_class_id "$port")

    # 出站限速
    tc qdisc add dev $interface root handle 1: htb default 30 2>/dev/null || true
    tc class add dev $interface parent 1: classid 1:1 htb rate 10gbit 2>/dev/null || true
    
    tc class del dev $interface classid $class_id 2>/dev/null || true
    tc class add dev $interface parent 1:1 classid $class_id htb rate $tc_rate ceil $tc_rate burst $burst cburst $burst

    local base_prio
    if is_port_range "$port"; then
        local start=$(echo "$port" | cut -d'-' -f1)
        base_prio=$((start % 1000 + 100))
    else
        base_prio=$((port % 1000 + 100))
    fi

    for proto_num in 6 17; do
        tc filter add dev $interface protocol ip parent 1:0 prio $base_prio u32 \
            match ip protocol $proto_num 0xff match ip sport $port 0xffff flowid $class_id 2>/dev/null || true
    done

    # 入站限速 (IFB)
    setup_ifb "$interface"
    
    local ifb_class_id="1:$(printf '%x' $(( 0x${class_id#1:} + 0x1000 )))"
    
    tc class del dev ifb0 classid $ifb_class_id 2>/dev/null || true
    tc class add dev ifb0 parent 1:1 classid $ifb_class_id htb rate $tc_rate ceil $tc_rate burst $burst cburst $burst 2>/dev/null || true

    for proto_num in 6 17; do
        tc filter add dev ifb0 protocol ip parent 1:0 prio $base_prio u32 \
            match ip protocol $proto_num 0xff match ip dport $port 0xffff flowid $ifb_class_id 2>/dev/null || true
    done
}

remove_tc_limit() {
    local port=$1
    local interface=$(get_default_interface)
    [ -z "$interface" ] && interface="eth0"

    local class_id=$(get_tc_class_id "$port")
    
    local base_prio
    if is_port_range "$port"; then
        local start=$(echo "$port" | cut -d'-' -f1)
        base_prio=$((start % 1000 + 100))
    else
        base_prio=$((port % 1000 + 100))
    fi

    for proto_num in 6 17; do
        tc filter del dev $interface protocol ip parent 1:0 prio $base_prio u32 \
            match ip protocol $proto_num 0xff match ip sport $port 0xffff 2>/dev/null || true
    done
    tc class del dev $interface classid $class_id 2>/dev/null || true

    local ifb_class_id="1:$(printf '%x' $(( 0x${class_id#1:} + 0x1000 )))"
    
    for proto_num in 6 17; do
        tc filter del dev ifb0 protocol ip parent 1:0 prio $base_prio u32 \
            match ip protocol $proto_num 0xff match ip dport $port 0xffff 2>/dev/null || true
    done
    tc class del dev ifb0 classid $ifb_class_id 2>/dev/null || true
}

# ============================================================================
# 突发速率保护
# ============================================================================

# 检查并执行突发速率保护
check_burst_protection() {
    local ports=($(get_active_ports))
    
    for port in "${ports[@]}"; do
        # 检查是否启用了突发保护
        local burst_enabled=$(jq -r ".ports.\"$port\".burst_protection.enabled // false" "$CONFIG_FILE")
        [ "$burst_enabled" != "true" ] && continue
        
        # 获取配置
        local burst_rate=$(jq -r ".ports.\"$port\".burst_protection.burst_rate // \"\"" "$CONFIG_FILE")
        local burst_window=$(jq -r ".ports.\"$port\".burst_protection.burst_window // 30" "$CONFIG_FILE")
        local throttle_rate=$(jq -r ".ports.\"$port\".burst_protection.throttle_rate // \"\"" "$CONFIG_FILE")
        local throttle_duration=$(jq -r ".ports.\"$port\".burst_protection.throttle_duration // 60" "$CONFIG_FILE")
        
        [ -z "$burst_rate" ] || [ -z "$throttle_rate" ] && continue
        
        local burst_rate_kbps=$(parse_rate_to_kbps "$burst_rate")
        
        # 记录流量快照
        record_traffic_snapshot "$port"
        
        # 检查当前状态
        local throttled=$(jq -r ".\"$port\".throttled // false" "$BURST_STATE_FILE" 2>/dev/null)
        local throttle_start=$(jq -r ".\"$port\".throttle_start // 0" "$BURST_STATE_FILE" 2>/dev/null)
        
        if [ "$throttled" = "true" ]; then
            # 已经在限速状态，检查是否该解除
            local now=$(get_timestamp)
            local elapsed=$(( (now - throttle_start) / 60 ))
            
            if [ "$elapsed" -ge "$throttle_duration" ]; then
                # 解除限速
                release_burst_throttle "$port"
            fi
        else
            # 正常状态，检查是否需要触发限速
            local high_duration=$(get_high_rate_duration "$port" "$burst_rate_kbps")
            
            if [ "$high_duration" -ge "$burst_window" ]; then
                # 触发限速
                apply_burst_throttle "$port" "$throttle_rate"
            fi
        fi
    done
}

# 应用突发限速
apply_burst_throttle() {
    local port=$1
    local throttle_rate=$2
    
    # 移除现有限速并应用新限速
    remove_tc_limit "$port"
    apply_tc_limit "$port" "$throttle_rate"
    
    # 更新状态
    local now=$(get_timestamp)
    local tmp="${BURST_STATE_FILE}.tmp.$$"
    jq ".\"$port\" = {\"throttled\": true, \"throttle_start\": $now, \"throttle_rate\": \"$throttle_rate\"}" \
        "$BURST_STATE_FILE" > "$tmp" && mv "$tmp" "$BURST_STATE_FILE"
    
    # 发送通知
    send_burst_throttle_alert "$port" "$throttle_rate" "triggered"
}

# 解除突发限速
release_burst_throttle() {
    local port=$1
    
    # 恢复原始限速
    remove_tc_limit "$port"
    local original_rate=$(jq -r ".ports.\"$port\".bandwidth.rate // \"unlimited\"" "$CONFIG_FILE")
    [ "$original_rate" != "unlimited" ] && [ "$original_rate" != "null" ] && apply_tc_limit "$port" "$original_rate"
    
    # 更新状态
    local tmp="${BURST_STATE_FILE}.tmp.$$"
    jq "del(.\"$port\")" "$BURST_STATE_FILE" > "$tmp" && mv "$tmp" "$BURST_STATE_FILE"
    
    # 清除历史记录
    local port_safe=$(get_port_safe "$port")
    rm -f "$TRAFFIC_HISTORY_DIR/${port_safe}.log"
    
    # 发送通知
    send_burst_throttle_alert "$port" "" "released"
}

# 发送突发限速通知
send_burst_throttle_alert() {
    local port=$1
    local throttle_rate=$2
    local action=$3  # triggered 或 released
    
    local telegram_enabled=$(jq -r '.telegram.enabled' "$CONFIG_FILE")
    [ "$telegram_enabled" != "true" ] && return
    
    local server_name=$(jq -r '.telegram.server_name // ""' "$CONFIG_FILE")
    [ -z "$server_name" ] || [ "$server_name" = "null" ] && server_name=$(hostname)
    
    local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
    local remark_display=""
    [ -n "$remark" ] && [ "$remark" != "null" ] && [ "$remark" != "" ] && remark_display=" ($remark)"
    
    local message
    if [ "$action" = "triggered" ]; then
        local burst_rate=$(jq -r ".ports.\"$port\".burst_protection.burst_rate // \"\"" "$CONFIG_FILE")
        local burst_window=$(jq -r ".ports.\"$port\".burst_protection.burst_window // 30" "$CONFIG_FILE")
        local throttle_duration=$(jq -r ".ports.\"$port\".burst_protection.throttle_duration // 60" "$CONFIG_FILE")
        
        message="🚨 <b>突发速率保护触发</b>
━━━━━━━━━━━━━━━━
🖥 服务器: ${server_name}
📌 端口: ${port}${remark_display}
⚡ 触发条件: 持续 ${burst_window} 分钟超过 ${burst_rate}
🔽 已限速至: <b>${throttle_rate}</b>
⏱ 限速时长: ${throttle_duration} 分钟
⏰ $(get_beijing_time '+%Y-%m-%d %H:%M:%S')"
    else
        message="✅ <b>突发速率保护解除</b>
━━━━━━━━━━━━━━━━
🖥 服务器: ${server_name}
📌 端口: ${port}${remark_display}
📊 已恢复正常速率
⏰ $(get_beijing_time '+%Y-%m-%d %H:%M:%S')"
    fi
    
    telegram_send "$message"
}

# 获取端口突发保护状态
get_burst_status() {
    local port=$1
    
    local enabled=$(jq -r ".ports.\"$port\".burst_protection.enabled // false" "$CONFIG_FILE")
    [ "$enabled" != "true" ] && echo "disabled" && return
    
    local throttled=$(jq -r ".\"$port\".throttled // false" "$BURST_STATE_FILE" 2>/dev/null)
    
    if [ "$throttled" = "true" ]; then
        local throttle_start=$(jq -r ".\"$port\".throttle_start // 0" "$BURST_STATE_FILE")
        local throttle_duration=$(jq -r ".ports.\"$port\".burst_protection.throttle_duration // 60" "$CONFIG_FILE")
        local now=$(get_timestamp)
        local elapsed=$(( (now - throttle_start) / 60 ))
        local remaining=$((throttle_duration - elapsed))
        [ $remaining -lt 0 ] && remaining=0
        echo "throttled:${remaining}m"
    else
        echo "normal"
    fi
}

# ============================================================================
# 定时任务管理
# ============================================================================

setup_reset_cron() {
    local port=$1
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "端口流量监控重置$port\$" > "$temp_cron" || true

    local reset_day=$(jq -r ".ports.\"$port\".quota.reset_day // null" "$CONFIG_FILE")
    local limit=$(jq -r ".ports.\"$port\".quota.limit // \"unlimited\"" "$CONFIG_FILE")

    if [ "$reset_day" != "null" ] && [ "$limit" != "unlimited" ] && [ "$limit" != "null" ]; then
        echo "5 0 $reset_day * * $SCRIPT_PATH --reset $port >/dev/null 2>&1  # 端口流量监控重置$port" >> "$temp_cron"
    fi
    crontab "$temp_cron" 2>/dev/null
    rm -f "$temp_cron"
}

remove_reset_cron() {
    local port=$1
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "端口流量监控重置$port\$" > "$temp_cron" || true
    crontab "$temp_cron" 2>/dev/null
    rm -f "$temp_cron"
}

setup_notify_cron() {
    local interval=$1
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "端口流量监控状态通知" | grep -v "端口流量监控阈值检查" | grep -v "端口流量监控突发检测" > "$temp_cron" || true

    # 状态通知
    if [ -n "$interval" ] && [ "$interval" != "0" ] && [ "$interval" != "" ]; then
        case "$interval" in
            "1m")  echo "* * * * * $SCRIPT_PATH --notify >/dev/null 2>&1  # 端口流量监控状态通知" >> "$temp_cron" ;;
            "5m")  echo "*/5 * * * * $SCRIPT_PATH --notify >/dev/null 2>&1  # 端口流量监控状态通知" >> "$temp_cron" ;;
            "15m") echo "*/15 * * * * $SCRIPT_PATH --notify >/dev/null 2>&1  # 端口流量监控状态通知" >> "$temp_cron" ;;
            "30m") echo "*/30 * * * * $SCRIPT_PATH --notify >/dev/null 2>&1  # 端口流量监控状态通知" >> "$temp_cron" ;;
            "1h")  echo "0 * * * * $SCRIPT_PATH --notify >/dev/null 2>&1  # 端口流量监控状态通知" >> "$temp_cron" ;;
            "2h")  echo "0 */2 * * * $SCRIPT_PATH --notify >/dev/null 2>&1  # 端口流量监控状态通知" >> "$temp_cron" ;;
            "6h")  echo "0 */6 * * * $SCRIPT_PATH --notify >/dev/null 2>&1  # 端口流量监控状态通知" >> "$temp_cron" ;;
            "12h") echo "0 */12 * * * $SCRIPT_PATH --notify >/dev/null 2>&1  # 端口流量监控状态通知" >> "$temp_cron" ;;
            "24h") echo "0 8 * * * $SCRIPT_PATH --notify >/dev/null 2>&1  # 端口流量监控状态通知" >> "$temp_cron" ;;
        esac
    fi

    # 阈值检查
    local alert_enabled=$(jq -r '.telegram.alert_enabled // true' "$CONFIG_FILE")
    [ "$alert_enabled" = "true" ] && echo "*/5 * * * * $SCRIPT_PATH --check-alert >/dev/null 2>&1  # 端口流量监控阈值检查" >> "$temp_cron"

    # 突发速率检测 (每分钟)
    local has_burst=false
    for port in $(get_active_ports); do
        local burst_enabled=$(jq -r ".ports.\"$port\".burst_protection.enabled // false" "$CONFIG_FILE")
        [ "$burst_enabled" = "true" ] && has_burst=true && break
    done
    [ "$has_burst" = "true" ] && echo "* * * * * $SCRIPT_PATH --check-burst >/dev/null 2>&1  # 端口流量监控突发检测" >> "$temp_cron"

    crontab "$temp_cron" 2>/dev/null
    rm -f "$temp_cron"
}

remove_notify_cron() {
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "端口流量监控状态通知" | grep -v "端口流量监控阈值检查" | grep -v "端口流量监控突发检测" > "$temp_cron" || true
    crontab "$temp_cron" 2>/dev/null
    rm -f "$temp_cron"
}

reset_port_traffic() {
    local port=$1
    local port_safe=$(get_port_safe "$port")

    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" >/dev/null 2>&1 || true
    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" >/dev/null 2>&1 || true
    nft reset quota $NFT_FAMILY $NFT_TABLE "port_${port_safe}_quota" >/dev/null 2>&1 || true

    local tmp="${ALERT_STATE_FILE}.tmp.$$"
    jq "del(.\"$port\")" "$ALERT_STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$ALERT_STATE_FILE" || rm -f "$tmp"
    
    # 清除流量历史
    rm -f "$TRAFFIC_HISTORY_DIR/${port_safe}.log"
}

# ============================================================================
# Telegram 通知
# ============================================================================

telegram_send() {
    local message=$1
    local bot_token=$(jq -r '.telegram.bot_token' "$CONFIG_FILE")
    local chat_id=$(jq -r '.telegram.chat_id' "$CONFIG_FILE")

    [ -z "$bot_token" ] || [ "$bot_token" = "null" ] && return 1
    [ -z "$chat_id" ] || [ "$chat_id" = "null" ] && return 1

    curl -s --connect-timeout $CONNECT_TIMEOUT --max-time $MAX_TIMEOUT \
        "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -d "chat_id=${chat_id}" -d "text=${message}" -d "parse_mode=HTML" >/dev/null 2>&1
}

telegram_test() {
    local bot_token=$1 chat_id=$2
    local result=$(curl -s --connect-timeout $CONNECT_TIMEOUT --max-time $MAX_TIMEOUT \
        "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -d "chat_id=${chat_id}" -d "text=🔔 端口流量监控测试消息 - $(get_beijing_time '+%Y-%m-%d %H:%M:%S')" 2>&1)
    echo "$result" | grep -q '"ok":true'
}

format_status_message() {
    local server_name=$(jq -r '.telegram.server_name // ""' "$CONFIG_FILE")
    [ -z "$server_name" ] || [ "$server_name" = "null" ] && server_name=$(hostname)

    local timestamp=$(get_beijing_time '+%Y-%m-%d %H:%M:%S')
    local ports=($(get_active_ports))
    local total=0 port_info=""

    for port in "${ports[@]}"; do
        local traffic=($(get_port_traffic "$port"))
        local billing=$(jq -r ".ports.\"$port\".billing // \"single\"" "$CONFIG_FILE")
        local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
        total=$((total + used))

        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
        local limit=$(jq -r ".ports.\"$port\".quota.limit // \"unlimited\"" "$CONFIG_FILE")
        
        local remark_display="" percent_display="" burst_display=""
        [ -n "$remark" ] && [ "$remark" != "null" ] && [ "$remark" != "" ] && remark_display=" ($remark)"

        if [ "$limit" != "unlimited" ] && [ "$limit" != "null" ]; then
            local limit_bytes=$(parse_size_to_bytes "$limit")
            [ "$limit_bytes" -gt 0 ] && percent_display=" [$(( used * 100 / limit_bytes ))%]"
        fi
        
        # 突发保护状态
        local burst_status=$(get_burst_status "$port")
        case "$burst_status" in
            throttled:*) burst_display=" 🔽限速中" ;;
            normal) burst_display=" ⚡保护中" ;;
        esac

        port_info+="
📌 端口 ${port}${remark_display}${percent_display}${burst_display}
   ├ 入站: $(format_bytes ${traffic[0]})
   ├ 出站: $(format_bytes ${traffic[1]})
   └ 总计: $(format_bytes $used)"
    done

    echo "🔔 <b>端口流量监控状态</b>
━━━━━━━━━━━━━━━━
⏰ ${timestamp}
🖥 ${server_name}
📊 监控端口: ${#ports[@]} 个
💾 总流量: $(format_bytes $total)
━━━━━━━━━━━━━━━━${port_info}"
}

# ============================================================================
# 阈值告警
# ============================================================================

check_and_send_alerts() {
    local telegram_enabled=$(jq -r '.telegram.enabled' "$CONFIG_FILE")
    local alert_enabled=$(jq -r '.telegram.alert_enabled // true' "$CONFIG_FILE")

    [ "$telegram_enabled" != "true" ] || [ "$alert_enabled" != "true" ] && return 0

    local ports=($(get_active_ports))
    
    for port in "${ports[@]}"; do
        local limit=$(jq -r ".ports.\"$port\".quota.limit // \"unlimited\"" "$CONFIG_FILE")
        [ "$limit" = "unlimited" ] || [ "$limit" = "null" ] && continue

        local limit_bytes=$(parse_size_to_bytes "$limit")
        [ "$limit_bytes" -eq 0 ] && continue

        local traffic=($(get_port_traffic "$port"))
        local billing=$(jq -r ".ports.\"$port\".billing // \"single\"" "$CONFIG_FILE")
        local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
        local percent=$((used * 100 / limit_bytes))

        local sent_threshold=$(jq -r ".\"$port\" // 0" "$ALERT_STATE_FILE" 2>/dev/null)
        [ "$sent_threshold" = "null" ] && sent_threshold=0

        for threshold in "${ALERT_THRESHOLDS[@]}"; do
            if [ $percent -ge $threshold ] && [ $sent_threshold -lt $threshold ]; then
                send_threshold_alert "$port" "$percent" "$threshold" "$used" "$limit"
                local tmp="${ALERT_STATE_FILE}.tmp.$$"
                jq ".\"$port\" = $threshold" "$ALERT_STATE_FILE" > "$tmp" && mv "$tmp" "$ALERT_STATE_FILE"
                break
            fi
        done
    done
}

send_threshold_alert() {
    local port=$1 percent=$2 threshold=$3 used=$4 limit=$5

    local server_name=$(jq -r '.telegram.server_name // ""' "$CONFIG_FILE")
    [ -z "$server_name" ] || [ "$server_name" = "null" ] && server_name=$(hostname)

    local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
    local remark_display=""
    [ -n "$remark" ] && [ "$remark" != "null" ] && [ "$remark" != "" ] && remark_display=" ($remark)"

    local icon="⚠️"
    [ $threshold -ge 80 ] && icon="🔴"
    [ $threshold -ge 100 ] && icon="🚫"

    local message="${icon} <b>流量告警 - ${threshold}%</b>
━━━━━━━━━━━━━━━━
🖥 服务器: ${server_name}
📌 端口: ${port}${remark_display}
📊 使用率: <b>${percent}%</b>
💾 已用: $(format_bytes $used)
📦 配额: $limit
⏰ $(get_beijing_time '+%Y-%m-%d %H:%M:%S')"

    [ $threshold -ge 100 ] && message+="
━━━━━━━━━━━━━━━━
⚠️ <b>流量已超限，连接已被阻断！</b>"

    telegram_send "$message"
}

# ============================================================================
# 端口管理
# ============================================================================

add_port() {
    echo -e "${CYAN}=== 添加端口监控 ===${NC}"
    echo

    local system_ports="20|21|22|23|25|53|67|68|80|110|143|443|465|587|993|995|3306|5432|6379"
    echo -e "${GREEN}当前系统监听端口 (已过滤常用端口):${NC}"
    local ports_list=$(ss -tulnp 2>/dev/null | grep -E "LISTEN|UNCONN" | awk '{print $5}' | \
        grep -oE '[0-9]+$' | sort -nu | grep -vE "^($system_ports)$" | head -20 | tr '\n' ' ')
    [ -n "$ports_list" ] && echo "$ports_list" || echo -e "${YELLOW}无可用端口${NC}"
    echo

    read -p "请输入端口号 (多个用逗号分隔, 支持范围如 8000-8010): " port_input
    [ -z "$port_input" ] && return

    local ports=()
    IFS=',' read -ra parts <<< "$port_input"
    for part in "${parts[@]}"; do
        part=$(echo "$part" | tr -d ' ')
        if validate_port_range "$part"; then
            ports+=("$part")
        else
            echo -e "${RED}无效端口: $part${NC}"
        fi
    done
    [ ${#ports[@]} -eq 0 ] && return

    echo -e "\n计费模式:\n  1. 单向 (只计出站流量)\n  2. 双向 (入站+出站)"
    read -p "选择 [1]: " billing_choice
    local billing="single"
    [ "$billing_choice" = "2" ] && billing="double"

    echo
    read -p "流量配额 (如 100GB, 1.5TB, 留空无限制): " quota_input
    local quota="unlimited" reset_day="null"
    if [ -n "$quota_input" ]; then
        if parse_size_to_bytes "$quota_input" >/dev/null 2>&1; then
            quota="$quota_input"
            read -p "每月重置日 (1-31, 留空默认1日, 0=不重置): " reset_input
            if [ -z "$reset_input" ]; then
                reset_day=1
            elif [ "$reset_input" != "0" ]; then
                reset_day="$reset_input"
            fi
        else
            echo -e "${RED}无效的配额格式，使用无限制${NC}"
        fi
    fi

    read -p "带宽限制 (如 100Mbps, 留空无限制): " rate_input
    local rate="unlimited"
    [ -n "$rate_input" ] && rate="$rate_input"

    read -p "备注 (可选): " remark
    remark=$(escape_json "$remark")

    for port in "${ports[@]}"; do
        if jq -e ".ports.\"$port\"" "$CONFIG_FILE" >/dev/null 2>&1; then
            echo -e "${YELLOW}端口 $port 已存在，跳过${NC}"
            continue
        fi

        local config="{\"billing\": \"$billing\", \"quota\": {\"limit\": \"$quota\", \"reset_day\": $reset_day}, \"bandwidth\": {\"rate\": \"$rate\"}, \"remark\": \"$remark\", \"created\": \"$(get_beijing_time -Iseconds)\"}"

        update_config ".ports.\"$port\" = $config"
        add_nftables_rules "$port"
        [ "$quota" != "unlimited" ] && apply_quota "$port" "$quota"
        [ "$rate" != "unlimited" ] && apply_tc_limit "$port" "$rate"
        [ "$reset_day" != "null" ] && setup_reset_cron "$port"

        echo -e "${GREEN}✓ 端口 $port 添加成功${NC}"
    done
    sleep 1
}

remove_port() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && sleep 1 && return

    echo -e "${CYAN}=== 删除端口监控 ===${NC}\n"
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
        local remark_display=""
        [ -n "$remark" ] && [ "$remark" != "null" ] && [ "$remark" != "" ] && remark_display=" ($remark)"
        echo "  $((i+1)). 端口 $port$remark_display"
    done
    echo

    read -p "选择要删除的端口 (多个用逗号分隔): " choice
    [ -z "$choice" ] && return

    IFS=',' read -ra selections <<< "$choice"
    for sel in "${selections[@]}"; do
        sel=$(echo "$sel" | tr -d ' ')
        [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && continue

        local port=${ports[$((sel-1))]}
        read -p "确认删除端口 $port? [y/N]: " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && continue

        remove_nftables_rules "$port"
        remove_quota "$port"
        remove_tc_limit "$port"
        remove_reset_cron "$port"
        update_config "del(.ports.\"$port\")"

        local tmp="${ALERT_STATE_FILE}.tmp.$$"
        jq "del(.\"$port\")" "$ALERT_STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$ALERT_STATE_FILE" || rm -f "$tmp"
        
        tmp="${BURST_STATE_FILE}.tmp.$$"
        jq "del(.\"$port\")" "$BURST_STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$BURST_STATE_FILE" || rm -f "$tmp"
        
        local port_safe=$(get_port_safe "$port")
        rm -f "$TRAFFIC_HISTORY_DIR/${port_safe}.log"

        if command -v conntrack >/dev/null 2>&1; then
            conntrack -D -p tcp --dport $port 2>/dev/null || true
            conntrack -D -p udp --dport $port 2>/dev/null || true
        fi

        echo -e "${GREEN}✓ 端口 $port 已删除${NC}"
    done
    
    # 更新 cron (可能需要移除突发检测)
    setup_notify_cron "$(jq -r '.telegram.notify_interval // ""' "$CONFIG_FILE")"
    sleep 1
}

set_bandwidth() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && sleep 1 && return

    echo -e "${CYAN}=== 设置带宽限制 ===${NC}\n"
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local rate=$(jq -r ".ports.\"$port\".bandwidth.rate // \"unlimited\"" "$CONFIG_FILE")
        local burst_status=$(get_burst_status "$port")
        local status_display=""
        [ "$burst_status" != "disabled" ] && status_display=" [突发保护]"
        echo "  $((i+1)). 端口 $port [当前: $rate]$status_display"
    done
    echo

    read -p "选择端口: " sel
    [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && return

    local port=${ports[$((sel-1))]}
    echo -e "\n示例: 100Mbps, 1Gbps, 500Kbps (同时限制入站和出站)"
    read -p "带宽限制 (0=取消): " rate

    if [ "$rate" = "0" ] || [ -z "$rate" ]; then
        remove_tc_limit "$port"
        update_config ".ports.\"$port\".bandwidth.rate = \"unlimited\""
        echo -e "${GREEN}✓ 已取消带宽限制${NC}"
    else
        # 检查是否在突发限速状态
        local throttled=$(jq -r ".\"$port\".throttled // false" "$BURST_STATE_FILE" 2>/dev/null)
        if [ "$throttled" = "true" ]; then
            echo -e "${YELLOW}注意: 端口当前处于突发限速状态，新限速将在限速解除后生效${NC}"
        else
            remove_tc_limit "$port"
            if apply_tc_limit "$port" "$rate"; then
                echo -e "${GREEN}✓ 带宽限制设置为 $rate${NC}"
            else
                echo -e "${RED}✗ 无效的速率格式${NC}"
                sleep 1
                return
            fi
        fi
        update_config ".ports.\"$port\".bandwidth.rate = \"$rate\""
    fi
    sleep 1
}

set_quota() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && sleep 1 && return

    echo -e "${CYAN}=== 设置流量配额 ===${NC}\n"
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local limit=$(jq -r ".ports.\"$port\".quota.limit // \"unlimited\"" "$CONFIG_FILE")
        local traffic=($(get_port_traffic "$port"))
        local billing=$(jq -r ".ports.\"$port\".billing // \"single\"" "$CONFIG_FILE")
        local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
        echo "  $((i+1)). 端口 $port [配额: $limit, 已用: $(format_bytes $used)]"
    done
    echo

    read -p "选择端口: " sel
    [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && return

    local port=${ports[$((sel-1))]}
    echo -e "\n示例: 100GB, 1.5TB, 500MB"
    read -p "流量配额 (0=取消): " limit

    if [ "$limit" = "0" ] || [ -z "$limit" ]; then
        remove_quota "$port"
        remove_reset_cron "$port"
        update_config ".ports.\"$port\".quota.limit = \"unlimited\" | del(.ports.\"$port\".quota.reset_day)"
        local tmp="${ALERT_STATE_FILE}.tmp.$$"
        jq "del(.\"$port\")" "$ALERT_STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$ALERT_STATE_FILE" || rm -f "$tmp"
        echo -e "${GREEN}✓ 已取消流量配额${NC}"
    else
        if ! parse_size_to_bytes "$limit" >/dev/null 2>&1 || [ "$(parse_size_to_bytes "$limit")" -eq 0 ]; then
            echo -e "${RED}✗ 无效的配额格式${NC}"
            sleep 1
            return
        fi

        read -p "每月重置日 (1-31, 留空默认1日, 0=不重置): " reset_day
        [ -z "$reset_day" ] && reset_day="1"

        remove_quota "$port"
        apply_quota "$port" "$limit"

        if [ "$reset_day" != "0" ]; then
            update_config ".ports.\"$port\".quota.limit = \"$limit\" | .ports.\"$port\".quota.reset_day = $reset_day"
            setup_reset_cron "$port"
            echo -e "${GREEN}✓ 配额 $limit, 每月 ${reset_day} 日重置${NC}"
        else
            update_config ".ports.\"$port\".quota.limit = \"$limit\" | del(.ports.\"$port\".quota.reset_day)"
            remove_reset_cron "$port"
            echo -e "${GREEN}✓ 配额 $limit, 不自动重置${NC}"
        fi

        local tmp="${ALERT_STATE_FILE}.tmp.$$"
        jq "del(.\"$port\")" "$ALERT_STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$ALERT_STATE_FILE" || rm -f "$tmp"
    fi
    sleep 1
}

reset_traffic() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && sleep 1 && return

    echo -e "${CYAN}=== 重置流量统计 ===${NC}\n"
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local traffic=($(get_port_traffic "$port"))
        local billing=$(jq -r ".ports.\"$port\".billing // \"single\"" "$CONFIG_FILE")
        local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
        echo "  $((i+1)). 端口 $port [$(format_bytes $used)]"
    done
    echo "  0. 全部重置"
    echo

    read -p "选择端口: " sel

    if [ "$sel" = "0" ]; then
        read -p "确认重置所有端口? [y/N]: " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && return
        for port in "${ports[@]}"; do reset_port_traffic "$port"; done
        echo -e "${GREEN}✓ 已重置所有端口${NC}"
    elif [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#ports[@]} ]; then
        local port=${ports[$((sel-1))]}
        read -p "确认重置端口 $port? [y/N]: " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && return
        reset_port_traffic "$port"
        echo -e "${GREEN}✓ 已重置端口 $port${NC}"
    fi
    sleep 1
}

set_remark() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && sleep 1 && return

    echo -e "${CYAN}=== 修改端口备注 ===${NC}\n"
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
        local remark_display="(无)"
        [ -n "$remark" ] && [ "$remark" != "null" ] && [ "$remark" != "" ] && remark_display="$remark"
        echo "  $((i+1)). 端口 $port [备注: $remark_display]"
    done
    echo

    read -p "选择端口: " sel
    [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && return

    local port=${ports[$((sel-1))]}
    read -p "新备注 (留空清除): " new_remark
    new_remark=$(escape_json "$new_remark")

    update_config ".ports.\"$port\".remark = \"$new_remark\""
    echo -e "${GREEN}✓ 备注已更新${NC}"
    sleep 1
}

# ============================================================================
# 突发速率保护设置
# ============================================================================

setup_burst_protection() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && sleep 1 && return

    echo -e "${CYAN}=== 突发速率保护设置 ===${NC}\n"
    echo -e "${YELLOW}功能说明: 当端口持续高速率超过指定时间后，自动限速${NC}"
    echo
    
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local enabled=$(jq -r ".ports.\"$port\".burst_protection.enabled // false" "$CONFIG_FILE")
        local status_display="未启用"
        
        if [ "$enabled" = "true" ]; then
            local burst_rate=$(jq -r ".ports.\"$port\".burst_protection.burst_rate // \"\"" "$CONFIG_FILE")
            local burst_window=$(jq -r ".ports.\"$port\".burst_protection.burst_window // 30" "$CONFIG_FILE")
            local throttle_rate=$(jq -r ".ports.\"$port\".burst_protection.throttle_rate // \"\"" "$CONFIG_FILE")
            local burst_status=$(get_burst_status "$port")
            
            status_display="${GREEN}已启用${NC} (>${burst_rate}持续${burst_window}分钟→${throttle_rate})"
            [ "$burst_status" != "normal" ] && [ "$burst_status" != "disabled" ] && status_display+=" ${RED}[限速中]${NC}"
        fi
        
        echo -e "  $((i+1)). 端口 $port [$status_display]"
    done
    echo

    read -p "选择端口: " sel
    [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && return

    local port=${ports[$((sel-1))]}
    local enabled=$(jq -r ".ports.\"$port\".burst_protection.enabled // false" "$CONFIG_FILE")
    
    echo
    if [ "$enabled" = "true" ]; then
        echo "当前配置:"
        echo "  突发阈值: $(jq -r ".ports.\"$port\".burst_protection.burst_rate" "$CONFIG_FILE")"
        echo "  持续时间: $(jq -r ".ports.\"$port\".burst_protection.burst_window" "$CONFIG_FILE") 分钟"
        echo "  限速至: $(jq -r ".ports.\"$port\".burst_protection.throttle_rate" "$CONFIG_FILE")"
        echo "  限速时长: $(jq -r ".ports.\"$port\".burst_protection.throttle_duration" "$CONFIG_FILE") 分钟"
        echo
        echo "1. 修改配置"
        echo "2. 禁用保护"
        echo "3. 手动解除当前限速"
        echo "0. 返回"
        read -p "选择: " action
        
        case $action in
            1) configure_burst_protection "$port" ;;
            2)
                update_config ".ports.\"$port\".burst_protection.enabled = false"
                # 解除限速
                local throttled=$(jq -r ".\"$port\".throttled // false" "$BURST_STATE_FILE" 2>/dev/null)
                if [ "$throttled" = "true" ]; then
                    release_burst_throttle "$port"
                fi
                setup_notify_cron "$(jq -r '.telegram.notify_interval // ""' "$CONFIG_FILE")"
                echo -e "${GREEN}✓ 已禁用突发保护${NC}"
                ;;
            3)
                local throttled=$(jq -r ".\"$port\".throttled // false" "$BURST_STATE_FILE" 2>/dev/null)
                if [ "$throttled" = "true" ]; then
                    release_burst_throttle "$port"
                    echo -e "${GREEN}✓ 已解除限速${NC}"
                else
                    echo -e "${YELLOW}端口未处于限速状态${NC}"
                fi
                ;;
        esac
    else
        echo "1. 启用突发保护"
        echo "0. 返回"
        read -p "选择: " action
        
        [ "$action" = "1" ] && configure_burst_protection "$port"
    fi
    sleep 1
}

configure_burst_protection() {
    local port=$1
    
    echo
    echo -e "${CYAN}配置突发速率保护${NC}"
    echo -e "${YELLOW}示例: 当速率持续30分钟超过100Mbps时，自动限速到10Mbps，持续60分钟${NC}"
    echo
    
    # 突发阈值
    local current_burst=$(jq -r ".ports.\"$port\".burst_protection.burst_rate // \"100Mbps\"" "$CONFIG_FILE")
    read -p "突发阈值 (如 100Mbps, 默认 $current_burst): " burst_rate
    [ -z "$burst_rate" ] && burst_rate="$current_burst"
    
    if [ "$(parse_rate_to_kbps "$burst_rate")" -eq 0 ]; then
        echo -e "${RED}无效的速率格式${NC}"
        return
    fi
    
    # 持续时间
    local current_window=$(jq -r ".ports.\"$port\".burst_protection.burst_window // 30" "$CONFIG_FILE")
    read -p "持续时间 (分钟, 默认 $current_window): " burst_window
    [ -z "$burst_window" ] && burst_window="$current_window"
    [[ ! "$burst_window" =~ ^[0-9]+$ ]] && burst_window=30
    
    # 限速值
    local current_throttle=$(jq -r ".ports.\"$port\".burst_protection.throttle_rate // \"10Mbps\"" "$CONFIG_FILE")
    read -p "限速至 (如 10Mbps, 默认 $current_throttle): " throttle_rate
    [ -z "$throttle_rate" ] && throttle_rate="$current_throttle"
    
    if [ "$(parse_rate_to_kbps "$throttle_rate")" -eq 0 ]; then
        echo -e "${RED}无效的速率格式${NC}"
        return
    fi
    
    # 限速时长
    local current_duration=$(jq -r ".ports.\"$port\".burst_protection.throttle_duration // 60" "$CONFIG_FILE")
    read -p "限速时长 (分钟, 默认 $current_duration): " throttle_duration
    [ -z "$throttle_duration" ] && throttle_duration="$current_duration"
    [[ ! "$throttle_duration" =~ ^[0-9]+$ ]] && throttle_duration=60
    
    # 保存配置
    local burst_config="{\"enabled\": true, \"burst_rate\": \"$burst_rate\", \"burst_window\": $burst_window, \"throttle_rate\": \"$throttle_rate\", \"throttle_duration\": $throttle_duration}"
    update_config ".ports.\"$port\".burst_protection = $burst_config"
    
    # 更新 cron
    setup_notify_cron "$(jq -r '.telegram.notify_interval // ""' "$CONFIG_FILE")"
    
    echo
    echo -e "${GREEN}✓ 突发保护已启用${NC}"
    echo "  当速率持续 $burst_window 分钟超过 $burst_rate 时"
    echo "  自动限速到 $throttle_rate，持续 $throttle_duration 分钟"
}

# ============================================================================
# Telegram 设置
# ============================================================================

setup_telegram() {
    echo -e "${CYAN}=== Telegram 通知设置 ===${NC}\n"

    local enabled=$(jq -r '.telegram.enabled' "$CONFIG_FILE")
    local token=$(jq -r '.telegram.bot_token // ""' "$CONFIG_FILE")
    local chat=$(jq -r '.telegram.chat_id // ""' "$CONFIG_FILE")
    local server=$(jq -r '.telegram.server_name // ""' "$CONFIG_FILE")
    local interval=$(jq -r '.telegram.notify_interval // ""' "$CONFIG_FILE")
    local alert=$(jq -r '.telegram.alert_enabled // true' "$CONFIG_FILE")

    echo "状态: $([ "$enabled" = "true" ] && echo -e "${GREEN}已启用${NC}" || echo -e "${YELLOW}未启用${NC}")"
    [ -n "$token" ] && [ "$token" != "null" ] && [ "$token" != "" ] && echo "Bot Token: ${token:0:10}..."
    [ -n "$chat" ] && [ "$chat" != "null" ] && [ "$chat" != "" ] && echo "Chat ID: $chat"
    [ -n "$server" ] && [ "$server" != "null" ] && [ "$server" != "" ] && echo "服务器: $server"
    echo "定时推送: $([ -n "$interval" ] && [ "$interval" != "null" ] && [ "$interval" != "" ] && echo "$interval" || echo "未设置")"
    echo "阈值告警: $([ "$alert" = "true" ] && echo -e "${GREEN}已启用${NC}" || echo -e "${YELLOW}未启用${NC}")"
    echo
    echo "1. 配置 Bot Token 和 Chat ID"
    echo "2. 发送测试消息"
    echo "3. $([ "$enabled" = "true" ] && echo "禁用通知" || echo "启用通知")"
    echo "4. 设置服务器名称"
    echo "5. 设置定时推送"
    echo "6. $([ "$alert" = "true" ] && echo "禁用阈值告警" || echo "启用阈值告警")"
    echo "0. 返回"
    echo

    read -p "选择: " choice

    case $choice in
        1)
            read -p "Bot Token: " new_token
            read -p "Chat ID: " new_chat
            if [ -n "$new_token" ] && [ -n "$new_chat" ]; then
                update_config ".telegram.bot_token = \"$new_token\" | .telegram.chat_id = \"$new_chat\""
                echo -e "${GREEN}✓ 配置已保存${NC}"
            fi
            ;;
        2)
            if [ -n "$token" ] && [ "$token" != "null" ] && [ -n "$chat" ] && [ "$chat" != "null" ]; then
                telegram_test "$token" "$chat" && echo -e "${GREEN}✓ 测试成功${NC}" || echo -e "${RED}✗ 发送失败${NC}"
            else
                echo -e "${RED}请先配置 Bot Token 和 Chat ID${NC}"
            fi
            ;;
        3)
            if [ "$enabled" = "true" ]; then
                update_config ".telegram.enabled = false"
                remove_notify_cron
                echo -e "${YELLOW}已禁用通知${NC}"
            else
                update_config ".telegram.enabled = true"
                setup_notify_cron "$(jq -r '.telegram.notify_interval // ""' "$CONFIG_FILE")"
                echo -e "${GREEN}已启用通知${NC}"
            fi
            ;;
        4)
            read -p "服务器名称: " name
            if [ -n "$name" ]; then
                name=$(escape_json "$name")
                update_config ".telegram.server_name = \"$name\""
                echo -e "${GREEN}✓ 已设置${NC}"
            fi
            ;;
        5)
            echo -e "\n定时推送间隔:"
            echo "  1. 1分钟   2. 5分钟   3. 15分钟  4. 30分钟"
            echo "  5. 1小时   6. 2小时   7. 6小时   8. 12小时  9. 24小时"
            echo "  0. 关闭"
            read -p "选择: " int_choice

            local new_interval=""
            case $int_choice in
                1) new_interval="1m" ;; 2) new_interval="5m" ;; 3) new_interval="15m" ;; 4) new_interval="30m" ;;
                5) new_interval="1h" ;; 6) new_interval="2h" ;; 7) new_interval="6h" ;; 8) new_interval="12h" ;;
                9) new_interval="24h" ;; 0) new_interval="" ;;
            esac

            update_config ".telegram.notify_interval = \"$new_interval\""
            setup_notify_cron "$new_interval"
            [ -n "$new_interval" ] && echo -e "${GREEN}✓ 定时推送: $new_interval${NC}" || echo -e "${YELLOW}已关闭定时推送${NC}"
            ;;
        6)
            if [ "$alert" = "true" ]; then
                update_config ".telegram.alert_enabled = false"
                setup_notify_cron "$(jq -r '.telegram.notify_interval // ""' "$CONFIG_FILE")"
                echo -e "${YELLOW}已禁用阈值告警${NC}"
            else
                update_config ".telegram.alert_enabled = true"
                setup_notify_cron "$(jq -r '.telegram.notify_interval // ""' "$CONFIG_FILE")"
                echo -e "${GREEN}已启用阈值告警${NC}"
            fi
            ;;
    esac
    sleep 1
}

# ============================================================================
# 主菜单
# ============================================================================

show_status() {
    clear
    local ports=($(get_active_ports))
    local total=0

    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}             ${CYAN}端口流量监控 v${SCRIPT_VERSION}${NC}               ${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"

    if [ ${#ports[@]} -eq 0 ]; then
        echo -e "${BLUE}║${NC}  ${YELLOW}暂无监控端口${NC}                                            ${BLUE}║${NC}"
    else
        for port in "${ports[@]}"; do
            local traffic=($(get_port_traffic "$port"))
            local billing=$(jq -r ".ports.\"$port\".billing // \"single\"" "$CONFIG_FILE")
            local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
            total=$((total + used))

            local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
            local limit=$(jq -r ".ports.\"$port\".quota.limit // \"unlimited\"" "$CONFIG_FILE")
            local rate=$(jq -r ".ports.\"$port\".bandwidth.rate // \"unlimited\"" "$CONFIG_FILE")

            local percent_display=""
            if [ "$limit" != "unlimited" ] && [ "$limit" != "null" ]; then
                local limit_bytes=$(parse_size_to_bytes "$limit")
                if [ "$limit_bytes" -gt 0 ]; then
                    local percent=$((used * 100 / limit_bytes))
                    if [ $percent -ge 100 ]; then percent_display=" ${RED}[${percent}%]${NC}"
                    elif [ $percent -ge 80 ]; then percent_display=" ${YELLOW}[${percent}%]${NC}"
                    else percent_display=" ${GREEN}[${percent}%]${NC}"; fi
                fi
            fi
            
            # 突发保护状态
            local burst_display=""
            local burst_status=$(get_burst_status "$port")
            case "$burst_status" in
                throttled:*) 
                    local remaining=$(echo "$burst_status" | cut -d: -f2)
                    burst_display=" ${RED}🔽${remaining}${NC}"
                    ;;
                normal) burst_display=" ${GREEN}⚡${NC}" ;;
            esac

            printf "${BLUE}║${NC}  ${GREEN}%-8s${NC} ↑%-8s ↓%-8s 计:%-8s%b%b${BLUE}║${NC}\n" \
                "$port" "$(format_bytes ${traffic[0]})" "$(format_bytes ${traffic[1]})" "$(format_bytes $used)" "$percent_display" "$burst_display"
            
            local tags=""
            [ -n "$remark" ] && [ "$remark" != "null" ] && [ "$remark" != "" ] && tags+="[$remark] "
            [ "$limit" != "unlimited" ] && [ "$limit" != "null" ] && tags+="配额:$limit "
            [ "$rate" != "unlimited" ] && [ "$rate" != "null" ] && tags+="限速:$rate"
            [ -n "$tags" ] && printf "${BLUE}║${NC}    ${YELLOW}%-56s${NC}${BLUE}║${NC}\n" "$tags"
        done
    fi

    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
    printf "${BLUE}║${NC}  监控: ${GREEN}%-2d${NC} 个  总流量: ${GREEN}%-10s${NC}  快捷命令: ${CYAN}%-4s${NC}     ${BLUE}║${NC}\n" "${#ports[@]}" "$(format_bytes $total)" "$SHORTCUT_COMMAND"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "  ${YELLOW}⚡=突发保护  🔽=限速中${NC}"
    echo
}

show_menu() {
    echo -e "${CYAN}── 端口管理 ──${NC}"
    echo "  1. 添加端口    2. 删除端口    3. 修改备注"
    echo -e "${CYAN}── 流量设置 ──${NC}"
    echo "  4. 带宽限制    5. 流量配额    6. 重置流量"
    echo -e "${CYAN}── 保护设置 ──${NC}"
    echo "  7. 突发保护"
    echo -e "${CYAN}── 通知设置 ──${NC}"
    echo "  8. Telegram    9. 立即推送"
    echo -e "${CYAN}── 系统 ──${NC}"
    echo "  10. 卸载       0. 退出"
    echo
}

uninstall() {
    echo -e "${RED}=== 卸载脚本 ===${NC}\n"
    echo "将删除: nftables规则, TC限速, IFB设备, 定时任务, 配置文件, 快捷命令"
    echo
    read -p "确认卸载? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && return

    for port in $(get_active_ports); do
        remove_nftables_rules "$port"
        remove_quota "$port"
        remove_tc_limit "$port"
        remove_reset_cron "$port"
    done

    remove_notify_cron
    nft delete table $NFT_FAMILY $NFT_TABLE 2>/dev/null || true

    local interface=$(get_default_interface)
    [ -n "$interface" ] && tc qdisc del dev $interface handle ffff: ingress 2>/dev/null || true
    tc qdisc del dev ifb0 root 2>/dev/null || true
    ip link set ifb0 down 2>/dev/null || true

    rm -rf "$CONFIG_DIR"
    rm -f "/usr/local/bin/$SHORTCUT_COMMAND"
    rm -f "$SCRIPT_PATH"

    echo -e "${GREEN}卸载完成${NC}"
    exit 0
}

create_shortcut() {
    [ -f "/usr/local/bin/$SHORTCUT_COMMAND" ] && return
    cat > "/usr/local/bin/$SHORTCUT_COMMAND" << EOF
#!/bin/bash
exec bash "$SCRIPT_PATH" "\$@"
EOF
    chmod +x "/usr/local/bin/$SHORTCUT_COMMAND"
}

# ============================================================================
# 主函数
# ============================================================================

main() {
    check_root
    check_dependencies
    init_config
    create_shortcut

    if [ $# -gt 0 ]; then
        case $1 in
            --reset)
                [ -n "$2" ] && reset_port_traffic "$2" && echo "端口 $2 已重置"
                exit 0 ;;
            --notify|--status)
                [ "$(jq -r '.telegram.enabled' "$CONFIG_FILE")" = "true" ] && telegram_send "$(format_status_message)"
                exit 0 ;;
            --check-alert)
                check_and_send_alerts
                exit 0 ;;
            --check-burst)
                check_burst_protection
                exit 0 ;;
            --version|-v)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                exit 0 ;;
            --help|-h)
                echo "用法: $0 [选项]"
                echo "  --reset <port>   重置端口流量"
                echo "  --notify         发送状态通知"
                echo "  --check-alert    检查阈值告警"
                echo "  --check-burst    检查突发速率保护"
                echo "  --version        显示版本"
                exit 0 ;;
            *)
                echo "未知参数，使用 --help 查看帮助"
                exit 1 ;;
        esac
    fi

    while true; do
        show_status
        show_menu
        read -p "选择 [0-10]: " choice
        case $choice in
            1) add_port ;;
            2) remove_port ;;
            3) set_remark ;;
            4) set_bandwidth ;;
            5) set_quota ;;
            6) reset_traffic ;;
            7) setup_burst_protection ;;
            8) setup_telegram ;;
            9)
                if [ "$(jq -r '.telegram.enabled' "$CONFIG_FILE")" = "true" ]; then
                    telegram_send "$(format_status_message)" && echo -e "${GREEN}✓ 已发送${NC}" || echo -e "${RED}✗ 发送失败${NC}"
                else
                    echo -e "${YELLOW}请先启用 Telegram 通知${NC}"
                fi
                sleep 1 ;;
            10) uninstall ;;
            0) exit 0 ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

main "$@"
