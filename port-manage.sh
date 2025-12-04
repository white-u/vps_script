#!/bin/bash

set -euo pipefail

# ============================================================================
# 端口流量监控脚本 v2.2.0
# 功能: 流量监控、速率限制、流量配额、阈值告警、Telegram通知
# 优化: 配置缓存、入站限速、小数配额支持、备注修改
# ============================================================================

readonly SCRIPT_VERSION="2.2.0"
readonly SCRIPT_NAME="端口流量监控"
readonly SCRIPT_PATH="$(realpath "$0" 2>/dev/null || echo "$0")"
readonly CONFIG_DIR="/etc/port-traffic-monitor"
readonly CONFIG_FILE="$CONFIG_DIR/config.json"
readonly TRAFFIC_DATA_FILE="$CONFIG_DIR/traffic_data.json"
readonly ALERT_STATE_FILE="$CONFIG_DIR/alert_state.json"

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

# 格式化字节 (支持更高精度)
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

# 解析大小到字节 (支持小数如 1.5GB)
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
    
    # 使用 bc 处理小数
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

get_beijing_time() { TZ='Asia/Shanghai' date "$@"; }

update_config() {
    local tmp="${CONFIG_FILE}.tmp.$$"
    if jq "$1" "$CONFIG_FILE" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$CONFIG_FILE"
    else
        rm -f "$tmp"
        return 1
    fi
}

# 获取活动端口 (正确排序端口段)
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

# 验证端口段合法性
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

# 转义 JSON 字符串
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

# 优化: 批量保存流量数据
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
        local rate=$(jq -r ".ports.\"$port\".bandwidth.rate // \"unlimited\"" "$CONFIG_FILE")
        [ "$rate" != "unlimited" ] && [ "$rate" != "null" ] && apply_tc_limit "$port" "$rate"
        setup_reset_cron "$port"
    done
}

# ============================================================================
# nftables 规则管理
# ============================================================================

add_nftables_rules() {
    local port=$1
    local port_safe=$(get_port_safe "$port")

    # 创建计数器
    nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" >/dev/null 2>&1 || \
        nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null || true
    nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" >/dev/null 2>&1 || \
        nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null || true

    # 添加规则
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

    # 删除规则 (按 handle)
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

    # 删除计数器
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

    # 创建配额
    nft add quota $NFT_FAMILY $NFT_TABLE $quota_name "{ over $quota_bytes bytes used $used bytes }" 2>/dev/null || true

    # 插入 drop 规则
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

    # 删除配额规则
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

# 计算 burst: burst = rate * 50ms, 最小 3000 bytes (2*MTU)
calculate_burst() {
    local rate_kbps=$1
    local burst_bytes=$(( rate_kbps * 1000 / 8 / 20 ))
    [ $burst_bytes -lt 3000 ] && burst_bytes=3000
    
    if [ $burst_bytes -ge 1048576 ]; then echo "$((burst_bytes / 1048576))m"
    elif [ $burst_bytes -ge 1024 ]; then echo "$((burst_bytes / 1024))k"
    else echo "$burst_bytes"; fi
}

# 计算稳定的 class_id (避免冲突)
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

# 设置 IFB 用于入站限速
setup_ifb() {
    local interface=$1
    
    # 加载 ifb 模块
    modprobe ifb numifbs=1 2>/dev/null || true
    
    # 启用 ifb0
    ip link set ifb0 up 2>/dev/null || true
    
    # 在物理接口上设置 ingress qdisc
    tc qdisc add dev $interface handle ffff: ingress 2>/dev/null || true
    
    # 将入站流量重定向到 ifb0
    tc filter add dev $interface parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0 2>/dev/null || true
    
    # 在 ifb0 上设置 htb
    tc qdisc add dev ifb0 root handle 1: htb default 30 2>/dev/null || true
    tc class add dev ifb0 parent 1: classid 1:1 htb rate 10gbit 2>/dev/null || true
}

apply_tc_limit() {
    local port=$1 rate=$2
    local interface=$(get_default_interface)
    [ -z "$interface" ] && interface="eth0"

    # 转换速率格式
    local tc_rate rate_lower=$(echo "$rate" | tr '[:upper:]' '[:lower:]')
    if [[ "$rate_lower" =~ kbps$ ]]; then tc_rate=$(echo "$rate_lower" | sed 's/kbps$/kbit/')
    elif [[ "$rate_lower" =~ mbps$ ]]; then tc_rate=$(echo "$rate_lower" | sed 's/mbps$/mbit/')
    elif [[ "$rate_lower" =~ gbps$ ]]; then tc_rate=$(echo "$rate_lower" | sed 's/gbps$/gbit/')
    else return 1; fi

    local rate_kbps=$(parse_rate_to_kbps "$rate")
    local burst=$(calculate_burst $rate_kbps)
    local class_id=$(get_tc_class_id "$port")

    # === 出站限速 ===
    tc qdisc add dev $interface root handle 1: htb default 30 2>/dev/null || true
    tc class add dev $interface parent 1: classid 1:1 htb rate 10gbit 2>/dev/null || true
    
    tc class del dev $interface classid $class_id 2>/dev/null || true
    tc class add dev $interface parent 1:1 classid $class_id htb rate $tc_rate ceil $tc_rate burst $burst cburst $burst

    # 出站过滤器 (使用端口号作为 prio 的一部分)
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

    # === 入站限速 (使用 IFB) ===
    setup_ifb "$interface"
    
    local ifb_class_id=$(echo "$class_id" | sed 's/1:/2:/')
    ifb_class_id="1:$(printf '%x' $(( 0x${ifb_class_id#2:} + 0x1000 )))"
    
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

    # 删除出站过滤器和 class
    for proto_num in 6 17; do
        tc filter del dev $interface protocol ip parent 1:0 prio $base_prio u32 \
            match ip protocol $proto_num 0xff match ip sport $port 0xffff 2>/dev/null || true
    done
    tc class del dev $interface classid $class_id 2>/dev/null || true

    # 删除入站过滤器和 class
    local ifb_class_id="1:$(printf '%x' $(( 0x${class_id#1:} + 0x1000 )))"
    
    for proto_num in 6 17; do
        tc filter del dev ifb0 protocol ip parent 1:0 prio $base_prio u32 \
            match ip protocol $proto_num 0xff match ip dport $port 0xffff 2>/dev/null || true
    done
    tc class del dev ifb0 classid $ifb_class_id 2>/dev/null || true
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
    crontab -l 2>/dev/null | grep -v "端口流量监控状态通知" | grep -v "端口流量监控阈值检查" > "$temp_cron" || true

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

    local alert_enabled=$(jq -r '.telegram.alert_enabled // true' "$CONFIG_FILE")
    [ "$alert_enabled" = "true" ] && echo "*/5 * * * * $SCRIPT_PATH --check-alert >/dev/null 2>&1  # 端口流量监控阈值检查" >> "$temp_cron"

    crontab "$temp_cron" 2>/dev/null
    rm -f "$temp_cron"
}

remove_notify_cron() {
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "端口流量监控状态通知" | grep -v "端口流量监控阈值检查" > "$temp_cron" || true
    crontab "$temp_cron" 2>/dev/null
    rm -f "$temp_cron"
}

reset_port_traffic() {
    local port=$1
    local port_safe=$(get_port_safe "$port")

    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" >/dev/null 2>&1 || true
    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" >/dev/null 2>&1 || true
    nft reset quota $NFT_FAMILY $NFT_TABLE "port_${port_safe}_quota" >/dev/null 2>&1 || true

    # 清除告警状态
    local tmp="${ALERT_STATE_FILE}.tmp.$$"
    jq "del(.\"$port\")" "$ALERT_STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$ALERT_STATE_FILE" || rm -f "$tmp"
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
        
        local remark_display="" percent_display=""
        [ -n "$remark" ] && [ "$remark" != "null" ] && [ "$remark" != "" ] && remark_display=" ($remark)"

        if [ "$limit" != "unlimited" ] && [ "$limit" != "null" ]; then
            local limit_bytes=$(parse_size_to_bytes "$limit")
            [ "$limit_bytes" -gt 0 ] && percent_display=" [$(( used * 100 / limit_bytes ))%]"
        fi

        port_info+="
📌 端口 ${port}${remark_display}${percent_display}
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
        # 验证配额格式
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

        # 清除连接跟踪
        if command -v conntrack >/dev/null 2>&1; then
            conntrack -D -p tcp --dport $port 2>/dev/null || true
            conntrack -D -p udp --dport $port 2>/dev/null || true
        fi

        echo -e "${GREEN}✓ 端口 $port 已删除${NC}"
    done
    sleep 1
}

set_bandwidth() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && sleep 1 && return

    echo -e "${CYAN}=== 设置带宽限制 ===${NC}\n"
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local rate=$(jq -r ".ports.\"$port\".bandwidth.rate // \"unlimited\"" "$CONFIG_FILE")
        echo "  $((i+1)). 端口 $port [当前: $rate]"
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
        remove_tc_limit "$port"
        if apply_tc_limit "$port" "$rate"; then
            update_config ".ports.\"$port\".bandwidth.rate = \"$rate\""
            echo -e "${GREEN}✓ 带宽限制设置为 $rate (入站+出站)${NC}"
        else
            echo -e "${RED}✗ 无效的速率格式${NC}"
        fi
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
        # 验证配额格式
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

# 新增: 修改备注
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
    echo "阈值告警: $([ "$alert" = "true" ] && echo -e "${GREEN}已启用${NC} (30%/50%/80%/100%)" || echo -e "${YELLOW}未启用${NC}")"
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
                echo -e "${GREEN}已启用阈值告警 (30%/50%/80%/100%)${NC}"
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

    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}           ${CYAN}端口流量监控 v${SCRIPT_VERSION}${NC}             ${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════╣${NC}"

    if [ ${#ports[@]} -eq 0 ]; then
        echo -e "${BLUE}║${NC}  ${YELLOW}暂无监控端口${NC}                                          ${BLUE}║${NC}"
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

            printf "${BLUE}║${NC}  ${GREEN}%-8s${NC} ↑%-8s ↓%-8s 计:%-8s%b${BLUE}║${NC}\n" \
                "$port" "$(format_bytes ${traffic[0]})" "$(format_bytes ${traffic[1]})" "$(format_bytes $used)" "$percent_display"
            
            local tags=""
            [ -n "$remark" ] && [ "$remark" != "null" ] && [ "$remark" != "" ] && tags+="[$remark] "
            [ "$limit" != "unlimited" ] && [ "$limit" != "null" ] && tags+="配额:$limit "
            [ "$rate" != "unlimited" ] && [ "$rate" != "null" ] && tags+="限速:$rate"
            [ -n "$tags" ] && printf "${BLUE}║${NC}    ${YELLOW}%-52s${NC}${BLUE}║${NC}\n" "$tags"
        done
    fi

    echo -e "${BLUE}╠══════════════════════════════════════════════════════════╣${NC}"
    printf "${BLUE}║${NC}  监控: ${GREEN}%-2d${NC} 个  总流量: ${GREEN}%-10s${NC}  快捷命令: ${CYAN}%s${NC}   ${BLUE}║${NC}\n" "${#ports[@]}" "$(format_bytes $total)" "$SHORTCUT_COMMAND"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo
}

show_menu() {
    echo -e "${CYAN}── 端口管理 ──${NC}"
    echo "  1. 添加端口    2. 删除端口    3. 修改备注"
    echo -e "${CYAN}── 流量设置 ──${NC}"
    echo "  4. 带宽限制    5. 流量配额    6. 重置流量"
    echo -e "${CYAN}── 通知设置 ──${NC}"
    echo "  7. Telegram    8. 立即推送"
    echo -e "${CYAN}── 系统 ──${NC}"
    echo "  9. 卸载        0. 退出"
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

    # 清理 IFB
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
            --version|-v)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                exit 0 ;;
            --help|-h)
                echo "用法: $0 [选项]"
                echo "  --reset <port>  重置端口流量"
                echo "  --notify        发送状态通知"
                echo "  --check-alert   检查阈值告警"
                echo "  --version       显示版本"
                exit 0 ;;
            *)
                echo "未知参数，使用 --help 查看帮助"
                exit 1 ;;
        esac
    fi

    while true; do
        show_status
        show_menu
        read -p "选择 [0-9]: " choice
        case $choice in
            1) add_port ;;
            2) remove_port ;;
            3) set_remark ;;
            4) set_bandwidth ;;
            5) set_quota ;;
            6) reset_traffic ;;
            7) setup_telegram ;;
            8)
                if [ "$(jq -r '.telegram.enabled' "$CONFIG_FILE")" = "true" ]; then
                    telegram_send "$(format_status_message)" && echo -e "${GREEN}✓ 已发送${NC}" || echo -e "${RED}✗ 发送失败${NC}"
                else
                    echo -e "${YELLOW}请先启用 Telegram 通知${NC}"
                fi
                sleep 1 ;;
            9) uninstall ;;
            0) exit 0 ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

main "$@"
