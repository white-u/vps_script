#!/bin/bash

set -euo pipefail

# ============================================================================
# 端口流量监控脚本 (精简版)
# 基于 port-traffic-dog 优化
# 移除: 企业微信通知、配置导入导出、多源下载
# ============================================================================

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="端口流量监控"
readonly SCRIPT_PATH="$(realpath "$0" 2>/dev/null || echo "$0")"
readonly CONFIG_DIR="/etc/port-traffic-monitor"
readonly CONFIG_FILE="$CONFIG_DIR/config.json"
readonly LOG_FILE="$CONFIG_DIR/logs/traffic.log"
readonly TRAFFIC_DATA_FILE="$CONFIG_DIR/traffic_data.json"

# 颜色定义
readonly RED='\033[0;31m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly GREEN='\033[0;32m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# 网络超时设置
readonly CONNECT_TIMEOUT=10
readonly MAX_TIMEOUT=30

# 快捷命令
readonly SHORTCUT_COMMAND="ptm"

# ============================================================================
# 系统检测与依赖安装
# ============================================================================

detect_system() {
    if [ -f /etc/lsb-release ] && grep -q "Ubuntu" /etc/lsb-release 2>/dev/null; then
        echo "ubuntu"
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
        "ubuntu"|"debian")
            apt-get update -qq
            for tool in "${missing_tools[@]}"; do
                case $tool in
                    "nft") apt-get install -y nftables ;;
                    "tc"|"ss") apt-get install -y iproute2 ;;
                    "jq") apt-get install -y jq ;;
                    "bc") apt-get install -y bc ;;
                    "cron")
                        apt-get install -y cron
                        systemctl enable cron 2>/dev/null || true
                        systemctl start cron 2>/dev/null || true
                        ;;
                    "conntrack") apt-get install -y conntrack ;;
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
                    "cron")
                        yum install -y cronie
                        systemctl enable crond 2>/dev/null || true
                        systemctl start crond 2>/dev/null || true
                        ;;
                    "conntrack") yum install -y conntrack-tools ;;
                    *) yum install -y "$tool" ;;
                esac
            done
            ;;
        *)
            echo -e "${RED}不支持的系统类型${NC}"
            echo "请手动安装: ${missing_tools[*]}"
            exit 1
            ;;
    esac

    echo -e "${GREEN}依赖安装完成${NC}"
}

check_dependencies() {
    local missing_tools=()
    local required_tools=("nft" "tc" "ss" "jq" "bc")

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        install_missing_tools "${missing_tools[@]}"

        # 验证安装
        for tool in "${missing_tools[@]}"; do
            if ! command -v "$tool" >/dev/null 2>&1; then
                echo -e "${RED}安装失败: $tool${NC}"
                exit 1
            fi
        done
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误：需要 root 权限${NC}"
        exit 1
    fi
}

# ============================================================================
# 配置初始化
# ============================================================================

init_config() {
    mkdir -p "$CONFIG_DIR" "$(dirname "$LOG_FILE")"

    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" << 'EOF'
{
  "ports": {},
  "nftables": {
    "table_name": "port_monitor",
    "family": "inet"
  },
  "telegram": {
    "enabled": false,
    "bot_token": "",
    "chat_id": "",
    "server_name": ""
  }
}
EOF
    fi

    init_nftables
    setup_exit_hooks
    restore_monitoring_if_needed
}

init_nftables() {
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")

    nft add table $family $table_name 2>/dev/null || true
    nft add chain $family $table_name input { type filter hook input priority 0\; } 2>/dev/null || true
    nft add chain $family $table_name output { type filter hook output priority 0\; } 2>/dev/null || true
    nft add chain $family $table_name forward { type filter hook forward priority 0\; } 2>/dev/null || true
}

# ============================================================================
# 工具函数
# ============================================================================

get_default_interface() {
    local iface=$(ip route | grep default | awk '{print $5}' | head -n1)
    echo "${iface:-eth0}"
}

format_bytes() {
    local bytes=$1
    [[ ! "$bytes" =~ ^[0-9]+$ ]] && bytes=0

    if [ $bytes -ge 1073741824 ]; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc)GB"
    elif [ $bytes -ge 1048576 ]; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc)MB"
    elif [ $bytes -ge 1024 ]; then
        echo "$(echo "scale=2; $bytes / 1024" | bc)KB"
    else
        echo "${bytes}B"
    fi
}

parse_size_to_bytes() {
    local size_str=$1
    local number=$(echo "$size_str" | grep -o '^[0-9]\+')
    local unit=$(echo "$size_str" | grep -o '[A-Za-z]\+$' | tr '[:lower:]' '[:upper:]')

    [ -z "$number" ] && echo "0" && return 1

    case $unit in
        "MB"|"M") echo $((number * 1048576)) ;;
        "GB"|"G") echo $((number * 1073741824)) ;;
        "TB"|"T") echo $((number * 1099511627776)) ;;
        *) echo "0" ;;
    esac
}

get_beijing_time() {
    TZ='Asia/Shanghai' date "$@"
}

update_config() {
    local jq_expression="$1"
    jq "$jq_expression" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

get_active_ports() {
    jq -r '.ports | keys[]' "$CONFIG_FILE" 2>/dev/null | sort -n
}

is_port_range() {
    [[ "$1" =~ ^[0-9]+-[0-9]+$ ]]
}

# ============================================================================
# 流量数据管理
# ============================================================================

get_port_traffic() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")

    local port_safe=$(echo "$port" | tr '-' '_')
    local input_bytes=$(nft list counter $family $table_name "port_${port_safe}_in" 2>/dev/null | \
        grep -o 'bytes [0-9]*' | awk '{print $2}')
    local output_bytes=$(nft list counter $family $table_name "port_${port_safe}_out" 2>/dev/null | \
        grep -o 'bytes [0-9]*' | awk '{print $2}')

    echo "${input_bytes:-0} ${output_bytes:-0}"
}

calculate_total_traffic() {
    local input_bytes=$1
    local output_bytes=$2
    local billing_mode=${3:-"single"}

    case $billing_mode in
        "double") echo $((input_bytes + output_bytes)) ;;
        *) echo $output_bytes ;;
    esac
}

save_traffic_data() {
    local temp_file=$(mktemp)
    local active_ports=($(get_active_ports 2>/dev/null || true))

    [ ${#active_ports[@]} -eq 0 ] && return 0

    echo '{}' > "$temp_file"

    for port in "${active_ports[@]}"; do
        local traffic_data=($(get_port_traffic "$port"))
        local current_input=${traffic_data[0]}
        local current_output=${traffic_data[1]}

        if [ $current_input -gt 0 ] || [ $current_output -gt 0 ]; then
            jq ".\"$port\" = {\"input\": $current_input, \"output\": $current_output, \"time\": \"$(get_beijing_time -Iseconds)\"}" \
                "$temp_file" > "${temp_file}.tmp" && mv "${temp_file}.tmp" "$temp_file"
        fi
    done

    [ -s "$temp_file" ] && mv "$temp_file" "$TRAFFIC_DATA_FILE" || rm -f "$temp_file"
}

setup_exit_hooks() {
    trap 'save_traffic_data >/dev/null 2>&1' EXIT
    trap 'save_traffic_data >/dev/null 2>&1; exit 1' INT TERM
}

restore_monitoring_if_needed() {
    local active_ports=($(get_active_ports 2>/dev/null || true))
    [ ${#active_ports[@]} -eq 0 ] && return 0

    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")

    for port in "${active_ports[@]}"; do
        local port_safe=$(echo "$port" | tr '-' '_')
        if ! nft list counter $family $table_name "port_${port_safe}_in" >/dev/null 2>&1; then
            restore_traffic_from_backup
            restore_all_rules
            return
        fi
    done
}

restore_traffic_from_backup() {
    [ ! -f "$TRAFFIC_DATA_FILE" ] && return 0

    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")

    for port in $(jq -r 'keys[]' "$TRAFFIC_DATA_FILE" 2>/dev/null); do
        local input=$(jq -r ".\"$port\".input // 0" "$TRAFFIC_DATA_FILE")
        local output=$(jq -r ".\"$port\".output // 0" "$TRAFFIC_DATA_FILE")
        local port_safe=$(echo "$port" | tr '-' '_')

        nft add counter $family $table_name "port_${port_safe}_in" { packets 0 bytes $input } 2>/dev/null || true
        nft add counter $family $table_name "port_${port_safe}_out" { packets 0 bytes $output } 2>/dev/null || true
    done

    rm -f "$TRAFFIC_DATA_FILE"
}

restore_all_rules() {
    for port in $(get_active_ports); do
        add_nftables_rules "$port"

        local quota=$(jq -r ".ports.\"$port\".quota.limit // \"unlimited\"" "$CONFIG_FILE")
        [ "$quota" != "unlimited" ] && apply_quota "$port" "$quota"

        local rate=$(jq -r ".ports.\"$port\".bandwidth.rate // \"unlimited\"" "$CONFIG_FILE")
        [ "$rate" != "unlimited" ] && apply_tc_limit "$port" "$rate"

        setup_reset_cron "$port"
    done
}

# ============================================================================
# nftables 规则管理
# ============================================================================

add_nftables_rules() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    local port_safe=$(echo "$port" | tr '-' '_')

    # 创建计数器
    nft list counter $family $table_name "port_${port_safe}_in" >/dev/null 2>&1 || \
        nft add counter $family $table_name "port_${port_safe}_in" 2>/dev/null || true
    nft list counter $family $table_name "port_${port_safe}_out" >/dev/null 2>&1 || \
        nft add counter $family $table_name "port_${port_safe}_out" 2>/dev/null || true

    # 添加规则
    for proto in tcp udp; do
        nft add rule $family $table_name input $proto dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $family $table_name forward $proto dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $family $table_name output $proto sport $port counter name "port_${port_safe}_out" 2>/dev/null || true
        nft add rule $family $table_name forward $proto sport $port counter name "port_${port_safe}_out" 2>/dev/null || true
    done
}

remove_nftables_rules() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    local port_safe=$(echo "$port" | tr '-' '_')

    # 删除规则
    local deleted=0
    while [ $deleted -lt 50 ]; do
        local handle=$(nft -a list table $family $table_name 2>/dev/null | \
            grep -E "port_${port_safe}_" | head -n1 | \
            sed -n 's/.*# handle \([0-9]\+\)$/\1/p')

        [ -z "$handle" ] && break

        for chain in input output forward; do
            nft delete rule $family $table_name $chain handle $handle 2>/dev/null && break
        done
        deleted=$((deleted + 1))
    done

    # 删除计数器
    nft delete counter $family $table_name "port_${port_safe}_in" 2>/dev/null || true
    nft delete counter $family $table_name "port_${port_safe}_out" 2>/dev/null || true
}

# ============================================================================
# 配额管理
# ============================================================================

apply_quota() {
    local port=$1
    local limit=$2
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    local port_safe=$(echo "$port" | tr '-' '_')
    local billing=$(jq -r ".ports.\"$port\".billing // \"single\"" "$CONFIG_FILE")

    local quota_bytes=$(parse_size_to_bytes "$limit")
    local traffic=($(get_port_traffic "$port"))
    local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")

    local quota_name="port_${port_safe}_quota"
    nft add quota $family $table_name $quota_name { over $quota_bytes bytes used $used bytes } 2>/dev/null || true

    if [ "$billing" = "double" ]; then
        for proto in tcp udp; do
            nft insert rule $family $table_name input $proto dport $port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $family $table_name output $proto sport $port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $family $table_name forward $proto dport $port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $family $table_name forward $proto sport $port quota name "$quota_name" drop 2>/dev/null || true
        done
    else
        for proto in tcp udp; do
            nft insert rule $family $table_name output $proto sport $port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $family $table_name forward $proto sport $port quota name "$quota_name" drop 2>/dev/null || true
        done
    fi
}

remove_quota() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    local port_safe=$(echo "$port" | tr '-' '_')
    local quota_name="port_${port_safe}_quota"

    # 删除配额规则
    local deleted=0
    while [ $deleted -lt 50 ]; do
        local handle=$(nft -a list table $family $table_name 2>/dev/null | \
            grep "quota name \"$quota_name\"" | head -n1 | \
            sed -n 's/.*# handle \([0-9]\+\)$/\1/p')

        [ -z "$handle" ] && break

        for chain in input output forward; do
            nft delete rule $family $table_name $chain handle $handle 2>/dev/null && break
        done
        deleted=$((deleted + 1))
    done

    nft delete quota $family $table_name "$quota_name" 2>/dev/null || true
}

# ============================================================================
# TC 带宽限制
# ============================================================================

apply_tc_limit() {
    local port=$1
    local rate=$2
    local interface=$(get_default_interface)

    # 转换速率格式
    local tc_rate
    local rate_lower=$(echo "$rate" | tr '[:upper:]' '[:lower:]')
    if [[ "$rate_lower" =~ kbps$ ]]; then
        tc_rate=$(echo "$rate_lower" | sed 's/kbps$/kbit/')
    elif [[ "$rate_lower" =~ mbps$ ]]; then
        tc_rate=$(echo "$rate_lower" | sed 's/mbps$/mbit/')
    elif [[ "$rate_lower" =~ gbps$ ]]; then
        tc_rate=$(echo "$rate_lower" | sed 's/gbps$/gbit/')
    else
        return 1
    fi

    # 设置 HTB qdisc
    tc qdisc add dev $interface root handle 1: htb default 30 2>/dev/null || true
    tc class add dev $interface parent 1: classid 1:1 htb rate 1000mbit 2>/dev/null || true

    # 计算 class ID
    local class_id
    if is_port_range "$port"; then
        local start=$(echo "$port" | cut -d'-' -f1)
        local end=$(echo "$port" | cut -d'-' -f2)
        class_id="1:$(printf '%x' $(( (start * 1000 + end) % 65536 + 0x2000 )))"
    else
        class_id="1:$(printf '%x' $((0x1000 + port)))"
    fi

    tc class del dev $interface classid $class_id 2>/dev/null || true
    tc class add dev $interface parent 1:1 classid $class_id htb rate $tc_rate ceil $tc_rate

    # 添加过滤器
    local prio=$((port % 1000 + 1))
    for proto_num in 6 17; do  # TCP=6, UDP=17
        tc filter add dev $interface protocol ip parent 1:0 prio $prio u32 \
            match ip protocol $proto_num 0xff match ip sport $port 0xffff flowid $class_id 2>/dev/null || true
        tc filter add dev $interface protocol ip parent 1:0 prio $prio u32 \
            match ip protocol $proto_num 0xff match ip dport $port 0xffff flowid $class_id 2>/dev/null || true
    done
}

remove_tc_limit() {
    local port=$1
    local interface=$(get_default_interface)

    local class_id
    if is_port_range "$port"; then
        local start=$(echo "$port" | cut -d'-' -f1)
        local end=$(echo "$port" | cut -d'-' -f2)
        class_id="1:$(printf '%x' $(( (start * 1000 + end) % 65536 + 0x2000 )))"
    else
        class_id="1:$(printf '%x' $((0x1000 + port)))"
    fi

    local prio=$((port % 1000 + 1))
    for proto_num in 6 17; do
        tc filter del dev $interface protocol ip parent 1:0 prio $prio u32 \
            match ip protocol $proto_num 0xff match ip sport $port 0xffff 2>/dev/null || true
        tc filter del dev $interface protocol ip parent 1:0 prio $prio u32 \
            match ip protocol $proto_num 0xff match ip dport $port 0xffff 2>/dev/null || true
    done

    tc class del dev $interface classid $class_id 2>/dev/null || true
}

# ============================================================================
# 定时重置
# ============================================================================

setup_reset_cron() {
    local port=$1
    local temp_cron=$(mktemp)

    crontab -l 2>/dev/null | grep -v "端口流量监控重置$port" > "$temp_cron" || true

    local reset_day=$(jq -r ".ports.\"$port\".quota.reset_day // null" "$CONFIG_FILE")
    local limit=$(jq -r ".ports.\"$port\".quota.limit // \"unlimited\"" "$CONFIG_FILE")

    if [ "$reset_day" != "null" ] && [ "$limit" != "unlimited" ]; then
        echo "5 0 $reset_day * * $SCRIPT_PATH --reset $port >/dev/null 2>&1  # 端口流量监控重置$port" >> "$temp_cron"
    fi

    crontab "$temp_cron"
    rm -f "$temp_cron"
}

remove_reset_cron() {
    local port=$1
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "端口流量监控重置$port" > "$temp_cron" || true
    crontab "$temp_cron"
    rm -f "$temp_cron"
}

reset_port_traffic() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    local port_safe=$(echo "$port" | tr '-' '_')

    nft reset counter $family $table_name "port_${port_safe}_in" >/dev/null 2>&1 || true
    nft reset counter $family $table_name "port_${port_safe}_out" >/dev/null 2>&1 || true
    nft reset quota $family $table_name "port_${port_safe}_quota" >/dev/null 2>&1 || true
}

# ============================================================================
# Telegram 通知
# ============================================================================

telegram_send() {
    local message=$1
    local bot_token=$(jq -r '.telegram.bot_token' "$CONFIG_FILE")
    local chat_id=$(jq -r '.telegram.chat_id' "$CONFIG_FILE")

    [ -z "$bot_token" ] || [ -z "$chat_id" ] && return 1

    curl -s --connect-timeout $CONNECT_TIMEOUT --max-time $MAX_TIMEOUT \
        "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -d "chat_id=${chat_id}" \
        -d "text=${message}" \
        -d "parse_mode=HTML" >/dev/null 2>&1
}

telegram_test() {
    local bot_token=$1
    local chat_id=$2

    local result=$(curl -s --connect-timeout $CONNECT_TIMEOUT --max-time $MAX_TIMEOUT \
        "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -d "chat_id=${chat_id}" \
        -d "text=🔔 端口流量监控测试消息" 2>&1)

    echo "$result" | grep -q '"ok":true'
}

format_status_message() {
    local server_name=$(jq -r '.telegram.server_name // ""' "$CONFIG_FILE")
    [ -z "$server_name" ] && server_name=$(hostname)

    local timestamp=$(get_beijing_time '+%Y-%m-%d %H:%M:%S')
    local ports=($(get_active_ports))
    local total=0

    local port_info=""
    for port in "${ports[@]}"; do
        local traffic=($(get_port_traffic "$port"))
        local billing=$(jq -r ".ports.\"$port\".billing // \"single\"" "$CONFIG_FILE")
        local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
        total=$((total + used))

        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
        [ -n "$remark" ] && remark=" ($remark)"

        port_info+="
📌 端口 ${port}${remark}
   ├ 入站: $(format_bytes ${traffic[0]})
   ├ 出站: $(format_bytes ${traffic[1]})
   └ 总计: $(format_bytes $used)"
    done

    echo "🔔 <b>端口流量监控</b>
━━━━━━━━━━━━━━━━
⏰ ${timestamp}
🖥 ${server_name}
📊 监控端口: ${#ports[@]} 个
💾 总流量: $(format_bytes $total)
━━━━━━━━━━━━━━━━${port_info}"
}

# ============================================================================
# 端口管理
# ============================================================================

add_port() {
    echo -e "${CYAN}=== 添加端口监控 ===${NC}"
    echo

    # 显示当前监听端口
    echo -e "${GREEN}当前系统监听端口:${NC}"
    ss -tulnp 2>/dev/null | grep -E "LISTEN|UNCONN" | awk '{print $5}' | \
        grep -oE '[0-9]+$' | sort -nu | head -20 | tr '\n' ' '
    echo -e "\n"

    read -p "请输入端口号 (多个用逗号分隔, 支持范围如 8000-8010): " port_input
    [ -z "$port_input" ] && return

    # 解析端口
    local ports=()
    IFS=',' read -ra parts <<< "$port_input"
    for part in "${parts[@]}"; do
        part=$(echo "$part" | tr -d ' ')
        if [[ "$part" =~ ^[0-9]+$ ]] && [ "$part" -ge 1 ] && [ "$part" -le 65535 ]; then
            ports+=("$part")
        elif [[ "$part" =~ ^[0-9]+-[0-9]+$ ]]; then
            ports+=("$part")
        else
            echo -e "${RED}无效端口: $part${NC}"
        fi
    done

    [ ${#ports[@]} -eq 0 ] && return

    # 计费模式
    echo
    echo "计费模式:"
    echo "  1. 单向 (只计出站流量)"
    echo "  2. 双向 (入站+出站)"
    read -p "选择 [1]: " billing_choice
    local billing="single"
    [ "$billing_choice" = "2" ] && billing="double"

    # 流量配额
    echo
    read -p "流量配额 (如 100GB, 留空无限制): " quota_input
    local quota="unlimited"
    local reset_day="null"
    if [ -n "$quota_input" ]; then
        quota="$quota_input"
        read -p "每月重置日 (1-31, 0=不自动重置): " reset_input
        [ -n "$reset_input" ] && [ "$reset_input" != "0" ] && reset_day="$reset_input"
    fi

    # 带宽限制
    read -p "带宽限制 (如 100Mbps, 留空无限制): " rate_input
    local rate="unlimited"
    [ -n "$rate_input" ] && rate="$rate_input"

    # 备注
    read -p "备注 (可选): " remark

    # 添加端口
    for port in "${ports[@]}"; do
        if jq -e ".ports.\"$port\"" "$CONFIG_FILE" >/dev/null 2>&1; then
            echo -e "${YELLOW}端口 $port 已存在，跳过${NC}"
            continue
        fi

        local config="{
            \"billing\": \"$billing\",
            \"quota\": {\"limit\": \"$quota\", \"reset_day\": $reset_day},
            \"bandwidth\": {\"rate\": \"$rate\"},
            \"remark\": \"$remark\",
            \"created\": \"$(get_beijing_time -Iseconds)\"
        }"

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
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && return

    echo -e "${CYAN}=== 删除端口监控 ===${NC}"
    echo
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
        [ -n "$remark" ] && remark=" ($remark)"
        echo "  $((i+1)). 端口 $port$remark"
    done
    echo

    read -p "选择要删除的端口 (多个用逗号分隔): " choice
    [ -z "$choice" ] && return

    IFS=',' read -ra selections <<< "$choice"
    for sel in "${selections[@]}"; do
        sel=$(echo "$sel" | tr -d ' ')
        [[ ! "$sel" =~ ^[0-9]+$ ]] && continue
        [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && continue

        local port=${ports[$((sel-1))]}

        read -p "确认删除端口 $port? [y/N]: " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && continue

        remove_nftables_rules "$port"
        remove_quota "$port"
        remove_tc_limit "$port"
        remove_reset_cron "$port"
        update_config "del(.ports.\"$port\")"

        # 清理连接
        conntrack -D -p tcp --dport $port 2>/dev/null || true
        conntrack -D -p udp --dport $port 2>/dev/null || true

        echo -e "${GREEN}✓ 端口 $port 已删除${NC}"
    done

    sleep 1
}

# ============================================================================
# 设置管理
# ============================================================================

set_bandwidth() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && return

    echo -e "${CYAN}=== 设置带宽限制 ===${NC}"
    echo
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local rate=$(jq -r ".ports.\"$port\".bandwidth.rate // \"unlimited\"" "$CONFIG_FILE")
        echo "  $((i+1)). 端口 $port [当前: $rate]"
    done
    echo

    read -p "选择端口: " sel
    [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && return

    local port=${ports[$((sel-1))]}
    read -p "带宽限制 (如 100Mbps, 0=取消限制): " rate

    if [ "$rate" = "0" ] || [ -z "$rate" ]; then
        remove_tc_limit "$port"
        update_config ".ports.\"$port\".bandwidth.rate = \"unlimited\""
        echo -e "${GREEN}✓ 已取消带宽限制${NC}"
    else
        remove_tc_limit "$port"
        apply_tc_limit "$port" "$rate"
        update_config ".ports.\"$port\".bandwidth.rate = \"$rate\""
        echo -e "${GREEN}✓ 带宽限制设置为 $rate${NC}"
    fi

    sleep 1
}

set_quota() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && return

    echo -e "${CYAN}=== 设置流量配额 ===${NC}"
    echo
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local limit=$(jq -r ".ports.\"$port\".quota.limit // \"unlimited\"" "$CONFIG_FILE")
        echo "  $((i+1)). 端口 $port [当前: $limit]"
    done
    echo

    read -p "选择端口: " sel
    [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && return

    local port=${ports[$((sel-1))]}
    read -p "流量配额 (如 100GB, 0=取消配额): " limit

    if [ "$limit" = "0" ] || [ -z "$limit" ]; then
        remove_quota "$port"
        remove_reset_cron "$port"
        update_config ".ports.\"$port\".quota.limit = \"unlimited\" | del(.ports.\"$port\".quota.reset_day)"
        echo -e "${GREEN}✓ 已取消流量配额${NC}"
    else
        read -p "每月重置日 (1-31, 0=不自动重置): " reset_day

        remove_quota "$port"
        apply_quota "$port" "$limit"

        if [ -n "$reset_day" ] && [ "$reset_day" != "0" ]; then
            update_config ".ports.\"$port\".quota.limit = \"$limit\" | .ports.\"$port\".quota.reset_day = $reset_day"
            setup_reset_cron "$port"
        else
            update_config ".ports.\"$port\".quota.limit = \"$limit\" | del(.ports.\"$port\".quota.reset_day)"
            remove_reset_cron "$port"
        fi

        echo -e "${GREEN}✓ 流量配额设置为 $limit${NC}"
    fi

    sleep 1
}

reset_traffic() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && return

    echo -e "${CYAN}=== 重置流量统计 ===${NC}"
    echo
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
        read -p "确认重置所有端口流量? [y/N]: " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && return
        for port in "${ports[@]}"; do
            reset_port_traffic "$port"
        done
        echo -e "${GREEN}✓ 已重置所有端口流量${NC}"
    elif [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#ports[@]} ]; then
        local port=${ports[$((sel-1))]}
        read -p "确认重置端口 $port 流量? [y/N]: " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && return
        reset_port_traffic "$port"
        echo -e "${GREEN}✓ 已重置端口 $port 流量${NC}"
    fi

    sleep 1
}

# ============================================================================
# Telegram 设置
# ============================================================================

setup_telegram() {
    echo -e "${CYAN}=== Telegram 通知设置 ===${NC}"
    echo

    local enabled=$(jq -r '.telegram.enabled' "$CONFIG_FILE")
    local current_token=$(jq -r '.telegram.bot_token // ""' "$CONFIG_FILE")
    local current_chat=$(jq -r '.telegram.chat_id // ""' "$CONFIG_FILE")

    echo "当前状态: $([ "$enabled" = "true" ] && echo -e "${GREEN}已启用${NC}" || echo -e "${YELLOW}未启用${NC}")"
    [ -n "$current_token" ] && echo "Bot Token: ${current_token:0:10}..."
    [ -n "$current_chat" ] && echo "Chat ID: $current_chat"
    echo

    echo "1. 配置 Bot Token 和 Chat ID"
    echo "2. 发送测试消息"
    echo "3. $([ "$enabled" = "true" ] && echo "禁用通知" || echo "启用通知")"
    echo "4. 设置服务器名称"
    echo "0. 返回"
    echo

    read -p "选择: " choice

    case $choice in
        1)
            read -p "Bot Token: " token
            read -p "Chat ID: " chat_id
            if [ -n "$token" ] && [ -n "$chat_id" ]; then
                update_config ".telegram.bot_token = \"$token\" | .telegram.chat_id = \"$chat_id\""
                echo -e "${GREEN}✓ 配置已保存${NC}"
            fi
            ;;
        2)
            if telegram_test "$current_token" "$current_chat"; then
                echo -e "${GREEN}✓ 测试消息发送成功${NC}"
            else
                echo -e "${RED}✗ 发送失败，请检查配置${NC}"
            fi
            ;;
        3)
            if [ "$enabled" = "true" ]; then
                update_config ".telegram.enabled = false"
                echo -e "${YELLOW}已禁用 Telegram 通知${NC}"
            else
                update_config ".telegram.enabled = true"
                echo -e "${GREEN}已启用 Telegram 通知${NC}"
            fi
            ;;
        4)
            read -p "服务器名称: " name
            [ -n "$name" ] && update_config ".telegram.server_name = \"$name\""
            echo -e "${GREEN}✓ 服务器名称已设置${NC}"
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

    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}          ${CYAN}端口流量监控 v${SCRIPT_VERSION}${NC}          ${BLUE}║${NC}"
    echo -e "${BLUE}╠════════════════════════════════════════════════════════╣${NC}"

    if [ ${#ports[@]} -eq 0 ]; then
        echo -e "${BLUE}║${NC}  ${YELLOW}暂无监控端口${NC}                                        ${BLUE}║${NC}"
    else
        for port in "${ports[@]}"; do
            local traffic=($(get_port_traffic "$port"))
            local billing=$(jq -r ".ports.\"$port\".billing // \"single\"" "$CONFIG_FILE")
            local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
            total=$((total + used))

            local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
            local limit=$(jq -r ".ports.\"$port\".quota.limit // \"unlimited\"" "$CONFIG_FILE")
            local rate=$(jq -r ".ports.\"$port\".bandwidth.rate // \"unlimited\"" "$CONFIG_FILE")

            local port_display="端口 $port"
            [ -n "$remark" ] && port_display="$port_display ($remark)"

            local status_tags=""
            [ "$limit" != "unlimited" ] && status_tags+=" [配额:$limit]"
            [ "$rate" != "unlimited" ] && status_tags+=" [限速:$rate]"

            printf "${BLUE}║${NC}  ${GREEN}%-12s${NC} ↑%-8s ↓%-8s 计:%-8s${BLUE}║${NC}\n" \
                "$port" "$(format_bytes ${traffic[0]})" "$(format_bytes ${traffic[1]})" "$(format_bytes $used)"
            [ -n "$status_tags" ] && printf "${BLUE}║${NC}    ${YELLOW}%s${NC}%*s${BLUE}║${NC}\n" "$status_tags" $((42 - ${#status_tags})) ""
        done
    fi

    echo -e "${BLUE}╠════════════════════════════════════════════════════════╣${NC}"
    printf "${BLUE}║${NC}  监控端口: ${GREEN}%-3d${NC} 个    总流量: ${GREEN}%-12s${NC}       ${BLUE}║${NC}\n" "${#ports[@]}" "$(format_bytes $total)"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo
}

show_menu() {
    echo -e "${CYAN}── 端口管理 ──${NC}"
    echo "  1. 添加端口监控"
    echo "  2. 删除端口监控"
    echo
    echo -e "${CYAN}── 流量设置 ──${NC}"
    echo "  3. 设置带宽限制"
    echo "  4. 设置流量配额"
    echo "  5. 重置流量统计"
    echo
    echo -e "${CYAN}── 系统设置 ──${NC}"
    echo "  6. Telegram 通知"
    echo "  7. 发送状态通知"
    echo "  8. 卸载脚本"
    echo
    echo "  0. 退出"
    echo
}

uninstall() {
    echo -e "${RED}=== 卸载脚本 ===${NC}"
    echo
    echo "将删除:"
    echo "  - 所有 nftables 规则"
    echo "  - 所有 TC 限速规则"
    echo "  - 配置文件 $CONFIG_DIR"
    echo "  - 快捷命令 $SHORTCUT_COMMAND"
    echo

    read -p "确认卸载? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && return

    # 清理规则
    for port in $(get_active_ports); do
        remove_nftables_rules "$port"
        remove_tc_limit "$port"
        remove_reset_cron "$port"
    done

    # 删除 nftables 表
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE" 2>/dev/null || echo "port_monitor")
    nft delete table inet $table_name 2>/dev/null || true

    # 清理文件
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

    # 命令行参数
    if [ $# -gt 0 ]; then
        case $1 in
            --reset)
                [ -z "$2" ] && echo "用法: $0 --reset <port>" && exit 1
                reset_port_traffic "$2"
                echo "端口 $2 流量已重置"
                exit 0
                ;;
            --status)
                telegram_send "$(format_status_message)"
                exit 0
                ;;
            --version)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                exit 0
                ;;
            *)
                echo "用法: $0 [--reset <port>|--status|--version]"
                exit 1
                ;;
        esac
    fi

    # 主循环
    while true; do
        show_status
        show_menu
        read -p "选择 [0-8]: " choice

        case $choice in
            1) add_port ;;
            2) remove_port ;;
            3) set_bandwidth ;;
            4) set_quota ;;
            5) reset_traffic ;;
            6) setup_telegram ;;
            7)
                local enabled=$(jq -r '.telegram.enabled' "$CONFIG_FILE")
                if [ "$enabled" = "true" ]; then
                    telegram_send "$(format_status_message)"
                    echo -e "${GREEN}✓ 状态通知已发送${NC}"
                else
                    echo -e "${YELLOW}Telegram 通知未启用${NC}"
                fi
                sleep 1
                ;;
            8) uninstall ;;
            0) exit 0 ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

main "$@"
