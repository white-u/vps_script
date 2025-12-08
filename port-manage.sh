#!/bin/bash

# ============================================================================
# 端口流量监控脚本 v2.3.2
# 功能: 流量监控、速率限制、流量配额、阈值告警、Telegram通知、突发速率保护
# ============================================================================

# 错误处理 - 移除 set -e，改用显式错误检查
set -o pipefail

readonly SCRIPT_VERSION="2.4.0"
readonly SCRIPT_NAME="端口流量监控"

# 处理通过 bash <(curl ...) 或临时文件执行的情况
if [[ "$0" == "/dev/fd/"* ]] || [[ "$0" == "/proc/"* ]] || [[ "$0" == "bash" ]] || [[ "$0" == /tmp/* ]]; then
    SCRIPT_PATH="/usr/local/bin/port-traffic-monitor.sh"
    REMOTE_INSTALL=true
else
    SCRIPT_PATH="$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "$0")"
    REMOTE_INSTALL=false
fi

readonly CONFIG_DIR="/etc/port-traffic-monitor"
readonly CONFIG_FILE="$CONFIG_DIR/config.json"
readonly TRAFFIC_DATA_FILE="$CONFIG_DIR/traffic_data.json"
readonly ALERT_STATE_FILE="$CONFIG_DIR/alert_state.json"
readonly BURST_STATE_FILE="$CONFIG_DIR/burst_state.json"
readonly TRAFFIC_HISTORY_DIR="$CONFIG_DIR/traffic_history"
readonly LOCK_FILE="$CONFIG_DIR/.lock"

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

# 网络重试常量
readonly CURL_MAX_RETRIES=3
readonly CURL_RETRY_DELAY=2

# 字节转换常量
readonly BYTES_PER_KB=1024
readonly BYTES_PER_MB=1048576
readonly BYTES_PER_GB=1073741824
readonly BYTES_PER_TB=1099511627776

# 速率转换常量
readonly KBPS_PER_MBPS=1000
readonly KBPS_PER_GBPS=1000000

# nftables 操作常量
readonly MAX_NFT_DELETE_ITERATIONS=50

# TC 带宽控制常量
readonly BURST_CALC_DIVISOR=20
readonly MIN_BURST_BYTES=3000
readonly DEFAULT_INTERFACE="eth0"
readonly TC_CLASS_ID_FILE="$CONFIG_DIR/tc_class_ids.json"

# 流量历史常量
readonly TRAFFIC_HISTORY_MAX_LINES=150
readonly TRAFFIC_HISTORY_KEEP_LINES=120

# 端口范围
readonly PORT_MIN=1
readonly PORT_MAX=65535

# 协议定义
readonly PROTO_TCP=6
readonly PROTO_UDP=17

NFT_TABLE=""
NFT_FAMILY=""

# ============================================================================
# 锁机制
# ============================================================================

acquire_lock() {
    local timeout=${1:-5}
    local count=0

    mkdir -p "$CONFIG_DIR" 2>/dev/null || true

    # 使用 set -C (noclobber) 保证原子性
    while ! (set -C; echo $$ > "$LOCK_FILE") 2>/dev/null; do
        if [ -f "$LOCK_FILE" ]; then
            local pid
            pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")

            # 检查进程是否存活
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                count=$((count + 1))
                if [ $count -ge $timeout ]; then
                    return 1
                fi
                sleep 1
            else
                # 进程已死，清理陈旧锁文件
                rm -f "$LOCK_FILE"
            fi
        else
            # 锁文件被其他进程删除，短暂等待后重试
            sleep 0.1
        fi
    done

    return 0
}

release_lock() {
    [ -f "$LOCK_FILE" ] && [ "$(cat "$LOCK_FILE" 2>/dev/null || echo "")" = "$$" ] && rm -f "$LOCK_FILE"
}

# ============================================================================
# 日志函数
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}✓${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# ============================================================================
# 网络请求重试
# ============================================================================

curl_with_retry() {
    local url=$1
    shift
    local retry_count=0

    while [ $retry_count -lt $CURL_MAX_RETRIES ]; do
        if curl -s --connect-timeout $CONNECT_TIMEOUT --max-time $MAX_TIMEOUT "$@" "$url"; then
            return 0
        fi
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $CURL_MAX_RETRIES ]; then
            sleep $CURL_RETRY_DELAY
        fi
    done
    return 1
}

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
            alpine) echo "alpine" ;;
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
            apt-get update -qq 2>/dev/null
            for tool in "${missing_tools[@]}"; do
                case $tool in
                    "nft") apt-get install -y nftables >/dev/null 2>&1 ;;
                    "tc"|"ss") apt-get install -y iproute2 >/dev/null 2>&1 ;;
                    "jq") apt-get install -y jq >/dev/null 2>&1 ;;
                    "bc") apt-get install -y bc >/dev/null 2>&1 ;;
                    "curl") apt-get install -y curl >/dev/null 2>&1 ;;
                    *) apt-get install -y "$tool" >/dev/null 2>&1 ;;
                esac
            done
            ;;
        "centos")
            yum install -y epel-release >/dev/null 2>&1 || true
            for tool in "${missing_tools[@]}"; do
                case $tool in
                    "nft") yum install -y nftables >/dev/null 2>&1 ;;
                    "tc"|"ss") yum install -y iproute >/dev/null 2>&1 ;;
                    "jq") yum install -y jq >/dev/null 2>&1 ;;
                    "bc") yum install -y bc >/dev/null 2>&1 ;;
                    "curl") yum install -y curl >/dev/null 2>&1 ;;
                    *) yum install -y "$tool" >/dev/null 2>&1 ;;
                esac
            done
            ;;
        "arch")
            for tool in "${missing_tools[@]}"; do
                case $tool in
                    "nft") pacman -S --noconfirm nftables >/dev/null 2>&1 ;;
                    "tc"|"ss") pacman -S --noconfirm iproute2 >/dev/null 2>&1 ;;
                    *) pacman -S --noconfirm "$tool" >/dev/null 2>&1 ;;
                esac
            done
            ;;
        "alpine")
            for tool in "${missing_tools[@]}"; do
                case $tool in
                    "nft") apk add nftables >/dev/null 2>&1 ;;
                    "tc"|"ss") apk add iproute2 >/dev/null 2>&1 ;;
                    *) apk add "$tool" >/dev/null 2>&1 ;;
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
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        install_missing_tools "${missing_tools[@]}"
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误：需要 root 权限${NC}"
        echo "请使用: sudo bash <(curl -fsSL URL)"
        exit 1
    fi
}

# ============================================================================
# 配置管理
# ============================================================================

load_nft_config() {
    [ -n "$NFT_TABLE" ] && return
    if [ -f "$CONFIG_FILE" ]; then
        NFT_TABLE=$(jq -r '.nftables.table_name // "port_monitor"' "$CONFIG_FILE" 2>/dev/null) || NFT_TABLE="port_monitor"
        NFT_FAMILY=$(jq -r '.nftables.family // "inet"' "$CONFIG_FILE" 2>/dev/null) || NFT_FAMILY="inet"
    else
        NFT_TABLE="port_monitor"
        NFT_FAMILY="inet"
    fi
}

init_config() {
    mkdir -p "$CONFIG_DIR" 2>/dev/null || true
    mkdir -p "$TRAFFIC_HISTORY_DIR" 2>/dev/null || true

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

    if [ $bytes -ge $BYTES_PER_TB ]; then
        printf "%.2fTB" "$(echo "scale=2; $bytes / $BYTES_PER_TB" | bc)"
    elif [ $bytes -ge $BYTES_PER_GB ]; then
        printf "%.2fGB" "$(echo "scale=2; $bytes / $BYTES_PER_GB" | bc)"
    elif [ $bytes -ge $BYTES_PER_MB ]; then
        printf "%.2fMB" "$(echo "scale=2; $bytes / $BYTES_PER_MB" | bc)"
    elif [ $bytes -ge $BYTES_PER_KB ]; then
        printf "%.2fKB" "$(echo "scale=2; $bytes / $BYTES_PER_KB" | bc)"
    else
        echo "${bytes}B"
    fi
}

format_rate() {
    local kbps=${1:-0}
    [[ ! "$kbps" =~ ^[0-9]+$ ]] && kbps=0

    if [ $kbps -ge $KBPS_PER_GBPS ]; then
        printf "%.2fGbps" "$(echo "scale=2; $kbps / $KBPS_PER_GBPS" | bc)"
    elif [ $kbps -ge $KBPS_PER_MBPS ]; then
        printf "%.2fMbps" "$(echo "scale=2; $kbps / $KBPS_PER_MBPS" | bc)"
    else
        echo "${kbps}Kbps"
    fi
}

# 自动补全速率单位 (默认 Mbps)
normalize_rate() {
    local input=$1
    [ -z "$input" ] && echo "" && return
    
    local input_lower=$(echo "$input" | tr '[:upper:]' '[:lower:]')
    
    # 已有单位，直接返回
    if [[ "$input_lower" =~ (kbps|mbps|gbps)$ ]]; then
        echo "$input"
    # 只有 k/m/g 后缀
    elif [[ "$input_lower" =~ ^([0-9]+\.?[0-9]*)k$ ]]; then
        echo "${BASH_REMATCH[1]}Kbps"
    elif [[ "$input_lower" =~ ^([0-9]+\.?[0-9]*)m$ ]]; then
        echo "${BASH_REMATCH[1]}Mbps"
    elif [[ "$input_lower" =~ ^([0-9]+\.?[0-9]*)g$ ]]; then
        echo "${BASH_REMATCH[1]}Gbps"
    # 纯数字，默认 Mbps
    elif [[ "$input" =~ ^[0-9]+\.?[0-9]*$ ]]; then
        echo "${input}Mbps"
    else
        echo "$input"
    fi
}

# 自动补全流量单位 (默认 GB)
normalize_size() {
    local input=$1
    [ -z "$input" ] && echo "" && return
    
    local input_upper=$(echo "$input" | tr '[:lower:]' '[:upper:]')
    
    # 已有完整单位
    if [[ "$input_upper" =~ (KB|MB|GB|TB)$ ]]; then
        echo "$input"
    # 只有 k/m/g/t 后缀
    elif [[ "$input_upper" =~ ^([0-9]+\.?[0-9]*)K$ ]]; then
        echo "${BASH_REMATCH[1]}KB"
    elif [[ "$input_upper" =~ ^([0-9]+\.?[0-9]*)M$ ]]; then
        echo "${BASH_REMATCH[1]}MB"
    elif [[ "$input_upper" =~ ^([0-9]+\.?[0-9]*)G$ ]]; then
        echo "${BASH_REMATCH[1]}GB"
    elif [[ "$input_upper" =~ ^([0-9]+\.?[0-9]*)T$ ]]; then
        echo "${BASH_REMATCH[1]}TB"
    # 纯数字，默认 GB
    elif [[ "$input" =~ ^[0-9]+\.?[0-9]*$ ]]; then
        echo "${input}GB"
    else
        echo "$input"
    fi
}

parse_size_to_bytes() {
    local size_str=$1
    local number=$(echo "$size_str" | grep -oE '^[0-9]+\.?[0-9]*')
    local unit=$(echo "$size_str" | grep -oE '[A-Za-z]+$' | tr '[:lower:]' '[:upper:]')

    [ -z "$number" ] && echo "0" && return 1

    local multiplier=0
    case $unit in
        "KB"|"K") multiplier=$BYTES_PER_KB ;;
        "MB"|"M") multiplier=$BYTES_PER_MB ;;
        "GB"|"G") multiplier=$BYTES_PER_GB ;;
        "TB"|"T") multiplier=$BYTES_PER_TB ;;
        *) echo "0" && return 1 ;;
    esac

    echo "scale=0; $number * $multiplier / 1" | bc
}

parse_rate_to_kbps() {
    local rate=$1
    local rate_lower=$(echo "$rate" | tr '[:upper:]' '[:lower:]')
    local number=$(echo "$rate_lower" | grep -oE '^[0-9]+')
    
    [ -z "$number" ] && echo "0" && return
    
    if [[ "$rate_lower" =~ kbps$ ]]; then echo "$number"
    elif [[ "$rate_lower" =~ mbps$ ]]; then echo $((number * 1000))
    elif [[ "$rate_lower" =~ gbps$ ]]; then echo $((number * 1000000))
    else echo "0"; fi
}

get_beijing_time() { TZ='Asia/Shanghai' date "$@"; }
get_timestamp() { date +%s; }

jq_safe() {
    local result
    result=$(jq -r "$1" "$2" 2>/dev/null) || result=""
    [ -z "$result" ] || [ "$result" = "null" ] && echo "${3:-}" || echo "$result"
}

update_config() {
    local tmp
    tmp=$(mktemp "${CONFIG_FILE}.XXXXXX") || {
        log_error "Failed to create temporary file"
        return 1
    }

    if jq "$1" "$CONFIG_FILE" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$CONFIG_FILE"
    else
        rm -f "$tmp"
        return 1
    fi
}

update_json_file() {
    local file=$1
    local expr=$2
    local tmp
    tmp=$(mktemp "${file}.XXXXXX") || {
        log_error "Failed to create temporary file for $file"
        return 1
    }

    if jq "$expr" "$file" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$file"
    else
        rm -f "$tmp"
        return 1
    fi
}

get_active_ports() {
    [ ! -f "$CONFIG_FILE" ] && return
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
        [ "$start" -ge $PORT_MIN ] && [ "$end" -le $PORT_MAX ] && [ "$start" -lt "$end" ]
    else
        [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge $PORT_MIN ] && [ "$port" -le $PORT_MAX ]
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
    local input=${1:-0} output=${2:-0} mode=${3:-"single"}
    [ "$mode" = "double" ] && echo $((input + output)) || echo $output
}

save_traffic_data() {
    local active_ports
    active_ports=($(get_active_ports 2>/dev/null)) || return 0
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
    trap 'save_traffic_data >/dev/null 2>&1; release_lock' EXIT
    trap 'save_traffic_data >/dev/null 2>&1; release_lock; exit 1' INT TERM
}

restore_monitoring_if_needed() {
    local active_ports
    active_ports=($(get_active_ports 2>/dev/null)) || return 0
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

    local port
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
    local port
    for port in $(get_active_ports); do
        add_nftables_rules "$port"
        local quota=$(jq_safe ".ports.\"$port\".quota.limit" "$CONFIG_FILE" "unlimited")
        [ "$quota" != "unlimited" ] && apply_quota "$port" "$quota"
        
        local throttled=$(jq_safe ".\"$port\".throttled" "$BURST_STATE_FILE" "false")
        if [ "$throttled" = "true" ]; then
            local throttle_rate=$(jq_safe ".\"$port\".throttle_rate" "$BURST_STATE_FILE" "")
            [ -n "$throttle_rate" ] && apply_tc_limit "$port" "$throttle_rate"
        else
            local rate=$(jq_safe ".ports.\"$port\".bandwidth.rate" "$CONFIG_FILE" "unlimited")
            [ "$rate" != "unlimited" ] && apply_tc_limit "$port" "$rate"
        fi
        
        setup_reset_cron "$port"
    done
}

# ============================================================================
# 流量历史记录
# ============================================================================

record_traffic_snapshot() {
    local port=$1
    local port_safe=$(get_port_safe "$port")
    local history_file="$TRAFFIC_HISTORY_DIR/${port_safe}.log"

    local traffic=($(get_port_traffic "$port"))
    local timestamp=$(get_timestamp)
    local total=$((${traffic[0]} + ${traffic[1]}))

    # 检查数据有效性 - 避免记录异常数据
    if [ -f "$history_file" ]; then
        local last_line
        last_line=$(tail -n 1 "$history_file" 2>/dev/null)
        if [ -n "$last_line" ]; then
            local last_ts last_bytes
            read -r last_ts last_bytes <<< "$last_line"
            # 跳过时间回退或流量回退的异常情况 (流量重置除外)
            if [ "$timestamp" -le "$last_ts" ]; then
                return
            fi
            # 如果流量小于上次记录，说明可能是重置，清空历史
            if [ "$total" -lt "$last_bytes" ]; then
                echo "$timestamp $total" > "$history_file"
                return
            fi
        fi
    fi

    echo "$timestamp $total" >> "$history_file"

    # 清理过旧的记录
    if [ -f "$history_file" ]; then
        local lines
        lines=$(wc -l < "$history_file" 2>/dev/null || echo "0")
        if [ "$lines" -gt $TRAFFIC_HISTORY_MAX_LINES ]; then
            tail -n $TRAFFIC_HISTORY_KEEP_LINES "$history_file" > "${history_file}.tmp" && \
                mv "${history_file}.tmp" "$history_file"
        fi
    fi
}

# 计算指定时间窗口内的平均速率 (Kbps)
get_average_rate() {
    local port=$1
    local window_minutes=${2:-5}
    local port_safe=$(get_port_safe "$port")
    local history_file="$TRAFFIC_HISTORY_DIR/${port_safe}.log"

    [ ! -f "$history_file" ] && echo "0" && return

    local now=$(get_timestamp)
    local window_start=$((now - window_minutes * 60))
    local first_ts=0 first_bytes=0 last_ts=0 last_bytes=0
    local count=0

    while read -r ts bytes; do
        [ "$ts" -lt "$window_start" ] && continue
        if [ $count -eq 0 ]; then
            first_ts=$ts
            first_bytes=$bytes
        fi
        last_ts=$ts
        last_bytes=$bytes
        count=$((count + 1))
    done < "$history_file"

    if [ $count -lt 2 ] || [ "$last_ts" -eq "$first_ts" ]; then
        echo "0"
        return
    fi

    local time_diff=$((last_ts - first_ts))
    local bytes_diff=$((last_bytes - first_bytes))

    if [ $time_diff -gt 0 ] && [ $bytes_diff -ge 0 ]; then
        echo $((bytes_diff * 8 / time_diff / 1000))
    else
        echo "0"
    fi
}

get_high_rate_duration() {
    local port=$1
    local threshold_kbps=$2
    local port_safe=$(get_port_safe "$port")
    local history_file="$TRAFFIC_HISTORY_DIR/${port_safe}.log"

    [ ! -f "$history_file" ] && echo "0" && return

    local line_count
    line_count=$(wc -l < "$history_file" 2>/dev/null || echo "0")
    [ "$line_count" -lt 2 ] && echo "0" && return

    local prev_ts=0 prev_bytes=0
    local high_rate_start=0
    local consecutive_high=0
    local now=$(get_timestamp)

    # 使用滑动窗口 (3 个采样点) 计算平均速率，减少瞬时峰值误判
    local -a ts_history=() bytes_history=()

    while read -r ts bytes; do
        # 数据校验
        [[ ! "$ts" =~ ^[0-9]+$ ]] && continue
        [[ ! "$bytes" =~ ^[0-9]+$ ]] && continue

        ts_history+=("$ts")
        bytes_history+=("$bytes")

        # 保持窗口大小为 3
        if [ ${#ts_history[@]} -gt 3 ]; then
            ts_history=("${ts_history[@]:1}")
            bytes_history=("${bytes_history[@]:1}")
        fi

        if [ ${#ts_history[@]} -ge 2 ]; then
            local window_start_ts=${ts_history[0]}
            local window_start_bytes=${bytes_history[0]}
            local window_end_ts=${ts_history[-1]}
            local window_end_bytes=${bytes_history[-1]}

            local time_diff=$((window_end_ts - window_start_ts))
            local bytes_diff=$((window_end_bytes - window_start_bytes))

            if [ $time_diff -gt 0 ] && [ $bytes_diff -ge 0 ]; then
                local rate_kbps=$((bytes_diff * 8 / time_diff / 1000))

                if [ $rate_kbps -ge $threshold_kbps ]; then
                    consecutive_high=$((consecutive_high + 1))
                    # 需要连续 2 次超阈值才开始计时
                    if [ $consecutive_high -ge 2 ] && [ $high_rate_start -eq 0 ]; then
                        high_rate_start=$window_start_ts
                    fi
                else
                    consecutive_high=0
                    high_rate_start=0
                fi
            fi
        fi
        prev_ts=$ts
        prev_bytes=$bytes
    done < "$history_file"

    if [ $high_rate_start -gt 0 ]; then
        echo $(( (now - high_rate_start) / 60 ))
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

    local proto
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

    # 批量获取所有相关规则的 handle 和所属 chain
    local nft_output
    nft_output=$(nft -a list table $NFT_FAMILY $NFT_TABLE 2>/dev/null) || return

    local chain="" handle
    while IFS= read -r line; do
        # 检测 chain 声明
        if [[ "$line" =~ ^[[:space:]]*chain[[:space:]]+([a-zA-Z_]+) ]]; then
            chain="${BASH_REMATCH[1]}"
        # 检测包含端口计数器的规则
        elif [[ "$line" =~ port_${port_safe}_ ]] && [[ "$line" =~ \#[[:space:]]*handle[[:space:]]+([0-9]+) ]]; then
            handle="${BASH_REMATCH[1]}"
            [ -n "$chain" ] && [ -n "$handle" ] && \
                nft delete rule $NFT_FAMILY $NFT_TABLE "$chain" handle "$handle" 2>/dev/null || true
        fi
    done <<< "$nft_output"

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
    local billing=$(jq_safe ".ports.\"$port\".billing" "$CONFIG_FILE" "single")

    local quota_bytes=$(parse_size_to_bytes "$limit")
    [ "$quota_bytes" -eq 0 ] && return 1
    
    local traffic=($(get_port_traffic "$port"))
    local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
    local quota_name="port_${port_safe}_quota"

    nft add quota $NFT_FAMILY $NFT_TABLE $quota_name "{ over $quota_bytes bytes used $used bytes }" 2>/dev/null || true

    local proto
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

    # 批量获取所有配额规则的 handle 和所属 chain
    local nft_output
    nft_output=$(nft -a list table $NFT_FAMILY $NFT_TABLE 2>/dev/null) || {
        nft delete quota $NFT_FAMILY $NFT_TABLE "$quota_name" 2>/dev/null || true
        return
    }

    local chain="" handle
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*chain[[:space:]]+([a-zA-Z_]+) ]]; then
            chain="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ quota\ name\ \"$quota_name\" ]] && [[ "$line" =~ \#[[:space:]]*handle[[:space:]]+([0-9]+) ]]; then
            handle="${BASH_REMATCH[1]}"
            [ -n "$chain" ] && [ -n "$handle" ] && \
                nft delete rule $NFT_FAMILY $NFT_TABLE "$chain" handle "$handle" 2>/dev/null || true
        fi
    done <<< "$nft_output"

    nft delete quota $NFT_FAMILY $NFT_TABLE "$quota_name" 2>/dev/null || true
}

# ============================================================================
# TC 带宽限制
# ============================================================================

calculate_burst() {
    local rate_kbps=$1
    local burst_bytes=$(( rate_kbps * 1000 / 8 / BURST_CALC_DIVISOR ))
    [ $burst_bytes -lt $MIN_BURST_BYTES ] && burst_bytes=$MIN_BURST_BYTES

    if [ $burst_bytes -ge $BYTES_PER_MB ]; then echo "$((burst_bytes / BYTES_PER_MB))m"
    elif [ $burst_bytes -ge $BYTES_PER_KB ]; then echo "$((burst_bytes / BYTES_PER_KB))k"
    else echo "$burst_bytes"; fi
}

# TC class ID 管理 - 使用持久化映射避免碰撞
init_tc_class_ids() {
    [ ! -f "$TC_CLASS_ID_FILE" ] && echo '{"next_id": 256, "mappings": {}}' > "$TC_CLASS_ID_FILE"
}

get_tc_class_id() {
    local port=$1
    init_tc_class_ids

    # 检查是否已有映射
    local existing_id
    existing_id=$(jq -r ".mappings.\"$port\" // empty" "$TC_CLASS_ID_FILE" 2>/dev/null)

    if [ -n "$existing_id" ]; then
        printf "1:%x" "$existing_id"
        return
    fi

    # 分配新 ID (范围 0x100 - 0xFFFF)
    local next_id
    next_id=$(jq -r '.next_id' "$TC_CLASS_ID_FILE" 2>/dev/null)
    [ -z "$next_id" ] || [ "$next_id" = "null" ] && next_id=256

    # 更新映射文件
    local tmp
    tmp=$(mktemp "${TC_CLASS_ID_FILE}.XXXXXX")
    if jq ".mappings.\"$port\" = $next_id | .next_id = $((next_id + 1))" "$TC_CLASS_ID_FILE" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$TC_CLASS_ID_FILE"
    else
        rm -f "$tmp"
    fi

    printf "1:%x" "$next_id"
}

release_tc_class_id() {
    local port=$1
    [ ! -f "$TC_CLASS_ID_FILE" ] && return

    local tmp
    tmp=$(mktemp "${TC_CLASS_ID_FILE}.XXXXXX")
    if jq "del(.mappings.\"$port\")" "$TC_CLASS_ID_FILE" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$TC_CLASS_ID_FILE"
    else
        rm -f "$tmp"
    fi
}

setup_ifb() {
    local interface=$1

    modprobe ifb numifbs=1 2>/dev/null || true
    ip link set ifb0 up 2>/dev/null || true
    tc qdisc add dev "$interface" handle ffff: ingress 2>/dev/null || true
    tc qdisc add dev ifb0 root handle 1: htb default 30 2>/dev/null || true
    tc class add dev ifb0 parent 1: classid 1:1 htb rate 10gbit 2>/dev/null || true
}

# 获取端口对应的 filter 优先级 (基于 class ID 确保唯一)
get_tc_filter_prio() {
    local port=$1
    init_tc_class_ids

    local class_id_num
    class_id_num=$(jq -r ".mappings.\"$port\" // empty" "$TC_CLASS_ID_FILE" 2>/dev/null)

    if [ -n "$class_id_num" ]; then
        # 使用 class ID 作为优先级基础，确保唯一
        echo "$class_id_num"
    else
        # 降级方案：使用端口号
        if is_port_range "$port"; then
            local start=$(echo "$port" | cut -d'-' -f1)
            echo "$start"
        else
            echo "$port"
        fi
    fi
}

apply_tc_limit() {
    local port=$1 rate=$2
    local interface=$(get_default_interface)
    [ -z "$interface" ] && interface="$DEFAULT_INTERFACE"

    local tc_rate rate_lower=$(echo "$rate" | tr '[:upper:]' '[:lower:]')
    if [[ "$rate_lower" =~ kbps$ ]]; then tc_rate=$(echo "$rate_lower" | sed 's/kbps$/kbit/')
    elif [[ "$rate_lower" =~ mbps$ ]]; then tc_rate=$(echo "$rate_lower" | sed 's/mbps$/mbit/')
    elif [[ "$rate_lower" =~ gbps$ ]]; then tc_rate=$(echo "$rate_lower" | sed 's/gbps$/gbit/')
    else return 1; fi

    local rate_kbps=$(parse_rate_to_kbps "$rate")
    [ "$rate_kbps" -eq 0 ] && return 1

    local burst=$(calculate_burst $rate_kbps)
    local class_id=$(get_tc_class_id "$port")
    local filter_prio=$(get_tc_filter_prio "$port")

    # 出站限速 (egress)
    tc qdisc add dev "$interface" root handle 1: htb default 30 2>/dev/null || true
    tc class add dev "$interface" parent 1: classid 1:1 htb rate 10gbit 2>/dev/null || true

    tc class del dev "$interface" classid "$class_id" 2>/dev/null || true
    tc class add dev "$interface" parent 1:1 classid "$class_id" htb rate "$tc_rate" ceil "$tc_rate" burst "$burst" cburst "$burst"

    local proto_num
    for proto_num in 6 17; do
        tc filter add dev "$interface" protocol ip parent 1:0 prio "$filter_prio" u32 \
            match ip protocol "$proto_num" 0xff match ip sport "$port" 0xffff flowid "$class_id" 2>/dev/null || true
    done

    # 入站限速 (ingress via IFB) - 只重定向目标端口的流量
    setup_ifb "$interface"

    local ifb_class_id="1:$(printf '%x' $(( 0x${class_id#1:} + 0x1000 )))"
    local ifb_prio=$((filter_prio + 10000))

    tc class del dev ifb0 classid "$ifb_class_id" 2>/dev/null || true
    tc class add dev ifb0 parent 1:1 classid "$ifb_class_id" htb rate "$tc_rate" ceil "$tc_rate" burst "$burst" cburst "$burst" 2>/dev/null || true

    # 针对特定端口的流量重定向到 IFB 并分类
    for proto_num in 6 17; do
        # 先重定向匹配端口的流量到 IFB
        tc filter add dev "$interface" parent ffff: protocol ip prio "$ifb_prio" u32 \
            match ip protocol "$proto_num" 0xff match ip dport "$port" 0xffff \
            action mirred egress redirect dev ifb0 2>/dev/null || true
        # 在 IFB 上分类
        tc filter add dev ifb0 protocol ip parent 1:0 prio "$filter_prio" u32 \
            match ip protocol "$proto_num" 0xff match ip dport "$port" 0xffff flowid "$ifb_class_id" 2>/dev/null || true
    done
}

remove_tc_limit() {
    local port=$1
    local interface=$(get_default_interface)
    [ -z "$interface" ] && interface="$DEFAULT_INTERFACE"

    local class_id=$(get_tc_class_id "$port")
    local filter_prio=$(get_tc_filter_prio "$port")
    local ifb_prio=$((filter_prio + 10000))

    # 删除出站限速规则
    local proto_num
    for proto_num in 6 17; do
        tc filter del dev "$interface" protocol ip parent 1:0 prio "$filter_prio" u32 \
            match ip protocol "$proto_num" 0xff match ip sport "$port" 0xffff 2>/dev/null || true
    done
    tc class del dev "$interface" classid "$class_id" 2>/dev/null || true

    # 删除入站限速规则
    local ifb_class_id="1:$(printf '%x' $(( 0x${class_id#1:} + 0x1000 )))"

    for proto_num in 6 17; do
        # 删除 ingress 重定向 filter
        tc filter del dev "$interface" parent ffff: protocol ip prio "$ifb_prio" u32 \
            match ip protocol "$proto_num" 0xff match ip dport "$port" 0xffff 2>/dev/null || true
        # 删除 IFB 分类 filter
        tc filter del dev ifb0 protocol ip parent 1:0 prio "$filter_prio" u32 \
            match ip protocol "$proto_num" 0xff match ip dport "$port" 0xffff 2>/dev/null || true
    done
    tc class del dev ifb0 classid "$ifb_class_id" 2>/dev/null || true
}

# ============================================================================
# 突发速率保护
# ============================================================================

check_burst_protection() {
    acquire_lock 3 || return 0
    
    local ports=($(get_active_ports))
    local port
    
    for port in "${ports[@]}"; do
        local burst_enabled=$(jq_safe ".ports.\"$port\".burst_protection.enabled" "$CONFIG_FILE" "false")
        [ "$burst_enabled" != "true" ] && continue
        
        local burst_rate=$(jq_safe ".ports.\"$port\".burst_protection.burst_rate" "$CONFIG_FILE" "")
        local burst_window=$(jq_safe ".ports.\"$port\".burst_protection.burst_window" "$CONFIG_FILE" "30")
        local throttle_rate=$(jq_safe ".ports.\"$port\".burst_protection.throttle_rate" "$CONFIG_FILE" "")
        local throttle_duration=$(jq_safe ".ports.\"$port\".burst_protection.throttle_duration" "$CONFIG_FILE" "10")
        
        [ -z "$burst_rate" ] || [ -z "$throttle_rate" ] && continue
        
        local burst_rate_kbps=$(parse_rate_to_kbps "$burst_rate")
        [ "$burst_rate_kbps" -eq 0 ] && continue
        
        record_traffic_snapshot "$port"
        
        local throttled=$(jq_safe ".\"$port\".throttled" "$BURST_STATE_FILE" "false")
        local throttle_start=$(jq_safe ".\"$port\".throttle_start" "$BURST_STATE_FILE" "0")
        
        if [ "$throttled" = "true" ]; then
            local now=$(get_timestamp)
            local elapsed=$(( (now - throttle_start) / 60 ))
            
            if [ "$elapsed" -ge "$throttle_duration" ]; then
                release_burst_throttle "$port"
            fi
        else
            local high_duration=$(get_high_rate_duration "$port" "$burst_rate_kbps")
            
            if [ "$high_duration" -ge "$burst_window" ]; then
                apply_burst_throttle "$port" "$throttle_rate"
            fi
        fi
    done
    
    release_lock
}

apply_burst_throttle() {
    local port=$1
    local throttle_rate=$2
    
    remove_tc_limit "$port"
    apply_tc_limit "$port" "$throttle_rate"
    
    local now=$(get_timestamp)
    update_json_file "$BURST_STATE_FILE" ".\"$port\" = {\"throttled\": true, \"throttle_start\": $now, \"throttle_rate\": \"$throttle_rate\"}"
    
    send_burst_throttle_alert "$port" "$throttle_rate" "triggered"
}

release_burst_throttle() {
    local port=$1
    
    remove_tc_limit "$port"
    local original_rate=$(jq_safe ".ports.\"$port\".bandwidth.rate" "$CONFIG_FILE" "unlimited")
    [ "$original_rate" != "unlimited" ] && apply_tc_limit "$port" "$original_rate"
    
    update_json_file "$BURST_STATE_FILE" "del(.\"$port\")"
    
    local port_safe=$(get_port_safe "$port")
    local history_file="$TRAFFIC_HISTORY_DIR/${port_safe}.log"
    [ -f "$history_file" ] && tail -n 1 "$history_file" > "${history_file}.tmp" && mv "${history_file}.tmp" "$history_file"
    
    send_burst_throttle_alert "$port" "" "released"
}

send_burst_throttle_alert() {
    local port=$1
    local throttle_rate=$2
    local action=$3
    
    local telegram_enabled=$(jq_safe ".telegram.enabled" "$CONFIG_FILE" "false")
    [ "$telegram_enabled" != "true" ] && return
    
    local server_name=$(jq_safe ".telegram.server_name" "$CONFIG_FILE" "$(hostname)")
    local remark=$(jq_safe ".ports.\"$port\".remark" "$CONFIG_FILE" "")
    local remark_display=""
    [ -n "$remark" ] && remark_display=" ($remark)"
    
    local message
    if [ "$action" = "triggered" ]; then
        local burst_rate=$(jq_safe ".ports.\"$port\".burst_protection.burst_rate" "$CONFIG_FILE" "")
        local burst_window=$(jq_safe ".ports.\"$port\".burst_protection.burst_window" "$CONFIG_FILE" "30")
        local throttle_duration=$(jq_safe ".ports.\"$port\".burst_protection.throttle_duration" "$CONFIG_FILE" "10")
        
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

get_burst_status() {
    local port=$1
    
    local enabled=$(jq_safe ".ports.\"$port\".burst_protection.enabled" "$CONFIG_FILE" "false")
    [ "$enabled" != "true" ] && echo "disabled" && return
    
    local throttled=$(jq_safe ".\"$port\".throttled" "$BURST_STATE_FILE" "false")
    
    if [ "$throttled" = "true" ]; then
        local throttle_start=$(jq_safe ".\"$port\".throttle_start" "$BURST_STATE_FILE" "0")
        local throttle_duration=$(jq_safe ".ports.\"$port\".burst_protection.throttle_duration" "$CONFIG_FILE" "10")
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

    local reset_day=$(jq_safe ".ports.\"$port\".quota.reset_day" "$CONFIG_FILE" "")
    local limit=$(jq_safe ".ports.\"$port\".quota.limit" "$CONFIG_FILE" "unlimited")

    if [ -n "$reset_day" ] && [ "$limit" != "unlimited" ]; then
        echo "5 0 $reset_day * * $SCRIPT_PATH --reset $port >/dev/null 2>&1  # 端口流量监控重置$port" >> "$temp_cron"
    fi
    crontab "$temp_cron" 2>/dev/null || true
    rm -f "$temp_cron"
}

remove_reset_cron() {
    local port=$1
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "端口流量监控重置$port\$" > "$temp_cron" || true
    crontab "$temp_cron" 2>/dev/null || true
    rm -f "$temp_cron"
}

setup_notify_cron() {
    local interval=$1
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "端口流量监控状态通知" | grep -v "端口流量监控阈值检查" | grep -v "端口流量监控突发检测" > "$temp_cron" || true

    if [ -n "$interval" ] && [ "$interval" != "0" ]; then
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

    local alert_enabled=$(jq_safe ".telegram.alert_enabled" "$CONFIG_FILE" "true")
    local telegram_enabled=$(jq_safe ".telegram.enabled" "$CONFIG_FILE" "false")
    [ "$alert_enabled" = "true" ] && [ "$telegram_enabled" = "true" ] && echo "*/5 * * * * $SCRIPT_PATH --check-alert >/dev/null 2>&1  # 端口流量监控阈值检查" >> "$temp_cron"

    local has_burst=false
    local port
    for port in $(get_active_ports); do
        local burst_enabled=$(jq_safe ".ports.\"$port\".burst_protection.enabled" "$CONFIG_FILE" "false")
        [ "$burst_enabled" = "true" ] && has_burst=true && break
    done
    [ "$has_burst" = "true" ] && echo "* * * * * $SCRIPT_PATH --check-burst >/dev/null 2>&1  # 端口流量监控突发检测" >> "$temp_cron"

    crontab "$temp_cron" 2>/dev/null || true
    rm -f "$temp_cron"
}

remove_notify_cron() {
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "端口流量监控状态通知" | grep -v "端口流量监控阈值检查" | grep -v "端口流量监控突发检测" > "$temp_cron" || true
    crontab "$temp_cron" 2>/dev/null || true
    rm -f "$temp_cron"
}

reset_port_traffic() {
    local port=$1
    local port_safe=$(get_port_safe "$port")

    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" >/dev/null 2>&1 || true
    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" >/dev/null 2>&1 || true
    nft reset quota $NFT_FAMILY $NFT_TABLE "port_${port_safe}_quota" >/dev/null 2>&1 || true

    update_json_file "$ALERT_STATE_FILE" "del(.\"$port\")" 2>/dev/null || true
    
    rm -f "$TRAFFIC_HISTORY_DIR/${port_safe}.log"
}

# ============================================================================
# Telegram 通知
# ============================================================================

telegram_send() {
    local message=$1
    local bot_token=$(jq_safe ".telegram.bot_token" "$CONFIG_FILE" "")
    local chat_id=$(jq_safe ".telegram.chat_id" "$CONFIG_FILE" "")

    [ -z "$bot_token" ] || [ -z "$chat_id" ] && return 1

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
    local server_name=$(jq_safe ".telegram.server_name" "$CONFIG_FILE" "$(hostname)")
    local timestamp=$(get_beijing_time '+%Y-%m-%d %H:%M:%S')
    local ports=($(get_active_ports))
    local total=0 port_info=""
    local port

    for port in "${ports[@]}"; do
        local traffic=($(get_port_traffic "$port"))
        local billing=$(jq_safe ".ports.\"$port\".billing" "$CONFIG_FILE" "single")
        local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
        total=$((total + used))

        local remark=$(jq_safe ".ports.\"$port\".remark" "$CONFIG_FILE" "")
        local limit=$(jq_safe ".ports.\"$port\".quota.limit" "$CONFIG_FILE" "unlimited")

        local remark_display="" percent_display="" burst_display="" rate_display=""
        [ -n "$remark" ] && remark_display=" ($remark)"

        if [ "$limit" != "unlimited" ]; then
            local limit_bytes=$(parse_size_to_bytes "$limit")
            [ "$limit_bytes" -gt 0 ] && percent_display=" [$(( used * 100 / limit_bytes ))%]"
        fi

        local burst_status=$(get_burst_status "$port")
        case "$burst_status" in
            throttled:*) burst_display=" 🔽限速中" ;;
            normal) burst_display=" ⚡保护中" ;;
        esac

        # 获取实时速率
        local current_rate_kbps=$(get_average_rate "$port" 5)
        [ "$current_rate_kbps" -gt 0 ] && rate_display=" 📶$(format_rate $current_rate_kbps)"

        port_info+="
📌 端口 ${port}${remark_display}${percent_display}${burst_display}${rate_display}
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
    local telegram_enabled=$(jq_safe ".telegram.enabled" "$CONFIG_FILE" "false")
    local alert_enabled=$(jq_safe ".telegram.alert_enabled" "$CONFIG_FILE" "true")

    [ "$telegram_enabled" != "true" ] || [ "$alert_enabled" != "true" ] && return 0

    local ports=($(get_active_ports))
    local port
    
    for port in "${ports[@]}"; do
        local limit=$(jq_safe ".ports.\"$port\".quota.limit" "$CONFIG_FILE" "unlimited")
        [ "$limit" = "unlimited" ] && continue

        local limit_bytes=$(parse_size_to_bytes "$limit")
        [ "$limit_bytes" -eq 0 ] && continue

        local traffic=($(get_port_traffic "$port"))
        local billing=$(jq_safe ".ports.\"$port\".billing" "$CONFIG_FILE" "single")
        local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
        local percent=$((used * 100 / limit_bytes))

        local sent_threshold=$(jq_safe ".\"$port\"" "$ALERT_STATE_FILE" "0")
        [[ ! "$sent_threshold" =~ ^[0-9]+$ ]] && sent_threshold=0

        local threshold
        for threshold in "${ALERT_THRESHOLDS[@]}"; do
            if [ $percent -ge $threshold ] && [ $sent_threshold -lt $threshold ]; then
                send_threshold_alert "$port" "$percent" "$threshold" "$used" "$limit"
                update_json_file "$ALERT_STATE_FILE" ".\"$port\" = $threshold"
                break
            fi
        done
    done
}

send_threshold_alert() {
    local port=$1 percent=$2 threshold=$3 used=$4 limit=$5

    local server_name=$(jq_safe ".telegram.server_name" "$CONFIG_FILE" "$(hostname)")
    local remark=$(jq_safe ".ports.\"$port\".remark" "$CONFIG_FILE" "")
    local remark_display=""
    [ -n "$remark" ] && remark_display=" ($remark)"

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

    local system_ports="20|21|22|23|25|53|67|68|80|110|143|443|465|546|587|993|995|3306|5432|6379"
    echo -e "${GREEN}当前系统监听端口 (已过滤常用端口):${NC}"
    local ports_list=$(ss -tulnp 2>/dev/null | grep -E "LISTEN|UNCONN" | awk '{print $5}' | \
        grep -oE '[0-9]+$' | sort -nu | grep -vE "^($system_ports)$" | head -20 | tr '\n' ' ')
    [ -n "$ports_list" ] && echo "$ports_list" || echo -e "${YELLOW}无可用端口${NC}"
    echo

    read -p "请输入端口号 (多个用逗号分隔, 支持范围如 8000-8010): " port_input
    [ -z "$port_input" ] && return

    local ports=()
    local part
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
    read -p "流量配额 (默认单位GB, 如 100 或 1.5T, 留空无限制): " quota_input
    local quota="unlimited" reset_day=""
    if [ -n "$quota_input" ]; then
        local normalized_quota=$(normalize_size "$quota_input")
        local quota_bytes=$(parse_size_to_bytes "$normalized_quota")
        if [ "$quota_bytes" -gt 0 ]; then
            quota="$normalized_quota"
            read -p "每月重置日 (1-31, 留空默认1日, 0=不重置): " reset_input
            if [ -z "$reset_input" ]; then
                reset_day="1"
            elif [ "$reset_input" != "0" ]; then
                reset_day="$reset_input"
            fi
        else
            echo -e "${RED}无效的配额格式，使用无限制${NC}"
        fi
    fi

    read -p "带宽限制 (默认单位Mbps, 如 100 或 1G, 留空无限制): " rate_input
    local rate="unlimited"
    if [ -n "$rate_input" ]; then
        rate=$(normalize_rate "$rate_input")
    fi

    read -p "备注 (可选): " remark
    remark=$(escape_json "$remark")

    local port
    for port in "${ports[@]}"; do
        if jq -e ".ports.\"$port\"" "$CONFIG_FILE" >/dev/null 2>&1; then
            echo -e "${YELLOW}端口 $port 已存在，跳过${NC}"
            continue
        fi

        local reset_day_json="null"
        [ -n "$reset_day" ] && reset_day_json="$reset_day"

        local config="{\"billing\": \"$billing\", \"quota\": {\"limit\": \"$quota\", \"reset_day\": $reset_day_json}, \"bandwidth\": {\"rate\": \"$rate\"}, \"remark\": \"$remark\", \"created\": \"$(get_beijing_time -Iseconds)\"}"

        update_config ".ports.\"$port\" = $config"
        add_nftables_rules "$port"
        [ "$quota" != "unlimited" ] && apply_quota "$port" "$quota"
        [ "$rate" != "unlimited" ] && apply_tc_limit "$port" "$rate"
        [ -n "$reset_day" ] && setup_reset_cron "$port"

        echo -e "${GREEN}✓ 端口 $port 添加成功${NC}"
    done
    sleep 1
}

remove_port() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && sleep 1 && return

    echo -e "${CYAN}=== 删除端口监控 ===${NC}\n"
    local i port
    for i in "${!ports[@]}"; do
        port=${ports[$i]}
        local remark=$(jq_safe ".ports.\"$port\".remark" "$CONFIG_FILE" "")
        local remark_display=""
        [ -n "$remark" ] && remark_display=" ($remark)"
        echo "  $((i+1)). 端口 $port$remark_display"
    done
    echo

    read -p "选择要删除的端口 (多个用逗号分隔): " choice
    [ -z "$choice" ] && return

    local sel
    IFS=',' read -ra selections <<< "$choice"
    for sel in "${selections[@]}"; do
        sel=$(echo "$sel" | tr -d ' ')
        [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && continue

        port=${ports[$((sel-1))]}
        read -p "确认删除端口 $port? [y/N]: " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && continue

        remove_nftables_rules "$port"
        remove_quota "$port"
        remove_tc_limit "$port"
        release_tc_class_id "$port"
        remove_reset_cron "$port"
        update_config "del(.ports.\"$port\")"

        update_json_file "$ALERT_STATE_FILE" "del(.\"$port\")" 2>/dev/null || true
        update_json_file "$BURST_STATE_FILE" "del(.\"$port\")" 2>/dev/null || true

        local port_safe=$(get_port_safe "$port")
        rm -f "$TRAFFIC_HISTORY_DIR/${port_safe}.log"

        if command -v conntrack >/dev/null 2>&1; then
            conntrack -D -p tcp --dport "$port" 2>/dev/null || true
            conntrack -D -p udp --dport "$port" 2>/dev/null || true
        fi

        echo -e "${GREEN}✓ 端口 $port 已删除${NC}"
    done
    
    setup_notify_cron "$(jq_safe '.telegram.notify_interval' "$CONFIG_FILE" "")"
    sleep 1
}

set_bandwidth() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && sleep 1 && return

    echo -e "${CYAN}=== 设置带宽限制 ===${NC}\n"
    local i port
    for i in "${!ports[@]}"; do
        port=${ports[$i]}
        local rate=$(jq_safe ".ports.\"$port\".bandwidth.rate" "$CONFIG_FILE" "unlimited")
        local burst_status=$(get_burst_status "$port")
        local status_display=""
        [ "$burst_status" != "disabled" ] && status_display=" [突发保护]"
        echo "  $((i+1)). 端口 $port [当前: $rate]$status_display"
    done
    echo

    read -p "选择端口: " sel
    [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && return

    port=${ports[$((sel-1))]}
    echo -e "\n默认单位 Mbps (如 100 表示 100Mbps, 1G 表示 1Gbps)"
    read -p "带宽限制 (0=取消): " rate_input

    if [ "$rate_input" = "0" ] || [ -z "$rate_input" ]; then
        remove_tc_limit "$port"
        update_config ".ports.\"$port\".bandwidth.rate = \"unlimited\""
        echo -e "${GREEN}✓ 已取消带宽限制${NC}"
    else
        local rate=$(normalize_rate "$rate_input")
        local throttled=$(jq_safe ".\"$port\".throttled" "$BURST_STATE_FILE" "false")
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
    local i port
    for i in "${!ports[@]}"; do
        port=${ports[$i]}
        local limit=$(jq_safe ".ports.\"$port\".quota.limit" "$CONFIG_FILE" "unlimited")
        local traffic=($(get_port_traffic "$port"))
        local billing=$(jq_safe ".ports.\"$port\".billing" "$CONFIG_FILE" "single")
        local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
        echo "  $((i+1)). 端口 $port [配额: $limit, 已用: $(format_bytes $used)]"
    done
    echo

    read -p "选择端口: " sel
    [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && return

    port=${ports[$((sel-1))]}
    echo -e "\n默认单位 GB (如 100 表示 100GB, 1.5T 表示 1.5TB)"
    read -p "流量配额 (0=取消): " limit_input

    if [ "$limit_input" = "0" ] || [ -z "$limit_input" ]; then
        remove_quota "$port"
        remove_reset_cron "$port"
        update_config ".ports.\"$port\".quota.limit = \"unlimited\" | .ports.\"$port\".quota.reset_day = null"
        update_json_file "$ALERT_STATE_FILE" "del(.\"$port\")" 2>/dev/null || true
        echo -e "${GREEN}✓ 已取消流量配额${NC}"
    else
        local limit=$(normalize_size "$limit_input")
        local limit_bytes=$(parse_size_to_bytes "$limit")
        if [ "$limit_bytes" -eq 0 ]; then
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
            update_config ".ports.\"$port\".quota.limit = \"$limit\" | .ports.\"$port\".quota.reset_day = null"
            remove_reset_cron "$port"
            echo -e "${GREEN}✓ 配额 $limit, 不自动重置${NC}"
        fi

        update_json_file "$ALERT_STATE_FILE" "del(.\"$port\")" 2>/dev/null || true
    fi
    sleep 1
}

reset_traffic() {
    local ports=($(get_active_ports))
    [ ${#ports[@]} -eq 0 ] && echo -e "${YELLOW}没有监控的端口${NC}" && sleep 1 && return

    echo -e "${CYAN}=== 重置流量统计 ===${NC}\n"
    local i port
    for i in "${!ports[@]}"; do
        port=${ports[$i]}
        local traffic=($(get_port_traffic "$port"))
        local billing=$(jq_safe ".ports.\"$port\".billing" "$CONFIG_FILE" "single")
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
        port=${ports[$((sel-1))]}
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
    local i port
    for i in "${!ports[@]}"; do
        port=${ports[$i]}
        local remark=$(jq_safe ".ports.\"$port\".remark" "$CONFIG_FILE" "")
        local remark_display="(无)"
        [ -n "$remark" ] && remark_display="$remark"
        echo "  $((i+1)). 端口 $port [备注: $remark_display]"
    done
    echo

    read -p "选择端口: " sel
    [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && return

    port=${ports[$((sel-1))]}
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
    
    local i port
    for i in "${!ports[@]}"; do
        port=${ports[$i]}
        local enabled=$(jq_safe ".ports.\"$port\".burst_protection.enabled" "$CONFIG_FILE" "false")
        local status_display="未启用"
        
        if [ "$enabled" = "true" ]; then
            local burst_rate=$(jq_safe ".ports.\"$port\".burst_protection.burst_rate" "$CONFIG_FILE" "")
            local burst_window=$(jq_safe ".ports.\"$port\".burst_protection.burst_window" "$CONFIG_FILE" "30")
            local throttle_rate=$(jq_safe ".ports.\"$port\".burst_protection.throttle_rate" "$CONFIG_FILE" "")
            local burst_status=$(get_burst_status "$port")
            
            status_display="${GREEN}已启用${NC} (>${burst_rate}持续${burst_window}分钟→${throttle_rate})"
            [ "$burst_status" != "normal" ] && [ "$burst_status" != "disabled" ] && status_display+=" ${RED}[限速中]${NC}"
        fi
        
        echo -e "  $((i+1)). 端口 $port [$status_display]"
    done
    echo

    read -p "选择端口: " sel
    [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt ${#ports[@]} ] && return

    port=${ports[$((sel-1))]}
    local enabled=$(jq_safe ".ports.\"$port\".burst_protection.enabled" "$CONFIG_FILE" "false")
    
    echo
    if [ "$enabled" = "true" ]; then
        echo "当前配置:"
        echo "  突发阈值: $(jq_safe ".ports.\"$port\".burst_protection.burst_rate" "$CONFIG_FILE" "")"
        echo "  持续时间: $(jq_safe ".ports.\"$port\".burst_protection.burst_window" "$CONFIG_FILE" "30") 分钟"
        echo "  限速至: $(jq_safe ".ports.\"$port\".burst_protection.throttle_rate" "$CONFIG_FILE" "")"
        echo "  限速时长: $(jq_safe ".ports.\"$port\".burst_protection.throttle_duration" "$CONFIG_FILE" "10") 分钟"
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
                local throttled=$(jq_safe ".\"$port\".throttled" "$BURST_STATE_FILE" "false")
                if [ "$throttled" = "true" ]; then
                    release_burst_throttle "$port"
                fi
                setup_notify_cron "$(jq_safe '.telegram.notify_interval' "$CONFIG_FILE" "")"
                echo -e "${GREEN}✓ 已禁用突发保护${NC}"
                ;;
            3)
                local throttled=$(jq_safe ".\"$port\".throttled" "$BURST_STATE_FILE" "false")
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
    echo -e "${YELLOW}示例: 当速率持续30分钟超过500Mbps时，自动限速到20Mbps，持续10分钟${NC}"
    echo
    
    local current_burst=$(jq_safe ".ports.\"$port\".burst_protection.burst_rate" "$CONFIG_FILE" "500Mbps")
    read -p "突发阈值 (默认单位Mbps, 如 100, 默认 $current_burst): " burst_rate_input
    local burst_rate
    if [ -z "$burst_rate_input" ]; then
        burst_rate="$current_burst"
    else
        burst_rate=$(normalize_rate "$burst_rate_input")
    fi
    
    if [ "$(parse_rate_to_kbps "$burst_rate")" -eq 0 ]; then
        echo -e "${RED}无效的速率格式${NC}"
        return
    fi
    
    local current_window=$(jq_safe ".ports.\"$port\".burst_protection.burst_window" "$CONFIG_FILE" "30")
    read -p "持续时间 (分钟, 默认 $current_window): " burst_window
    [ -z "$burst_window" ] && burst_window="$current_window"
    [[ ! "$burst_window" =~ ^[0-9]+$ ]] && burst_window=30
    
    local current_throttle=$(jq_safe ".ports.\"$port\".burst_protection.throttle_rate" "$CONFIG_FILE" "20Mbps")
    read -p "限速至 (默认单位Mbps, 如 20, 默认 $current_throttle): " throttle_rate_input
    local throttle_rate
    if [ -z "$throttle_rate_input" ]; then
        throttle_rate="$current_throttle"
    else
        throttle_rate=$(normalize_rate "$throttle_rate_input")
    fi
    
    if [ "$(parse_rate_to_kbps "$throttle_rate")" -eq 0 ]; then
        echo -e "${RED}无效的速率格式${NC}"
        return
    fi
    
    local current_duration=$(jq_safe ".ports.\"$port\".burst_protection.throttle_duration" "$CONFIG_FILE" "10")
    read -p "限速时长 (分钟, 默认 $current_duration): " throttle_duration
    [ -z "$throttle_duration" ] && throttle_duration="$current_duration"
    [[ ! "$throttle_duration" =~ ^[0-9]+$ ]] && throttle_duration=10
    
    local burst_config="{\"enabled\": true, \"burst_rate\": \"$burst_rate\", \"burst_window\": $burst_window, \"throttle_rate\": \"$throttle_rate\", \"throttle_duration\": $throttle_duration}"
    update_config ".ports.\"$port\".burst_protection = $burst_config"
    
    setup_notify_cron "$(jq_safe '.telegram.notify_interval' "$CONFIG_FILE" "")"
    
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

    local enabled=$(jq_safe ".telegram.enabled" "$CONFIG_FILE" "false")
    local token=$(jq_safe ".telegram.bot_token" "$CONFIG_FILE" "")
    local chat=$(jq_safe ".telegram.chat_id" "$CONFIG_FILE" "")
    local server=$(jq_safe ".telegram.server_name" "$CONFIG_FILE" "")
    local interval=$(jq_safe ".telegram.notify_interval" "$CONFIG_FILE" "")
    local alert=$(jq_safe ".telegram.alert_enabled" "$CONFIG_FILE" "true")

    echo "状态: $([ "$enabled" = "true" ] && echo -e "${GREEN}已启用${NC}" || echo -e "${YELLOW}未启用${NC}")"
    [ -n "$token" ] && echo "Bot Token: ${token:0:10}..."
    [ -n "$chat" ] && echo "Chat ID: $chat"
    [ -n "$server" ] && echo "服务器: $server"
    echo "定时推送: $([ -n "$interval" ] && echo "$interval" || echo "未设置")"
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
            if [ -n "$token" ] && [ -n "$chat" ]; then
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
                setup_notify_cron "$(jq_safe '.telegram.notify_interval' "$CONFIG_FILE" "")"
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
                setup_notify_cron "$(jq_safe '.telegram.notify_interval' "$CONFIG_FILE" "")"
                echo -e "${YELLOW}已禁用阈值告警${NC}"
            else
                update_config ".telegram.alert_enabled = true"
                setup_notify_cron "$(jq_safe '.telegram.notify_interval' "$CONFIG_FILE" "")"
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

    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}               ${CYAN}端口流量监控 v${SCRIPT_VERSION}${NC}                   ${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════╣${NC}"

    if [ ${#ports[@]} -eq 0 ]; then
        echo -e "${BLUE}║${NC}  ${YELLOW}暂无监控端口${NC}                                                ${BLUE}║${NC}"
    else
        local port
        for port in "${ports[@]}"; do
            local traffic=($(get_port_traffic "$port"))
            local billing=$(jq_safe ".ports.\"$port\".billing" "$CONFIG_FILE" "single")
            local used=$(calculate_total_traffic ${traffic[0]} ${traffic[1]} "$billing")
            total=$((total + used))

            local remark=$(jq_safe ".ports.\"$port\".remark" "$CONFIG_FILE" "")
            local limit=$(jq_safe ".ports.\"$port\".quota.limit" "$CONFIG_FILE" "unlimited")
            local rate=$(jq_safe ".ports.\"$port\".bandwidth.rate" "$CONFIG_FILE" "unlimited")

            local percent_display=""
            if [ "$limit" != "unlimited" ]; then
                local limit_bytes=$(parse_size_to_bytes "$limit")
                if [ "$limit_bytes" -gt 0 ]; then
                    local percent=$((used * 100 / limit_bytes))
                    if [ $percent -ge 100 ]; then percent_display=" ${RED}[${percent}%]${NC}"
                    elif [ $percent -ge 80 ]; then percent_display=" ${YELLOW}[${percent}%]${NC}"
                    else percent_display=" ${GREEN}[${percent}%]${NC}"; fi
                fi
            fi

            local burst_display=""
            local burst_status=$(get_burst_status "$port")
            case "$burst_status" in
                throttled:*)
                    local remaining=$(echo "$burst_status" | cut -d: -f2)
                    burst_display=" ${RED}🔽${remaining}${NC}"
                    ;;
                normal) burst_display=" ${GREEN}⚡${NC}" ;;
            esac

            # 获取实时速率 (基于最近 1 分钟)
            local current_rate_kbps=$(get_average_rate "$port" 1)
            local rate_display=""
            if [ "$current_rate_kbps" -gt 0 ]; then
                rate_display=" $(format_rate $current_rate_kbps)"
            fi

            printf "${BLUE}║${NC}  ${GREEN}%-8s${NC} ↑%-8s ↓%-8s 计:%-8s%b%b%b${BLUE}║${NC}\n" \
                "$port" "$(format_bytes ${traffic[0]})" "$(format_bytes ${traffic[1]})" "$(format_bytes $used)" "$percent_display" "$burst_display" "$rate_display"

            local tags=""
            [ -n "$remark" ] && tags+="[$remark] "
            [ "$limit" != "unlimited" ] && tags+="配额:$limit "
            [ "$rate" != "unlimited" ] && tags+="限速:$rate"
            [ -n "$tags" ] && printf "${BLUE}║${NC}    ${YELLOW}%-60s${NC}${BLUE}║${NC}\n" "$tags"
        done
    fi

    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════╣${NC}"
    printf "${BLUE}║${NC}  监控: ${GREEN}%-2d${NC} 个  总流量: ${GREEN}%-10s${NC}  快捷命令: ${CYAN}%-4s${NC}         ${BLUE}║${NC}\n" "${#ports[@]}" "$(format_bytes $total)" "$SHORTCUT_COMMAND"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
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

    local port
    for port in $(get_active_ports); do
        remove_nftables_rules "$port"
        remove_quota "$port"
        remove_tc_limit "$port"
        remove_reset_cron "$port"
    done

    remove_notify_cron
    nft delete table $NFT_FAMILY $NFT_TABLE 2>/dev/null || true

    local interface=$(get_default_interface)
    if [ -n "$interface" ]; then
        tc qdisc del dev "$interface" handle ffff: ingress 2>/dev/null || true
        tc qdisc del dev "$interface" root 2>/dev/null || true
    fi
    tc qdisc del dev ifb0 root 2>/dev/null || true
    ip link set ifb0 down 2>/dev/null || true

    rm -rf "$CONFIG_DIR"
    rm -f "/usr/local/bin/$SHORTCUT_COMMAND"
    rm -f "$SCRIPT_PATH"

    echo -e "${GREEN}卸载完成${NC}"
    exit 0
}

create_shortcut() {
    # 如果是远程安装，先保存脚本
    if [ "$REMOTE_INSTALL" = "true" ] && [ ! -f "$SCRIPT_PATH" ]; then
        echo -e "${YELLOW}首次运行，正在安装脚本...${NC}"
        
        # 从当前进程读取脚本内容
        local script_content
        script_content=$(cat "$0" 2>/dev/null) || script_content=""
        
        if [ -z "$script_content" ]; then
            # 尝试从网络下载
            local download_url="https://raw.githubusercontent.com/white-u/vps_script/main/port-manage.sh"
            echo "正在从 GitHub 下载..."
            if curl -fsSL "$download_url" -o "$SCRIPT_PATH" 2>/dev/null; then
                chmod +x "$SCRIPT_PATH"
                echo -e "${GREEN}✓ 脚本已安装到 $SCRIPT_PATH${NC}"
            else
                echo -e "${RED}下载失败，脚本将在内存中运行${NC}"
                echo -e "${YELLOW}建议手动下载脚本到 $SCRIPT_PATH${NC}"
            fi
        else
            echo "$script_content" > "$SCRIPT_PATH"
            chmod +x "$SCRIPT_PATH"
            echo -e "${GREEN}✓ 脚本已安装到 $SCRIPT_PATH${NC}"
        fi
    fi
    
    # 创建快捷命令
    if [ ! -f "/usr/local/bin/$SHORTCUT_COMMAND" ] && [ -f "$SCRIPT_PATH" ]; then
        cat > "/usr/local/bin/$SHORTCUT_COMMAND" << EOF
#!/bin/bash
exec bash "$SCRIPT_PATH" "\$@"
EOF
        chmod +x "/usr/local/bin/$SHORTCUT_COMMAND"
        echo -e "${GREEN}✓ 快捷命令 '$SHORTCUT_COMMAND' 已创建${NC}"
    fi
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
                [ "$(jq_safe '.telegram.enabled' "$CONFIG_FILE" "false")" = "true" ] && telegram_send "$(format_status_message)"
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
                if [ "$(jq_safe '.telegram.enabled' "$CONFIG_FILE" "false")" = "true" ]; then
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
