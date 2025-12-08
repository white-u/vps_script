#!/bin/bash
#
# Port Traffic Monitor v2.0
# 端口流量监控系统 - 完全重写版本
#
# 功能特性：
# - 基于 nftables 的流量统计
# - TC (Traffic Control) 带宽限制
# - 流量配额管理（月度重置）
# - 突发速率保护
# - Telegram 通知和告警
# - SQLite 数据存储（ACID 事务支持）
# - systemd timer 定时任务
# - flock 内核级锁机制
#

set -euo pipefail

# ============================================================================
# 常量定义
# ============================================================================

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="端口流量监控"
readonly SCRIPT_PATH="$(realpath "$0")"

# 路径配置
readonly CONFIG_DIR="/etc/port-traffic-monitor"
readonly DB_FILE="$CONFIG_DIR/config.db"
readonly LOG_DIR="/var/log/port-traffic-monitor"
readonly LOG_FILE="$LOG_DIR/daemon.log"
readonly LOCK_FILE="/var/run/port-traffic-monitor.lock"
readonly LOCK_FD=200

# 网络配置
readonly NFT_FAMILY="inet"
readonly NFT_TABLE="port_traffic"
readonly DEFAULT_INTERFACE="eth0"

# 流量计算常量
readonly BYTES_PER_KB=1024
readonly BYTES_PER_MB=1048576
readonly BYTES_PER_GB=1073741824
readonly BURST_CALC_DIVISOR=20
readonly MIN_BURST_BYTES=1600

# 快捷命令
readonly SHORTCUT_COMMAND="ptm"

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly GRAY='\033[0;90m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# ============================================================================
# 日志函数
# ============================================================================

log() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_daemon() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $*" >> "$LOG_FILE"
}

# ============================================================================
# 系统检查
# ============================================================================

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "需要 root 权限运行此脚本"
        echo "提示: sudo $0 $*"
        exit 1
    fi
}

check_dependencies() {
    local missing=()

    # 必需工具
    command -v nft >/dev/null 2>&1 || missing+=("nftables")
    command -v tc >/dev/null 2>&1 || missing+=("iproute2")
    command -v jq >/dev/null 2>&1 || missing+=("jq")
    command -v sqlite3 >/dev/null 2>&1 || missing+=("sqlite3")
    command -v bc >/dev/null 2>&1 || missing+=("bc")
    command -v systemctl >/dev/null 2>&1 || missing+=("systemd")

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "缺少必需工具: ${missing[*]}"
        echo ""
        echo "请安装缺失的工具："
        echo "  Debian/Ubuntu: apt install ${missing[*]}"
        echo "  CentOS/RHEL:   yum install ${missing[*]}"
        echo ""
        exit 1
    fi
}

# ============================================================================
# 锁机制（基于 flock）
# ============================================================================

lock_acquire() {
    local timeout=${1:-10}

    # 创建锁文件目录
    mkdir -p "$(dirname "$LOCK_FILE")"

    # 打开文件描述符
    eval "exec $LOCK_FD>$LOCK_FILE"

    # 尝试获取排他锁
    if flock -x -w "$timeout" $LOCK_FD; then
        echo $$ >&$LOCK_FD
        return 0
    else
        log_error "无法获取锁（超时 ${timeout}s），可能有其他实例正在运行"
        eval "exec $LOCK_FD>&-"
        return 1
    fi
}

lock_release() {
    # 关闭文件描述符会自动释放锁
    eval "exec $LOCK_FD>&-" 2>/dev/null || true
}

# ============================================================================
# SQLite 数据库抽象层
# ============================================================================

db_init() {
    mkdir -p "$CONFIG_DIR" "$LOG_DIR"

    if [ ! -f "$DB_FILE" ]; then
        log "初始化数据库..."

        sqlite3 "$DB_FILE" <<'EOF'
-- 端口配置表
CREATE TABLE IF NOT EXISTS ports (
    port TEXT PRIMARY KEY,
    remark TEXT DEFAULT '',
    billing_mode TEXT DEFAULT 'single' CHECK(billing_mode IN ('single', 'double')),
    tc_class_id TEXT UNIQUE,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- 流量配额配置
CREATE TABLE IF NOT EXISTS quotas (
    port TEXT PRIMARY KEY,
    limit_bytes INTEGER NOT NULL,
    reset_day INTEGER NOT NULL CHECK(reset_day >= 1 AND reset_day <= 31),
    last_reset INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY(port) REFERENCES ports(port) ON DELETE CASCADE
);

-- 带宽限制配置
CREATE TABLE IF NOT EXISTS bandwidth_limits (
    port TEXT PRIMARY KEY,
    rate_kbps INTEGER NOT NULL CHECK(rate_kbps > 0),
    FOREIGN KEY(port) REFERENCES ports(port) ON DELETE CASCADE
);

-- 突发保护配置
CREATE TABLE IF NOT EXISTS burst_protection (
    port TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 0 CHECK(enabled IN (0, 1)),
    burst_rate_kbps INTEGER NOT NULL,
    burst_window INTEGER DEFAULT 30 CHECK(burst_window > 0),
    throttle_rate_kbps INTEGER NOT NULL,
    throttle_duration INTEGER DEFAULT 10 CHECK(throttle_duration > 0),
    FOREIGN KEY(port) REFERENCES ports(port) ON DELETE CASCADE
);

-- 流量快照表（用于突发检测）
CREATE TABLE IF NOT EXISTS traffic_snapshots (
    port TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    input_bytes INTEGER NOT NULL,
    output_bytes INTEGER NOT NULL,
    PRIMARY KEY(port, timestamp),
    FOREIGN KEY(port) REFERENCES ports(port) ON DELETE CASCADE
);

-- 创建索引加速查询
CREATE INDEX IF NOT EXISTS idx_snapshots_port_time ON traffic_snapshots(port, timestamp DESC);

-- 突发保护状态
CREATE TABLE IF NOT EXISTS burst_state (
    port TEXT PRIMARY KEY,
    throttled INTEGER DEFAULT 0 CHECK(throttled IN (0, 1)),
    throttle_start INTEGER,
    throttle_rate_kbps INTEGER,
    FOREIGN KEY(port) REFERENCES ports(port) ON DELETE CASCADE
);

-- 告警历史（防止重复发送）
CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port TEXT NOT NULL,
    threshold INTEGER NOT NULL CHECK(threshold IN (30, 50, 80, 100)),
    sent_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY(port) REFERENCES ports(port) ON DELETE CASCADE
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_alert_port_threshold ON alert_history(port, threshold, sent_at DESC);

-- 全局配置表
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 初始化默认配置
INSERT OR IGNORE INTO config (key, value) VALUES
    ('telegram_enabled', 'false'),
    ('telegram_bot_token', ''),
    ('telegram_chat_id', ''),
    ('telegram_notify_interval', '0'),
    ('telegram_alert_enabled', 'true');

-- 触发器：自动更新 updated_at
CREATE TRIGGER IF NOT EXISTS ports_updated_at
AFTER UPDATE ON ports
FOR EACH ROW
BEGIN
    UPDATE ports SET updated_at = strftime('%s', 'now') WHERE port = NEW.port;
END;
EOF

        log_success "数据库初始化完成"
    fi
}

# 安全的数据库查询（返回 JSON）
db_query() {
    local sql="$1"
    sqlite3 -json "$DB_FILE" "$sql" 2>/dev/null || echo "[]"
}

# 执行 SQL 语句（无返回值）
db_exec() {
    local sql="$1"
    sqlite3 "$DB_FILE" "$sql" 2>/dev/null
}

# 事务执行（多条 SQL）
db_transaction() {
    local sql="$1"
    sqlite3 "$DB_FILE" <<EOF
BEGIN TRANSACTION;
$sql
COMMIT;
EOF
}

# ============================================================================
# 数据库操作 - 端口管理
# ============================================================================

db_port_exists() {
    local port="$1"
    local result=$(db_query "SELECT 1 FROM ports WHERE port='$port' LIMIT 1;")
    [ "$result" != "[]" ]
}

db_port_add() {
    local port="$1"
    local remark="${2:-}"
    local billing="${3:-single}"
    local tc_class="${4}"

    db_exec "INSERT INTO ports (port, remark, billing_mode, tc_class_id)
             VALUES ('$port', '$remark', '$billing', '$tc_class');"
}

db_port_remove() {
    local port="$1"
    db_exec "DELETE FROM ports WHERE port='$port';"
}

db_port_list() {
    db_query "SELECT port FROM ports ORDER BY
              CASE WHEN port LIKE '%-%' THEN 1 ELSE 0 END,
              CAST(port AS INTEGER);" | jq -r '.[].port'
}

db_port_get_tc_class() {
    local port="$1"
    db_query "SELECT tc_class_id FROM ports WHERE port='$port';" | jq -r '.[0].tc_class_id // ""'
}

db_port_get_billing() {
    local port="$1"
    db_query "SELECT billing_mode FROM ports WHERE port='$port';" | jq -r '.[0].billing_mode // "single"'
}

db_port_get_remark() {
    local port="$1"
    db_query "SELECT remark FROM ports WHERE port='$port';" | jq -r '.[0].remark // ""'
}

db_port_set_remark() {
    local port="$1"
    local remark="$2"
    db_exec "UPDATE ports SET remark='$remark' WHERE port='$port';"
}

# ============================================================================
# 数据库操作 - 配额管理
# ============================================================================

db_quota_get() {
    local port="$1"
    db_query "SELECT * FROM quotas WHERE port='$port';" | jq -r '.[0] // null'
}

db_quota_set() {
    local port="$1"
    local limit_bytes="$2"
    local reset_day="$3"

    db_exec "INSERT OR REPLACE INTO quotas (port, limit_bytes, reset_day, last_reset)
             VALUES ('$port', $limit_bytes, $reset_day, strftime('%s', 'now'));"
}

db_quota_remove() {
    local port="$1"
    db_exec "DELETE FROM quotas WHERE port='$port';"
}

db_quota_update_reset_time() {
    local port="$1"
    db_exec "UPDATE quotas SET last_reset=strftime('%s', 'now') WHERE port='$port';"
}

# ============================================================================
# 数据库操作 - 带宽限制
# ============================================================================

db_bandwidth_get() {
    local port="$1"
    db_query "SELECT rate_kbps FROM bandwidth_limits WHERE port='$port';" | jq -r '.[0].rate_kbps // 0'
}

db_bandwidth_set() {
    local port="$1"
    local rate_kbps="$2"

    db_exec "INSERT OR REPLACE INTO bandwidth_limits (port, rate_kbps)
             VALUES ('$port', $rate_kbps);"
}

db_bandwidth_remove() {
    local port="$1"
    db_exec "DELETE FROM bandwidth_limits WHERE port='$port';"
}

# ============================================================================
# 数据库操作 - 突发保护
# ============================================================================

db_burst_get_config() {
    local port="$1"
    db_query "SELECT * FROM burst_protection WHERE port='$port';" | jq -r '.[0] // null'
}

db_burst_set_config() {
    local port="$1"
    local burst_rate_kbps="$2"
    local burst_window="$3"
    local throttle_rate_kbps="$4"
    local throttle_duration="$5"

    db_exec "INSERT OR REPLACE INTO burst_protection
             (port, enabled, burst_rate_kbps, burst_window, throttle_rate_kbps, throttle_duration)
             VALUES ('$port', 1, $burst_rate_kbps, $burst_window, $throttle_rate_kbps, $throttle_duration);"
}

db_burst_remove_config() {
    local port="$1"
    db_exec "DELETE FROM burst_protection WHERE port='$port';"
}

db_burst_get_state() {
    local port="$1"
    db_query "SELECT * FROM burst_state WHERE port='$port';" | jq -r '.[0] // null'
}

db_burst_set_throttled() {
    local port="$1"
    local rate_kbps="$2"

    db_exec "INSERT OR REPLACE INTO burst_state (port, throttled, throttle_start, throttle_rate_kbps)
             VALUES ('$port', 1, strftime('%s', 'now'), $rate_kbps);"
}

db_burst_clear_throttled() {
    local port="$1"
    db_exec "DELETE FROM burst_state WHERE port='$port';"
}

# ============================================================================
# 数据库操作 - 流量快照
# ============================================================================

db_snapshot_add() {
    local port="$1"
    local input_bytes="$2"
    local output_bytes="$3"
    local timestamp="${4:-$(date +%s)}"

    db_exec "INSERT INTO traffic_snapshots (port, timestamp, input_bytes, output_bytes)
             VALUES ('$port', $timestamp, $input_bytes, $output_bytes);"
}

db_snapshot_get_recent() {
    local port="$1"
    local minutes="${2:-60}"
    local since=$(($(date +%s) - minutes * 60))

    db_query "SELECT * FROM traffic_snapshots
              WHERE port='$port' AND timestamp >= $since
              ORDER BY timestamp DESC;"
}

db_snapshot_cleanup_old() {
    local port="$1"
    local keep_minutes="${2:-120}"
    local cutoff=$(($(date +%s) - keep_minutes * 60))

    db_exec "DELETE FROM traffic_snapshots WHERE port='$port' AND timestamp < $cutoff;"
}

# ============================================================================
# 数据库操作 - 全局配置
# ============================================================================

db_config_get() {
    local key="$1"
    db_query "SELECT value FROM config WHERE key='$key';" | jq -r '.[0].value // ""'
}

db_config_set() {
    local key="$1"
    local value="$2"

    db_exec "INSERT OR REPLACE INTO config (key, value) VALUES ('$key', '$value');"
}

# ============================================================================
# 工具函数 - 验证和格式化
# ============================================================================

validate_port() {
    local port="$1"

    # 单个端口：1-65535
    if [[ "$port" =~ ^[0-9]+$ ]]; then
        [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
        return $?
    fi

    # 端口范围：1-65535
    if [[ "$port" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        local start="${BASH_REMATCH[1]}"
        local end="${BASH_REMATCH[2]}"
        [ "$start" -ge 1 ] && [ "$start" -le 65535 ] && \
        [ "$end" -ge 1 ] && [ "$end" -le 65535 ] && \
        [ "$start" -lt "$end" ]
        return $?
    fi

    return 1
}

is_port_range() {
    [[ "$1" =~ ^[0-9]+-[0-9]+$ ]]
}

# 端口安全化（用于文件名/标识符）
port_safe() {
    echo "$1" | tr '-:' '__'
}

# 格式化字节数
format_bytes() {
    local bytes=$1

    if [ "$bytes" -ge $BYTES_PER_GB ]; then
        echo "$(awk "BEGIN {printf \"%.2f\", $bytes / $BYTES_PER_GB}")GB"
    elif [ "$bytes" -ge $BYTES_PER_MB ]; then
        echo "$(awk "BEGIN {printf \"%.2f\", $bytes / $BYTES_PER_MB}")MB"
    elif [ "$bytes" -ge $BYTES_PER_KB ]; then
        echo "$(awk "BEGIN {printf \"%.2f\", $bytes / $BYTES_PER_KB}")KB"
    else
        echo "${bytes}B"
    fi
}

# 解析速率字符串为 kbps
parse_rate_to_kbps() {
    local rate="$1"
    local rate_lower=$(echo "$rate" | tr '[:upper:]' '[:lower:]')

    if [[ "$rate_lower" =~ ^([0-9]+)kbps$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [[ "$rate_lower" =~ ^([0-9]+)mbps$ ]]; then
        echo $((${BASH_REMATCH[1]} * 1000))
    elif [[ "$rate_lower" =~ ^([0-9]+)gbps$ ]]; then
        echo $((${BASH_REMATCH[1]} * 1000000))
    else
        echo "0"
    fi
}

# 解析大小字符串为字节
parse_size_to_bytes() {
    local size="$1"
    local size_upper=$(echo "$size" | tr '[:lower:]' '[:upper:]')

    if [[ "$size_upper" =~ ^([0-9]+)KB$ ]]; then
        echo $((${BASH_REMATCH[1]} * BYTES_PER_KB))
    elif [[ "$size_upper" =~ ^([0-9]+)MB$ ]]; then
        echo $((${BASH_REMATCH[1]} * BYTES_PER_MB))
    elif [[ "$size_upper" =~ ^([0-9]+)GB$ ]]; then
        echo $((${BASH_REMATCH[1]} * BYTES_PER_GB))
    elif [[ "$size_upper" =~ ^([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo "0"
    fi
}

# ============================================================================
# nftables 流量统计
# ============================================================================

nft_init() {
    log "初始化 nftables..."

    # 创建表
    nft add table $NFT_FAMILY $NFT_TABLE 2>/dev/null || true

    # 创建链
    nft add chain $NFT_FAMILY $NFT_TABLE input { type filter hook input priority filter \; } 2>/dev/null || true
    nft add chain $NFT_FAMILY $NFT_TABLE output { type filter hook output priority filter \; } 2>/dev/null || true
    nft add chain $NFT_FAMILY $NFT_TABLE forward { type filter hook forward priority filter \; } 2>/dev/null || true
}

nft_add_port_counter() {
    local port="$1"
    local port_safe=$(port_safe "$port")

    log "添加 nftables 计数器: $port"

    # 创建计数器对象
    nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null || true
    nft add counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null || true

    # 添加规则
    if is_port_range "$port"; then
        local start="${port%-*}"
        local end="${port#*-}"

        # TCP
        nft add rule $NFT_FAMILY $NFT_TABLE input tcp dport $start-$end counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE output tcp sport $start-$end counter name "port_${port_safe}_out" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE forward tcp dport $start-$end counter name "port_${port_safe}_in" 2>/dev/null || true

        # UDP
        nft add rule $NFT_FAMILY $NFT_TABLE input udp dport $start-$end counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE output udp sport $start-$end counter name "port_${port_safe}_out" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE forward udp dport $start-$end counter name "port_${port_safe}_in" 2>/dev/null || true
    else
        # TCP
        nft add rule $NFT_FAMILY $NFT_TABLE input tcp dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE output tcp sport $port counter name "port_${port_safe}_out" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE forward tcp dport $port counter name "port_${port_safe}_in" 2>/dev/null || true

        # UDP
        nft add rule $NFT_FAMILY $NFT_TABLE input udp dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE output udp sport $port counter name "port_${port_safe}_out" 2>/dev/null || true
        nft add rule $NFT_FAMILY $NFT_TABLE forward udp dport $port counter name "port_${port_safe}_in" 2>/dev/null || true
    fi
}

nft_get_port_traffic() {
    local port="$1"
    local port_safe=$(port_safe "$port")

    local input_bytes=$(nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null | \
        grep -oE 'bytes [0-9]+' | awk '{print $2}')
    local output_bytes=$(nft list counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null | \
        grep -oE 'bytes [0-9]+' | awk '{print $2}')

    echo "${input_bytes:-0} ${output_bytes:-0}"
}

nft_reset_port_counter() {
    local port="$1"
    local port_safe=$(port_safe "$port")

    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null || true
    nft reset counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null || true
}

nft_remove_port() {
    local port="$1"
    local port_safe=$(port_safe "$port")

    log "删除 nftables 规则: $port"

    # 删除计数器会自动删除相关规则
    nft delete counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_in" 2>/dev/null || true
    nft delete counter $NFT_FAMILY $NFT_TABLE "port_${port_safe}_out" 2>/dev/null || true
}

# ============================================================================
# TC (Traffic Control) 带宽限制
# ============================================================================

tc_get_default_interface() {
    ip route | grep default | awk '{print $5}' | head -n1
}

tc_allocate_class_id() {
    local port="$1"

    # 直接使用端口号作为 class ID（零碰撞）
    if is_port_range "$port"; then
        local start="${port%-*}"
        printf "1:%x" "$start"
    else
        printf "1:%x" "$port"
    fi
}

tc_init() {
    local interface=$(tc_get_default_interface)
    [ -z "$interface" ] && interface="$DEFAULT_INTERFACE"

    log "初始化 TC (接口: $interface)..."

    # 初始化出站 HTB qdisc
    tc qdisc add dev "$interface" root handle 1: htb default 30 2>/dev/null || true
    tc class add dev "$interface" parent 1: classid 1:1 htb rate 10gbit 2>/dev/null || true

    # 初始化 IFB 用于入站限速
    modprobe ifb numifbs=1 2>/dev/null || true
    ip link set ifb0 up 2>/dev/null || true

    # 重定向入站流量到 IFB
    tc qdisc add dev "$interface" handle ffff: ingress 2>/dev/null || true
    tc filter add dev "$interface" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0 2>/dev/null || true

    # IFB 上的 HTB
    tc qdisc add dev ifb0 root handle 1: htb default 30 2>/dev/null || true
    tc class add dev ifb0 parent 1: classid 1:1 htb rate 10gbit 2>/dev/null || true
}

tc_calculate_burst() {
    local rate_kbps=$1
    local burst_bytes=$(( rate_kbps * 1000 / 8 / BURST_CALC_DIVISOR ))

    [ $burst_bytes -lt $MIN_BURST_BYTES ] && burst_bytes=$MIN_BURST_BYTES

    echo "$burst_bytes"
}

tc_add_limit() {
    local port="$1"
    local rate_kbps="$2"
    local interface=$(tc_get_default_interface)
    [ -z "$interface" ] && interface="$DEFAULT_INTERFACE"

    local class_id=$(tc_allocate_class_id "$port")
    local tc_rate="${rate_kbps}kbit"
    local burst=$(tc_calculate_burst "$rate_kbps")

    log "设置 TC 限速: $port -> ${rate_kbps}kbps (class: $class_id)"

    # 出站限速
    tc class add dev "$interface" parent 1:1 classid "$class_id" htb \
        rate "$tc_rate" ceil "$tc_rate" burst "$burst" cburst "$burst" 2>/dev/null || \
    tc class change dev "$interface" parent 1:1 classid "$class_id" htb \
        rate "$tc_rate" ceil "$tc_rate" burst "$burst" cburst "$burst"

    # 添加过滤器（出站）
    if is_port_range "$port"; then
        local start="${port%-*}"
        local end="${port#*-}"
        tc filter add dev "$interface" protocol ip parent 1:0 prio 1 u32 \
            match ip sport "$start" 0xffff flowid "$class_id" 2>/dev/null || true
    else
        tc filter add dev "$interface" protocol ip parent 1:0 prio 1 u32 \
            match ip sport "$port" 0xffff flowid "$class_id" 2>/dev/null || true
    fi

    # 入站限速（IFB）
    tc class add dev ifb0 parent 1:1 classid "$class_id" htb \
        rate "$tc_rate" ceil "$tc_rate" burst "$burst" cburst "$burst" 2>/dev/null || \
    tc class change dev ifb0 parent 1:1 classid "$class_id" htb \
        rate "$tc_rate" ceil "$tc_rate" burst "$burst" cburst "$burst"

    # 添加过滤器（入站，使用 dport）
    if is_port_range "$port"; then
        local start="${port%-*}"
        local end="${port#*-}"
        tc filter add dev ifb0 protocol ip parent 1:0 prio 1 u32 \
            match ip dport "$start" 0xffff flowid "$class_id" 2>/dev/null || true
    else
        tc filter add dev ifb0 protocol ip parent 1:0 prio 1 u32 \
            match ip dport "$port" 0xffff flowid "$class_id" 2>/dev/null || true
    fi
}

tc_remove_limit() {
    local port="$1"
    local interface=$(tc_get_default_interface)
    [ -z "$interface" ] && interface="$DEFAULT_INTERFACE"

    local class_id=$(tc_allocate_class_id "$port")

    log "删除 TC 限速: $port (class: $class_id)"

    # 删除 class 会自动删除关联的 filter
    tc class del dev "$interface" classid "$class_id" 2>/dev/null || true
    tc class del dev ifb0 classid "$class_id" 2>/dev/null || true
}

# ============================================================================
# systemd timer 定时任务管理
# ============================================================================

systemd_create_reset_timer() {
    local port="$1"
    local reset_day="$2"
    local port_safe=$(port_safe "$port")

    log "创建重置定时器: 端口 $port (每月 ${reset_day} 日)"

    # 创建 service 文件
    cat > "/etc/systemd/system/port-traffic-reset-${port_safe}.service" <<EOF
[Unit]
Description=Reset traffic counter for port $port
After=network.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH --reset-port $port
StandardOutput=journal
StandardError=journal
EOF

    # 创建 timer 文件
    cat > "/etc/systemd/system/port-traffic-reset-${port_safe}.timer" <<EOF
[Unit]
Description=Monthly traffic reset timer for port $port

[Timer]
OnCalendar=*-*-${reset_day} 00:05:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "port-traffic-reset-${port_safe}.timer" 2>/dev/null || true
}

systemd_remove_reset_timer() {
    local port="$1"
    local port_safe=$(port_safe "$port")

    systemctl disable --now "port-traffic-reset-${port_safe}.timer" 2>/dev/null || true
    rm -f "/etc/systemd/system/port-traffic-reset-${port_safe}.service"
    rm -f "/etc/systemd/system/port-traffic-reset-${port_safe}.timer"
    systemctl daemon-reload
}

systemd_create_global_timers() {
    log "创建全局定时器..."

    # 告警检查 timer (每5分钟)
    cat > "/etc/systemd/system/port-traffic-alert.service" <<EOF
[Unit]
Description=Port traffic alert check
After=network.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH --check-alert
StandardOutput=journal
StandardError=journal
EOF

    cat > "/etc/systemd/system/port-traffic-alert.timer" <<EOF
[Unit]
Description=Port traffic alert check timer

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # 突发保护检查 timer (每分钟)
    cat > "/etc/systemd/system/port-traffic-burst.service" <<EOF
[Unit]
Description=Port traffic burst protection check
After=network.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH --check-burst
StandardOutput=journal
StandardError=journal
EOF

    cat > "/etc/systemd/system/port-traffic-burst.timer" <<EOF
[Unit]
Description=Port traffic burst protection check timer

[Timer]
OnCalendar=*:0/1
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now port-traffic-alert.timer 2>/dev/null || true
    systemctl enable --now port-traffic-burst.timer 2>/dev/null || true
}

systemd_remove_global_timers() {
    systemctl disable --now port-traffic-alert.timer 2>/dev/null || true
    systemctl disable --now port-traffic-burst.timer 2>/dev/null || true
    rm -f /etc/systemd/system/port-traffic-alert.{service,timer}
    rm -f /etc/systemd/system/port-traffic-burst.{service,timer}
    systemctl daemon-reload
}

# ============================================================================
# 业务逻辑 - 端口管理
# ============================================================================

port_add() {
    local port="$1"
    local remark="${2:-}"
    local billing="${3:-single}"

    # 验证端口格式
    if ! validate_port "$port"; then
        log_error "无效的端口格式: $port"
        return 1
    fi

    # 检查是否已存在
    if db_port_exists "$port"; then
        log_error "端口已存在: $port"
        return 1
    fi

    # 分配 TC class ID
    local tc_class=$(tc_allocate_class_id "$port")

    # 检查 TC class ID 冲突
    local existing=$(db_query "SELECT port FROM ports WHERE tc_class_id='$tc_class' LIMIT 1;" | jq -r '.[0].port // ""')
    if [ -n "$existing" ]; then
        log_error "TC class ID 冲突: $port 与 $existing 冲突 (class: $tc_class)"
        return 1
    fi

    # 添加到数据库
    db_port_add "$port" "$remark" "$billing" "$tc_class"

    # 添加 nftables 规则
    nft_add_port_counter "$port"

    log_success "✓ 端口 $port 已添加"
    [ -n "$remark" ] && log "  备注: $remark"
    log "  计费模式: $billing"
    log "  TC Class: $tc_class"

    return 0
}

port_remove() {
    local port="$1"

    if ! db_port_exists "$port"; then
        log_error "端口不存在: $port"
        return 1
    fi

    lock_acquire 10 || return 1
    trap lock_release RETURN

    # 删除 TC 限速
    tc_remove_limit "$port"

    # 删除 nftables 规则
    nft_remove_port "$port"

    # 删除 systemd timer
    systemd_remove_reset_timer "$port"

    # 从数据库删除（级联删除相关配置）
    db_port_remove "$port"

    log_success "✓ 端口 $port 已删除"
    return 0
}

port_set_bandwidth() {
    local port="$1"
    local rate_input="$2"

    if ! db_port_exists "$port"; then
        log_error "端口不存在: $port"
        return 1
    fi

    local rate_kbps=$(parse_rate_to_kbps "$rate_input")
    if [ "$rate_kbps" -eq 0 ]; then
        log_error "无效的速率格式: $rate_input"
        return 1
    fi

    lock_acquire 10 || return 1
    trap lock_release RETURN

    # 保存到数据库
    db_bandwidth_set "$port" "$rate_kbps"

    # 应用 TC 限速
    tc_add_limit "$port" "$rate_kbps"

    log_success "✓ 端口 $port 限速已设置: $rate_input"
    return 0
}

port_remove_bandwidth() {
    local port="$1"

    if ! db_port_exists "$port"; then
        log_error "端口不存在: $port"
        return 1
    fi

    lock_acquire 10 || return 1
    trap lock_release RETURN

    # 删除 TC 限速
    tc_remove_limit "$port"

    # 从数据库删除
    db_bandwidth_remove "$port"

    log_success "✓ 端口 $port 限速已移除"
    return 0
}

port_set_quota() {
    local port="$1"
    local limit_input="$2"
    local reset_day="$3"

    if ! db_port_exists "$port"; then
        log_error "端口不存在: $port"
        return 1
    fi

    local limit_bytes=$(parse_size_to_bytes "$limit_input")
    if [ "$limit_bytes" -eq 0 ]; then
        log_error "无效的配额格式: $limit_input"
        return 1
    fi

    if [ "$reset_day" -lt 1 ] || [ "$reset_day" -gt 31 ]; then
        log_error "重置日期必须在 1-31 之间"
        return 1
    fi

    # 保存到数据库
    db_quota_set "$port" "$limit_bytes" "$reset_day"

    # 创建定时重置任务
    systemd_create_reset_timer "$port" "$reset_day"

    log_success "✓ 端口 $port 配额已设置: $limit_input"
    log "  重置日期: 每月 ${reset_day} 日"
    return 0
}

port_remove_quota() {
    local port="$1"

    if ! db_port_exists "$port"; then
        log_error "端口不存在: $port"
        return 1
    fi

    # 删除定时器
    systemd_remove_reset_timer "$port"

    # 从数据库删除
    db_quota_remove "$port"

    log_success "✓ 端口 $port 配额已移除"
    return 0
}

port_reset_traffic() {
    local port="$1"

    if ! db_port_exists "$port"; then
        log_error "端口不存在: $port"
        return 1
    fi

    lock_acquire 10 || return 1
    trap lock_release RETURN

    # 重置 nftables 计数器
    nft_reset_port_counter "$port"

    # 更新数据库中的重置时间
    db_quota_update_reset_time "$port"

    # 清除告警历史
    db_exec "DELETE FROM alert_history WHERE port='$port';"

    # 清除突发保护状态
    db_burst_clear_throttled "$port"

    log_daemon "端口 $port 流量已重置"
    log_success "✓ 端口 $port 流量已重置"
    return 0
}

# ============================================================================
# 业务逻辑 - 突发保护
# ============================================================================

burst_check_all_ports() {
    lock_acquire 3 || return 0
    trap lock_release RETURN

    local ports=($(db_port_list))

    for port in "${ports[@]}"; do
        local config=$(db_burst_get_config "$port")
        [ "$config" = "null" ] && continue

        local enabled=$(echo "$config" | jq -r '.enabled')
        [ "$enabled" != "1" ] && continue

        burst_check_port "$port"
    done
}

burst_check_port() {
    local port="$1"

    local config=$(db_burst_get_config "$port")
    local burst_rate_kbps=$(echo "$config" | jq -r '.burst_rate_kbps')
    local burst_window=$(echo "$config" | jq -r '.burst_window')
    local throttle_rate_kbps=$(echo "$config" | jq -r '.throttle_rate_kbps')
    local throttle_duration=$(echo "$config" | jq -r '.throttle_duration')

    # 记录当前流量快照
    local traffic=($(nft_get_port_traffic "$port"))
    db_snapshot_add "$port" "${traffic[0]}" "${traffic[1]}"

    # 清理旧快照
    db_snapshot_cleanup_old "$port" 120

    # 检查当前状态
    local state=$(db_burst_get_state "$port")

    if [ "$state" != "null" ]; then
        # 当前处于限速状态，检查是否应该解除
        local throttled=$(echo "$state" | jq -r '.throttled')
        local throttle_start=$(echo "$state" | jq -r '.throttle_start')
        local now=$(date +%s)
        local elapsed=$(( (now - throttle_start) / 60 ))

        if [ "$elapsed" -ge "$throttle_duration" ]; then
            burst_release_throttle "$port"
        fi
    else
        # 检查是否触发突发保护
        local high_duration=$(burst_calculate_high_rate_duration "$port" "$burst_rate_kbps")

        if [ "$high_duration" -ge "$burst_window" ]; then
            burst_apply_throttle "$port" "$throttle_rate_kbps"
        fi
    fi
}

burst_calculate_high_rate_duration() {
    local port="$1"
    local threshold_kbps="$2"
    local threshold_bps=$((threshold_kbps * 1000))

    local snapshots=$(db_snapshot_get_recent "$port" 60)
    local count=$(echo "$snapshots" | jq 'length')

    [ "$count" -lt 2 ] && echo "0" && return

    local high_minutes=0
    local prev_timestamp=""
    local prev_input=0
    local prev_output=0

    echo "$snapshots" | jq -c '.[]' | while read -r snap; do
        local timestamp=$(echo "$snap" | jq -r '.timestamp')
        local input_bytes=$(echo "$snap" | jq -r '.input_bytes')
        local output_bytes=$(echo "$snap" | jq -r '.output_bytes')

        if [ -n "$prev_timestamp" ]; then
            local time_diff=$((prev_timestamp - timestamp))
            [ "$time_diff" -eq 0 ] && continue

            local input_rate=$(( (prev_input - input_bytes) * 8 / time_diff ))
            local output_rate=$(( (prev_output - output_bytes) * 8 / time_diff ))
            local total_rate=$((input_rate + output_rate))

            if [ "$total_rate" -ge "$threshold_bps" ]; then
                high_minutes=$((high_minutes + time_diff / 60))
            fi
        fi

        prev_timestamp="$timestamp"
        prev_input="$input_bytes"
        prev_output="$output_bytes"
    done | tail -n1

    echo "${high_minutes:-0}"
}

burst_apply_throttle() {
    local port="$1"
    local throttle_rate_kbps="$2"

    log_warn "⚠ 端口 $port 触发突发保护，限速至 ${throttle_rate_kbps}kbps"

    # 应用限速
    tc_add_limit "$port" "$throttle_rate_kbps"

    # 更新状态
    db_burst_set_throttled "$port" "$throttle_rate_kbps"

    log_daemon "端口 $port 突发保护已触发"

    # 发送 Telegram 通知
    telegram_send_burst_alert "$port" "$throttle_rate_kbps" "triggered"
}

burst_release_throttle() {
    local port="$1"

    log "✓ 端口 $port 突发保护限速已解除"

    # 恢复原始限速（如果有）
    local original_rate=$(db_bandwidth_get "$port")
    if [ "$original_rate" -gt 0 ]; then
        tc_add_limit "$port" "$original_rate"
    else
        tc_remove_limit "$port"
    fi

    # 清除状态
    db_burst_clear_throttled "$port"

    log_daemon "端口 $port 突发保护限速已解除"

    # 发送 Telegram 通知
    telegram_send_burst_alert "$port" "" "released"
}

# ============================================================================
# Telegram 通知
# ============================================================================

telegram_send() {
    local message="$1"

    local enabled=$(db_config_get "telegram_enabled")
    [ "$enabled" != "true" ] && return 1

    local bot_token=$(db_config_get "telegram_bot_token")
    local chat_id=$(db_config_get "telegram_chat_id")

    [ -z "$bot_token" ] || [ -z "$chat_id" ] && return 1

    # 转义 HTML 特殊字符
    message=$(echo "$message" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')

    curl -s --connect-timeout 10 --max-time 30 \
        -X POST "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -d "chat_id=${chat_id}" \
        -d "text=${message}" \
        -d "parse_mode=HTML" >/dev/null 2>&1
}

telegram_send_burst_alert() {
    local port="$1"
    local throttle_rate="$2"
    local action="$3"

    local enabled=$(db_config_get "telegram_enabled")
    [ "$enabled" != "true" ] && return

    local remark=$(db_port_get_remark "$port")
    local port_display="$port"
    [ -n "$remark" ] && port_display="$port ($remark)"

    local message
    if [ "$action" = "triggered" ]; then
        message="⚠️ <b>突发保护触发</b>

端口: <code>$port_display</code>
限速至: <code>${throttle_rate}kbps</code>
时间: $(date '+%Y-%m-%d %H:%M:%S')"
    else
        message="✅ <b>突发保护解除</b>

端口: <code>$port_display</code>
时间: $(date '+%Y-%m-%d %H:%M:%S')"
    fi

    telegram_send "$message"
}

telegram_check_alerts() {
    local enabled=$(db_config_get "telegram_enabled")
    [ "$enabled" != "true" ] && return

    local alert_enabled=$(db_config_get "telegram_alert_enabled")
    [ "$alert_enabled" != "true" ] && return

    local ports=($(db_port_list))

    for port in "${ports[@]}"; do
        local quota=$(db_quota_get "$port")
        [ "$quota" = "null" ] && continue

        local limit_bytes=$(echo "$quota" | jq -r '.limit_bytes')
        local billing=$(db_port_get_billing "$port")

        # 获取当前流量
        local traffic=($(nft_get_port_traffic "$port"))
        local used_bytes
        if [ "$billing" = "double" ]; then
            used_bytes=$((traffic[0] + traffic[1]))
        else
            used_bytes=${traffic[1]}
        fi

        # 计算百分比
        local percent=$((used_bytes * 100 / limit_bytes))

        # 检查阈值
        for threshold in 30 50 80 100; do
            if [ "$percent" -ge "$threshold" ]; then
                # 检查是否已发送过此阈值告警
                local last_alert=$(db_query "SELECT sent_at FROM alert_history
                    WHERE port='$port' AND threshold=$threshold
                    ORDER BY sent_at DESC LIMIT 1;" | jq -r '.[0].sent_at // 0')

                local now=$(date +%s)
                local quota_info=$(echo "$quota" | jq -r '.last_reset')

                # 如果告警是在上次重置之前发送的，则可以重新发送
                if [ "$last_alert" -lt "$quota_info" ]; then
                    telegram_send_quota_alert "$port" "$percent" "$threshold"

                    # 记录告警历史
                    db_exec "INSERT INTO alert_history (port, threshold) VALUES ('$port', $threshold);"
                fi
            fi
        done
    done
}

telegram_send_quota_alert() {
    local port="$1"
    local percent="$2"
    local threshold="$3"

    local remark=$(db_port_get_remark "$port")
    local port_display="$port"
    [ -n "$remark" ] && port_display="$port ($remark)"

    local quota=$(db_quota_get "$port")
    local limit_bytes=$(echo "$quota" | jq -r '.limit_bytes')
    local limit_display=$(format_bytes "$limit_bytes")

    local icon="ℹ️"
    [ "$threshold" -ge 80 ] && icon="⚠️"
    [ "$threshold" -ge 100 ] && icon="🚫"

    local message="$icon <b>流量告警</b>

端口: <code>$port_display</code>
使用: <b>${percent}%</b>
配额: <code>$limit_display</code>
时间: $(date '+%Y-%m-%d %H:%M:%S')"

    telegram_send "$message"
}

# ============================================================================
# UI 层 - 状态显示
# ============================================================================

ui_show_status() {
    clear
    local ports=($(db_port_list))
    local total_used=0

    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}             ${CYAN}${SCRIPT_NAME} v${SCRIPT_VERSION}${NC}               ${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"

    if [ ${#ports[@]} -eq 0 ]; then
        echo -e "${BLUE}║${NC}  ${YELLOW}暂无监控端口${NC}                                            ${BLUE}║${NC}"
    else
        for port in "${ports[@]}"; do
            local traffic=($(nft_get_port_traffic "$port"))
            local billing=$(db_port_get_billing "$port")
            local remark=$(db_port_get_remark "$port")

            local used_bytes
            if [ "$billing" = "double" ]; then
                used_bytes=$((traffic[0] + traffic[1]))
            else
                used_bytes=${traffic[1]}
            fi
            total_used=$((total_used + used_bytes))

            # 获取配额和限速信息
            local quota=$(db_quota_get "$port")
            local rate_kbps=$(db_bandwidth_get "$port")

            local percent_display=""
            if [ "$quota" != "null" ]; then
                local limit_bytes=$(echo "$quota" | jq -r '.limit_bytes')
                local percent=$((used_bytes * 100 / limit_bytes))

                if [ $percent -ge 100 ]; then
                    percent_display=" ${RED}[${percent}%]${NC}"
                elif [ $percent -ge 80 ]; then
                    percent_display=" ${YELLOW}[${percent}%]${NC}"
                else
                    percent_display=" ${GREEN}[${percent}%]${NC}"
                fi
            fi

            # 检查突发保护状态
            local burst_display=""
            local burst_state=$(db_burst_get_state "$port")
            if [ "$burst_state" != "null" ]; then
                local throttle_start=$(echo "$burst_state" | jq -r '.throttle_start')
                local now=$(date +%s)
                local remaining=$(( (throttle_start + 600 - now) / 60 ))
                [ $remaining -lt 0 ] && remaining=0
                burst_display=" ${RED}🔽${remaining}m${NC}"
            else
                local burst_config=$(db_burst_get_config "$port")
                if [ "$burst_config" != "null" ]; then
                    burst_display=" ${GREEN}⚡${NC}"
                fi
            fi

            # 显示端口行
            printf "${BLUE}║${NC}  ${GREEN}%-8s${NC} ↑%-8s ↓%-8s 计:%-8s%b%b ${BLUE}║${NC}\n" \
                "$port" "$(format_bytes ${traffic[0]})" "$(format_bytes ${traffic[1]})" \
                "$(format_bytes $used_bytes)" "$percent_display" "$burst_display"

            # 显示标签行
            local tags=""
            [ -n "$remark" ] && tags+="[$remark] "
            if [ "$quota" != "null" ]; then
                local limit_bytes=$(echo "$quota" | jq -r '.limit_bytes')
                tags+="配额:$(format_bytes $limit_bytes) "
            fi
            [ "$rate_kbps" -gt 0 ] && tags+="限速:${rate_kbps}kbps"

            if [ -n "$tags" ]; then
                printf "${BLUE}║${NC}    ${GRAY}%-56s${NC} ${BLUE}║${NC}\n" "$tags"
            fi
        done
    fi

    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
    printf "${BLUE}║${NC}  监控端口: ${GREEN}%-2d${NC}  总流量: ${GREEN}%-12s${NC}  快捷命令: ${CYAN}%-4s${NC}  ${BLUE}║${NC}\n" \
        "${#ports[@]}" "$(format_bytes $total_used)" "$SHORTCUT_COMMAND"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${GRAY}⚡=突发保护启用  🔽=限速中(剩余分钟数)${NC}"
    echo ""
}

ui_show_menu() {
    echo -e "${CYAN}╔════════════════╗${NC}"
    echo -e "${CYAN}║  端口管理      ║${NC}"
    echo -e "${CYAN}╚════════════════╝${NC}"
    echo "  1. 添加端口       2. 删除端口       3. 修改备注"
    echo ""
    echo -e "${CYAN}╔════════════════╗${NC}"
    echo -e "${CYAN}║  流量控制      ║${NC}"
    echo -e "${CYAN}╚════════════════╝${NC}"
    echo "  4. 带宽限速       5. 流量配额       6. 重置流量"
    echo ""
    echo -e "${CYAN}╔════════════════╗${NC}"
    echo -e "${CYAN}║  高级功能      ║${NC}"
    echo -e "${CYAN}╚════════════════╝${NC}"
    echo "  7. 突发保护       8. Telegram       9. 立即推送"
    echo ""
    echo -e "${CYAN}╔════════════════╗${NC}"
    echo -e "${CYAN}║  系统          ║${NC}"
    echo -e "${CYAN}╚════════════════╝${NC}"
    echo "  10. 卸载          0. 退出"
    echo ""
}

# ============================================================================
# UI 层 - 交互功能
# ============================================================================

# 排除的常用系统端口
readonly EXCLUDED_PORTS="22 80 443 53 67 68 546 547 25 110 143 993 995 587 465 21 23 3306 5432 6379 27017 11211"

# 获取当前监听的端口列表（排除常用端口和已监控端口）
get_listening_ports() {
    local monitored_ports=($(db_port_list 2>/dev/null))

    # 构建排除列表
    local all_excluded="$EXCLUDED_PORTS"
    for p in "${monitored_ports[@]}"; do
        all_excluded="$all_excluded $p"
    done

    # 获取监听端口并过滤
    ss -tlnp 2>/dev/null | awk 'NR>1 {
        split($4, a, ":")
        port = a[length(a)]
        if (port ~ /^[0-9]+$/) {
            ports[port] = 1
        }
    }
    END {
        for (p in ports) print p
    }' | while read port; do
        local skip=0
        for excluded in $all_excluded; do
            if [ "$port" = "$excluded" ]; then
                skip=1
                break
            fi
        done
        [ $skip -eq 0 ] && echo "$port"
    done | sort -n
}

ui_add_port() {
    echo -e "\n${CYAN}=== 添加端口 ===${NC}\n"

    # 显示当前监听的端口
    echo -e "${YELLOW}当前监听的端口（已排除系统常用端口和已监控端口）:${NC}"
    echo ""

    local listening_ports=($(get_listening_ports))

    if [ ${#listening_ports[@]} -eq 0 ]; then
        echo -e "  ${GRAY}(无可用端口)${NC}"
    else
        local i=1
        for port in "${listening_ports[@]}"; do
            printf "  ${GREEN}%d.${NC} %s\n" "$i" "$port"
            i=$((i + 1))
        done
    fi
    echo ""

    # 支持输入序号或端口号
    read -p "输入序号或端口号 (如: 1 或 8000 或 8000-9000): " input
    [ -z "$input" ] && return

    local port="$input"
    # 如果输入的是纯数字且在列表范围内，则视为序号
    if [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -ge 1 ] && [ "$input" -le ${#listening_ports[@]} ]; then
        port="${listening_ports[$((input - 1))]}"
        echo -e "已选择端口: ${GREEN}$port${NC}"
    fi

    if ! validate_port "$port"; then
        log_error "无效的端口格式"
        read -p "按回车继续..." _
        return
    fi

    read -p "备注 (可选): " remark
    read -p "计费模式 [single/double] (默认: single): " billing
    [ -z "$billing" ] && billing="single"

    if port_add "$port" "$remark" "$billing"; then
        read -p "按回车继续..." _
    else
        read -p "按回车继续..." _
    fi
}

ui_remove_port() {
    echo -e "\n${CYAN}=== 删除端口 ===${NC}\n"

    local ports=($(db_port_list))
    if [ ${#ports[@]} -eq 0 ]; then
        log_warn "没有可删除的端口"
        read -p "按回车继续..." _
        return
    fi

    echo "当前端口:"
    local i=1
    for port in "${ports[@]}"; do
        local remark=$(db_port_get_remark "$port")
        if [ -n "$remark" ]; then
            echo "  $i. $port ($remark)"
        else
            echo "  $i. $port"
        fi
        i=$((i + 1))
    done
    echo ""

    read -p "选择端口编号: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#ports[@]} ]; then
        local port="${ports[$((choice - 1))]}"
        read -p "确认删除端口 $port? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            port_remove "$port"
        fi
    else
        log_error "无效选择"
    fi

    read -p "按回车继续..." _
}

ui_set_bandwidth() {
    echo -e "\n${CYAN}=== 带宽限速 ===${NC}\n"

    local ports=($(db_port_list))
    if [ ${#ports[@]} -eq 0 ]; then
        log_warn "没有可配置的端口"
        read -p "按回车继续..." _
        return
    fi

    echo "当前端口:"
    local i=1
    for port in "${ports[@]}"; do
        local rate=$(db_bandwidth_get "$port")
        local rate_display="未限速"
        [ "$rate" -gt 0 ] && rate_display="${rate}kbps"
        echo "  $i. $port - $rate_display"
        i=$((i + 1))
    done
    echo ""

    read -p "选择端口编号: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#ports[@]} ]; then
        local port="${ports[$((choice - 1))]}"

        echo ""
        echo "设置限速 (格式: 100kbps / 10mbps / 1gbps，输入 0 移除限速)"
        read -p "速率: " rate_input

        if [ "$rate_input" = "0" ]; then
            port_remove_bandwidth "$port"
        else
            port_set_bandwidth "$port" "$rate_input"
        fi
    else
        log_error "无效选择"
    fi

    read -p "按回车继续..." _
}

ui_set_quota() {
    echo -e "\n${CYAN}=== 流量配额 ===${NC}\n"

    local ports=($(db_port_list))
    if [ ${#ports[@]} -eq 0 ]; then
        log_warn "没有可配置的端口"
        read -p "按回车继续..." _
        return
    fi

    echo "当前端口:"
    local i=1
    for port in "${ports[@]}"; do
        local quota=$(db_quota_get "$port")
        local quota_display="未设置"
        if [ "$quota" != "null" ]; then
            local limit=$(echo "$quota" | jq -r '.limit_bytes')
            quota_display="$(format_bytes $limit)"
        fi
        echo "  $i. $port - $quota_display"
        i=$((i + 1))
    done
    echo ""

    read -p "选择端口编号: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#ports[@]} ]; then
        local port="${ports[$((choice - 1))]}"

        echo ""
        echo "设置配额 (格式: 100GB / 500MB，输入 0 移除配额)"
        read -p "配额: " limit_input

        if [ "$limit_input" = "0" ]; then
            port_remove_quota "$port"
        else
            read -p "每月重置日期 (1-31): " reset_day
            port_set_quota "$port" "$limit_input" "$reset_day"
        fi
    else
        log_error "无效选择"
    fi

    read -p "按回车继续..." _
}

ui_reset_traffic() {
    echo -e "\n${CYAN}=== 重置流量 ===${NC}\n"

    local ports=($(db_port_list))
    if [ ${#ports[@]} -eq 0 ]; then
        log_warn "没有可重置的端口"
        read -p "按回车继续..." _
        return
    fi

    echo "当前端口:"
    local i=1
    for port in "${ports[@]}"; do
        echo "  $i. $port"
        i=$((i + 1))
    done
    echo ""

    read -p "选择端口编号 (0=全部): " choice
    if [ "$choice" = "0" ]; then
        read -p "确认重置所有端口流量? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            for port in "${ports[@]}"; do
                port_reset_traffic "$port"
            done
        fi
    elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#ports[@]} ]; then
        local port="${ports[$((choice - 1))]}"
        port_reset_traffic "$port"
    else
        log_error "无效选择"
    fi

    read -p "按回车继续..." _
}

ui_modify_remark() {
    echo -e "\n${CYAN}=== 修改备注 ===${NC}\n"

    local ports=($(db_port_list))
    if [ ${#ports[@]} -eq 0 ]; then
        log_warn "没有可修改的端口"
        read -p "按回车继续..." _
        return
    fi

    echo "当前端口:"
    local i=1
    for port in "${ports[@]}"; do
        local remark=$(db_port_get_remark "$port")
        if [ -n "$remark" ]; then
            echo "  $i. $port - [$remark]"
        else
            echo "  $i. $port - (无备注)"
        fi
        i=$((i + 1))
    done
    echo ""

    read -p "选择端口编号: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#ports[@]} ]; then
        local port="${ports[$((choice - 1))]}"
        local current_remark=$(db_port_get_remark "$port")

        echo ""
        if [ -n "$current_remark" ]; then
            echo "当前备注: $current_remark"
        else
            echo "当前无备注"
        fi

        read -p "新备注 (留空删除备注): " new_remark

        db_port_set_remark "$port" "$new_remark"

        if [ -z "$new_remark" ]; then
            log_success "✓ 端口 $port 备注已删除"
        else
            log_success "✓ 端口 $port 备注已更新为: $new_remark"
        fi
    else
        log_error "无效选择"
    fi

    read -p "按回车继续..." _
}

ui_setup_burst_protection() {
    echo -e "\n${CYAN}=== 突发保护配置 ===${NC}\n"

    local ports=($(db_port_list))
    if [ ${#ports[@]} -eq 0 ]; then
        log_warn "没有可配置的端口"
        read -p "按回车继续..." _
        return
    fi

    echo "当前端口:"
    local i=1
    for port in "${ports[@]}"; do
        local config=$(db_burst_get_config "$port")
        local status_display="${GRAY}未启用${NC}"

        if [ "$config" != "null" ]; then
            local enabled=$(echo "$config" | jq -r '.enabled')
            if [ "$enabled" = "1" ]; then
                local burst_rate=$(echo "$config" | jq -r '.burst_rate_kbps')
                local throttle_rate=$(echo "$config" | jq -r '.throttle_rate_kbps')
                status_display="${GREEN}已启用${NC} (触发:${burst_rate}kbps → 限速:${throttle_rate}kbps)"
            fi
        fi

        echo -e "  $i. $port - $status_display"
        i=$((i + 1))
    done
    echo ""

    read -p "选择端口编号: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#ports[@]} ]; then
        local port="${ports[$((choice - 1))]}"

        echo ""
        echo "突发保护配置"
        echo "----------------------------------------"
        echo "功能说明:"
        echo "  - 检测持续高速率流量使用"
        echo "  - 自动临时限速，防止短时间耗尽配额"
        echo "  - 限速到期后自动恢复"
        echo ""

        local config=$(db_burst_get_config "$port")

        if [ "$config" != "null" ]; then
            echo "当前配置:"
            echo "  触发速率: $(echo "$config" | jq -r '.burst_rate_kbps')kbps"
            echo "  检测窗口: $(echo "$config" | jq -r '.burst_window')分钟"
            echo "  限速至: $(echo "$config" | jq -r '.throttle_rate_kbps')kbps"
            echo "  限速时长: $(echo "$config" | jq -r '.throttle_duration')分钟"
            echo ""
        fi

        echo "1. 启用/配置突发保护"
        echo "2. 禁用突发保护"
        echo "0. 返回"
        echo ""

        read -p "选择 [0-2]: " sub_choice

        case $sub_choice in
            1)
                echo ""
                echo "配置参数 (支持格式: 100kbps / 10mbps)"
                echo ""

                read -p "触发速率 (超过此速率触发保护): " burst_rate_input
                local burst_rate_kbps=$(parse_rate_to_kbps "$burst_rate_input")

                if [ "$burst_rate_kbps" -eq 0 ]; then
                    log_error "无效的速率格式"
                    read -p "按回车继续..." _
                    return
                fi

                read -p "检测窗口 (分钟, 默认30): " burst_window
                [ -z "$burst_window" ] && burst_window=30

                read -p "限速至 (触发后的限速值): " throttle_rate_input
                local throttle_rate_kbps=$(parse_rate_to_kbps "$throttle_rate_input")

                if [ "$throttle_rate_kbps" -eq 0 ]; then
                    log_error "无效的速率格式"
                    read -p "按回车继续..." _
                    return
                fi

                read -p "限速时长 (分钟, 默认10): " throttle_duration
                [ -z "$throttle_duration" ] && throttle_duration=10

                # 保存配置
                db_burst_set_config "$port" "$burst_rate_kbps" "$burst_window" \
                    "$throttle_rate_kbps" "$throttle_duration"

                log_success "✓ 端口 $port 突发保护已配置"
                log "  触发速率: $burst_rate_input"
                log "  检测窗口: ${burst_window}分钟"
                log "  限速至: $throttle_rate_input"
                log "  限速时长: ${throttle_duration}分钟"
                ;;

            2)
                db_burst_remove_config "$port"
                db_burst_clear_throttled "$port"

                log_success "✓ 端口 $port 突发保护已禁用"
                ;;

            0)
                return
                ;;

            *)
                log_error "无效选择"
                ;;
        esac
    else
        log_error "无效选择"
    fi

    read -p "按回车继续..." _
}

ui_setup_telegram() {
    echo -e "\n${CYAN}=== Telegram 通知设置 ===${NC}\n"

    local enabled=$(db_config_get "telegram_enabled")
    echo "当前状态: $([ "$enabled" = "true" ] && echo "${GREEN}已启用${NC}" || echo "${GRAY}未启用${NC}")"
    echo ""

    echo "1. 启用/禁用通知"
    echo "2. 设置 Bot Token"
    echo "3. 设置 Chat ID"
    echo "4. 测试通知"
    echo "0. 返回"
    echo ""

    read -p "选择 [0-4]: " choice
    case $choice in
        1)
            if [ "$enabled" = "true" ]; then
                db_config_set "telegram_enabled" "false"
                log_success "Telegram 通知已禁用"
            else
                db_config_set "telegram_enabled" "true"
                log_success "Telegram 通知已启用"
            fi
            ;;
        2)
            read -p "Bot Token: " bot_token
            db_config_set "telegram_bot_token" "$bot_token"
            log_success "Bot Token 已更新"
            ;;
        3)
            read -p "Chat ID: " chat_id
            db_config_set "telegram_chat_id" "$chat_id"
            log_success "Chat ID 已更新"
            ;;
        4)
            if telegram_send "✅ 测试消息\n\n时间: $(date '+%Y-%m-%d %H:%M:%S')"; then
                log_success "测试消息已发送"
            else
                log_error "发送失败，请检查配置"
            fi
            ;;
    esac

    read -p "按回车继续..." _
}

ui_uninstall() {
    echo -e "\n${RED}=== 卸载脚本 ===${NC}\n"

    echo "将删除以下内容:"
    echo "  - 所有 nftables 规则和计数器"
    echo "  - 所有 TC 限速规则"
    echo "  - systemd 定时器"
    echo "  - 配置数据库和日志"
    echo "  - 快捷命令"
    echo ""

    read -p "确认卸载? 输入 'YES' 继续: " confirm
    if [ "$confirm" != "YES" ]; then
        log "已取消"
        read -p "按回车继续..." _
        return
    fi

    log "正在卸载..."

    # 删除所有端口
    local ports=($(db_port_list))
    for port in "${ports[@]}"; do
        port_remove "$port"
    done

    # 删除全局定时器
    systemd_remove_global_timers

    # 删除 nftables 表
    nft delete table $NFT_FAMILY $NFT_TABLE 2>/dev/null || true

    # 删除 TC 配置
    local interface=$(tc_get_default_interface)
    [ -n "$interface" ] && tc qdisc del dev "$interface" root 2>/dev/null || true
    tc qdisc del dev ifb0 root 2>/dev/null || true
    ip link set ifb0 down 2>/dev/null || true

    # 删除配置和日志
    rm -rf "$CONFIG_DIR"
    rm -rf "$LOG_DIR"
    rm -f "$LOCK_FILE"

    # 删除快捷命令
    rm -f "/usr/local/bin/$SHORTCUT_COMMAND"

    log_success "✓ 卸载完成"
    exit 0
}

# ============================================================================
# 主程序入口
# ============================================================================

main() {
    check_root "$@"
    check_dependencies

    # CLI 参数处理
    if [ $# -gt 0 ]; then
        case "$1" in
            --reset-port)
                db_init
                port_reset_traffic "$2"
                exit 0
                ;;
            --check-alert)
                db_init
                telegram_check_alerts
                exit 0
                ;;
            --check-burst)
                db_init
                nft_init
                tc_init
                burst_check_all_ports
                exit 0
                ;;
            --version|-v)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                exit 0
                ;;
            --help|-h)
                cat <<EOF
$SCRIPT_NAME v$SCRIPT_VERSION

用法:
  $0                   启动交互式界面
  $0 --reset-port PORT 重置指定端口流量
  $0 --check-alert     检查配额告警
  $0 --check-burst     检查突发保护
  $0 --version         显示版本
  $0 --help            显示帮助

交互式界面功能:
  - 端口监控和流量统计
  - 带宽限速控制
  - 流量配额管理
  - 突发速率保护
  - Telegram 通知告警

EOF
                exit 0
                ;;
            *)
                log_error "未知参数: $1"
                echo "使用 --help 查看帮助"
                exit 1
                ;;
        esac
    fi

    # 初始化
    db_init
    nft_init
    tc_init

    # 创建全局定时器
    systemd_create_global_timers

    # 创建快捷命令
    if [ ! -L "/usr/local/bin/$SHORTCUT_COMMAND" ]; then
        ln -sf "$SCRIPT_PATH" "/usr/local/bin/$SHORTCUT_COMMAND"
        log_success "快捷命令已创建: $SHORTCUT_COMMAND"
    fi

    # 交互式菜单循环
    while true; do
        ui_show_status
        ui_show_menu

        read -p "选择 [0-10]: " choice

        case "$choice" in
            1) ui_add_port ;;
            2) ui_remove_port ;;
            3) ui_modify_remark ;;
            4) ui_set_bandwidth ;;
            5) ui_set_quota ;;
            6) ui_reset_traffic ;;
            7) ui_setup_burst_protection ;;
            8) ui_setup_telegram ;;
            9)
                if [ "$(db_config_get 'telegram_enabled')" = "true" ]; then
                    telegram_send "📊 端口流量状态

时间: $(date '+%Y-%m-%d %H:%M:%S')
监控端口数: $(db_port_list | wc -l)"
                    log_success "状态已发送"
                else
                    log_warn "请先启用 Telegram 通知"
                fi
                read -p "按回车继续..." _
                ;;
            10) ui_uninstall ;;
            0) echo "" ; log "退出" ; exit 0 ;;
            *) log_error "无效选择" ; sleep 1 ;;
        esac
    done
}

main "$@"
