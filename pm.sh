#!/bin/bash

# ==============================================================================
# Linux 端口流量管理脚本 (Port Monitor & Shaper)
# 版本: v5.6.3 (终端列表布局优化)
# ==============================================================================

# --- 全局配置 ---
SHORTCUT_NAME="pm"
INSTALL_PATH="/usr/local/bin/$SHORTCUT_NAME"
# [注意] 如果您 Fork 了此脚本，请修改下方的更新源地址
DOWNLOAD_URL="https://raw.githubusercontent.com/white-u/vps_script/main/pm.sh"

CONFIG_DIR="/etc/port_monitor"
CONFIG_FILE="$CONFIG_DIR/config.json"
STATE_DIR="$CONFIG_DIR/state"
TC_OWNER_FILE="$CONFIG_DIR/tc_root_owned"
LOCK_FILE="/var/run/pm.lock"
CRON_LOCK_FILE="/var/run/pm_cron.lock"
LOG_FILE="/var/log/port_monitor.log"
SCRIPT_VERSION="5.6.3"
# 配置结构版本号 (用于数据迁移)
CURRENT_CONFIG_VERSION=6
# 信号锁文件：当此文件存在时，Cron 暂停运行，防止覆盖用户正在编辑的数据
USER_EDIT_LOCK="/tmp/pm_user_editing"
NFT_TABLE="inet port_monitor"
TC_CLASS_MAP="burst_classes"
MAX_QUOTA_GB=8589934591
PORT_STATE_VERSION=2
BURST_TRIGGER_MBPS=300
BURST_TRIGGER_MINUTES=20
BURST_LIMIT_MBPS=50
BURST_DURATION_MINUTES=5
BURST_MAX_SAMPLE_SECONDS=90
SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null)

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'
TG_DIVIDER="━━━━━━━━━━━━━━"
UI_DIVIDER="=============================================================================="
UI_SEPARATOR="------------------------------------------------------------------------------"

pm_error() {
    local message="$*"
    local line="$(date '+%Y-%m-%d %H:%M:%S') [ERROR] ${message}"
    if ! printf '%s\n' "$line" >> "$LOG_FILE" 2>/dev/null; then
        command -v logger >/dev/null 2>&1 && logger -t port-monitor -- "$message" 2>/dev/null || true
        printf '%s\n' "$line" >&2
    fi
    if [ -t 2 ]; then
        echo -e "${RED}❌ ${message}${PLAIN}" >&2
    fi
}

rotate_pm_log() {
    [ -f "$LOG_FILE" ] || return 0
    local size=$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$size" -gt 1048576 ] 2>/dev/null; then
        local rotated="${LOG_FILE}.tmp.$$"
        tail -n 1000 "$LOG_FILE" > "$rotated" 2>/dev/null && mv -f "$rotated" "$LOG_FILE"
        rm -f "$rotated" 2>/dev/null
    fi
}

# --- 临时资源清理 ---
_CLEANUP_FILES=()
_IS_MENU_MODE=false
_CONNECTION_SNAPSHOT_FILE=""
_UNIQUE_CONNECTION_SNAPSHOT_FILE=""
_CONNECTION_SNAPSHOT_TS=0
_SENTINEL_GEO_REQUESTS=0
_TG_SYNC_FAILED=false
_MENU_LOCK_HELD=false
_global_cleanup() {
    for f in "${_CLEANUP_FILES[@]+"${_CLEANUP_FILES[@]}"}"; do
        rm -rf "$f" 2>/dev/null
    done
    # 仅菜单模式才删除编辑锁, cron(--monitor) 模式不能删(锁可能属于菜单进程)
    if [ "$_IS_MENU_MODE" == "true" ]; then
        rm -f "$USER_EDIT_LOCK" 2>/dev/null
        if [ "$_MENU_LOCK_HELD" == "true" ]; then
            flock -u 8 2>/dev/null || true
            exec 8>&-
            _MENU_LOCK_HELD=false
        fi
    fi
}
trap _global_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# 按需抓取一次当前 TCP 已建立连接，供同一轮任务中的 Sentinel 与云推送复用。
# 快照格式: 本地端口<TAB>对端 IP（每条连接一行，保留重复项用于连接数排序）。
_ensure_connection_snapshot() {
    if [ -n "$_CONNECTION_SNAPSHOT_FILE" ] && [ -f "$_CONNECTION_SNAPSHOT_FILE" ]; then
        return 0
    fi

    local snapshot_file
    snapshot_file=$(mktemp) || return 1
    _CLEANUP_FILES+=("$snapshot_file")
    _CONNECTION_SNAPSHOT_FILE="$snapshot_file"

    ss -Hnt state established 2>/dev/null | awk '
        function endpoint_port(value) {
            sub(/^.*:/, "", value)
            return value
        }
        function endpoint_ip(value) {
            sub(/:[^:]*$/, "", value)
            sub(/^\[/, "", value)
            sub(/\]$/, "", value)
            sub(/^::ffff:/, "", value)
            return value
        }
        {
            local_port = endpoint_port($3)
            peer_ip = endpoint_ip($4)
            if (local_port ~ /^[0-9]+$/ && peer_ip != "") {
                print local_port "\t" peer_ip
            }
        }
    ' > "$snapshot_file"
    local ss_status=${PIPESTATUS[0]}
    if [ "$ss_status" -ne 0 ]; then
        : > "$snapshot_file"
        _CONNECTION_SNAPSHOT_TS=0
        return 1
    fi
    _CONNECTION_SNAPSHOT_TS=$(date +%s)
}

_ensure_unique_connection_snapshot() {
    if [ -n "$_UNIQUE_CONNECTION_SNAPSHOT_FILE" ] && [ -f "$_UNIQUE_CONNECTION_SNAPSHOT_FILE" ]; then
        return 0
    fi
    _ensure_connection_snapshot || true

    local unique_file
    unique_file=$(mktemp) || return 1
    _CLEANUP_FILES+=("$unique_file")
    _UNIQUE_CONNECTION_SNAPSHOT_FILE="$unique_file"
    sort -t $'\t' -k1,1n -k2,2 -u "$_CONNECTION_SNAPSHOT_FILE" > "$unique_file" 2>/dev/null || : > "$unique_file"
}

# --- 输入清洗 ---
# Windows 终端/SSH 粘贴可能带 \r (CR)，导致正则校验失败或 bc 报错
strip_cr() { echo "${1//$'\r'/}"; }

confirm_yes() {
    local prompt=$1 answer
    read -r -p "${prompt} [y/N，默认 N]: " answer
    answer=$(strip_cr "$answer")
    [[ "$answer" =~ ^[Yy]$ ]]
}

validate_expiry_date() {
    local value=$1 normalized
    [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1
    normalized=$(date -d "$value" '+%Y-%m-%d' 2>/dev/null) || return 1
    [ "$normalized" = "$value" ]
}

fresh_script_url() {
    printf '%s?t=%s-%s' "$DOWNLOAD_URL" "$(date +%s)" "$$"
}

validate_script_candidate() {
    local file=$1
    local version
    [ -s "$file" ] || return 1
    head -n 1 "$file" | grep -qx '#!/bin/bash' || return 1
    grep -q '^SCRIPT_VERSION="' "$file" || return 1
    version=$(grep '^SCRIPT_VERSION=' "$file" | head -1 | cut -d'"' -f2)
    [[ "$version" =~ ^[0-9]+([.][0-9]+)*$ ]] || return 1
    bash -n "$file"
}

validate_config_candidate() {
    local file=$1
    jq -e --argjson max_quota "$MAX_QUOTA_GB" '
        type == "object" and (.ports | type == "object") and
        all(.ports | to_entries[];
            (.key | try tonumber catch null) as $port |
            $port != null and $port >= 1 and $port <= 65535 and
            (.value | type == "object") and
            ((.value.quota_gb | type) == "number") and
            (.value.quota_gb == (.value.quota_gb | floor)) and
            (.value.quota_gb >= 1 and .value.quota_gb <= $max_quota) and
            ((.value.quota_mode // "in_out") as $mode | ($mode == "in_out" or $mode == "out_only")) and
            (((.value.dyn_limit // {"enable": false}) | type) == "object") and
            (((.value.dyn_limit.enable // false) | type) == "boolean") and
            (((.value.ip_limit // {}) | type) == "object") and
            (((.value.ip_limit.enable // false) | type) == "boolean") and
            (((.value.ip_limit.max_ips // 3) | type) == "number") and
            ((.value.ip_limit.max_ips // 3) == ((.value.ip_limit.max_ips // 3) | floor)) and
            ((.value.ip_limit.max_ips // 3) >= 1 and (.value.ip_limit.max_ips // 3) <= 65535) and
            (((.value.ip_limit.cooldown_min // 30) | type) == "number") and
            ((.value.ip_limit.cooldown_min // 30) == ((.value.ip_limit.cooldown_min // 30) | floor)) and
            ((.value.ip_limit.cooldown_min // 30) >= 1 and (.value.ip_limit.cooldown_min // 30) <= 525600) and
            ((.value.ip_limit.action // "alert") as $action | ($action == "alert" or $action == "block")) and
            (((.value.ip_limit.whitelist // []) | type) == "array") and
            all((.value.ip_limit.whitelist // [])[]; type == "string") and
            (((.value.reset_day // 0) | type) == "number") and
            ((.value.reset_day // 0) == ((.value.reset_day // 0) | floor)) and
            ((.value.reset_day // 0) >= 0 and (.value.reset_day // 0) <= 31)
        )
    ' "$file" >/dev/null 2>&1
}

version_is_older() {
    local candidate=$1 current=$2 i candidate_part current_part
    local IFS=.
    local -a candidate_parts current_parts
    read -ra candidate_parts <<< "$candidate"
    read -ra current_parts <<< "$current"
    for ((i=0; i<${#candidate_parts[@]} || i<${#current_parts[@]}; i++)); do
        candidate_part=${candidate_parts[i]:-0}; current_part=${current_parts[i]:-0}
        ((10#$candidate_part < 10#$current_part)) && return 0
        ((10#$candidate_part > 10#$current_part)) && return 1
    done
    return 1
}

# --- 端口运行状态 读/写 (零 fork, bash 内置) ---
# 所有运行时变量使用 s_ 前缀, 避免与其他变量冲突
_init_port_state_defaults() {
    s_state_version=0
    s_acc_in=0; s_acc_out=0; s_last_k_in=0; s_last_k_out=0
    s_last_reset_ts=0; s_high_seconds=0; s_is_punished=false; s_punish_end_ts=0
    s_quota_level=0; s_punish_notified=false; s_recover_notified=true
    s_last_alert_ts=0; s_last_alert_ips=""; s_ip_alert_level=0
    s_expiry_notified_date=""
    s_last_sample_ts=0; s_rules_dirty=false; s_pending_qos_notice=""
}

_load_port_state() {
    _init_port_state_defaults
    local sf="$STATE_DIR/${1}.txt"
    [ -f "$sf" ] || return 0

    # 状态文件是数据而不是脚本；仅接收已知字段，损坏内容不会被执行。
    local key value
    while IFS='=' read -r key value; do
        case "$key" in
            s_state_version|s_acc_in|s_acc_out|s_last_k_in|s_last_k_out|s_last_reset_ts|s_high_seconds|s_punish_end_ts|s_quota_level|s_last_alert_ts|s_ip_alert_level|s_last_sample_ts)
                [[ "$value" =~ ^[0-9]+$ ]] && printf -v "$key" '%s' "$value"
                ;;
            s_is_punished|s_punish_notified|s_recover_notified|s_rules_dirty)
                [[ "$value" == "true" || "$value" == "false" ]] && printf -v "$key" '%s' "$value"
                ;;
            s_last_alert_ips)
                printf -v "$key" '%s' "$value"
                ;;
            s_expiry_notified_date)
                [[ -z "$value" || "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] && printf -v "$key" '%s' "$value"
                ;;
            s_pending_qos_notice)
                [[ -z "$value" || "$value" == "punish" || "$value" == "recover" ]] && printf -v "$key" '%s' "$value"
                ;;
        esac
    done < "$sf"

    # v1 状态可能包含旧的自定义 QoS 惩罚；升级后统一从固定策略的未触发状态开始。
    if [ "$s_state_version" -lt "$PORT_STATE_VERSION" ]; then
        s_state_version=$PORT_STATE_VERSION
        s_high_seconds=0; s_is_punished=false; s_punish_end_ts=0
        s_punish_notified=false; s_recover_notified=true
        s_rules_dirty=false; s_pending_qos_notice=""
    fi
}

_save_port_state() {
    local port=$1 tmp
    [[ "$port" =~ ^[0-9]+$ ]] || { pm_error "拒绝写入无效端口状态: ${port}"; return 1; }
    tmp=$(mktemp "$STATE_DIR/.${port}.tmp.XXXXXX") || { pm_error "无法创建端口 ${port} 的状态临时文件"; return 1; }
    if ! cat > "$tmp" << STATEEOF
s_state_version=$PORT_STATE_VERSION
s_acc_in=$s_acc_in
s_acc_out=$s_acc_out
s_last_k_in=$s_last_k_in
s_last_k_out=$s_last_k_out
s_last_reset_ts=$s_last_reset_ts
s_high_seconds=$s_high_seconds
s_is_punished=$s_is_punished
s_punish_end_ts=$s_punish_end_ts
s_quota_level=$s_quota_level
s_punish_notified=$s_punish_notified
s_recover_notified=$s_recover_notified
s_last_alert_ts=$s_last_alert_ts
s_last_alert_ips=$s_last_alert_ips
s_ip_alert_level=$s_ip_alert_level
s_expiry_notified_date=$s_expiry_notified_date
s_last_sample_ts=$s_last_sample_ts
s_rules_dirty=$s_rules_dirty
s_pending_qos_notice=$s_pending_qos_notice
STATEEOF
    then
        rm -f "$tmp"
        pm_error "端口 ${port} 状态写入失败"
        return 1
    fi
    if ! chmod 600 "$tmp" || ! mv -f "$tmp" "$STATE_DIR/${port}.txt"; then
        rm -f "$tmp"
        pm_error "端口 ${port} 状态提交失败"
        return 1
    fi
}

# ==============================================================================
# 1. 基础架构模块 (安装与环境)
# ==============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 必须使用 root 权限运行此脚本。${PLAIN}"
        exit 1
    fi
}

# 智能安装逻辑：兼容管道运行、Loader加载和本地运行
install_shortcut() {
    # 如果是 Cron 模式，或者当前运行的程序路径($0)已经是安装目标，则跳过安装
    [[ "$1" == "--monitor" || "$1" == "--ipl" ]] && return
    [[ "$0" == "$INSTALL_PATH" ]] && return
    
    # 增加逻辑：如果是被 source 加载的 (Loader 模式)，$0 也是 INSTALL_PATH，会自动跳过，无需额外改动
    
    echo -e "${YELLOW}正在初始化系统环境...${PLAIN}"
    
    # 下载到临时文件, 校验成功后再覆盖, 防止中途断网损坏已有脚本
    local tmp_dl
    tmp_dl=$(mktemp "${INSTALL_PATH}.install.XXXXXX") || {
        echo -e "${RED}无法创建快捷命令安装临时文件。${PLAIN}" >&2
        return 1
    }
    
    # 验证下载完整性
    if curl -fsSLo "$tmp_dl" --connect-timeout 8 --max-time 15 "$(fresh_script_url)" \
        && validate_script_candidate "$tmp_dl"; then
        if ! chmod 755 "$tmp_dl" || ! mv -f "$tmp_dl" "$INSTALL_PATH"; then
            echo -e "${RED}快捷命令安装失败，现有文件未被覆盖。${PLAIN}" >&2
            return 1
        fi
        echo -e "${GREEN}安装成功! 快捷指令: $SHORTCUT_NAME${PLAIN}"
        echo -e "${GREEN}正在启动管理面板...${PLAIN}"
        sleep 1
        # 移交控制权给安装好的脚本
        exec "$INSTALL_PATH" "$@"
    else
        # 降级策略：本地复制 (仅当本地文件存在且非管道运行时)
        if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ] \
            && validate_script_candidate "$SCRIPT_PATH"; then
            echo -e "${YELLOW}网络下载失败，尝试本地安装...${PLAIN}"
            if ! cp "$SCRIPT_PATH" "$tmp_dl" || ! chmod 755 "$tmp_dl" \
                || ! mv -f "$tmp_dl" "$INSTALL_PATH"; then
                echo -e "${RED}快捷命令本地安装失败，现有文件未被覆盖。${PLAIN}" >&2
                return 1
            fi
            exec "$INSTALL_PATH" "$@"
        else
            rm -f "$tmp_dl"
            echo -e "${RED}无法安装快捷指令；后台任务依赖 ${INSTALL_PATH}，本次安装已停止。${PLAIN}" >&2
            return 1
        fi
    fi
}

get_iface() {
    ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n 1
}

install_deps() {
    # 核心依赖清单 (Alpine 需特判)
    local deps=("nft" "tc" "jq" "bc" "curl" "ss" "numfmt" "flock" "stat" "openssl" "crontab")
    local missing=false
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then missing=true; break; fi
    done

    if [ "$missing" = true ]; then
        echo -e "${YELLOW}正在安装依赖 (${deps[*]})...${PLAIN}"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case $ID in
                debian|ubuntu)
                    if ! apt-get update -q; then
                        echo -e "${YELLOW}警告: 部分 APT 软件源刷新失败；将使用现有索引继续安装依赖。请检查上方报错的软件源。${PLAIN}" >&2
                    fi
                    apt-get install -y -q nftables iproute2 jq bc curl coreutils util-linux openssl cron || true ;;
                centos|rhel|almalinux|rocky)
                    yum install -y -q nftables iproute tc jq bc curl coreutils util-linux openssl cronie ;;
                alpine)
                    # Alpine 特别需要 coreutils(stat, numfmt) 和 util-linux(flock)
                    apk add --no-cache nftables iproute2 jq bc curl coreutils util-linux openssl dcron ;;
                *)
                    echo -e "${RED}系统不受支持，请手动安装: ${deps[*]}${PLAIN}" && exit 1 ;;
            esac
        fi
        # 验证全部声明依赖，禁止安装器失败后带病进入菜单。
        local failed=()
        for dep in "${deps[@]}"; do
            command -v "$dep" &>/dev/null || failed+=("$dep")
        done
        if [[ ${#failed[@]} -gt 0 ]]; then
            echo -e "${RED}依赖安装失败: ${failed[*]}，请手动安装后重试。${PLAIN}"
            exit 1
        fi
    fi

    # 初始化配置目录与文件
    if ! mkdir -p "$CONFIG_DIR" "$STATE_DIR"; then
        echo -e "${RED}无法创建配置目录 ${CONFIG_DIR}。${PLAIN}" >&2
        exit 1
    fi
    chmod 700 "$CONFIG_DIR" "$STATE_DIR" 2>/dev/null || {
        echo -e "${RED}无法保护配置目录权限。${PLAIN}" >&2
        exit 1
    }
    # 仅首次运行时创建配置；已有配置损坏时保留现场并停止，禁止静默清空。
    if [ ! -e "$CONFIG_FILE" ]; then
        safe_write_config '{"node_id": "'"$(hostname 2>/dev/null || echo unknown)"'", "interface": "'"$(get_iface)"'", "ports": {}, "telegram": {"enable": false, "bot_token": "", "chat_id": "", "api_url": "https://api.telegram.org", "thresholds": [50, 80, 100]}}' || exit 1
    elif [ ! -s "$CONFIG_FILE" ] || ! validate_config_candidate "$CONFIG_FILE"; then
        local corrupt_backup="${CONFIG_FILE}.corrupt.$(date +%Y%m%d%H%M%S)"
        cp -p "$CONFIG_FILE" "$corrupt_backup" 2>/dev/null || true
        echo -e "${RED}错误: 配置文件损坏或字段无效，已保留为 ${corrupt_backup}，请修复后重试。${PLAIN}" >&2
        exit 1
    fi
    # 确保存在 telegram 字段 (旧版本升级兼容)
    if ! jq -e '.telegram' "$CONFIG_FILE" >/dev/null 2>&1; then
        local tmp=$(mktemp)
        if ! jq '.telegram = {"enable": false, "bot_token": "", "chat_id": "", "api_url": "https://api.telegram.org", "thresholds": [50, 80, 100]}' "$CONFIG_FILE" > "$tmp" \
            || ! safe_write_config_from_file "$tmp"; then
            rm -f "$tmp"; pm_error "Telegram 默认配置补全失败"; exit 1
        fi
        rm -f "$tmp"
    fi
    # 确保存在 node_id 字段 (旧版本升级兼容)
    if ! jq -e '.node_id' "$CONFIG_FILE" >/dev/null 2>&1; then
        local tmp=$(mktemp)
        if ! jq --arg nid "$(hostname 2>/dev/null || echo unknown)" '.node_id = $nid' "$CONFIG_FILE" > "$tmp" \
            || ! safe_write_config_from_file "$tmp"; then
            rm -f "$tmp"; pm_error "节点标识补全失败"; exit 1
        fi
        rm -f "$tmp"
    fi
    # 确保存在 push 字段 (v4.4+ 云端推送)
    if ! jq -e '.push' "$CONFIG_FILE" >/dev/null 2>&1; then
        local tmp=$(mktemp)
        if ! jq '.push = {"enable": false, "worker_url": "", "secret": "", "node_key": ""}' "$CONFIG_FILE" > "$tmp" \
            || ! safe_write_config_from_file "$tmp"; then
            rm -f "$tmp"; pm_error "云端推送默认配置补全失败"; exit 1
        fi
        rm -f "$tmp"
    fi
    # 保护配置文件 (含 bot_token)
    chmod 600 "$CONFIG_FILE" || { echo -e "${RED}无法保护配置文件权限。${PLAIN}" >&2; exit 1; }
    find "$STATE_DIR" -maxdepth 1 -type f -name '*.txt' -exec chmod 600 {} + 2>/dev/null || true
    
    # 执行数据迁移
    migrate_config || exit 1
}

# ==============================================================================
# 1.5 数据迁移模块 (Schema Migration)
# ==============================================================================

migrate_config() {
    local modified=false
    local tmp_json=$(cat "$CONFIG_FILE")
    
    # 获取当前文件内的版本号 (若无则为0)
    local file_ver=$(echo "$tmp_json" | jq -r '.config_version // 0')
    
    # --- 迁移逻辑链 ---
    
    # v0 -> v1: 初始化版本号 & 规范化 group_id
    if [ "$file_ver" -lt 1 ]; then
        echo -e "${YELLOW}正在升级配置文件结构 (v${file_ver} -> v1)...${PLAIN}"
        
        # 1. 补全 config_version
        # 2. 遍历所有端口，如果缺 group_id，补全为空字符串 (规范化)
        # 3. 清理可能存在的废弃字段 (示例: 删除 legacy_field)
        tmp_json=$(echo "$tmp_json" | jq '
            .config_version = 1 |
            .ports |= with_entries(
                .value.group_id = (.value.group_id // "") |
                del(.value.legacy_field)
            )
        ')
        modified=true
    fi
    
    # 未来 v1 -> v2 可以继续追加:
    if [ "$file_ver" -lt 2 ]; then
        echo -e "${YELLOW}正在升级配置文件结构 (v${file_ver} -> v2)...${PLAIN}"
        # 为所有端口补全 ip_limit 默认结构 (接入监控)
        tmp_json=$(echo "$tmp_json" | jq '
            .config_version = 2 |
            .ports |= with_entries(
                .value.ip_limit = (.value.ip_limit // {
                    "enable": false,
                    "max_ips": 3,
                    "action": "alert",
                    "cooldown_min": 30,
                    "whitelist": [],
                    "last_alert_ts": 0,
                    "last_alert_ips": []
                })
            )
        ')
        modified=true
    fi

    # v2 -> v3: 运行状态分离至 state/*.txt (cron 零 jq 读写)
    if [ "$file_ver" -lt 3 ]; then
        echo -e "${YELLOW}正在升级配置文件结构 (v${file_ver} -> v3: 状态分离)...${PLAIN}"
        mkdir -p "$STATE_DIR"
        # 从 config.json 提取每个端口的运行状态写入 .txt
        local _mig_ports=$(echo "$tmp_json" | jq -r '.ports | keys[]')
        for _mp in $_mig_ports; do
            local _sf="$STATE_DIR/${_mp}.txt"
            [ -f "$_sf" ] && continue  # 已有则跳过
            IFS=$'\t' read -r _ai _ao _ki _ko _lrt _ql _lat _laips <<< \
                "$(echo "$tmp_json" | jq -r ".ports[\"$_mp\"] | [
                    ((.stats.acc_in//0)|floor), ((.stats.acc_out//0)|floor),
                    ((.stats.last_kernel_in//0)|floor), ((.stats.last_kernel_out//0)|floor),
                    ((.last_reset_ts//0)|floor),
                    (.notify_state.quota_level//0),
                    (.ip_limit.last_alert_ts//0),
                    ((.ip_limit.last_alert_ips//[]) | join(\",\"))
                ] | @tsv")"
            cat > "$_sf" << MEOF
s_acc_in=${_ai:-0}
s_acc_out=${_ao:-0}
s_last_k_in=${_ki:-0}
s_last_k_out=${_ko:-0}
s_last_reset_ts=${_lrt:-0}
s_state_version=$PORT_STATE_VERSION
s_high_seconds=0
s_is_punished=false
s_punish_end_ts=0
s_quota_level=${_ql:-0}
s_punish_notified=false
s_recover_notified=true
s_last_alert_ts=${_lat:-0}
s_last_alert_ips=${_laips:-}
s_ip_alert_level=0
s_expiry_notified_date=
MEOF
        done
        tmp_json=$(echo "$tmp_json" | jq '.config_version = 3')
        modified=true
    fi

    # v3 -> v4: 为每个端口增加用户到期日期；空字符串表示不提醒。
    if [ "$file_ver" -lt 4 ]; then
        echo -e "${YELLOW}正在升级配置文件结构 (v${file_ver} -> v4: 用户到期提醒)...${PLAIN}"
        tmp_json=$(echo "$tmp_json" | jq '
            .config_version = 4 |
            .ports |= with_entries(
                .value.expiry_date = (
                    if ((.value.expiry_date // "") | type) == "string"
                    then (.value.expiry_date // "")
                    else ""
                    end
                )
            )
        ')
        modified=true
    fi

    # v4 -> v5: 移除基础限速与自定义 QoS 参数，只保留固定突发策略开关。
    if [ "$file_ver" -lt 5 ]; then
        echo -e "${YELLOW}正在升级配置文件结构 (v4 -> v5: 固定突发限速)...${PLAIN}"
        tmp_json=$(echo "$tmp_json" | jq '
            .config_version = 5 |
            .ports |= with_entries(
                .value.dyn_limit = {"enable": (.value.dyn_limit.enable == true)} |
                del(.value.limit_mbps)
            )
        ')
        modified=true
    fi

    # v5 -> v6: Telegram 不再提供配额重置通知和定时流量报告。
    if [ "$file_ver" -lt 6 ]; then
        echo -e "${YELLOW}正在升级配置文件结构 (v5 -> v6: 精简通知设置)...${PLAIN}"
        tmp_json=$(echo "$tmp_json" | jq '
            .config_version = 6 |
            if ((.telegram // {}) | type) == "object" then
                .telegram |= del(.report_interval_hours, .last_report_ts)
            else . end
        ')
        modified=true
    fi
    if [ "$modified" == "true" ]; then
        local tmp_file=$(mktemp)
        printf '%s\n' "$tmp_json" > "$tmp_file"
        if ! safe_write_config_from_file "$tmp_file"; then
            rm -f "$tmp_file"
            pm_error "配置文件迁移写入失败，原配置保持不变"
            return 1
        fi
        rm -f "$tmp_file"
        find "$STATE_DIR" -maxdepth 1 -type f -name '*.txt' -exec chmod 600 {} + 2>/dev/null || true
        echo -e "${GREEN}配置文件已升级至 v${CURRENT_CONFIG_VERSION}。${PLAIN}"
        sleep 1
    fi
}

# ==============================================================================
# 2. 网络引擎模块 (Nftables + TC)
# ==============================================================================

init_nft_table() {
    nft list table $NFT_TABLE &>/dev/null
    if [ $? -ne 0 ]; then
        nft add table $NFT_TABLE || { echo -e "${RED}[错误] 无法创建 nft 表，请检查 nftables 是否正常。${PLAIN}" >&2; return 1; }
        nft add set $NFT_TABLE blocked_ports { type inet_service\; } || {
            pm_error "无法创建 Nftables blocked_ports 集合"; nft delete table $NFT_TABLE 2>/dev/null; return 1;
        }
        nft add map $NFT_TABLE "$TC_CLASS_MAP" { type inet_service : classid\; } || {
            pm_error "无法创建 Nftables ${TC_CLASS_MAP} 映射"; nft delete table $NFT_TABLE 2>/dev/null; return 1;
        }
        # 优先级 -5，确保先计数再通过系统防火墙(UFW等通常是0)
        nft add chain $NFT_TABLE input { type filter hook input priority -5\; } || {
            pm_error "无法创建 Nftables input 链"; nft delete table $NFT_TABLE 2>/dev/null; return 1;
        }
        nft add chain $NFT_TABLE output { type filter hook output priority -5\; } || {
            pm_error "无法创建 Nftables output 链"; nft delete table $NFT_TABLE 2>/dev/null; return 1;
        }
        
        # 显式拆分 TCP/UDP，修复部分内核兼容性
        nft add rule $NFT_TABLE input tcp dport @blocked_ports drop || { pm_error "无法创建 TCP 入站封禁规则"; nft delete table $NFT_TABLE 2>/dev/null; return 1; }
        nft add rule $NFT_TABLE input udp dport @blocked_ports drop || { pm_error "无法创建 UDP 入站封禁规则"; nft delete table $NFT_TABLE 2>/dev/null; return 1; }
        nft add rule $NFT_TABLE output tcp sport @blocked_ports drop || { pm_error "无法创建 TCP 出站封禁规则"; nft delete table $NFT_TABLE 2>/dev/null; return 1; }
        nft add rule $NFT_TABLE output udp sport @blocked_ports drop || { pm_error "无法创建 UDP 出站封禁规则"; nft delete table $NFT_TABLE 2>/dev/null; return 1; }
        # 只有实际限速端口才在 map 中；直接设置 TC classid，不占用 packet mark。
        nft add rule $NFT_TABLE output meta priority set tcp sport map @"$TC_CLASS_MAP" || {
            pm_error "无法创建 TCP 限速分类规则"; nft delete table $NFT_TABLE 2>/dev/null; return 1;
        }
        nft add rule $NFT_TABLE output meta priority set udp sport map @"$TC_CLASS_MAP" || {
            pm_error "无法创建 UDP 限速分类规则"; nft delete table $NFT_TABLE 2>/dev/null; return 1;
        }
        return 0
    fi
    return 0
}

nft_table_healthy() {
    nft list set $NFT_TABLE blocked_ports >/dev/null 2>&1 || return 1
    local input_rules output_rules
    input_rules=$(nft list chain $NFT_TABLE input 2>/dev/null) || return 1
    output_rules=$(nft list chain $NFT_TABLE output 2>/dev/null) || return 1
    [ "$(grep -Fc '@blocked_ports' <<< "$input_rules")" -eq 2 ] 2>/dev/null || return 1
    [ "$(grep -Fc '@blocked_ports' <<< "$output_rules")" -eq 2 ] 2>/dev/null || return 1
    [ "$(grep -Fc "@${TC_CLASS_MAP}" <<< "$output_rules")" -eq 2 ] 2>/dev/null || return 1
}

init_tc_root() {
    local iface qdisc_state
    iface=$(jq -r '.interface // empty' "$CONFIG_FILE")
    [ -z "$iface" ] && iface=$(get_iface)
    
    if [ -z "$iface" ]; then
        echo -e "${RED}[错误] 无法获取网络接口，请检查网络配置。${PLAIN}" >&2
        return 1
    fi
    
    qdisc_state=$(tc qdisc show dev "$iface" 2>/dev/null) || {
        pm_error "无法读取 ${iface} 的 TC 队列"
        return 1
    }

    # 不接管其他程序的 HTB 根队列，避免 class 冲突及卸载残留。
    if grep -Eq 'qdisc htb 1:.* root' <<< "$qdisc_state"; then
        if [ ! -f "$TC_OWNER_FILE" ] || [ "$(cat "$TC_OWNER_FILE" 2>/dev/null)" != "$iface" ]; then
            echo -e "${RED}[错误] ${iface} 已存在非 PM 管理的 HTB 1: 根队列，拒绝添加限速规则。${PLAIN}" >&2
            return 1
        fi
        return 0
    fi

    # 不设置默认分类：未命中 classid 的流量走 HTB direct queue，不受隐性带宽上限。
    if ! tc qdisc add dev "$iface" root handle 1: htb 2>/dev/null; then
        echo -e "${RED}[错误] 无法在 $iface 上创建 TC 队列, 限速功能可能不可用。${PLAIN}" >&2
        return 1
    fi
    if ! printf '%s\n' "$iface" > "$TC_OWNER_FILE" || ! chmod 600 "$TC_OWNER_FILE"; then
        tc qdisc del dev "$iface" root 2>/dev/null || true
        echo -e "${RED}[错误] 无法记录 TC 根队列所有权，已撤销创建。${PLAIN}" >&2
        return 1
    fi
}

ensure_port_class_map() {
    local port=$1 port_hex=$2
    class_map_has_port "$port" && return 0
    nft add element $NFT_TABLE "$TC_CLASS_MAP" \{ "$port" : "1:${port_hex}" \} 2>/dev/null && return 0
    pm_error "无法将端口 ${port} 加入 TC 分类映射"
    return 1
}

class_map_has_port() {
    local port=$1
    nft -n list map $NFT_TABLE "$TC_CLASS_MAP" 2>/dev/null \
        | grep -Eq "(^|[,{[:space:]])${port}[[:space:]]*:"
}

remove_port_class_map() {
    local port=$1
    nft list map $NFT_TABLE "$TC_CLASS_MAP" >/dev/null 2>&1 || return 0
    class_map_has_port "$port" || return 0
    nft delete element $NFT_TABLE "$TC_CLASS_MAP" \{ "$port" \} 2>/dev/null && return 0
    if class_map_has_port "$port"; then
        pm_error "端口 ${port} 的 TC 分类映射清理失败"
        return 1
    fi
    return 0
}

remove_port_tc_rules() {
    local port=$1 iface port_hex class_state
    remove_port_class_map "$port" || return 1

    iface=$(jq -r '.interface // empty' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$iface" ] && iface=$(get_iface)
    [ -n "$iface" ] || return 0
    # 仅修改 PM 自己创建的根队列。
    [ -f "$TC_OWNER_FILE" ] && [ "$(cat "$TC_OWNER_FILE" 2>/dev/null)" = "$iface" ] || return 0
    port_hex=$(printf '%x' "$port")

    tc class del dev "$iface" parent 1: classid "1:${port_hex}" 2>/dev/null || true
    class_state=$(tc class show dev "$iface" 2>/dev/null) || {
        pm_error "无法读取 ${iface} 的 TC class"
        return 1
    }
    if grep -Fq "class htb 1:${port_hex} " <<< "$class_state"; then
        pm_error "端口 ${port} 的 TC class 清理失败"
        return 1
    fi
    # 最后一个限速 class 删除后同步撤销 PM 根队列，仅监控模式不留 TC 影响。
    if ! grep -Fq 'class htb 1:' <<< "$class_state"; then
        reset_owned_tc_root || return 1
    fi
    return 0
}

reset_owned_tc_root() {
    [ -f "$TC_OWNER_FILE" ] || return 0
    local owner_iface qdisc_state
    owner_iface=$(cat "$TC_OWNER_FILE" 2>/dev/null)
    if [ -z "$owner_iface" ] || ! ip link show dev "$owner_iface" >/dev/null 2>&1; then
        rm -f "$TC_OWNER_FILE" || { pm_error "无法清理失效的 TC 所有权记录"; return 1; }
        return 0
    fi
    qdisc_state=$(tc qdisc show dev "$owner_iface" 2>/dev/null) || {
        pm_error "无法读取 ${owner_iface} 的 TC 队列"
        return 1
    }
    if grep -Eq 'qdisc htb 1:.* root' <<< "$qdisc_state" \
        && ! tc qdisc del dev "$owner_iface" root 2>/dev/null; then
        pm_error "无法重建 PM 自有的 TC 根队列"
        return 1
    fi
    rm -f "$TC_OWNER_FILE" || { pm_error "无法清理 TC 所有权记录"; return 1; }
}

apply_port_rules() {
    local port=$1
    local conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
    local burst_enabled=$(echo "$conf" | jq -r '.dyn_limit.enable // false')
    local effective_limit_mbps=0
    local iface=$(jq -r '.interface // empty' "$CONFIG_FILE")
    [ -z "$iface" ] && iface=$(get_iface)
    
    # 正常状态始终不限速；只有已接入端口处于保护期时才临时创建 50 Mbps class。
    _load_port_state "$port"
    if [ "$burst_enabled" == "true" ] && [ "$s_is_punished" == "true" ]; then
        effective_limit_mbps=$BURST_LIMIT_MBPS
    fi

    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || {
        pm_error "拒绝应用无效端口规则: ${port}"; return 1;
    }
    init_nft_table || { pm_error "Nftables 初始化失败（端口 ${port}）"; return 1; }

    # [双轨制] TC 使用 Hex 格式 ID，防止 >9999 报错
    local port_hex=$(printf '%x' $port)

    # 1. NFT: 计数器
    nft add counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null || \
        nft list counter $NFT_TABLE "cnt_in_${port}" >/dev/null 2>&1 || {
            pm_error "无法创建端口 ${port} 的入站计数器"; return 1;
        }
    nft add counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null || \
        nft list counter $NFT_TABLE "cnt_out_${port}" >/dev/null 2>&1 || {
            pm_error "无法创建端口 ${port} 的出站计数器"; return 1;
        }

    # 2. NFT: 统计（限速分类由全局 classid map 独立管理）
    # TCP/UDP 分开判断，防止规则重复堆积
    local input_rule_count output_rule_count
    input_rule_count=$(nft list chain $NFT_TABLE input 2>/dev/null | grep -Fc "counter name \"cnt_in_${port}\"")
    if [ "$input_rule_count" -eq 0 ]; then
        if ! printf '%s\n' \
            "add rule ${NFT_TABLE} input tcp dport ${port} counter name \"cnt_in_${port}\"" \
            "add rule ${NFT_TABLE} input udp dport ${port} counter name \"cnt_in_${port}\"" | nft -f -; then
            pm_error "无法创建端口 ${port} 的入站统计规则"
            return 1
        fi
    elif [ "$input_rule_count" -ne 2 ]; then
        pm_error "端口 ${port} 的入站统计规则不完整，请先执行规则重载"
        return 1
    fi
    
    output_rule_count=$(nft list chain $NFT_TABLE output 2>/dev/null | grep -Fc "counter name \"cnt_out_${port}\"")
    if [ "$output_rule_count" -eq 0 ]; then
        if ! printf '%s\n' \
            "add rule ${NFT_TABLE} output tcp sport ${port} counter name \"cnt_out_${port}\"" \
            "add rule ${NFT_TABLE} output udp sport ${port} counter name \"cnt_out_${port}\"" | nft -f -; then
            pm_error "无法创建端口 ${port} 的出站统计规则"
            return 1
        fi
    elif [ "$output_rule_count" -ne 2 ]; then
        pm_error "端口 ${port} 的出站统计规则不完整，请先执行规则重载"
        return 1
    fi

    # 3. TC: 不限速时只清理本端口；限速时先就绪 class，再将端口加入 map。
    if [ "$effective_limit_mbps" = "0" ]; then
        remove_port_tc_rules "$port" || return 1
        return 0
    fi

    init_tc_root || { pm_error "TC 初始化失败（端口 ${port}）"; return 1; }
    if ! tc class replace dev "$iface" parent 1: classid "1:${port_hex}" htb rate "${effective_limit_mbps}mbit" 2>/dev/null; then
        pm_error "端口 ${port} 的 TC 限速分类创建失败 (classid 1:${port_hex})"
        return 1
    fi
    if ! ensure_port_class_map "$port" "$port_hex"; then
        remove_port_tc_rules "$port" || pm_error "端口 ${port} 限速映射失败后的 TC 清理不完整"
        return 1
    fi
    return 0
}

reload_all_rules() {
    local blocked_before=""
    blocked_before=$(nft -j list set $NFT_TABLE blocked_ports 2>/dev/null | jq -r '
        [ .nftables[] | select(.set) | .set.elem[]? ] | map(tostring) | .[]' 2>/dev/null || true)
    # 只重建 PM 登记的 TC 根队列，同时清理旧 mark/filter/默认分类。
    reset_owned_tc_root || return 1
    # 彻底销毁旧表再重建，防止已删除端口的规则残留。
    if nft list table $NFT_TABLE >/dev/null 2>&1 && ! nft delete table $NFT_TABLE 2>/dev/null; then
        pm_error "无法删除旧 Nftables 规则表"
        return 1
    fi
    init_nft_table || { pm_error "Nftables 规则表重建失败"; return 1; }
    local ports=$(jq -r '.ports | keys[]' "$CONFIG_FILE")
    local reload_failed=false reload_port
    for reload_port in $ports; do
        apply_port_rules "$reload_port" || reload_failed=true
    done
    for reload_port in $blocked_before; do
        jq -e --arg p "$reload_port" '.ports[$p] != null' "$CONFIG_FILE" >/dev/null 2>&1 || continue
        nft add element $NFT_TABLE blocked_ports \{ "$reload_port" \} 2>/dev/null || {
            pm_error "无法恢复端口 ${reload_port} 的封禁状态"
            reload_failed=true
        }
    done
    [ "$reload_failed" == "false" ]
}

ensure_runtime_rules() {
    local port_count
    port_count=$(jq -r '.ports | length' "$CONFIG_FILE" 2>/dev/null) || return 1

    # 新安装且没有监控端口时不创建空表；仅清理可能存在的失效 TC 所有权。
    if [ "$port_count" -eq 0 ] && ! nft list table $NFT_TABLE >/dev/null 2>&1; then
        reset_owned_tc_root
        return $?
    fi
    nft_table_healthy && return 0

    echo -e "${YELLOW}检测到旧版或缺失的内核规则，正在进行一次性迁移...${PLAIN}"
    reload_all_rules || { pm_error "Nftables/TC 规则迁移失败"; return 1; }
    echo -e "${GREEN}内核规则已更新。${PLAIN}"
}

# ==============================================================================
# 3. 守护进程 (Writer: Cron)
# ==============================================================================

safe_write_config() {
    local content="$1"
    if ! (
        flock -x 200 || exit 1
        local tmp
        tmp=$(mktemp "$CONFIG_DIR/.config.json.tmp.XXXXXX") || exit 1
        printf '%s\n' "$content" > "$tmp"
        if ! validate_config_candidate "$tmp"; then
            rm -f "$tmp"
            echo -e "${RED}拒绝写入无效 JSON 配置。${PLAIN}" >&2
            exit 1
        fi
        chmod 600 "$tmp"
        mv -f "$tmp" "$CONFIG_FILE"
    ) 200>"$LOCK_FILE"; then
        pm_error "配置文件写入失败，原配置保持不变"
        return 1
    fi
    return 0
}

# 从文件原子写入配置 (避免 ARG_MAX 限制)
safe_write_config_from_file() {
    local src_file="$1"
    [ -s "$src_file" ] && validate_config_candidate "$src_file" || {
        echo -e "${RED}拒绝写入无效 JSON 配置。${PLAIN}" >&2
        return 1
    }
    if ! (
        flock -x 200 || exit 1
        local tmp
        tmp=$(mktemp "$CONFIG_DIR/.config.json.tmp.XXXXXX") || exit 1
        cp "$src_file" "$tmp" || { rm -f "$tmp"; exit 1; }
        chmod 600 "$tmp"
        mv -f "$tmp" "$CONFIG_FILE"
    ) 200>"$LOCK_FILE"; then
        pm_error "配置文件提交失败，原配置保持不变"
        return 1
    fi
    return 0
}

commit_generated_config() {
    local file=$1 success_message=$2 error_message=$3
    if safe_write_config_from_file "$file"; then
        echo -e "${GREEN}${success_message}${PLAIN}"
        return 0
    fi
    echo -e "${RED}${error_message}，原配置保持不变。${PLAIN}"
    return 1
}

# ==============================================================================
# 2.5 Telegram 通知引擎
# ==============================================================================

get_host_label() {
    local comment="$1"
    local group_id="$2"
    local host_part=""
    
    # 主标识: hostname → IP
    local h=$(hostname 2>/dev/null)
    if [ -n "$h" ] && [ "$h" != "localhost" ]; then
        host_part="$h"
    else
        host_part=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n 1)
    fi
    [ -z "$host_part" ] && host_part="Unknown"
    
    # 附加用户 + 组名（底层继续使用 comment 字段以兼容旧配置与 Worker）
    local raw="$host_part"
    local suffix=""
    if [ -n "$group_id" ] && [ "$group_id" != "null" ]; then
        suffix="${suffix} [组:$group_id]"
    fi
    if [ -n "$comment" ] && [ "$comment" != "null" ] && [ "$comment" != "" ]; then
        suffix="${suffix} ($comment)"
    fi
    raw="${raw}${suffix}"
    
    # 转义 Telegram Markdown V1 特殊字符: * _ ` [
    echo "$raw" | sed 's/[_*`\[]/\\&/g'
}

fmt_bytes_plain() {
    local b=$1
    [ -z "$b" ] || [ "$b" -eq 0 ] 2>/dev/null && echo "0B" && return
    echo "$b" | awk '{
        if ($1>=1073741824) printf "%.1fGB", $1/1073741824
        else if ($1>=1048576) printf "%.1fMB", $1/1048576
        else if ($1>=1024) printf "%.1fKB", $1/1024
        else printf "%dB", $1
    }'
}

_tg_send_now() {
    local msg="$1"
    [ -z "$msg" ] && return 2
    local tg_conf=$(jq -r '.telegram // empty' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$tg_conf" ] && return 2
    local enabled=$(echo "$tg_conf" | jq -r '.enable // false')
    [ "$enabled" != "true" ] && return 2
    local token=$(echo "$tg_conf" | jq -r '.bot_token // empty')
    local chat_id=$(echo "$tg_conf" | jq -r '.chat_id // empty')
    [ -z "$token" ] || [ -z "$chat_id" ] && return 2
    local api_url=$(echo "$tg_conf" | jq -r '.api_url // "https://api.telegram.org"')
    local send_failed=false chunks_sent=0
    if [ "${#msg}" -le 3900 ]; then
        curl -sf --max-time 10 "${api_url}/bot${token}/sendMessage" \
            -d chat_id="$chat_id" -d text="$msg" -d parse_mode="Markdown" >/dev/null 2>&1 || send_failed=true
    else
        while IFS= read -r -d '' chunk; do
            [ -z "$chunk" ] && continue
            chunks_sent=$((chunks_sent + 1))
            if ! curl -sf --max-time 10 "${api_url}/bot${token}/sendMessage" \
                -d chat_id="$chat_id" -d text="$chunk" -d parse_mode="Markdown" >/dev/null 2>&1; then
                send_failed=true
                break
            fi
        done < <(printf '%s' "$msg" | jq -Rrsj '
            def chunks($limit):
                reduce (split("\n")[]) as $line
                    ({parts: [], current: ""};
                     (if .current == "" then $line else .current + "\n" + $line end) as $candidate
                     | if ($candidate | length) <= $limit then
                           .current = $candidate
                       else
                           .parts += [.current]
                           | .current = $line
                       end)
                | .parts + (if .current == "" then [] else [.current] end)
                | map(. as $part
                      | [range(0; ($part | length); $limit) as $offset
                         | $part[$offset:($offset + $limit)]])
                | add;
            chunks(3900)[] + "\u0000"
        ' 2>/dev/null)
        [ "$chunks_sent" -eq 0 ] && send_failed=true
    fi
    [ "$send_failed" = "false" ]
}

tg_send() {
    local msg="$1"
    [ -z "$msg" ] && return
    (
        local send_rc=0
        _tg_send_now "$msg" || send_rc=$?
        if [ "$send_rc" -eq 1 ]; then
            pm_error "Telegram 通知发送失败，请检查 Bot Token、Chat ID 和网络"
        fi
    ) &
}

tg_send_checked() {
    local msg="$1" send_rc=0
    [ "$_TG_SYNC_FAILED" == "false" ] || return 1
    _tg_send_now "$msg" || send_rc=$?
    if [ "$send_rc" -eq 1 ]; then
        _TG_SYNC_FAILED=true
        pm_error "Telegram 通知发送失败，请检查 Bot Token、Chat ID 和网络；未送达通知将在下一轮重试"
    fi
    return "$send_rc"
}

# --- 通知模板 ---

tg_notify_quota() {
    local port=$1 comment=$2 percent=$3 used_fmt=$4 quota_gb=$5 mode=$6 threshold=$7 group_id=$8
    local label=$(get_host_label "$comment" "$group_id")
    local mode_str="双向"
    [ "$mode" == "out_only" ] && mode_str="仅出站"
    local icon="⚠️"
    [ "$threshold" -ge 100 ] && icon="🔴"
    
    local port_info="\`${port}\`"
    if [ -n "$group_id" ] && [ "$group_id" != "null" ]; then
        local safe_group_id=$(echo "$group_id" | sed 's/[_*`\[]/\\&/g')
        port_info="\`${port}\` (Group: $safe_group_id)"
    fi

    tg_send "${icon} *流量预警*
${TG_DIVIDER}
🖥 *${label}*
├ 🔌 端口  ${port_info}
├ 📦 流量  ${used_fmt} / ${quota_gb}GB
├ 📋 统计  ${mode_str}
└ 📈 使用  *${percent}%*
${TG_DIVIDER}
⚠️ 已超过 ${threshold}% 提醒阈值"
}

tg_notify_blocked() {
    local port=$1 comment=$2 quota_gb=$3 reset_day=$4 group_id=$5
    local label=$(get_host_label "$comment" "$group_id")
    local reset_str="手动重置"
    [ "$reset_day" -gt 0 ] 2>/dev/null && reset_str="每月 ${reset_day} 日自动重置"
    
    local title="端口已封禁"
    if [ -n "$group_id" ] && [ "$group_id" != "null" ]; then
        title="组流量耗尽 (Group Blocked)"
    fi

    tg_send "🚫 *${title}*
${TG_DIVIDER}
🖥 *${label}*
├ 🔌 端口  \`${port}\`
├ 📦 配额  ${quota_gb}GB
└ 🔄 重置  ${reset_str}
${TG_DIVIDER}
⛔ 流量配额已耗尽，服务连接已阻断"
}

tg_notify_punish() {
    local port=$1 comment=$2 avg_mbps=$3 group_id=$4
    local label=$(get_host_label "$comment" "$group_id")
    tg_send "⚡ *突发限速触发*
${TG_DIVIDER}
🖥 *${label}*
├ 🔌 端口  \`${port}\`
├ 📈 速率  ${avg_mbps} Mbps
├ 🎯 阈值  ${BURST_TRIGGER_MBPS} Mbps / ${BURST_TRIGGER_MINUTES} 分钟
├ 📉 限速  *${BURST_LIMIT_MBPS} Mbps*
└ ⏱ 时长  ${BURST_DURATION_MINUTES} 分钟
${TG_DIVIDER}
ℹ️ 保护期结束后将自动恢复不限速"
}

tg_notify_recover() {
    local port=$1 comment=$2 group_id=$3
    local label=$(get_host_label "$comment" "$group_id")
    tg_send "✅ *限速已恢复*
${TG_DIVIDER}
🖥 *${label}*
├ 🔌 端口  \`${port}\`
└ 📈 状态  已恢复不限速
${TG_DIVIDER}
ℹ️ 突发限速保护期已结束"
}

telegram_notifications_ready() {
    jq -e '
        .telegram.enable == true and
        ((.telegram.bot_token // "") | length > 0) and
        ((.telegram.chat_id // "") | length > 0)
    ' "$CONFIG_FILE" >/dev/null 2>&1
}

tg_notify_expiry() {
    local port=$1 user=$2 expiry_date=$3 days_remaining=$4 group_id=$5
    local label=$(get_host_label "$user" "$group_id")
    local remaining="剩余 *${days_remaining} 天*"
    [ "$days_remaining" -eq 0 ] && remaining="*今天到期*"
    tg_send_checked "⏰ *用户到期提醒*
${TG_DIVIDER}
🖥 *${label}*
├ 🔌 端口  \`${port}\`
├ 📅 到期  ${expiry_date}
└ ⏳ ${remaining}
${TG_DIVIDER}
ℹ️ 仅提醒，不会自动封禁或删除用户"
}

_notify_user_expiry_if_due() {
    local port=$1 user=$2 expiry_date=$3 expiry_day=$4 current_utc_day=$5 group_id=$6
    [ "$expiry_day" -ge 0 ] 2>/dev/null || return 0
    local days_remaining=$((expiry_day - current_utc_day))
    [ "$days_remaining" -ge 0 ] && [ "$days_remaining" -le 3 ] || return 0
    [ "$s_expiry_notified_date" != "$expiry_date" ] || return 0
    telegram_notifications_ready || return 0

    tg_notify_expiry "$port" "$user" "$expiry_date" "$days_remaining" "$group_id" || return 1
    s_expiry_notified_date=$expiry_date
    _save_port_state "$port"
}

push_to_worker() {
    local push_values enabled worker_url secret node_key
    push_values=$(jq -r '[.push.enable // false, .push.worker_url // "", .push.secret // "", .push.node_key // ""] | @tsv' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$push_values" ] && return
    IFS=$'\t' read -r enabled worker_url secret node_key <<< "$push_values"
    [ "$enabled" != "true" ] && return
    [ -z "$worker_url" ] || [ -z "$secret" ] || [ -z "$node_key" ] && return
    local payload
    payload=$(jq '{node_id, interface, ports}' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$payload" ] && return

    local push_ports_json push_ports scan_ts online_json runtime_json
    push_ports_json=$(jq -c '.ports | keys' <<< "$payload")
    push_ports=$(jq -r '.[]' <<< "$push_ports_json")
    scan_ts=$(date +%s)

    # 一次 jq 完成按端口去重、计数和 50 条上传上限，避免 Bash 大字符串反复拼接。
    online_json='{}'
    if [ -n "$push_ports" ]; then
        _ensure_unique_connection_snapshot || true
        if [ "$_CONNECTION_SNAPSHOT_TS" -gt 0 ] 2>/dev/null; then
            scan_ts=$_CONNECTION_SNAPSHOT_TS
        fi
        online_json=$(jq -Rn -c --argjson monitored_ports "$push_ports_json" --argjson scan_ts "$scan_ts" '
            ($monitored_ports | reduce .[] as $port ({}; .[$port] = true)) as $monitored |
            [inputs
             | split("\t")
             | select(length == 2 and $monitored[.[0]] == true)
             | {port: .[0], ip: .[1]}]
            | group_by(.port)
            | reduce .[] as $group ({};
                ($group | map(.ip)) as $ips
                | .[$group[0].port] = {
                    ip_count: ($ips | length),
                    ips: $ips[:50],
                    updated_at: $scan_ts,
                    truncated: (($ips | length) > 50)
                  })
        ' < "$_UNIQUE_CONNECTION_SNAPSHOT_FILE")
    fi
    [ -z "$online_json" ] && online_json='{}'

    # 运行状态先汇总成对象，再一次性合并到 payload，端口数增加时不再线性启动 jq。
    runtime_json=$(
        for _pp in $push_ports; do
            _load_port_state "$_pp"
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$_pp" "$s_acc_in" "$s_acc_out" "$s_last_k_in" "$s_last_k_out" \
                "$s_is_punished" "$s_high_seconds" "$s_punish_end_ts" "$s_quota_level"
        done | jq -Rn -c --argjson online "$online_json" --argjson scan_ts "$scan_ts" '
            def number_or_zero: tonumber? // 0;
            reduce inputs as $line ({};
                ($line | split("\t")) as $f
                | .[$f[0]] = {
                    acc_in: ($f[1] | number_or_zero),
                    acc_out: ($f[2] | number_or_zero),
                    last_kernel_in: ($f[3] | number_or_zero),
                    last_kernel_out: ($f[4] | number_or_zero),
                    is_punished: ($f[5] == "true"),
                    high_seconds: ($f[6] | number_or_zero),
                    punish_end_ts: ($f[7] | number_or_zero),
                    quota_level: ($f[8] | number_or_zero),
                    online: ($online[$f[0]] // {
                        ip_count: 0,
                        ips: [],
                        updated_at: $scan_ts,
                        truncated: false
                    })
                  })
        '
    )
    [ -z "$runtime_json" ] && return
    payload=$(jq -c --argjson runtime "$runtime_json" '
        reduce ($runtime | to_entries[]) as $entry (.;
            .ports[$entry.key].stats.acc_in = $entry.value.acc_in
            | .ports[$entry.key].stats.acc_out = $entry.value.acc_out
            | .ports[$entry.key].stats.last_kernel_in = $entry.value.last_kernel_in
            | .ports[$entry.key].stats.last_kernel_out = $entry.value.last_kernel_out
            | .ports[$entry.key].dyn_limit.is_punished = $entry.value.is_punished
            | .ports[$entry.key].dyn_limit.high_seconds = $entry.value.high_seconds
            | .ports[$entry.key].dyn_limit.punish_end_ts = $entry.value.punish_end_ts
            | .ports[$entry.key].notify_state.quota_level = $entry.value.quota_level
            | .ports[$entry.key].online = $entry.value.online)
    ' <<< "$payload")
    [ -z "$payload" ] && return
    local timestamp signature
    timestamp=$(date +%s)
    signature=$(printf '%s\n%s\n%s' "$node_key" "$timestamp" "$payload" | openssl dgst -sha256 -hmac "$secret" 2>/dev/null | awk '{print $NF}')
    if [ -z "$signature" ]; then
        pm_error "Worker 推送签名生成失败，请检查 openssl"
        return 1
    fi
    local http_code
    local response_file
    response_file=$(mktemp) || { pm_error "无法创建 Worker 响应临时文件"; return 1; }
    _CLEANUP_FILES+=("$response_file")
    if ! http_code=$(curl -sS --max-time 10 -o "$response_file" -w '%{http_code}' -X PUT "${worker_url}" \
        -H "Content-Type: application/json" -H "X-Node: ${node_key}" \
        -H "X-Timestamp: ${timestamp}" -H "X-Signature: ${signature}" -d "$payload" 2>>"$LOG_FILE"); then
        pm_error "Worker 推送请求失败，请检查 URL、DNS 和网络"
        return 1
    fi
    case "$http_code" in
        2??) return 0 ;;
        *)
            local response_hint=$(head -c 200 "$response_file" 2>/dev/null | tr '\r\n' ' ')
            pm_error "Worker 推送被拒绝（HTTP ${http_code}）${response_hint:+: ${response_hint}}"
            return 1
            ;;
    esac
}

# ==============================================================================
# 2.6 接入监控引擎 (IP Sentinel)
# ==============================================================================

tg_notify_ip_alert() {
    local port=$1 comment=$2 ip_count=$3 max_ips=$4 ip_details=$5 group_id=$6 alert_level=$7
    local label=$(get_host_label "$comment" "$group_id")
    local title="🚨 *异常接入警报*"
    local level_text="普通超限"
    if [ "$alert_level" -ge 2 ]; then
        title="🔴 *异常接入升级*"
        level_text="高风险（超过 $((max_ips + 2)) IP）"
    fi
    tg_send_checked "${title}
${TG_DIVIDER}
🖥 *${label}*
├ 🔌 端口  \`${port}\`
├ 👥 在线  *${ip_count} IP*
├ 🎯 阈值  ${max_ips} IP
└ 🚦 等级  ${level_text}
${TG_DIVIDER}
📋 *当前连接*
${ip_details}
${TG_DIVIDER}
⚠️ 建议检查密码或重启服务
🕒 $(date '+%Y-%m-%d %H:%M:%S')"
}

# 从 ss 输出中提取端口的独立对端 IP（去重、清洗 IPv4-mapped）
_sentinel_scan_ips() {
    local port=$1
    _ensure_unique_connection_snapshot || true
    awk -F '\t' -v port="$port" '$1 == port {print $2}' "$_UNIQUE_CONNECTION_SNAPSHOT_FILE" 2>/dev/null
}

_sentinel_alert_level() {
    local ip_count=$1 max_ips=$2 result_var=$3 _level=0
    if [ "$ip_count" -gt $((max_ips + 2)) ]; then
        _level=2
    elif [ "$ip_count" -gt "$max_ips" ]; then
        _level=1
    fi
    printf -v "$result_var" '%s' "$_level"
}

_sentinel_alert_due() {
    local alert_level=$1 previous_level=$2 current_ts=$3 last_alert_ts=$4 cooldown_min=$5
    [ "$alert_level" -gt "$previous_level" ] \
        || [ $((current_ts - last_alert_ts)) -ge $((cooldown_min * 60)) ]
}

# 阶段四入口: 遍历启用了 ip_limit 的端口执行检测
check_ip_sentinel() {
    local current_ts=$1
    local snapshot_changed=false
    local sentinel_failed=false
    # [PERF] 一次性读取所有启用了 ip_limit 的端口配置
    local _sentinel_cfg=$(jq -r '
        .ports | to_entries[] | select(.value.ip_limit.enable == true) |
        [.key, (.value.ip_limit.max_ips // 3), (.value.ip_limit.action // "alert"),
         (.value.ip_limit.cooldown_min // 30), (.value.comment // ""),
         (.value.group_id // ""), ((.value.ip_limit.whitelist // []) | join(","))]
        | map(tostring) | join("\u001f")' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$_sentinel_cfg" ] && return
    if ! _ensure_unique_connection_snapshot \
        || [ -z "$_UNIQUE_CONNECTION_SNAPSHOT_FILE" ] \
        || [ ! -f "$_UNIQUE_CONNECTION_SNAPSHOT_FILE" ] \
        || [ "$_CONNECTION_SNAPSHOT_TS" -le 0 ]; then
        pm_error "IP 接入监控无法读取当前 TCP 连接快照，本轮检测已跳过"
        return 1
    fi

    # 默认开启后仍只读取一次快照；按端口在 Bash 内分组，避免每个端口启动一次 awk。
    declare -A _sentinel_ips_by_port=()
    local _snapshot_port _snapshot_ip
    while IFS=$'\t' read -r _snapshot_port _snapshot_ip; do
        [ -n "$_snapshot_port" ] && [ -n "$_snapshot_ip" ] || continue
        _sentinel_ips_by_port["$_snapshot_port"]+="${_snapshot_ip}"$'\n'
    done < "$_UNIQUE_CONNECTION_SNAPSHOT_FILE"

    while IFS=$'\x1f' read -r port max_ips action cooldown_min comment gid whitelist_csv; do
        [ -z "$port" ] && continue

        # --- 扫描 ---
        local raw_ips="${_sentinel_ips_by_port[$port]:-}"

        # --- 过滤白名单 ---
        declare -A whitelist_set=()
        local -a whitelist_items=()
        IFS=',' read -ra whitelist_items <<< "$whitelist_csv"
        for w in "${whitelist_items[@]}"; do
            [ -n "$w" ] && whitelist_set["$w"]=1
        done
        local -a filtered_ips=()
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            [[ -z "${whitelist_set[$ip]+x}" ]] && filtered_ips+=("$ip")
        done <<< "$raw_ips"
        local ip_count=${#filtered_ips[@]}
        _load_port_state "$port"

        # 回到安全范围即结束本轮事件；下次再次超限会重新发送一级告警。
        if [ "$ip_count" -le "$max_ips" ]; then
            if [ "$s_ip_alert_level" -gt 0 ] || [ "$s_last_alert_ts" -gt 0 ] || [ -n "$s_last_alert_ips" ]; then
                s_ip_alert_level=0; s_last_alert_ts=0; s_last_alert_ips=""
                if ! _save_port_state "$port"; then
                    pm_error "端口 ${port} 的接入告警状态重置失败"
                    sentinel_failed=true
                fi
            fi
            continue
        fi

        # 默认 max_ips=3：4-5 个 IP 为一级，6 个及以上为二级。
        # 等级升级立即通知；同级持续超限遵循冷却时间，避免 IP 变动造成刷屏。
        local alert_level
        _sentinel_alert_level "$ip_count" "$max_ips" alert_level
        local alert_sent=false
        if _sentinel_alert_due "$alert_level" "$s_ip_alert_level" \
            "$current_ts" "$s_last_alert_ts" "$cooldown_min" \
            && telegram_notifications_ready; then
            # --- 归属地查询 (最多 15 个 IP 合并为一次 HTTP 请求) ---
            local details="" idx=1 detail_ips ips_json geo_response
            detail_ips=$(printf '%s\n' "${filtered_ips[@]:0:15}")
            ips_json=$(printf '%s\n' "$detail_ips" | jq -R -s -c 'split("\n") | map(select(length > 0))')
            geo_response=""
            if [ "$_SENTINEL_GEO_REQUESTS" -lt 15 ]; then
                _SENTINEL_GEO_REQUESTS=$((_SENTINEL_GEO_REQUESTS + 1))
                geo_response=$(curl -sf --max-time 3 \
                    -H 'Content-Type: application/json' \
                    -d "$ips_json" \
                    'http://ip-api.com/batch?fields=status,country,regionName,isp,query&lang=zh-CN' 2>/dev/null || true)
            fi
            declare -A geo_by_ip=()
            while IFS=$'\t' read -r geo_ip geo_label; do
                [ -n "$geo_ip" ] && geo_by_ip["$geo_ip"]="${geo_label:-(查询失败)}"
            done < <(printf '%s' "$geo_response" | jq -r '
                if type == "array" then .[] else empty end
                | [.query, (if .status == "success"
                    then ([.country, .regionName, .isp] | map(select(. != null and . != "")) | join(", "))
                    else "(查询失败)" end)]
                | @tsv' 2>/dev/null)

            while IFS= read -r ip; do
                [ -z "$ip" ] && continue
                local geo="${geo_by_ip[$ip]:-(查询失败)}"
                geo=$(echo "$geo" | sed 's/[_*`\[]/\\&/g')
                details+="${idx}. \`${ip}\` - ${geo}"$'\n'
                idx=$((idx + 1))
            done <<< "$detail_ips"
            [ "$ip_count" -gt 15 ] && details+="... 仅显示前 15 条"$'\n'

            if tg_notify_ip_alert "$port" "$comment" "$ip_count" "$max_ips" "$details" "$gid" "$alert_level"; then
                alert_sent=true
            else
                sentinel_failed=true
            fi
        fi

        # --- 自动阻断 (可选, 保留连接数最多的前 N 个 IP) ---
        if [ "$action" = "block" ]; then
            local ranked
            ranked=$(awk -F '\t' -v port="$port" '$1 == port {print $2}' "$_CONNECTION_SNAPSHOT_FILE" 2>/dev/null | sort | uniq -c | sort -rn)
            local kept=0
            while read -r cnt kip; do
                [ -z "$kip" ] && continue
                [[ -n "${whitelist_set[$kip]+x}" ]] && continue
                kept=$((kept + 1))
                if [ "$kept" -gt "$max_ips" ]; then
                    if ss -K dst "$kip" sport = ":$port" >/dev/null 2>&1; then
                        snapshot_changed=true
                    else
                        pm_error "端口 ${port} 无法自动断开 IP ${kip}，请检查内核是否支持 ss -K"
                        sentinel_failed=true
                    fi
                fi
            done <<< "$ranked"
        fi

        # 只有 Telegram 确认送达后才开始通知冷却；失败或尚未配置时保留补发机会。
        if [ "$alert_sent" = "true" ]; then
            s_last_alert_ts=$current_ts
            s_ip_alert_level=$alert_level
            printf -v s_last_alert_ips '%s,' "${filtered_ips[@]}"
            s_last_alert_ips=${s_last_alert_ips%,}
            _save_port_state "$port" || sentinel_failed=true
        fi
    done <<< "$_sentinel_cfg"

    # 阻断动作改变了连接表；让后续云推送重新采样，避免上报已被踢出的 IP。
    if [ "$snapshot_changed" = "true" ]; then
        _CONNECTION_SNAPSHOT_FILE=""
        _UNIQUE_CONNECTION_SNAPSHOT_FILE=""
        _CONNECTION_SNAPSHOT_TS=0
    fi
    [ "$sentinel_failed" == "false" ]
}

_reset_ip_alert_state() {
    local port=$1
    _load_port_state "$port"
    s_last_alert_ts=0; s_last_alert_ips=""; s_ip_alert_level=0
    _save_port_state "$port"
}

configure_ip_sentinel() {
    local port=$1
    while true; do
        local conf=$(jq ".ports[\"$port\"].ip_limit // {}" "$CONFIG_FILE")
        local ip_en=$(echo "$conf" | jq -r '.enable // false')
        local ip_max=$(echo "$conf" | jq -r '.max_ips // 3')
        local ip_act=$(echo "$conf" | jq -r '.action // "alert"')
        local ip_cd=$(echo "$conf" | jq -r '.cooldown_min // 30')
        local ip_wl=$(echo "$conf" | jq -r '.whitelist // [] | join(", ")')
        [ -z "$ip_wl" ] && ip_wl="(空)"

        local act_str="仅报警"
        [ "$ip_act" = "block" ] && act_str="${RED}自动阻断${PLAIN}"

        clear
        echo -e "$UI_DIVIDER"
        echo -e " 接入监控 (IP Sentinel) - 端口 $port"
        echo -e "$UI_DIVIDER"
        echo -e " 状态:     $([ "$ip_en" = "true" ] && echo "${GREEN}已启用${PLAIN}" || echo "${YELLOW}未启用${PLAIN}")"
        echo -e " 允许 IP:  $ip_max"
        echo -e " 升级告警: 超过 $((ip_max + 2)) IP"
        echo -e " 处理策略: $act_str"
        echo -e " 冷却时间: ${ip_cd} 分钟"
        echo -e " 白名单:   $ip_wl"
        echo -e "$UI_SEPARATOR"
        echo -e " 1. 启用/禁用"
        echo -e " 2. 设置 允许 IP 数"
        echo -e " 3. 设置 处理策略"
        echo -e " 4. 设置 冷却时间"
        echo -e " 5. 管理 白名单"
        echo -e " 0. 返回"
        echo -e "$UI_DIVIDER"
        read -r -p "请选择: " sc; sc=$(strip_cr "$sc")
        local tmp=$(mktemp)

        case $sc in
            1)  local nv="true"; [ "$ip_en" = "true" ] && nv="false"
                if jq --argjson v "$nv" --arg p "$port" '.ports[$p].ip_limit.enable = $v' \
                    "$CONFIG_FILE" > "$tmp" && commit_generated_config "$tmp" \
                    "已$([ "$nv" = "true" ] && echo "启用" || echo "禁用")。" "接入监控状态写入失败"; then
                    _reset_ip_alert_state "$port" || pm_error "端口 ${port} 的接入告警状态重置失败"
                    sleep 0.5
                else sleep 1; fi ;;
            2)  read -r -p "最大允许独立 IP 数（1-65535）: " val; val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -ge 1 ] && [ "$val" -le 65535 ]; then
                    if jq --argjson v "$val" --arg p "$port" '.ports[$p].ip_limit.max_ips = $v' \
                        "$CONFIG_FILE" > "$tmp" && commit_generated_config "$tmp" "已更新。" "最大 IP 数写入失败"; then
                        _reset_ip_alert_state "$port" || pm_error "端口 ${port} 的接入告警状态重置失败"
                        sleep 0.5
                    else sleep 1; fi
                else echo -e "${RED}无效输入，请输入 1-65535。${PLAIN}"; sleep 1; fi ;;
            3)  echo -e " 1. 仅报警"
                echo -e " 2. 自动断开多余 IP"
                echo -e " 0. 取消"
                read -r -p "请选择 [0-2，默认 0]: " am; am=$(strip_cr "$am")
                local nact
                case "$am" in
                    1) nact="alert" ;;
                    2) nact="block" ;;
                    ""|0) rm -f "$tmp"; continue ;;
                    *) echo -e "${RED}无效选项。${PLAIN}"; rm -f "$tmp"; sleep 1; continue ;;
                esac
                if jq --arg v "$nact" --arg p "$port" '.ports[$p].ip_limit.action = $v' \
                    "$CONFIG_FILE" > "$tmp" && commit_generated_config "$tmp" "已更新。" "接入监控策略写入失败"; then
                    _reset_ip_alert_state "$port" || pm_error "端口 ${port} 的接入告警状态重置失败"
                    if [ "$nact" = "block" ]; then
                        echo -e "${YELLOW}注意: 自动阻断会切断多余 IP 的连接，存在误杀风险。${PLAIN}"
                        echo -e "${YELLOW}建议先以「仅报警」模式运行一段时间再决定。${PLAIN}"
                    fi
                fi
                sleep 1 ;;
            4)  read -r -p "冷却时间（分钟，同级持续超限的提醒间隔）: " val; val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -ge 1 ] && [ "$val" -le 525600 ]; then
                    if jq --argjson v "$val" --arg p "$port" '.ports[$p].ip_limit.cooldown_min = $v' \
                        "$CONFIG_FILE" > "$tmp" && commit_generated_config "$tmp" "已更新。" "冷却时间写入失败"; then
                        sleep 0.5
                    else sleep 1; fi
                else echo -e "${RED}无效输入，请输入 1-525600 分钟。${PLAIN}"; sleep 1; fi ;;
            5)  echo -e "\n当前白名单: $ip_wl"
                echo -e " 1. 添加 IP  2. 清空白名单  0. 返回"
                read -r -p "请选择 [0-2，默认 0]: " wc; wc=$(strip_cr "$wc")
                if [ "$wc" = "1" ]; then
                    read -r -p "输入 IP 地址（支持 IPv4/IPv6，留空取消）: " wip; wip=$(strip_cr "$wip")
                    if [ -n "$wip" ]; then
                        if jq --arg ip "$wip" --arg p "$port" '.ports[$p].ip_limit.whitelist += [$ip] | .ports[$p].ip_limit.whitelist |= unique' \
                            "$CONFIG_FILE" > "$tmp" && commit_generated_config "$tmp" "已添加。" "白名单写入失败"; then
                            _reset_ip_alert_state "$port" || pm_error "端口 ${port} 的接入告警状态重置失败"
                            sleep 0.5
                        else sleep 1; fi
                    fi
                elif [ "$wc" = "2" ]; then
                    if jq --arg p "$port" '.ports[$p].ip_limit.whitelist = []' \
                        "$CONFIG_FILE" > "$tmp" && commit_generated_config "$tmp" "已清空。" "白名单清空失败"; then
                        _reset_ip_alert_state "$port" || pm_error "端口 ${port} 的接入告警状态重置失败"
                        sleep 0.5
                    else sleep 1; fi
                fi ;;
            0)  rm -f "$tmp"; break ;;
        esac
        rm -f "$tmp"
    done
}

_update_burst_state() {
    local current_mbps=$1 sample_seconds=$2 current_ts=$3 sample_contiguous=$4

    if [ "$s_is_punished" == "true" ]; then
        if (( current_ts >= s_punish_end_ts )); then
            s_is_punished=false; s_high_seconds=0; s_punish_end_ts=0
            s_rules_dirty=true
            s_pending_qos_notice="recover"
        fi
        return 0
    fi

    if [ "$sample_contiguous" == "true" ] \
        && [ "$(echo "$current_mbps > $BURST_TRIGGER_MBPS" | bc)" -eq 1 ]; then
        s_high_seconds=$((s_high_seconds + sample_seconds))
        if (( s_high_seconds >= BURST_TRIGGER_MINUTES * 60 )); then
            s_is_punished=true
            s_high_seconds=0
            s_punish_end_ts=$((current_ts + BURST_DURATION_MINUTES * 60))
            s_rules_dirty=true
            s_pending_qos_notice="punish"
        fi
    else
        s_high_seconds=0
    fi
}

cron_task() {
    exec 9>"$CRON_LOCK_FILE"
    flock -n 9 || exit 0
    rotate_pm_log

    # 能拿到同一把 flock 说明没有菜单进程持锁，残留信号文件可直接清理。
    [ -f "$USER_EDIT_LOCK" ] && rm -f "$USER_EDIT_LOCK"

    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

    if ! nft_table_healthy; then
        reload_all_rules || { pm_error "后台任务无法重建 Nftables/TC 规则"; return 1; }
    fi

    local tmp_json=$(cat "$CONFIG_FILE")
    local ports=$(echo "$tmp_json" | jq -r '.ports | keys[]')
    local current_ts=$(date +%s)
    local cron_failed=false

    # --- 阶段一：采集数据 + 固定突发限速 (Port Level) ---
    # [PERF] 一次性读取全部 nft 计数器 (零循环内 nft 调用)
    declare -A _ctr_cache
    while IFS=$'\t' read -r _cn _cb; do
        [ -n "$_cn" ] && _ctr_cache["$_cn"]=$_cb
    done <<< "$(nft -j list counters table $NFT_TABLE 2>/dev/null | jq -r '
        [.nftables[] | select(.counter) | .counter] | .[] | "\(.name)\t\(.bytes)"')"

    # [PERF] 一次性读取已接入突发保护的端口，不在循环内重复启动 jq。
    local _burst_cfg_data=$(echo "$tmp_json" | jq -r '
        .ports | to_entries[] | select(.value.dyn_limit.enable == true) |
        [.key, (.value.comment // ""), (.value.group_id // "")]
        | map(tostring) | join("\u001f")')

    declare -A _burst_enabled _burst_comment _burst_gid
    while IFS=$'\x1f' read -r _bp _bc _bg; do
        [ -z "$_bp" ] && continue
        _burst_enabled["$_bp"]=true
        _burst_comment["$_bp"]=$_bc; _burst_gid["$_bp"]=$_bg
    done <<< "$_burst_cfg_data"

    for port in $ports; do
        _load_port_state "$port"

        local sample_seconds=60
        local sample_contiguous=true
        if [ "$s_last_sample_ts" -gt 0 ] 2>/dev/null && [ "$current_ts" -gt "$s_last_sample_ts" ]; then
            sample_seconds=$((current_ts - s_last_sample_ts))
        fi
        # 菜单编辑、停机或 Cron 延迟造成采样断档时，无法证明每一分钟都持续超标。
        # 超过容差的区间只用于流量累计，不计入连续高速时间，避免恢复后误触发。
        [ "$sample_seconds" -gt "$BURST_MAX_SAMPLE_SECONDS" ] && sample_contiguous=false
        s_last_sample_ts=$current_ts

        local curr_k_in=${_ctr_cache["cnt_in_${port}"]:-0}
        local curr_k_out=${_ctr_cache["cnt_out_${port}"]:-0}

        local delta_in=0
        if (( curr_k_in < s_last_k_in )); then delta_in=$curr_k_in; else delta_in=$((curr_k_in - s_last_k_in)); fi
        local delta_out=0
        if (( curr_k_out < s_last_k_out )); then delta_out=$curr_k_out; else delta_out=$((curr_k_out - s_last_k_out)); fi

        s_acc_in=$((s_acc_in + delta_in))
        s_acc_out=$((s_acc_out + delta_out))
        s_last_k_in=$curr_k_in
        s_last_k_out=$curr_k_out

        local current_mbps=0
        # 固定策略只观察出站平均速率：>300 Mbps 累计 20 分钟，限速 50 Mbps 5 分钟。
        if [ -n "${_burst_enabled[$port]+x}" ]; then
            current_mbps=$(echo "scale=2; $delta_out * 8 / $sample_seconds / 1000000" | bc)
            _update_burst_state "$current_mbps" "$sample_seconds" "$current_ts" "$sample_contiguous"
        fi

        # 规则提交失败时保留 dirty 标记，下一轮继续恢复不限速或临时限速。
        if [ "$s_rules_dirty" == "true" ]; then
            _save_port_state "$port" || cron_failed=true
            if apply_port_rules "$port"; then
                case "$s_pending_qos_notice" in
                    punish)
                        if [ "$s_punish_notified" != "true" ]; then
                            tg_notify_punish "$port" "${_burst_comment[$port]}" "$current_mbps" "${_burst_gid[$port]}"
                        fi
                        s_punish_notified=true; s_recover_notified=false
                        ;;
                    recover)
                        if [ "$s_recover_notified" != "true" ]; then
                            tg_notify_recover "$port" "${_burst_comment[$port]}" "${_burst_gid[$port]}"
                        fi
                        s_recover_notified=true; s_punish_notified=false
                        ;;
                esac
                s_rules_dirty=false
                s_pending_qos_notice=""
            else
                pm_error "端口 ${port} 的限速规则应用失败，将在下一轮重试"
                cron_failed=true
            fi
        fi

        _save_port_state "$port" || cron_failed=true
    done

    # --- 阶段二：计算组流量 (Aggregation) ---
    # [PERF] 一次性读取 group_id + quota_mode (静态配置)
    declare -A group_usage
    local _grp_cfg=$(echo "$tmp_json" | jq -r '
        .ports | to_entries[] |
        select(.value.group_id != null and .value.group_id != "" and .value.group_id != "null") |
        "\(.key)\t\(.value.group_id)\t\(.value.quota_mode)"')

    while IFS=$'\t' read -r _gp _gid _gmode; do
        [ -z "$_gp" ] && continue
        _load_port_state "$_gp"
        local _gu=0
        if [ "$_gmode" == "out_only" ]; then _gu=$s_acc_out; else _gu=$((s_acc_in + s_acc_out)); fi
        group_usage["$_gid"]=$(( ${group_usage["$_gid"]:-0} + _gu ))
    done <<< "$_grp_cfg"

    # --- 阶段三：执行策略 (Quota Check / Reset) ---
    # [PERF] 循环外缓存
    local blocked_ports_str=" $(nft -j list set $NFT_TABLE blocked_ports 2>/dev/null | jq -r '[ .nftables[] | select(.set) | .set.elem[]? ] | map(tostring) | join(" ")') "
    local thresholds
    thresholds=$(jq -r '((.telegram.thresholds // [50,80,100]) + [100]) | unique | .[]' <<< "$tmp_json" | sort -rn)
    local current_year_month="" days_in_month=""
    local current_utc_day=$((current_ts / 86400))
    declare -A reset_ts_cache
    # [PERF] 一次性读取所有端口的静态配置
    local _p3_cfg=$(echo "$tmp_json" | jq -r '
        .ports | to_entries[] |
        (.value.expiry_date // "") as $expiry |
        [.key, .value.quota_gb, .value.quota_mode, (.value.group_id // ""),
         (.value.reset_day // 0), (.value.comment // ""), $expiry,
         (if $expiry == "" then -1
          else try (((($expiry + "T00:00:00Z") | fromdateiso8601) / 86400) | floor) catch -1
          end)]
        | map(tostring) | join("\u001f")')

    while IFS=$'\x1f' read -r port quota_gb mode gid reset_day p3_comment expiry_date expiry_day; do
        [ -z "$port" ] && continue
        _load_port_state "$port"

        # 用户到期提醒由本机 Telegram 发送；3 天窗口内每个端口/日期只提醒一次。
        _notify_user_expiry_if_due "$port" "$p3_comment" "$expiry_date" "$expiry_day" \
            "$current_utc_day" "$gid" || cron_failed=true

        # 确定用于判断的流量值
        local check_usage=0
        if [ -n "$gid" ] && [ "$gid" != "null" ]; then
            check_usage=${group_usage["$gid"]:-0}
        else
            if [ "$mode" == "out_only" ]; then check_usage=$s_acc_out; else check_usage=$((s_acc_in + s_acc_out)); fi
        fi

        # 自动重置判断
        if [ "$reset_day" -gt 0 ] 2>/dev/null && [ "$reset_day" -le 31 ] 2>/dev/null; then
            if [ -z "$current_year_month" ]; then
                current_year_month=$(date +%Y-%m)
                days_in_month=$(date -d "${current_year_month}-01 +1 month -1 day" +%-d 2>/dev/null)
                [ -z "$days_in_month" ] && days_in_month=28
            fi
            local effective_day=$reset_day
            [ "$effective_day" -gt "$days_in_month" ] && effective_day=$days_in_month
            local reset_ts=${reset_ts_cache[$effective_day]:-}
            if [ -z "$reset_ts" ]; then
                local reset_date
                reset_date=$(printf "%s-%02d 00:00:00" "$current_year_month" "$effective_day")
                reset_ts=$(date -d "$reset_date" +%s 2>/dev/null || echo 0)
                reset_ts_cache["$effective_day"]=$reset_ts
            fi

            if [ "$current_ts" -ge "$reset_ts" ] && [ "$s_last_reset_ts" -lt "$reset_ts" ]; then
                # 重置: 清零流量, 记录当前内核计数器作为新基准
                s_acc_in=0; s_acc_out=0
                s_last_k_in=${_ctr_cache["cnt_in_${port}"]:-0}
                s_last_k_out=${_ctr_cache["cnt_out_${port}"]:-0}
                # 配额周期与突发保护相互独立；月度清零不提前结束 5 分钟保护期。
                s_quota_level=0
                _save_port_state "$port" || cron_failed=true

                local reset_rules_ok=true
                if [[ "$blocked_ports_str" == *" $port "* ]] \
                    && ! nft delete element $NFT_TABLE blocked_ports \{ $port \} 2>/dev/null; then
                    pm_error "自动重置时无法解除端口 ${port} 的封禁"
                    cron_failed=true
                    reset_rules_ok=false
                fi
                if apply_port_rules "$port"; then
                    s_rules_dirty=false
                else
                    cron_failed=true
                    reset_rules_ok=false
                fi
                if [ "$reset_rules_ok" == "true" ]; then
                    s_last_reset_ts=$current_ts
                    _save_port_state "$port" || cron_failed=true
                else
                    pm_error "端口 ${port} 流量已清零，但规则恢复未完成，将在下一轮重试"
                fi

                check_usage=0
                blocked_ports_str=" $(nft -j list set $NFT_TABLE blocked_ports 2>/dev/null | jq -r '[ .nftables[] | select(.set) | .set.elem[]? ] | map(tostring) | join(" ")') "
            fi
        fi

        # 配额封禁检查
        local quota_bytes=$((quota_gb * 1073741824))
        local is_blocked_nft=false
        [[ "$blocked_ports_str" == *" $port "* ]] && is_blocked_nft=true

        if (( check_usage > quota_bytes )); then
            if [ "$is_blocked_nft" == "false" ]; then
                if nft add element $NFT_TABLE blocked_ports \{ $port \}; then
                    blocked_ports_str="${blocked_ports_str}${port} "
                    is_blocked_nft=true
                else
                    pm_error "端口 ${port} 已超额，但封禁规则添加失败"
                    cron_failed=true
                fi
            fi
        else
            if [ "$is_blocked_nft" == "true" ]; then
                if nft delete element $NFT_TABLE blocked_ports \{ $port \}; then
                    blocked_ports_str="${blocked_ports_str/ $port / }"
                    is_blocked_nft=false
                else
                    pm_error "端口 ${port} 未超额，但封禁规则解除失败"
                    cron_failed=true
                fi
            fi
        fi

        # 阈值通知
        if [ "$quota_bytes" != "0" ] && [ -n "$quota_bytes" ]; then
            local percent=$(echo "scale=1; $check_usage * 100 / $quota_bytes" | bc 2>/dev/null)
            [ -z "$percent" ] && percent=0
            local percent_int=${percent%.*}
            [ -z "$percent_int" ] && percent_int=0

            local new_level=$s_quota_level
            for thr in $thresholds; do
                [ -z "$thr" ] && continue
                if (( percent_int >= thr )) && (( s_quota_level < thr )); then
                    new_level=$thr; break
                fi
            done

            if (( new_level > s_quota_level )); then
                # 只有封禁规则真正存在后，才发送“已封禁”并记录 100% 状态。
                if (( new_level >= 100 )) && [ "$is_blocked_nft" != "true" ]; then
                    continue
                fi
                local used_fmt=$(fmt_bytes_plain "$check_usage")
                tg_notify_quota "$port" "$p3_comment" "$percent" "$used_fmt" "$quota_gb" "$mode" "$new_level" "$gid"
                if (( new_level >= 100 )); then
                    tg_notify_blocked "$port" "$p3_comment" "$quota_gb" "$reset_day" "$gid"
                fi
                s_quota_level=$new_level
                _save_port_state "$port" || cron_failed=true
            fi
        fi
    done <<< "$_p3_cfg"

    # --- 阶段四: 接入 IP 监控 (Sentinel) ---
    check_ip_sentinel "$current_ts" || cron_failed=true

    push_to_worker || cron_failed=true
    [ "$cron_failed" == "false" ]
}

setup_cron() {
    local old_line="* * * * * $INSTALL_PATH --monitor"
    local cron_line="${old_line} >> $LOG_FILE 2>&1"
    crontab -l 2>/dev/null | grep -Fqx -- "$cron_line" && return 0

    local tmp_cron
    tmp_cron=$(mktemp) || { pm_error "无法创建 Cron 临时文件"; return 1; }
    _CLEANUP_FILES+=("$tmp_cron")
    crontab -l 2>/dev/null | awk -v old="$old_line" -v current="$cron_line" \
        '$0 != old && $0 != current' > "$tmp_cron"
    echo "$cron_line" >> "$tmp_cron"
    if ! crontab "$tmp_cron"; then
        pm_error "Cron 任务安装失败，请检查 crontab 服务"
        return 1
    fi
    echo -e "${GREEN}后台错误日志: $LOG_FILE${PLAIN}"
}

# ==============================================================================
# 4. UI 模块 (Reader)
# ==============================================================================

start_edit_lock() {
    [ "$_MENU_LOCK_HELD" == "true" ] && return 0
    exec 8>"$CRON_LOCK_FILE" || { pm_error "无法打开后台任务锁"; return 1; }
    flock -x 8 || { pm_error "无法等待后台任务结束"; exec 8>&-; return 1; }
    if ! touch "$USER_EDIT_LOCK"; then
        pm_error "无法创建菜单编辑锁"
        flock -u 8 2>/dev/null || true
        exec 8>&-
        return 1
    fi
    _MENU_LOCK_HELD=true
}
stop_edit_lock() {
    rm -f "$USER_EDIT_LOCK"
    if [ "$_MENU_LOCK_HELD" == "true" ]; then
        flock -u 8 2>/dev/null || true
        exec 8>&-
        _MENU_LOCK_HELD=false
    fi
}

scan_active_services() {
    echo -e "${YELLOW}正在扫描系统活跃服务...${PLAIN}" >&2
    local scan_res=$(ss -lntupH | awk '{
        proto=$1; n=split($5,a,":"); port=a[n]; proc="Unknown"
        idx=index($0,"users:((\"");
        if(idx>0){subline=substr($0,idx+9);q_idx=index(subline,"\"");if(q_idx>0)proc=substr(subline,1,q_idx-1)}
        k=port" "proc
        if(s[k]==""){p[k]=proto;pt[k]=port;pc[k]=proc;s[k]=1}else{if(index(p[k],proto)==0)p[k]=p[k]"/"proto}
    }END{for(k in p)print pt[k],p[k],pc[k]}' | sort -n -k1)
    echo "$scan_res"
}

fmt_bytes() {
    local bytes=$1
    if [[ ! "$bytes" =~ ^[0-9]+$ ]] || [ "$bytes" -eq 0 ]; then echo "0B"; return; fi
    numfmt --to=iec --suffix=B "$bytes"
}

telegram_status_text() {
    local values enabled token chat_id
    values=$(jq -r '[.telegram.enable // false, .telegram.bot_token // "", .telegram.chat_id // ""]
        | map(tostring) | join("\u001f")' "$CONFIG_FILE" 2>/dev/null)
    IFS=$'\x1f' read -r enabled token chat_id <<< "$values"
    if [ "$enabled" != "true" ]; then
        echo -e "${YELLOW}⚪ 已关闭${PLAIN}"
    elif [ -z "$token" ] || [ -z "$chat_id" ]; then
        echo -e "${YELLOW}⚠️ 配置不完整${PLAIN}"
    else
        echo -e "${GREEN}✅ 已开启${PLAIN}"
    fi
}

push_status_text() {
    local values enabled worker_url secret node_key
    values=$(jq -r '[.push.enable // false, .push.worker_url // "", .push.secret // "", .push.node_key // ""]
        | map(tostring) | join("\u001f")' "$CONFIG_FILE" 2>/dev/null)
    IFS=$'\x1f' read -r enabled worker_url secret node_key <<< "$values"
    if [ "$enabled" != "true" ]; then
        echo -e "${YELLOW}⚪ 已关闭${PLAIN}"
    elif [ -z "$worker_url" ] || [ -z "$secret" ] || [ -z "$node_key" ]; then
        echo -e "${YELLOW}⚠️ 配置不完整${PLAIN}"
    else
        echo -e "${GREEN}✅ 已开启${PLAIN}"
    fi
}

show_main_menu() {
    start_edit_lock || exit 1

    clear
    echo -e "$UI_DIVIDER"
    echo -e "  Linux 端口流量管理 v${SCRIPT_VERSION}"
    echo -e "  每分钟刷新 · 编辑期间后台任务暂停"
    echo -e "$UI_DIVIDER"

    local port_list=()
    local i=1
    local ports=$(jq -r '.ports | keys[]' "$CONFIG_FILE" | sort -n)
    local -A menu_group_usage=()

    # 与配额执行逻辑保持一致：分组端口显示组内合计用量。
    local group_port group_conf group_mode group_gid group_used
    for group_port in $ports; do
        group_conf=$(jq ".ports[\"$group_port\"]" "$CONFIG_FILE")
        group_gid=$(echo "$group_conf" | jq -r '.group_id // empty')
        [ -z "$group_gid" ] && continue
        group_mode=$(echo "$group_conf" | jq -r '.quota_mode // "in_out"')
        _load_port_state "$group_port"
        if [ "$group_mode" == "out_only" ]; then
            group_used=$s_acc_out
        else
            group_used=$((s_acc_in + s_acc_out))
        fi
        menu_group_usage["$group_gid"]=$(( ${menu_group_usage["$group_gid"]:-0} + group_used ))
    done

    for port in $ports; do
        local conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
        local mode=$(echo "$conf" | jq -r '.quota_mode')
        local burst_enabled=$(echo "$conf" | jq -r '.dyn_limit.enable // false')
        local comment=$(echo "$conf" | jq -r '.comment // ""')
        local quota=$(echo "$conf" | jq -r '.quota_gb')
        local gid=$(echo "$conf" | jq -r '.group_id // empty')
        
        # 从 state 文件读取运行数据
        _load_port_state "$port"
        
        local mode_str="双向"
        local total_used=0
        if [ "$mode" == "out_only" ]; then
            mode_str="仅出站"
            total_used=$s_acc_out
        else
            total_used=$((s_acc_in + s_acc_out))
        fi
        if [ -n "$gid" ] && [ "$gid" != "null" ]; then
            total_used=${menu_group_usage["$gid"]:-0}
        fi
        
        local status_clean=""
        
        if nft -j list set $NFT_TABLE blocked_ports 2>/dev/null | jq -r --argjson p "$port" '[ .nftables[] | select(.set) | .set.elem[]? ] | any(. == $p)' | grep -q "true"; then
            status_clean="[已阻断]"
        else
            status_clean="$(fmt_bytes $total_used)"
        fi
        
        local reset_day=$(echo "$conf" | jq -r '.reset_day // 0')
        local quota_str="${status_clean} / ${quota} GB"
        local reset_str=""
        if [ "$reset_day" -gt 0 ] 2>/dev/null; then reset_str=" · ${reset_day} 日重置"; fi
        
        local limit_str=""
        if [ "$burst_enabled" == "true" ] && [ "$s_is_punished" == "true" ]; then
            limit_str="${RED}${BURST_LIMIT_MBPS} Mbps（生效中）${PLAIN}"
        elif [ "$burst_enabled" == "true" ]; then
            limit_str="${GREEN}已接入${PLAIN}"
        else
            limit_str="未接入"
        fi

        local group_str=""
        if [ -n "$gid" ] && [ "$gid" != "null" ]; then
            group_str=" · 分组 ${gid}"
        fi
        [ -z "$comment" ] && comment="未设置"

        [ "$i" -gt 1 ] && echo
        printf " [%d] %s · %s%s · 用户 %s\n" \
            "$i" "$port" "$mode_str" "$group_str" "$comment"
        printf "     流量 %s%s · 突发 %b\n" \
            "$quota_str" "$reset_str" "$limit_str"
        
        port_list[$i]=$port
        i=$((i + 1))
    done
    if [ "$i" -eq 1 ]; then
        echo -e " 暂无监控端口"
    fi
    echo -e "$UI_SEPARATOR"
    echo -e " 提示：分组端口显示组内合计流量。\n"

    local tg_status=$(telegram_status_text)
    local push_status=$(push_status_text)

    echo -e " 1. 添加 监控端口 (服务扫描)"
    echo -e " 2. 配置 端口 (修改/分组/保护/重置)"
    echo -e " 3. 删除 监控端口"
    echo -e " 4. 通知与推送 [TG: $tg_status] [CF: $push_status]"
    echo -e " 5. 更新 脚本"
    echo -e " 6. ${RED}卸载 脚本${PLAIN}"
    echo -e " 0. 退出"
    echo -e "$UI_DIVIDER"
    read -r -p "请选择: " choice
    choice=$(strip_cr "$choice")
    
    case $choice in
        1) add_port_flow ;;
        2) config_port_menu "${port_list[@]}" ;;
        3) delete_port_flow "${port_list[@]}" ;;
        4) configure_notifications ;;
        5) update_script ;;
        6) uninstall_script ;;
        0) stop_edit_lock; exit 0 ;;
        *) ;; 
    esac
}

add_port_flow() {
    local scan_data=$(scan_active_services)
    echo -e "\n$UI_DIVIDER"
    echo -e "  系统当前活跃端口 · TCP/UDP"
    echo -e "$UI_DIVIDER"
    local map_ports=()
    local idx=1
    while read -r line; do
        [ -z "$line" ] && continue
        local p_port=$(echo "$line" | awk '{print $1}')
        local p_proto=$(echo "$line" | awk '{print $2}')
        local p_proc=$(echo "$line" | awk '{$1=""; $2=""; print $0}' | sed 's/^ *//')
        local is_monitored=false
        if jq -e ".ports[\"$p_port\"]" "$CONFIG_FILE" >/dev/null; then is_monitored=true; fi
        if [ "$is_monitored" = true ]; then
            printf " [%d] %s · %s · %b\n" \
                "$idx" "${p_port}/${p_proto}" "$p_proc" "${YELLOW}已监控${PLAIN}"
        else
            printf " [%d] %s · %s · 可选\n" "$idx" "${p_port}/${p_proto}" "$p_proc"
        fi
        map_ports[$idx]=$p_port
        idx=$((idx + 1))
    done <<< "$scan_data"
    if [ "$idx" -eq 1 ]; then
        echo -e " 未发现活跃端口，可选择手动输入。"
    fi
    echo -e "$UI_SEPARATOR"
    echo -e " [M] 手动输入端口号"
    echo -e " [0] 返回主菜单"
    echo -e "$UI_DIVIDER"
    read -r -p "请选择: " sel
    sel=$(strip_cr "$sel")
    local target_port=""
    if [ "$sel" == "0" ]; then return; fi
    if [[ "$sel" =~ ^[0-9]+$ ]] && [ -n "${map_ports[$sel]}" ]; then
        target_port=${map_ports[$sel]}
        if jq -e ".ports[\"$target_port\"]" "$CONFIG_FILE" >/dev/null; then
            echo -e "${RED}该端口已在监控列表中!${PLAIN}"; sleep 2; return
        fi
    elif [ "$sel" == "m" ] || [ "$sel" == "M" ]; then
        read -r -p "请输入端口号: " target_port
        target_port=$(strip_cr "$target_port")
    else
        return
    fi
    if [[ ! "$target_port" =~ ^[0-9]+$ ]] || [ "$target_port" -lt 1 ] || [ "$target_port" -gt 65535 ]; then
        echo -e "${RED}无效端口${PLAIN}"; sleep 1; return
    fi
    echo -e "\n>> 正在配置端口: $target_port"
    
    read -r -p "月流量配额（GB，正整数）: " quota
    quota=$(strip_cr "$quota")
    if [[ ! "$quota" =~ ^[0-9]+$ ]] || [ "$quota" -eq 0 ] || [ "$quota" -gt "$MAX_QUOTA_GB" ]; then
        echo -e "${RED}错误: 配额必须是 1-${MAX_QUOTA_GB} 的整数!${PLAIN}"; sleep 2; return
    fi

    echo "计费模式：1. 双向计费  2. 仅出站计费"
    read -r -p "选择模式 [1/2，默认 1]: " mode_idx
    mode_idx=$(strip_cr "$mode_idx")
    local mode
    case "$mode_idx" in
        ""|1) mode="in_out" ;;
        2) mode="out_only" ;;
        *) echo -e "${RED}无效模式，请输入 1 或 2。${PLAIN}"; sleep 1; return ;;
    esac

    echo -e "突发限速: 出站连续 ${BURST_TRIGGER_MINUTES} 分钟超过 ${BURST_TRIGGER_MBPS} Mbps，"
    echo -e "          临时限制为 ${BURST_LIMIT_MBPS} Mbps，持续 ${BURST_DURATION_MINUTES} 分钟。"
    local burst_enabled=false
    confirm_yes "是否接入突发限速？" && burst_enabled=true

    read -r -p "每月自动重置日 [0-31，默认 0（不自动重置）]: " reset_day
    reset_day=$(strip_cr "$reset_day")
    [ -z "$reset_day" ] && reset_day=0
    if [[ ! "$reset_day" =~ ^[0-9]+$ ]] || [ "$reset_day" -gt 31 ]; then
        echo -e "${RED}无效重置日，请输入 0-31。${PLAIN}"; sleep 1; return
    fi

    read -r -p "用户（可留空）: " comment
    comment=$(strip_cr "$comment")

    read -r -p "用户到期日期（YYYY-MM-DD，留空为不提醒）: " expiry_date
    expiry_date=$(strip_cr "$expiry_date")
    if [ -n "$expiry_date" ] && ! validate_expiry_date "$expiry_date"; then
        echo -e "${RED}错误: 到期日期必须是有效的 YYYY-MM-DD。${PLAIN}"
        sleep 2
        return
    fi

    local tmp=$(mktemp)
    if jq --argjson q "$quota" --arg m "$mode" --argjson burst "$burst_enabled" --argjson rd "$reset_day" \
          --arg c "$comment" --arg expiry "$expiry_date" --arg p "$target_port" \
       '.ports[$p] = {
        "quota_gb": $q, 
        "quota_mode": $m, 
        "reset_day": $rd,
        "comment": $c, 
        "expiry_date": $expiry,
        "group_id": "",
        "dyn_limit": {"enable": $burst},
        "ip_limit": {"enable": true, "max_ips": 3, "action": "alert", "cooldown_min": 30, "whitelist": []}
    }' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
        rm -f "$tmp"
        # 创建初始 state 文件
        _init_port_state_defaults
        s_last_reset_ts=$(date +%s)
        s_last_sample_ts=$s_last_reset_ts
        if ! _save_port_state "$target_port" || ! apply_port_rules "$target_port"; then
            pm_error "端口 ${target_port} 的规则创建失败，正在回滚配置"
            rm -f "$STATE_DIR/${target_port}.txt"
            local rollback_tmp=$(mktemp)
            if jq --arg p "$target_port" 'del(.ports[$p])' "$CONFIG_FILE" > "$rollback_tmp" \
                && safe_write_config_from_file "$rollback_tmp"; then
                reload_all_rules || pm_error "添加失败后的规则回滚不完整，请立即检查"
            else
                pm_error "端口 ${target_port} 配置回滚失败，请立即检查"
            fi
            rm -f "$rollback_tmp"
            echo -e "${RED}添加失败，配置已回滚；详情请查看 ${LOG_FILE}。${PLAIN}"
            sleep 2
            return 1
        fi
        echo -e "${GREEN}添加成功，IP 接入监控已默认开启（>3 告警，>5 升级）。${PLAIN}"; sleep 1; return
    else
        rm -f "$tmp"
        echo -e "${RED}写入配置失败!${PLAIN}"; sleep 2; return
    fi
}

config_port_menu() {
    local arr=("$@")
    echo
    read -r -p "请输入要配置的端口 ID（0 返回）: " id
    id=$(strip_cr "$id")
    [ "$id" = "0" ] && return
    if [[ ! "$id" =~ ^[0-9]+$ ]] || [ "$id" -le 0 ]; then
        echo -e "${RED}无效 ID。${PLAIN}"; sleep 1; return
    fi
    local port=${arr[$((id-1))]}
    if [ -z "$port" ]; then echo -e "${RED}无效 ID。${PLAIN}"; sleep 1; return; fi
    
    while true; do
        local conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
        local comment=$(echo "$conf" | jq -r '.comment // ""')
        local quota=$(echo "$conf" | jq -r '.quota_gb')
        local mode=$(echo "$conf" | jq -r '.quota_mode')
        local gid=$(echo "$conf" | jq -r '.group_id // empty')
        local gid_display="$gid"
        [ -z "$gid_display" ] && gid_display="${YELLOW}无 (独立)${PLAIN}"
        
        local dyn_conf=$(echo "$conf" | jq '.dyn_limit')
        local dyn_enable=$(echo "$dyn_conf" | jq -r '.enable // false')
        local reset_day=$(echo "$conf" | jq -r '.reset_day // 0')
        local expiry_date=$(echo "$conf" | jq -r '.expiry_date // ""')
        local ip_enable=$(echo "$conf" | jq -r '.ip_limit.enable // false')
        local ip_max=$(echo "$conf" | jq -r '.ip_limit.max_ips // 3')
        
        clear
        echo -e "$UI_DIVIDER"
        echo -e " 当前配置: [$id]  $port"
        echo -e "$UI_DIVIDER"
        echo -e " 流量配额: $quota GB"
        echo -e " 用户:     $([ -n "$comment" ] && echo "$comment" || echo "${YELLOW}未设置${PLAIN}")"
        echo -e " 流量分组: $gid_display"
        echo -e " 计费模式: $([ "$mode" == "out_only" ] && echo "仅出站" || echo "双向")"
        echo -e " 突发限速: $([ "$dyn_enable" == "true" ] && echo "${GREEN}已接入${PLAIN}" || echo "${YELLOW}未接入${PLAIN}")"
        [ "$dyn_enable" == "true" ] && echo -e " 固定策略: >${BURST_TRIGGER_MBPS} Mbps ${BURST_TRIGGER_MINUTES}分钟 → ${BURST_LIMIT_MBPS} Mbps ${BURST_DURATION_MINUTES}分钟"
        if [ "$reset_day" -gt 0 ] 2>/dev/null; then echo -e " 自动重置: 每月 ${GREEN}${reset_day}${PLAIN} 日"; else echo -e " 自动重置: ${YELLOW}未设置${PLAIN}"; fi
        if [ -n "$expiry_date" ]; then echo -e " 用户到期: ${GREEN}${expiry_date}${PLAIN} (提前 3 天提醒)"; else echo -e " 用户到期: ${YELLOW}未设置${PLAIN}"; fi
        echo -e "$UI_SEPARATOR"
        echo -e " 1. 修改 流量配额"
        echo -e " 2. 修改 计费模式"
        echo -e " 3. 设置 突发限速"
        echo -e " 4. 修改 用户"
        echo -e " 5. 重置 统计数据 (清零)"
        echo -e " 6. 修改 自动重置日"
        echo -e " 7. 设置/修改 分组 ID"
        echo -e " 8. 设置 IP 接入监控 $([ "$ip_enable" == "true" ] && echo "[已开启，>${ip_max} 告警]" || echo "[未开启]")"
        echo -e " 9. 设置 用户到期提醒"
        echo -e " 0. 返回主菜单"
        echo -e "$UI_DIVIDER"
        read -r -p "请选择: " sub_choice
        sub_choice=$(strip_cr "$sub_choice")
        
        local tmp=$(mktemp)
        local success=false

        case $sub_choice in
            1) 
                read -r -p "新配额（GB，正整数）: " val
                val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -gt 0 ] && [ "$val" -le "$MAX_QUOTA_GB" ]; then
                    local sync_gid=$(jq -r --arg p "$port" '.ports[$p].group_id // empty' "$CONFIG_FILE")
                    if jq --argjson v "$val" --arg p "$port" --arg g "$sync_gid" '
                        if $g != "" then
                            .ports |= with_entries(if .value.group_id == $g then .value.quota_gb = $v else . end)
                        else .ports[$p].quota_gb = $v end
                    ' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                        success=true
                        [ -n "$sync_gid" ] && echo -e "${GREEN}已同步配额到组 [${sync_gid}] 的所有端口。${PLAIN}"
                    fi
                else
                    echo -e "${RED}错误: 必须输入大于0的纯整数!${PLAIN}"; sleep 1
                fi 
                ;;
            2) 
                read -r -p "选择模式 [1 双向 / 2 仅出站，留空取消]: " m
                m=$(strip_cr "$m")
                local nm
                case "$m" in
                    "") rm -f "$tmp"; continue ;;
                    1) nm="in_out" ;;
                    2) nm="out_only" ;;
                    *) echo -e "${RED}无效模式，请输入 1 或 2。${PLAIN}"; rm -f "$tmp"; sleep 1; continue ;;
                esac
                if jq --arg v "$nm" --arg p "$port" '.ports[$p].quota_mode = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then success=true; fi
                ;;
            3) rm -f "$tmp"; configure_burst_limit "$port" ;;
            4)
                read -r -p "新用户（留空清除）: " val
                val=$(strip_cr "$val")
                if jq --arg v "$val" --arg p "$port" '.ports[$p].comment = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then success=true; fi
                ;;
            5)
                if [ -n "$gid" ]; then
                    echo -e "${YELLOW}端口属于组 [${gid}]，将清零该组全部端口。${PLAIN}"
                fi
                if confirm_yes "确定清零吗？"; then
                   local reset_ports="$port"
                   if [ -n "$gid" ]; then
                       reset_ports=$(jq -r --arg g "$gid" '.ports | to_entries[] | select(.value.group_id == $g) | .key' "$CONFIG_FILE")
                   fi
                   local reset_failed=false reset_port reset_now=$(date +%s)
                   local reset_blocked=" $(nft -j list set $NFT_TABLE blocked_ports 2>/dev/null | jq -r '[ .nftables[] | select(.set) | .set.elem[]? ] | map(tostring) | join(" ")') "
                   for reset_port in $reset_ports; do
                       local k_in=$(nft -j list counter $NFT_TABLE "cnt_in_${reset_port}" 2>/dev/null | jq -r '[ .nftables[] | select(.counter) | .counter.bytes ] | .[0] // 0')
                       local k_out=$(nft -j list counter $NFT_TABLE "cnt_out_${reset_port}" 2>/dev/null | jq -r '[ .nftables[] | select(.counter) | .counter.bytes ] | .[0] // 0')
                       _load_port_state "$reset_port"
                       s_acc_in=0; s_acc_out=0; s_last_k_in=$k_in; s_last_k_out=$k_out
                       s_last_reset_ts=$reset_now; s_quota_level=0
                       _save_port_state "$reset_port" || reset_failed=true
                       if [[ "$reset_blocked" == *" $reset_port "* ]] \
                           && ! nft delete element $NFT_TABLE blocked_ports \{ $reset_port \} 2>/dev/null; then
                           pm_error "手动重置时无法解除端口 ${reset_port} 的封禁"
                           reset_failed=true
                       fi
                   done
                   if [ "$reset_failed" == "false" ]; then
                       echo -e "${GREEN}$([ -n "$gid" ] && echo "组 [${gid}]" || echo "端口 ${port}") 已重置。${PLAIN}"
                   else
                       echo -e "${RED}部分状态重置失败，请查看 ${LOG_FILE}。${PLAIN}"
                   fi
                   sleep 1
                fi 
                ;;
            6)
                read -r -p "自动重置日（1-31，0 为关闭）: " val
                val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -le 31 ]; then
                    local sync_gid=$(jq -r --arg p "$port" '.ports[$p].group_id // empty' "$CONFIG_FILE")
                    if jq --argjson v "$val" --arg p "$port" --arg g "$sync_gid" '
                        if $g != "" then
                            .ports |= with_entries(if .value.group_id == $g then .value.reset_day = $v else . end)
                        else .ports[$p].reset_day = $v end
                    ' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                        success=true
                        [ -n "$sync_gid" ] && echo -e "${GREEN}已同步重置日到组 [${sync_gid}] 的所有端口。${PLAIN}"
                    fi
                else
                    echo -e "${RED}错误: 必须输入 0-31 的整数!${PLAIN}"; sleep 1
                fi
                ;;
            7)
                # [优化] 自动列出已有分组供选择
                echo -e "\n$UI_SEPARATOR"
                echo -e " 分组设置"
                echo -e "$UI_SEPARATOR"
                local existing_groups=$(jq -r '.ports | to_entries[] | select(.value.group_id != null and .value.group_id != "") | "\(.value.group_id)|\(.value.quota_gb)"' "$CONFIG_FILE" | sort -t'|' -k1,1 -u)
                declare -A group_map
                group_map=()
                local g_idx=1
                
                if [ -n "$existing_groups" ]; then
                    echo -e "当前已有分组:"
                    while IFS='|' read -r g_name g_quota; do
                        echo -e " [${g_idx}] ${BLUE}${g_name}${PLAIN} (配额: ${g_quota}GB)"
                        group_map[$g_idx]="$g_name"
                        g_idx=$((g_idx + 1))
                    done <<< "$existing_groups"
                    echo -e "$UI_SEPARATOR"
                fi
                
                read -r -p "分组 ID（输入名称新建/输入序号选择/留空清除）: " input_val
                input_val=$(strip_cr "$input_val")
                
                local val=""
                if [[ "$input_val" =~ ^[0-9]+$ ]] && [ -n "${group_map[$input_val]}" ]; then
                    val="${group_map[$input_val]}"
                    echo -e "已选择分组: ${BLUE}${val}${PLAIN}"
                else
                    # [Sanitization] 输入清洗: 只允许字母数字下划线中划线
                    if [ -n "$input_val" ] && [ "$input_val" != "0" ]; then
                        if [[ ! "$input_val" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                            echo -e "${RED}错误: 组名仅支持字母、数字、下划线(_)和连字符(-)！${PLAIN}"
                            rm -f "$tmp"; sleep 2; continue
                        fi
                    fi
                    val="$input_val"
                fi
                
                [ "$val" == "0" ] && val=""
                
                # 加入现有组时，在一次原子写入中同步配额和重置日。
                local template_json="" t_quota=0 t_reset=0 has_template=false
                if [ -n "$val" ]; then
                    template_json=$(jq -c --arg g "$val" --arg p "$port" \
                        '.ports | to_entries[] | select(.value.group_id == $g and .key != $p) | .value' \
                        "$CONFIG_FILE" | head -1)
                    if [ -n "$template_json" ] && echo "$template_json" | jq -e '.quota_gb' >/dev/null 2>&1; then
                        t_quota=$(echo "$template_json" | jq -r '.quota_gb')
                        t_reset=$(echo "$template_json" | jq -r '.reset_day // 0')
                        has_template=true
                    fi
                fi
                if jq --arg v "$val" --arg p "$port" --argjson sync "$has_template" \
                    --argjson q "$t_quota" --argjson r "$t_reset" '
                    .ports[$p].group_id = $v |
                    if $sync then .ports[$p].quota_gb = $q | .ports[$p].reset_day = $r else . end
                ' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                    echo -e "${GREEN}分组 ID 已更新。${PLAIN}"
                    if [ "$has_template" == "true" ]; then
                        echo -e "${GREEN}已同步现有组配置: 配额=${t_quota}GB，重置日=${t_reset}。${PLAIN}"
                    fi
                    success=true
                else
                    echo -e "${RED}写入失败。${PLAIN}"
                fi
                ;;
            8) rm -f "$tmp"; configure_ip_sentinel "$port" ;;
            9) rm -f "$tmp"; configure_user_expiry "$port" ;;
            0) rm -f "$tmp"; break ;;
        esac
        
        if [ "$success" == "true" ]; then echo -e "${GREEN}配置已更新。${PLAIN}"; sleep 0.5; fi
        rm -f "$tmp"
    done
}

# ==============================================================================
# 4.5 辅助配置函数
# ==============================================================================

configure_user_expiry() {
    local port=$1 value tmp
    echo -e "\n用户到期前 3 天将通过本机 Telegram 告警提醒一次。"
    read -r -p "到期日期（YYYY-MM-DD，0 为关闭，留空取消）: " value
    value=$(strip_cr "$value")
    [ -z "$value" ] && return 0
    [ "$value" = "0" ] && value=""
    if [ -n "$value" ] && ! validate_expiry_date "$value"; then
        echo -e "${RED}错误: 到期日期必须是有效的 YYYY-MM-DD。${PLAIN}"
        sleep 2
        return 1
    fi

    tmp=$(mktemp) || { pm_error "无法创建到期配置临时文件"; return 1; }
    if jq --arg p "$port" --arg value "$value" '.ports[$p].expiry_date = $value' "$CONFIG_FILE" > "$tmp" \
        && safe_write_config_from_file "$tmp"; then
        _load_port_state "$port"
        s_expiry_notified_date=""
        if ! _save_port_state "$port"; then
            rm -f "$tmp"
            pm_error "端口 ${port} 的到期提醒状态重置失败"
            echo -e "${RED}到期日期已保存，但提醒状态重置失败，请修复后重新设置。${PLAIN}"
            sleep 2
            return 1
        fi
        if [ -n "$value" ]; then
            echo -e "${GREEN}已设置为 ${value}，将提前 3 天提醒。${PLAIN}"
        else
            echo -e "${GREEN}已关闭该用户的到期提醒。${PLAIN}"
        fi
        rm -f "$tmp"
        sleep 1
        return 0
    fi
    rm -f "$tmp"
    pm_error "端口 ${port} 的到期日期写入失败"
    sleep 2
    return 1
}

configure_burst_limit() {
    local port=$1 conf enabled action target tmp old_config
    conf=$(jq ".ports[\"$port\"].dyn_limit // {\"enable\":false}" "$CONFIG_FILE")
    enabled=$(echo "$conf" | jq -r '.enable // false')
    _load_port_state "$port"

    echo -e "\n$UI_DIVIDER"
    echo -e " 突发限速 - 端口 $port"
    echo -e "$UI_DIVIDER"
    echo -e " 状态: $([ "$enabled" == "true" ] && echo "${GREEN}已接入${PLAIN}" || echo "${YELLOW}未接入${PLAIN}")"
    echo -e " 规则: 出站连续 ${BURST_TRIGGER_MINUTES} 分钟 > ${BURST_TRIGGER_MBPS} Mbps"
    echo -e "       限制为 ${BURST_LIMIT_MBPS} Mbps，持续 ${BURST_DURATION_MINUTES} 分钟后恢复不限速"
    echo -e " 通知: 触发和恢复时发送 Telegram 通知（需已开启）"
    if [ "$enabled" == "true" ]; then
        echo -e " 当前: $([ "$s_is_punished" == "true" ] && echo "${RED}限速生效中${PLAIN}" || echo "等待触发")"
        echo -e " 累计: $((s_high_seconds / 60)) / ${BURST_TRIGGER_MINUTES} 分钟"
    fi
    echo -e "$UI_SEPARATOR"
    if [ "$enabled" == "true" ]; then action="关闭"; target=false; else action="开启"; target=true; fi
    echo -e " 1. ${action}突发限速"
    echo -e " 0. 取消"
    echo -e "$UI_DIVIDER"
    read -r -p "请选择 [0-1，默认 0]: " choice; choice=$(strip_cr "$choice")
    [ "$choice" != "1" ] && return 0

    old_config=$(cat "$CONFIG_FILE") || { pm_error "无法备份当前配置"; return 1; }
    tmp=$(mktemp) || { pm_error "无法创建突发限速配置临时文件"; return 1; }
    if ! jq --argjson value "$target" --arg p "$port" '.ports[$p].dyn_limit={"enable":$value}' \
        "$CONFIG_FILE" > "$tmp" || ! safe_write_config_from_file "$tmp"; then
        rm -f "$tmp"
        pm_error "端口 ${port} 的突发限速配置写入失败"
        sleep 2
        return 1
    fi
    rm -f "$tmp"

    local old_high=$s_high_seconds old_punished=$s_is_punished old_end=$s_punish_end_ts
    local old_punish_notified=$s_punish_notified old_recover_notified=$s_recover_notified
    local old_dirty=$s_rules_dirty old_notice=$s_pending_qos_notice
    s_high_seconds=0; s_is_punished=false; s_punish_end_ts=0
    s_punish_notified=false; s_recover_notified=true
    s_rules_dirty=false; s_pending_qos_notice=""

    if _save_port_state "$port" && apply_port_rules "$port"; then
        echo -e "${GREEN}已${action}突发限速。${PLAIN}"
        sleep 0.5
        return 0
    fi

    pm_error "端口 ${port} 的突发限速规则更新失败，正在恢复"
    safe_write_config "$old_config" || pm_error "突发限速配置恢复失败"
    s_high_seconds=$old_high; s_is_punished=$old_punished; s_punish_end_ts=$old_end
    s_punish_notified=$old_punish_notified; s_recover_notified=$old_recover_notified
    s_rules_dirty=$old_dirty; s_pending_qos_notice=$old_notice
    _save_port_state "$port" || pm_error "突发限速状态恢复失败"
    apply_port_rules "$port" || pm_error "原突发限速规则恢复失败"
    echo -e "${RED}操作失败，原配置已恢复。${PLAIN}"
    sleep 2
    return 1
}

configure_notifications() {
    while true; do
        local tg_status=$(telegram_status_text)
        local push_status=$(push_status_text)
        clear
        echo -e "$UI_DIVIDER"
        echo -e "   通知与推送"
        echo -e "$UI_DIVIDER"
        echo -e " Telegram 告警    $tg_status"
        echo -e " Cloudflare 上报  $push_status"
        echo -e "$UI_SEPARATOR"
        echo -e " 1. Telegram 告警设置"
        echo -e " 2. Cloudflare 云端推送"
        echo -e " 0. 返回主菜单"
        echo -e "$UI_DIVIDER"
        read -r -p "请选择: " choice
        choice=$(strip_cr "$choice")
        case $choice in
            1) configure_telegram ;;
            2) configure_push ;;
            0) break ;;
        esac
    done
}

configure_telegram() {
    while true; do
        local tg=$(jq '.telegram' "$CONFIG_FILE")
        local t_enable=$(echo "$tg" | jq -r '.enable // false')
        local t_token=$(echo "$tg" | jq -r '.bot_token // ""')
        local t_chatid=$(echo "$tg" | jq -r '.chat_id // ""')
        local t_api=$(echo "$tg" | jq -r '.api_url // "https://api.telegram.org"')
        local t_thr=$(echo "$tg" | jq -r '.thresholds // [50,80,100] | map(tostring) | join(", ")')

        local status_str=$(telegram_status_text)
        local bot_str="${YELLOW}⚠️ 未完成${PLAIN}"
        [ -n "$t_token" ] && [ -n "$t_chatid" ] && bot_str="${GREEN}✅ 已完成${PLAIN}"
        local api_str="$t_api"
        [ "$t_api" == "https://api.telegram.org" ] && api_str="官方 API"

        clear
        echo -e "$UI_DIVIDER"
        echo -e "   Telegram 告警设置"
        echo -e "$UI_DIVIDER"
        echo -e " 状态:      $status_str"
        echo -e " Bot 配置:  $bot_str"
        echo -e " 流量阈值:  ${t_thr}%"
        echo -e " API 地址:  $api_str"
        echo -e "$UI_SEPARATOR"
        echo -e " 1. 开启/关闭通知"
        echo -e " 2. 配置 Bot (Token + Chat ID)"
        echo -e " 3. 发送测试消息"
        echo -e " 4. 设置流量提醒阈值"
        echo -e " 5. 设置 API 地址"
        echo -e " 0. 返回通知与推送"
        echo -e "$UI_DIVIDER"
        read -r -p "请选择: " c
        c=$(strip_cr "$c")
        local tmp=$(mktemp)

        case $c in
            1)
                local nv="true"; [ "$t_enable" == "true" ] && nv="false"
                if [ "$nv" == "true" ] && { [ -z "$t_token" ] || [ -z "$t_chatid" ]; }; then
                    echo -e "${RED}请先完成 Bot Token 和 Chat ID 配置。${PLAIN}"
                    sleep 1
                elif jq --argjson v "$nv" '.telegram.enable=$v' "$CONFIG_FILE" > "$tmp" \
                    && commit_generated_config "$tmp" "已$([ "$nv" == "true" ] && echo "开启" || echo "关闭")。" "Telegram 状态写入失败"; then
                    sleep 0.5
                else sleep 1; fi ;;
            2)
                local new_token new_chatid
                read -r -s -p "Bot Token（留空保留当前值）: " new_token; echo
                new_token=$(strip_cr "$new_token")
                read -r -p "Chat ID（留空保留当前值）: " new_chatid
                new_chatid=$(strip_cr "$new_chatid")
                [ -z "$new_token" ] && new_token="$t_token"
                [ -z "$new_chatid" ] && new_chatid="$t_chatid"
                if [ -z "$new_token" ] || [ -z "$new_chatid" ]; then
                    echo -e "${RED}Bot Token 和 Chat ID 必须同时配置。${PLAIN}"
                    sleep 1
                elif jq --arg token "$new_token" --arg chat_id "$new_chatid" \
                    '.telegram.bot_token=$token | .telegram.chat_id=$chat_id' "$CONFIG_FILE" > "$tmp" \
                    && commit_generated_config "$tmp" "Bot 配置已更新。" "Bot 配置写入失败"; then
                    sleep 0.5
                else sleep 1; fi ;;
            3)
                echo -e "${YELLOW}正在发送测试消息...${PLAIN}"
                if [ -z "$t_token" ] || [ -z "$t_chatid" ]; then
                    echo -e "${RED}请先配置 Bot Token 和 Chat ID。${PLAIN}"; sleep 1
                else
                    local nid=$(jq -r '.node_id // "unknown"' "$CONFIG_FILE")
                    local safe_nid=$(echo "$nid" | sed 's/[_*`\[]/\\&/g')
                    local test_msg="✅ *Telegram 通知测试*
${TG_DIVIDER}
🖥 节点  *${safe_nid}*
└ 📡 状态  Bot 通信正常
${TG_DIVIDER}
ℹ️ PM 通知配置已生效"
                    local result=$(curl -s --max-time 10 "${t_api}/bot${t_token}/sendMessage" \
                        -d chat_id="$t_chatid" -d text="$test_msg" -d parse_mode="Markdown")
                    if echo "$result" | jq -e '.ok == true' >/dev/null 2>&1; then
                        echo -e "${GREEN}发送成功!${PLAIN}"
                    else
                        local err=$(echo "$result" | jq -r '.description // "未知错误"' 2>/dev/null)
                        echo -e "${RED}发送失败: ${err}${PLAIN}"
                    fi
                    sleep 2
                fi ;;
            4)
                echo -e "当前阈值: ${t_thr}%"
                read -r -p "新阈值（逗号分隔，如 50,80,100；留空取消）: " val
                val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
                    local arr_json=$(echo "$val" | tr ',' '\n' | jq -s '.')
                    if jq --argjson v "$arr_json" '.telegram.thresholds=$v' "$CONFIG_FILE" > "$tmp" \
                        && commit_generated_config "$tmp" "阈值已更新。" "通知阈值写入失败"; then sleep 0.5; else sleep 1; fi
                elif [ -n "$val" ]; then
                    echo -e "${RED}格式错误，请输入纯数字并用逗号分隔。${PLAIN}"; sleep 1
                fi ;;
            5)
                echo -e "当前 API: $t_api"
                echo -e "留空恢复默认：https://api.telegram.org"
                read -r -p "新 API 地址（留空恢复官方 API）: " val
                val=$(strip_cr "$val")
                [ -z "$val" ] && val="https://api.telegram.org"
                if jq --arg v "$val" '.telegram.api_url=$v' "$CONFIG_FILE" > "$tmp" \
                    && commit_generated_config "$tmp" "API 地址已更新。" "Telegram API 地址写入失败"; then sleep 0.5; else sleep 1; fi ;;
            0) rm -f "$tmp"; break ;;
        esac
        rm -f "$tmp"
    done
}

configure_push() {
    while true; do
        local pc=$(jq '.push // {}' "$CONFIG_FILE")
        local p_enable=$(echo "$pc" | jq -r '.enable // false')
        local p_url=$(echo "$pc" | jq -r '.worker_url // ""')
        local p_secret=$(echo "$pc" | jq -r '.secret // ""')
        local p_nkey=$(echo "$pc" | jq -r '.node_key // ""')

        local status_str=$(push_status_text)
        local url_str="${YELLOW}未配置${PLAIN}"
        [ -n "$p_url" ] && [ "$p_url" != "" ] && url_str="${GREEN}${p_url}${PLAIN}"
        local secret_str="${YELLOW}未配置${PLAIN}"
        [ -n "$p_secret" ] && [ "$p_secret" != "" ] && secret_str="${GREEN}已配置${PLAIN} (${p_secret:0:6}...)"
        local nkey_str="${YELLOW}未配置${PLAIN}"
        [ -n "$p_nkey" ] && [ "$p_nkey" != "" ] && nkey_str="${GREEN}${p_nkey}${PLAIN}"

        clear
        echo -e "$UI_DIVIDER"
        echo -e "   Cloudflare Worker 云端推送"
        echo -e "$UI_DIVIDER"
        echo -e " 状态:     $status_str"
        echo -e " Worker:   $url_str"
        echo -e " Secret:   $secret_str"
        echo -e " Node Key: $nkey_str"
        echo -e "$UI_SEPARATOR"
        echo -e " 1. 开启/关闭推送"
        echo -e " 2. 配置 Worker URL"
        echo -e " 3. 配置 Secret"
        echo -e " 4. 配置 Node Key"
        echo -e " 0. 返回通知与推送"
        echo -e "$UI_DIVIDER"
        read -r -p "请选择: " c
        c=$(strip_cr "$c")
        local tmp=$(mktemp)

        case $c in
            1)
                local nv="true"; [ "$p_enable" == "true" ] && nv="false"
                if [ "$nv" == "true" ] && { [ -z "$p_url" ] || [ -z "$p_secret" ] || [ -z "$p_nkey" ]; }; then
                    echo -e "${RED}请先完成 Worker URL、Secret 和 Node Key 配置。${PLAIN}"
                    sleep 1
                elif jq --argjson v "$nv" '.push.enable=$v' "$CONFIG_FILE" > "$tmp" \
                    && commit_generated_config "$tmp" "已$([ "$nv" == "true" ] && echo "开启" || echo "关闭")。" "云端推送状态写入失败"; then
                    sleep 0.5
                else sleep 1; fi ;;
            2)
                read -r -p "Worker URL（留空取消）: " val; val=$(strip_cr "$val")
                if [ -n "$val" ]; then
                    if jq --arg v "$val" '.push.worker_url=$v' "$CONFIG_FILE" > "$tmp" \
                        && commit_generated_config "$tmp" "已更新。" "Worker URL 写入失败"; then sleep 0.5; else sleep 1; fi
                fi ;;
            3)
                read -r -s -p "Secret（留空取消）: " val; echo; val=$(strip_cr "$val")
                if [ -n "$val" ]; then
                    if jq --arg v "$val" '.push.secret=$v' "$CONFIG_FILE" > "$tmp" \
                        && commit_generated_config "$tmp" "已更新。" "Worker Secret 写入失败"; then sleep 0.5; else sleep 1; fi
                fi ;;
            4)
                read -r -p "Node Key（留空取消）: " val; val=$(strip_cr "$val")
                [ -z "$val" ] && { rm -f "$tmp"; continue; }
                val=${val,,}
                if [[ "$val" =~ ^[a-z0-9][a-z0-9_-]{0,63}$ ]]; then
                    if jq --arg v "$val" '.push.node_key=$v' "$CONFIG_FILE" > "$tmp" \
                        && commit_generated_config "$tmp" "已更新。" "Node Key 写入失败"; then sleep 0.5; else sleep 1; fi
                else
                    echo -e "${RED}Node Key 必须为 1-64 位小写字母、数字、下划线或连字符，且以字母或数字开头。${PLAIN}"; sleep 1
                fi ;;
            0) rm -f "$tmp"; break ;;
        esac
        rm -f "$tmp"
    done
}

delete_port_flow() {
    local arr=("$@")
    read -r -p "请输入要删除的端口 ID（0 返回）: " id
    id=$(strip_cr "$id")
    [ "$id" = "0" ] && return
    if [[ ! "$id" =~ ^[0-9]+$ ]] || [ "$id" -le 0 ]; then
        echo -e "${RED}无效 ID。${PLAIN}"; sleep 1; return
    fi
    local port=${arr[$((id-1))]}
    if [ -z "$port" ]; then echo -e "${RED}无效 ID。${PLAIN}"; sleep 1; return; fi

    confirm_yes "确认删除端口 ${port}？" || return

    # 配置、Nftables 与 TC 作为一个操作处理；失败时恢复原配置。
    local backup
    backup=$(mktemp) || { pm_error "无法创建删除回滚文件"; return 1; }
    cp "$CONFIG_FILE" "$backup" || { rm -f "$backup"; pm_error "无法备份当前配置"; return 1; }
    local tmp=$(mktemp)
    if jq "del(.ports[\"$port\"])" "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
        rm -f "$tmp"
        if remove_port_tc_rules "$port" && reload_all_rules; then
            rm -f "$STATE_DIR/${port}.txt" "$backup"
            echo -e "${GREEN}端口 ${port} 已删除。${PLAIN}"; sleep 1
        else
            pm_error "端口 ${port} 删除后的规则清理失败，正在恢复"
            if safe_write_config_from_file "$backup" && reload_all_rules; then
                echo -e "${RED}删除失败，原配置与规则已恢复。${PLAIN}"
            else
                echo -e "${RED}删除失败且自动恢复不完整，请立即检查 ${LOG_FILE}。${PLAIN}"
            fi
            rm -f "$backup"
            sleep 2
            return 1
        fi
    else
        rm -f "$tmp" "$backup"
        echo -e "${RED}删除失败。${PLAIN}"; sleep 1
        return 1
    fi
}

update_script() {
    echo -e "${YELLOW}正在检查更新...${PLAIN}"
    local tmp
    tmp=$(mktemp "${INSTALL_PATH}.update.XXXXXX") || {
        echo -e "${RED}无法创建更新临时文件，现有脚本未被覆盖。${PLAIN}" >&2
        return 1
    }
    if curl -fsSLo "$tmp" --connect-timeout 8 --max-time 30 "$(fresh_script_url)" \
        && validate_script_candidate "$tmp"; then
        local remote_ver
        remote_ver=$(grep '^SCRIPT_VERSION=' "$tmp" | head -1 | cut -d'"' -f2)
        if version_is_older "$remote_ver" "$SCRIPT_VERSION"; then
            rm -f "$tmp"
            echo -e "${RED}拒绝降级：远端 v${remote_ver} 低于当前 v${SCRIPT_VERSION}。${PLAIN}" >&2
            return 1
        fi
        if [ "$remote_ver" == "$SCRIPT_VERSION" ] && cmp -s "$tmp" "$INSTALL_PATH"; then
            rm -f "$tmp"
            echo -e "${GREEN}已是最新版本 (v${SCRIPT_VERSION})。${PLAIN}"
            return 0
        fi
        if [ "$remote_ver" == "$SCRIPT_VERSION" ]; then
            echo -e "${YELLOW}检测到同版本内容修订，将继续更新。${PLAIN}"
        fi
        if ! chmod 755 "$tmp" || ! mv -f "$tmp" "$INSTALL_PATH"; then
            echo -e "${RED}替换脚本失败，现有脚本保持不变。${PLAIN}" >&2
            return 1
        fi
        echo -e "${GREEN}更新成功 (v${remote_ver})，正在重启...${PLAIN}"; sleep 1
        # exec 前释放菜单持有的 Cron 锁，新版启动后才能立即完成规则迁移。
        stop_edit_lock
        exec "$INSTALL_PATH"
    else
        rm -f "$tmp"
        echo -e "${RED}更新失败: 下载、格式或 Bash 语法校验未通过；现有脚本未被覆盖。${PLAIN}"
        sleep 2
        return 1
    fi
}

uninstall_script() {
    echo -e "${RED}警告: 将删除所有配置和监控规则!${PLAIN}"
    read -r -p "确认卸载？输入 yes 确认，直接回车取消: " c
    c=$(strip_cr "$c")
    [ "$c" != "yes" ] && return

    echo -e "${YELLOW}正在清理...${PLAIN}"

    # 1. 先停止后台入口；失败时不继续破坏运行状态。
    local old_line="* * * * * $INSTALL_PATH --monitor"
    local cron_line="${old_line} >> $LOG_FILE 2>&1"
    if ! crontab -l 2>/dev/null | awk -v old="$old_line" -v current="$cron_line" \
        '$0 != old && $0 != current' | crontab -; then
        pm_error "Cron 任务清理失败，卸载已停止"
        echo -e "${RED}卸载失败: 无法清理 Cron，配置和规则均已保留。${PLAIN}"
        return 1
    fi
    echo -e "  Cron 任务已清除"

    local cleanup_failed=false

    # 2. 清除 nftables 规则
    if nft list table $NFT_TABLE >/dev/null 2>&1 && ! nft delete table $NFT_TABLE 2>/dev/null; then
        pm_error "Nftables 规则清理失败"
        cleanup_failed=true
    else
        echo -e "  nftables 规则已清除"
    fi

    # 3. 仅清除由本脚本创建并登记的 TC 根队列
    local iface=$(jq -r '.interface // empty' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$iface" ] && iface=$(get_iface)
    if [ -n "$iface" ] && [ -f "$TC_OWNER_FILE" ] && [ "$(cat "$TC_OWNER_FILE" 2>/dev/null)" = "$iface" ] && \
       tc qdisc show dev "$iface" 2>/dev/null | grep -Eq 'qdisc htb 1:.* root'; then
        if tc qdisc del dev "$iface" root 2>/dev/null; then
            echo -e "  TC 限速规则已清除"
        else
            pm_error "TC 根队列清理失败"
            cleanup_failed=true
        fi
    else
        echo -e "  TC 根队列非本脚本所有，已保留"
    fi

    if [ "$cleanup_failed" == "true" ]; then
        echo -e "${RED}卸载未完成: 规则清理失败，配置文件已保留，请根据 ${LOG_FILE} 排查后重试。${PLAIN}"
        return 1
    fi

    # 4. 删除文件
    if ! rm -rf "$CONFIG_DIR" "$INSTALL_PATH" "$LOCK_FILE" "$CRON_LOCK_FILE" "$USER_EDIT_LOCK" "$LOG_FILE" 2>/dev/null; then
        echo -e "${RED}卸载未完成: 部分文件无法删除，请检查权限后重试。${PLAIN}"
        return 1
    fi
    echo -e "  文件已清除"

    echo -e "${GREEN}卸载完成。${PLAIN}"
    exit 0
}

# ==============================================================================
# 入口逻辑
# ==============================================================================
check_root
install_shortcut "${1:-}" || exit 1
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [ "${1:-}" == "--monitor" ] || [ "${1:-}" == "--ipl" ]; then
    # [OPT-FAST] cron/CLI 模式: 跳过完整 install_deps (依赖已在首次运行时安装, 配置已迁移)
    # 仅做最小化检查: 配置文件存在且 JSON 合法
    if [ ! -s "$CONFIG_FILE" ] || ! validate_config_candidate "$CONFIG_FILE"; then
        pm_error "配置文件不存在或损坏，监控任务已停止；请运行 pm 进行检查"
        echo -e "${RED}错误: 配置文件不存在或损坏，监控任务已停止；请运行 pm 进行检查。${PLAIN}" >&2
        exit 1
    fi
    mkdir -p "$STATE_DIR"
else
    # 首次安装、升级迁移也与既有 Cron 互斥，避免迁移状态时被旧任务覆盖。
    exec 7>"$CRON_LOCK_FILE" || { pm_error "无法打开后台任务锁"; exit 1; }
    flock -x 7 || { pm_error "无法等待后台任务结束"; exit 1; }
    install_deps
    ensure_runtime_rules || {
        flock -u 7 2>/dev/null || true
        exec 7>&-
        exit 1
    }
    flock -u 7 2>/dev/null || true
    exec 7>&-
fi

if [ "${1:-}" == "--monitor" ]; then
    if ! cron_task; then
        pm_error "本轮后台监控任务未完成"
        exit 1
    fi
elif [ "${1:-}" == "--ipl" ]; then
    echo -e "$UI_DIVIDER"
    echo -e " 当前 TCP 接入"
    echo -e "$UI_DIVIDER"
    _ensure_unique_connection_snapshot || true
    displayed=false
    for p in $(jq -r '.ports | keys[]' "$CONFIG_FILE" | sort -n); do
        ips=$(_sentinel_scan_ips "$p")
        cnt=0; [ -n "$ips" ] && cnt=$(printf '%s\n' "$ips" | grep -c .)
        [ "$displayed" = "true" ] && echo
        printf " 端口 %s · 在线 %s IP\n" "$p" "$cnt"
        if [ -n "$ips" ]; then
            while IFS= read -r ip; do
                [ -n "$ip" ] && printf "   - %s\n" "$ip"
            done <<< "$ips"
        fi
        displayed=true
    done
    [ "$displayed" = "false" ] && echo -e " 暂无监控端口"
    echo -e "$UI_DIVIDER"
elif [ "${1:-}" == "update" ]; then
    update_script
elif [ "${1:-}" == "uninstall" ]; then
    uninstall_script
else
    setup_cron || exit 1
    _IS_MENU_MODE=true
    while true; do show_main_menu; done
fi
