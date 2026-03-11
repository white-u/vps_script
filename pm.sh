#!/bin/bash

# ==============================================================================
# Linux 端口流量管理脚本 (Port Monitor & Shaper)
# 版本: v5.4.0 (IP Sentinel)
# ==============================================================================

# --- 全局配置 ---
SHORTCUT_NAME="pm"
INSTALL_PATH="/usr/local/bin/$SHORTCUT_NAME"
# [注意] 如果您 Fork 了此脚本，请修改下方的更新源地址
DOWNLOAD_URL="https://raw.githubusercontent.com/white-u/vps_script/main/pm.sh"

CONFIG_DIR="/etc/port_monitor"
CONFIG_FILE="$CONFIG_DIR/config.json"
STATE_DIR="$CONFIG_DIR/state"
LOCK_FILE="/var/run/pm.lock"
SCRIPT_VERSION="5.4.0"
# 配置结构版本号 (用于数据迁移)
CURRENT_CONFIG_VERSION=3
# 信号锁文件：当此文件存在时，Cron 暂停运行，防止覆盖用户正在编辑的数据
USER_EDIT_LOCK="/tmp/pm_user_editing"
NFT_TABLE="inet port_monitor"
# TC 默认分类 ID (hex)，不得与任何可监控端口的 hex 值冲突
# 0xfffe = 端口 65534，几乎不会被监控
TC_DEFAULT_CID="fffe"
SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null)

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

# --- 临时资源清理 ---
_CLEANUP_FILES=()
_IS_MENU_MODE=false
_global_cleanup() {
    for f in "${_CLEANUP_FILES[@]+"${_CLEANUP_FILES[@]}"}"; do
        rm -rf "$f" 2>/dev/null
    done
    # 仅菜单模式才删除编辑锁, cron(--monitor) 模式不能删(锁可能属于菜单进程)
    if [ "$_IS_MENU_MODE" == "true" ]; then
        rm -f "$USER_EDIT_LOCK" 2>/dev/null
    fi
}
trap _global_cleanup EXIT INT TERM

# --- 输入清洗 ---
# Windows 终端/SSH 粘贴可能带 \r (CR)，导致正则校验失败或 bc 报错
strip_cr() { echo "${1//$'\r'/}"; }

# --- 端口运行状态 读/写 (零 fork, bash 内置) ---
# 所有运行时变量使用 s_ 前缀, 避免与其他变量冲突
_init_port_state_defaults() {
    s_acc_in=0; s_acc_out=0; s_last_k_in=0; s_last_k_out=0
    s_last_reset_ts=0; s_strike=0; s_is_punished=false; s_punish_end_ts=0
    s_quota_level=0; s_punish_notified=false; s_recover_notified=true
    s_last_alert_ts=0; s_last_alert_ips=""
}

_load_port_state() {
    _init_port_state_defaults
    local sf="$STATE_DIR/${1}.txt"
    [ -f "$sf" ] && . "$sf"
}

_save_port_state() {
    cat > "$STATE_DIR/${1}.txt" << STATEEOF
s_acc_in=$s_acc_in
s_acc_out=$s_acc_out
s_last_k_in=$s_last_k_in
s_last_k_out=$s_last_k_out
s_last_reset_ts=$s_last_reset_ts
s_strike=$s_strike
s_is_punished=$s_is_punished
s_punish_end_ts=$s_punish_end_ts
s_quota_level=$s_quota_level
s_punish_notified=$s_punish_notified
s_recover_notified=$s_recover_notified
s_last_alert_ts=$s_last_alert_ts
s_last_alert_ips=$s_last_alert_ips
STATEEOF
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
    local tmp_dl=$(mktemp /tmp/pm_install.XXXXXX.sh)
    curl -fsSL --max-time 15 "$DOWNLOAD_URL" -o "$tmp_dl" 2>/dev/null
    
    # 验证下载完整性
    if [ -s "$tmp_dl" ]; then
        mv -f "$tmp_dl" "$INSTALL_PATH"
        chmod +x "$INSTALL_PATH"
        echo -e "${GREEN}安装成功! 快捷指令: $SHORTCUT_NAME${PLAIN}"
        echo -e "${GREEN}正在启动管理面板...${PLAIN}"
        sleep 1
        # 移交控制权给安装好的脚本
        exec "$INSTALL_PATH" "$@"
    else
        rm -f "$tmp_dl"
        # 降级策略：本地复制 (仅当本地文件存在且非管道运行时)
        if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
            echo -e "${YELLOW}网络下载失败，尝试本地安装...${PLAIN}"
            cp "$SCRIPT_PATH" "$INSTALL_PATH" && chmod +x "$INSTALL_PATH"
            exec "$INSTALL_PATH" "$@"
        else
            # 如果是 curl | bash 且下载失败，我们依然允许内存中的脚本继续运行
            # 但不会生成快捷指令
            echo -e "${YELLOW}警告: 无法安装快捷指令 (网络问题或管道运行)，将仅在本次会话运行。${PLAIN}"
        fi
    fi
}

get_iface() {
    ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n 1
}

install_deps() {
    # 核心依赖清单 (Alpine 需特判)
    local deps=("nft" "tc" "jq" "bc" "curl" "ss" "numfmt" "flock" "stat")
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
                    apt-get update -q && apt-get install -y -q nftables iproute2 jq bc curl coreutils util-linux ;;
                centos|rhel|almalinux|rocky)
                    yum install -y -q nftables iproute tc jq bc curl coreutils util-linux ;;
                alpine)
                    # Alpine 特别需要 coreutils(stat, numfmt) 和 util-linux(flock)
                    apk add --no-cache nftables iproute2 jq bc curl coreutils util-linux ;;
                *)
                    echo -e "${RED}系统不受支持，请手动安装: ${deps[*]}${PLAIN}" && exit 1 ;;
            esac
        fi
        # 验证关键依赖是否真正可用
        local failed=()
        for dep in "nft" "tc" "jq" "bc"; do
            command -v "$dep" &>/dev/null || failed+=("$dep")
        done
        if [[ ${#failed[@]} -gt 0 ]]; then
            echo -e "${RED}依赖安装失败: ${failed[*]}，请手动安装后重试。${PLAIN}"
            exit 1
        fi
    fi

    # 初始化配置目录与文件
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
    fi
    mkdir -p "$STATE_DIR"
    # 强制完整性检查：如果文件损坏或为空，重置它
    if [ ! -s "$CONFIG_FILE" ] || ! jq empty "$CONFIG_FILE" >/dev/null 2>&1; then
        echo '{"node_id": "'"$(hostname 2>/dev/null || echo unknown)"'", "interface": "'"$(get_iface)"'", "ports": {}, "telegram": {"enable": false, "bot_token": "", "chat_id": "", "api_url": "https://api.telegram.org", "thresholds": [50, 80, 100]}}' > "$CONFIG_FILE"
    fi
    # 确保存在 telegram 字段 (旧版本升级兼容)
    if ! jq -e '.telegram' "$CONFIG_FILE" >/dev/null 2>&1; then
        local tmp=$(mktemp)
        jq '.telegram = {"enable": false, "bot_token": "", "chat_id": "", "api_url": "https://api.telegram.org", "thresholds": [50, 80, 100]}' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
        rm -f "$tmp"
    fi
    # 确保存在 node_id 字段 (旧版本升级兼容)
    if ! jq -e '.node_id' "$CONFIG_FILE" >/dev/null 2>&1; then
        local tmp=$(mktemp)
        jq --arg nid "$(hostname 2>/dev/null || echo unknown)" '.node_id = $nid' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
        rm -f "$tmp"
    fi
    # 确保存在 push 字段 (v4.4+ 云端推送)
    if ! jq -e '.push' "$CONFIG_FILE" >/dev/null 2>&1; then
        local tmp=$(mktemp)
        jq '.push = {"enable": false, "worker_url": "", "secret": "", "node_key": ""}' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
        rm -f "$tmp"
    fi
    # 保护配置文件 (含 bot_token)
    chmod 600 "$CONFIG_FILE"
    
    # 执行数据迁移
    migrate_config
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
            IFS=$'\t' read -r _ai _ao _ki _ko _lrt _sc _ip _pet _ql _pn _rn _lat _laips <<< \
                "$(echo "$tmp_json" | jq -r ".ports[\"$_mp\"] | [
                    ((.stats.acc_in//0)|floor), ((.stats.acc_out//0)|floor),
                    ((.stats.last_kernel_in//0)|floor), ((.stats.last_kernel_out//0)|floor),
                    ((.last_reset_ts//0)|floor),
                    (.dyn_limit.strike_count//0), (.dyn_limit.is_punished//false), (.dyn_limit.punish_end_ts//0),
                    (.notify_state.quota_level//0), (.notify_state.punish_notified//false), (.notify_state.recover_notified//true),
                    (.ip_limit.last_alert_ts//0),
                    ((.ip_limit.last_alert_ips//[]) | join(\",\"))
                ] | @tsv")"
            cat > "$_sf" << MEOF
s_acc_in=${_ai:-0}
s_acc_out=${_ao:-0}
s_last_k_in=${_ki:-0}
s_last_k_out=${_ko:-0}
s_last_reset_ts=${_lrt:-0}
s_strike=${_sc:-0}
s_is_punished=${_ip:-false}
s_punish_end_ts=${_pet:-0}
s_quota_level=${_ql:-0}
s_punish_notified=${_pn:-false}
s_recover_notified=${_rn:-true}
s_last_alert_ts=${_lat:-0}
s_last_alert_ips=${_laips:-}
MEOF
        done
        tmp_json=$(echo "$tmp_json" | jq '.config_version = 3')
        modified=true
    fi
    if [ "$modified" == "true" ]; then
        local tmp_file=$(mktemp)
        printf '%s\n' "$tmp_json" > "$tmp_file"
        safe_write_config_from_file "$tmp_file"
        rm -f "$tmp_file"
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
        nft add set $NFT_TABLE blocked_ports { type inet_service\; }
        # 优先级 -5，确保先计数再通过系统防火墙(UFW等通常是0)
        nft add chain $NFT_TABLE input { type filter hook input priority -5\; }
        nft add chain $NFT_TABLE output { type filter hook output priority -5\; }
        
        # 显式拆分 TCP/UDP，修复部分内核兼容性
        nft add rule $NFT_TABLE input tcp dport @blocked_ports drop
        nft add rule $NFT_TABLE input udp dport @blocked_ports drop
        nft add rule $NFT_TABLE output tcp sport @blocked_ports drop
        nft add rule $NFT_TABLE output udp sport @blocked_ports drop
        return 0
    fi
    return 1
}

init_tc_root() {
    local iface=$(jq -r '.interface' "$CONFIG_FILE")
    [ -z "$iface" ] && iface=$(get_iface)
    
    if [ -z "$iface" ]; then
        echo -e "${RED}[错误] 无法获取网络接口，请检查网络配置。${PLAIN}" >&2
        return 1
    fi
    
    # 初始化 HTB 根队列
    if ! tc qdisc show dev "$iface" | grep -q "htb 1:"; then
        if ! tc qdisc add dev "$iface" root handle 1: htb default $TC_DEFAULT_CID 2>/dev/null; then
            echo -e "${RED}[错误] 无法在 $iface 上创建 TC 队列, 限速功能可能不可用。${PLAIN}" >&2
            return 1
        fi
        # 默认分类 (不限速通道, ID 使用高位值避免与端口 hex 冲突)
        tc class add dev "$iface" parent 1: classid 1:$TC_DEFAULT_CID htb rate 1000mbit
    fi
}

apply_port_rules() {
    local port=$1
    local conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
    local limit_mbps=$(echo "$conf" | jq -r '.limit_mbps // 0')
    local iface=$(jq -r '.interface' "$CONFIG_FILE")
    [ -z "$iface" ] && iface=$(get_iface)
    
    # 检查惩罚状态，优先应用惩罚限速 (从 state 文件读取)
    _load_port_state "$port"
    if [ "$s_is_punished" == "true" ]; then
        limit_mbps=$(echo "$conf" | jq -r '.dyn_limit.punish_mbps // 50')
    fi

    init_nft_table
    init_tc_root

    # [双轨制] TC 使用 Hex 格式 ID，防止 >9999 报错
    local port_hex=$(printf '%x' $port)

    # 1. NFT: 计数器
    nft add counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null
    nft add counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null

    # 2. NFT: 统计 + 打标
    # TCP/UDP 分开判断，防止规则重复堆积
    if ! nft list chain $NFT_TABLE input | grep -qw "cnt_in_${port}"; then
        nft add rule $NFT_TABLE input tcp dport $port counter name "cnt_in_${port}"
        nft add rule $NFT_TABLE input udp dport $port counter name "cnt_in_${port}"
    fi
    
    if ! nft list chain $NFT_TABLE output | grep -qw "cnt_out_${port}"; then
        # 注意: Nftables 使用十进制打标
        nft add rule $NFT_TABLE output tcp sport $port counter name "cnt_out_${port}" meta mark set $port
        nft add rule $NFT_TABLE output udp sport $port counter name "cnt_out_${port}" meta mark set $port
    fi

    # 3. TC: 限速
    # 删除旧规则 (使用 Hex, IPv4 + IPv6)
    tc filter del dev "$iface" parent 1: protocol ip prio 1 handle 0x$port_hex fw 2>/dev/null
    tc filter del dev "$iface" parent 1: protocol ipv6 prio 1 handle 0x$port_hex fw 2>/dev/null
    tc class del dev "$iface" parent 1: classid 1:$port_hex 2>/dev/null

    # 添加新规则 (如果限速不为0)
    if [ "$limit_mbps" != "0" ] && [ -n "$limit_mbps" ]; then
        # 建立类 ID (Hex)
        if tc class add dev "$iface" parent 1: classid 1:$port_hex htb rate "${limit_mbps}mbit" 2>/dev/null; then
            # 建立过滤器 (Hex) 拦截 Nftables 的 Mark (IPv4 + IPv6)
            tc filter add dev "$iface" parent 1: protocol ip prio 1 handle 0x$port_hex fw flowid 1:$port_hex
            tc filter add dev "$iface" parent 1: protocol ipv6 prio 1 handle 0x$port_hex fw flowid 1:$port_hex 2>/dev/null
        else
            echo -e "${YELLOW}[警告] 端口 $port 的 TC 限速规则创建失败 (classid 1:$port_hex)${PLAIN}" >&2
        fi
    fi
}

reload_all_rules() {
    # 彻底销毁旧表再重建，防止已删除端口的规则残留
    nft delete table $NFT_TABLE 2>/dev/null
    init_nft_table
    local ports=$(jq -r '.ports | keys[]' "$CONFIG_FILE")
    for port in $ports; do
        apply_port_rules "$port"
    done
}

# ==============================================================================
# 3. 守护进程 (Writer: Cron)
# ==============================================================================

safe_write_config() {
    local content="$1"
    # 使用 flock 确保原子写入, printf 防止 echo 对 -e/-n 开头内容的误处理
    (
        flock -x 200
        printf '%s\n' "$content" > "$CONFIG_FILE"
    ) 200>"$LOCK_FILE"
}

# 从文件原子写入配置 (避免 ARG_MAX 限制)
safe_write_config_from_file() {
    local src_file="$1"
    (
        flock -x 200
        cat "$src_file" > "$CONFIG_FILE"
    ) 200>"$LOCK_FILE"
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
    
    # 附加备注 + 组名
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

tg_send() {
    local msg="$1"
    [ -z "$msg" ] && return
    local tg_conf=$(jq -r '.telegram // empty' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$tg_conf" ] && return
    local enabled=$(echo "$tg_conf" | jq -r '.enable // false')
    [ "$enabled" != "true" ] && return
    local token=$(echo "$tg_conf" | jq -r '.bot_token // empty')
    local chat_id=$(echo "$tg_conf" | jq -r '.chat_id // empty')
    [ -z "$token" ] || [ -z "$chat_id" ] && return
    local api_url=$(echo "$tg_conf" | jq -r '.api_url // "https://api.telegram.org"')
    curl -sf --max-time 10 "${api_url}/bot${token}/sendMessage" -d chat_id="$chat_id" -d text="$msg" -d parse_mode="Markdown" >/dev/null 2>&1 &
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
        port_info="\`${port}\` (Group: $group_id)"
    fi

    tg_send "${icon} *流量预警*
🏷 标识: *${label}*
🔌 端口: ${port_info}
📊 已用: ${used_fmt} / ${quota_gb}GB (*${percent}%*)
📋 模式: ${mode_str}
⏰ 状态: 已超过 *${threshold}%* 阈值"
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
🏷 标识: *${label}*
🔌 端口: \`${port}\`
📊 流量配额已耗尽，服务已阻断
🔄 重置策略: ${reset_str}"
}

tg_notify_punish() {
    local port=$1 comment=$2 avg_mbps=$3 trigger_mbps=$4 punish_mbps=$5 punish_min=$6 group_id=$7
    local label=$(get_host_label "$comment" "$group_id")
    tg_send "⚡ *动态限速触发*
🏷 标识: *${label}*
🔌 端口: \`${port}\`
📈 平均速率: ${avg_mbps} Mbps (阈值 ${trigger_mbps} Mbps)
📉 已降速至: *${punish_mbps} Mbps*
⏱ 持续时间: ${punish_min} 分钟"
}

tg_notify_recover() {
    local port=$1 comment=$2 group_id=$3
    local label=$(get_host_label "$comment" "$group_id")
    tg_send "✅ *限速已恢复*
🏷 标识: *${label}*
🔌 端口: \`${port}\`
📈 惩罚期结束，已恢复原始速率"
}

tg_notify_reset() {
    local port=$1 comment=$2 quota_gb=$3 group_id=$4
    local label=$(get_host_label "$comment" "$group_id")
    tg_send "🔄 *配额已自动重置*
🏷 标识: *${label}*
🔌 端口: \`${port}\`
📊 新配额: ${quota_gb} GB
⏰ 新周期已开始"
}

tg_notify_report() {
    local host_label=$(get_host_label "")
    local now_str=$(date '+%Y-%m-%d %H:%M')
    local report_lines=""
    
    local ports=$(jq -r '.ports | keys[]' "$CONFIG_FILE" 2>/dev/null | sort -n)
    [ -z "$ports" ] && return
    
    # 临时缓存组流量，避免重复计算
    declare -A group_usage_cache
    declare -A group_quota_cache

    # 第一次遍历：计算组流量
    for port in $ports; do
        local p_conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
        local gid=$(echo "$p_conf" | jq -r '.group_id // empty')
        [ -z "$gid" ] && continue
        
        local mode=$(echo "$p_conf" | jq -r '.quota_mode')
        _load_port_state "$port"
        local quota_gb=$(echo "$p_conf" | jq -r '.quota_gb')
        
        local used=0
        if [ "$mode" == "out_only" ]; then used=$s_acc_out; else used=$((s_acc_in + s_acc_out)); fi
        
        group_usage_cache["$gid"]=$(( ${group_usage_cache["$gid"]:-0} + used ))
        group_quota_cache["$gid"]=$quota_gb
    done

    for port in $ports; do
        local p_conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
        local comment=$(echo "$p_conf" | jq -r '.comment // ""')
        local quota_gb=$(echo "$p_conf" | jq -r '.quota_gb')
        local mode=$(echo "$p_conf" | jq -r '.quota_mode')
        _load_port_state "$port"
        local limit=$(echo "$p_conf" | jq -r '.limit_mbps // 0')
        local gid=$(echo "$p_conf" | jq -r '.group_id // empty')
        
        local display_used=0
        
        # 确定显示用的流量值
        if [ -n "$gid" ]; then
            display_used=${group_usage_cache["$gid"]:-0}
            quota_gb=${group_quota_cache["$gid"]}
        else
            if [ "$mode" == "out_only" ]; then display_used=$s_acc_out; else display_used=$((s_acc_in + s_acc_out)); fi
        fi
        
        local used_fmt=$(fmt_bytes_plain "$display_used")
        local quota_bytes=$((quota_gb * 1073741824))
        local percent=0
        if [ "$quota_bytes" != "0" ] && [ -n "$quota_bytes" ]; then
            percent=$(echo "scale=1; $display_used * 100 / $quota_bytes" | bc 2>/dev/null)
        fi
        [ -z "$percent" ] && percent=0
        
        local status_icon="✅"
        local is_blocked=$(nft -j list set $NFT_TABLE blocked_ports 2>/dev/null | jq -r --argjson p "$port" '[ .nftables[] | select(.set) | .set.elem[]? ] | any(. == $p)')
        if [ "$is_blocked" == "true" ]; then status_icon="🚫";
        elif [ "$s_is_punished" == "true" ]; then status_icon="⚡";
        elif [ $(echo "$percent >= 80" | bc 2>/dev/null) -eq 1 ] 2>/dev/null; then status_icon="⚠️"; fi
        
        local port_title="\`${port}\`"
        if [ -n "$gid" ]; then port_title="${port_title} [G:$gid]"; fi
        if [ -n "$comment" ]; then
            local safe_comment=$(echo "$comment" | sed 's/[_*`\[]/\\&/g')
            port_title="${port_title} ${safe_comment}"
        fi
        
        local speed_info=""
        if [ "$s_is_punished" == "true" ]; then
            local pun_mbps=$(echo "$p_conf" | jq -r '.dyn_limit.punish_mbps // 0')
            speed_info=" ⚡${pun_mbps}M"
        elif [ "$limit" != "0" ] && [ -n "$limit" ]; then
            speed_info=" 🔒${limit}M"
        fi
        
        report_lines="${report_lines}
${status_icon} ${port_title}
   ${used_fmt} / ${quota_gb}GB (${percent}%)${speed_info}"
    done
    
    tg_send "📋 *定时流量报告*
🖥 主机: \`${host_label}\`
⏰ ${now_str}
${report_lines}"
}

push_to_worker() {
    local push_conf=$(jq -r '.push // empty' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$push_conf" ] && return
    local enabled=$(echo "$push_conf" | jq -r '.enable // false')
    [ "$enabled" != "true" ] && return
    local worker_url=$(echo "$push_conf" | jq -r '.worker_url // empty')
    local secret=$(echo "$push_conf" | jq -r '.secret // empty')
    local node_key=$(echo "$push_conf" | jq -r '.node_key // empty')
    [ -z "$worker_url" ] || [ -z "$secret" ] || [ -z "$node_key" ] && return
    local payload=$(jq '{node_id, interface, ports}' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$payload" ] && return
    # 从 state/*.txt 注入实时运行数据到 payload
    local _push_ports=$(echo "$payload" | jq -r '.ports | keys[]')
    for _pp in $_push_ports; do
        _load_port_state "$_pp"
        payload=$(echo "$payload" | jq \
            --arg p "$_pp" --argjson ai "$s_acc_in" --argjson ao "$s_acc_out" \
            --argjson ki "$s_last_k_in" --argjson ko "$s_last_k_out" \
            --argjson ip "$( [ "$s_is_punished" = "true" ] && echo true || echo false )" \
            --argjson sc "$s_strike" --argjson pet "$s_punish_end_ts" \
            --argjson ql "$s_quota_level" \
            '.ports[$p].stats.acc_in = $ai | .ports[$p].stats.acc_out = $ao
             | .ports[$p].stats.last_kernel_in = $ki | .ports[$p].stats.last_kernel_out = $ko
             | .ports[$p].dyn_limit.is_punished = $ip | .ports[$p].dyn_limit.strike_count = $sc
             | .ports[$p].dyn_limit.punish_end_ts = $pet
             | .ports[$p].notify_state.quota_level = $ql')
    done
    local timestamp=$(date +%s)
    local signature=$(printf '%s%s' "$timestamp" "$payload" | openssl dgst -sha256 -hmac "$secret" 2>/dev/null | awk '{print $NF}')
    [ -z "$signature" ] && return
    curl -sf --max-time 10 -X PUT "${worker_url}" -H "Content-Type: application/json" -H "X-Node: ${node_key}" -H "X-Timestamp: ${timestamp}" -H "X-Signature: ${signature}" -d "$payload" >/dev/null 2>&1 &
}

# ==============================================================================
# 2.6 接入监控引擎 (IP Sentinel)
# ==============================================================================

tg_notify_ip_alert() {
    local port=$1 comment=$2 ip_count=$3 max_ips=$4 ip_details=$5 group_id=$6
    local label=$(get_host_label "$comment" "$group_id")
    tg_send "🚨 *异常接入警报*
🏷 标识: *${label}*
🔌 端口: \`${port}\`
📊 状态: 🔴 *${ip_count}* 人在线 (阈值: ${max_ips})

📋 接入详情:
${ip_details}
⚠️ 建议检查密码或重启服务
⏱ $(date '+%Y-%m-%d %H:%M:%S')"
}

# 从 ss 输出中提取端口的独立对端 IP（去重、清洗 IPv4-mapped）
_sentinel_scan_ips() {
    local port=$1
    ss -nt state established "( sport = :$port )" 2>/dev/null | \
        grep -v 'Address:Port' | awk '{print $4}' | \
        rev | cut -d: -f2- | rev | \
        sed 's/^\[//;s/\]$//;s/^::ffff://' | \
        grep -v '^$' | sort -u
}

# 阶段四入口: 遍历启用了 ip_limit 的端口执行检测
check_ip_sentinel() {
    local current_ts=$1
    # [PERF] 一次性读取所有启用了 ip_limit 的端口配置
    local _sentinel_cfg=$(jq -r '
        .ports | to_entries[] | select(.value.ip_limit.enable == true) |
        [.key, (.value.ip_limit.max_ips // 3), (.value.ip_limit.action // "alert"),
         (.value.ip_limit.cooldown_min // 30), (.value.comment // ""),
         (.value.group_id // "")] | @tsv' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$_sentinel_cfg" ] && return

    # 白名单需要单独读 (数组字段无法 @tsv)
    local _s_json=$(cat "$CONFIG_FILE")

    while IFS=$'\t' read -r port max_ips action cooldown_min comment gid; do
        [ -z "$port" ] && continue

        # --- 扫描 ---
        local raw_ips=$(_sentinel_scan_ips "$port")
        [ -z "$raw_ips" ] && continue

        # --- 过滤白名单 ---
        local wl_json=$(echo "$_s_json" | jq -r ".ports[\"$port\"].ip_limit.whitelist // [] | .[]" 2>/dev/null)
        local filtered=""
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            local skip=false
            if [ -n "$wl_json" ]; then
                while IFS= read -r w; do
                    [ "$ip" = "$w" ] && { skip=true; break; }
                done <<< "$wl_json"
            fi
            [ "$skip" = "false" ] && filtered+="${ip}"$'\n'
        done <<< "$raw_ips"
        filtered=$(echo "$filtered" | grep -v '^$')
        local ip_count=$(echo "$filtered" | grep -cve '^\s*$')
        [ "$ip_count" -le "$max_ips" ] && continue

        # --- 冷却: 从 state 文件读取, 有新 IP 则强制报警 ---
        _load_port_state "$port"
        local has_new=false
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            if [ -z "$s_last_alert_ips" ] || [[ ",$s_last_alert_ips," != *",$ip,"* ]]; then
                has_new=true; break
            fi
        done <<< "$filtered"
        if [ "$has_new" = "false" ] && [ $((current_ts - s_last_alert_ts)) -lt $((cooldown_min * 60)) ]; then
            continue
        fi

        # --- 归属地查询 (降级容错) ---
        local details="" idx=1
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            local geo=""
            geo=$(curl -sf --max-time 3 "http://ip-api.com/line/${ip}?fields=country,regionName,isp&lang=zh-CN" 2>/dev/null | tr '\n' ', ' | sed 's/, *$//')
            [ -z "$geo" ] && geo="(查询失败)"
            geo=$(echo "$geo" | sed 's/[_*`\[]/\\&/g')
            details+="${idx}. \`${ip}\` - ${geo}"$'\n'
            idx=$((idx + 1))
            [ "$idx" -gt 15 ] && { details+="... 仅显示前 15 条"$'\n'; break; }
        done <<< "$filtered"

        # --- 通知 ---
        tg_notify_ip_alert "$port" "$comment" "$ip_count" "$max_ips" "$details" "$gid"

        # --- 自动阻断 (可选, 保留连接数最多的前 N 个 IP) ---
        if [ "$action" = "block" ]; then
            local ranked=$(ss -nt state established "( sport = :$port )" 2>/dev/null | \
                grep -v 'Address:Port' | awk '{print $4}' | \
                rev | cut -d: -f2- | rev | \
                sed 's/^\[//;s/\]$//;s/^::ffff://' | \
                grep -v '^$' | sort | uniq -c | sort -rn)
            local kept=0
            while read -r cnt kip; do
                [ -z "$kip" ] && continue
                local in_wl=false
                if [ -n "$wl_json" ]; then
                    while IFS= read -r w; do [ "$kip" = "$w" ] && { in_wl=true; break; }; done <<< "$wl_json"
                fi
                [ "$in_wl" = "true" ] && continue
                kept=$((kept + 1))
                [ "$kept" -gt "$max_ips" ] && ss -K dst "$kip" sport = ":$port" 2>/dev/null
            done <<< "$ranked"
        fi

        # --- 更新状态至 .txt ---
        s_last_alert_ts=$current_ts
        s_last_alert_ips=$(echo "$filtered" | tr '\n' ',' | sed 's/,$//')
        _save_port_state "$port"
    done <<< "$_sentinel_cfg"
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
        echo -e "========================================"
        echo -e " 接入监控 (IP Sentinel) - 端口 $port"
        echo -e "========================================"
        echo -e " 状态:     $([ "$ip_en" = "true" ] && echo "${GREEN}已启用${PLAIN}" || echo "${YELLOW}未启用${PLAIN}")"
        echo -e " 最大人数: $ip_max"
        echo -e " 处理策略: $act_str"
        echo -e " 冷却时间: ${ip_cd} 分钟"
        echo -e " 白名单:   $ip_wl"
        echo -e "========================================"
        echo -e " 1. 启用/禁用"
        echo -e " 2. 设置 最大人数"
        echo -e " 3. 设置 处理策略"
        echo -e " 4. 设置 冷却时间"
        echo -e " 5. 管理 白名单"
        echo -e " 0. 返回"
        echo -e "========================================"
        read -p "> " sc; sc=$(strip_cr "$sc")
        local tmp=$(mktemp)

        case $sc in
            1)  local nv="true"; [ "$ip_en" = "true" ] && nv="false"
                jq --argjson v "$nv" --arg p "$port" '.ports[$p].ip_limit.enable = $v' \
                    "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                echo -e "${GREEN}已$([ "$nv" = "true" ] && echo "启用" || echo "禁用")。${PLAIN}"; sleep 0.5 ;;
            2)  read -p "最大允许独立 IP 数: " val; val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -ge 1 ]; then
                    jq --argjson v "$val" --arg p "$port" '.ports[$p].ip_limit.max_ips = $v' \
                        "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                    echo -e "${GREEN}已更新。${PLAIN}"; sleep 0.5
                else echo -e "${RED}无效输入。${PLAIN}"; sleep 1; fi ;;
            3)  echo -e "1. 仅报警 (alert)  2. 自动阻断 (block)"
                read -p "> " am; am=$(strip_cr "$am")
                local nact="alert"; [ "$am" = "2" ] && nact="block"
                jq --arg v "$nact" --arg p "$port" '.ports[$p].ip_limit.action = $v' \
                    "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                if [ "$nact" = "block" ]; then
                    echo -e "${YELLOW}注意: 自动阻断会切断多余 IP 的连接，存在误杀风险。${PLAIN}"
                    echo -e "${YELLOW}建议先以「仅报警」模式运行一段时间再决定。${PLAIN}"
                fi
                echo -e "${GREEN}已更新。${PLAIN}"; sleep 1 ;;
            4)  read -p "冷却时间 (分钟, IP 不变时抑制重复报警): " val; val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -ge 1 ]; then
                    jq --argjson v "$val" --arg p "$port" '.ports[$p].ip_limit.cooldown_min = $v' \
                        "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                    echo -e "${GREEN}已更新。${PLAIN}"; sleep 0.5
                else echo -e "${RED}无效输入。${PLAIN}"; sleep 1; fi ;;
            5)  echo -e "\n当前白名单: $ip_wl"
                echo -e " 1. 添加 IP  2. 清空白名单  0. 返回"
                read -p "> " wc; wc=$(strip_cr "$wc")
                if [ "$wc" = "1" ]; then
                    read -p "输入 IP 地址 (支持 IPv4/IPv6): " wip; wip=$(strip_cr "$wip")
                    if [ -n "$wip" ]; then
                        jq --arg ip "$wip" --arg p "$port" '.ports[$p].ip_limit.whitelist += [$ip] | .ports[$p].ip_limit.whitelist |= unique' \
                            "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                        echo -e "${GREEN}已添加。${PLAIN}"; sleep 0.5
                    fi
                elif [ "$wc" = "2" ]; then
                    jq --arg p "$port" '.ports[$p].ip_limit.whitelist = []' \
                        "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                    echo -e "${GREEN}已清空。${PLAIN}"; sleep 0.5
                fi ;;
            0)  rm -f "$tmp"; break ;;
        esac
        rm -f "$tmp"
    done
}

CRON_LOCK_FILE="/var/run/pm_cron.lock"

cron_task() {
    exec 9>"$CRON_LOCK_FILE"
    flock -n 9 || exit 0

    if [ -f "$USER_EDIT_LOCK" ]; then
        local lock_age=$(($(date +%s) - $(stat -c %Y "$USER_EDIT_LOCK" 2>/dev/null || echo 0)))
        if [ "$lock_age" -gt 600 ] || [ "$lock_age" -lt 0 ]; then
             rm -f "$USER_EDIT_LOCK"
        else
             exit 0
        fi
    fi

    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

    if ! nft list table $NFT_TABLE &>/dev/null; then reload_all_rules; fi

    local tmp_json=$(cat "$CONFIG_FILE")
    local ports=$(echo "$tmp_json" | jq -r '.ports | keys[]')
    local current_ts=$(date +%s)

    # --- 阶段一：采集数据 + DynQoS (Port Level) ---
    # [PERF] 一次性读取全部 nft 计数器 (零循环内 nft 调用)
    declare -A _ctr_cache
    while IFS=$'\t' read -r _cn _cb; do
        [ -n "$_cn" ] && _ctr_cache["$_cn"]=$_cb
    done <<< "$(nft -j list counters table $NFT_TABLE 2>/dev/null | jq -r '
        [.nftables[] | select(.counter) | .counter] | .[] | "\(.name)\t\(.bytes)"')"

    # [PERF] 一次性读取所有端口的 DynQoS 配置 (仅静态配置字段)
    local _dyn_cfg_data=$(echo "$tmp_json" | jq -r '
        .ports | to_entries[] | select(.value.dyn_limit.enable == true) |
        [.key, .value.dyn_limit.trigger_mbps, .value.dyn_limit.trigger_time,
         .value.dyn_limit.punish_time, .value.dyn_limit.punish_mbps,
         (.value.comment // ""), (.value.group_id // "")] | @tsv')

    # 构建 DynQoS 配置查找表 (避免循环内 jq)
    declare -A _dyn_trigger _dyn_trig_time _dyn_punish_time _dyn_punish_mbps _dyn_comment _dyn_gid
    while IFS=$'\t' read -r _dp _dt _dtt _dpt _dpm _dc _dg; do
        [ -z "$_dp" ] && continue
        _dyn_trigger["$_dp"]=$_dt; _dyn_trig_time["$_dp"]=$_dtt
        _dyn_punish_time["$_dp"]=$_dpt; _dyn_punish_mbps["$_dp"]=$_dpm
        _dyn_comment["$_dp"]=$_dc; _dyn_gid["$_dp"]=$_dg
    done <<< "$_dyn_cfg_data"

    for port in $ports; do
        _load_port_state "$port"

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

        # DynQoS (仅已启用的端口有查找表条目)
        if [ -n "${_dyn_trigger[$port]+x}" ]; then
            local current_mbps=$(echo "scale=2; ($delta_in + $delta_out) * 8 / 60 / 1000000" | bc)
            local rule_changed=false

            if [ "$s_is_punished" == "true" ]; then
                if (( current_ts >= s_punish_end_ts )); then
                    s_is_punished=false; s_strike=0
                    if [ "$s_recover_notified" != "true" ]; then
                        s_recover_notified=true; s_punish_notified=false
                        tg_notify_recover "$port" "${_dyn_comment[$port]}" "${_dyn_gid[$port]}"
                    fi
                    rule_changed=true
                fi
            else
                if [ $(echo "$current_mbps > ${_dyn_trigger[$port]}" | bc) -eq 1 ]; then
                    s_strike=$((s_strike + 1))
                    if (( s_strike >= ${_dyn_trig_time[$port]} )); then
                        s_is_punished=true
                        s_punish_end_ts=$((current_ts + ${_dyn_punish_time[$port]} * 60))
                        if [ "$s_punish_notified" != "true" ]; then
                            s_punish_notified=true; s_recover_notified=false
                            tg_notify_punish "$port" "${_dyn_comment[$port]}" "$current_mbps" "${_dyn_trigger[$port]}" "${_dyn_punish_mbps[$port]}" "${_dyn_punish_time[$port]}" "${_dyn_gid[$port]}"
                        fi
                        rule_changed=true
                    fi
                else
                    (( s_strike > 0 )) && s_strike=0
                fi
            fi

            if [ "$rule_changed" == "true" ]; then
                _save_port_state "$port"
                apply_port_rules "$port"
            fi
        fi

        _save_port_state "$port"
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
    local thresholds=$(jq -r '.telegram.thresholds // [50,80,100] | .[]' "$CONFIG_FILE" 2>/dev/null)
    # [PERF] 一次性读取所有端口的静态配置
    local _p3_cfg=$(echo "$tmp_json" | jq -r '
        .ports | to_entries[] |
        [.key, .value.quota_gb, .value.quota_mode, (.value.group_id // ""),
         (.value.reset_day // 0), (.value.comment // "")] | @tsv')

    while IFS=$'\t' read -r port quota_gb mode gid reset_day p3_comment; do
        [ -z "$port" ] && continue
        _load_port_state "$port"

        # 确定用于判断的流量值
        local check_usage=0
        if [ -n "$gid" ] && [ "$gid" != "null" ]; then
            check_usage=${group_usage["$gid"]:-0}
        else
            if [ "$mode" == "out_only" ]; then check_usage=$s_acc_out; else check_usage=$((s_acc_in + s_acc_out)); fi
        fi

        # 自动重置判断
        if [ "$reset_day" -gt 0 ] 2>/dev/null && [ "$reset_day" -le 31 ] 2>/dev/null; then
            local days_in_month=$(date -d "$(date +%Y-%m-01) +1 month -1 day" +%-d 2>/dev/null)
            [ -z "$days_in_month" ] && days_in_month=28
            local effective_day=$reset_day
            [ "$effective_day" -gt "$days_in_month" ] && effective_day=$days_in_month
            local reset_date=$(printf "%s-%02d 00:00:00" "$(date +%Y-%m)" "$effective_day")
            local reset_ts=$(date -d "$reset_date" +%s 2>/dev/null || echo 0)

            if [ "$current_ts" -ge "$reset_ts" ] && [ "$s_last_reset_ts" -lt "$reset_ts" ]; then
                # 重置: 清零流量, 记录当前内核计数器作为新基准
                s_acc_in=0; s_acc_out=0
                s_last_k_in=${_ctr_cache["cnt_in_${port}"]:-0}
                s_last_k_out=${_ctr_cache["cnt_out_${port}"]:-0}
                s_last_reset_ts=$current_ts
                s_is_punished=false; s_strike=0
                s_quota_level=0; s_punish_notified=false; s_recover_notified=true
                _save_port_state "$port"

                nft delete element $NFT_TABLE blocked_ports \{ $port \} 2>/dev/null
                apply_port_rules "$port"
                tg_notify_reset "$port" "$p3_comment" "$quota_gb" "$gid"

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
                nft add element $NFT_TABLE blocked_ports \{ $port \}
                blocked_ports_str="${blocked_ports_str}${port} "
            fi
        else
            if [ "$is_blocked_nft" == "true" ]; then
                nft delete element $NFT_TABLE blocked_ports \{ $port \}
                blocked_ports_str="${blocked_ports_str/ $port / }"
            fi
        fi

        # 阈值通知
        if [ "$quota_bytes" != "0" ] && [ -n "$quota_bytes" ]; then
            local percent=$(echo "scale=1; $check_usage * 100 / $quota_bytes" | bc 2>/dev/null)
            [ -z "$percent" ] && percent=0
            local percent_int=${percent%.*}
            [ -z "$percent_int" ] && percent_int=0

            local new_level=$s_quota_level
            for thr in $(echo "$thresholds" | sort -rn); do
                [ -z "$thr" ] && continue
                if (( percent_int >= thr )) && (( s_quota_level < thr )); then
                    new_level=$thr; break
                fi
            done

            if (( new_level > s_quota_level )); then
                local used_fmt=$(fmt_bytes_plain "$check_usage")
                tg_notify_quota "$port" "$p3_comment" "$percent" "$used_fmt" "$quota_gb" "$mode" "$new_level" "$gid"
                if (( new_level >= 100 )); then
                    tg_notify_blocked "$port" "$p3_comment" "$quota_gb" "$reset_day" "$gid"
                fi
                s_quota_level=$new_level
                _save_port_state "$port"
            fi
        fi
    done <<< "$_p3_cfg"

    # 周期报告 & 推送 (不变)
    local report_hours=$(jq -r '.telegram.report_interval_hours // 0' "$CONFIG_FILE" 2>/dev/null)
    if [ "$report_hours" -gt 0 ] 2>/dev/null; then
        local last_report_ts=$(jq -r '.telegram.last_report_ts // 0' "$CONFIG_FILE" 2>/dev/null)
        local next_report_ts=$((last_report_ts + report_hours * 3600))
        if [ "$current_ts" -ge "$next_report_ts" ]; then
            tg_notify_report
            local _tmp_rpt=$(mktemp)
            jq --argjson ts "$current_ts" '.telegram.last_report_ts = $ts' "$CONFIG_FILE" > "$_tmp_rpt" && safe_write_config_from_file "$_tmp_rpt"
            rm -f "$_tmp_rpt"
        fi
    fi

    # --- 阶段四: 接入 IP 监控 (Sentinel) ---
    check_ip_sentinel "$current_ts"

    push_to_worker
}

setup_cron() {
    if ! crontab -l 2>/dev/null | grep -q "$INSTALL_PATH --monitor"; then
        (crontab -l 2>/dev/null; echo "* * * * * $INSTALL_PATH --monitor") | crontab -
    fi
}

# ==============================================================================
# 4. UI 模块 (Reader)
# ==============================================================================

start_edit_lock() { touch "$USER_EDIT_LOCK"; }
stop_edit_lock() { rm -f "$USER_EDIT_LOCK"; }

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

show_main_menu() {
    start_edit_lock 

    clear
    echo -e "========================================================================================="
    echo -e "   Linux 端口流量管理 (v${SCRIPT_VERSION}) - 后台每分钟刷新"
    echo -e "========================================================================================="
    printf " %-4s %-12s %-10s %-30s %-15s %-15s\n" "ID" "端口" "模式" "已用流量 / 总配额" "出站限速" "备注"
    echo -e "-----------------------------------------------------------------------------------------"

    local port_list=()
    local i=1
    local ports=$(jq -r '.ports | keys[]' "$CONFIG_FILE" | sort -n)

    for port in $ports; do
        local conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
        local mode=$(echo "$conf" | jq -r '.quota_mode')
        local limit=$(echo "$conf" | jq -r '.limit_mbps')
        local comment=$(echo "$conf" | jq -r '.comment')
        local quota=$(echo "$conf" | jq -r '.quota_gb')
        local gid=$(echo "$conf" | jq -r '.group_id // empty')
        
        # 从 state 文件读取运行数据
        _load_port_state "$port"
        
        local mode_str="[双向]"
        local total_used=0
        if [ "$mode" == "out_only" ]; then
            mode_str="[仅出站]"
            total_used=$s_acc_out
        else
            total_used=$((s_acc_in + s_acc_out))
        fi
        
        local status_clean=""
        local is_blocked=false
        
        if nft -j list set $NFT_TABLE blocked_ports 2>/dev/null | jq -r --argjson p "$port" '[ .nftables[] | select(.set) | .set.elem[]? ] | any(. == $p)' | grep -q "true"; then
            status_clean="[已阻断]"
            is_blocked=true
        else
            status_clean="$(fmt_bytes $total_used)"
        fi
        
        local reset_day=$(echo "$conf" | jq -r '.reset_day // 0')
        local quota_str="${status_clean} / ${quota} GB"
        if [ "$reset_day" -gt 0 ] 2>/dev/null; then quota_str="${quota_str} [R${reset_day}]"; fi
        
        local limit_str=""
        if [ "$s_is_punished" == "true" ]; then
            local punish_val=$(echo "$conf" | jq -r '.dyn_limit.punish_mbps')
            limit_str="${RED}${punish_val}Mbps(惩罚中)${PLAIN}"
        else
            if [ "$limit" == "0" ]; then limit_str="无限制"; else limit_str="${limit} Mbps"; fi
        fi
        
        # 显示组ID
        if [ -n "$gid" ] && [ "$gid" != "null" ]; then
            mode_str="${mode_str} ${BLUE}[${gid}]${PLAIN}"
        fi

        if [ "$is_blocked" == true ]; then
            echo -e " ${RED}[${i}]  ${port}         [已阻断]  配额用尽，端口已封禁${PLAIN}"
        else
            printf " [%d]  %-12s %-20b %-30s %-24b %-15s\n" $i "$port" "$mode_str" "$quota_str" "$limit_str" "$comment"
        fi
        
        port_list[$i]=$port
        i=$((i + 1))
    done
    echo -e "-----------------------------------------------------------------------------------------"
    echo -e " 说明: [G:xxx]表示组。流量每分钟更新。当前正在编辑中，后台刷新已暂停。\n"

    local tg_status="${YELLOW}⚪ 未配置${PLAIN}"
    local tg_enabled=$(jq -r '.telegram.enable // false' "$CONFIG_FILE" 2>/dev/null)
    [ "$tg_enabled" == "true" ] && tg_status="${GREEN}✅ 已开启${PLAIN}"

    local push_status="${YELLOW}⚪ 未配置${PLAIN}"
    local push_enabled=$(jq -r '.push.enable // false' "$CONFIG_FILE" 2>/dev/null)
    [ "$push_enabled" == "true" ] && push_status="${GREEN}✅ 已开启${PLAIN}"

    echo -e " 1. 添加 监控端口 (服务扫描)"
    echo -e " 2. 配置 端口 (修改/分组/QoS/重置)"
    echo -e " 3. 删除 监控端口"
    echo -e " 4. 通知设置 (Telegram) $tg_status"
    echo -e " 5. 云端推送 (Cloudflare) $push_status"
    echo -e " 6. 更新 脚本"
    echo -e " 7. ${RED}卸载 脚本${PLAIN}"
    echo -e " 0. 退出"
    echo -e "========================================================================================="
    read -p "请输入选项: " choice
    choice=$(strip_cr "$choice")
    
    case $choice in
        1) add_port_flow ;;
        2) config_port_menu "${port_list[@]}" ;;
        3) delete_port_flow "${port_list[@]}" ;;
        4) configure_telegram ;;
        5) configure_push ;;
        6) update_script ;;
        7) uninstall_script ;;
        0) stop_edit_lock; exit 0 ;;
        *) ;; 
    esac
}

add_port_flow() {
    local scan_data=$(scan_active_services)
    echo -e "\n======================================================================"
    echo -e "   系统当前活跃端口 (TCP/UDP)"
    echo -e "======================================================================"
    printf " %-4s %-15s %-25s %-10s\n" "ID" "端口/协议" "进程名称" "状态"
    echo -e "----------------------------------------------------------------------"
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
            echo -e " [${idx}]  ${p_port}/${p_proto}\t\t${p_proc}\t\t${YELLOW}[已监控]${PLAIN}"
        else
            printf " [%d]  %-15s %-25s %-10s\n" $idx "${p_port}/${p_proto}" "$p_proc" "[可选]"
        fi
        map_ports[$idx]=$p_port
        idx=$((idx + 1))
    done <<< "$scan_data"
    echo -e "----------------------------------------------------------------------"
    echo -e " [M]   手动输入端口号"
    echo -e " [0]   返回主菜单"
    echo -e "======================================================================"
    read -p "请输入选项: " sel
    sel=$(strip_cr "$sel")
    local target_port=""
    if [ "$sel" == "0" ]; then return; fi
    if [[ "$sel" =~ ^[0-9]+$ ]] && [ -n "${map_ports[$sel]}" ]; then
        target_port=${map_ports[$sel]}
        if jq -e ".ports[\"$target_port\"]" "$CONFIG_FILE" >/dev/null; then
            echo -e "${RED}该端口已在监控列表中!${PLAIN}"; sleep 2; return
        fi
    elif [ "$sel" == "m" ] || [ "$sel" == "M" ]; then
        read -p "请输入端口号: " target_port
        target_port=$(strip_cr "$target_port")
    else
        return
    fi
    if [[ ! "$target_port" =~ ^[0-9]+$ ]] || [ "$target_port" -lt 1 ] || [ "$target_port" -gt 65535 ]; then
        echo -e "${RED}无效端口${PLAIN}"; sleep 1; return
    fi
    local reserved_port=$((16#$TC_DEFAULT_CID))
    if [ "$target_port" -eq "$reserved_port" ]; then
        echo -e "${RED}端口 $reserved_port 为系统保留端口，无法监控!${PLAIN}"; sleep 2; return
    fi
    
    echo -e "\n>> 正在配置端口: $target_port"
    
    read -p "月流量配额 (纯数字, GB): " quota
    quota=$(strip_cr "$quota")
    if [[ ! "$quota" =~ ^[0-9]+$ ]] || [ "$quota" -eq 0 ]; then
        echo -e "${RED}错误: 配额必须是大于0的纯整数!${PLAIN}"; sleep 2; return
    fi

    echo "计费模式: 1.双向计费(默认)  2.仅出站计费"
    read -p "选择模式 [1/2]: " mode_idx
    mode_idx=$(strip_cr "$mode_idx")
    local mode="in_out"
    [ "$mode_idx" == "2" ] && mode="out_only"

    read -p "出站限速 (纯数字, Mbps, 0为不限速): " limit
    limit=$(strip_cr "$limit")
    if [[ ! "$limit" =~ ^[0-9]+$ ]]; then
        if [ -z "$limit" ]; then limit=0; else
             echo -e "${RED}错误: 限速必须是纯整数!${PLAIN}"; sleep 2; return
        fi
    fi
    [ -z "$limit" ] && limit=0

    read -p "每月自动重置日 (1-31, 0为不自动重置): " reset_day
    reset_day=$(strip_cr "$reset_day")
    if [[ ! "$reset_day" =~ ^[0-9]+$ ]]; then reset_day=0; fi
    if [ "$reset_day" -gt 31 ]; then echo -e "${RED}错误!${PLAIN}"; sleep 2; return; fi

    read -p "备注信息: " comment
    comment=$(strip_cr "$comment")

    local tmp=$(mktemp)
    if jq --argjson q "$quota" --arg m "$mode" --argjson l "$limit" --argjson rd "$reset_day" \
          --arg c "$comment" --arg p "$target_port" \
       '.ports[$p] = {
        "quota_gb": $q, 
        "quota_mode": $m, 
        "limit_mbps": $l, 
        "reset_day": $rd,
        "comment": $c, 
        "group_id": "",
        "dyn_limit": {"enable": false},
        "ip_limit": {"enable": false, "max_ips": 3, "action": "alert", "cooldown_min": 30, "whitelist": []}
    }' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
        rm -f "$tmp"
        apply_port_rules "$target_port"
        # 创建初始 state 文件
        _init_port_state_defaults
        s_last_reset_ts=$(date +%s)
        _save_port_state "$target_port"
        echo -e "${GREEN}添加成功!${PLAIN}"; sleep 1; return
    else
        rm -f "$tmp"
        echo -e "${RED}写入配置失败!${PLAIN}"; sleep 2; return
    fi
}

config_port_menu() {
    local arr=("$@")
    echo -e "\n请输入要配置的端口 ID (查看上方列表): "
    read -p "ID > " id
    id=$(strip_cr "$id")
    if [[ ! "$id" =~ ^[0-9]+$ ]] || [ "$id" -le 0 ]; then return; fi
    local port=${arr[$((id-1))]}
    if [ -z "$port" ]; then return; fi
    
    while true; do
        local conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
        local comment=$(echo "$conf" | jq -r '.comment')
        local quota=$(echo "$conf" | jq -r '.quota_gb')
        local mode=$(echo "$conf" | jq -r '.quota_mode')
        local limit=$(echo "$conf" | jq -r '.limit_mbps')
        local gid=$(echo "$conf" | jq -r '.group_id // empty')
        [ -z "$gid" ] && gid="${YELLOW}无 (独立)${PLAIN}"
        
        local dyn_conf=$(echo "$conf" | jq '.dyn_limit')
        local dyn_enable=$(echo "$dyn_conf" | jq -r '.enable // false')
        local reset_day=$(echo "$conf" | jq -r '.reset_day // 0')
        
        clear
        echo -e "========================================"
        echo -e " 当前配置: [$id]  $port  $comment"
        echo -e "========================================"
        echo -e " 流量配额: $quota GB"
        echo -e " 流量分组: $gid"
        echo -e " 计费模式: $([ "$mode" == "out_only" ] && echo "仅出站" || echo "双向")"
        echo -e " 基础限速: $([ "$limit" == "0" ] && echo "无限制" || echo "$limit Mbps")"
        if [ "$reset_day" -gt 0 ] 2>/dev/null; then echo -e " 自动重置: 每月 ${GREEN}${reset_day}${PLAIN} 日"; else echo -e " 自动重置: ${YELLOW}未设置${PLAIN}"; fi
        echo -e "========================================"
        echo -e " 1. 修改 流量配额"
        echo -e " 2. 修改 计费模式"
        echo -e " 3. 修改 基础出站限速"
        echo -e " 4. 配置 动态突发限制 (QoS)"
        echo -e " 5. 修改 备注信息"
        echo -e " 6. 重置 统计数据 (清零)"
        echo -e " 7. 修改 自动重置日"
        echo -e " 8. 设置/修改 分组 ID (Group)"
        echo -e " 9. 接入监控 (IP Sentinel)"
        echo -e " 0. 返回主菜单"
        echo -e "========================================"
        read -p "请输入选项: " sub_choice
        sub_choice=$(strip_cr "$sub_choice")
        
        local tmp=$(mktemp)
        local success=false

        case $sub_choice in
            1) 
                read -p "新配额 (纯数字, GB): " val
                val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -gt 0 ]; then
                    if jq --argjson v "$val" --arg p "$port" '.ports[$p].quota_gb = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then 
                        success=true
                        # [Sync Fix] 同步配额给同组端口
                        local gid=$(jq -r --arg p "$port" '.ports[$p].group_id // empty' "$CONFIG_FILE")
                        if [ -n "$gid" ] && [ "$gid" != "null" ]; then
                            local tmp_sync=$(mktemp)
                            if jq --arg g "$gid" --argjson v "$val" '
                                .ports |= with_entries(if .value.group_id == $g then .value.quota_gb = $v else . end)
                            ' "$CONFIG_FILE" > "$tmp_sync" && safe_write_config_from_file "$tmp_sync"; then
                                echo -e "${GREEN}已同步配额到组 [${gid}] 的所有端口。${PLAIN}"
                            fi
                            rm -f "$tmp_sync"
                        fi
                    fi
                else
                    echo -e "${RED}错误: 必须输入大于0的纯整数!${PLAIN}"; sleep 1
                fi 
                ;;
            2) 
                read -p "模式 (1.双向 2.仅出站): " m
                m=$(strip_cr "$m")
                local nm="in_out"; [ "$m" == "2" ] && nm="out_only"
                if jq --arg v "$nm" --arg p "$port" '.ports[$p].quota_mode = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then success=true; fi
                ;;
            3) 
                read -p "新限速 (纯数字, Mbps): " val
                val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]]; then
                    if jq --argjson v "$val" --arg p "$port" '.ports[$p].limit_mbps = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then apply_port_rules "$port"; success=true; fi
                fi
                ;;
            4) configure_dyn_qos "$port" ;;
            5) 
                read -p "新备注: " val
                val=$(strip_cr "$val")
                if jq --arg v "$val" --arg p "$port" '.ports[$p].comment = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then success=true; fi
                ;;
            6) 
                read -p "确定清零吗? [y/N]: " confirm
                confirm=$(strip_cr "$confirm")
                if [[ "$confirm" == "y" ]]; then
                   local k_in=$(nft -j list counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null | jq -r '[ .nftables[] | select(.counter) | .counter.bytes ] | .[0] // 0')
                   local k_out=$(nft -j list counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null | jq -r '[ .nftables[] | select(.counter) | .counter.bytes ] | .[0] // 0')
                   _load_port_state "$port"
                   s_acc_in=0; s_acc_out=0; s_last_k_in=$k_in; s_last_k_out=$k_out; s_quota_level=0
                   _save_port_state "$port"
                   nft delete element $NFT_TABLE blocked_ports \{ $port \} 2>/dev/null
                   echo -e "${GREEN}已重置。${PLAIN}"; sleep 1
                fi 
                ;;
            7) 
                read -p "自动重置日 (1-31, 0为关闭): " val
                val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -le 31 ]; then
                    if jq --argjson v "$val" --arg p "$port" '.ports[$p].reset_day = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then 
                        success=true
                        # [Sync Fix] 同步重置日给同组端口
                        local gid=$(jq -r --arg p "$port" '.ports[$p].group_id // empty' "$CONFIG_FILE")
                        if [ -n "$gid" ] && [ "$gid" != "null" ]; then
                            local tmp_sync=$(mktemp)
                            if jq --arg g "$gid" --argjson v "$val" '
                                .ports |= with_entries(if .value.group_id == $g then .value.reset_day = $v else . end)
                            ' "$CONFIG_FILE" > "$tmp_sync" && safe_write_config_from_file "$tmp_sync"; then
                                echo -e "${GREEN}已同步重置日到组 [${gid}] 的所有端口。${PLAIN}"
                            fi
                            rm -f "$tmp_sync"
                        fi
                    fi
                else
                    echo -e "${RED}错误: 必须输入 0-31 的整数!${PLAIN}"; sleep 1
                fi
                ;;
            8)
                # [优化] 自动列出已有分组供选择
                echo -e "\n--- 设置分组 (Group) ---"
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
                    echo -e " ------------------------"
                fi
                
                read -p "请输入分组 ID (输入新名称新建，或输入序号选择，留空清除): " input_val
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
                
                # 1. 先更新当前端口的 group_id
                if jq --arg v "$val" --arg p "$port" '.ports[$p].group_id = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                    echo -e "${GREEN}分组 ID 已更新。${PLAIN}"
                    
                    # 2. 强制同步 (如果加入了有效组)
                    if [ -n "$val" ]; then
                        local template_json=$(jq -c --arg g "$val" --arg p "$port" '.ports | to_entries[] | select(.value.group_id == $g and .key != $p) | .value' "$CONFIG_FILE" | head -1)
                        
                        if [ -n "$template_json" ] && echo "$template_json" | jq -e '.quota_gb' >/dev/null 2>&1; then
                            local t_quota=$(echo "$template_json" | jq -r '.quota_gb')
                            local t_reset=$(echo "$template_json" | jq -r '.reset_day // 0')
                            
                            if [ -n "$t_quota" ] && [ "$t_quota" != "null" ]; then
                                echo -e "${YELLOW}检测到同组现有配置: 配额=${t_quota}GB, 重置日=${t_reset}号${PLAIN}"
                                echo -e "${YELLOW}正在强制同步当前端口至该配置...${PLAIN}"
                                
                                local tmp2=$(mktemp)
                                if jq --argjson q "$t_quota" --argjson r "$t_reset" --arg p "$port" \
                                   '.ports[$p].quota_gb = $q | .ports[$p].reset_day = $r' \
                                   "$CONFIG_FILE" > "$tmp2" && safe_write_config_from_file "$tmp2"; then
                                    echo -e "${GREEN}同步完成。${PLAIN}"
                                fi
                                rm -f "$tmp2"
                            fi
                        fi
                    fi
                    success=true
                else
                    echo -e "${RED}写入失败。${PLAIN}"
                fi
                ;;
            9) rm -f "$tmp"; configure_ip_sentinel "$port" ;;
            0) rm -f "$tmp"; break ;;
        esac
        
        if [ "$success" == "true" ]; then echo -e "${GREEN}配置已更新。${PLAIN}"; sleep 0.5; fi
        rm -f "$tmp"
    done
}

# ==============================================================================
# 4.5 辅助配置函数
# ==============================================================================

configure_dyn_qos() {
    local port=$1
    local conf=$(jq ".ports[\"$port\"].dyn_limit // {}" "$CONFIG_FILE")
    local d_en=$(echo "$conf" | jq -r '.enable // false')
    local d_trigger=$(echo "$conf" | jq -r '.trigger_mbps // "-"')
    local d_trig_t=$(echo "$conf" | jq -r '.trigger_time // "-"')
    local d_pun_m=$(echo "$conf" | jq -r '.punish_mbps // "-"')
    local d_pun_t=$(echo "$conf" | jq -r '.punish_time // "-"')
    # 惩罚状态从 state 文件读取 (实时)
    _load_port_state "$port"
    local d_punished=$s_is_punished

    echo -e "\n========================================"
    echo -e " 动态突发限制 (QoS) - 端口 $port"
    echo -e "========================================"
    echo -e " 状态:     $([ "$d_en" == "true" ] && echo "${GREEN}已启用${PLAIN}" || echo "${YELLOW}未启用${PLAIN}")"
    if [ "$d_en" == "true" ]; then
        echo -e " 触发阈值: ${d_trigger} Mbps"
        echo -e " 触发时长: ${d_trig_t} 分钟"
        echo -e " 惩罚限速: ${d_pun_m} Mbps"
        echo -e " 惩罚时长: ${d_pun_t} 分钟"
        echo -e " 惩罚中:   $([ "$d_punished" == "true" ] && echo "${RED}是${PLAIN}" || echo "否")"
    fi
    echo -e "========================================"
    echo -e " 1. 启用 (配置参数)"
    echo -e " 2. 禁用"
    echo -e " 0. 取消"
    echo -e "========================================"
    read -p "> " s; s=$(strip_cr "$s")
    local tmp=$(mktemp)

    if [ "$s" == "2" ]; then
        if jq --arg p "$port" '.ports[$p].dyn_limit.enable=false' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
            # 同步清除 state 中的惩罚状态
            _load_port_state "$port"
            s_is_punished=false; s_strike=0; s_punish_end_ts=0
            _save_port_state "$port"
            apply_port_rules "$port"
            echo -e "${GREEN}已禁用动态限速。${PLAIN}"; sleep 0.5
        fi
    elif [ "$s" == "1" ]; then
        read -p "触发阈值 (Mbps, 超过此速率开始计数): " tm; tm=$(strip_cr "$tm")
        read -p "触发时长 (分钟, 连续超标多久触发惩罚): " tt; tt=$(strip_cr "$tt")
        read -p "惩罚限速 (Mbps, 触发后降速到): " pm; pm=$(strip_cr "$pm")
        read -p "惩罚时长 (分钟, 降速持续多久): " pt; pt=$(strip_cr "$pt")
        if [[ "$tm" =~ ^[0-9]+$ ]] && [[ "$tt" =~ ^[0-9]+$ ]] && [[ "$pm" =~ ^[0-9]+$ ]] && [[ "$pt" =~ ^[0-9]+$ ]]; then
            if jq --argjson tm "$tm" --argjson tt "$tt" --argjson pm "$pm" --argjson pt "$pt" --arg p "$port" \
                '.ports[$p].dyn_limit={enable:true,trigger_mbps:$tm,trigger_time:$tt,punish_mbps:$pm,punish_time:$pt}' \
                "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                # 同步重置 state 文件中的 DynQoS 运行状态
                _load_port_state "$port"
                s_strike=0; s_is_punished=false; s_punish_end_ts=0; s_punish_notified=false
                _save_port_state "$port"
                echo -e "${GREEN}动态限速已启用。${PLAIN}"; sleep 0.5
            fi
        else
            echo -e "${RED}错误: 所有参数必须为纯整数!${PLAIN}"; sleep 1
        fi
    fi
    rm -f "$tmp"
}

configure_telegram() {
    while true; do
        local tg=$(jq '.telegram' "$CONFIG_FILE")
        local t_enable=$(echo "$tg" | jq -r '.enable // false')
        local t_token=$(echo "$tg" | jq -r '.bot_token // ""')
        local t_chatid=$(echo "$tg" | jq -r '.chat_id // ""')
        local t_api=$(echo "$tg" | jq -r '.api_url // "https://api.telegram.org"')
        local t_thr=$(echo "$tg" | jq -r '.thresholds // [50,80,100] | map(tostring) | join(", ")')
        local t_rpt=$(echo "$tg" | jq -r '.report_interval_hours // 0')

        local status_str="${YELLOW}⚪ 未启用${PLAIN}"
        [ "$t_enable" == "true" ] && status_str="${GREEN}✅ 已启用${PLAIN}"
        local token_str="${YELLOW}未配置${PLAIN}"
        [ -n "$t_token" ] && [ "$t_token" != "" ] && token_str="${GREEN}已配置${PLAIN} (${t_token:0:8}...)"
        local chatid_str="${YELLOW}未配置${PLAIN}"
        [ -n "$t_chatid" ] && [ "$t_chatid" != "" ] && chatid_str="${GREEN}${t_chatid}${PLAIN}"
        local rpt_str="${YELLOW}未开启${PLAIN}"
        [ "$t_rpt" -gt 0 ] 2>/dev/null && rpt_str="${GREEN}每 ${t_rpt} 小时${PLAIN}"

        clear
        echo -e "========================================"
        echo -e "   Telegram 通知配置"
        echo -e "========================================"
        echo -e " 状态:   $status_str"
        echo -e " Token:  $token_str"
        echo -e " ChatID: $chatid_str"
        echo -e " API:    $t_api"
        echo -e " 阈值:   ${t_thr} (%)"
        echo -e " 定时报告: $rpt_str"
        echo -e "========================================"
        echo -e " 1. 配置 Bot Token"
        echo -e " 2. 配置 Chat ID"
        echo -e " 3. 发送测试消息"
        echo -e " 4. 开启/关闭 通知"
        echo -e " 5. 修改 通知阈值"
        echo -e " 6. 修改 API 地址 (国内反代)"
        echo -e " 7. 配置 定时流量报告"
        echo -e " 0. 返回主菜单"
        echo -e "========================================"
        read -p "请输入选项: " c
        c=$(strip_cr "$c")
        local tmp=$(mktemp)

        case $c in
            1)
                read -p "请输入 Bot Token: " val; val=$(strip_cr "$val")
                if [ -n "$val" ]; then
                    jq --arg v "$val" '.telegram.bot_token=$v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                    echo -e "${GREEN}Token 已更新。${PLAIN}"; sleep 0.5
                fi ;;
            2)
                read -p "请输入 Chat ID: " val; val=$(strip_cr "$val")
                if [ -n "$val" ]; then
                    jq --arg v "$val" '.telegram.chat_id=$v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                    echo -e "${GREEN}Chat ID 已更新。${PLAIN}"; sleep 0.5
                fi ;;
            3)
                echo -e "${YELLOW}正在发送测试消息...${PLAIN}"
                local tk=$(jq -r '.telegram.bot_token' "$CONFIG_FILE")
                local ci=$(jq -r '.telegram.chat_id' "$CONFIG_FILE")
                local au=$(jq -r '.telegram.api_url // "https://api.telegram.org"' "$CONFIG_FILE")
                if [ -z "$tk" ] || [ -z "$ci" ]; then
                    echo -e "${RED}请先配置 Token 和 Chat ID!${PLAIN}"; sleep 1
                else
                    local nid=$(jq -r '.node_id // "unknown"' "$CONFIG_FILE")
                    local result=$(curl -s --max-time 10 "${au}/bot${tk}/sendMessage" \
                        -d chat_id="$ci" -d text="✅ PM 测试消息 (节点: ${nid})" -d parse_mode="Markdown")
                    if echo "$result" | jq -e '.ok == true' >/dev/null 2>&1; then
                        echo -e "${GREEN}发送成功!${PLAIN}"
                    else
                        local err=$(echo "$result" | jq -r '.description // "未知错误"' 2>/dev/null)
                        echo -e "${RED}发送失败: ${err}${PLAIN}"
                    fi
                    sleep 2
                fi ;;
            4)
                local nv="true"; [ "$t_enable" == "true" ] && nv="false"
                jq --argjson v "$nv" '.telegram.enable=$v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                echo -e "${GREEN}已$([ "$nv" == "true" ] && echo "开启" || echo "关闭")。${PLAIN}"; sleep 0.5 ;;
            5)
                echo -e "当前阈值: ${t_thr} (%)"
                read -p "请输入新阈值 (用逗号分隔, 如 50,80,100): " val; val=$(strip_cr "$val")
                if [ -n "$val" ]; then
                    # 解析逗号分隔为 JSON 数组
                    local arr_json=$(echo "$val" | tr ',' '\n' | grep -E '^[0-9]+$' | jq -s '.')
                    if [ -n "$arr_json" ] && [ "$arr_json" != "[]" ]; then
                        jq --argjson v "$arr_json" '.telegram.thresholds=$v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                        echo -e "${GREEN}阈值已更新。${PLAIN}"; sleep 0.5
                    else
                        echo -e "${RED}格式错误! 请输入纯数字用逗号分隔。${PLAIN}"; sleep 1
                    fi
                fi ;;
            6)
                echo -e "当前 API: $t_api"
                echo -e "留空恢复默认 (https://api.telegram.org)"
                read -p "请输入新 API 地址: " val; val=$(strip_cr "$val")
                [ -z "$val" ] && val="https://api.telegram.org"
                jq --arg v "$val" '.telegram.api_url=$v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                echo -e "${GREEN}API 地址已更新。${PLAIN}"; sleep 0.5 ;;
            7)
                echo -e "当前设置: $([ "$t_rpt" -gt 0 ] 2>/dev/null && echo "每 ${t_rpt} 小时" || echo "未开启")"
                read -p "报告间隔 (小时, 0为关闭): " val; val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]]; then
                    jq --argjson v "$val" '.telegram.report_interval_hours=$v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                    if [ "$val" -eq 0 ]; then
                        echo -e "${GREEN}定时报告已关闭。${PLAIN}"
                    else
                        echo -e "${GREEN}已设置为每 ${val} 小时报告一次。${PLAIN}"
                    fi
                    sleep 0.5
                else
                    echo -e "${RED}请输入纯整数!${PLAIN}"; sleep 1
                fi ;;
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

        local status_str="${YELLOW}⚪ 未启用${PLAIN}"
        [ "$p_enable" == "true" ] && status_str="${GREEN}✅ 已启用${PLAIN}"
        local url_str="${YELLOW}未配置${PLAIN}"
        [ -n "$p_url" ] && [ "$p_url" != "" ] && url_str="${GREEN}${p_url}${PLAIN}"
        local secret_str="${YELLOW}未配置${PLAIN}"
        [ -n "$p_secret" ] && [ "$p_secret" != "" ] && secret_str="${GREEN}已配置${PLAIN} (${p_secret:0:6}...)"
        local nkey_str="${YELLOW}未配置${PLAIN}"
        [ -n "$p_nkey" ] && [ "$p_nkey" != "" ] && nkey_str="${GREEN}${p_nkey}${PLAIN}"

        clear
        echo -e "========================================"
        echo -e "   Cloudflare Worker 云端推送"
        echo -e "========================================"
        echo -e " 状态:     $status_str"
        echo -e " Worker:   $url_str"
        echo -e " Secret:   $secret_str"
        echo -e " Node Key: $nkey_str"
        echo -e "========================================"
        echo -e " 1. 配置 Worker URL"
        echo -e " 2. 配置 Secret"
        echo -e " 3. 配置 Node Key"
        echo -e " 4. 开启/关闭 推送"
        echo -e " 0. 返回主菜单"
        echo -e "========================================"
        read -p "请输入选项: " c
        c=$(strip_cr "$c")
        local tmp=$(mktemp)

        case $c in
            1)
                read -p "请输入 Worker URL: " val; val=$(strip_cr "$val")
                if [ -n "$val" ]; then
                    jq --arg v "$val" '.push.worker_url=$v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                    echo -e "${GREEN}已更新。${PLAIN}"; sleep 0.5
                fi ;;
            2)
                read -p "请输入 Secret: " val; val=$(strip_cr "$val")
                if [ -n "$val" ]; then
                    jq --arg v "$val" '.push.secret=$v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                    echo -e "${GREEN}已更新。${PLAIN}"; sleep 0.5
                fi ;;
            3)
                read -p "请输入 Node Key: " val; val=$(strip_cr "$val")
                if [ -n "$val" ]; then
                    jq --arg v "$val" '.push.node_key=$v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                    echo -e "${GREEN}已更新。${PLAIN}"; sleep 0.5
                fi ;;
            4)
                local nv="true"; [ "$p_enable" == "true" ] && nv="false"
                jq --argjson v "$nv" '.push.enable=$v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"
                echo -e "${GREEN}已$([ "$nv" == "true" ] && echo "开启" || echo "关闭")。${PLAIN}"; sleep 0.5 ;;
            0) rm -f "$tmp"; break ;;
        esac
        rm -f "$tmp"
    done
}

delete_port_flow() {
    local arr=("$@")
    read -p "ID to delete: " id
    id=$(strip_cr "$id")
    if [[ ! "$id" =~ ^[0-9]+$ ]] || [ "$id" -le 0 ]; then return; fi
    local port=${arr[$((id-1))]}
    if [ -z "$port" ]; then echo -e "${RED}无效 ID。${PLAIN}"; sleep 1; return; fi

    read -p "确认删除端口 ${port}? [y/N]: " confirm
    confirm=$(strip_cr "$confirm")
    [ "$confirm" != "y" ] && return

    # 1. 从封禁集合移除 (可能不在集合中, 忽略错误)
    nft delete element $NFT_TABLE blocked_ports \{ $port \} 2>/dev/null

    # 2. 从配置中删除
    local tmp=$(mktemp)
    if jq "del(.ports[\"$port\"])" "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
        rm -f "$tmp"
        reload_all_rules
        rm -f "$STATE_DIR/${port}.txt"
        echo -e "${GREEN}端口 ${port} 已删除。${PLAIN}"; sleep 1
    else
        rm -f "$tmp"
        echo -e "${RED}删除失败。${PLAIN}"; sleep 1
    fi
}

update_script() {
    echo -e "${YELLOW}正在检查更新...${PLAIN}"
    local tmp=$(mktemp /tmp/pm_update.XXXXXX.sh)
    curl -fsSL --max-time 30 "$DOWNLOAD_URL" -o "$tmp" 2>/dev/null
    if [ -s "$tmp" ] && head -1 "$tmp" | grep -q '^#!/bin/bash'; then
        mv -f "$tmp" "$INSTALL_PATH" && chmod +x "$INSTALL_PATH"
        echo -e "${GREEN}更新成功，正在重启...${PLAIN}"; sleep 1
        exec "$INSTALL_PATH"
    else
        rm -f "$tmp"
        echo -e "${RED}更新失败: 下载文件无效或网络不可用。${PLAIN}"; sleep 2
    fi
}

uninstall_script() {
    echo -e "${RED}警告: 将删除所有配置和监控规则!${PLAIN}"
    read -p "确认卸载? (输入 yes): " c
    c=$(strip_cr "$c")
    [ "$c" != "yes" ] && return

    echo -e "${YELLOW}正在清理...${PLAIN}"

    # 1. 清除 nftables 规则
    nft delete table $NFT_TABLE 2>/dev/null
    echo -e "  nftables 规则已清除"

    # 2. 清除 TC 根队列
    local iface=$(jq -r '.interface // empty' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$iface" ] && iface=$(get_iface)
    if [ -n "$iface" ]; then
        tc qdisc del dev "$iface" root 2>/dev/null
        echo -e "  TC 限速规则已清除"
    fi

    # 3. 移除 Cron
    crontab -l 2>/dev/null | grep -v "$SHORTCUT_NAME" | crontab -
    echo -e "  Cron 任务已清除"

    # 4. 删除文件
    rm -rf "$CONFIG_DIR" "$INSTALL_PATH" "$LOCK_FILE" "$CRON_LOCK_FILE" "$USER_EDIT_LOCK" 2>/dev/null
    echo -e "  文件已清除"

    echo -e "${GREEN}卸载完成。${PLAIN}"
    exit 0
}

# ==============================================================================
# 入口逻辑
# ==============================================================================
check_root
install_shortcut "${1:-}"
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [ "${1:-}" == "--monitor" ] || [ "${1:-}" == "--ipl" ]; then
    # [OPT-FAST] cron/CLI 模式: 跳过完整 install_deps (依赖已在首次运行时安装, 配置已迁移)
    # 仅做最小化检查: 配置文件存在且 JSON 合法
    if [ ! -s "$CONFIG_FILE" ] || ! jq empty "$CONFIG_FILE" >/dev/null 2>&1; then
        # 配置异常, 回退到完整初始化
        install_deps
    fi
    mkdir -p "$STATE_DIR"
else
    install_deps
fi

if [ "${1:-}" == "--monitor" ]; then
    cron_task
elif [ "${1:-}" == "--ipl" ]; then
    echo -e "端口\t在线IP数\tIP列表"
    echo -e "----\t--------\t------"
    for p in $(jq -r '.ports | keys[]' "$CONFIG_FILE" | sort -n); do
        ips=$(_sentinel_scan_ips "$p")
        cnt=0; [ -n "$ips" ] && cnt=$(echo "$ips" | wc -l)
        list="-"; [ -n "$ips" ] && list=$(echo "$ips" | tr '\n' ' ')
        echo -e "${p}\t${cnt}\t\t${list}"
    done
elif [ "${1:-}" == "update" ]; then
    update_script
else
    setup_cron
    _IS_MENU_MODE=true
    while true; do show_main_menu; done
fi