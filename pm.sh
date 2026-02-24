#!/bin/bash

# ==============================================================================
# Linux 端口流量管理脚本 (Port Monitor & Shaper)
# 版本: v4.3 Stable
# ==============================================================================

# --- 全局配置 ---
SHORTCUT_NAME="pm"
INSTALL_PATH="/usr/local/bin/$SHORTCUT_NAME"
# [注意] 如果您 Fork 了此脚本，请修改下方的更新源地址
DOWNLOAD_URL="https://raw.githubusercontent.com/white-u/vps_script/main/pm.sh"

CONFIG_DIR="/etc/port_monitor"
CONFIG_FILE="$CONFIG_DIR/config.json"
LOCK_FILE="/var/run/pm.lock"
SCRIPT_VERSION="4.4.1"
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
    [[ "$1" == "--monitor" ]] && return
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
    
    # 检查惩罚状态，优先应用惩罚限速
    local is_punished=$(echo "$conf" | jq -r '.dyn_limit.is_punished // false')
    if [ "$is_punished" == "true" ]; then
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

# 获取通知标识 (优先 hostname + 端口备注)
# 格式: "hostname (备注)" 或 "hostname" 或 "IP"
# 返回值经过 Markdown 安全转义，可直接用于 Telegram 消息
get_host_label() {
    local comment="$1"
    local host_part=""
    
    # 主标识: hostname → IP
    local h=$(hostname 2>/dev/null)
    if [ -n "$h" ] && [ "$h" != "localhost" ]; then
        host_part="$h"
    else
        host_part=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n 1)
    fi
    [ -z "$host_part" ] && host_part="Unknown"
    
    # 附加备注
    local raw="$host_part"
    if [ -n "$comment" ] && [ "$comment" != "null" ] && [ "$comment" != "" ]; then
        raw="${host_part} (${comment})"
    fi
    
    # 转义 Telegram Markdown V1 特殊字符: * _ ` [
    echo "$raw" | sed 's/[_*`\[]/\\&/g'
}

# 格式化字节为人类可读 (纯 Shell 实现，cron 环境下 numfmt 可能不在 PATH)
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

# Telegram 发送核心
# 用法: tg_send "消息内容"
tg_send() {
    local msg="$1"
    [ -z "$msg" ] && return
    
    # 读取 Telegram 配置
    local tg_conf=$(jq -r '.telegram // empty' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$tg_conf" ] && return
    
    local enabled=$(echo "$tg_conf" | jq -r '.enable // false')
    [ "$enabled" != "true" ] && return
    
    local token=$(echo "$tg_conf" | jq -r '.bot_token // empty')
    local chat_id=$(echo "$tg_conf" | jq -r '.chat_id // empty')
    [ -z "$token" ] || [ -z "$chat_id" ] && return
    
    # 支持自定义 API 地址 (国内反代)
    local api_url=$(echo "$tg_conf" | jq -r '.api_url // "https://api.telegram.org"')
    
    # 异步发送，不阻塞 Cron，超时 10 秒
    curl -sf --max-time 10 \
        "${api_url}/bot${token}/sendMessage" \
        -d chat_id="$chat_id" \
        -d text="$msg" \
        -d parse_mode="Markdown" \
        >/dev/null 2>&1 &
}

# --- 预定义通知模板 ---

# 配额阈值预警
tg_notify_quota() {
    local port=$1 comment=$2 percent=$3 used_fmt=$4 quota_gb=$5 mode=$6 threshold=$7
    local label=$(get_host_label "$comment")
    local mode_str="双向"
    [ "$mode" == "out_only" ] && mode_str="仅出站"
    local icon="⚠️"
    [ "$threshold" -ge 100 ] && icon="🔴"
    tg_send "${icon} *端口流量预警*
🏷 标识: *${label}*
🔌 端口: \`${port}\`
📊 已用: ${used_fmt} / ${quota_gb}GB (*${percent}%*)
📋 模式: ${mode_str}
⏰ 状态: 已超过 *${threshold}%* 阈值"
}

# 端口封禁通知
tg_notify_blocked() {
    local port=$1 comment=$2 quota_gb=$3 reset_day=$4
    local label=$(get_host_label "$comment")
    local reset_str="手动重置"
    [ "$reset_day" -gt 0 ] 2>/dev/null && reset_str="每月 ${reset_day} 日自动重置"
    tg_send "🚫 *端口已封禁*
🏷 标识: *${label}*
🔌 端口: \`${port}\`
📊 流量配额已耗尽，端口已被封禁
🔄 重置策略: ${reset_str}"
}

# DynQoS 惩罚触发
tg_notify_punish() {
    local port=$1 comment=$2 avg_mbps=$3 trigger_mbps=$4 punish_mbps=$5 punish_min=$6
    local label=$(get_host_label "$comment")
    tg_send "⚡ *动态限速触发*
🏷 标识: *${label}*
🔌 端口: \`${port}\`
📈 平均速率: ${avg_mbps} Mbps (阈值 ${trigger_mbps} Mbps)
📉 已降速至: *${punish_mbps} Mbps*
⏱ 持续时间: ${punish_min} 分钟"
}

# DynQoS 惩罚恢复
tg_notify_recover() {
    local port=$1 comment=$2
    local label=$(get_host_label "$comment")
    tg_send "✅ *限速已恢复*
🏷 标识: *${label}*
🔌 端口: \`${port}\`
📈 惩罚期结束，已恢复原始速率"
}

# 配额自动重置
tg_notify_reset() {
    local port=$1 comment=$2 quota_gb=$3
    local label=$(get_host_label "$comment")
    tg_send "🔄 *配额已自动重置*
🏷 标识: *${label}*
🔌 端口: \`${port}\`
📊 新配额: ${quota_gb} GB
⏰ 新周期已开始"
}

# 周期性流量报告 (汇总所有端口)
tg_notify_report() {
    local host_label=$(get_host_label "")
    local now_str=$(date '+%Y-%m-%d %H:%M')
    local report_lines=""
    
    local ports=$(jq -r '.ports | keys[]' "$CONFIG_FILE" 2>/dev/null | sort -n)
    [ -z "$ports" ] && return
    
    for port in $ports; do
        local p_conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
        local comment=$(echo "$p_conf" | jq -r '.comment // ""')
        local quota_gb=$(echo "$p_conf" | jq -r '.quota_gb')
        local mode=$(echo "$p_conf" | jq -r '.quota_mode')
        local acc_in=$(echo "$p_conf" | jq -r '(.stats.acc_in // 0) | floor')
        local acc_out=$(echo "$p_conf" | jq -r '(.stats.acc_out // 0) | floor')
        local limit=$(echo "$p_conf" | jq -r '.limit_mbps // 0')
        local is_punished=$(echo "$p_conf" | jq -r '.dyn_limit.is_punished // false')
        
        local total_used=0
        if [ "$mode" == "out_only" ]; then
            total_used=$acc_out
        else
            total_used=$(echo "scale=0; $acc_in + $acc_out" | bc)
        fi
        
        local used_fmt=$(fmt_bytes_plain "$total_used")
        local quota_bytes=$(echo "scale=0; $quota_gb * 1024 * 1024 * 1024" | bc)
        local percent=0
        if [ "$quota_bytes" != "0" ] && [ -n "$quota_bytes" ]; then
            percent=$(echo "scale=1; $total_used * 100 / $quota_bytes" | bc 2>/dev/null)
        fi
        [ -z "$percent" ] && percent=0
        
        # 状态图标
        local status_icon="✅"
        local is_blocked=$(nft -j list set $NFT_TABLE blocked_ports 2>/dev/null | jq -r --argjson p "$port" '[ .nftables[] | select(.set) | .set.elem[]? ] | any(. == $p)')
        if [ "$is_blocked" == "true" ]; then
            status_icon="🚫"
        elif [ "$is_punished" == "true" ]; then
            status_icon="⚡"
        elif [ $(echo "$percent >= 80" | bc 2>/dev/null) -eq 1 ] 2>/dev/null; then
            status_icon="⚠️"
        fi
        
        # 端口标题
        local port_title="\`${port}\`"
        if [ -n "$comment" ] && [ "$comment" != "null" ] && [ "$comment" != "" ]; then
            local safe_comment=$(echo "$comment" | sed 's/[_*`\[]/\\&/g')
            port_title="\`${port}\` ${safe_comment}"
        fi
        
        # 限速信息
        local speed_info=""
        if [ "$is_punished" == "true" ]; then
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

# 推送端口数据到 Cloudflare Worker (D1)
# 在 cron_task 末尾调用，开启后每分钟随 Cron 推送一次
push_to_worker() {
    local push_conf=$(jq -r '.push // empty' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$push_conf" ] && return

    local enabled=$(echo "$push_conf" | jq -r '.enable // false')
    [ "$enabled" != "true" ] && return

    local worker_url=$(echo "$push_conf" | jq -r '.worker_url // empty')
    local secret=$(echo "$push_conf" | jq -r '.secret // empty')
    local node_key=$(echo "$push_conf" | jq -r '.node_key // empty')
    [ -z "$worker_url" ] || [ -z "$secret" ] || [ -z "$node_key" ] && return

    # 脱敏: 仅推送端口数据，剥离 telegram/push 配置段（含密钥）
    local payload=$(jq '{node_id, interface, ports}' "$CONFIG_FILE" 2>/dev/null)
    [ -z "$payload" ] && return

    # HMAC-SHA256 签名 (timestamp + body)
    local timestamp=$(date +%s)
    local signature=$(printf '%s%s' "$timestamp" "$payload" | openssl dgst -sha256 -hmac "$secret" 2>/dev/null | awk '{print $NF}')
    [ -z "$signature" ] && return

    # 异步推送，不阻塞 Cron，超时 10 秒
    curl -sf --max-time 10 \
        -X PUT "${worker_url}" \
        -H "Content-Type: application/json" \
        -H "X-Node: ${node_key}" \
        -H "X-Timestamp: ${timestamp}" \
        -H "X-Signature: ${signature}" \
        -d "$payload" \
        >/dev/null 2>&1 &
}

CRON_LOCK_FILE="/var/run/pm_cron.lock"

cron_task() {
    # 单例锁: 如果上一轮 cron 还没跑完, 直接退出不堆积
    exec 9>"$CRON_LOCK_FILE"
    flock -n 9 || exit 0

    # [核心修复 V3.7] 智能死锁解除与并发避让
    if [ -f "$USER_EDIT_LOCK" ]; then
        # 获取锁文件未更新的秒数
        local lock_age=$(($(date +%s) - $(stat -c %Y "$USER_EDIT_LOCK" 2>/dev/null || echo 0)))
        
        # 阈值判定：10分钟 (600秒)
        if [ "$lock_age" -gt 600 ] || [ "$lock_age" -lt 0 ]; then
             # 超时，视为用户异常断线，强制清理锁，恢复监控
             rm -f "$USER_EDIT_LOCK"
        else
             # 未超时，避让用户操作
             exit 0
        fi
    fi

    # 注入 PATH 确保命令可用
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

    # 规则自愈
    if ! nft list table $NFT_TABLE &>/dev/null; then
        reload_all_rules
    fi

    local tmp_json=$(cat "$CONFIG_FILE")
    local ports=$(echo "$tmp_json" | jq -r '.ports | keys[]')
    local modified=false
    local current_ts=$(date +%s)

    for port in $ports; do
        local p_conf=$(echo "$tmp_json" | jq ".ports[\"$port\"]")
        local mode=$(echo "$p_conf" | jq -r '.quota_mode')
        local quota_gb=$(echo "$p_conf" | jq -r '.quota_gb')
        
        # [格式清洗] 强制转整数，消除科学计数法 (使用 jq 内置 floor)
        local acc_in=$(echo "$p_conf" | jq -r '(.stats.acc_in // 0) | floor')
        local acc_out=$(echo "$p_conf" | jq -r '(.stats.acc_out // 0) | floor')
        local last_k_in=$(echo "$p_conf" | jq -r '(.stats.last_kernel_in // 0) | floor')
        local last_k_out=$(echo "$p_conf" | jq -r '(.stats.last_kernel_out // 0) | floor')

        # 读取内核 (使用 select 兼容新版 nft 的 metainfo 头)
        local curr_k_in=$(nft -j list counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null | jq -r '[ .nftables[] | select(.counter) | .counter.bytes ] | .[0] // 0')
        local curr_k_out=$(nft -j list counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null | jq -r '[ .nftables[] | select(.counter) | .counter.bytes ] | .[0] // 0')
        [ -z "$curr_k_in" ] && curr_k_in=0
        [ -z "$curr_k_out" ] && curr_k_out=0

        # 计算增量 (Shell + BC 整数)
        local delta_in=0
        if [ $(echo "scale=0; $curr_k_in < $last_k_in" | bc) -eq 1 ]; then 
            delta_in=$curr_k_in # 重启过
        else 
            delta_in=$(echo "scale=0; $curr_k_in - $last_k_in" | bc)
        fi

        local delta_out=0
        if [ $(echo "scale=0; $curr_k_out < $last_k_out" | bc) -eq 1 ]; then 
            delta_out=$curr_k_out 
        else 
            delta_out=$(echo "scale=0; $curr_k_out - $last_k_out" | bc)
        fi
        
        acc_in=$(echo "scale=0; $acc_in + $delta_in" | bc)
        acc_out=$(echo "scale=0; $acc_out + $delta_out" | bc)

        # 写入 JSON 变量
        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].stats.acc_in = $acc_in | .ports[\"$port\"].stats.acc_out = $acc_out | .ports[\"$port\"].stats.last_kernel_in = $curr_k_in | .ports[\"$port\"].stats.last_kernel_out = $curr_k_out")
        modified=true

        # --- Dynamic QoS 逻辑 ---
        local dyn_enable=$(echo "$p_conf" | jq -r '.dyn_limit.enable // false')
        if [ "$dyn_enable" == "true" ]; then
            local dyn_trigger=$(echo "$p_conf" | jq -r '.dyn_limit.trigger_mbps')
            local dyn_trig_time=$(echo "$p_conf" | jq -r '.dyn_limit.trigger_time')
            local dyn_punish_time=$(echo "$p_conf" | jq -r '.dyn_limit.punish_time')
            local dyn_punish_mbps=$(echo "$p_conf" | jq -r '.dyn_limit.punish_mbps')
            local strike=$(echo "$p_conf" | jq -r '.dyn_limit.strike_count // 0')
            local is_punished=$(echo "$p_conf" | jq -r '.dyn_limit.is_punished // false')
            local end_ts=$(echo "$p_conf" | jq -r '.dyn_limit.punish_end_ts // 0')
            local comment=$(echo "$p_conf" | jq -r '.comment // ""')

            local current_mbps=$(echo "scale=2; ($delta_in + $delta_out) * 8 / 60 / 1000000" | bc)
            local rule_changed=false

            # 通知状态
            local punish_notified=$(echo "$p_conf" | jq -r '.notify_state.punish_notified // false')
            local recover_notified=$(echo "$p_conf" | jq -r '.notify_state.recover_notified // true')

            if [ "$is_punished" == "true" ]; then
                if [ "$current_ts" -ge "$end_ts" ]; then
                    is_punished="false"
                    strike=0
                    tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.is_punished = false | .ports[\"$port\"].dyn_limit.strike_count = 0")
                    # 通知: 惩罚恢复
                    if [ "$recover_notified" != "true" ]; then
                        tg_notify_recover "$port" "$comment"
                        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].notify_state.recover_notified = true | .ports[\"$port\"].notify_state.punish_notified = false")
                    fi
                    rule_changed=true
                fi
            else
                if [ $(echo "$current_mbps > $dyn_trigger" | bc) -eq 1 ]; then
                    strike=$((strike + 1))
                    if [ "$strike" -ge "$dyn_trig_time" ]; then
                        is_punished="true"
                        end_ts=$((current_ts + dyn_punish_time * 60))
                        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.is_punished = true | .ports[\"$port\"].dyn_limit.punish_end_ts = $end_ts")
                        # 通知: 惩罚触发
                        if [ "$punish_notified" != "true" ]; then
                            tg_notify_punish "$port" "$comment" "$current_mbps" "$dyn_trigger" "$dyn_punish_mbps" "$dyn_punish_time"
                            tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].notify_state.punish_notified = true | .ports[\"$port\"].notify_state.recover_notified = false")
                        fi
                        rule_changed=true
                    else
                        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.strike_count = $strike")
                    fi
                else
                    if [ "$strike" -gt 0 ]; then
                        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.strike_count = 0")
                    fi
                fi
            fi
            
            if [ "$rule_changed" == "true" ]; then
                local _tmp_dyn=$(mktemp)
                printf '%s\n' "$tmp_json" > "$_tmp_dyn"
                safe_write_config_from_file "$_tmp_dyn"
                rm -f "$_tmp_dyn"
                apply_port_rules "$port"
                tmp_json=$(cat "$CONFIG_FILE")
            fi
        fi

        # --- 自动重置配额 ---
        local reset_day=$(echo "$p_conf" | jq -r '.reset_day // 0')
        if [ "$reset_day" -gt 0 ] 2>/dev/null && [ "$reset_day" -le 31 ] 2>/dev/null; then
            local last_reset_ts=$(echo "$p_conf" | jq -r '(.last_reset_ts // 0) | floor')
            
            # 计算当月有效重置日 (处理大月小月: 设31日但当月只有28/30天)
            local days_in_month=$(date -d "$(date +%Y-%m-01) +1 month -1 day" +%-d 2>/dev/null)
            [ -z "$days_in_month" ] && days_in_month=28
            local effective_day=$reset_day
            [ "$effective_day" -gt "$days_in_month" ] && effective_day=$days_in_month
            
            # 计算本月重置时间点 (当月 effective_day 日 00:00:00)
            local reset_date=$(printf "%s-%02d 00:00:00" "$(date +%Y-%m)" "$effective_day")
            local reset_ts=$(date -d "$reset_date" +%s 2>/dev/null || echo 0)
            
            # 判定: 已过重置日 且 上次重置在本周期之前 → 执行重置
            if [ "$current_ts" -ge "$reset_ts" ] && [ "$last_reset_ts" -lt "$reset_ts" ]; then
                local comment_r=$(echo "$p_conf" | jq -r '.comment // ""')
                acc_in=0; acc_out=0
                tmp_json=$(echo "$tmp_json" | jq \
                    --arg p "$port" --argjson ts "$current_ts" --argjson ki "$curr_k_in" --argjson ko "$curr_k_out" \
                    '.ports[$p].stats.acc_in = 0 | .ports[$p].stats.acc_out = 0 
                     | .ports[$p].stats.last_kernel_in = $ki | .ports[$p].stats.last_kernel_out = $ko 
                     | .ports[$p].last_reset_ts = $ts
                     | .ports[$p].dyn_limit.is_punished = false | .ports[$p].dyn_limit.strike_count = 0
                     | .ports[$p].notify_state.quota_level = 0 | .ports[$p].notify_state.punish_notified = false | .ports[$p].notify_state.recover_notified = true')
                # 解封端口
                nft delete element $NFT_TABLE blocked_ports \{ $port \} 2>/dev/null
                apply_port_rules "$port"
                # 通知: 配额已重置
                tg_notify_reset "$port" "$comment_r" "$quota_gb"
                modified=true
            fi
        fi

        # --- 配额检查 ---
        local total_usage=0
        if [ "$mode" == "out_only" ]; then
            total_usage=$acc_out
        else
            total_usage=$(echo "scale=0; $acc_in + $acc_out" | bc)
        fi
        
        # 1024 计算 GiB
        local quota_bytes=$(echo "scale=0; $quota_gb * 1024 * 1024 * 1024" | bc)
        local is_blocked_nft=$(nft -j list set $NFT_TABLE blocked_ports 2>/dev/null | jq -r --argjson p "$port" '[ .nftables[] | select(.set) | .set.elem[]? ] | any(. == $p)')
        # is_blocked_nft 为 "true" 或 "false"

        if (( $(echo "$total_usage > $quota_bytes" | bc -l) )); then
            [ "$is_blocked_nft" == "false" ] && nft add element $NFT_TABLE blocked_ports \{ $port \}
        else
            [ "$is_blocked_nft" == "true" ] && nft delete element $NFT_TABLE blocked_ports \{ $port \}
        fi

        # --- 配额阈值通知 (状态机: quota_level 只升不降，重置时归零) ---
        local comment_n=$(echo "$p_conf" | jq -r '.comment // ""')
        local reset_day_n=$(echo "$p_conf" | jq -r '.reset_day // 0')
        local quota_level=$(echo "$p_conf" | jq -r '.notify_state.quota_level // 0')
        # 获取用户自定义阈值列表 (默认 [50,80,100])
        local thresholds=$(jq -r '.telegram.thresholds // [50,80,100] | .[]' "$CONFIG_FILE" 2>/dev/null)
        
        if [ "$quota_bytes" != "0" ] && [ -n "$quota_bytes" ]; then
            local percent=$(echo "scale=1; $total_usage * 100 / $quota_bytes" | bc 2>/dev/null)
            [ -z "$percent" ] && percent=0
            local used_fmt=$(fmt_bytes_plain "$total_usage")

            # 从高到低遍历阈值，命中最高的未通知阈值
            local new_level=$quota_level
            for thr in $(echo "$thresholds" | sort -rn); do
                [ -z "$thr" ] && continue
                if (( $(echo "$percent >= $thr" | bc -l) )) && [ "$quota_level" -lt "$thr" ]; then
                    new_level=$thr
                    break
                fi
            done

            if [ "$new_level" -gt "$quota_level" ]; then
                # 发阈值通知
                tg_notify_quota "$port" "$comment_n" "$percent" "$used_fmt" "$quota_gb" "$mode" "$new_level"
                # 如果达到 100% 同时发封禁通知
                if [ "$new_level" -ge 100 ]; then
                    tg_notify_blocked "$port" "$comment_n" "$quota_gb" "$reset_day_n"
                fi
                tmp_json=$(echo "$tmp_json" | jq --argjson lv "$new_level" ".ports[\"$port\"].notify_state.quota_level = \$lv")
                modified=true
            fi
        fi
    done

    if [ "$modified" == "true" ]; then
        local _tmp_final=$(mktemp)
        printf '%s\n' "$tmp_json" > "$_tmp_final"
        safe_write_config_from_file "$_tmp_final"
        rm -f "$_tmp_final"
    fi

    # --- 周期性流量报告 ---
    local report_hours=$(jq -r '.telegram.report_interval_hours // 0' "$CONFIG_FILE" 2>/dev/null)
    if [ "$report_hours" -gt 0 ] 2>/dev/null; then
        local last_report_ts=$(jq -r '.telegram.last_report_ts // 0' "$CONFIG_FILE" 2>/dev/null)
        local report_interval_sec=$((report_hours * 3600))
        local next_report_ts=$((last_report_ts + report_interval_sec))
        
        if [ "$current_ts" -ge "$next_report_ts" ]; then
            tg_notify_report
            # 更新 last_report_ts
            local _tmp_rpt=$(mktemp)
            jq --argjson ts "$current_ts" '.telegram.last_report_ts = $ts' "$CONFIG_FILE" > "$_tmp_rpt" && safe_write_config_from_file "$_tmp_rpt"
            rm -f "$_tmp_rpt"
        fi
    fi

    # --- 推送到 Cloudflare Worker (D1) ---
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

# 创建锁文件，进入编辑模式
start_edit_lock() { touch "$USER_EDIT_LOCK"; }
# 删除锁文件，Cron 恢复工作
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
        
        # UI 只读 JSON，不再自行计算，保证与 Cron 数据源一致
        local acc_in=$(echo "$conf" | jq -r '(.stats.acc_in // 0) | floor')
        local acc_out=$(echo "$conf" | jq -r '(.stats.acc_out // 0) | floor')
        
        local mode_str="[双向]"
        local total_used=0
        if [ "$mode" == "out_only" ]; then
            mode_str="[仅出站]"
            total_used=$acc_out
        else
            total_used=$(echo "scale=0; $acc_in + $acc_out" | bc)
        fi
        
        local status_clean=""
        local is_blocked=false
        
        if nft -j list set $NFT_TABLE blocked_ports 2>/dev/null | jq -r --argjson p "$port" '[ .nftables[] | select(.set) | .set.elem[]? ] | any(. == $p)' | grep -q "true"; then
            status_clean="[已阻断]"
            is_blocked=true
        else
            status_clean="$(fmt_bytes $total_used)"
        fi
        
        local is_punished=$(echo "$conf" | jq -r '.dyn_limit.is_punished // false')
        local reset_day=$(echo "$conf" | jq -r '.reset_day // 0')
        local quota_str="${status_clean} / ${quota} GB"
        if [ "$reset_day" -gt 0 ] 2>/dev/null; then
            quota_str="${quota_str} [R${reset_day}]"
        fi
        local limit_str=""
        if [ "$is_punished" == "true" ]; then
            local punish_val=$(echo "$conf" | jq -r '.dyn_limit.punish_mbps')
            limit_str="${RED}${punish_val}Mbps(惩罚中)${PLAIN}"
        else
            if [ "$limit" == "0" ]; then
                limit_str="无限制"
            else
                limit_str="${limit} Mbps"
            fi
        fi

        if [ "$is_blocked" == true ]; then
            echo -e " ${RED}[${i}]  ${port}         [已阻断]  配额用尽，端口已封禁${PLAIN}"
        else
            printf " [%d]  %-12s %-10s %-30s %-24b %-15s\n" $i "$port" "$mode_str" "$quota_str" "$limit_str" "$comment"
        fi
        
        port_list[$i]=$port
        i=$((i + 1))
    done
    echo -e "-----------------------------------------------------------------------------------------"
    echo -e " 说明: 流量每分钟更新一次。[Rxx]=每月xx日自动重置。当前正在编辑中，后台刷新已暂停。\n"

    # Telegram 状态指示
    local tg_status="${YELLOW}⚪ 未配置${PLAIN}"
    local tg_enabled=$(jq -r '.telegram.enable // false' "$CONFIG_FILE" 2>/dev/null)
    [ "$tg_enabled" == "true" ] && tg_status="${GREEN}✅ 已开启${PLAIN}"

    # 云端推送状态指示
    local push_status="${YELLOW}⚪ 未配置${PLAIN}"
    local push_enabled=$(jq -r '.push.enable // false' "$CONFIG_FILE" 2>/dev/null)
    [ "$push_enabled" == "true" ] && push_status="${GREEN}✅ 已开启${PLAIN}"

    echo -e " 1. 添加 监控端口 (服务扫描)"
    echo -e " 2. 配置 端口 (修改/动态QoS/重置)"
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
        *) ;; # 无效输入, 循环重新显示菜单
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
    # TC 保留端口 (default classid = 0xfffe = 65534)，禁止监控以避免 TC 规则冲突
    local reserved_port=$((16#$TC_DEFAULT_CID))
    if [ "$target_port" -eq "$reserved_port" ]; then
        echo -e "${RED}端口 $reserved_port 为系统保留端口 (TC 默认分类)，无法监控!${PLAIN}"; sleep 2; return
    fi
    
    echo -e "\n>> 正在配置端口: $target_port"
    
    read -p "月流量配额 (纯数字, GB): " quota
    quota=$(strip_cr "$quota")
    if [[ ! "$quota" =~ ^[0-9]+$ ]] || [ "$quota" -eq 0 ]; then
        echo -e "${RED}错误: 配额必须是大于0的纯整数，不要带单位!${PLAIN}"; sleep 2; return
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
    if [[ ! "$reset_day" =~ ^[0-9]+$ ]]; then
        reset_day=0
    fi
    if [ "$reset_day" -gt 31 ]; then
        echo -e "${RED}错误: 重置日必须在 1-31 之间!${PLAIN}"; sleep 2; return
    fi

    read -p "备注信息: " comment
    comment=$(strip_cr "$comment")

    local tmp=$(mktemp)
    
    # 使用 --argjson 确保 JSON 类型安全
    if jq --argjson q "$quota" \
          --arg m "$mode" \
          --argjson l "$limit" \
          --argjson rd "$reset_day" \
          --argjson lrt "$(date +%s)" \
          --arg c "$comment" \
          --arg p "$target_port" \
       '.ports[$p] = {
        "quota_gb": $q, 
        "quota_mode": $m, 
        "limit_mbps": $l, 
        "reset_day": $rd,
        "last_reset_ts": $lrt,
        "comment": $c, 
        "stats": {"acc_in": 0, "acc_out": 0, "last_kernel_in": 0, "last_kernel_out": 0},
        "dyn_limit": {"enable": false},
        "notify_state": {"quota_level": 0, "punish_notified": false, "recover_notified": true}
    }' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
    
        rm -f "$tmp"
        apply_port_rules "$target_port"
        echo -e "${GREEN}添加成功! 流量将在下次 Cron 周期开始统计。${PLAIN}"
        sleep 1
        return
    else
        rm -f "$tmp"
        echo -e "${RED}写入配置失败! 请检查输入内容。${PLAIN}"
        sleep 2
        return
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
        local dyn_conf=$(echo "$conf" | jq '.dyn_limit')
        local dyn_enable=$(echo "$dyn_conf" | jq -r '.enable // false')
        local dyn_strike=$(echo "$dyn_conf" | jq -r '.strike_count // 0')
        local dyn_trig_time=$(echo "$dyn_conf" | jq -r '.trigger_time // 0')
        local reset_day=$(echo "$conf" | jq -r '.reset_day // 0')
        
        clear
        echo -e "========================================"
        echo -e " 当前配置: [$id]  $port  $comment"
        echo -e "========================================"
        echo -e " [基础信息]"
        echo -e " 流量配额: $quota GB"
        echo -e " 计费模式: $([ "$mode" == "out_only" ] && echo "仅出站" || echo "双向")"
        echo -e " 基础限速: $([ "$limit" == "0" ] && echo "无限制" || echo "$limit Mbps")"
        if [ "$reset_day" -gt 0 ] 2>/dev/null; then
            echo -e " 自动重置: 每月 ${GREEN}${reset_day}${PLAIN} 日"
        else
            echo -e " 自动重置: ${YELLOW}未设置 (手动重置)${PLAIN}"
        fi
        echo -e ""
        echo -e " [动态突发限制 (QoS)]"
        if [ "$dyn_enable" == "true" ]; then
            local desc="> $(echo "$dyn_conf" | jq -r '.trigger_mbps')Mbps 持续 $(echo "$dyn_conf" | jq -r '.trigger_time')分 -> 降至 $(echo "$dyn_conf" | jq -r '.punish_mbps')Mbps"
            echo -e " 策略状态: ${GREEN}✅ 已启用${PLAIN}"
            echo -e " 规则详情: $desc"
            echo -e " 当前监测: 连续超标 $dyn_strike 次 / $dyn_trig_time 次"
        else
            echo -e " 策略状态: ⚪ 未启用 (默认)"
        fi
        echo -e "========================================"
        echo -e " 1. 修改 流量配额"
        echo -e " 2. 修改 计费模式"
        echo -e " 3. 修改 基础出站限速"
        echo -e " 4. 配置 动态突发限制 (QoS)"
        echo -e " 5. 修改 备注信息"
        echo -e " 6. 重置 统计数据 (清零)"
        echo -e " 7. 修改 自动重置日"
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
                    fi
                else
                    echo -e "${RED}错误: 必须输入大于0的纯整数!${PLAIN}"; sleep 1
                fi 
                ;;
            2) 
                read -p "模式 (1.双向 2.仅出站): " m
                m=$(strip_cr "$m")
                local nm="in_out"
                [ "$m" == "2" ] && nm="out_only"
                if jq --arg v "$nm" --arg p "$port" '.ports[$p].quota_mode = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                    success=true
                fi
                ;;
            3) 
                read -p "新限速 (纯数字, Mbps): " val
                val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]]; then
                    if jq --argjson v "$val" --arg p "$port" '.ports[$p].limit_mbps = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                        apply_port_rules "$port"
                        success=true
                    fi
                else
                    echo -e "${RED}错误: 必须输入纯整数!${PLAIN}"; sleep 1
                fi
                ;;
            4) 
                configure_dyn_qos "$port" 
                ;;
            5) 
                read -p "新备注: " val
                val=$(strip_cr "$val")
                if jq --arg v "$val" --arg p "$port" '.ports[$p].comment = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                    success=true
                fi
                ;;
            6) 
                read -p "确定清零吗? [y/N]: " confirm
                confirm=$(strip_cr "$confirm")
                if [[ "$confirm" == "y" ]]; then
                   local k_in=$(nft -j list counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null | jq -r '[ .nftables[] | select(.counter) | .counter.bytes ] | .[0] // 0')
                   local k_out=$(nft -j list counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null | jq -r '[ .nftables[] | select(.counter) | .counter.bytes ] | .[0] // 0')
                   
                   if jq --argjson ki "$k_in" --argjson ko "$k_out" --arg p "$port" \
                      '.ports[$p].stats.acc_in = 0 | .ports[$p].stats.acc_out = 0 | .ports[$p].stats.last_kernel_in = $ki | .ports[$p].stats.last_kernel_out = $ko | .ports[$p].notify_state.quota_level = 0' \
                      "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                       
                       nft delete element $NFT_TABLE blocked_ports \{ $port \} 2>/dev/null
                       echo -e "${GREEN}已重置。${PLAIN}"; sleep 1
                   fi
                fi 
                ;;
            7) 
                read -p "自动重置日 (1-31, 0为关闭自动重置): " val
                val=$(strip_cr "$val")
                if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -le 31 ]; then
                    if jq --argjson v "$val" --arg p "$port" '.ports[$p].reset_day = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                        if [ "$val" -eq 0 ]; then
                            echo -e "${GREEN}已关闭自动重置。${PLAIN}"
                        else
                            echo -e "${GREEN}已设置每月 ${val} 日自动重置。${PLAIN}"
                        fi
                        success=true
                    fi
                else
                    echo -e "${RED}错误: 必须输入 0-31 的整数!${PLAIN}"; sleep 1
                fi
                ;;
            0) rm -f "$tmp"; break ;;
        esac
        
        if [ "$success" == "true" ]; then
            echo -e "${GREEN}配置已更新。${PLAIN}"
            sleep 0.5
        fi
        rm -f "$tmp"
    done
}

configure_dyn_qos() {
    local port=$1
    local tmp=$(mktemp)
    echo -e "\n--- 配置动态突发限制 (Dynamic QoS) ---"
    echo -e "1. 启用 (Enable)"
    echo -e "2. 禁用 (Disable)"
    echo -e "0. 取消 (Cancel)"
    read -p "请选择: " qos_sel
    qos_sel=$(strip_cr "$qos_sel")
    
    if [ "$qos_sel" == "2" ]; then
        if jq --arg p "$port" '.ports[$p].dyn_limit.enable = false | .ports[$p].dyn_limit.is_punished = false | .ports[$p].dyn_limit.strike_count = 0 | .ports[$p].notify_state.punish_notified = false | .ports[$p].notify_state.recover_notified = true' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
            apply_port_rules "$port"
            echo -e "${GREEN}已禁用 QoS 策略。${PLAIN}"
        fi

    elif [ "$qos_sel" == "1" ]; then
        echo "请输入整数参数 (不要带单位):"
        read -p "(1/4) 触发阈值 [例如 100] (Mbps): " trig_mbps
        read -p "(2/4) 连续触发时长 [例如 5] (分钟): " trig_time
        read -p "(3/4) 惩罚限速值 [例如 5] (Mbps): " pun_mbps
        read -p "(4/4) 惩罚持续时长 [例如 60] (分钟): " pun_time
        trig_mbps=$(strip_cr "$trig_mbps"); trig_time=$(strip_cr "$trig_time")
        pun_mbps=$(strip_cr "$pun_mbps"); pun_time=$(strip_cr "$pun_time")
        
        # 统一校验所有输入是否为纯数字
        if [[ ! "$trig_mbps" =~ ^[0-9]+$ ]] || [[ ! "$trig_time" =~ ^[0-9]+$ ]] || \
           [[ ! "$pun_mbps" =~ ^[0-9]+$ ]] || [[ ! "$pun_time" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}错误: 所有参数必须为纯整数! 设置已取消。${PLAIN}"
            rm -f "$tmp"; sleep 2; return
        fi
        
        if jq --argjson tm "$trig_mbps" --argjson tt "$trig_time" \
              --argjson pm "$pun_mbps"  --argjson pt "$pun_time" \
              --arg p "$port" \
              '.ports[$p].dyn_limit = {
                  "enable": true, 
                  "trigger_mbps": $tm, 
                  "trigger_time": $tt, 
                  "punish_mbps": $pm, 
                  "punish_time": $pt, 
                  "strike_count": 0, 
                  "is_punished": false,
                  "punish_end_ts": 0
              } | .ports[$p].notify_state.punish_notified = false | .ports[$p].notify_state.recover_notified = true' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
              echo -e "${GREEN}动态策略已更新!${PLAIN}"
        else
              echo -e "${RED}写入失败，请检查配置文件权限。${PLAIN}"
        fi
    fi
    rm -f "$tmp"
    sleep 1
}

# ==============================================================================
# Telegram 通知配置菜单
# ==============================================================================

configure_telegram() {
    while true; do
        local tg_conf=$(jq '.telegram // {}' "$CONFIG_FILE")
        local tg_enable=$(echo "$tg_conf" | jq -r '.enable // false')
        local tg_token=$(echo "$tg_conf" | jq -r '.bot_token // ""')
        local tg_chat=$(echo "$tg_conf" | jq -r '.chat_id // ""')
        local tg_api=$(echo "$tg_conf" | jq -r '.api_url // "https://api.telegram.org"')
        local tg_thresholds=$(echo "$tg_conf" | jq -r '.thresholds // [50,80,100] | map(tostring) | join(", ")')
        local tg_report_hours=$(echo "$tg_conf" | jq -r '.report_interval_hours // 0')
        
        # 脱敏显示 Token
        local token_display="未配置"
        if [ -n "$tg_token" ] && [ ${#tg_token} -gt 10 ]; then
            token_display="${tg_token:0:6}...${tg_token: -4}"
        elif [ -n "$tg_token" ]; then
            token_display="已配置"
        fi
        
        clear
        echo -e "========================================"
        echo -e "   Telegram 通知配置"
        echo -e "========================================"
        if [ "$tg_enable" == "true" ]; then
            echo -e " 状态:   ${GREEN}✅ 已启用${PLAIN}"
        else
            echo -e " 状态:   ${YELLOW}⚪ 未启用${PLAIN}"
        fi
        echo -e " Token:  $token_display"
        echo -e " ChatID: ${tg_chat:-未配置}"
        echo -e " API:    $tg_api"
        echo -e " 阈值:   $tg_thresholds (%)"
        if [ "$tg_report_hours" -gt 0 ] 2>/dev/null; then
            echo -e " 定时报告: 每 ${GREEN}${tg_report_hours}${PLAIN} 小时"
        else
            echo -e " 定时报告: ${YELLOW}未开启${PLAIN}"
        fi
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
        read -p "请输入选项: " tg_choice
        tg_choice=$(strip_cr "$tg_choice")
        
        local tmp=$(mktemp)
        local success=false
        
        case $tg_choice in
            1)
                echo -e "\n从 @BotFather 获取 Bot Token"
                echo -e "格式示例: 123456789:ABCdefGhIJKlmNoPQRsTUVwxyz"
                read -p "Bot Token: " new_token
                new_token=$(strip_cr "$new_token")
                if [ -n "$new_token" ]; then
                    if jq --arg v "$new_token" '.telegram.bot_token = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                        echo -e "${GREEN}Token 已保存。${PLAIN}"; success=true
                    fi
                else
                    echo -e "${RED}输入不能为空!${PLAIN}"
                fi
                ;;
            2)
                echo -e "\n发送任意消息给 @userinfobot 获取 Chat ID"
                echo -e "群组 ID 为负数, 示例: -1001234567890"
                read -p "Chat ID: " new_chat
                new_chat=$(strip_cr "$new_chat")
                if [ -n "$new_chat" ]; then
                    if jq --arg v "$new_chat" '.telegram.chat_id = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                        echo -e "${GREEN}Chat ID 已保存。${PLAIN}"; success=true
                    fi
                else
                    echo -e "${RED}输入不能为空!${PLAIN}"
                fi
                ;;
            3)
                echo -e "\n${YELLOW}正在发送测试消息...${PLAIN}"
                # 临时强制启用发送
                local test_token=$(jq -r '.telegram.bot_token // ""' "$CONFIG_FILE")
                local test_chat=$(jq -r '.telegram.chat_id // ""' "$CONFIG_FILE")
                local test_api=$(jq -r '.telegram.api_url // "https://api.telegram.org"' "$CONFIG_FILE")
                
                if [ -z "$test_token" ] || [ -z "$test_chat" ]; then
                    echo -e "${RED}请先配置 Bot Token 和 Chat ID!${PLAIN}"
                else
                    local test_host=$(get_host_label)
                    local result=$(curl -sf --max-time 10 \
                        "${test_api}/bot${test_token}/sendMessage" \
                        -d chat_id="$test_chat" \
                        -d text="🔔 *测试通知*
🖥 主机: \`${test_host}\`
✅ Telegram 通知功能正常!" \
                        -d parse_mode="Markdown" 2>&1)
                    
                    if echo "$result" | jq -e '.ok == true' >/dev/null 2>&1; then
                        echo -e "${GREEN}✅ 发送成功! 请检查 Telegram。${PLAIN}"
                        # 如果通知未启用，提醒并提供一键开启
                        if [ "$tg_enable" != "true" ]; then
                            echo -e "\n${RED}⚠️  注意: 通知功能当前未开启!${PLAIN}"
                            echo -e "${YELLOW}   测试消息可以发送，但配额预警/限速通知不会生效。${PLAIN}"
                            read -p "   是否立即开启通知? [Y/n] " auto_enable
                            auto_enable=$(strip_cr "$auto_enable")
                            if [[ ! "$auto_enable" =~ ^[nN] ]]; then
                                local tmp_en=$(mktemp)
                                if jq '.telegram.enable = true' "$CONFIG_FILE" > "$tmp_en" && safe_write_config_from_file "$tmp_en"; then
                                    echo -e "${GREEN}   ✅ 通知已开启${PLAIN}"
                                    tg_enable="true"  # 更新循环变量
                                fi
                                rm -f "$tmp_en"
                            fi
                        fi
                    else
                        local err_desc=$(echo "$result" | jq -r '.description // "连接失败或超时"' 2>/dev/null)
                        echo -e "${RED}❌ 发送失败: $err_desc${PLAIN}"
                        echo -e "${YELLOW}提示: 如果在国内服务器，请配置 API 反代地址 (选项6)${PLAIN}"
                    fi
                fi
                ;;
            4)
                local new_state="true"
                [ "$tg_enable" == "true" ] && new_state="false"
                
                # 开启前检查配置完整性
                if [ "$new_state" == "true" ]; then
                    if [ -z "$tg_token" ] || [ -z "$tg_chat" ]; then
                        echo -e "${RED}请先配置 Bot Token 和 Chat ID!${PLAIN}"
                        sleep 1; rm -f "$tmp"; continue
                    fi
                fi
                
                if jq --argjson v "$new_state" '.telegram.enable = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                    if [ "$new_state" == "true" ]; then
                        echo -e "${GREEN}✅ 通知已开启${PLAIN}"
                    else
                        echo -e "${YELLOW}⚪ 通知已关闭${PLAIN}"
                    fi
                    success=true
                fi
                ;;
            5)
                echo -e "\n当前阈值: $tg_thresholds (%)"
                echo -e "输入新阈值 (逗号分隔, 例如: 50,80,100)"
                read -p "阈值: " new_thr
                new_thr=$(strip_cr "$new_thr")
                if [ -n "$new_thr" ]; then
                    # 清洗输入: 去空格，转数组，过滤非法值
                    local thr_json=$(echo "$new_thr" | tr -d ' ' | tr ',' '\n' | awk '$1 ~ /^[0-9]+$/ && $1>0 && $1<=100' | sort -n -u | jq -R 'tonumber' | jq -s '.')
                    if [ "$(echo "$thr_json" | jq 'length')" -gt 0 ]; then
                        if jq --argjson v "$thr_json" '.telegram.thresholds = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                            echo -e "${GREEN}阈值已更新: $(echo $thr_json | jq -r 'map(tostring) | join(", ")')%${PLAIN}"
                            success=true
                        fi
                    else
                        echo -e "${RED}无有效阈值! 请输入 1-100 之间的整数。${PLAIN}"
                    fi
                fi
                ;;
            6)
                echo -e "\n当前 API 地址: $tg_api"
                echo -e "国内推荐反代示例: https://tg.example.com"
                echo -e "留空则恢复默认: https://api.telegram.org"
                read -p "新地址: " new_api
                new_api=$(strip_cr "$new_api")
                [ -z "$new_api" ] && new_api="https://api.telegram.org"
                # 去掉末尾斜杠
                new_api="${new_api%/}"
                if jq --arg v "$new_api" '.telegram.api_url = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                    echo -e "${GREEN}API 地址已更新: $new_api${PLAIN}"
                    success=true
                fi
                ;;
            7)
                echo -e "\n当前定时报告: $([ "$tg_report_hours" -gt 0 ] 2>/dev/null && echo "每 ${tg_report_hours} 小时" || echo "未开启")"
                echo -e "输入间隔小时数 (1-168), 0 为关闭"
                read -p "间隔 (小时): " rpt_hours
                rpt_hours=$(strip_cr "$rpt_hours")
                if [[ "$rpt_hours" =~ ^[0-9]+$ ]] && [ "$rpt_hours" -le 168 ]; then
                    if jq --argjson v "$rpt_hours" '.telegram.report_interval_hours = $v | .telegram.last_report_ts = 0' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                        if [ "$rpt_hours" -eq 0 ]; then
                            echo -e "${GREEN}定时报告已关闭。${PLAIN}"
                        else
                            echo -e "${GREEN}已设置每 ${rpt_hours} 小时发送流量报告。${PLAIN}"
                        fi
                        success=true
                    fi
                else
                    echo -e "${RED}错误: 请输入 0-168 之间的整数!${PLAIN}"; sleep 1
                fi
                ;;
            0)
                rm -f "$tmp"; break
                ;;
        esac
        
        rm -f "$tmp"
        [ "$success" == "true" ] && sleep 0.5 || sleep 1.5
    done
}

# ==============================================================================
# 云端推送配置菜单 (Cloudflare D1)
# ==============================================================================

configure_push() {
    while true; do
        local push_conf=$(jq '.push // {}' "$CONFIG_FILE")
        local push_enable=$(echo "$push_conf" | jq -r '.enable // false')
        local push_url=$(echo "$push_conf" | jq -r '.worker_url // ""')
        local push_secret=$(echo "$push_conf" | jq -r '.secret // ""')
        local push_node=$(echo "$push_conf" | jq -r '.node_key // ""')

        # 脱敏显示
        local secret_display="未配置"
        if [ -n "$push_secret" ] && [ ${#push_secret} -gt 10 ]; then
            secret_display="${push_secret:0:6}...${push_secret: -4}"
        elif [ -n "$push_secret" ]; then
            secret_display="已配置"
        fi

        clear
        echo -e "========================================"
        echo -e "   云端推送配置 (Cloudflare D1)"
        echo -e "========================================"
        if [ "$push_enable" == "true" ]; then
            echo -e " 状态:    ${GREEN}✅ 已启用${PLAIN}"
        else
            echo -e " 状态:    ${YELLOW}⚪ 未启用${PLAIN}"
        fi
        echo -e " Worker:  ${push_url:-未配置}"
        echo -e " 密钥:    $secret_display"
        echo -e " 节点 Key: ${push_node:-未配置}"
        echo -e "========================================"
        echo -e " 1. 配置 Worker URL"
        echo -e " 2. 配置 通信密钥"
        echo -e " 3. 配置 节点 Key (如 hk, us, sg)"
        echo -e " 4. 开启/关闭 推送"
        echo -e " 5. 测试推送"
        echo -e " 0. 返回主菜单"
        echo -e "========================================"
        read -p "请输入选项: " p_choice
        p_choice=$(strip_cr "$p_choice")

        local tmp=$(mktemp)
        local success=false

        case $p_choice in
            1)
                echo -e "\n输入 Worker 推送地址"
                echo -e "格式: https://your-worker.your-domain.workers.dev/api/push"
                read -p "URL: " new_url
                new_url=$(strip_cr "$new_url")
                new_url="${new_url%/}"
                if [ -n "$new_url" ]; then
                    if jq --arg v "$new_url" '.push.worker_url = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                        echo -e "${GREEN}URL 已保存。${PLAIN}"; success=true
                    fi
                else
                    echo -e "${RED}输入不能为空!${PLAIN}"
                fi
                ;;
            2)
                echo -e "\n输入通信密钥 (必须与 Worker 环境变量 SHARED_SECRET 一致)"
                echo -e "建议: 使用 openssl rand -hex 32 生成"
                read -p "密钥: " new_secret
                new_secret=$(strip_cr "$new_secret")
                if [ -n "$new_secret" ]; then
                    if jq --arg v "$new_secret" '.push.secret = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                        echo -e "${GREEN}密钥已保存。${PLAIN}"; success=true
                    fi
                else
                    echo -e "${RED}输入不能为空!${PLAIN}"
                fi
                ;;
            3)
                echo -e "\n输入节点标识 (简短英文, 如 hk, us, sg, jp)"
                read -p "Node Key: " new_node
                new_node=$(strip_cr "$new_node")
                new_node=$(echo "$new_node" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
                if [ -n "$new_node" ]; then
                    if jq --arg v "$new_node" '.push.node_key = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                        echo -e "${GREEN}节点 Key 已保存: $new_node${PLAIN}"; success=true
                    fi
                else
                    echo -e "${RED}输入不能为空!${PLAIN}"
                fi
                ;;
            4)
                local new_state="true"
                [ "$push_enable" == "true" ] && new_state="false"

                if [ "$new_state" == "true" ]; then
                    if [ -z "$push_url" ] || [ -z "$push_secret" ] || [ -z "$push_node" ]; then
                        echo -e "${RED}请先配置 Worker URL、密钥和节点 Key!${PLAIN}"
                        sleep 1; rm -f "$tmp"; continue
                    fi
                    # 检查 openssl 是否可用 (签名依赖)
                    if ! command -v openssl &>/dev/null; then
                        echo -e "${RED}错误: 推送功能需要 openssl, 请安装后重试!${PLAIN}"
                        echo -e "${YELLOW}  Debian/Ubuntu: apt install openssl${PLAIN}"
                        echo -e "${YELLOW}  CentOS/RHEL:   yum install openssl${PLAIN}"
                        echo -e "${YELLOW}  Alpine:         apk add openssl${PLAIN}"
                        sleep 3; rm -f "$tmp"; continue
                    fi
                fi

                if jq --argjson v "$new_state" '.push.enable = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                    if [ "$new_state" == "true" ]; then
                        echo -e "${GREEN}✅ 推送已开启 (下次 Cron 周期生效)${PLAIN}"
                    else
                        echo -e "${YELLOW}⚪ 推送已关闭${PLAIN}"
                    fi
                    success=true
                fi
                ;;
            5)
                echo -e "\n${YELLOW}正在测试推送...${PLAIN}"
                local t_url=$(jq -r '.push.worker_url // ""' "$CONFIG_FILE")
                local t_secret=$(jq -r '.push.secret // ""' "$CONFIG_FILE")
                local t_node=$(jq -r '.push.node_key // ""' "$CONFIG_FILE")

                if [ -z "$t_url" ] || [ -z "$t_secret" ] || [ -z "$t_node" ]; then
                    echo -e "${RED}请先完成所有配置!${PLAIN}"; sleep 1; rm -f "$tmp"; continue
                fi

                if ! command -v openssl &>/dev/null; then
                    echo -e "${RED}错误: 未安装 openssl!${PLAIN}"; sleep 1; rm -f "$tmp"; continue
                fi

                local t_payload=$(jq '{node_id, interface, ports}' "$CONFIG_FILE" 2>/dev/null)
                local t_ts=$(date +%s)
                local t_sig=$(printf '%s%s' "$t_ts" "$t_payload" | openssl dgst -sha256 -hmac "$t_secret" 2>/dev/null | awk '{print $NF}')

                local t_http_code=$(curl -sf --max-time 10 -o /dev/null -w "%{http_code}" \
                    -X PUT "$t_url" \
                    -H "Content-Type: application/json" \
                    -H "X-Node: $t_node" \
                    -H "X-Timestamp: $t_ts" \
                    -H "X-Signature: $t_sig" \
                    -d "$t_payload" 2>&1)

                if [ "$t_http_code" == "200" ]; then
                    echo -e "${GREEN}✅ 推送成功! (HTTP $t_http_code)${PLAIN}"
                elif [ "$t_http_code" == "403" ]; then
                    echo -e "${RED}❌ 签名验证失败 (HTTP 403), 请检查密钥是否一致!${PLAIN}"
                elif [ "$t_http_code" == "000" ]; then
                    echo -e "${RED}❌ 连接失败, 请检查 Worker URL 是否正确!${PLAIN}"
                else
                    echo -e "${RED}❌ 推送失败 (HTTP $t_http_code)${PLAIN}"
                fi
                ;;
            0)
                rm -f "$tmp"; break ;;
        esac

        rm -f "$tmp"
        [ "$success" == "true" ] && sleep 0.5 || sleep 1.5
    done
}

delete_port_flow() {
    local arr=("$@")
    read -p "请输入要删除的端口 ID: " id
    id=$(strip_cr "$id")
    if [[ ! "$id" =~ ^[0-9]+$ ]] || [ "$id" -le 0 ]; then return; fi
    local port=${arr[$((id-1))]}
    if [ -z "$port" ]; then return; fi
    
    read -p "确定删除端口 $port 监控吗? [y/N]: " confirm
    confirm=$(strip_cr "$confirm")
    if [[ "$confirm" == "y" ]]; then
        # 1. 优先解封
        nft delete element $NFT_TABLE blocked_ports \{ $port \} 2>/dev/null
        
        # 2. 删除 TC 规则 (使用 Hex, IPv4 + IPv6)
        local port_hex=$(printf '%x' $port)
        local iface=$(jq -r '.interface' "$CONFIG_FILE")
        [ -z "$iface" ] && iface=$(get_iface)
        tc filter del dev "$iface" parent 1: protocol ip prio 1 handle 0x$port_hex fw 2>/dev/null
        tc filter del dev "$iface" parent 1: protocol ipv6 prio 1 handle 0x$port_hex fw 2>/dev/null
        tc class del dev "$iface" parent 1: classid 1:$port_hex 2>/dev/null
        
        # 3. 删除 Config
        local tmp=$(mktemp)
        jq "del(.ports[\"$port\"])" "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp" && rm -f "$tmp"
        
        # 4. 彻底刷新
        reload_all_rules
        echo -e "${GREEN}删除完成。${PLAIN}"; sleep 1
    fi
}

update_script() {
    echo
    echo -e " ${BLUE}>>> 更新管理脚本${PLAIN}"
    echo -e " 当前版本: v${SCRIPT_VERSION}"
    echo -e " 远程地址: ${DOWNLOAD_URL}"
    echo

    local tmp_script=$(mktemp /tmp/pm_update.XXXXXX.sh)
    _CLEANUP_FILES+=("$tmp_script")

    if ! curl -fsSL --max-time 15 "$DOWNLOAD_URL" -o "$tmp_script" 2>/dev/null; then
        echo -e "${RED}下载失败，请检查网络。${PLAIN}"
        rm -f "$tmp_script"
        sleep 2
        return
    fi

    # 提取远程版本号
    local remote_ver=$(grep '^SCRIPT_VERSION=' "$tmp_script" | head -1 | cut -d'"' -f2)

    if [ -z "$remote_ver" ]; then
        echo -e "${YELLOW}无法解析远程版本号，继续更新...${PLAIN}"
    elif [ "$remote_ver" == "$SCRIPT_VERSION" ]; then
        echo -e "${GREEN}已是最新版本 (v${SCRIPT_VERSION})，无需更新。${PLAIN}"
        rm -f "$tmp_script"
        sleep 1
        return
    else
        echo -e " 发现新版本: ${GREEN}v${remote_ver}${PLAIN}"
    fi

    mv -f "$tmp_script" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    echo -e "${GREEN}脚本已更新完成! 正在重新加载...${PLAIN}"
    echo
    exec "$INSTALL_PATH"
}

uninstall_script() {
    echo -e "${RED}!!! 危险操作警告 !!!${PLAIN}"
    read -p "确定要彻底卸载 (清除规则、停止服务、删除文件)? (输入 yes 确认): " confirm
    confirm=$(strip_cr "$confirm")
    if [[ "${confirm,,}" == "yes" ]]; then
        # 1. 停服务
        crontab -l 2>/dev/null | grep -vF "$INSTALL_PATH --monitor" | crontab -
        stop_edit_lock
        
        # 2. 清内核
        local iface=$(get_iface)
        if [ -n "$iface" ] && tc qdisc show dev "$iface" | grep -q "htb 1:"; then
            tc qdisc del dev "$iface" root handle 1: htb 2>/dev/null
        fi
        nft delete table $NFT_TABLE 2>/dev/null
        
        # 3. 删文件
        rm -rf "$CONFIG_DIR"
        rm -f "$LOCK_FILE"
        rm -f "$CRON_LOCK_FILE"
        rm -f "$USER_EDIT_LOCK"
        rm -f "$INSTALL_PATH"
        
        echo -e "${GREEN}卸载完成。${PLAIN}"
        exit 0
    fi
}

# ==============================================================================
# 入口逻辑
# ==============================================================================
check_root
install_shortcut "${1:-}"
install_deps

if [ "${1:-}" == "--monitor" ]; then
    cron_task
elif [ "${1:-}" == "update" ]; then
    update_script
else
    setup_cron
    _IS_MENU_MODE=true
    # 使用循环代替递归调用，防止长时间使用导致栈溢出
    while true; do
        show_main_menu
    done
fi