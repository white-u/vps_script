#!/bin/bash

# ==============================================================================
# Linux 端口流量管理脚本 (Port Monitor & Shaper)
# 版本: v2.1 (Fix: Alpine兼容性, 服务发现解析优化)
# ==============================================================================

# --- 全局配置 ---
SHORTCUT_NAME="pm"
INSTALL_PATH="/usr/local/bin/$SHORTCUT_NAME"
DOWNLOAD_URL="https://raw.githubusercontent.com/white-u/vps_script/main/pm.sh"

CONFIG_DIR="/etc/port_monitor"
CONFIG_FILE="$CONFIG_DIR/config.json"
LOCK_FILE="/var/run/pm.lock"
NFT_TABLE="inet port_monitor"
SCRIPT_PATH=$(readlink -f "$0")

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

# ==============================================================================
# 1. 基础架构模块 (Infrastructure)
# ==============================================================================

check_root() {
    [[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 权限运行此脚本。${PLAIN}" && exit 1
}

get_iface() {
    ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n 1
}

install_deps() {
    # 检查命令是否存在
    local deps=("nft" "tc" "jq" "bc" "curl" "ss" "numfmt")
    local missing=false
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then missing=true; break; fi
    done

    if [ "$missing" = true ]; then
        echo -e "${YELLOW}正在自动安装依赖...${PLAIN}"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case $ID in
                debian|ubuntu)
                    apt-get update && apt-get install -y nftables iproute2 jq bc curl coreutils ;;
                centos|rhel|almalinux|rocky)
                    yum install -y nftables iproute tc jq bc curl coreutils ;;
                alpine)
                    # Alpine 需要 coreutils(含numfmt) 和 iproute2(含ss/tc)
                    apk add nftables iproute2 jq bc curl coreutils ;;
                *)
                    echo -e "${RED}不支持的系统，请手动安装: nftables iproute2 jq bc curl coreutils${PLAIN}" && exit 1 ;;
            esac
        fi
    fi

    # 初始化配置
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
        echo "{\"interface\": \"$(get_iface)\", \"ports\": {}}" > "$CONFIG_FILE"
    fi
}

install_shortcut() {
    # 只有当脚本不在安装路径，且不是由cron调用时才安装快捷指令
    if [[ "$0" != "$INSTALL_PATH" ]] && [[ "$1" != "--monitor" ]]; then
        echo -e "${YELLOW}正在安装快捷指令 '$SHORTCUT_NAME'...${PLAIN}"
        cp "$0" "$INSTALL_PATH"
        chmod +x "$INSTALL_PATH"
        echo -e "${GREEN}安装成功! 以后输入 '$SHORTCUT_NAME' 即可使用。${PLAIN}"
        sleep 1
        exec "$INSTALL_PATH"
    fi
}

# ==============================================================================
# 2. 网络引擎模块 (Network Engine)
# ==============================================================================

init_nft_table() {
    nft list table $NFT_TABLE &>/dev/null
    if [ $? -ne 0 ]; then
        nft add table $NFT_TABLE
        nft add set $NFT_TABLE blocked_ports { type inet_service\; }
        nft add chain $NFT_TABLE input { type filter hook input priority 0\; }
        nft add chain $NFT_TABLE output { type filter hook output priority 0\; }
        # 阻断规则 (最高优先级)
        nft add rule $NFT_TABLE input meta l4proto { tcp, udp } dport @blocked_ports drop
        nft add rule $NFT_TABLE output meta l4proto { tcp, udp } sport @blocked_ports drop
        return 0
    fi
    return 1
}

init_tc_root() {
    local iface=$(jq -r '.interface' "$CONFIG_FILE")
    # 检查是否存在 HTB root
    if ! tc qdisc show dev "$iface" | grep -q "htb 1:"; then
        # 创建根队列，默认流量走 1:10 (未监控流量不限速)
        tc qdisc add dev "$iface" root handle 1: htb default 10
        # 默认类: 1Gbps
        tc class add dev "$iface" parent 1: classid 1:10 htb rate 1000mbit
    fi
}

apply_port_rules() {
    local port=$1
    local conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
    local limit_mbps=$(echo "$conf" | jq -r '.limit_mbps // 0')
    local iface=$(jq -r '.interface' "$CONFIG_FILE")
    
    # 动态限速检查: 如果处于惩罚状态，覆盖限速值
    local is_punished=$(echo "$conf" | jq -r '.dyn_limit.is_punished // false')
    if [ "$is_punished" == "true" ]; then
        local punish_val=$(echo "$conf" | jq -r '.dyn_limit.punish_mbps // 50')
        limit_mbps=$punish_val
    fi

    init_nft_table
    init_tc_root

    # 1. NFT 计数器
    nft add counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null
    nft add counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null

    # 2. NFT 规则 (监控 + 打标)
    if ! nft list chain $NFT_TABLE input | grep -q "dport $port"; then
        nft add rule $NFT_TABLE input meta l4proto { tcp, udp } dport $port counter name "cnt_in_${port}"
    fi
    if ! nft list chain $NFT_TABLE output | grep -q "sport $port"; then
        # 统计 + Mark (用于TC分类，mark值等于端口号)
        nft add rule $NFT_TABLE output meta l4proto { tcp, udp } sport $port counter name "cnt_out_${port}" meta mark set $port
    fi

    # 3. TC 规则 (隔离限速)
    # 清理旧规则
    tc filter del dev "$iface" parent 1: protocol ip prio 1 handle $port fw 2>/dev/null
    tc class del dev "$iface" parent 1: classid 1:$port 2>/dev/null

    # 应用新限速
    if [ "$limit_mbps" != "0" ] && [ -n "$limit_mbps" ]; then
        tc class add dev "$iface" parent 1: classid 1:$port htb rate "${limit_mbps}mbit"
        tc filter add dev "$iface" parent 1: protocol ip prio 1 handle $port fw flowid 1:$port
    fi
}

reload_all_rules() {
    init_nft_table
    local ports=$(jq -r '.ports | keys[]' "$CONFIG_FILE")
    for port in $ports; do
        apply_port_rules "$port"
    done
}

# ==============================================================================
# 3. 核心守护进程 (The Watchdog) - Crontab 任务
# ==============================================================================

safe_write_config() {
    local content="$1"
    (
        flock -x 200
        echo "$content" > "$CONFIG_FILE"
    ) 200>"$LOCK_FILE"
}

cron_task() {
    # 自愈: 检查 NFT 表是否存在 (防止重启失效)
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
        
        # 统计数据读取
        local acc_in=$(echo "$p_conf" | jq -r '.stats.acc_in // 0')
        local acc_out=$(echo "$p_conf" | jq -r '.stats.acc_out // 0')
        local last_k_in=$(echo "$p_conf" | jq -r '.stats.last_kernel_in // 0')
        local last_k_out=$(echo "$p_conf" | jq -r '.stats.last_kernel_out // 0')

        # 获取内核当前值
        local curr_k_in=$(nft -j list counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null | jq -r '.nftables[0].counter.bytes // 0')
        local curr_k_out=$(nft -j list counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null | jq -r '.nftables[0].counter.bytes // 0')

        # --- Sync 算法 ---
        # 如果当前值 < 上次值，说明重启过，delta = 当前值
        local delta_in=$(echo "if ($curr_k_in < $last_k_in) $curr_k_in else $curr_k_in - $last_k_in" | bc)
        local delta_out=$(echo "if ($curr_k_out < $last_k_out) $curr_k_out else $curr_k_out - $last_k_out" | bc)
        
        acc_in=$(echo "$acc_in + $delta_in" | bc)
        acc_out=$(echo "$acc_out + $delta_out" | bc)

        # 更新 JSON 对象
        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].stats.acc_in = $acc_in | .ports[\"$port\"].stats.acc_out = $acc_out | .ports[\"$port\"].stats.last_kernel_in = $curr_k_in | .ports[\"$port\"].stats.last_kernel_out = $curr_k_out")
        modified=true

        # --- Dynamic QoS 算法 ---
        local dyn_enable=$(echo "$p_conf" | jq -r '.dyn_limit.enable // false')
        if [ "$dyn_enable" == "true" ]; then
            local dyn_trigger=$(echo "$p_conf" | jq -r '.dyn_limit.trigger_mbps')
            local dyn_trig_time=$(echo "$p_conf" | jq -r '.dyn_limit.trigger_time')
            local dyn_punish_time=$(echo "$p_conf" | jq -r '.dyn_limit.punish_time')
            
            local strike=$(echo "$p_conf" | jq -r '.dyn_limit.strike_count // 0')
            local is_punished=$(echo "$p_conf" | jq -r '.dyn_limit.is_punished // false')
            local end_ts=$(echo "$p_conf" | jq -r '.dyn_limit.punish_end_ts // 0')

            # 计算本分钟速率 (Mbps)
            local current_mbps=$(echo "scale=2; ($delta_in + $delta_out) * 8 / 60 / 1024 / 1024" | bc)
            local rule_changed=false

            if [ "$is_punished" == "true" ]; then
                # 惩罚中 -> 检查是否刑满
                if [ "$current_ts" -ge "$end_ts" ]; then
                    is_punished="false"
                    strike=0
                    tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.is_punished = false | .ports[\"$port\"].dyn_limit.strike_count = 0")
                    rule_changed=true
                fi
            else
                # 正常中 -> 检查是否超速
                if [ $(echo "$current_mbps > $dyn_trigger" | bc) -eq 1 ]; then
                    strike=$((strike + 1))
                    if [ "$strike" -ge "$dyn_trig_time" ]; then
                        # 触发惩罚
                        is_punished="true"
                        end_ts=$((current_ts + dyn_punish_time * 60))
                        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.is_punished = true | .ports[\"$port\"].dyn_limit.punish_end_ts = $end_ts")
                        rule_changed=true
                    else
                        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.strike_count = $strike")
                    fi
                else
                    # 速度正常，重置连续计数
                    if [ "$strike" -gt 0 ]; then
                        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.strike_count = 0")
                    fi
                fi
            fi
            
            if [ "$rule_changed" == "true" ]; then
                safe_write_config "$tmp_json"
                apply_port_rules "$port"
                tmp_json=$(cat "$CONFIG_FILE") # 重新读取最新
            fi
        fi

        # --- Quota 算法 ---
        local total_usage=0
        if [ "$mode" == "out_only" ]; then
            total_usage=$acc_out
        else
            total_usage=$(echo "$acc_in + $acc_out" | bc)
        fi
        
        local quota_bytes=$(echo "$quota_gb * 1024 * 1024 * 1024" | bc)
        local is_blocked_nft=$(nft list set $NFT_TABLE blocked_ports | grep -q "$port" && echo "yes" || echo "no")

        if (( $(echo "$total_usage > $quota_bytes" | bc -l) )); then
            [ "$is_blocked_nft" == "no" ] && nft add element $NFT_TABLE blocked_ports \{ $port \}
        else
            [ "$is_blocked_nft" == "yes" ] && nft delete element $NFT_TABLE blocked_ports \{ $port \}
        fi
    done

    if [ "$modified" == "true" ]; then
        safe_write_config "$tmp_json"
    fi
}

setup_cron() {
    # 修正路径指向安装位置
    if ! crontab -l 2>/dev/null | grep -q "$INSTALL_PATH --monitor"; then
        (crontab -l 2>/dev/null; echo "* * * * * $INSTALL_PATH --monitor") | crontab -
    fi
}

# ==============================================================================
# 4. 服务发现与扫描 (Service Discovery)
# ==============================================================================

scan_active_services() {
    echo -e "${YELLOW}正在扫描系统活跃服务...${PLAIN}"
    # 修正: 使用 sed 提取进程名，兼容 BusyBox awk
    local scan_res=$(ss -lntuH | awk '{
        n = split($5, addr, ":")
        port = addr[n]
        proto = $1
        # 将整行传给 sed 提取进程名
        print port "/" proto " " $0
    }' | sed -E 's/.*users:\(\("([^"]+)".*/\1/' | awk '{print $1 " " $NF}' | sort -u -k1,1)

    echo "$scan_res"
}

# ==============================================================================
# 5. UI 交互模块 (User Interface)
# ==============================================================================

fmt_bytes() {
    local bytes=$1
    if [ -z "$bytes" ] || [ "$bytes" == "0" ]; then echo "0B"; return; fi
    numfmt --to=iec --suffix=B "$bytes"
}

show_main_menu() {
    clear
    echo -e "====================================================================================="
    echo -e "   Linux 端口流量管理 (快捷指令: $SHORTCUT_NAME)"
    echo -e "====================================================================================="
    printf " %-4s %-12s %-10s %-25s %-15s %-15s\n" "ID" "端口" "模式" "已用流量 / 总配额" "出站限速" "备注"
    echo -e "-------------------------------------------------------------------------------------"

    local port_list=()
    local i=1
    local ports=$(jq -r '.ports | keys[]' "$CONFIG_FILE" | sort -n)

    for port in $ports; do
        local conf=$(jq -r ".ports[\"$port\"]" "$CONFIG_FILE")
        local mode=$(echo "$conf" | jq -r '.quota_mode')
        local limit=$(echo "$conf" | jq -r '.limit_mbps')
        local comment=$(echo "$conf" | jq -r '.comment')
        local quota=$(echo "$conf" | jq -r '.quota_gb')
        
        local acc_in=$(echo "$conf" | jq -r '.stats.acc_in // 0')
        local acc_out=$(echo "$conf" | jq -r '.stats.acc_out // 0')
        
        local mode_str="[双向]"
        local total_used=0
        if [ "$mode" == "out_only" ]; then
            mode_str="[仅出站]"
            total_used=$acc_out
        else
            total_used=$(echo "$acc_in + $acc_out" | bc)
        fi
        
        local status_str=""
        if nft list set $NFT_TABLE blocked_ports 2>/dev/null | grep -q "$port"; then
            status_str="${RED}[已阻断]${PLAIN}"
        else
            status_str="$(fmt_bytes $total_used)"
        fi
        
        local is_punished=$(echo "$conf" | jq -r '.dyn_limit.is_punished // false')
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

        printf " [%d]  %-12s %-10s %-25s %-24s %-15s\n" $i "$port" "$mode_str" "${status_str} / ${quota} GB" "$limit_str" "$comment"
        port_list[$i]=$port
        ((i++))
    done
    echo -e "-------------------------------------------------------------------------------------"
    echo -e " 说明: [双向]=入站+出站计费  [仅出站]=仅出站计费  [已阻断]=流量超标\n"

    echo -e " 1. 添加 监控端口 (服务扫描)"
    echo -e " 2. 配置 端口 (修改/动态QoS/重置)"
    echo -e " 3. 删除 监控端口"
    echo -e " 4. 卸载 脚本"
    echo -e " 0. 退出"
    echo -e "====================================================================================="
    read -p "请输入选项: " choice
    
    case $choice in
        1) add_port_flow ;;
        2) config_port_menu "${port_list[@]}" ;;
        3) delete_port_flow "${port_list[@]}" ;;
        4) uninstall_script ;;
        0) exit 0 ;;
        *) show_main_menu ;;
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
        local p_proto=$(echo "$line" | awk '{print $1}')
        # 提取进程名 (处理可能的空格)
        local p_proc=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ //')
        [ -z "$p_proc" ] && p_proc="Unknown"
        local p_num=$(echo "$p_proto" | awk -F/ '{print $1}')
        
        local status="[可选]"
        if jq -e ".ports[\"$p_num\"]" "$CONFIG_FILE" >/dev/null; then
            status="${YELLOW}[已监控]${PLAIN}"
        fi
        
        printf " [%d]  %-15s %-25s %-10s\n" $idx "$p_proto" "$p_proc" "$status"
        map_ports[$idx]=$p_num
        ((idx++))
    done <<< "$scan_data"
    
    echo -e "----------------------------------------------------------------------"
    echo -e " [M]   手动输入端口号"
    echo -e " [0]   返回主菜单"
    echo -e "======================================================================"
    
    read -p "请输入选项: " sel
    local target_port=""
    
    if [ "$sel" == "0" ]; then show_main_menu; return; fi
    if [[ "$sel" =~ ^[0-9]+$ ]] && [ -n "${map_ports[$sel]}" ]; then
        target_port=${map_ports[$sel]}
        if jq -e ".ports[\"$target_port\"]" "$CONFIG_FILE" >/dev/null; then
            echo -e "${RED}该端口已在监控列表中! 请去配置菜单修改。${PLAIN}"
            sleep 2; show_main_menu; return
        fi
    elif [ "$sel" == "m" ] || [ "$sel" == "M" ]; then
        read -p "请输入端口号: " target_port
    else
        show_main_menu; return
    fi
    
    if [[ ! "$target_port" =~ ^[0-9]+$ ]] || [ "$target_port" -gt 65535 ]; then
        echo -e "${RED}无效端口${PLAIN}"; sleep 1; show_main_menu; return
    fi
    
    echo -e "\n>> 正在配置端口: $target_port"
    read -p "月流量配额 (GB): " quota
    echo "计费模式: 1.双向计费(默认)  2.仅出站计费"
    read -p "选择模式 [1/2]: " mode_idx
    local mode="in_out"
    [ "$mode_idx" == "2" ] && mode="out_only"
    
    read -p "出站限速 (Mbps, 0为不限速): " limit
    [ -z "$limit" ] && limit=0
    read -p "备注信息: " comment

    local tmp=$(mktemp)
    jq ".ports[\"$target_port\"] = {
        \"quota_gb\": $quota, 
        \"quota_mode\": \"$mode\", 
        \"limit_mbps\": $limit, 
        \"comment\": \"$comment\", 
        \"stats\": {\"acc_in\": 0, \"acc_out\": 0},
        \"dyn_limit\": {\"enable\": false}
    }" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)" && rm "$tmp"

    apply_port_rules "$target_port"
    echo -e "${GREEN}添加成功!${PLAIN}"
    sleep 1
    show_main_menu
}

config_port_menu() {
    local -n arr=$1
    echo -e "\n请输入要配置的端口 ID (查看上方列表): "
    read -p "ID > " id
    local port=${arr[$id]}
    if [ -z "$port" ]; then show_main_menu; return; fi
    
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
        
        clear
        echo -e "========================================"
        echo -e " 当前配置: [$id]  $port  $comment"
        echo -e "========================================"
        echo -e " [基础信息]"
        echo -e " 流量配额: $quota GB"
        echo -e " 计费模式: $([ "$mode" == "out_only" ] && echo "仅出站" || echo "双向")"
        echo -e " 基础限速: $([ "$limit" == "0" ] && echo "无限制" || echo "$limit Mbps")"
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
        echo -e " 0. 返回主菜单"
        echo -e "========================================"
        read -p "请输入选项: " sub_choice
        
        local tmp=$(mktemp)
        case $sub_choice in
            1) read -p "新配额 (GB): " val; jq ".ports[\"$port\"].quota_gb = $val" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)" ;;
            2) read -p "模式 (1.双向 2.仅出站): " m; local nm="in_out"; [ "$m" == "2" ] && nm="out_only"; jq ".ports[\"$port\"].quota_mode = \"$nm\"" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)" ;;
            3) read -p "新限速 (Mbps): " val; jq ".ports[\"$port\"].limit_mbps = $val" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)"; apply_port_rules "$port" ;;
            4) configure_dyn_qos "$port" ;;
            5) read -p "新备注: " val; jq ".ports[\"$port\"].comment = \"$val\"" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)" ;;
            6) 
                read -p "确定清零吗? [y/N]: " confirm
                if [[ "$confirm" == "y" ]]; then
                    local k_in=$(nft -j list counter $NFT_TABLE "cnt_in_${port}" | jq -r '.nftables[0].counter.bytes // 0')
                    local k_out=$(nft -j list counter $NFT_TABLE "cnt_out_${port}" | jq -r '.nftables[0].counter.bytes // 0')
                    jq ".ports[\"$port\"].stats.acc_in = 0 | .ports[\"$port\"].stats.acc_out = 0 | .ports[\"$port\"].stats.last_kernel_in = $k_in | .ports[\"$port\"].stats.last_kernel_out = $k_out" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)"
                    nft delete element $NFT_TABLE blocked_ports \{ $port \} 2>/dev/null
                    echo "已重置。"
                fi 
                ;;
            0) rm "$tmp"; break ;;
        esac
        rm "$tmp" 2>/dev/null
    done
    show_main_menu
}

configure_dyn_qos() {
    local port=$1
    local tmp=$(mktemp)
    
    echo -e "\n--- 配置动态突发限制 (Dynamic QoS) ---"
    echo -e "说明: 可设置连续一段时间高占用后，自动触发临时限速惩罚。"
    echo -e "1. 启用此功能"
    echo -e "2. 禁用此功能"
    echo -e "0. 取消"
    read -p "请选择: " qos_sel
    
    if [ "$qos_sel" == "2" ]; then
        jq ".ports[\"$port\"].dyn_limit.enable = false" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)"
        echo "已禁用。"
    elif [ "$qos_sel" == "1" ]; then
        read -p "(1/4) 触发阈值 (Mbps): " trig_mbps
        read -p "(2/4) 连续触发时长 (分钟): " trig_time
        read -p "(3/4) 惩罚限速值 (Mbps): " pun_mbps
        read -p "(4/4) 惩罚持续时长 (分钟): " pun_time
        
        jq ".ports[\"$port\"].dyn_limit = {
            \"enable\": true,
            \"trigger_mbps\": $trig_mbps,
            \"trigger_time\": $trig_time,
            \"punish_mbps\": $pun_mbps,
            \"punish_time\": $pun_time,
            \"strike_count\": 0,
            \"is_punished\": false
        }" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)"
        echo -e "${GREEN}动态策略已更新!${PLAIN}"
    fi
    rm "$tmp"
    sleep 1
}

delete_port_flow() {
    local -n arr=$1
    read -p "请输入要删除的端口 ID: " id
    local port=${arr[$id]}
    if [ -z "$port" ]; then show_main_menu; return; fi
    
    read -p "确定删除端口 $port 监控吗? [y/N]: " confirm
    if [[ "$confirm" == "y" ]]; then
        local tmp=$(mktemp)
        jq "del(.ports[\"$port\"])" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)" && rm "$tmp"
        local iface=$(jq -r '.interface' "$CONFIG_FILE")
        tc filter del dev "$iface" parent 1: protocol ip prio 1 handle $port fw 2>/dev/null
        tc class del dev "$iface" parent 1: classid 1:$port 2>/dev/null
        reload_all_rules
        echo -e "${GREEN}删除完成。${PLAIN}"; sleep 1
    fi
    show_main_menu
}

uninstall_script() {
    echo -e "${RED}!!! 危险操作警告 !!!${PLAIN}"
    read -p "确定要卸载 (删除脚本/规则/配置) 吗? [y/N]: " confirm
    if [[ "$confirm" == "y" ]]; then
        crontab -l | grep -v "$INSTALL_PATH" | crontab -
        local iface=$(jq -r '.interface' "$CONFIG_FILE")
        tc qdisc del dev "$iface" root handle 1: htb 2>/dev/null
        nft delete table $NFT_TABLE 2>/dev/null
        rm -rf "$CONFIG_DIR"
        rm -f "$INSTALL_PATH"
        echo -e "${GREEN}卸载完成。${PLAIN}"
        exit 0
    fi
    show_main_menu
}

# ==============================================================================
# 入口逻辑
# ==============================================================================
check_root
install_deps
install_shortcut "$1"

if [ "$1" == "--monitor" ]; then
    cron_task
else
    setup_cron
    show_main_menu
fi