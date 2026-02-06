#!/bin/bash

# ==============================================================================
# Linux 端口流量管理脚本 (Port Monitor & Shaper)
# 版本: v3.5 Final (修复安装路径、环境路径、数值格式、TC进制溢出)
# ==============================================================================

# --- 全局配置 ---
SHORTCUT_NAME="pm"
INSTALL_PATH="/usr/local/bin/$SHORTCUT_NAME"
# 这是脚本自我修复和安装的源，请确保可访问
DOWNLOAD_URL="https://raw.githubusercontent.com/white-u/vps_script/main/vps.sh"

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
PLAIN='\033[0m'

# ==============================================================================
# 1. 基础架构 (安装与自检)
# ==============================================================================

check_root() {
    [[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 权限运行。${PLAIN}" && exit 1
}

# 智能安装逻辑：兼容管道运行和本地运行
install_shortcut() {
    # 排除条件：不是由 Cron 调用 且 (当前不在安装位置 或 文件不存在)
    if [[ "$1" != "--monitor" ]] && [[ "$0" != "$INSTALL_PATH" ]]; then
        echo -e "${YELLOW}正在初始化系统环境...${PLAIN}"
        
        # 强制从网络下载最新版到安装目录 (解决 curl | bash 导致的 $0 丢失问题)
        curl -fsSL "$DOWNLOAD_URL" -o "$INSTALL_PATH" 2>/dev/null
        
        # 验证下载完整性
        if [ -s "$INSTALL_PATH" ]; then
            chmod +x "$INSTALL_PATH"
            echo -e "${GREEN}安装成功! 快捷指令: $SHORTCUT_NAME${PLAIN}"
            echo -e "${GREEN}正在启动管理面板...${PLAIN}"
            sleep 1
            # 移交控制权给安装好的脚本
            exec "$INSTALL_PATH" "$@"
        else
            # 降级策略：如果网络下载失败，尝试本地复制
            if [ -f "$0" ]; then
                echo -e "${YELLOW}网络下载失败，尝试本地安装...${PLAIN}"
                cp "$0" "$INSTALL_PATH" && chmod +x "$INSTALL_PATH"
                exec "$INSTALL_PATH" "$@"
            else
                echo -e "${RED}致命错误: 安装失败，请检查网络连接。${PLAIN}"
                exit 1
            fi
        fi
    fi
}

get_iface() {
    ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n 1
}

install_deps() {
    local deps=("nft" "tc" "jq" "bc" "curl" "ss" "numfmt" "flock")
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
                    apk add --no-cache nftables iproute2 jq bc curl coreutils util-linux ;;
                *)
                    echo -e "${RED}系统不受支持，请手动安装依赖。${PLAIN}" && exit 1 ;;
            esac
        fi
    fi

    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
        echo "{\"interface\": \"$(get_iface)\", \"ports\": {}}" > "$CONFIG_FILE"
    fi
}

# ==============================================================================
# 2. 网络引擎 (Nftables + Traffic Control)
# ==============================================================================

init_nft_table() {
    nft list table $NFT_TABLE &>/dev/null
    if [ $? -ne 0 ]; then
        nft add table $NFT_TABLE
        nft add set $NFT_TABLE blocked_ports { type inet_service\; }
        # 优先级 -5 (略高于 filter hook)，确保计数器优先执行
        nft add chain $NFT_TABLE input { type filter hook input priority -5\; }
        nft add chain $NFT_TABLE output { type filter hook output priority -5\; }
        
        # 显式拆分 TCP/UDP 规则，修复 NFT 类型检查报错
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
    # 初始化 HTB 根队列
    if ! tc qdisc show dev "$iface" | grep -q "htb 1:"; then
        tc qdisc add dev "$iface" root handle 1: htb default 10
        # 默认分类 1:10 (1Gbps/不限速通道)
        tc class add dev "$iface" parent 1: classid 1:10 htb rate 1000mbit
    fi
}

apply_port_rules() {
    local port=$1
    local conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
    local limit_mbps=$(echo "$conf" | jq -r '.limit_mbps // 0')
    local iface=$(jq -r '.interface' "$CONFIG_FILE")
    
    # 检查是否处于惩罚状态
    local is_punished=$(echo "$conf" | jq -r '.dyn_limit.is_punished // false')
    if [ "$is_punished" == "true" ]; then
        limit_mbps=$(echo "$conf" | jq -r '.dyn_limit.punish_mbps // 50')
    fi

    init_nft_table
    init_tc_root

    # [双轨制核心] 计算端口的十六进制，用于 TC ClassID (避免 >9999 报错)
    local port_hex=$(printf '%x' $port)

    # 1. NFT: 计数器 (十进制)
    nft add counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null
    nft add counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null

    # 2. NFT: 规则 + 打标 (十进制)
    # 输入方向统计
    if ! nft list chain $NFT_TABLE input | grep -q "counter name cnt_in_${port}"; then
        nft add rule $NFT_TABLE input tcp dport $port counter name "cnt_in_${port}"
        nft add rule $NFT_TABLE input udp dport $port counter name "cnt_in_${port}"
    fi
    # 输出方向统计 + Mark
    if ! nft list chain $NFT_TABLE output | grep -q "counter name cnt_out_${port}"; then
        nft add rule $NFT_TABLE output tcp sport $port counter name "cnt_out_${port}" meta mark set $port
        nft add rule $NFT_TABLE output udp sport $port counter name "cnt_out_${port}" meta mark set $port
    fi

    # 3. TC: 限速规则 (十六进制)
    # 清理旧规则
    tc filter del dev "$iface" parent 1: protocol ip prio 1 handle 0x$port_hex fw 2>/dev/null
    tc class del dev "$iface" parent 1: classid 1:$port_hex 2>/dev/null

    # 如果有限速值
    if [ "$limit_mbps" != "0" ] && [ -n "$limit_mbps" ]; then
        # ClassID 使用 hex (1:ac9d)
        tc class add dev "$iface" parent 1: classid 1:$port_hex htb rate "${limit_mbps}mbit"
        # Filter 匹配 Hex Mark (0xac9d) 并导流
        tc filter add dev "$iface" parent 1: protocol ip prio 1 handle 0x$port_hex fw flowid 1:$port_hex
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
# 3. 核心守护进程 (Writer: Cron)
# ==============================================================================

safe_write_config() {
    local content="$1"
    # 文件锁互斥写入
    (
        flock -x 200
        echo "$content" > "$CONFIG_FILE"
    ) 200>"$LOCK_FILE"
}

cron_task() {
    # [环境修复] 显式注入 PATH，解决 Cron 找不到 nft/bc 的问题
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

    # 1. 规则自愈检查
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
        
        # [格式清洗] 读取历史数据时强制转为整数 (printf %.0f)，去除可能存在的科学计数法
        local acc_in=$(echo "$p_conf" | jq -r '.stats.acc_in // 0 | printf "%.0f" .')
        local acc_out=$(echo "$p_conf" | jq -r '.stats.acc_out // 0 | printf "%.0f" .')
        local last_k_in=$(echo "$p_conf" | jq -r '.stats.last_kernel_in // 0 | printf "%.0f" .')
        local last_k_out=$(echo "$p_conf" | jq -r '.stats.last_kernel_out // 0 | printf "%.0f" .')

        # 读取内核当前值
        local curr_k_in=$(nft -j list counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null | jq -r '.nftables[0].counter.bytes // 0')
        local curr_k_out=$(nft -j list counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null | jq -r '.nftables[0].counter.bytes // 0')
        [ -z "$curr_k_in" ] && curr_k_in=0
        [ -z "$curr_k_out" ] && curr_k_out=0

        # [算法核心] 计算增量 (Shell + BC scale=0)
        local delta_in=0
        if [ $(echo "scale=0; $curr_k_in < $last_k_in" | bc) -eq 1 ]; then 
            delta_in=$curr_k_in # 发生过重启
        else 
            delta_in=$(echo "scale=0; $curr_k_in - $last_k_in" | bc)
        fi

        local delta_out=0
        if [ $(echo "scale=0; $curr_k_out < $last_k_out" | bc) -eq 1 ]; then 
            delta_out=$curr_k_out 
        else 
            delta_out=$(echo "scale=0; $curr_k_out - $last_k_out" | bc)
        fi
        
        # 更新累积总量
        acc_in=$(echo "scale=0; $acc_in + $delta_in" | bc)
        acc_out=$(echo "scale=0; $acc_out + $delta_out" | bc)

        # 存入 JSON
        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].stats.acc_in = $acc_in | .ports[\"$port\"].stats.acc_out = $acc_out | .ports[\"$port\"].stats.last_kernel_in = $curr_k_in | .ports[\"$port\"].stats.last_kernel_out = $curr_k_out")
        modified=true

        # --- 功能 A: 动态限速 (Dynamic QoS) ---
        local dyn_enable=$(echo "$p_conf" | jq -r '.dyn_limit.enable // false')
        if [ "$dyn_enable" == "true" ]; then
            local dyn_trigger=$(echo "$p_conf" | jq -r '.dyn_limit.trigger_mbps')
            local dyn_trig_time=$(echo "$p_conf" | jq -r '.dyn_limit.trigger_time')
            local dyn_punish_time=$(echo "$p_conf" | jq -r '.dyn_limit.punish_time')
            local strike=$(echo "$p_conf" | jq -r '.dyn_limit.strike_count // 0')
            local is_punished=$(echo "$p_conf" | jq -r '.dyn_limit.is_punished // false')
            local end_ts=$(echo "$p_conf" | jq -r '.dyn_limit.punish_end_ts // 0')

            # 速率计算 (Mbps)
            local current_mbps=$(echo "scale=2; ($delta_in + $delta_out) * 8 / 60 / 1024 / 1024" | bc)
            local rule_changed=false

            if [ "$is_punished" == "true" ]; then
                # 检查刑期
                if [ "$current_ts" -ge "$end_ts" ]; then
                    is_punished="false"
                    strike=0
                    tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.is_punished = false | .ports[\"$port\"].dyn_limit.strike_count = 0")
                    rule_changed=true
                fi
            else
                # 检查违规
                if [ $(echo "$current_mbps > $dyn_trigger" | bc) -eq 1 ]; then
                    strike=$((strike + 1))
                    if [ "$strike" -ge "$dyn_trig_time" ]; then
                        is_punished="true"
                        end_ts=$((current_ts + dyn_punish_time * 60))
                        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.is_punished = true | .ports[\"$port\"].dyn_limit.punish_end_ts = $end_ts")
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
                safe_write_config "$tmp_json"
                apply_port_rules "$port"
                tmp_json=$(cat "$CONFIG_FILE")
            fi
        fi

        # --- 功能 B: 配额阻断 ---
        local total_usage=0
        if [ "$mode" == "out_only" ]; then
            total_usage=$acc_out
        else
            total_usage=$(echo "scale=0; $acc_in + $acc_out" | bc)
        fi
        
        # [单位遵循] 严格按 1024 计算 GiB
        local quota_bytes=$(echo "scale=0; $quota_gb * 1024 * 1024 * 1024" | bc)
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
    # 确保 Cron 中使用绝对路径
    if ! crontab -l 2>/dev/null | grep -q "$INSTALL_PATH --monitor"; then
        (crontab -l 2>/dev/null; echo "* * * * * $INSTALL_PATH --monitor") | crontab -
    fi
}

# ==============================================================================
# 4. UI 模块 (Reader: 只读，极速)
# ==============================================================================

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
    clear
    echo -e "====================================================================================="
    echo -e "   Linux 端口流量管理 (快捷指令: $SHORTCUT_NAME) - 后台每分钟刷新"
    echo -e "====================================================================================="
    printf " %-4s %-12s %-10s %-25s %-15s %-15s\n" "ID" "端口" "模式" "已用流量 / 总配额" "出站限速" "备注"
    echo -e "-------------------------------------------------------------------------------------"

    local port_list=()
    local i=1
    local ports=$(jq -r '.ports | keys[]' "$CONFIG_FILE" | sort -n)

    for port in $ports; do
        local conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
        local mode=$(echo "$conf" | jq -r '.quota_mode')
        local limit=$(echo "$conf" | jq -r '.limit_mbps')
        local comment=$(echo "$conf" | jq -r '.comment')
        local quota=$(echo "$conf" | jq -r '.quota_gb')
        
        # [架构调整] UI 纯读取，不计算 delta，保证显示与阻断逻辑一致
        local acc_in=$(echo "$conf" | jq -r '.stats.acc_in // 0 | printf "%.0f" .')
        local acc_out=$(echo "$conf" | jq -r '.stats.acc_out // 0 | printf "%.0f" .')
        
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
        
        if nft list set $NFT_TABLE blocked_ports 2>/dev/null | grep -q "$port"; then
            status_clean="[已阻断]"
            is_blocked=true
        else
            status_clean="$(fmt_bytes $total_used)"
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

        # 格式化输出
        printf " [%d]  %-12s %-10s %-25s %-24s %-15s" $i "$port" "$mode_str" "${status_clean} / ${quota} GB" "$limit_str" "$comment"
        
        if [ "$is_blocked" == true ]; then
            echo -e "\r${RED} [${i}]  ${port} ... (已阻断)${PLAIN}"
        else
            echo ""
        fi
        
        port_list[$i]=$port
        ((i++))
    done
    echo -e "-------------------------------------------------------------------------------------"
    echo -e " 说明: 流量每分钟更新。限速调整与配额阻断由 Cron 任务自动执行。\n"

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
            echo -e "${RED}该端口已在监控列表中!${PLAIN}"; sleep 2; show_main_menu; return
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
    echo -e "${GREEN}添加成功! 等待下次Cron刷新数据...${PLAIN}"
    # 立即尝试手动触发一次后台更新，提升体验
    cron_task >/dev/null 2>&1
    sleep 1
    show_main_menu
}

config_port_menu() {
    local arr=("$@")
    echo -e "\n请输入要配置的端口 ID (查看上方列表): "
    read -p "ID > " id
    if [[ ! "$id" =~ ^[0-9]+$ ]] || [ "$id" -le 0 ]; then show_main_menu; return; fi
    local port=${arr[$((id-1))]}
    if [ -z "$port" ]; then show_main_menu; return; fi
    
    while true; do
        local conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
        local comment=$(echo "$conf" | jq -r '.comment')
        local quota=$(echo "$conf" | jq -r '.quota_gb')
        local mode=$(echo "$conf" | jq -r '.quota_mode')
        local limit=$(echo "$conf" | jq -r '.limit_mbps')
        
        # 显示动态QoS信息
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
            6) read -p "确定清零吗? [y/N]: " confirm
               if [[ "$confirm" == "y" ]]; then
                   local k_in=$(nft -j list counter $NFT_TABLE "cnt_in_${port}" | jq -r '.nftables[0].counter.bytes // 0')
                   local k_out=$(nft -j list counter $NFT_TABLE "cnt_out_${port}" | jq -r '.nftables[0].counter.bytes // 0')
                   jq ".ports[\"$port\"].stats.acc_in = 0 | .ports[\"$port\"].stats.acc_out = 0 | .ports[\"$port\"].stats.last_kernel_in = $k_in | .ports[\"$port\"].stats.last_kernel_out = $k_out" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)"
                   nft delete element $NFT_TABLE blocked_ports \{ $port \} 2>/dev/null
                   echo "已重置。"
               fi ;;
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
    echo -e "1. 启用"
    echo -e "2. 禁用"
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
        jq ".ports[\"$port\"].dyn_limit = {\"enable\": true, \"trigger_mbps\": $trig_mbps, \"trigger_time\": $trig_time, \"punish_mbps\": $pun_mbps, \"punish_time\": $pun_time, \"strike_count\": 0, \"is_punished\": false}" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)"
        echo -e "${GREEN}动态策略已更新!${PLAIN}"
    fi
    rm "$tmp"
    sleep 1
}

delete_port_flow() {
    local arr=("$@")
    read -p "请输入要删除的端口 ID: " id
    if [[ ! "$id" =~ ^[0-9]+$ ]] || [ "$id" -le 0 ]; then show_main_menu; return; fi
    local port=${arr[$((id-1))]}
    if [ -z "$port" ]; then show_main_menu; return; fi
    
    read -p "确定删除端口 $port 监控吗? [y/N]: " confirm
    if [[ "$confirm" == "y" ]]; then
        local tmp=$(mktemp)
        jq "del(.ports[\"$port\"])" "$CONFIG_FILE" > "$tmp" && safe_write_config "$(cat $tmp)" && rm "$tmp"
        local iface=$(jq -r '.interface' "$CONFIG_FILE")
        
        # 使用 Hex 句柄删除
        local port_hex=$(printf '%x' $port)
        tc filter del dev "$iface" parent 1: protocol ip prio 1 handle 0x$port_hex fw 2>/dev/null
        tc class del dev "$iface" parent 1: classid 1:$port_hex 2>/dev/null
        
        reload_all_rules
        echo -e "${GREEN}删除完成。${PLAIN}"; sleep 1
    fi
    show_main_menu
}

uninstall_script() {
    echo -e "${RED}!!! 危险操作警告 !!!${PLAIN}"
    read -p "确定要卸载? [y/N]: " confirm
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
install_shortcut "$1"
install_deps

if [ "$1" == "--monitor" ]; then
    cron_task
else
    setup_cron
    show_main_menu
fi