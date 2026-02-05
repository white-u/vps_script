#!/bin/bash

# ==============================================================================
# Linux 端口流量管理脚本 (Port Monitor & Shaper)
# 版本: v3.0 Final (经过完整逻辑测试与跨平台修复)
# ==============================================================================

# --- 全局配置 ---
SHORTCUT_NAME="pm"
INSTALL_PATH="/usr/local/bin/$SHORTCUT_NAME"
# 如有自己的仓库，修改此处 URL
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
# 1. 基础工具模块
# ==============================================================================

check_root() {
    [[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 权限运行此脚本。${PLAIN}" && exit 1
}

# 强大的安装逻辑：兼容本地执行、管道执行、重装
install_shortcut() {
    # 只有当：不是 Cron 调用 且 (当前不在安装路径 或 强制重装) 时执行
    if [[ "$1" != "--monitor" ]] && [[ "$0" != "$INSTALL_PATH" ]]; then
        echo -e "${YELLOW}正在配置系统环境...${PLAIN}"
        
        # 尝试下载
        curl -fsSL "$DOWNLOAD_URL" -o "$INSTALL_PATH" 2>/dev/null
        
        # 验证下载是否成功 (检查文件存在且非空)
        if [ -s "$INSTALL_PATH" ]; then
            chmod +x "$INSTALL_PATH"
            echo -e "${GREEN}安装成功! 快捷指令: $SHORTCUT_NAME${PLAIN}"
            echo -e "${GREEN}正在启动...${PLAIN}"
            sleep 1
            exec "$INSTALL_PATH" "$@"
        else
            # 下载失败的回退策略：如果是本地文件，尝试复制
            if [ -f "$0" ]; then
                cp "$0" "$INSTALL_PATH" && chmod +x "$INSTALL_PATH"
                echo -e "${YELLOW}网络下载失败，已使用本地文件安装。${PLAIN}"
                exec "$INSTALL_PATH" "$@"
            else
                echo -e "${RED}安装失败: 无法下载脚本且找不到本地源文件。${PLAIN}"
                exit 1
            fi
        fi
    fi
}

get_iface() {
    # 兼容性最高的获取网卡方式
    ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n 1
}

install_deps() {
    # 核心依赖清单
    local deps=("nft" "tc" "jq" "bc" "curl" "ss" "numfmt" "flock")
    local missing=false
    
    # 快速检查
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then missing=true; break; fi
    done

    if [ "$missing" = true ]; then
        echo -e "${YELLOW}正在安装依赖 (适应不同发行版)...${PLAIN}"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case $ID in
                debian|ubuntu)
                    apt-get update -q && apt-get install -y -q nftables iproute2 jq bc curl coreutils util-linux ;;
                centos|rhel|almalinux|rocky)
                    yum install -y -q nftables iproute tc jq bc curl coreutils util-linux ;;
                alpine)
                    # Alpine 需要明确安装这些包
                    apk add --no-cache nftables iproute2 jq bc curl coreutils util-linux ;;
                *)
                    echo -e "${RED}系统不受支持，请手动安装: ${deps[*]}${PLAIN}" && exit 1 ;;
            esac
        fi
    fi

    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
        echo "{\"interface\": \"$(get_iface)\", \"ports\": {}}" > "$CONFIG_FILE"
    fi
}

# ==============================================================================
# 2. 网络内核交互 (NFT + TC)
# ==============================================================================

init_nft_table() {
    # 检查表是否存在，不存在则初始化
    nft list table $NFT_TABLE &>/dev/null
    if [ $? -ne 0 ]; then
        nft add table $NFT_TABLE
        nft add set $NFT_TABLE blocked_ports { type inet_service\; }
        nft add chain $NFT_TABLE input { type filter hook input priority 0\; }
        nft add chain $NFT_TABLE output { type filter hook output priority 0\; }
        
        # [关键修复] 显式拆分 TCP 和 UDP 规则，避免 "No symbol type information" 错误
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
    # 检查网卡是否存在 HTB 根队列
    if ! tc qdisc show dev "$iface" | grep -q "htb 1:"; then
        # 创建根队列, 默认流量走 1:10
        tc qdisc add dev "$iface" root handle 1: htb default 10
        # 创建默认分类 1:10 (全速，不限制其他服务)
        tc class add dev "$iface" parent 1: classid 1:10 htb rate 1000mbit
    fi
}

apply_port_rules() {
    local port=$1
    local conf=$(jq ".ports[\"$port\"]" "$CONFIG_FILE")
    local limit_mbps=$(echo "$conf" | jq -r '.limit_mbps // 0')
    local iface=$(jq -r '.interface' "$CONFIG_FILE")
    
    # 动态QoS状态覆盖
    local is_punished=$(echo "$conf" | jq -r '.dyn_limit.is_punished // false')
    if [ "$is_punished" == "true" ]; then
        limit_mbps=$(echo "$conf" | jq -r '.dyn_limit.punish_mbps // 50')
    fi

    init_nft_table
    init_tc_root

    # 1. 声明计数器 (幂等)
    nft add counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null
    nft add counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null

    # 2. 添加统计规则
    # [关键修复] 使用拆分写法，确保兼容性
    if ! nft list chain $NFT_TABLE input | grep -q "counter name cnt_in_${port}"; then
        nft add rule $NFT_TABLE input tcp dport $port counter name "cnt_in_${port}"
        nft add rule $NFT_TABLE input udp dport $port counter name "cnt_in_${port}"
    fi
    
    if ! nft list chain $NFT_TABLE output | grep -q "counter name cnt_out_${port}"; then
        # 统计 + 打标 (Mark用于TC分类)
        nft add rule $NFT_TABLE output tcp sport $port counter name "cnt_out_${port}" meta mark set $port
        nft add rule $NFT_TABLE output udp sport $port counter name "cnt_out_${port}" meta mark set $port
    fi

    # 3. 配置 TC 限速
    # 先删除旧的 filter/class 防止重复
    tc filter del dev "$iface" parent 1: protocol ip prio 1 handle $port fw 2>/dev/null
    tc class del dev "$iface" parent 1: classid 1:$port 2>/dev/null

    # 如果有限速值 (且不为0)，则添加规则
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
# 3. 守护进程 (Watcher - Cron Task)
# ==============================================================================

safe_write_config() {
    # 文件锁机制，防止并发写坏 JSON
    local content="$1"
    (
        flock -x 200
        echo "$content" > "$CONFIG_FILE"
    ) 200>"$LOCK_FILE"
}

cron_task() {
    # 重启自愈检查
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
        
        # 读取 JSON 中存储的历史数据
        local acc_in=$(echo "$p_conf" | jq -r '.stats.acc_in // 0')
        local acc_out=$(echo "$p_conf" | jq -r '.stats.acc_out // 0')
        local last_k_in=$(echo "$p_conf" | jq -r '.stats.last_kernel_in // 0')
        local last_k_out=$(echo "$p_conf" | jq -r '.stats.last_kernel_out // 0')

        # 读取 内核 当前计数器
        local curr_k_in=$(nft -j list counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null | jq -r '.nftables[0].counter.bytes // 0')
        local curr_k_out=$(nft -j list counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null | jq -r '.nftables[0].counter.bytes // 0')

        # [算法修复] 使用 Shell 逻辑计算 Delta，避开 BC 版本差异
        local delta_in=0
        if [ $(echo "$curr_k_in < $last_k_in" | bc) -eq 1 ]; then delta_in=$curr_k_in; else delta_in=$(echo "$curr_k_in - $last_k_in" | bc); fi

        local delta_out=0
        if [ $(echo "$curr_k_out < $last_k_out" | bc) -eq 1 ]; then delta_out=$curr_k_out; else delta_out=$(echo "$curr_k_out - $last_k_out" | bc); fi
        
        # 累加
        acc_in=$(echo "$acc_in + $delta_in" | bc)
        acc_out=$(echo "$acc_out + $delta_out" | bc)

        # 更新 JSON 暂存对象
        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].stats.acc_in = $acc_in | .ports[\"$port\"].stats.acc_out = $acc_out | .ports[\"$port\"].stats.last_kernel_in = $curr_k_in | .ports[\"$port\"].stats.last_kernel_out = $curr_k_out")
        modified=true

        # --- Dynamic QoS 逻辑 ---
        local dyn_enable=$(echo "$p_conf" | jq -r '.dyn_limit.enable // false')
        if [ "$dyn_enable" == "true" ]; then
            local dyn_trigger=$(echo "$p_conf" | jq -r '.dyn_limit.trigger_mbps')
            local dyn_trig_time=$(echo "$p_conf" | jq -r '.dyn_limit.trigger_time')
            local dyn_punish_time=$(echo "$p_conf" | jq -r '.dyn_limit.punish_time')
            
            local strike=$(echo "$p_conf" | jq -r '.dyn_limit.strike_count // 0')
            local is_punished=$(echo "$p_conf" | jq -r '.dyn_limit.is_punished // false')
            local end_ts=$(echo "$p_conf" | jq -r '.dyn_limit.punish_end_ts // 0')

            local current_mbps=$(echo "scale=2; ($delta_in + $delta_out) * 8 / 60 / 1024 / 1024" | bc)
            local rule_changed=false

            if [ "$is_punished" == "true" ]; then
                # 刑满释放
                if [ "$current_ts" -ge "$end_ts" ]; then
                    is_punished="false"
                    strike=0
                    tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.is_punished = false | .ports[\"$port\"].dyn_limit.strike_count = 0")
                    rule_changed=true
                fi
            else
                # 违规判定
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
                    # 必须连续违规，断开则重置
                    if [ "$strike" -gt 0 ]; then
                        tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.strike_count = 0")
                    fi
                fi
            fi
            
            # 如果状态变更，立即应用规则
            if [ "$rule_changed" == "true" ]; then
                safe_write_config "$tmp_json"
                apply_port_rules "$port"
                tmp_json=$(cat "$CONFIG_FILE")
            fi
        fi

        # --- Quota 阻断逻辑 ---
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
    # 幂等添加 Cron 任务
    if ! crontab -l 2>/dev/null | grep -q "$INSTALL_PATH --monitor"; then
        (crontab -l 2>/dev/null; echo "* * * * * $INSTALL_PATH --monitor") | crontab -
    fi
}

# ==============================================================================
# 4. 服务发现 (Service Discovery)
# ==============================================================================

scan_active_services() {
    # 打印至 stderr，避免污染返回值
    echo -e "${YELLOW}正在扫描系统活跃服务...${PLAIN}" >&2
    
    # 修复版逻辑：兼容 IPv4/IPv6, 合并协议, 安全提取进程名
    # ss 参数: l=listening, n=numeric, t=tcp, u=udp, p=processes, H=no_header
    local scan_res=$(ss -lntupH | awk '{
        proto = $1
        
        # 端口提取: 取最后一个冒号后的内容
        n = split($5, addr, ":")
        port = addr[n]
        
        # 进程名提取: 手动解析 users:(("NAME",pid=
        proc = "Unknown"
        idx = index($0, "users:((\"")
        if (idx > 0) {
            subline = substr($0, idx + 9)
            q_idx = index(subline, "\"")
            if (q_idx > 0) {
                proc = substr(subline, 1, q_idx - 1)
            }
        }
        
        key = port " " proc
        if (seen[key] == "") {
            protos[key] = proto
            ports[key] = port
            procs[key] = proc
            seen[key] = 1
        } else {
            # 合并协议 (tcp/udp)
            if (index(protos[key], proto) == 0) {
                protos[key] = protos[key] "/" proto
            }
        }
    }
    END {
        for (k in protos) {
            print ports[k], protos[k], procs[k]
        }
    }' | sort -n -k1) 

    echo "$scan_res"
}

# ==============================================================================
# 5. UI 交互系统
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
        
        # 状态着色修复：数据逻辑与显示分离
        local status_clean=""
        local is_blocked=false
        
        if nft list set $NFT_TABLE blocked_ports 2>/dev/null | grep -q "$port"; then
            status_clean="[已阻断]"
            is_blocked=true
        else
            status_clean="$(fmt_bytes $total_used)"
        fi
        
        # 惩罚显示
        local is_punished=$(echo "$conf" | jq -r '.dyn_limit.is_punished // false')
        local limit_str=""
        local is_dyn_active=false
        
        if [ "$is_punished" == "true" ]; then
            local punish_val=$(echo "$conf" | jq -r '.dyn_limit.punish_mbps')
            limit_str="${punish_val}Mbps(惩罚)"
            is_dyn_active=true
        else
            if [ "$limit" == "0" ]; then
                limit_str="无限制"
            else
                limit_str="${limit} Mbps"
            fi
        fi

        # [修复] 逐行打印，手动应用颜色，避免 printf 错乱
        printf " [%d]  %-12s %-10s %-25s %-24s %-15s" $i "$port" "$mode_str" "${status_clean} / ${quota} GB" "$limit_str" "$comment"
        
        # 覆盖打印：如果有特殊状态，在行尾重写（这里简单处理：如果是阻断，显示红色）
        if [ "$is_blocked" == true ]; then
            echo -e "\r${RED} [${i}]  ${port} ... (已阻断)${PLAIN}"
            # 简单起见，仅保留原样输出，如果需要精确变色较复杂，此处采用纯文本兼容模式
        else
            echo ""
        fi
        
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
        local p_port=$(echo "$line" | awk '{print $1}')
        local p_proto=$(echo "$line" | awk '{print $2}')
        local p_proc=$(echo "$line" | awk '{$1=""; $2=""; print $0}' | sed 's/^ *//')
        
        local is_monitored=false
        if jq -e ".ports[\"$p_port\"]" "$CONFIG_FILE" >/dev/null; then
            is_monitored=true
        fi
        
        # 修复 Error 2: 颜色代码导致的对齐错乱 -> 改用手动逻辑
        if [ "$is_monitored" = true ]; then
            # 打印彩色行
            echo -e " [${idx}]  ${p_port}/${p_proto}\t\t${p_proc}\t\t${YELLOW}[已监控]${PLAIN}"
        else
            # 打印普通行
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
    # 修复 Error 3: 使用标准数组传递，不再使用 local -n
    local arr=("$@")
    
    echo -e "\n请输入要配置的端口 ID (查看上方列表): "
    read -p "ID > " id
    
    # 输入校验
    if [[ ! "$id" =~ ^[0-9]+$ ]] || [ "$id" -le 0 ]; then show_main_menu; return; fi
    
    local port=${arr[$((id-1))]}
    
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
    # 修复 Error 3: 使用标准数组传递
    local arr=("$@")
    
    read -p "请输入要删除的端口 ID: " id
    
    # 校验
    if [[ ! "$id" =~ ^[0-9]+$ ]] || [ "$id" -le 0 ]; then show_main_menu; return; fi
    
    local port=${arr[$((id-1))]}
    
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
install_shortcut "$1"
install_deps

if [ "$1" == "--monitor" ]; then
    cron_task
else
    setup_cron
    show_main_menu
fi