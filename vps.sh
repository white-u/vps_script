#!/bin/bash

# ==============================================================================
# Linux 端口流量管理脚本 (Port Monitor & Shaper)
# 版本: v3.8 Stable
# 更新日志:
# 1. [致命修复] jq printf → floor: 修复流量统计完全失效的问题
# 2. [致命修复] nft JSON 索引 [0] → select(.counter): 修复内核计数器永远读为0
# 3. [严重修复] 端口封禁状态改用 nft JSON 精确匹配，防止子串误判
# 4. [严重修复] reload_all_rules 先销毁再重建，清理已删端口的残留规则
# 5. [严重修复] 菜单系统递归调用改为循环，防止长时间使用栈溢出
# 6. [修复] safe_write_config 使用 printf 替代 echo 防止特殊字符
# 7. [修复] 添加 IPv6 TC 过滤器与 NFT inet 表保持一致
# 8. [修复] 端口验证增加下限检查(1-65535), 配额不允许为0
# 9. [修复] 新增端口补全 last_kernel_in/out 初始值
# 10. [修复] DynQoS 速率计算改用 SI 单位 (Mbps)
# 11. [优化] 移除 add_port_flow 中过早释放编辑锁的问题
# 12. [优化] safe_write_config_from_file: 文件路径传参避免 ARG_MAX 限制
# 13. [优化] nft/tc 关键操作添加错误检测与日志输出
# ==============================================================================

# --- 全局配置 ---
SHORTCUT_NAME="pm"
INSTALL_PATH="/usr/local/bin/$SHORTCUT_NAME"
# [注意] 如果您 Fork 了此脚本，请修改下方的更新源地址
DOWNLOAD_URL="https://raw.githubusercontent.com/white-u/vps_script/main/vps.sh"

CONFIG_DIR="/etc/port_monitor"
CONFIG_FILE="$CONFIG_DIR/config.json"
LOCK_FILE="/var/run/pm.lock"
# 信号锁文件：当此文件存在时，Cron 暂停运行，防止覆盖用户正在编辑的数据
USER_EDIT_LOCK="/tmp/pm_user_editing"
NFT_TABLE="inet port_monitor"
SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null)

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

# ==============================================================================
# 1. 基础架构模块 (安装与环境)
# ==============================================================================

check_root() {
    [[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 权限运行此脚本。${PLAIN}" && exit 1
}

# 智能安装逻辑：兼容管道运行、Loader加载和本地运行
install_shortcut() {
    # 如果是 Cron 模式，或者当前运行的程序路径($0)已经是安装目标，则跳过安装
    [[ "$1" == "--monitor" ]] && return
    [[ "$0" == "$INSTALL_PATH" ]] && return
    
    # 增加逻辑：如果是被 source 加载的 (Loader 模式)，$0 也是 INSTALL_PATH，会自动跳过，无需额外改动
    
    echo -e "${YELLOW}正在初始化系统环境...${PLAIN}"
    
    # 强制从网络下载最新版到安装目录
    # 注意：如果这台机器没有外网，这里会失败，但不影响核心逻辑运行
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
    fi

    # 初始化配置目录与文件
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
    fi
    # 强制完整性检查：如果文件损坏或为空，重置它
    if [ ! -s "$CONFIG_FILE" ] || ! jq empty "$CONFIG_FILE" >/dev/null 2>&1; then
        echo "{\"interface\": \"$(get_iface)\", \"ports\": {}}" > "$CONFIG_FILE"
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
        if ! tc qdisc add dev "$iface" root handle 1: htb default 10 2>/dev/null; then
            echo -e "${RED}[错误] 无法在 $iface 上创建 TC 队列, 限速功能可能不可用。${PLAIN}" >&2
            return 1
        fi
        # 默认分类 1:10 (1Gbps/不限速通道)
        tc class add dev "$iface" parent 1: classid 1:10 htb rate 1000mbit
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
    if ! nft list chain $NFT_TABLE input | grep -q "counter name cnt_in_${port}"; then
        nft add rule $NFT_TABLE input tcp dport $port counter name "cnt_in_${port}"
        nft add rule $NFT_TABLE input udp dport $port counter name "cnt_in_${port}"
    fi
    
    if ! nft list chain $NFT_TABLE output | grep -q "counter name cnt_out_${port}"; then
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

cron_task() {
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
            local strike=$(echo "$p_conf" | jq -r '.dyn_limit.strike_count // 0')
            local is_punished=$(echo "$p_conf" | jq -r '.dyn_limit.is_punished // false')
            local end_ts=$(echo "$p_conf" | jq -r '.dyn_limit.punish_end_ts // 0')

            local current_mbps=$(echo "scale=2; ($delta_in + $delta_out) * 8 / 60 / 1000000" | bc)
            local rule_changed=false

            if [ "$is_punished" == "true" ]; then
                if [ "$current_ts" -ge "$end_ts" ]; then
                    is_punished="false"
                    strike=0
                    tmp_json=$(echo "$tmp_json" | jq ".ports[\"$port\"].dyn_limit.is_punished = false | .ports[\"$port\"].dyn_limit.strike_count = 0")
                    rule_changed=true
                fi
            else
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
    done

    if [ "$modified" == "true" ]; then
        safe_write_config "$tmp_json"
    fi
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
    # 捕获 Ctrl+C，确保退出时删除锁
    trap stop_edit_lock EXIT SIGINT SIGTERM
    start_edit_lock 

    clear
    echo -e "====================================================================================="
    echo -e "   Linux 端口流量管理 (v3.8 Stable) - 后台每分钟刷新"
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
    echo -e " 说明: 流量每分钟更新一次。当前正在编辑中，后台刷新已暂停。\n"

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
        ((idx++))
    done <<< "$scan_data"
    echo -e "----------------------------------------------------------------------"
    echo -e " [M]   手动输入端口号"
    echo -e " [0]   返回主菜单"
    echo -e "======================================================================"
    read -p "请输入选项: " sel
    local target_port=""
    if [ "$sel" == "0" ]; then return; fi
    if [[ "$sel" =~ ^[0-9]+$ ]] && [ -n "${map_ports[$sel]}" ]; then
        target_port=${map_ports[$sel]}
        if jq -e ".ports[\"$target_port\"]" "$CONFIG_FILE" >/dev/null; then
            echo -e "${RED}该端口已在监控列表中!${PLAIN}"; sleep 2; return
        fi
    elif [ "$sel" == "m" ] || [ "$sel" == "M" ]; then
        read -p "请输入端口号: " target_port
    else
        return
    fi
    if [[ ! "$target_port" =~ ^[0-9]+$ ]] || [ "$target_port" -lt 1 ] || [ "$target_port" -gt 65535 ]; then
        echo -e "${RED}无效端口${PLAIN}"; sleep 1; return
    fi
    
    echo -e "\n>> 正在配置端口: $target_port"
    
    read -p "月流量配额 (纯数字, GB): " quota
    if [[ ! "$quota" =~ ^[0-9]+$ ]] || [ "$quota" -eq 0 ]; then
        echo -e "${RED}错误: 配额必须是大于0的纯整数，不要带单位!${PLAIN}"; sleep 2; return
    fi

    echo "计费模式: 1.双向计费(默认)  2.仅出站计费"
    read -p "选择模式 [1/2]: " mode_idx
    local mode="in_out"
    [ "$mode_idx" == "2" ] && mode="out_only"

    read -p "出站限速 (纯数字, Mbps, 0为不限速): " limit
    if [[ ! "$limit" =~ ^[0-9]+$ ]]; then
        if [ -z "$limit" ]; then limit=0; else
             echo -e "${RED}错误: 限速必须是纯整数!${PLAIN}"; sleep 2; return
        fi
    fi
    [ -z "$limit" ] && limit=0

    read -p "备注信息: " comment

    local tmp=$(mktemp)
    
    # 使用 --argjson 确保 JSON 类型安全
    if jq --argjson q "$quota" \
          --arg m "$mode" \
          --argjson l "$limit" \
          --arg c "$comment" \
          --arg p "$target_port" \
       '.ports[$p] = {
        "quota_gb": $q, 
        "quota_mode": $m, 
        "limit_mbps": $l, 
        "comment": $c, 
        "stats": {"acc_in": 0, "acc_out": 0, "last_kernel_in": 0, "last_kernel_out": 0},
        "dyn_limit": {"enable": false}
    }' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
    
        rm "$tmp"
        apply_port_rules "$target_port"
        echo -e "${GREEN}添加成功! 流量将在下次 Cron 周期开始统计。${PLAIN}"
        sleep 1
        return
    else
        rm "$tmp" 2>/dev/null
        echo -e "${RED}写入配置失败! 请检查输入内容。${PLAIN}"
        sleep 2
        return
    fi
}

config_port_menu() {
    local arr=("$@")
    echo -e "\n请输入要配置的端口 ID (查看上方列表): "
    read -p "ID > " id
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
        local success=false

        case $sub_choice in
            1) 
                read -p "新配额 (纯数字, GB): " val
                if [[ "$val" =~ ^[0-9]+$ ]]; then
                    if jq --argjson v "$val" --arg p "$port" '.ports[$p].quota_gb = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                        success=true
                    fi
                else
                    echo -e "${RED}错误: 必须输入纯整数!${PLAIN}"; sleep 1
                fi 
                ;;
            2) 
                read -p "模式 (1.双向 2.仅出站): " m
                local nm="in_out"
                [ "$m" == "2" ] && nm="out_only"
                if jq --arg v "$nm" --arg p "$port" '.ports[$p].quota_mode = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                    success=true
                fi
                ;;
            3) 
                read -p "新限速 (纯数字, Mbps): " val
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
                if jq --arg v "$val" --arg p "$port" '.ports[$p].comment = $v' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                    success=true
                fi
                ;;
            6) 
                read -p "确定清零吗? [y/N]: " confirm
                if [[ "$confirm" == "y" ]]; then
                   local k_in=$(nft -j list counter $NFT_TABLE "cnt_in_${port}" 2>/dev/null | jq -r '[ .nftables[] | select(.counter) | .counter.bytes ] | .[0] // 0')
                   local k_out=$(nft -j list counter $NFT_TABLE "cnt_out_${port}" 2>/dev/null | jq -r '[ .nftables[] | select(.counter) | .counter.bytes ] | .[0] // 0')
                   
                   if jq --argjson ki "$k_in" --argjson ko "$k_out" --arg p "$port" \
                      '.ports[$p].stats.acc_in = 0 | .ports[$p].stats.acc_out = 0 | .ports[$p].stats.last_kernel_in = $ki | .ports[$p].stats.last_kernel_out = $ko' \
                      "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
                       
                       nft delete element $NFT_TABLE blocked_ports \{ $port \} 2>/dev/null
                       echo -e "${GREEN}已重置。${PLAIN}"; sleep 1
                   fi
                fi 
                ;;
            0) rm "$tmp"; break ;;
        esac
        
        if [ "$success" == "true" ]; then
            echo -e "${GREEN}配置已更新。${PLAIN}"
            sleep 0.5
        fi
        rm "$tmp" 2>/dev/null
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
    
    if [ "$qos_sel" == "2" ]; then
        if jq --arg p "$port" '.ports[$p].dyn_limit.enable = false | .ports[$p].dyn_limit.is_punished = false | .ports[$p].dyn_limit.strike_count = 0' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
            apply_port_rules "$port"
            echo -e "${GREEN}已禁用 QoS 策略。${PLAIN}"
        fi

    elif [ "$qos_sel" == "1" ]; then
        echo "请输入整数参数 (不要带单位):"
        read -p "(1/4) 触发阈值 [例如 100] (Mbps): " trig_mbps
        read -p "(2/4) 连续触发时长 [例如 5] (分钟): " trig_time
        read -p "(3/4) 惩罚限速值 [例如 5] (Mbps): " pun_mbps
        read -p "(4/4) 惩罚持续时长 [例如 60] (分钟): " pun_time
        
        # 统一校验所有输入是否为纯数字
        if [[ ! "$trig_mbps" =~ ^[0-9]+$ ]] || [[ ! "$trig_time" =~ ^[0-9]+$ ]] || \
           [[ ! "$pun_mbps" =~ ^[0-9]+$ ]] || [[ ! "$pun_time" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}错误: 所有参数必须为纯整数! 设置已取消。${PLAIN}"
            rm "$tmp"; sleep 2; return
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
              }' "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp"; then
              echo -e "${GREEN}动态策略已更新!${PLAIN}"
        else
              echo -e "${RED}写入失败，请检查配置文件权限。${PLAIN}"
        fi
    fi
    rm "$tmp" 2>/dev/null
    sleep 1
}

delete_port_flow() {
    local arr=("$@")
    read -p "请输入要删除的端口 ID: " id
    if [[ ! "$id" =~ ^[0-9]+$ ]] || [ "$id" -le 0 ]; then return; fi
    local port=${arr[$((id-1))]}
    if [ -z "$port" ]; then return; fi
    
    read -p "确定删除端口 $port 监控吗? [y/N]: " confirm
    if [[ "$confirm" == "y" ]]; then
        # 1. 优先解封
        nft delete element $NFT_TABLE blocked_ports \{ $port \} 2>/dev/null
        
        # 2. 删除 TC 规则 (使用 Hex, IPv4 + IPv6)
        local port_hex=$(printf '%x' $port)
        local iface=$(jq -r '.interface' "$CONFIG_FILE")
        tc filter del dev "$iface" parent 1: protocol ip prio 1 handle 0x$port_hex fw 2>/dev/null
        tc filter del dev "$iface" parent 1: protocol ipv6 prio 1 handle 0x$port_hex fw 2>/dev/null
        tc class del dev "$iface" parent 1: classid 1:$port_hex 2>/dev/null
        
        # 3. 删除 Config
        local tmp=$(mktemp)
        jq "del(.ports[\"$port\"])" "$CONFIG_FILE" > "$tmp" && safe_write_config_from_file "$tmp" && rm "$tmp"
        
        # 4. 彻底刷新
        reload_all_rules
        echo -e "${GREEN}删除完成。${PLAIN}"; sleep 1
    fi
}

uninstall_script() {
    echo -e "${RED}!!! 危险操作警告 !!!${PLAIN}"
    read -p "确定要彻底卸载 (清除规则、停止服务、删除文件)? [y/N]: " confirm
    if [[ "${confirm,,}" == "y" ]]; then
        # 1. 停服务
        crontab -l 2>/dev/null | grep -v "$SHORTCUT_NAME" | crontab -
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
install_shortcut "$1"
install_deps

if [ "$1" == "--monitor" ]; then
    cron_task
else
    setup_cron
    # 使用循环代替递归调用，防止长时间使用导致栈溢出
    while true; do
        show_main_menu
    done
fi