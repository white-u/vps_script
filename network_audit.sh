#!/bin/bash

# ====================================================
# 脚本名称: network_audit.sh
# 功能: 中转机与落地机之间的链路多维深度测试
# 版本: v1.0.0
# ====================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

# 汇总数据变量
SUMMARY_LATENCY_SMALL="N/A"
SUMMARY_LATENCY_LARGE="N/A"
SUMMARY_RATIO="N/A"
SUMMARY_LOSS="N/A"
SUMMARY_QOS_CONCLUSION="N/A"
SUMMARY_FWD_BW="未测试"
SUMMARY_FWD_RETR="N/A"
SUMMARY_REV_BW="未测试"
SUMMARY_REV_RETR="N/A"

# iperf3 结果解析函数
# Linux sender 行: ... 333 Mbits/sec  21422  sender  (NF=10)
# macOS sender 行: ... 333 Mbits/sec  sender         (NF=9)
parse_iperf_bw() {
    local output="$1"
    local role="$2"   # sender 或 receiver
    local line
    line=$(echo "$output" | grep "$role" | tail -1)
    local nf
    nf=$(echo "$line" | awk '{print NF}')
    if [ "$role" = "sender" ]; then
        if [ "$nf" -ge 10 ]; then
            # Linux: 有 Retr 列
            echo "$line" | awk '{print $(NF-3), $(NF-2)}'
        else
            # macOS: 无 Retr 列
            echo "$line" | awk '{print $(NF-2), $(NF-1)}'
        fi
    else
        # receiver 行两平台格式相同，均无 Retr
        echo "$line" | awk '{print $(NF-2), $(NF-1)}'
    fi
}

parse_iperf_retr() {
    local output="$1"
    local line
    line=$(echo "$output" | grep 'sender' | tail -1)
    local nf
    nf=$(echo "$line" | awk '{print NF}')
    if [ "$nf" -ge 10 ]; then
        echo "$line" | awk '{print $(NF-1)}'
    else
        echo "N/A"
    fi
}

# iputils 的 -W 单位为秒，macOS 为毫秒；同时限制整个预检的运行时间。
ping_check() {
    case "$(uname -s)" in
        Darwin) ping -c 1 -W 3000 -t 3 "$1" &>/dev/null ;;
        *) ping -c 1 -W 3 -w 3 "$1" &>/dev/null ;;
    esac
}

analyze_qos() {
    SUMMARY_RATIO="N/A"
    SUMMARY_QOS_CONCLUSION="⚠️ 测量不完整，无法评估 QoS"
    if [[ ! "$S_AVG" =~ ^[0-9]+([.][0-9]+)?$ || ! "$L_AVG" =~ ^[0-9]+([.][0-9]+)?$ ]] \
        || ! awk -v s="$S_AVG" -v l="$L_AVG" 'BEGIN {exit !(s > 0 && l > 0)}'; then
        echo -e "${YELLOW}${SUMMARY_QOS_CONCLUSION}${PLAIN}"
        return 0
    fi
    local ratio
    if ! ratio=$(awk -v s="$S_AVG" -v l="$L_AVG" 'BEGIN {printf "%.2f", l / s}'); then
        echo -e "${RED}延迟计算失败，无法评估 QoS${PLAIN}" >&2
        return 1
    fi
    SUMMARY_RATIO=$ratio
    printf '小包延迟: %s ms | 大包延迟: %s ms\n延迟比例: %s 倍\n' "$S_AVG" "$L_AVG" "$ratio"
    printf '去程丢包率: %s\n' "$SUMMARY_LOSS"
    if awk -v ratio="$ratio" 'BEGIN {exit !(ratio > 1.2)}'; then
        SUMMARY_QOS_CONCLUSION="❌ 大包延迟升高，疑似 QoS 或链路拥塞"
    else
        SUMMARY_QOS_CONCLUSION="✅ 未见明显大包延迟升高（不代表无丢包或无 QoS）"
    fi
    printf '%s\n' "$SUMMARY_QOS_CONCLUSION"
}

valid_ipv4() {
    local ip=$1 octet
    local -a octets
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        # 拒绝前导零，避免不同工具按八进制解释同一地址。
        [[ "$octet" == 0 || "$octet" != 0* ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
}

valid_ip() {
    local ip=$1 tail rest group count=0
    [[ "$ip" == *:* ]] || { valid_ipv4 "$ip"; return; }
    if [[ "$ip" == *.* ]]; then
        tail=${ip##*:}
        valid_ipv4 "$tail" || return 1
        ip="${ip%:*}:0:0"
    fi
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ && "$ip" != *:::* ]] || return 1
    [[ "$ip" != :* || "$ip" == ::* ]] || return 1
    [[ "$ip" != *: || "$ip" == *:: ]] || return 1
    rest=${ip/::/}
    [[ "$rest" != *::* ]] || return 1
    for group in ${ip//:/ }; do
        [[ ${#group} -le 4 ]] || return 1
        count=$((count + 1))
    done
    if [[ "$ip" == *::* ]]; then
        ((count < 8))
    else
        ((count == 8))
    fi
}

get_public_ip() {
    local endpoint ip
    for endpoint in https://ipconfig.io https://ifconfig.me; do
        if ip=$(curl -q -fsSL --proto '=https' --proto-redir '=https' \
            --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null) && valid_ip "$ip"; then
            printf '%s\n' "$ip"
            return 0
        fi
    done
    return 1
}

print_return_command() {
    valid_ip "$1" || return 1
    # 在落地机上同样先下载、检查，再执行；下载失败不会被管道掩盖。
    printf '%s' '(installer=$(mktemp) || exit; trap '\''rm -f "$installer"'\'' EXIT; curl -q -fsSL --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 30 -o "$installer" https://nxtrace.org/nt && test -s "$installer" && bash -n "$installer" && bash "$installer") && nexttrace -g cn '
    printf '%q\n' "$1"
}

clear
echo -e "${BLUE}====================================================${PLAIN}"
echo -e "${BLUE}       中转链路全能审计 (Relay <-> Exit)            ${PLAIN}"
echo -e "${BLUE}====================================================${PLAIN}"

# 自动获取本机公网 IP
if ! LOCAL_IP=$(get_public_ip); then
    echo -e "${YELLOW}警告: 无法自动获取本机公网 IP${PLAIN}"
    read -p "请手动输入本机公网 IPv4 或 IPv6 (用于回程检测指令生成): " LOCAL_IP
    if ! valid_ip "$LOCAL_IP"; then
        echo -e "${RED}错误: 本机 IP 格式无效${PLAIN}"
        exit 1
    fi
fi
echo -e "本机公网 IP: ${GREEN}${LOCAL_IP}${PLAIN}"

# 用户输入目标
read -p "请输入落地服务器 IP 或域名: " TARGET
if [ -z "$TARGET" ]; then
    echo -e "${RED}错误: 目标 IP 不能为空${PLAIN}"
    exit 1
fi

# --- 目标可达性预检 ---
echo -e "\n${YELLOW}正在预检目标可达性...${PLAIN}"
if ! ping_check "$TARGET"; then
    echo -e "${RED}错误: 目标 ${TARGET} 不可达，请检查 IP 或网络连接${PLAIN}"
    exit 1
fi
echo -e "${GREEN}目标可达，开始测试${PLAIN}"

# --- 1. 去程 QoS 与丢包探测 ---
echo -e "\n${YELLOW}[1/4] 正在探测去程质量 (QoS 识别)...${PLAIN}"

echo -n "正在发送小包 (64B)... "
if ! PING_S_OUT=$(ping -s 64 -c 10 -q "$TARGET" 2>/dev/null); then
    echo -e "${RED}失败：小包测量失败，已停止评估${PLAIN}"
    exit 1
fi
S_AVG=$(echo "$PING_S_OUT" | tail -1 | awk -F '/' '{print $5}' | tr -d ' ')
if [ -z "$S_AVG" ]; then
    echo -e "${RED}失败：目标不可达或不响应 ICMP${PLAIN}"
    exit 1
fi
echo -e "${GREEN}${S_AVG} ms${PLAIN}"
SUMMARY_LATENCY_SMALL="${S_AVG} ms"

# 修复: 用 -E 替代 -P，兼容 macOS BSD grep
S_LOSS=$(echo "$PING_S_OUT" | grep -Eo '[0-9]+% packet loss' | grep -Eo '^[0-9]+')
[ -z "$S_LOSS" ] && S_LOSS="N/A"
# 修复: N/A 时不拼接 %
[ "$S_LOSS" = "N/A" ] && SUMMARY_LOSS="N/A" || SUMMARY_LOSS="${S_LOSS}%"

echo -n "正在发送大包 (1400B)... "
L_AVG=""
if L_PING_OUT=$(ping -s 1400 -c 10 -q "$TARGET" 2>/dev/null); then
    L_AVG=$(printf '%s\n' "$L_PING_OUT" | tail -1 | awk -F '/' '{print $5}' | tr -d ' ')
fi
if [[ "$L_AVG" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo -e "${GREEN}${L_AVG} ms${PLAIN}"
    SUMMARY_LATENCY_LARGE="${L_AVG} ms"
else
    echo -e "${RED}失败：大包无有效测量结果${PLAIN}"
    SUMMARY_LATENCY_LARGE="测试失败"
fi
analyze_qos || exit 1

# --- 2. 路由分析 ---
echo -e "\n${YELLOW}[2/4] 正在分析去程路由路径...${PLAIN}"
if command -v nexttrace &>/dev/null; then
    nexttrace -g cn --dot-server aliyun "$TARGET"
else
    echo -e "${YELLOW}未检测到 NextTrace，使用标准 traceroute${PLAIN}"
    traceroute -n -m 30 "$TARGET"
fi

# --- 3. 回程测试指令生成 ---
echo -e "\n${BLUE}====================================================${PLAIN}"
echo -e "${YELLOW}[3/4] 关键：回程路径检测 (Exit -> Relay)${PLAIN}"
echo -e "请【登录落地机】执行以下一键检测指令以确认路由对称性："
echo -e "----------------------------------------------------"
print_return_command "$LOCAL_IP" || exit 1
echo -e "----------------------------------------------------"

# --- 4. 吞吐量压测 (iperf3) ---
echo -e "\n${YELLOW}[4/4] 吞吐量与稳定性压测${PLAIN}"
read -p "是否运行 10 秒吞吐量压测? (需要落地机已开启 iperf3 -s) [y/n]: " RUN_IPERF

if [[ "$RUN_IPERF" =~ ^[Yy]$ ]]; then
    if ! command -v iperf3 &>/dev/null; then
        echo -e "${RED}错误: 未找到 iperf3，请先安装 (apt install iperf3 / yum install iperf3)${PLAIN}"
    else
        read -p "请输入 iperf3 端口 (默认 5201): " PORT
        PORT=${PORT:-5201}

        # 正向压测
        echo -e "\n${GREEN}正在进行正向压测 (中转 -> 落地，10秒，单线程)...${PLAIN}"
        echo -e "${YELLOW}提示: 连接失败请检查落地机防火墙是否开放了 ${PORT} 端口${PLAIN}"
        FWD_OUT=$(iperf3 -c "$TARGET" -p "$PORT" -t 10 -P 1 --connect-timeout 5000 2>&1)
        echo "$FWD_OUT"
        SUMMARY_FWD_BW=$(parse_iperf_bw "$FWD_OUT" "sender")
        SUMMARY_FWD_RETR=$(parse_iperf_retr "$FWD_OUT")
        [ -z "$SUMMARY_FWD_BW" ] && SUMMARY_FWD_BW="连接失败"

        # 反向压测
        read -p "是否进行反向压测 (落地 -> 中转，测试下载方向带宽)? [y/n]: " RUN_REVERSE
        if [[ "$RUN_REVERSE" =~ ^[Yy]$ ]]; then
            echo -e "\n${GREEN}正在进行反向压测 (落地 -> 中转，10秒，单线程)...${PLAIN}"
            REV_OUT=$(iperf3 -c "$TARGET" -p "$PORT" -t 10 -P 1 -R --connect-timeout 5000 2>&1)
            echo "$REV_OUT"
            SUMMARY_REV_BW=$(parse_iperf_bw "$REV_OUT" "receiver")
            SUMMARY_REV_RETR=$(parse_iperf_retr "$REV_OUT")
            [ -z "$SUMMARY_REV_BW" ] && SUMMARY_REV_BW="连接失败"
        fi
    fi
fi

# --- 汇总报告 ---
echo -e "\n${BLUE}====================================================${PLAIN}"
echo -e "${BLUE}                   📊 测试汇总报告                   ${PLAIN}"
echo -e "${BLUE}====================================================${PLAIN}"
echo -e "${CYAN}  测试时间  :${PLAIN} $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${CYAN}  中转机 IP :${PLAIN} ${LOCAL_IP}"
echo -e "${CYAN}  落地机 IP :${PLAIN} ${TARGET}"
echo -e "${BLUE}----------------------------------------------------${PLAIN}"
echo -e "${CYAN}  【延迟 & QoS】${PLAIN}"
echo -e "  小包延迟   : ${SUMMARY_LATENCY_SMALL}"
echo -e "  大包延迟   : ${SUMMARY_LATENCY_LARGE}"
if [[ "$SUMMARY_RATIO" == N/A ]]; then
    echo -e "  延迟比例   : N/A"
else
    echo -e "  延迟比例   : ${SUMMARY_RATIO} 倍"
fi
echo -e "  去程丢包   : ${SUMMARY_LOSS}"
echo -e "  QoS 结论   : ${SUMMARY_QOS_CONCLUSION}"
echo -e "${BLUE}----------------------------------------------------${PLAIN}"
echo -e "${CYAN}  【吞吐量】${PLAIN}"
echo -e "  正向带宽   : ${SUMMARY_FWD_BW}  (重传: ${SUMMARY_FWD_RETR})"
echo -e "  反向带宽   : ${SUMMARY_REV_BW}  (重传: ${SUMMARY_REV_RETR})"
echo -e "${BLUE}====================================================${PLAIN}"
