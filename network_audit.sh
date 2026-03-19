#!/bin/bash

# ====================================================
# 脚本名称: network_audit.sh
# 功能: 中转机与落地机之间的链路多维深度测试
# 版本: v1.4 - 修复 iperf3 列解析（锚点倒数法）
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

clear
echo -e "${BLUE}====================================================${PLAIN}"
echo -e "${BLUE}       中转链路全能审计 (Relay <-> Exit)            ${PLAIN}"
echo -e "${BLUE}====================================================${PLAIN}"

# 自动获取本机公网 IP
LOCAL_IP=$(curl -s --connect-timeout 5 ipconfig.io 2>/dev/null || curl -s --connect-timeout 5 ifconfig.me 2>/dev/null)
if [ -z "$LOCAL_IP" ]; then
    echo -e "${YELLOW}警告: 无法自动获取本机公网 IP${PLAIN}"
    read -p "请手动输入本机公网 IP (用于回程检测指令生成): " LOCAL_IP
    if [ -z "$LOCAL_IP" ]; then
        echo -e "${RED}错误: 本机 IP 不能为空${PLAIN}"
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
if ! ping -c 1 -W 3 "$TARGET" &>/dev/null; then
    echo -e "${RED}错误: 目标 ${TARGET} 不可达，请检查 IP 或网络连接${PLAIN}"
    exit 1
fi
echo -e "${GREEN}目标可达，开始测试${PLAIN}"

# --- 1. 去程 QoS 与丢包探测 ---
echo -e "\n${YELLOW}[1/4] 正在探测去程质量 (QoS 识别)...${PLAIN}"

echo -n "正在发送小包 (64B)... "
PING_S_OUT=$(ping -s 64 -c 10 -q "$TARGET" 2>/dev/null)
S_AVG=$(echo "$PING_S_OUT" | tail -1 | awk -F '/' '{print $5}' | tr -d ' ')
if [ -z "$S_AVG" ]; then
    echo -e "${RED}失败：目标不可达或不响应 ICMP${PLAIN}"
    exit 1
fi
echo -e "${GREEN}${S_AVG} ms${PLAIN}"
SUMMARY_LATENCY_SMALL="${S_AVG} ms"

S_LOSS=$(echo "$PING_S_OUT" | grep -oP '\d+(?=% packet loss)')
[ -z "$S_LOSS" ] && S_LOSS="N/A"
SUMMARY_LOSS="${S_LOSS}%"

echo -n "正在发送大包 (1400B)... "
L_AVG=$(ping -s 1400 -c 10 -q "$TARGET" 2>/dev/null | tail -1 | awk -F '/' '{print $5}' | tr -d ' ')
[ -z "$L_AVG" ] && L_AVG="0"
echo -e "${GREEN}${L_AVG} ms${PLAIN}"
SUMMARY_LATENCY_LARGE="${L_AVG} ms"

QOS_RESULT=$(awk -v s="$S_AVG" -v l="$L_AVG" -v loss="$S_LOSS" 'BEGIN {
    s = s + 0; l = l + 0;
    if (l == 0) l = s;
    diff = l - s; ratio = (s > 0) ? l / s : 1;
    printf "----------------------------------------------------\n";
    printf "分析结果:\n";
    printf "去程丢包率: %s%%\n", loss;
    printf "小包延迟: %.3f ms | 大包延迟: %.3f ms\n", s, l;
    printf "延迟差值: %.3f ms\n", diff;
    printf "延迟比例: \033[33m%.2f 倍\033[0m (1.00 - 1.10 为极品)\n", ratio;
    if (ratio > 1.2)
        print "\033[31m[结论] 链路存在大包 QoS 限制，高带宽应用可能波动。\033[0m";
    else
        print "\033[32m[结论] 链路透明度高，适合高带宽转发。\033[0m";
    printf "RATIO:%.2f\n", ratio;
    printf "----------------------------------------------------\n";
}')
echo "$QOS_RESULT" | grep -v '^RATIO:'

SUMMARY_RATIO=$(echo "$QOS_RESULT" | grep '^RATIO:' | cut -d: -f2)
if awk "BEGIN {exit !($SUMMARY_RATIO > 1.2)}"; then
    SUMMARY_QOS_CONCLUSION="❌ 存在大包 QoS 限制"
else
    SUMMARY_QOS_CONCLUSION="✅ 链路透明，无 QoS"
fi

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
echo -e "${GREEN}curl -Ls https://raw.githubusercontent.com/sjlleo/nexttrace/main/nt_install.sh | bash && nexttrace -g cn ${LOCAL_IP}${PLAIN}"
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

        # iperf3 汇总行格式（以 sender/receiver 为最后一列作为锚点）:
        # [  5]  0.00-10.00  sec  397 MBytes  333 Mbits/sec  21422  sender
        # 从末尾倒数: $NF=sender, $(NF-1)=重传, $(NF-2)=单位, $(NF-3)=带宽数值

        # 正向压测
        echo -e "\n${GREEN}正在进行正向压测 (中转 -> 落地，10秒，单线程)...${PLAIN}"
        echo -e "${YELLOW}提示: 连接失败请检查落地机防火墙是否开放了 ${PORT} 端口${PLAIN}"
        FWD_OUT=$(iperf3 -c "$TARGET" -p "$PORT" -t 10 -P 1 --connect-timeout 5000 2>&1)
        echo "$FWD_OUT"
        SUMMARY_FWD_BW=$(echo "$FWD_OUT"   | grep 'sender' | tail -1 | awk '{print $(NF-3), $(NF-2)}')
        SUMMARY_FWD_RETR=$(echo "$FWD_OUT" | grep 'sender' | tail -1 | awk '{print $(NF-1)}')
        [ -z "$SUMMARY_FWD_BW" ]   && SUMMARY_FWD_BW="连接失败"
        [ -z "$SUMMARY_FWD_RETR" ] && SUMMARY_FWD_RETR="N/A"

        # 反向压测
        read -p "是否进行反向压测 (落地 -> 中转，测试下载方向带宽)? [y/n]: " RUN_REVERSE
        if [[ "$RUN_REVERSE" =~ ^[Yy]$ ]]; then
            echo -e "\n${GREEN}正在进行反向压测 (落地 -> 中转，10秒，单线程)...${PLAIN}"
            REV_OUT=$(iperf3 -c "$TARGET" -p "$PORT" -t 10 -P 1 -R --connect-timeout 5000 2>&1)
            echo "$REV_OUT"
            # 反向带宽取 receiver 行，重传取 sender 行
            SUMMARY_REV_BW=$(echo "$REV_OUT"   | grep 'receiver' | tail -1 | awk '{print $(NF-2), $(NF-1)}')
            SUMMARY_REV_RETR=$(echo "$REV_OUT" | grep 'sender'   | tail -1 | awk '{print $(NF-1)}')
            [ -z "$SUMMARY_REV_BW" ]   && SUMMARY_REV_BW="连接失败"
            [ -z "$SUMMARY_REV_RETR" ] && SUMMARY_REV_RETR="N/A"
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
echo -e "  延迟比例   : ${SUMMARY_RATIO} 倍"
echo -e "  去程丢包   : ${SUMMARY_LOSS}"
echo -e "  QoS 结论   : ${SUMMARY_QOS_CONCLUSION}"
echo -e "${BLUE}----------------------------------------------------${PLAIN}"
echo -e "${CYAN}  【吞吐量】${PLAIN}"
echo -e "  正向带宽   : ${SUMMARY_FWD_BW}  (重传: ${SUMMARY_FWD_RETR})"
echo -e "  反向带宽   : ${SUMMARY_REV_BW}  (重传: ${SUMMARY_REV_RETR})"
echo -e "${BLUE}====================================================${PLAIN}"
