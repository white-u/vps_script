#!/bin/bash

# ====================================================
# 脚本名称: network_audit.sh
# 功能: 中转机与落地机之间的链路多维深度测试
# 修复: v1.1 - 变量名错误、丢包解析兼容性、预检、参数修正
# ====================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

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

# 小包测试 (64B)
echo -n "正在发送小包 (64B)... "
PING_S_OUT=$(ping -s 64 -c 10 -q "$TARGET" 2>/dev/null)
S_AVG=$(echo "$PING_S_OUT" | tail -1 | awk -F '/' '{print $5}' | tr -d ' ')

if [ -z "$S_AVG" ]; then
    echo -e "${RED}失败：目标不可达或不响应 ICMP${PLAIN}"
    exit 1
fi
echo -e "${GREEN}${S_AVG} ms${PLAIN}"

# 丢包率解析 (兼容 Debian/Ubuntu/CentOS)
S_LOSS=$(echo "$PING_S_OUT" | grep -oP '\d+(?=% packet loss)')
[ -z "$S_LOSS" ] && S_LOSS="N/A"

# 大包测试 (1400B)  — 修复: 原脚本变量名为 L_AVG 但 awk 引用了未定义的 L_RES
echo -n "正在发送大包 (1400B)... "
L_AVG=$(ping -s 1400 -c 10 -q "$TARGET" 2>/dev/null | tail -1 | awk -F '/' '{print $5}' | tr -d ' ')
[ -z "$L_AVG" ] && L_AVG="0"
echo -e "${GREEN}${L_AVG} ms${PLAIN}"

# QoS 分析
awk -v s="$S_AVG" -v l="$L_AVG" -v loss="$S_LOSS" 'BEGIN {
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
    printf "----------------------------------------------------\n";
}'

# --- 2. 路由分析 ---
echo -e "\n${YELLOW}[2/4] 正在分析去程路由路径...${PLAIN}"
if command -v nexttrace &>/dev/null; then
    # 修复: --dot-metric 不是有效参数，改用 --dot-server 指定 DoH 解析服务商
    nexttrace -g cn --dot-server aliyun "$TARGET"
else
    echo -e "${YELLOW}未检测到 NextTrace，使用标准 traceroute (建议安装 NextTrace 以查看 AS 号和地理信息)${PLAIN}"
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

        echo -e "\n${GREEN}正在进行正向压测 (中转 -> 落地，10秒，4线程)...${PLAIN}"
        echo -e "${YELLOW}提示: 连接失败请检查落地机防火墙是否开放了 ${PORT} 端口${PLAIN}"
        # 修复: 正向压测补充 --connect-timeout，与反向压测保持一致
        iperf3 -c "$TARGET" -p "$PORT" -t 10 -P 4 --connect-timeout 5000

        read -p "是否进行反向压测 (落地 -> 中转，测试下载方向带宽)? [y/n]: " RUN_REVERSE
        if [[ "$RUN_REVERSE" =~ ^[Yy]$ ]]; then
            echo -e "\n${GREEN}正在进行反向压测 (落地 -> 中转，10秒，单线程)...${PLAIN}"
            iperf3 -c "$TARGET" -p "$PORT" -t 10 -P 1 -R --connect-timeout 5000
        fi
    fi
fi

echo -e "\n${BLUE}====================================================${PLAIN}"
echo -e "${BLUE}              测试流程结束，请对比数据              ${PLAIN}"
echo -e "${BLUE}====================================================${PLAIN}"
