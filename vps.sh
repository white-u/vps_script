#!/bin/bash
#
# VPS 综合部署向导 v1.0
# 整合: Port-Manage (基石) + Sing-box/Snell (应用)
# Usage: bash vps.sh

# 颜色定义
_red() { echo -e "\033[31m$@\033[0m"; }
_green() { echo -e "\033[32m$@\033[0m"; }
_yellow() { echo -e "\033[33m$@\033[0m"; }
_blue() { echo -e "\033[34m$@\033[0m"; }

clear
echo "================================================================"
echo "   VPS 综合流量治理与服务部署平台"
echo "   架构: Port-Manage (监控核心) + Proxy Services (业务节点)"
echo "================================================================"
echo

# ================= 阶段 1: 部署基础设施 (Port-Manage) =================
echo -e "$(_blue ">>> 阶段 1: 部署基础设施 (Port-Manage)...")"

if command -v ptm >/dev/null 2>&1; then
    _green "✓ 端口流量监控已安装"
else
    echo "正在安装 Port-Manage v3.0..."
    # 调用远程脚本安装，带 --version 参数测试运行
    bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/port-manage.sh) --version >/dev/null
    
    if command -v ptm >/dev/null 2>&1; then
        _green "✓ Port-Manage 安装成功"
    else
        _red "✗ Port-Manage 安装失败，请检查网络或依赖"
        exit 1
    fi
fi

echo
# ================= 阶段 2: 部署业务服务 =================
echo -e "$(_blue ">>> 阶段 2: 部署业务服务")"
echo "请选择要安装的服务:"
echo "  1. Sing-box (推荐: Reality/Shadowsocks)"
echo "  2. Snell (Surge 专用)"
echo "  3. 全部安装"
echo "  0. 跳过"
echo
read -rp "请输入选择 [1]: " choice
choice=${choice:-1}

case $choice in
    1)
        echo "正在拉取 Sing-box 脚本..."
        bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh)
        ;;
    2)
        echo "正在拉取 Snell 脚本..."
        bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh)
        ;;
    3)
        echo "正在安装 Sing-box..."
        bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh)
        echo
        echo "------------------------------------------------"
        echo "正在安装 Snell..."
        bash <(curl -sL https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh)
        ;;
    *)
        echo "跳过服务安装。"
        ;;
esac

echo
echo "================================================================"
echo -e "$(_green "部署流程结束！")"
echo "常用指令:"
echo "  ptm   - 打开流量监控面板"
echo "  sb    - 打开 Sing-box 面板"
echo "  snell - 打开 Snell 面板"
echo "================================================================"