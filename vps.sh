#!/bin/bash
#
# VPS 综合部署向导 v1.2
# 整合: Port-Manage (基石) + Sing-box/Snell (应用) + 一键卸载
# Usage: bash vps.sh

# 颜色定义
_red() { echo -e "\033[31m$@\033[0m"; }
_green() { echo -e "\033[32m$@\033[0m"; }
_yellow() { echo -e "\033[33m$@\033[0m"; }
_blue() { echo -e "\033[34m$@\033[0m"; }

# 脚本 URL (带缓存刷新)
TS=$(date +%s)
URL_PTM="https://raw.githubusercontent.com/white-u/vps_script/main/port-manage.sh?t=$TS"
URL_SB="https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh?t=$TS"
URL_SNELL="https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh?t=$TS"

clear
echo "================================================================"
echo "   VPS 综合流量治理与服务部署平台"
echo "   架构: Port-Manage (监控核心) + Proxy Services (业务节点)"
echo "================================================================"
echo

# ================= 阶段 1: 部署基础设施 (Port-Manage) =================
echo -e "$(_blue ">>> 阶段 1: 环境检测与基础组件")"

if command -v ptm >/dev/null 2>&1; then
    _green "✓ 端口流量监控 (PTM) 已安装"
else
    echo "正在安装 Port-Manage v3.0..."
    bash <(curl -sL "$URL_PTM") --version
    
    if command -v ptm >/dev/null 2>&1; then
        _green "✓ Port-Manage 安装成功"
    else
        echo
        _red "✗ Port-Manage 安装失败"
        echo "请检查网络或尝试手动安装。"
        exit 1
    fi
fi

echo
# ================= 阶段 2: 功能选择菜单 =================
echo -e "$(_blue ">>> 阶段 2: 请选择操作")"
echo "  1. 安装/更新 Sing-box (Reality/Shadowsocks)"
echo "  2. 安装/更新 Snell (Surge 专用)"
echo "  3. 全部安装 (Sing-box + Snell)"
echo "  --------------------------------"
echo "  4. 卸载与清理"
echo "  0. 退出"
echo
read -rp "请输入选择 [1]: " choice
choice=${choice:-1}

case $choice in
    1)
        echo "正在启动 Sing-box 脚本..."
        bash <(curl -sL "$URL_SB")
        ;;
    2)
        echo "正在启动 Snell 脚本..."
        bash <(curl -sL "$URL_SNELL")
        ;;
    3)
        echo ">>> 正在安装 Sing-box..."
        bash <(curl -sL "$URL_SB")
        echo
        echo ">>> ------------------------------------------------"
        echo ">>> 正在安装 Snell..."
        bash <(curl -sL "$URL_SNELL")
        ;;
    4)
        echo
        echo -e "$(_yellow "=== 卸载与清理 ===")"
        echo "  1. 卸载 Sing-box"
        echo "  2. 卸载 Snell"
        echo "  3. 卸载 Port-Manage (监控系统)"
        echo "  4. 全部卸载 (清空所有)"
        echo "  0. 返回"
        echo
        read -rp "请选择清理对象: " del_choice
        case $del_choice in
            1) bash <(curl -sL "$URL_SB") uninstall ;;
            2) bash <(curl -sL "$URL_SNELL") uninstall ;;
            3) bash <(curl -sL "$URL_PTM") uninstall ;;
            4) 
                echo ">>> 步骤 1/3: 卸载 Sing-box..."
                bash <(curl -sL "$URL_SB") uninstall
                echo
                echo ">>> 步骤 2/3: 卸载 Snell..."
                bash <(curl -sL "$URL_SNELL") uninstall
                echo
                echo ">>> 步骤 3/3: 卸载 Port-Manage..."
                # 这里必须手动指定 bash 解析，因为 uninstall 在 CLI 参数里
                # 注意：这里我们调用本地 ptm 命令可能更稳，如果已安装的话
                if command -v ptm >/dev/null 2>&1; then
                    ptm uninstall
                else
                    bash <(curl -sL "$URL_PTM") uninstall
                fi
                ;;
            *) echo "取消操作。" ;;
        esac
        ;;
    *)
        echo "退出。"
        ;;
esac

echo