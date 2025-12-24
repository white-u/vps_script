#!/bin/bash
#
# VPS 综合部署向导 v1.4
# 整合: Port-Manage (基石) + Sing-box/Snell (应用)
# 修复: 恢复强制防缓存机制，确保拉取最新无Bug代码
# Usage: bash vps.sh

# 颜色定义
_red() { echo -e "\033[31m$@\033[0m"; }
_green() { echo -e "\033[32m$@\033[0m"; }
_yellow() { echo -e "\033[33m$@\033[0m"; }
_blue() { echo -e "\033[34m$@\033[0m"; }

# ================= 关键修复：强制刷新缓存 =================
# 1. 获取时间戳
TS=$(date +%s)
# 2. 定义基础 URL (使用标准的 raw 路径)
BASE_URL="https://raw.githubusercontent.com/white-u/vps_script/main"

# 3. 在所有 URL 后强制加上时间戳参数 ?t=$TS
URL_PTM="${BASE_URL}/port-manage.sh?t=${TS}"
URL_SB="${BASE_URL}/sing-box.sh?t=${TS}"
URL_SNELL="${BASE_URL}/snell.sh?t=${TS}"
# ========================================================

clear
echo "================================================================"
echo "   VPS 综合流量治理与服务部署平台"
echo "   架构: Port-Manage (监控核心) + Proxy Services (业务节点)"
echo "================================================================"
echo

# ================= 阶段 1: 部署基础设施 (Port-Manage) =================
echo -e "$(_blue ">>> 阶段 1: 部署基础设施 (Port-Manage)...")"

if command -v ptm >/dev/null 2>&1; then
    _green "✓ 端口流量监控 (PTM) 已安装"
else
    echo "正在下载并安装 Port-Manage v3.0..."
    echo "下载地址: $URL_PTM"
    
    # 使用 -L (重定向) -f (失败报错) --progress-bar (进度条)
    if bash <(curl -L -f --progress-bar "$URL_PTM") --version; then
        echo
        if command -v ptm >/dev/null 2>&1; then
            _green "✓ Port-Manage 安装成功"
        else
            _red "✗ 安装脚本执行完毕，但 'ptm' 命令未创建。"
            echo "尝试手动执行以下命令排查:"
            echo "curl -L \"$URL_PTM\" > ptm.sh && bash ptm.sh"
            exit 1
        fi
    else
        echo
        _red "✗ 安装脚本执行失败！"
        echo "这通常是因为下载的脚本中存在语法错误(如多余的符号)。"
        echo "当前下载链接已强制刷新缓存，请检查 GitHub 仓库中的 port-manage.sh 最后一行是否还有 '}' 符号。"
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
echo "  --------------------------------"
echo "  4. 卸载与清理"
echo "  0. 跳过"
echo
read -rp "请输入选择 [1]: " choice
choice=${choice:-1}

case $choice in
    1)
        echo "正在启动 Sing-box 脚本..."
        bash <(curl -L "$URL_SB")
        ;;
    2)
        echo "正在启动 Snell 脚本..."
        bash <(curl -L "$URL_SNELL")
        ;;
    3)
        echo ">>> 正在安装 Sing-box..."
        bash <(curl -L "$URL_SB")
        echo
        echo ">>> ------------------------------------------------"
        echo ">>> 正在安装 Snell..."
        bash <(curl -L "$URL_SNELL")
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
            1) bash <(curl -L "$URL_SB") uninstall ;;
            2) bash <(curl -L "$URL_SNELL") uninstall ;;
            3) 
                if command -v ptm >/dev/null 2>&1; then
                    ptm uninstall
                else
                    bash <(curl -L "$URL_PTM") uninstall
                fi
                ;;
            4) 
                echo ">>> 步骤 1/3: 卸载 Sing-box..."
                bash <(curl -L "$URL_SB") uninstall
                echo
                echo ">>> 步骤 2/3: 卸载 Snell..."
                bash <(curl -L "$URL_SNELL") uninstall
                echo
                echo ">>> 步骤 3/3: 卸载 Port-Manage..."
                if command -v ptm >/dev/null 2>&1; then
                    ptm uninstall
                else
                    bash <(curl -L "$URL_PTM") uninstall
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
echo "================================================================"
echo -e "$(_green "部署流程结束！")"
echo "常用指令:"
echo "  ptm   - 打开流量监控面板"
echo "  sb    - 打开 Sing-box 面板"
echo "  snell - 打开 Snell 面板"
echo "================================================================"