#!/bin/bash
#
# VPS 综合部署向导 v1.5
# 整合: Port-Manage (基石) + Sing-box/Snell (应用)
# Usage: bash vps.sh 或 vps
#

SCRIPT_VERSION="v1.5"

# 颜色定义
_red() { echo -e "\033[31m$@\033[0m"; }
_green() { echo -e "\033[32m$@\033[0m"; }
_yellow() { echo -e "\033[33m$@\033[0m"; }
_blue() { echo -e "\033[34m$@\033[0m"; }

# ================= URL 配置 (强制刷新缓存) =================
TS=$(date +%s)
BASE_URL="https://raw.githubusercontent.com/white-u/vps_script/main"
URL_VPS="${BASE_URL}/vps.sh"
URL_PTM="${BASE_URL}/port-manage.sh?t=${TS}"
URL_SB="${BASE_URL}/sing-box.sh?t=${TS}"
URL_SNELL="${BASE_URL}/snell.sh?t=${TS}"

# 路径配置
VPS_SCRIPT="/usr/local/bin/vps-manager.sh"
VPS_LINK="/usr/local/bin/vps"

# ================= 安装 vps 快捷命令 =================
install_vps_shortcut() {
    if [[ ! -x "$VPS_SCRIPT" ]] || [[ ! -L "$VPS_LINK" ]]; then
        echo "正在安装 VPS 管理脚本..."
        curl -fsSL "${URL_VPS}?t=${TS}" -o "$VPS_SCRIPT" 2>/dev/null || \
        wget -qO "$VPS_SCRIPT" "${URL_VPS}?t=${TS}" 2>/dev/null || true

        if [[ -f "$VPS_SCRIPT" ]] && [[ -s "$VPS_SCRIPT" ]]; then
            chmod +x "$VPS_SCRIPT"
            ln -sf "$VPS_SCRIPT" "$VPS_LINK"
            _green "✓ 快捷命令 'vps' 已创建"
        fi
    fi
}

# ================= 主流程 =================
clear
echo "================================================================"
echo "   VPS 综合流量治理与服务部署平台 $SCRIPT_VERSION"
echo "   架构: Port-Manage (监控核心) + Proxy Services (业务节点)"
echo "================================================================"
echo

# 记录操作类型
ACTION_TYPE="install"

# ================= 阶段 1: 部署基础设施 (Port-Manage) =================
echo -e "$(_blue ">>> 阶段 1: 部署基础设施 (Port-Manage)...")"

if command -v ptm >/dev/null 2>&1; then
    _green "✓ 端口流量监控 (PTM) 已安装"
else
    echo "正在下载并安装 Port-Manage..."

    if bash <(curl -L -f --progress-bar "$URL_PTM") install; then
        echo
        if command -v ptm >/dev/null 2>&1; then
            _green "✓ Port-Manage 安装成功"
        else
            _red "✗ 安装脚本执行完毕，但 'ptm' 命令未创建。"
            exit 1
        fi
    else
        echo
        _red "✗ Port-Manage 安装失败！"
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
        echo ">>> 正在安装 Sing-box..."
        bash <(curl -L -f "$URL_SB") install || { _red "Sing-box 安装失败"; }
        ;;
    2)
        echo ">>> 正在安装 Snell..."
        bash <(curl -L -f "$URL_SNELL") install || { _red "Snell 安装失败"; }
        ;;
    3)
        echo ">>> 正在安装 Sing-box..."
        bash <(curl -L -f "$URL_SB") install || { _red "Sing-box 安装失败"; }
        echo
        echo ">>> ------------------------------------------------"
        echo ">>> 正在安装 Snell..."
        bash <(curl -L -f "$URL_SNELL") install || { _red "Snell 安装失败"; }
        ;;
    4)
        ACTION_TYPE="uninstall"
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
            1) bash <(curl -L -f "$URL_SB") uninstall ;;
            2) bash <(curl -L -f "$URL_SNELL") uninstall ;;
            3)
                if command -v ptm >/dev/null 2>&1; then
                    ptm uninstall
                else
                    bash <(curl -L -f "$URL_PTM") uninstall
                fi
                ;;
            4)
                echo ">>> 步骤 1/3: 卸载 Sing-box..."
                bash <(curl -L -f "$URL_SB") uninstall || true
                echo
                echo ">>> 步骤 2/3: 卸载 Snell..."
                bash <(curl -L -f "$URL_SNELL") uninstall || true
                echo
                echo ">>> 步骤 3/3: 卸载 Port-Manage..."
                if command -v ptm >/dev/null 2>&1; then
                    ptm uninstall
                else
                    bash <(curl -L -f "$URL_PTM") uninstall
                fi
                # 删除 vps 快捷命令
                rm -f "$VPS_SCRIPT" "$VPS_LINK" 2>/dev/null
                ;;
            *)
                ACTION_TYPE="cancel"
                echo "取消操作。"
                ;;
        esac
        ;;
    0)
        ACTION_TYPE="skip"
        ;;
    *)
        ACTION_TYPE="exit"
        echo "退出。"
        ;;
esac

# ================= 安装 vps 快捷命令 =================
if [[ "$ACTION_TYPE" == "install" ]] || [[ "$ACTION_TYPE" == "skip" ]]; then
    install_vps_shortcut
fi

# ================= 结束提示 =================
echo
echo "================================================================"
if [[ "$ACTION_TYPE" == "uninstall" ]]; then
    echo -e "$(_green "卸载完成！")"
else
    echo -e "$(_green "部署流程结束！")"
    echo "常用指令:"
    command -v ptm >/dev/null 2>&1 && echo "  ptm   - 打开流量监控面板"
    command -v sb >/dev/null 2>&1 && echo "  sb    - 打开 Sing-box 面板"
    command -v snell >/dev/null 2>&1 && echo "  snell - 打开 Snell 面板"
    command -v vps >/dev/null 2>&1 && echo "  vps   - 打开此安装向导"
fi
echo "================================================================"
