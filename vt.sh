#!/bin/bash
#
# VPS Toolbox — 调度器 & 状态监视器
# 纯调度, 不包含子脚本业务逻辑
# 子脚本: snell (Snell代理), x-sb (Xray多协议), sb (sing-box多协议), pm (端口流量监控), fw (端口转发)
#

VT_VERSION="2.0"
VT_SHORTCUT="vt"
VT_INSTALL_PATH="/usr/local/bin/$VT_SHORTCUT"
VT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/vt.sh"

# 子脚本远程地址
SNELL_URL="https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh"
XSB_URL="https://raw.githubusercontent.com/white-u/vps_script/main/x-sb.sh"
SB_URL="https://raw.githubusercontent.com/white-u/vps_script/main/sb.sh"
PM_URL="https://raw.githubusercontent.com/white-u/vps_script/main/pm.sh"
FW_URL="https://raw.githubusercontent.com/white-u/vps_script/main/fw.sh"

# 颜色
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[36m'; DIM='\033[2m'; PLAIN='\033[0m'

# Windows 终端兼容: 清洗 \r
strip_cr() { echo "${1//$'\r'/}"; }

# ─────────────────── 防火墙工具 ───────────────────

close_port() {
    local port=$1
    if command -v ufw >/dev/null 2>&1; then
        ufw delete allow "$port" >/dev/null 2>&1 || true
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --permanent --remove-port="${port}/udp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    elif command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    fi
}

# ─────────────────── 基础函数 ───────────────────

check_root() {
    [[ $(id -u) -ne 0 ]] && { echo -e "${RED}请使用 root 运行${PLAIN}"; exit 1; }
}

# 安装快捷命令 (首次运行时)
install_self() {
    [[ "$(realpath "$0" 2>/dev/null)" == "$(realpath "$VT_INSTALL_PATH" 2>/dev/null)" ]] && return
    local tmp=$(mktemp /tmp/vt_install.XXXXXX.sh)
    if curl -fsSL --max-time 15 "$VT_URL" -o "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
        mv -f "$tmp" "$VT_INSTALL_PATH"
        chmod +x "$VT_INSTALL_PATH"
        echo -e "${GREEN}快捷命令 '$VT_SHORTCUT' 已安装。${PLAIN}"
        exec "$VT_INSTALL_PATH" "$@"
    else
        rm -f "$tmp"
        if [[ -f "$0" ]]; then
            cp "$0" "$VT_INSTALL_PATH" && chmod +x "$VT_INSTALL_PATH"
            echo -e "${GREEN}快捷命令 '$VT_SHORTCUT' 已安装 (本地)。${PLAIN}"
            exec "$VT_INSTALL_PATH" "$@"
        fi
    fi
}

# ─────────────────── 状态检测 ───────────────────

snell_installed() { [[ -f /usr/local/bin/snell-server ]]; }
xray_installed()  { [[ -f /usr/local/bin/xray ]]; }
sb_installed()    { [[ -f /usr/local/bin/sing-box ]]; }
pm_installed()    { [[ -d /etc/port_monitor ]]; }
fw_installed()    { [[ -x /usr/local/bin/realm ]]; }

# 获取版本号
snell_version() { cat /etc/snell/.version 2>/dev/null || echo "?"; }
xray_version()  { /usr/local/bin/xray version 2>/dev/null | head -1 | awk '{print $2}' || echo "?"; }
sb_version()    { /usr/local/bin/sing-box version 2>/dev/null | grep -oP '[\d.]+' | head -1 || echo "?"; }
pm_version()    { grep -oP 'SCRIPT_VERSION="\K[^"]+' /usr/local/bin/pm 2>/dev/null || echo "?"; }
fw_version()    { /usr/local/bin/realm --version 2>/dev/null | grep -oP '[\d.]+' | head -1 || echo "?"; }

# 格式化状态行
status_line() {
    local name=$1 installed=$2 version=$3 cmd=$4
    if $installed; then
        echo -e "  ${GREEN}✅${PLAIN} ${name}  ${DIM}v${version}${PLAIN}  ${DIM}[${cmd}]${PLAIN}"
    else
        echo -e "  ⚪ ${name}  ${DIM}未安装${PLAIN}"
    fi
}

# ─────────────────── 调度 ───────────────────

dispatch() {
    local name=$1 cmd=$2 url=$3
    local target="/usr/local/bin/${cmd}"

    # 如果快捷命令已存在且可执行, 直接运行
    if [[ -x "$target" ]] && [[ -s "$target" ]]; then
        "$target"
        return
    fi

    # 否则下载到文件再执行 (避免 bash <(curl) 导致 $0 = /dev/fd/XX)
    echo -e "${YELLOW}正在下载 ${name} 管理脚本...${PLAIN}"
    local tmp=$(mktemp /tmp/vt_dl.XXXXXX.sh)
    if curl -fsSL --max-time 30 "$url" -o "$tmp" 2>/dev/null && [[ -s "$tmp" ]]; then
        mv -f "$tmp" "$target"
        chmod +x "$target"
        "$target"
    else
        rm -f "$tmp"
        echo -e "${RED}下载失败。${PLAIN}"
    fi
}

# ─────────────────── 统一卸载 ───────────────────

nuke_all() {
    echo ""
    echo -e "${RED}════════════════════════════════════════${PLAIN}"
    echo -e "${RED}  警告: 即将卸载所有组件并清除全部数据!${PLAIN}"
    echo -e "${RED}════════════════════════════════════════${PLAIN}"
    echo ""
    echo " 将清除: Snell 实例 / Xray 节点 / sing-box 节点 / PM 流量监控 / FW 端口转发 / 内核规则"
    echo ""
    read -p " 输入 yes 确认: " cf
    cf=$(strip_cr "$cf")
    [[ "${cf,,}" != "yes" ]] && { echo " 已取消。"; return; }

    echo ""

    # === Snell ===
    if snell_installed || [[ -d /etc/snell ]]; then
        echo -e " ${YELLOW}清理 Snell...${PLAIN}"
        if ls /etc/snell/*.conf >/dev/null 2>&1; then
            for conf in /etc/snell/*.conf; do
                local port=$(basename "$conf" .conf)
                systemctl stop "snell@${port}" 2>/dev/null || true
                systemctl disable "snell@${port}" 2>/dev/null || true
                close_port "$port"
            done
        fi
        rm -f /etc/systemd/system/snell@.service
        rm -rf /etc/snell
        rm -f /usr/local/bin/snell-server /usr/local/bin/snell
        userdel snell 2>/dev/null || true
        echo -e " ${GREEN}  Snell 已清除${PLAIN}"
    fi

    # === Xray ===
    if xray_installed || [[ -d /usr/local/etc/xray ]]; then
        echo -e " ${YELLOW}清理 Xray...${PLAIN}"
        # 关闭防火墙中已放行的端口
        if [[ -f /usr/local/etc/xray/config.json ]]; then
            local p
            for p in $(jq -r '.inbounds[]?.port // empty' /usr/local/etc/xray/config.json 2>/dev/null); do
                close_port "$p"
            done
        fi
        systemctl stop xray 2>/dev/null || true
        systemctl disable xray 2>/dev/null || true
        rm -f /etc/systemd/system/xray.service
        rm -rf /usr/local/etc/xray /usr/local/bin/xray /usr/local/share/xray /var/log/xray
        rm -f /usr/local/bin/x-sb
        echo -e " ${GREEN}  Xray 已清除${PLAIN}"
    fi

    # === sing-box ===
    if sb_installed || [[ -d /usr/local/etc/sing-box ]]; then
        echo -e " ${YELLOW}清理 sing-box...${PLAIN}"
        # 先读端口再删文件 (顺序不能反)
        if [[ -f /usr/local/etc/sing-box/config.json ]]; then
            local p
            for p in $(jq -r '.inbounds[]?.listen_port // empty' /usr/local/etc/sing-box/config.json 2>/dev/null); do
                close_port "$p"
            done
        fi
        systemctl stop sing-box 2>/dev/null || true
        systemctl disable sing-box 2>/dev/null || true
        rm -f /etc/systemd/system/sing-box.service
        rm -rf /usr/local/etc/sing-box /var/lib/sing-box
        rm -f /usr/local/bin/sing-box /usr/local/bin/sb
        echo -e " ${GREEN}  sing-box 已清除${PLAIN}"
    fi

    # === PM ===
    if pm_installed || [[ -f /usr/local/bin/pm ]]; then
        echo -e " ${YELLOW}清理 PM...${PLAIN}"
        crontab -l 2>/dev/null | grep -v 'pm.*--monitor' | crontab - 2>/dev/null
        local iface=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
        if [[ -n "$iface" ]] && tc qdisc show dev "$iface" 2>/dev/null | grep -q "htb 1:"; then
            tc qdisc del dev "$iface" root handle 1: htb 2>/dev/null || true
        fi
        nft delete table inet port_monitor 2>/dev/null || true
        rm -rf /etc/port_monitor
        rm -f /usr/local/bin/pm /var/run/pm.lock /tmp/pm_user_editing
        echo -e " ${GREEN}  PM 已清除${PLAIN}"
    fi

    # === FW (realm) ===
    if fw_installed || [[ -d /etc/realm ]]; then
        echo -e " ${YELLOW}清理 FW (realm)...${PLAIN}"
        # 关闭防火墙中已放行的端口
        if [[ -f /etc/realm/meta.json ]]; then
            local p
            for p in $(jq -r '.rules[].src_port' /etc/realm/meta.json 2>/dev/null); do
                close_port "$p"
            done
        fi
        systemctl stop realm 2>/dev/null || true
        systemctl disable realm 2>/dev/null || true
        rm -f /etc/systemd/system/realm.service
        rm -rf /etc/realm
        rm -f /usr/local/bin/realm /usr/local/bin/fw
        echo -e " ${GREEN}  FW 已清除${PLAIN}"
    fi

    systemctl daemon-reload 2>/dev/null

    echo ""
    echo -e "${GREEN}全部清除完成。${PLAIN}"
    read -p " 是否同时卸载工具箱自身? [y/N]: " rm_self
    rm_self=$(strip_cr "$rm_self")
    if [[ "${rm_self,,}" == "y" ]]; then
        rm -f "$VT_INSTALL_PATH"
        echo -e "${GREEN}工具箱已卸载。${PLAIN}"
        exit 0
    fi
}

# ─────────────────── 自更新 ───────────────────

update_self() {
    echo -e " 当前版本: v${VT_VERSION}"
    echo -e " 远程地址: ${DIM}${VT_URL}${PLAIN}"
    echo ""
    local tmp=$(mktemp /tmp/vt_update.XXXXXX.sh)
    if ! curl -fsSL --max-time 15 "$VT_URL" -o "$tmp" 2>/dev/null || [ ! -s "$tmp" ]; then
        rm -f "$tmp"
        echo -e "${RED}下载失败。${PLAIN}"
        return
    fi
    local remote_ver=$(grep '^VT_VERSION=' "$tmp" | head -1 | cut -d'"' -f2)
    if [[ "$remote_ver" == "$VT_VERSION" ]]; then
        rm -f "$tmp"
        echo -e "${GREEN}已是最新版本。${PLAIN}"
        return
    fi
    echo -e " 发现新版本: v${remote_ver}"
    mv -f "$tmp" "$VT_INSTALL_PATH"
    chmod +x "$VT_INSTALL_PATH"
    echo -e "${GREEN}更新完成, 正在重启...${PLAIN}"
    exec "$VT_INSTALL_PATH"
}

# ─────────────────── 系统信息 ───────────────────

sys_info() {
    local os=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -s)
    local arch=$(uname -m)
    local uptime_str=$(uptime -p 2>/dev/null | sed 's/up //' || echo "?")
    echo -e " ${DIM}${os} | ${arch} | 运行 ${uptime_str}${PLAIN}"
}

# ─────────────────── 主菜单 ───────────────────

main_menu() {
    while true; do
        clear
        echo -e "${BLUE}================================================================${PLAIN}"
        echo -e "   VPS 工具箱 (v${VT_VERSION})"
        echo -e "${BLUE}================================================================${PLAIN}"
        sys_info
        echo ""
        echo -e " 组件状态:"
        echo -e " ──────────────────────────────────────────────"
        status_line "Snell 代理管理  " snell_installed "$(snell_version)" "snell"
        status_line "Xray  多协议管理" xray_installed  "$(xray_version)"  "x-sb"
        status_line "SB    sing-box  " sb_installed     "$(sb_version)"    "sb"
        status_line "PM    端口流量  " pm_installed     "$(pm_version)"    "pm"
        status_line "FW    端口转发  " fw_installed     "$(fw_version)"    "fw"
        echo -e " ──────────────────────────────────────────────"
        echo ""
        echo -e "  1. Snell 代理管理"
        echo -e "  2. Xray 多协议管理"
        echo -e "  3. sing-box 多协议管理"
        echo -e "  4. 端口流量监控"
        echo -e "  5. 端口转发管理"
        echo -e " ──────────────────────────────────────────────"
        echo -e "  8. ${RED}全部卸载 (暴力清空)${PLAIN}"
        echo -e "  9. 更新工具箱"
        echo -e "  0. 退出"
        echo -e "${BLUE}================================================================${PLAIN}"
        read -p " 请选择: " choice
        choice=$(strip_cr "$choice")

        case $choice in
            1) dispatch "Snell" "snell" "$SNELL_URL" ;;
            2) dispatch "Xray"  "x-sb"  "$XSB_URL"  ;;
            3) dispatch "sing-box" "sb"  "$SB_URL"   ;;
            4) dispatch "PM"    "pm"    "$PM_URL"    ;;
            5) dispatch "FW"    "fw"    "$FW_URL"    ;;
            8) nuke_all ;;
            9) update_self; read -p " 按回车继续..." ;;
            0) exit 0 ;;
            *) ;;
        esac
    done
}

# ─────────────────── 入口 ───────────────────

check_root
install_self "$@"
main_menu
