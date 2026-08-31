#!/bin/bash
#
# VPS Toolbox — 调度器 & 状态监视器
# 纯调度, 不包含子脚本业务逻辑
# 子脚本: snell (Snell代理), sb (sing-box多协议), pm (端口流量监控), fw (端口转发)
#

VT_VERSION="2.2.0"
VT_SHORTCUT="vt"
VT_INSTALL_PATH="/usr/local/bin/$VT_SHORTCUT"
VT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/vt.sh"

# 子脚本远程地址
SNELL_URL="https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh"
SB_URL="https://raw.githubusercontent.com/white-u/vps_script/main/sb.sh"
PM_URL="https://raw.githubusercontent.com/white-u/vps_script/main/pm.sh"
FW_URL="https://raw.githubusercontent.com/white-u/vps_script/main/fw.sh"

# 颜色
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[36m'; DIM='\033[2m'; PLAIN='\033[0m'

# Windows 终端兼容: 清洗 \r
strip_cr() { echo "${1//$'\r'/}"; }

report_child_exit() {
    local name=$1 rc=$2
    if [[ $rc -ne 0 ]]; then
        echo -e "${RED}❌ ${name} 异常退出（退出码 ${rc}）。请查看上方错误信息和对应 systemd 日志。${PLAIN}" >&2
    fi
}

CLEANUP_FAILURES=0
cleanup_warn() {
    echo -e "${RED}❌ 清理未完成: $1${PLAIN}" >&2
    CLEANUP_FAILURES=$((CLEANUP_FAILURES + 1))
}

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

fresh_url() {
    printf '%s?t=%s-%s' "$1" "$(date +%s)" "$$"
}

validate_script_file() {
    local file=$1 version_key=$2
    local version
    [[ -s "$file" ]] || return 1
    head -n 1 "$file" | grep -qx '#!/bin/bash' || return 1
    grep -q "^${version_key}=\"" "$file" || return 1
    version=$(grep "^${version_key}=" "$file" | head -1 | cut -d'"' -f2)
    [[ "$version" =~ ^[0-9]+([.][0-9]+)*$ ]] || return 1
    bash -n "$file"
}

version_is_older() {
    local candidate=$1 current=$2 i candidate_part current_part
    local IFS=.
    local -a candidate_parts current_parts
    read -ra candidate_parts <<< "$candidate"
    read -ra current_parts <<< "$current"
    for ((i=0; i<${#candidate_parts[@]} || i<${#current_parts[@]}; i++)); do
        candidate_part=${candidate_parts[i]:-0}
        current_part=${current_parts[i]:-0}
        ((10#$candidate_part < 10#$current_part)) && return 0
        ((10#$candidate_part > 10#$current_part)) && return 1
    done
    return 1
}

# 安装快捷命令 (首次运行时)
install_self() {
    [[ "$(realpath "$0" 2>/dev/null)" == "$(realpath "$VT_INSTALL_PATH" 2>/dev/null)" ]] && return
    local tmp
    tmp=$(mktemp "${VT_INSTALL_PATH}.install.XXXXXX") || {
        echo -e "${RED}无法在 /usr/local/bin 创建更新临时文件。${PLAIN}" >&2
        return 1
    }
    if curl -fsSLo "$tmp" --connect-timeout 8 --max-time 15 "$(fresh_url "$VT_URL")" \
        && validate_script_file "$tmp" "VT_VERSION"; then
        if ! chmod 755 "$tmp" || ! mv -f "$tmp" "$VT_INSTALL_PATH"; then
            echo -e "${RED}快捷命令安装失败，现有文件未被覆盖。${PLAIN}" >&2
            return 1
        fi
        echo -e "${GREEN}快捷命令 '$VT_SHORTCUT' 已安装。${PLAIN}"
        exec "$VT_INSTALL_PATH" "$@"
    else
        if [[ -f "$0" ]] && cp "$0" "$tmp" \
            && validate_script_file "$tmp" "VT_VERSION" \
            && chmod 755 "$tmp" && mv -f "$tmp" "$VT_INSTALL_PATH"; then
            echo -e "${GREEN}快捷命令 '$VT_SHORTCUT' 已安装 (本地)。${PLAIN}"
            exec "$VT_INSTALL_PATH" "$@"
        fi
        rm -f "$tmp"
        echo -e "${YELLOW}快捷命令安装失败，继续运行当前脚本；现有文件未被覆盖。${PLAIN}" >&2
    fi
}

# ─────────────────── 状态检测 ───────────────────

snell_installed() { [[ -f /usr/local/bin/snell-server ]]; }
sb_installed()    { [[ -f /usr/local/bin/sing-box ]]; }
pm_installed()    { [[ -d /etc/port_monitor ]]; }
fw_installed()    { [[ -x /usr/local/bin/realm ]]; }

# 获取版本号
snell_version() { cat /etc/snell/.version 2>/dev/null || echo "?"; }
sb_version()    { /usr/local/bin/sing-box version 2>/dev/null | grep -oP '[\d.]+' | head -1 || echo "?"; }
pm_version() {
    local version
    version=$(sed -n 's/^SCRIPT_VERSION="\([^"]*\)".*/\1/p' /usr/local/bin/pm 2>/dev/null | head -n 1)
    echo "${version:-?}"
}
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
        local rc=$?
        report_child_exit "$name" "$rc"
        return
    fi

    # 否则下载到文件再执行 (避免 bash <(curl) 导致 $0 = /dev/fd/XX)
    echo -e "${YELLOW}正在下载 ${name} 管理脚本...${PLAIN}"
    local tmp
    tmp=$(mktemp "${target}.download.XXXXXX") || {
        echo -e "${RED}无法为 ${name} 创建下载临时文件。${PLAIN}" >&2
        return 1
    }
    if curl -fsSLo "$tmp" --connect-timeout 8 --max-time 30 "$(fresh_url "$url")" \
        && validate_script_file "$tmp" "SCRIPT_VERSION"; then
        if ! chmod 755 "$tmp" || ! mv -f "$tmp" "$target"; then
            echo -e "${RED}${name} 脚本安装失败，现有文件未被覆盖。${PLAIN}" >&2
            return 1
        fi
        "$target"
        local rc=$?
        report_child_exit "$name" "$rc"
    else
        rm -f "$tmp"
        echo -e "${RED}下载失败或远程脚本校验未通过，未覆盖现有脚本。${PLAIN}"
    fi
}

# ─────────────────── 统一卸载 ───────────────────

nuke_all() {
    CLEANUP_FAILURES=0
    echo ""
    echo -e "${RED}════════════════════════════════════════${PLAIN}"
    echo -e "${RED}  警告: 即将卸载所有组件并清除全部数据!${PLAIN}"
    echo -e "${RED}════════════════════════════════════════${PLAIN}"
    echo ""
    echo " 将清除: Snell 实例 / sing-box 节点 / PM 流量监控 / FW 端口转发 / 内核规则"
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
        if snell_installed || [[ -d /etc/snell ]] || \
           systemctl list-units 'snell@*.service' --state=active --no-legend 2>/dev/null | grep -q .; then
            cleanup_warn "Snell 文件或运行实例仍然存在"
        else
            echo -e " ${GREEN}  Snell 已清除${PLAIN}"
        fi
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
        if sb_installed || [[ -d /usr/local/etc/sing-box ]] || systemctl is-active --quiet sing-box 2>/dev/null; then
            cleanup_warn "sing-box 文件或服务仍然存在"
        else
            echo -e " ${GREEN}  sing-box 已清除${PLAIN}"
        fi
    fi

    # === PM ===
    if pm_installed || [[ -f /usr/local/bin/pm ]]; then
        echo -e " ${YELLOW}清理 PM...${PLAIN}"
        local pm_cron="* * * * * /usr/local/bin/pm --monitor"
        local pm_cron_logged="${pm_cron} >> /var/log/port_monitor.log 2>&1"
        crontab -l 2>/dev/null | awk -v old="$pm_cron" -v current="$pm_cron_logged" \
            '$0 != old && $0 != current' | crontab - 2>/dev/null
        local iface=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
        if [[ -n "$iface" ]] && [[ -f /etc/port_monitor/tc_root_owned ]] && \
           [[ "$(cat /etc/port_monitor/tc_root_owned 2>/dev/null)" == "$iface" ]] && \
           tc qdisc show dev "$iface" 2>/dev/null | grep -Eq 'qdisc htb 1:.* root'; then
            tc qdisc del dev "$iface" root 2>/dev/null || true
        fi
        nft delete table inet port_monitor 2>/dev/null || true
        rm -rf /etc/port_monitor
        rm -f /usr/local/bin/pm /var/run/pm.lock /tmp/pm_user_editing /var/log/port_monitor.log
        if pm_installed || [[ -f /usr/local/bin/pm ]] || \
           crontab -l 2>/dev/null | grep -Fqx -e "$pm_cron" -e "$pm_cron_logged"; then
            cleanup_warn "PM 文件或 Cron 任务仍然存在"
        else
            echo -e " ${GREEN}  PM 已清除${PLAIN}"
        fi
    fi

    # === FW (realm) ===
    if fw_installed || [[ -d /etc/realm ]]; then
        echo -e " ${YELLOW}清理 FW (realm)...${PLAIN}"
        # 关闭防火墙中已放行的端口
        if [[ -f /etc/realm/fw.json ]]; then
            local p
            for p in $(jq -r '.rules[].src_port' /etc/realm/fw.json 2>/dev/null); do
                close_port "$p"
            done
        fi
        systemctl stop realm 2>/dev/null || true
        systemctl disable realm 2>/dev/null || true
        rm -f /etc/systemd/system/realm.service
        rm -rf /etc/realm
        rm -f /usr/local/bin/realm /usr/local/bin/fw
        if fw_installed || [[ -d /etc/realm ]] || systemctl is-active --quiet realm 2>/dev/null; then
            cleanup_warn "realm 文件或服务仍然存在"
        else
            echo -e " ${GREEN}  FW 已清除${PLAIN}"
        fi
    fi

    systemctl daemon-reload 2>/dev/null || cleanup_warn "systemd daemon-reload 失败"

    echo ""
    if [[ $CLEANUP_FAILURES -gt 0 ]]; then
        echo -e "${RED}清理结束，但有 ${CLEANUP_FAILURES} 项失败；请根据上方提示手动处理。${PLAIN}"
        echo -e "${YELLOW}工具箱自身已保留，便于修复后重新执行清理。${PLAIN}"
        return 1
    else
        echo -e "${GREEN}全部清除完成。${PLAIN}"
    fi
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
    local tmp
    tmp=$(mktemp "${VT_INSTALL_PATH}.update.XXXXXX") || {
        echo -e "${RED}无法创建更新临时文件，当前版本保持不变。${PLAIN}" >&2
        return 1
    }
    if ! curl -fsSLo "$tmp" --connect-timeout 8 --max-time 15 "$(fresh_url "$VT_URL")" \
        || ! validate_script_file "$tmp" "VT_VERSION"; then
        rm -f "$tmp"
        echo -e "${RED}下载失败或远程脚本校验未通过，当前版本保持不变。${PLAIN}"
        return
    fi
    local remote_ver=$(grep '^VT_VERSION=' "$tmp" | head -1 | cut -d'"' -f2)
    if version_is_older "$remote_ver" "$VT_VERSION"; then
        rm -f "$tmp"
        echo -e "${RED}拒绝降级：远端 v${remote_ver} 低于当前 v${VT_VERSION}。${PLAIN}" >&2
        return 1
    fi
    if [[ "$remote_ver" == "$VT_VERSION" ]] && cmp -s "$tmp" "$VT_INSTALL_PATH"; then
        rm -f "$tmp"
        echo -e "${GREEN}已是最新版本。${PLAIN}"
        return
    fi
    if [[ "$remote_ver" == "$VT_VERSION" ]]; then
        echo -e " 发现同版本内容修订: v${remote_ver}"
    else
        echo -e " 发现新版本: v${remote_ver}"
    fi
    if ! chmod 755 "$tmp" || ! mv -f "$tmp" "$VT_INSTALL_PATH"; then
        echo -e "${RED}替换工具箱脚本失败，当前版本保持不变。${PLAIN}" >&2
        return 1
    fi
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
        status_line "SB    sing-box  " sb_installed     "$(sb_version)"    "sb"
        status_line "PM    端口流量  " pm_installed     "$(pm_version)"    "pm"
        status_line "FW    端口转发  " fw_installed     "$(fw_version)"    "fw"
        echo -e " ──────────────────────────────────────────────"
        echo ""
        echo -e "  1. Snell 代理管理"
        echo -e "  2. sing-box 多协议管理"
        echo -e "  3. 端口流量监控"
        echo -e "  4. 端口转发管理"
        echo -e " ──────────────────────────────────────────────"
        echo -e "  8. ${RED}全部卸载 (暴力清空)${PLAIN}"
        echo -e "  9. 更新工具箱"
        echo -e "  0. 退出"
        echo -e "${BLUE}================================================================${PLAIN}"
        read -p " 请选择: " choice
        choice=$(strip_cr "$choice")

        case $choice in
            1) dispatch "Snell" "snell" "$SNELL_URL" ;;
            2) dispatch "sing-box" "sb"  "$SB_URL"   ;;
            3) dispatch "PM"    "pm"    "$PM_URL"    ;;
            4) dispatch "FW"    "fw"    "$FW_URL"    ;;
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
