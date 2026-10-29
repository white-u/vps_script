#!/bin/bash
#
# VPS Toolbox — 调度器 & 状态监视器
# 组件调度、状态显示与统一卸载
# 子脚本: snell (Snell代理), sb (sing-box多协议), pm (端口流量监控), fw (端口转发)
#

VT_VERSION="1.0.0"
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
        echo -e "${RED}❌ ${name} 异常退出（退出码 ${rc}）。请查看上方错误信息和对应服务日志。${PLAIN}" >&2
    fi
}

CLEANUP_FAILURES=0
cleanup_warn() {
    echo -e "${RED}❌ 清理未完成: $1${PLAIN}" >&2
    CLEANUP_FAILURES=$((CLEANUP_FAILURES + 1))
}

# ─────────────────── 防火墙工具 ───────────────────

close_port() {
    local port=$1 proto rc=0 query_rc
    if command -v ufw >/dev/null 2>&1; then
        for proto in tcp udp; do
            ufw --force delete allow "${port}/${proto}" >/dev/null 2>&1 || rc=1
        done
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || rc=1
        firewall-cmd --permanent --remove-port="${port}/udp" >/dev/null 2>&1 || rc=1
        firewall-cmd --reload >/dev/null 2>&1 || rc=1
    elif command -v iptables >/dev/null 2>&1; then
        for proto in tcp udp; do
            if iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT >/dev/null 2>&1; then
                iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || rc=1
            else
                query_rc=$?
                [[ "$query_rc" -eq 1 ]] || rc=1
            fi
        done
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || rc=1
        fi
    fi
    return "$rc"
}

open_port() {
    local port=$1 proto rc=0 query_rc
    if command -v ufw >/dev/null 2>&1; then
        for proto in tcp udp; do
            ufw allow "${port}/${proto}" >/dev/null 2>&1 || rc=1
        done
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || rc=1
        firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 || rc=1
        firewall-cmd --reload >/dev/null 2>&1 || rc=1
    elif command -v iptables >/dev/null 2>&1; then
        for proto in tcp udp; do
            if iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT >/dev/null 2>&1; then
                :
            else
                query_rc=$?
                if [[ "$query_rc" -eq 1 ]]; then
                    iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || rc=1
                else
                    rc=1
                fi
            fi
        done
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || rc=1
        fi
    fi
    return "$rc"
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
sb_version()    { /usr/local/bin/sing-box version 2>/dev/null | sed -nE 's/^sing-box version v?([^[:space:]]+).*/\1/p' | head -1 || echo "?"; }
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
        return "$rc"
    fi

    # 否则下载到文件再执行 (避免 bash <(curl) 导致 $0 = /dev/fd/XX)
    echo -e "${YELLOW}正在下载 ${name} 管理脚本...${PLAIN}"
    local tmp
    tmp=$(mktemp "${target}.download.XXXXXX") || {
        echo -e "${RED}无法为 ${name} 创建下载临时文件。${PLAIN}" >&2
        return 1
    }
    if curl -fL --progress-bar -o "$tmp" --connect-timeout 8 --max-time 30 "$(fresh_url "$url")" \
        && validate_script_file "$tmp" "SCRIPT_VERSION"; then
        if ! chmod 755 "$tmp" || ! mv -f "$tmp" "$target"; then
            echo -e "${RED}${name} 脚本安装失败，现有文件未被覆盖。${PLAIN}" >&2
            return 1
        fi
        "$target"
        local rc=$?
        report_child_exit "$name" "$rc"
        return "$rc"
    else
        rm -f "$tmp"
        echo -e "${RED}下载失败或远程脚本校验未通过，未覆盖现有脚本。${PLAIN}"
        return 1
    fi
}

# ─────────────────── 统一卸载 ───────────────────

cleanup_snell() (
    local units="" links="" known=false conf unit port state
    local ports=() active_ports=() enabled_ports=()
    [[ -e /etc/snell || -L /etc/snell || -e /usr/local/bin/snell-server \
        || -e /usr/local/bin/snell || -e /etc/systemd/system/snell@.service ]] && known=true
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        if ! units=$(systemctl list-units 'snell@*.service' --all --plain --no-legend 2>/dev/null); then
            [[ "$known" == false ]] && return 0
            echo "无法读取 Snell 实例状态，文件已保留。" >&2; return 1
        fi
    elif [[ "$known" == true ]]; then
        echo "无法使用 systemd，Snell 文件已保留。" >&2; return 1
    fi
    if [[ -d /etc/systemd/system ]]; then
        links=$(find /etc/systemd/system -type l -name 'snell@*.service' -print) || return 1
    fi
    [[ "$known" == true || -n "$units" || -n "$links" ]] || return 0
    echo -e " ${YELLOW}清理 Snell...${PLAIN}"
    if [[ -L /etc/snell || ( -e /etc/snell && ! -d /etc/snell ) ]]; then
        echo "Snell 配置路径不是普通目录，拒绝卸载。" >&2; return 1
    fi
    shopt -s nullglob
    for conf in /etc/snell/*.conf; do
        if [[ ! -f "$conf" || -L "$conf" ]]; then
            echo "Snell 配置不是普通文件，拒绝卸载: $conf" >&2; return 1
        fi
        unit=$(basename "$conf" .conf)
        [[ "$unit" =~ ^[0-9]+$ ]] || { echo "Snell 实例端口无效: $conf" >&2; return 1; }
        ports+=("$unit")
    done
    while read -r unit _; do
        unit=${unit##*/}
        if [[ "$unit" =~ ^snell@([0-9]+)[.]service$ ]]; then ports+=("${BASH_REMATCH[1]}"); fi
    done <<< "${units}"$'\n'"${links}"
    # 配置丢失的运行实例与开机启动链接也要清理；同一端口只操作一次。
    local unique=""
    for port in "${ports[@]}"; do
        [[ " $unique " == *" $port "* ]] || unique="${unique:+$unique }$port"
    done
    ports=(); read -ra ports <<< "$unique"
    for port in "${ports[@]}"; do
        state=$(systemctl show "snell@${port}" -p LoadState -p ActiveState 2>/dev/null) || return 1
        case "$(sed -n 's/^ActiveState=//p' <<< "$state")" in
            active|activating|reloading) active_ports+=("$port") ;;
            inactive|failed|deactivating) ;;
            *) echo "无法确认 Snell ${port} 的运行状态，文件已保留。" >&2; return 1 ;;
        esac
        systemctl is-enabled --quiet "snell@${port}" 2>/dev/null && enabled_ports+=("$port")
    done
    local restore=true restore_firewall=false restore_failed=false
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap '
        trap "" INT TERM
        if [[ "$restore" == true ]]; then
            if [[ "$restore_firewall" == true ]]; then
                for port in "${ports[@]}"; do open_port "$port" || restore_failed=true; done
            fi
            for port in "${enabled_ports[@]}"; do systemctl enable "snell@${port}" >/dev/null 2>&1 || restore_failed=true; done
            for port in "${active_ports[@]}"; do systemctl start "snell@${port}" >/dev/null 2>&1 || restore_failed=true; done
            [[ "$restore_failed" == false ]] || echo "Snell 原状态恢复失败，请检查服务和防火墙；配置已保留。" >&2
        fi
    ' EXIT
    for port in "${ports[@]}"; do
        if ! systemctl stop "snell@${port}"; then
            state=$(systemctl show "snell@${port}" -p LoadState -p ActiveState 2>/dev/null) || state=""
            if ! grep -Fqx 'LoadState=not-found' <<< "$state" \
                || ! grep -Fqx 'ActiveState=inactive' <<< "$state"; then
                echo "Snell ${port} 停止失败，文件已保留。" >&2; return 1
            fi
        fi
        state=$(systemctl show "snell@${port}" -p ActiveState 2>/dev/null) || return 1
        if ! grep -Eq '^ActiveState=(inactive|failed)$' <<< "$state"; then
            echo "Snell ${port} 尚未停止，文件已保留。" >&2; return 1
        fi
    done
    for port in "${enabled_ports[@]}"; do
        systemctl disable "snell@${port}" || { echo "Snell ${port} 取消开机启动失败，文件已保留。" >&2; return 1; }
    done
    restore_firewall=true
    for port in "${ports[@]}"; do
        close_port "$port" || { echo "Snell ${port} 防火墙清理失败，文件已保留。" >&2; return 1; }
    done
    # 此后进入文件删除阶段；失败时保留配置和账户归属供重试，不再重启服务。
    restore=false
    rm -f /etc/systemd/system/snell@.service /usr/local/bin/snell-server /usr/local/bin/snell || return 1
    systemctl daemon-reload || return 1
    if [[ -f /etc/snell/.user-created-by-snell-script && ! -L /etc/snell/.user-created-by-snell-script ]]; then
        if id -u snell >/dev/null 2>&1; then userdel snell || return 1; fi
        if getent group snell >/dev/null 2>&1; then groupdel snell || return 1; fi
    elif id -u snell >/dev/null 2>&1; then
        echo " 保留既有 snell 用户和用户组（无法确认由脚本创建）。"
    fi
    rm -rf /etc/snell || return 1
    if find /etc/systemd/system -type l -name 'snell@*.service' -print -quit 2>/dev/null | grep -q .; then
        echo "Snell 开机启动链接仍有残留。" >&2; return 1
    fi
    echo -e " ${GREEN}  Snell 已清除${PLAIN}"
)

remove_pm_cron() {
    local scratch=$1 current="$1/current" next="$1/next" err="$1/error"
    local old="* * * * * /usr/local/bin/pm --monitor"
    local logged="${old} >> /var/log/port_monitor.log 2>&1" rc username error_text
    if LC_ALL=C crontab -l > "$current" 2> "$err"; then
        [[ ! -s "$err" ]] || { echo "读取 Cron 返回异常诊断，任务表保持不变。" >&2; return 1; }
    else
        rc=$?; username=$(id -un) || return 1; error_text=$(cat "$err") || return 1
        if [[ "$rc" -ne 1 || -s "$current" ]] \
            || [[ "$error_text" != "no crontab for $username" && "$error_text" != "crontab: no crontab for $username" ]]; then
            echo "无法完整读取 Cron，任务表保持不变。" >&2; return 1
        fi
    fi
    awk -v old="$old" -v current="$logged" '$0 != old && $0 != current' "$current" > "$next" || return 1
    if ! cmp -s "$current" "$next"; then
        crontab "$next" || { echo "PM Cron 清理失败。" >&2; return 1; }
        LC_ALL=C crontab -l > "$current" 2> "$err" || return 1
        [[ ! -s "$err" ]] && cmp -s "$current" "$next" || { echo "PM Cron 清理后的校验失败。" >&2; return 1; }
    fi
}

cleanup_pm() (
    [[ -e /etc/port_monitor || -L /etc/port_monitor || -e /usr/local/bin/pm ]] || return 0
    echo -e " ${YELLOW}清理 PM...${PLAIN}"
    if [[ -L /etc/port_monitor || ( -e /etc/port_monitor && ! -d /etc/port_monitor ) ]]; then
        echo "PM 配置路径不是普通目录，拒绝卸载。" >&2; return 1
    fi
    # 与后台任务共用锁，等待正在执行的任务结束，避免清理后又重建规则。
    exec 9>/var/run/pm_cron.lock || return 1
    flock -x 9 || { echo "无法等待 PM 后台任务结束。" >&2; return 1; }
    local scratch
    scratch=$(mktemp -d) || return 1
    trap 'rm -rf "$scratch"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    remove_pm_cron "$scratch" || { echo "PM 配置和内核规则已保留。" >&2; return 1; }
    local failed=false tables owner qdisc
    if ! tables=$(nft -j list tables 2>/dev/null) \
        || ! jq -e '.nftables | type == "array"' <<< "$tables" >/dev/null 2>&1; then
        echo "无法读取 Nftables 表列表，配置已保留。" >&2; failed=true
    elif jq -e 'any(.nftables[]; .table.family == "inet" and .table.name == "port_monitor")' <<< "$tables" >/dev/null; then
        nft delete table inet port_monitor || { echo "PM Nftables 清理失败。" >&2; failed=true; }
    fi
    if [[ -e /etc/port_monitor/tc_root_owned || -L /etc/port_monitor/tc_root_owned ]]; then
        if [[ ! -f /etc/port_monitor/tc_root_owned || -L /etc/port_monitor/tc_root_owned ]] \
            || ! owner=$(cat /etc/port_monitor/tc_root_owned) || [[ -z "$owner" ]]; then
            echo "无法读取 PM 的 TC 归属记录。" >&2; failed=true
        elif ! qdisc=$(tc qdisc show dev "$owner" 2>/dev/null); then
            echo "无法读取 ${owner} 的 TC 队列。" >&2; failed=true
        elif grep -Eq 'qdisc htb 1:.* root' <<< "$qdisc"; then
            tc qdisc del dev "$owner" root || { echo "PM TC 清理失败。" >&2; failed=true; }
        fi
    fi
    [[ "$failed" == false ]] || { echo "PM 卸载未完成，配置、日志和归属记录已保留，请排查后重试。" >&2; return 1; }
    rm -f /usr/local/bin/pm /var/run/pm.lock /tmp/pm_user_editing /var/log/port_monitor.log || return 1
    rm -rf /etc/port_monitor || return 1
    # 保留稳定的空锁文件，避免已启动的 Cron 进程与重装进程锁住不同 inode。
    echo -e " ${GREEN}  PM 已清除${PLAIN}"
)

nuke_all() {
    CLEANUP_FAILURES=0
    echo ""
    echo -e "${RED}════════════════════════════════════════${PLAIN}"
    echo -e "${RED}  警告: 即将卸载所有组件并清除全部数据!${PLAIN}"
    echo -e "${RED}════════════════════════════════════════${PLAIN}"
    echo ""
    echo " 将清除: Snell 实例 / sing-box 节点 / PM 流量监控 / FW 端口转发 / 内核规则"
    echo ""
    read -r -p " 输入 yes 确认: " cf || { echo " 已取消。"; return 0; }
    cf=$(strip_cr "$cf")
    [[ "${cf,,}" != "yes" ]] && { echo " 已取消。"; return; }

    echo ""

    # === Snell ===
    cleanup_snell || cleanup_warn "Snell 卸载未完成，请根据上方提示处理后重试"

    # === sing-box ===
    if sb_installed || [[ -d /usr/local/etc/sing-box ]]; then
        echo -e " ${YELLOW}清理 sing-box...${PLAIN}"
        local sb_manager="none" sb_stop_ok=true
        if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
            sb_manager="systemd"
            if ! systemctl stop sing-box; then
                local sb_state
                sb_state=$(systemctl show sing-box -p LoadState -p ActiveState 2>/dev/null) || sb_state=""
                if [[ "$sb_state" != *"LoadState=not-found"* || "$sb_state" != *"ActiveState=inactive"* ]]; then
                    sb_stop_ok=false
                fi
            fi
        elif command -v rc-service >/dev/null 2>&1; then
            sb_manager="openrc"
            if [[ -e /etc/init.d/sing-box || -e /run/sing-box.pid ]] \
               && ! rc-service sing-box stop; then
                sb_stop_ok=false
            fi
        else
            sb_stop_ok=false
        fi

        if [[ "$sb_stop_ok" != "true" ]]; then
            cleanup_warn "sing-box 服务停止失败，已保留其文件和防火墙规则"
        else
            # 先读端口再删配置，服务未成功停止时不会提前关闭端口。
            if [[ -f /usr/local/etc/sing-box/config.json ]]; then
                local p
                for p in $(jq -r '.inbounds[]?.listen_port // empty' /usr/local/etc/sing-box/config.json 2>/dev/null); do
                    close_port "$p"
                done
            fi
            if [[ "$sb_manager" == "systemd" ]]; then
                systemctl disable sing-box >/dev/null 2>&1 || true
            elif [[ "$sb_manager" == "openrc" ]]; then
                rc-update del sing-box default >/dev/null 2>&1 || true
            fi
            rm -f /etc/systemd/system/sing-box.service /etc/init.d/sing-box
            rm -rf /usr/local/etc/sing-box /var/lib/sing-box
            rm -f /usr/local/bin/sing-box /usr/local/bin/sb /var/log/sing-box.log /run/sing-box.pid
            if sb_installed || [[ -d /usr/local/etc/sing-box ]]; then
                cleanup_warn "sing-box 文件仍然存在"
            else
                echo -e " ${GREEN}  sing-box 已清除${PLAIN}"
            fi
        fi
    fi

    # === PM ===
    cleanup_pm || cleanup_warn "PM 卸载未完成，请根据上方提示处理后重试"

    # === FW (realm) ===
    if fw_installed || [[ -d /etc/realm ]]; then
        echo -e " ${YELLOW}清理 FW (realm)...${PLAIN}"
        # FW 不管理防火墙，不删除无法确认归属的放行规则。
        local realm_stop_ok=false realm_state
        if systemctl stop realm 2>/dev/null; then
            realm_stop_ok=true
        elif realm_state=$(systemctl show -p LoadState -p ActiveState realm 2>/dev/null) \
            && grep -Fqx 'LoadState=not-found' <<< "$realm_state" \
            && grep -Fqx 'ActiveState=inactive' <<< "$realm_state"; then
            # 初次打开或下载失败可能只有配置残留，尚未创建服务。
            realm_stop_ok=true
        fi
        if [[ "$realm_stop_ok" != "true" ]]; then
            cleanup_warn "realm 停止失败，已保留 FW 文件和配置"
        elif systemctl is-active --quiet realm 2>/dev/null; then
            cleanup_warn "realm 仍在运行，已保留 FW 文件和配置"
        else
            systemctl disable realm 2>/dev/null || true
            rm -f /etc/systemd/system/realm.service
            rm -rf /etc/realm
            rm -f /usr/local/bin/realm /usr/local/bin/fw
            if fw_installed || [[ -d /etc/realm ]] || systemctl is-active --quiet realm 2>/dev/null; then
                cleanup_warn "realm 文件或服务仍然存在"
            else
                echo -e " ${GREEN}  FW 已清除（未修改防火墙，旧版放行规则请手动检查）${PLAIN}"
            fi
        fi
    fi

    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        systemctl daemon-reload 2>/dev/null || cleanup_warn "systemd daemon-reload 失败"
    fi

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
    if ! curl -fL --progress-bar -o "$tmp" --connect-timeout 8 --max-time 15 "$(fresh_url "$VT_URL")" \
        || ! validate_script_file "$tmp" "VT_VERSION"; then
        rm -f "$tmp"
        echo -e "${RED}下载失败或远程脚本校验未通过，当前版本保持不变。${PLAIN}"
        return 1
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
        echo -e "  8. ${RED}全部卸载${PLAIN}"
        echo -e "  9. 更新工具箱"
        echo -e "  0. 退出"
        echo -e "${BLUE}================================================================${PLAIN}"
        if ! read -p " 请选择: " choice; then
            echo
            echo "输入已结束，退出工具箱。"
            return 0
        fi
        choice=$(strip_cr "$choice")

        case $choice in
            1) dispatch "Snell" "snell" "$SNELL_URL" || read -r -p " 按回车返回..." ;;
            2) dispatch "sing-box" "sb" "$SB_URL" || read -r -p " 按回车返回..." ;;
            3) dispatch "PM" "pm" "$PM_URL" || read -r -p " 按回车返回..." ;;
            4) dispatch "FW" "fw" "$FW_URL" || read -r -p " 按回车返回..." ;;
            8) nuke_all || read -r -p " 按回车返回..." ;;
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
