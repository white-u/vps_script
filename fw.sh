#!/bin/bash
#
# fw.sh — 端口转发管理器 (基于 realm)
# 版本: v1.0
#
# 架构:
#   realm 作为用户态进程监听本机端口，将流量转发到目标 IP:Port
#   流量路径: 客户端 → INPUT → realm 进程 → OUTPUT → 目标
#   因此 pm.sh 的 OUTPUT 链配额/限速规则天然命中转发端口
#
# 文件布局:
#   /usr/local/bin/realm           realm 二进制
#   /usr/local/bin/fw              本脚本快捷命令
#   /etc/realm/config.toml         realm 配置 (自动生成)
#   /etc/realm/fw.json             转发元数据 (备注等)
#   /etc/systemd/system/realm.service
#

# --- 全局配置 ---
SCRIPT_VERSION="1.0"
REALM_VERSION="2.7.0"
SHORTCUT_NAME="fw"
INSTALL_PATH="/usr/local/bin/$SHORTCUT_NAME"
DOWNLOAD_URL="https://raw.githubusercontent.com/white-u/vps_script/main/fw.sh"
SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null)

REALM_BIN="/usr/local/bin/realm"
CONFIG_DIR="/etc/realm"
CONFIG_TOML="${CONFIG_DIR}/config.toml"
META_FILE="${CONFIG_DIR}/fw.json"
SERVICE_NAME="realm"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# --- 颜色 (与 vt.sh/pm.sh 统一) ---
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[36m'
DIM='\033[2m'; BOLD='\033[1m'; PLAIN='\033[0m'

# --- 临时资源清理 ---
_CLEANUP_FILES=()
_global_cleanup() {
    for f in "${_CLEANUP_FILES[@]+"${_CLEANUP_FILES[@]}"}"; do
        rm -rf "$f" 2>/dev/null
    done
}
trap _global_cleanup EXIT INT TERM

# --- 输入清洗 (Windows 终端 \r) ---
strip_cr() { echo "${1//$'\r'/}"; }

# --- 日志 ---
info() { echo -e "${GREEN}[✓]${PLAIN} $*"; }
warn() { echo -e "${YELLOW}[!]${PLAIN} $*"; }
err()  { echo -e "${RED}[✗]${PLAIN} $*"; }
die()  { err "$@"; exit 1; }

# ============================================================================
# 基础函数
# ============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 必须使用 root 权限运行此脚本。${PLAIN}"
        exit 1
    fi
}

check_jq() {
    command -v jq &>/dev/null && return 0
    warn "jq 未安装，正在安装..."
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq jq >/dev/null 2>&1 || die "jq 安装失败"
    info "jq 已安装"
}

# 安装快捷方式 (与 pm.sh/vt.sh 统一模式)
install_shortcut() {
    [[ "$0" == "$INSTALL_PATH" ]] && return
    # 管道模式检测 (curl | bash 时 $0 = bash)
    local base
    base=$(basename "$0" 2>/dev/null)
    if [[ "$base" == "bash" || "$base" == "sh" ]]; then
        warn "管道运行模式，跳过快捷命令安装。"
        return
    fi
    if [[ -n "$SCRIPT_PATH" ]] && [[ -f "$SCRIPT_PATH" ]]; then
        cp "$SCRIPT_PATH" "$INSTALL_PATH" && chmod +x "$INSTALL_PATH"
        info "快捷命令 '${SHORTCUT_NAME}' 已安装。"
    fi
}

init_meta() {
    mkdir -p "$CONFIG_DIR"
    if [[ ! -f "$META_FILE" ]]; then
        echo '{"rules":[]}' > "$META_FILE"
        return
    fi
    # JSON 完整性校验, 损坏则备份重建
    if ! jq empty "$META_FILE" 2>/dev/null; then
        warn "fw.json 已损坏，正在重建 (旧文件备份为 fw.json.bak)"
        cp "$META_FILE" "${META_FILE}.bak" 2>/dev/null || true
        echo '{"rules":[]}' > "$META_FILE"
    fi
}

rule_count() {
    [[ -f "$META_FILE" ]] || { echo 0; return; }
    jq '.rules | length' "$META_FILE" 2>/dev/null || echo 0
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        armv7*)        echo "armv7-unknown-linux-gnueabihf" ;;
        *)             die "不支持的架构: $(uname -m)" ;;
    esac
}

realm_installed() { [[ -x "$REALM_BIN" ]]; }
realm_running()   { systemctl is-active "$SERVICE_NAME" &>/dev/null; }

# ============================================================================
# realm 安装
# ============================================================================

install_realm() {
    if realm_installed; then
        local cur_ver
        cur_ver=$("$REALM_BIN" --version 2>/dev/null | grep -oP '[\d.]+' || true)
        cur_ver=$(echo "$cur_ver" | head -1)
        info "realm 已安装 (v${cur_ver:-unknown})"
        read -rp "  是否重新安装 v${REALM_VERSION}? [y/N] " confirm || return
        confirm=$(strip_cr "$confirm")
        [[ "$confirm" =~ ^[yY] ]] || return 0
    fi

    local arch_name url tmp_dir
    arch_name=$(detect_arch)
    url="https://github.com/zhboner/realm/releases/download/v${REALM_VERSION}/realm-${arch_name}.tar.gz"
    tmp_dir=$(mktemp -d)
    _CLEANUP_FILES+=("$tmp_dir")

    info "下载 realm v${REALM_VERSION} (${arch_name})..."
    if ! curl -fsSL --connect-timeout 15 --max-time 120 -o "${tmp_dir}/realm.tar.gz" "$url"; then
        die "下载失败: $url"
    fi

    tar -xzf "${tmp_dir}/realm.tar.gz" -C "$tmp_dir"

    local bin_path
    bin_path=$(find "$tmp_dir" -name "realm" -type f -perm -111 2>/dev/null | head -1)
    [[ -n "$bin_path" ]] || bin_path=$(find "$tmp_dir" -maxdepth 1 -type f ! -name "*.tar.gz" ! -name "*.sha256" | head -1)
    [[ -n "$bin_path" ]] || die "解压后未找到 realm 二进制"

    # 正在运行则先停止
    if realm_running; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    fi

    cp "$bin_path" "$REALM_BIN"
    chmod +x "$REALM_BIN"

    info "realm v${REALM_VERSION} 已安装到 ${REALM_BIN}"

    install_service

    # 如果已有规则, 生成配置并启动
    local count
    count=$(rule_count)
    if [[ "$count" -gt 0 ]]; then
        reload_realm
    fi
}

install_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Realm Port Forwarding
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${REALM_BIN} -c ${CONFIG_TOML}
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    # 不在此处 enable, 由 reload_realm 根据规则数量决定
    info "systemd 服务已安装"
}

# ============================================================================
# 配置生成与重载
# ============================================================================

generate_config() {
    init_meta
    cat > "$CONFIG_TOML" <<'HEADER'
# 由 fw.sh 自动生成，请勿手动编辑
[network]
use_udp = true
HEADER

    local count
    count=$(rule_count)
    [[ "$count" -gt 0 ]] || return 0

    local rules
    rules=$(jq -c '.rules[]' "$META_FILE" 2>/dev/null) || return 0

    while IFS= read -r rule; do
        local sp dip dp
        sp=$(echo "$rule"  | jq -r '.src_port')
        dip=$(echo "$rule" | jq -r '.dst_ip')
        dp=$(echo "$rule"  | jq -r '.dst_port')
        cat >> "$CONFIG_TOML" <<EOF

[[endpoints]]
listen = "0.0.0.0:${sp}"
remote = "${dip}:${dp}"
EOF
    done <<< "$rules"
}

reload_realm() {
    local quiet=${1:-false}
    generate_config

    local count
    count=$(rule_count)

    if [[ "$count" -eq 0 ]]; then
        if realm_running; then
            systemctl stop "$SERVICE_NAME" 2>/dev/null || true
            [[ "$quiet" == "true" ]] || info "无转发规则，realm 已停止"
        fi
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
        return 0
    fi

    if ! realm_installed; then
        warn "realm 未安装，配置已保存，请先运行: fw install"
        return 0
    fi

    # 有规则, 确保开机自启
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true

    if realm_running; then
        systemctl restart "$SERVICE_NAME" 2>/dev/null || true
    else
        systemctl start "$SERVICE_NAME" 2>/dev/null || true
    fi

    sleep 0.5
    if realm_running; then
        [[ "$quiet" == "true" ]] || info "realm 已重载 (${count} 条规则)"
    else
        err "realm 启动失败，请检查: journalctl -u ${SERVICE_NAME} -n 20"
    fi
}

# ============================================================================
# 输入校验
# ============================================================================

validate_port() {
    local port=$1 label=$2
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        err "无效${label}: $port"; return 1
    fi
    # 去掉前导零 (jq --argjson 不接受 JSON 非法数字如 "08080")
    port=$((10#$port))
    if [[ $port -lt 1 || $port -gt 65535 ]]; then
        err "无效${label}: $port (范围 1-65535)"; return 1
    fi
}

validate_ipv4() {
    local ip=$1
    if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        err "无效 IP: $ip"; return 1
    fi
    local IFS='.'; local -a parts=($ip); IFS=' '
    local p; for p in "${parts[@]}"; do
        if [[ $p -gt 255 ]]; then
            err "无效 IP: $ip"; return 1
        fi
    done
}

# ============================================================================
# 转发规则 CRUD
# ============================================================================

add_forward() {
    local src_port=$1 dst_ip=$2 dst_port=$3 comment=${4:-""}

    validate_port "$src_port" "源端口" || return 1
    validate_port "$dst_port" "目标端口" || return 1
    validate_ipv4 "$dst_ip" || return 1

    # 规范化端口
    src_port=$((10#$src_port))
    dst_port=$((10#$dst_port))

    init_meta
    if jq -e --argjson p "$src_port" '.rules[] | select(.src_port == $p)' "$META_FILE" &>/dev/null; then
        err "源端口 ${src_port} 已存在"; return 1
    fi

    # 检查端口占用 (TCP + UDP, 排除 realm 自身)
    local port_in_use=false
    if ss -tlnp 2>/dev/null | grep -qE ":${src_port}\b" || \
       ss -ulnp 2>/dev/null | grep -qE ":${src_port}\b"; then
        if ! ss -tulnp 2>/dev/null | grep -E ":${src_port}\b" | grep -q "realm"; then
            port_in_use=true
        fi
    fi
    if [[ "$port_in_use" == "true" ]]; then
        warn "端口 ${src_port} 已被其他进程占用"
        read -rp "  仍要继续? [y/N] " c || return 1
        c=$(strip_cr "$c")
        [[ "$c" =~ ^[yY] ]] || return 1
    fi

    # 净化备注
    comment=$(echo "$comment" | tr -d '"\\' | head -c 80)

    local tmp
    tmp=$(jq --argjson sp "$src_port" --arg di "$dst_ip" --argjson dp "$dst_port" --arg c "$comment" \
        '.rules += [{"src_port":$sp, "dst_ip":$di, "dst_port":$dp, "comment":$c}]' "$META_FILE") \
        && echo "$tmp" > "$META_FILE"

    reload_realm true
    echo ""
    info "转发已添加: :${src_port} → ${dst_ip}:${dst_port}"
    echo -e "  ${DIM}提示: 如需配额/限速，在 pm.sh 中为端口 ${src_port} 添加监控${PLAIN}"
}

delete_forward() {
    local src_port=$1

    validate_port "$src_port" "源端口" || return 1
    src_port=$((10#$src_port))
    init_meta

    if ! jq -e --argjson p "$src_port" '.rules[] | select(.src_port == $p)' "$META_FILE" &>/dev/null; then
        err "源端口 ${src_port} 不存在"; return 1
    fi

    local tmp
    tmp=$(jq --argjson sp "$src_port" '.rules = [.rules[] | select(.src_port != $sp)]' "$META_FILE") \
        && echo "$tmp" > "$META_FILE"

    reload_realm true
    info "转发已删除: 源端口 ${src_port}"
    echo -e "  ${DIM}提示: 如在 pm.sh 中有对应监控，请手动移除${PLAIN}"
}

list_forwards() {
    echo ""
    init_meta
    local count
    count=$(rule_count)

    local status_icon status_text
    if ! realm_installed; then
        status_icon="${RED}●${PLAIN}"; status_text="未安装"
    elif realm_running; then
        status_icon="${GREEN}●${PLAIN}"; status_text="运行中"
    else
        status_icon="${YELLOW}●${PLAIN}"; status_text="已停止"
    fi

    echo -e "  ${BOLD}realm${PLAIN}  ${status_icon} ${status_text}   ${DIM}规则: ${count}${PLAIN}"
    if realm_installed; then
        local ver
        ver=$("$REALM_BIN" --version 2>/dev/null | grep -oP '[\d.]+' | head -1 || true)
        [[ -n "$ver" ]] && echo -e "  ${DIM}版本: v${ver}${PLAIN}"
    fi
    echo ""

    if [[ "$count" -eq 0 ]]; then
        echo -e "  ${DIM}(无转发规则)${PLAIN}"
        echo ""
        return
    fi

    printf "  %-3s  %-8s  %-24s  %s\n" "#" "源端口" "目标" "备注"
    echo -e "  -------------------------------------------------------"

    local i=1 rules
    rules=$(jq -c '.rules[]' "$META_FILE" 2>/dev/null) || return

    while IFS= read -r rule; do
        local sp dip dp cmt
        sp=$(echo "$rule"  | jq -r '.src_port')
        dip=$(echo "$rule" | jq -r '.dst_ip')
        dp=$(echo "$rule"  | jq -r '.dst_port')
        cmt=$(echo "$rule" | jq -r '.comment // ""')
        printf "  %-3s  %-8s  %-24s  %s\n" "$i" ":${sp}" "${dip}:${dp}" "$cmt"
        i=$((i + 1))
    done <<< "$rules"
    echo ""
}

# ============================================================================
# 完整卸载
# ============================================================================

full_uninstall() {
    echo ""
    echo -e "${RED}========================================${PLAIN}"
    echo -e "${RED}  警告: 即将卸载 realm 并清除全部配置!${PLAIN}"
    echo -e "${RED}========================================${PLAIN}"
    echo ""
    echo " 将清除: realm 二进制 / 所有转发配置 / systemd 服务 / fw 快捷命令"
    echo ""
    read -rp " 输入 yes 确认: " confirm || return
    confirm=$(strip_cr "$confirm")
    [[ "${confirm,,}" == "yes" ]] || { echo " 已取消。"; return; }

    echo ""
    if realm_running; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        info "realm 已停止"
    fi

    if [[ -f "$SERVICE_FILE" ]]; then
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        info "systemd 服务已删除"
    fi

    rm -f "$REALM_BIN"
    rm -rf "$CONFIG_DIR"
    rm -f "$INSTALL_PATH"
    info "完整卸载完成"
    echo -e "  ${DIM}提示: pm.sh 中的相关端口监控需手动移除${PLAIN}"
}

# ============================================================================
# 交互菜单
# ============================================================================

menu_add() {
    echo ""
    echo -e " ${BOLD}添加转发规则${PLAIN}"
    echo ""

    local src_port dst_ip dst_port comment

    read -rp " 源端口 (本机监听): " src_port || return
    src_port=$(strip_cr "$src_port")
    [[ -n "$src_port" ]] || return

    read -rp " 目标 IP: " dst_ip || return
    dst_ip=$(strip_cr "$dst_ip")
    [[ -n "$dst_ip" ]] || return

    read -rp " 目标端口 [${src_port}]: " dst_port || return
    dst_port=$(strip_cr "$dst_port")
    [[ -n "$dst_port" ]] || dst_port="$src_port"

    read -rp " 备注 (可选): " comment || true
    comment=$(strip_cr "$comment")

    echo ""
    echo -e " :${src_port} → ${dst_ip}:${dst_port}  ${DIM}${comment}${PLAIN}"
    read -rp " 确认? [Y/n] " confirm || return
    confirm=$(strip_cr "$confirm")
    [[ "$confirm" =~ ^[nN] ]] && { echo " 已取消"; return; }

    echo ""
    add_forward "$src_port" "$dst_ip" "$dst_port" "$comment"
}

menu_delete() {
    echo ""
    local count
    count=$(rule_count)

    if [[ "$count" -eq 0 ]]; then
        echo -e " ${DIM}(无转发规则)${PLAIN}"
        return
    fi

    echo -e " ${BOLD}删除转发规则${PLAIN}"
    echo ""

    local i=1 rules
    rules=$(jq -c '.rules[]' "$META_FILE" 2>/dev/null) || return

    while IFS= read -r rule; do
        local sp dip dp cmt
        sp=$(echo "$rule"  | jq -r '.src_port')
        dip=$(echo "$rule" | jq -r '.dst_ip')
        dp=$(echo "$rule"  | jq -r '.dst_port')
        cmt=$(echo "$rule" | jq -r '.comment // ""')
        echo -e " [${i}]  :${sp} → ${dip}:${dp}  ${DIM}${cmt}${PLAIN}"
        i=$((i + 1))
    done <<< "$rules"

    echo ""
    read -rp " 输入序号删除 (0=取消): " choice || return
    choice=$(strip_cr "$choice")
    [[ "$choice" =~ ^[0-9]+$ ]] || { warn "输入无效"; return; }
    [[ "$choice" -eq 0 ]] && return
    if [[ "$choice" -lt 1 || "$choice" -gt "$count" ]]; then
        warn "序号超出范围"; return
    fi

    local src_port
    src_port=$(jq -r ".rules[$(( choice - 1 ))].src_port" "$META_FILE")

    echo ""
    delete_forward "$src_port"
}

menu_status() {
    echo ""
    echo -e " ${BOLD}服务状态${PLAIN}"
    echo ""

    if ! realm_installed; then
        echo -e " realm: ${RED}未安装${PLAIN}"
        echo ""
        return
    fi

    local ver
    ver=$("$REALM_BIN" --version 2>/dev/null | grep -oP '[\d.]+' | head -1 || true)
    echo -e " 版本: ${BOLD}v${ver:-unknown}${PLAIN}"
    echo -e " 二进制: ${REALM_BIN}"
    echo -e " 配置: ${CONFIG_TOML}"
    echo ""

    if realm_running; then
        echo -e " 状态: ${GREEN}● 运行中${PLAIN}"
        local pid mem
        pid=$(systemctl show -p MainPID "$SERVICE_NAME" 2>/dev/null | cut -d= -f2)
        if [[ -n "$pid" && "$pid" != "0" ]]; then
            mem=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
            echo -e " PID: ${pid}  内存: ${mem}"
        fi
        echo ""
        echo -e " ${DIM}监听端口:${PLAIN}"
        ss -tlnp 2>/dev/null | grep realm | awk '{print "   " $4}' | head -20
    else
        echo -e " 状态: ${YELLOW}● 已停止${PLAIN}"
        echo ""
        if journalctl -u "$SERVICE_NAME" -n 1 &>/dev/null 2>&1; then
            echo -e " ${DIM}最近日志:${PLAIN}"
            journalctl -u "$SERVICE_NAME" -n 5 --no-pager 2>/dev/null | sed 's/^/   /'
        fi
    fi
    echo ""
}

show_menu() {
    while true; do
        clear
        local count status_str
        count=$(rule_count)

        if ! realm_installed; then
            status_str="${RED}未安装${PLAIN}"
        elif realm_running; then
            status_str="${GREEN}运行中${PLAIN}"
        else
            status_str="${YELLOW}已停止${PLAIN}"
        fi

        echo -e "${BLUE}================================================================${PLAIN}"
        echo -e "   端口转发管理 (v${SCRIPT_VERSION}) - realm ${status_str}  ${DIM}规则: ${count}${PLAIN}"
        echo -e "${BLUE}================================================================${PLAIN}"

        list_forwards

        echo -e " 1. 添加转发规则"
        echo -e " 2. 删除转发规则"
        echo -e " 3. 服务状态"

        if ! realm_installed; then
            echo -e " 4. ${GREEN}安装 realm${PLAIN}"
        else
            echo -e " 4. 重新安装 realm"
        fi

        echo -e " 5. ${RED}完整卸载${PLAIN}"
        echo -e " 0. 退出"
        echo -e "${BLUE}================================================================${PLAIN}"
        read -rp " 请选择: " choice || break
        choice=$(strip_cr "$choice")

        case $choice in
            1)
                if ! realm_installed; then
                    warn "realm 未安装"
                    read -rp " 现在安装? [Y/n] " c || continue
                    c=$(strip_cr "$c")
                    [[ "$c" =~ ^[nN] ]] && continue
                    install_realm
                fi
                menu_add
                ;;
            2) menu_delete ;;
            3) menu_status; read -rp " 按回车继续..." _ || true ;;
            4) install_realm; read -rp " 按回车继续..." _ || true ;;
            5) full_uninstall; read -rp " 按回车继续..." _ || true ;;
            0|"") echo ""; break ;;
            *) ;;
        esac
    done
}

# ============================================================================
# 入口
# ============================================================================

check_root
check_jq
install_shortcut
init_meta

case "${1:-}" in
    install)      install_realm ;;
    uninstall)    full_uninstall ;;
    list|ls)      list_forwards ;;
    status)       menu_status ;;
    add)
        if ! realm_installed; then
            die "realm 未安装，请先: $0 install"
        fi
        [[ $# -ge 4 ]] || die "用法: $0 add <源端口> <目标IP> <目标端口> [备注]"
        add_forward "$2" "$3" "$4" "${5:-}"
        ;;
    del|delete|rm)
        [[ $# -ge 2 ]] || die "用法: $0 del <源端口>"
        delete_forward "$2"
        ;;
    -h|--help|help)
        echo ""
        echo " fw.sh — 端口转发管理器 (基于 realm) v${SCRIPT_VERSION}"
        echo ""
        echo " 用法:"
        echo "   fw                交互菜单"
        echo "   fw install        安装 realm"
        echo "   fw list           列出转发规则"
        echo "   fw add SP DIP DP [备注]"
        echo "   fw del SP         删除转发"
        echo "   fw status         服务状态"
        echo "   fw uninstall      完整卸载"
        echo ""
        echo " 配额/限速: 在 pm.sh 中为相同端口添加监控"
        echo ""
        ;;
    "") show_menu ;;
    *)  die "未知命令: $1 ($0 help 查看帮助)" ;;
esac
