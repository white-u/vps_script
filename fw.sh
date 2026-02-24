#!/bin/bash
#
# 端口转发管理脚本 (基于 realm) v1.0
# - 支持 TCP/UDP 端口转发
# - 与 pm.sh 流量监控无缝协作
# - 基于 realm 用户态转发，无需内核 FORWARD 链
#
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/fw.sh)

set -euo pipefail

# 临时资源清理 (Ctrl+C / 异常退出时自动清理)
_CLEANUP_FILES=()
cleanup() {
    for f in "${_CLEANUP_FILES[@]+"${_CLEANUP_FILES[@]}"}"; do
        rm -rf "$f" 2>/dev/null
    done
}
trap cleanup EXIT INT TERM

# ==================== 变量定义 ====================
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
DIM="\033[2m"
PLAIN="\033[0m"

SCRIPT_VERSION="1.0"
REALM_VERSION="2.7.0"

REALM_BIN="/usr/local/bin/realm"
CONFIG_DIR="/etc/realm"
CONFIG_TOML="${CONFIG_DIR}/config.toml"
META_FILE="${CONFIG_DIR}/fw.json"
SERVICE_NAME="realm"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# 快捷命令路径
SCRIPT_PATH="/usr/local/bin/fw"
# 脚本远程地址 (用于管道运行时自动下载安装快捷命令)
SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/fw.sh"

# ==================== 基础函数 ====================
err() { echo -e "${RED}❌ 错误: $1${PLAIN}"; exit 1; }
info() { echo -e "${GREEN}INFO: $1${PLAIN}"; }
warn() { echo -e "${YELLOW}警告: $1${PLAIN}"; }
strip_cr() { echo "${1//$'\r'/}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "请使用 root 用户运行此脚本: sudo bash fw.sh"
    fi
}

# 同步快捷命令 (入口处调用, 确保 /usr/local/bin/fw 与运行版本一致)
sync_script() {
    if [[ -f "$0" ]] && [[ "$(basename "$0")" != "bash" ]] && [[ "$(basename "$0")" != "sh" ]]; then
        # 文件模式: 直接复制 (跳过从快捷命令自身运行的情况)
        if [[ "$(realpath "$0" 2>/dev/null)" != "$(realpath "$SCRIPT_PATH" 2>/dev/null)" ]]; then
            cp "$0" "$SCRIPT_PATH"
            chmod +x "$SCRIPT_PATH"
        fi
    else
        # 管道/进程替换模式: 从远程下载覆盖
        if curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH" 2>/dev/null; then
            chmod +x "$SCRIPT_PATH"
        fi
    fi
}

# 依赖检查
check_deps() {
    command -v jq &>/dev/null && return 0
    info "安装必要依赖..."
    if [ -f /etc/debian_version ]; then
        apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq jq >/dev/null 2>&1
    elif [ -f /etc/redhat-release ]; then
        yum install -y jq >/dev/null 2>&1 || true
    elif [ -f /etc/alpine-release ]; then
        apk add jq >/dev/null 2>&1 || true
    fi
    command -v jq &>/dev/null || err "jq 安装失败，请手动安装"
}

# 架构检测
detect_arch() {
    case $(uname -m) in
        x86_64|amd64)  echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        armv7*)        echo "armv7-unknown-linux-gnueabihf" ;;
        *) err "不支持的架构: $(uname -m)" ;;
    esac
}

realm_installed() { [[ -x "$REALM_BIN" ]]; }
realm_running()   { systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; }

# 获取 realm 运行状态 (带颜色)
get_realm_status() {
    if ! realm_installed; then
        echo -e "${RED}未安装${PLAIN}"
    elif realm_running; then
        echo -e "${GREEN}运行中${PLAIN}"
    else
        echo -e "${YELLOW}已停止${PLAIN}"
    fi
}

# 获取已安装的 realm 版本
get_realm_version() {
    if realm_installed; then
        "$REALM_BIN" --version 2>/dev/null | grep -oP '[\d.]+' | head -1 || true
    fi
}

# ==================== JSON 元数据 ====================

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

# ==================== 输入校验 ====================

validate_port() {
    local port=$1 label=$2
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        warn "无效${label}: $port"; return 1
    fi
    # 去掉前导零 (jq --argjson 不接受 JSON 非法数字如 "08080")
    port=$((10#$port))
    if [[ $port -lt 1 || $port -gt 65535 ]]; then
        warn "无效${label}: $port (范围 1-65535)"; return 1
    fi
}

validate_ipv4() {
    local ip=$1
    if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        warn "无效 IP: $ip"; return 1
    fi
    local IFS='.'; local -a parts=($ip); IFS=' '
    local p; for p in "${parts[@]}"; do
        if [[ $((10#$p)) -gt 255 ]]; then
            warn "无效 IP: $ip"; return 1
        fi
    done
}

# ==================== 核心逻辑 ====================

# 1. 安装/更新 realm 核心二进制
install_realm() {
    if realm_installed; then
        local cur_ver
        cur_ver=$(get_realm_version)
        echo -e " 当前版本: ${GREEN}v${cur_ver:-unknown}${PLAIN}"
        read -rp " 是否重新安装 v${REALM_VERSION}? [y/N] " confirm || return
        confirm=$(strip_cr "$confirm")
        [[ "$confirm" =~ ^[yY] ]] || return 0
    fi

    echo -e "${BLUE}>>> 准备安装 realm v${REALM_VERSION}${PLAIN}"

    local arch_name url tmp_dir
    arch_name=$(detect_arch)
    url="https://github.com/zhboner/realm/releases/download/v${REALM_VERSION}/realm-${arch_name}.tar.gz"

    tmp_dir=$(mktemp -d /tmp/realm_install.XXXXXX)
    _CLEANUP_FILES+=("$tmp_dir")

    if ! curl -fsSL --connect-timeout 15 --max-time 120 -o "${tmp_dir}/realm.tar.gz" "$url"; then
        err "下载失败，请检查网络。"
    fi

    # 解压到临时目录，只提取二进制
    if ! tar -xzf "${tmp_dir}/realm.tar.gz" -C "$tmp_dir"; then
        err "解压失败。"
    fi

    local bin_path
    bin_path=$(find "$tmp_dir" -name "realm" -type f -perm -111 2>/dev/null | head -1)
    [[ -n "$bin_path" ]] || bin_path=$(find "$tmp_dir" -maxdepth 1 -type f ! -name "*.tar.gz" ! -name "*.sha256" | head -1)
    [[ -n "$bin_path" ]] || err "解压后未找到 realm 二进制"

    # 正在运行则先停止
    if realm_running; then
        warn "正在暂停 realm 以更新核心..."
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    fi

    cp "$bin_path" "$REALM_BIN"
    chmod +x "$REALM_BIN"

    # 安装 Systemd 服务文件
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
    if ! systemctl daemon-reload; then
        err "systemctl daemon-reload 失败，请检查 systemd 状态。"
    fi

    # 如果已有规则, 生成配置并启动
    local count
    count=$(rule_count)
    if [[ "$count" -gt 0 ]]; then
        reload_realm true
    fi

    info "realm v${REALM_VERSION} 已安装完成"
}

# 2. 配置生成
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

# 3. 重载 realm
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
        warn "realm 启动失败，请检查: journalctl -u ${SERVICE_NAME} -n 20"
    fi
}

# 4. 添加转发规则
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
        warn "源端口 ${src_port} 已存在"; return 1
    fi

    # 检查端口占用 (TCP + UDP, 排除 realm 自身)
    local port_in_use=false
    if ss -tlnp 2>/dev/null | grep -qE ":${src_port}\b"; then
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
    echo -e " ${DIM}提示: 如需配额/限速，在 pm.sh 中为端口 ${src_port} 添加监控${PLAIN}"
}

# 5. 删除转发规则
delete_forward() {
    local src_port=$1

    validate_port "$src_port" "源端口" || return 1
    src_port=$((10#$src_port))
    init_meta

    if ! jq -e --argjson p "$src_port" '.rules[] | select(.src_port == $p)' "$META_FILE" &>/dev/null; then
        warn "源端口 ${src_port} 不存在"; return 1
    fi

    local tmp
    tmp=$(jq --argjson sp "$src_port" '.rules = [.rules[] | select(.src_port != $sp)]' "$META_FILE") \
        && echo "$tmp" > "$META_FILE"

    reload_realm true
    info "转发已删除: 源端口 ${src_port}"
    echo -e " ${DIM}提示: 如在 pm.sh 中有对应监控，请手动移除${PLAIN}"
}

# 6. 查看所有配置
show_all_configs() {
    init_meta
    local count
    count=$(rule_count)

    if [[ "$count" -eq 0 ]]; then
        warn "暂无转发规则。"
        return
    fi

    echo -e " ${BLUE}>>> 转发规则清单${PLAIN}"
    echo -e " ════════════════════════════════════════════════════════════════"

    local rules
    rules=$(jq -c '.rules[]' "$META_FILE" 2>/dev/null) || return

    local i=1
    while IFS= read -r rule; do
        local sp dip dp cmt
        sp=$(echo "$rule"  | jq -r '.src_port')
        dip=$(echo "$rule" | jq -r '.dst_ip')
        dp=$(echo "$rule"  | jq -r '.dst_port')
        cmt=$(echo "$rule" | jq -r '.comment // ""')

        local cmt_str=""
        [[ -n "$cmt" ]] && cmt_str=" ${DIM}(${cmt})${PLAIN}"

        echo -e " ${GREEN}▶ :${sp} → ${dip}:${dp}${PLAIN}${cmt_str}"
        echo -e " ────────────────────────────────────────────────────────────────"
        i=$((i + 1))
    done <<< "$rules"

    echo -e " ${DIM}提示: 配额/限速请在 pm.sh 中为对应端口添加监控。${PLAIN}"
}

# 7. 更新管理脚本
update_script() {
    echo
    echo -e " ${BLUE}>>> 更新管理脚本${PLAIN}"
    echo -e " 当前版本: v${SCRIPT_VERSION}"
    echo -e " 远程地址: ${DIM}${SCRIPT_URL}${PLAIN}"
    echo

    local tmp_script
    tmp_script=$(mktemp /tmp/fw_update.XXXXXX.sh)
    _CLEANUP_FILES+=("$tmp_script")

    if ! curl -fsSL "$SCRIPT_URL" -o "$tmp_script" 2>/dev/null; then
        err "下载失败，请检查网络。"
    fi

    # 提取远程版本号
    local remote_ver
    remote_ver=$(grep '^SCRIPT_VERSION=' "$tmp_script" | head -1 | cut -d'"' -f2 || true)

    if [[ -z "$remote_ver" ]]; then
        warn "无法解析远程版本号，继续更新..."
    elif [[ "$remote_ver" == "$SCRIPT_VERSION" ]]; then
        info "已是最新版本 (v${SCRIPT_VERSION})，无需更新。"
        rm -f "$tmp_script"
        return
    else
        echo -e " 发现新版本: ${GREEN}v${remote_ver}${PLAIN}"
    fi

    mv -f "$tmp_script" "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    info "脚本已更新完成! 正在重新加载..."
    echo
    exec "$SCRIPT_PATH"
}

# 8. 完整卸载
uninstall_all() {
    echo
    echo -e " ${RED}════════════════════════════════════════${PLAIN}"
    echo -e " ${RED}  警告: 即将卸载 realm 并清除全部配置!${PLAIN}"
    echo -e " ${RED}════════════════════════════════════════${PLAIN}"
    echo
    read -rp " 确认执行? (输入 yes 确认): " confirm
    confirm=$(strip_cr "$confirm")
    [[ "${confirm,,}" != "yes" ]] && { echo " 已取消。"; return; }

    if realm_running; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    fi

    if [[ -f "$SERVICE_FILE" ]]; then
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload 2>/dev/null || true
    fi

    rm -f "$REALM_BIN"
    rm -rf "$CONFIG_DIR"
    rm -f "$SCRIPT_PATH"

    info "realm 已彻底卸载。"
    exit 0
}

# ==================== 交互菜单 ====================

menu_add() {
    echo -e "\n${BLUE}>>> 添加转发规则${PLAIN}\n"
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

    echo -e "\n :${src_port} → ${dst_ip}:${dst_port}  ${DIM}${comment}${PLAIN}"
    read -rp " 确认? [Y/n] " confirm || return
    confirm=$(strip_cr "$confirm")
    [[ "$confirm" =~ ^[nN] ]] && { echo " 已取消"; return; }

    echo
    add_forward "$src_port" "$dst_ip" "$dst_port" "$comment"
}

menu_delete() {
    local count
    count=$(rule_count)

    if [[ "$count" -eq 0 ]]; then
        warn "暂无转发规则。"
        return
    fi

    echo -e "\n${BLUE}>>> 删除转发规则${PLAIN}\n"

    local i=1 rules
    rules=$(jq -c '.rules[]' "$META_FILE" 2>/dev/null) || return

    while IFS= read -r rule; do
        local sp dip dp cmt
        sp=$(echo "$rule"  | jq -r '.src_port')
        dip=$(echo "$rule" | jq -r '.dst_ip')
        dp=$(echo "$rule"  | jq -r '.dst_port')
        cmt=$(echo "$rule" | jq -r '.comment // ""')
        printf "  [%d]  :%-8s → %s:%s  %s\n" $i "$sp" "$dip" "$dp" "$cmt"
        i=$((i + 1))
    done <<< "$rules"

    echo
    read -rp " 请选择要删除的序号 (输入 0 取消): " choice
    choice=$(strip_cr "$choice")
    [[ "$choice" == "0" ]] && return
    [[ "$choice" =~ ^[0-9]+$ ]] || { warn "输入无效"; return; }

    local idx=$((choice - 1))
    if [[ $idx -ge $count ]]; then
        warn "序号超出范围"
        return
    fi

    local target_port
    target_port=$(jq -r ".rules[$idx].src_port" "$META_FILE")

    read -rp " 确认删除源端口 $target_port 的转发? [y/N]: " confirm
    confirm=$(strip_cr "$confirm")
    if [[ "${confirm,,}" == "y" ]]; then
        echo
        delete_forward "$target_port"
    else
        echo " 已取消。"
    fi
}

menu_status() {
    echo
    echo -e " ${BLUE}>>> 服务状态${PLAIN}"
    echo

    if ! realm_installed; then
        echo -e " realm: ${RED}未安装${PLAIN}"
        return
    fi

    local ver
    ver=$(get_realm_version)
    echo -e " 版本:  v${ver:-unknown}"
    echo -e " 二进制: ${REALM_BIN}"
    echo -e " 配置:  ${CONFIG_TOML}"
    echo

    if realm_running; then
        echo -e " 状态: ${GREEN}● 运行中${PLAIN}"
        local pid mem
        pid=$(systemctl show -p MainPID "$SERVICE_NAME" 2>/dev/null | cut -d= -f2)
        if [[ -n "$pid" && "$pid" != "0" ]]; then
            mem=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
            echo -e " PID: ${pid}  内存: ${mem}"
        fi
        echo
        echo -e " ${DIM}监听端口:${PLAIN}"
        ss -tlnp 2>/dev/null | grep realm | awk '{print "   " $4}' | head -20 || true
    else
        echo -e " 状态: ${YELLOW}● 已停止${PLAIN}"
        echo
        if journalctl -u "$SERVICE_NAME" -n 1 &>/dev/null 2>&1; then
            echo -e " ${DIM}最近日志:${PLAIN}"
            journalctl -u "$SERVICE_NAME" -n 5 --no-pager 2>/dev/null | sed 's/^/   /' || true
        fi
    fi
}

# ==================== 菜单 ====================
menu() {
    clear
    echo -e "========================================================================================="
    echo -e "   端口转发管理脚本 (v${SCRIPT_VERSION})"
    echo -e "========================================================================================="

    # ---- 状态面板 ----
    local realm_status
    realm_status=$(get_realm_status)
    local ver_str=""
    if realm_installed; then
        local ver
        ver=$(get_realm_version)
        [[ -n "$ver" ]] && ver_str=" v${ver}"
    fi
    echo -e " realm 状态: ${realm_status}${ver_str}    规则: $(rule_count) 条"
    echo -e "-----------------------------------------------------------------------------------------"

    # ---- 规则列表 ----
    local count
    count=$(rule_count)
    if [[ "$count" -gt 0 ]]; then
        printf " %-4s %-10s %-24s %-s\n" "序号" "源端口" "目标" "备注"
        echo -e " ─────────────────────────────────────────────────────────────────────────────────────"

        local i=1 rules
        rules=$(jq -c '.rules[]' "$META_FILE" 2>/dev/null) || true

        while IFS= read -r rule; do
            [[ -z "$rule" ]] && continue
            local sp dip dp cmt
            sp=$(echo "$rule"  | jq -r '.src_port')
            dip=$(echo "$rule" | jq -r '.dst_ip')
            dp=$(echo "$rule"  | jq -r '.dst_port')
            cmt=$(echo "$rule" | jq -r '.comment // ""')

            printf " [%d]  %-10s %-24s %-s\n" $i ":${sp}" "${dip}:${dp}" "$cmt"
            i=$((i + 1))
        done <<< "$rules"
    else
        echo -e " ${DIM}暂无转发规则，请先安装 realm 并添加规则。${PLAIN}"
    fi

    echo -e "========================================================================================="
    echo
    echo -e " 1. ${GREEN}添加转发规则${PLAIN}"
    echo -e " 2. 删除转发规则"
    echo -e " 3. 查看规则配置"
    echo -e " 4. 服务状态"

    if ! realm_installed; then
        echo -e " 5. ${GREEN}安装 realm${PLAIN}"
    else
        echo -e " 5. 重新安装 realm"
    fi

    echo -e " 6. 更新管理脚本"
    echo -e " 7. ${RED}卸载全部${PLAIN}"
    echo -e " 0. 退出"
    echo -e "========================================================================================="
    read -rp " 请输入选项: " choice
    choice=$(strip_cr "$choice")

    case $choice in
        1)
            if ! realm_installed; then
                warn "realm 未安装"
                read -rp " 现在安装? [Y/n] " c || return
                c=$(strip_cr "$c")
                [[ "$c" =~ ^[nN] ]] && return
                install_realm
            fi
            menu_add; read -rp " 按回车返回..." ;;
        2) menu_delete; read -rp " 按回车返回..." ;;
        3) show_all_configs; read -rp " 按回车返回..." ;;
        4) menu_status; read -rp " 按回车返回..." ;;
        5) install_realm; read -rp " 按回车返回..." ;;
        6) update_script; read -rp " 按回车返回..." ;;
        7) uninstall_all ;;
        0) exit 0 ;;
        *) ;;
    esac
}

# ==================== 入口 ====================
check_root
check_deps
sync_script
init_meta

if [[ $# -gt 0 ]]; then
    case "$1" in
        install)   install_realm ;;
        uninstall) uninstall_all ;;
        list|ls)   show_all_configs ;;
        status)    menu_status ;;
        update)    update_script ;;
        add)
            realm_installed || err "realm 未安装，请先: $0 install"
            [[ $# -ge 4 ]] || err "用法: $0 add <源端口> <目标IP> <目标端口> [备注]"
            add_forward "$2" "$3" "$4" "${5:-}"
            ;;
        del|delete|rm)
            [[ $# -ge 2 ]] || err "用法: $0 del <源端口>"
            delete_forward "$2"
            ;;
        -h|--help|help)
            echo
            echo " fw.sh — 端口转发管理器 (基于 realm) v${SCRIPT_VERSION}"
            echo
            echo " 用法:"
            echo "   fw                交互菜单"
            echo "   fw install        安装 realm"
            echo "   fw list           列出转发规则"
            echo "   fw add SP DIP DP [备注]"
            echo "   fw del SP         删除转发"
            echo "   fw status         服务状态"
            echo "   fw update         更新脚本"
            echo "   fw uninstall      完整卸载"
            echo
            ;;
        *) err "未知命令: $1 ($0 help 查看帮助)" ;;
    esac
else
    while true; do
        menu
    done
fi
