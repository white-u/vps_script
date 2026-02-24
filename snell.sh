#!/bin/bash
#
# Snell 多实例管理脚本 v5.0
# - 支持单机运行多个 Snell 实例 (不同端口)
# - 支持 Systemd 模板化管理 (snell@port)
# - 自动配置快捷命令 'snell'
#
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh)

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

SCRIPT_VERSION="5.0"

SNELL_BIN="/usr/local/bin/snell-server"
SNELL_CONF_DIR="/etc/snell"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_FILE="${SYSTEMD_DIR}/snell@.service"
DL_BASE="https://dl.nssurge.com/snell"

# 快捷命令路径
SCRIPT_PATH="/usr/local/bin/snell"
# 脚本远程地址 (用于管道运行时自动下载安装快捷命令)
SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh"

# 版本兜底 (如果官网抓取失败，使用此版本)
FALLBACK_VERSION="5.0.1"

# 读取已安装的 Snell 主版本号 (从 .version 文件)
get_installed_major_ver() {
    local ver_file="${SNELL_CONF_DIR}/.version"
    if [[ -f "$ver_file" ]]; then
        cut -d. -f1 < "$ver_file"
    else
        echo "5"
    fi
}

# 读取完整版本号
get_installed_full_ver() {
    local ver_file="${SNELL_CONF_DIR}/.version"
    if [[ -f "$ver_file" ]]; then
        cat "$ver_file"
    else
        echo ""
    fi
}

# 获取实例运行状态
get_instance_status() {
    local port=$1
    if systemctl is-active --quiet "snell@${port}" 2>/dev/null; then
        echo -e "${GREEN}运行中${PLAIN}"
    else
        echo -e "${RED}已停止${PLAIN}"
    fi
}

# ==================== 基础函数 ====================
err() { echo -e "${RED}❌ 错误: $1${PLAIN}"; exit 1; }
info() { echo -e "${GREEN}INFO: $1${PLAIN}"; }
warn() { echo -e "${YELLOW}警告: $1${PLAIN}"; }
strip_cr() { echo "${1//$'\r'/}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "请使用 root 用户运行此脚本: sudo bash snell.sh"
    fi
}

# 同步快捷命令 (入口处调用, 确保 /usr/local/bin/snell 与运行版本一致)
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

# 架构检测
map_arch() {
    case $(uname -m) in
        x86_64) echo "amd64" ;;
        aarch64|armv8*) echo "aarch64" ;;
        *) err "不支持的架构: $(uname -m)" ;;
    esac
}

# 依赖检查
check_deps() {
    local deps=("curl" "wget" "unzip")
    local need_install=0
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then need_install=1; fi
    done
    
    if [[ $need_install -eq 1 ]]; then
        info "安装必要依赖..."
        if [ -f /etc/debian_version ]; then
            apt-get update && apt-get install -y "${deps[@]}"
        elif [ -f /etc/redhat-release ]; then
            yum install -y "${deps[@]}" || true
        elif [ -f /etc/alpine-release ]; then
            apk add "${deps[@]}" || true
        fi
        # 验证关键依赖是否真正可用
        local dep; for dep in "${deps[@]}"; do
            command -v "$dep" &>/dev/null || err "依赖安装失败: $dep，请手动安装"
        done
    fi
}

# 版本获取 (混合模式: 爬虫 + 兜底)
get_latest_version() {
    local ver
    # 尝试从 Surge 知识库获取
    ver=$(curl -sL --max-time 3 "https://kb.nssurge.com/surge-knowledge-base/release-notes/snell" | \
          grep -oE 'snell-server-v[0-9]+\.[0-9]+\.[0-9]+-linux' | \
          sed 's/snell-server-v//g; s/-linux//g' | sort -V | tail -1 || true)
    
    if [[ -z "$ver" ]]; then
        echo "$FALLBACK_VERSION"
    else
        echo "$ver"
    fi
}

# ==================== 核心逻辑 ====================

# 1. 安装/更新 Snell 核心二进制
install_core() {
    check_root
    check_deps
    
    local arch
    arch=$(map_arch)
    local ver
    ver=$(get_latest_version)
    
    echo -e "${BLUE}>>> 准备安装 Snell Core v${ver} (${arch})${PLAIN}"
    
    # 停止所有正在运行的 snell 实例 (为了覆盖二进制)
    # 这是一个稍微暴力的操作，但在更新核心时是必须的
    local port conf
    if ls "${SNELL_CONF_DIR}"/*.conf >/dev/null 2>&1; then
        warn "正在暂停所有 Snell 实例以更新核心..."
        for conf in "${SNELL_CONF_DIR}"/*.conf; do
            port=$(basename "$conf" .conf)
            systemctl stop "snell@${port}" 2>/dev/null || true
        done
    fi

    local url="${DL_BASE}/snell-server-v${ver}-linux-${arch}.zip"
    local tmp_file
    tmp_file=$(mktemp /tmp/snell.XXXXXX.zip)
    local tmp_dir
    tmp_dir=$(mktemp -d /tmp/snell_extract.XXXXXX)
    _CLEANUP_FILES+=("$tmp_file" "$tmp_dir")
    
    if ! curl -L -o "$tmp_file" --progress-bar "$url"; then
        err "下载失败，请检查网络。"
    fi
    
    # 解压到临时目录，只提取二进制，防止 README 等文件污染 /usr/local/bin/
    if ! unzip -o "$tmp_file" -d "$tmp_dir" >/dev/null; then
        err "解压失败。"
    fi
    
    if [[ ! -f "$tmp_dir/snell-server" ]]; then
        err "压缩包中未找到 snell-server 二进制文件。"
    fi
    
    mv -f "$tmp_dir/snell-server" "$SNELL_BIN"
    rm -rf "$tmp_file" "$tmp_dir"
    chmod +x "$SNELL_BIN"
    
    # 赋予绑定低端口能力 (允许非 root 绑定 80/443)
    if command -v setcap >/dev/null; then
        setcap cap_net_bind_service=+ep "$SNELL_BIN" 2>/dev/null || true
    fi
    
    # 创建用户
    id -u snell &>/dev/null || useradd -r -s /usr/sbin/nologin snell
    
    # 创建配置目录
    mkdir -p "$SNELL_CONF_DIR"
    chown snell:snell "$SNELL_CONF_DIR"

    # 安装 Systemd 模板文件 (核心: 支持 snell@10000 这种调用方式)
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Snell Proxy Service on Port %i
After=network.target

[Service]
Type=simple
User=snell
Group=snell
# 允许绑定特权端口
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
# %i 代表 systemctl start snell@XXXX 中的 XXXX (即端口号)
ExecStart=${SNELL_BIN} -c ${SNELL_CONF_DIR}/%i.conf
Restart=always
RestartSec=3
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
    if ! systemctl daemon-reload; then
        err "systemctl daemon-reload 失败，请检查 systemd 状态。"
    fi

    # 恢复服务
    if ls "${SNELL_CONF_DIR}"/*.conf >/dev/null 2>&1; then
        for conf in "${SNELL_CONF_DIR}"/*.conf; do
            port=$(basename "$conf" .conf)
            systemctl start "snell@${port}" 2>/dev/null || true
        done
    fi
    
    info "Snell 核心安装/更新完成 (v${ver})"
    # 记录已安装版本号, 供配置输出使用
    echo "$ver" > "${SNELL_CONF_DIR}/.version"
}

# 2. 添加新实例 (多实例逻辑)
add_instance() {
    if [[ ! -f "$SNELL_BIN" ]]; then
        err "未检测到 Snell 核心，请先执行安装核心。"
    fi

    echo -e "${BLUE}>>> 添加新的 Snell 实例${PLAIN}"
    
    # 端口输入与检查
    local port
    while true; do
        read -rp "请输入端口号 (1-65535): " port || return
        port=$(strip_cr "$port")
        [[ "$port" =~ ^[0-9]+$ ]] || { echo "输入无效"; continue; }
        if [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then echo "范围无效"; continue; fi
        
        if [ -f "${SNELL_CONF_DIR}/${port}.conf" ]; then
            warn "端口 $port 的配置文件已存在!"
            read -rp "是否覆盖? [y/N]: " override
            override=$(strip_cr "$override")
            [[ "${override,,}" == "y" ]] && break
        else
            # 简单检查系统端口占用
            if ss -tuln | grep -qE ":$port "; then
                warn "系统提示端口 $port 可能被占用 (如果是旧的 Snell 实例可以忽略)"
            fi
            break
        fi
    done
    
    # 生成 PSK
    local psk
    psk=$(tr -dc A-Za-z0-9 </dev/urandom 2>/dev/null | head -c 25 || true)
    if [[ -z "$psk" ]]; then
        err "PSK 生成失败，请检查 /dev/urandom 是否可用。"
    fi
    
    # 写入配置文件 (文件名必须是 端口.conf)
    cat > "${SNELL_CONF_DIR}/${port}.conf" <<EOF
[snell-server]
listen = ::0:${port}
psk = ${psk}
ipv6 = true
tfo = true
obfs = off
dns = 1.1.1.1, 8.8.8.8, 2001:4860:4860::8888
EOF
    chown snell:snell "${SNELL_CONF_DIR}/${port}.conf"
    chmod 600 "${SNELL_CONF_DIR}/${port}.conf"
    
    # 防火墙放行
    open_port "$port"
    
    # 启动特定实例
    systemctl enable "snell@${port}" >/dev/null 2>&1 || true
    systemctl restart "snell@${port}" 2>/dev/null || true
    
    if systemctl is-active --quiet "snell@${port}"; then
        info "实例 (端口: $port) 启动成功!"
        show_single_config "$port"
    else
        err "实例启动失败，请检查日志: journalctl -u snell@${port} -n 20"
    fi
}

# 3. 删除实例
del_instance() {
    # 扫描现有配置
    local configs=(${SNELL_CONF_DIR}/*.conf)
    if [[ ! -e "${configs[0]}" ]]; then
        warn "没有找到任何运行的实例。"
        return
    fi
    
    echo -e " ${BLUE}>>> 删除 Snell 实例${PLAIN}"
    echo -e " ─────────────────────────────────────"
    
    local i=1
    local ports=()
    for conf in "${configs[@]}"; do
        local p
        p=$(basename "$conf" .conf)
        ports+=("$p")
        local status
        status=$(get_instance_status "$p")
        printf "  [%d]  端口: %-8s  状态: %b\n" $i "$p" "$status"
        i=$((i+1))
    done
    echo -e " ─────────────────────────────────────"
    
    read -rp "请选择要删除的序号 (输入 0 取消): " choice
    choice=$(strip_cr "$choice")
    [[ "$choice" == "0" ]] && return
    [[ "$choice" =~ ^[0-9]+$ ]] || { warn "输入无效"; return; }
    
    local idx=$((choice-1))
    if [[ $idx -ge ${#ports[@]} ]]; then
        warn "序号超出范围"
        return
    fi
    local target_port="${ports[$idx]}"
    
    read -rp "确认删除端口 $target_port 的实例? [y/N]: " confirm
    confirm=$(strip_cr "$confirm")
    if [[ "${confirm,,}" == "y" ]]; then
        systemctl stop "snell@${target_port}" 2>/dev/null || true
        systemctl disable "snell@${target_port}" >/dev/null 2>&1 || true
        rm -f "${SNELL_CONF_DIR}/${target_port}.conf"
        close_port "$target_port"
        info "实例 $target_port 已删除。"
    else
        echo "已取消。"
    fi
}

# 4. 查看所有配置
show_all_configs() {
    local configs=(${SNELL_CONF_DIR}/*.conf)
    if [[ ! -e "${configs[0]}" ]]; then
        warn "暂无实例配置。"
        return
    fi
    
    local ip
    ip=$(curl -s4m3 ip.sb || curl -s4m3 api.ipify.org || echo "YOUR_IP")
    local snell_ver
    snell_ver=$(get_installed_major_ver)
    
    echo -e " ${BLUE}>>> Snell 节点配置清单${PLAIN}"
    echo -e " ════════════════════════════════════════════════════════════════"
    for conf in "${configs[@]}"; do
        local p
        p=$(basename "$conf" .conf)
        local key
        key=$(grep '^psk *=' "$conf" | cut -d= -f2 | tr -d '[:space:]' || true)
        local status
        status=$(get_instance_status "$p")
        
        echo -e " ${GREEN}▶ 端口: $p${PLAIN}  状态: $status"
        echo -e "   ${DIM}snell-$p = snell, $ip, $p, psk=$key, version=${snell_ver}, tfo=true, reuse=true${PLAIN}"
        echo -e " ────────────────────────────────────────────────────────────────"
    done
    echo -e " ${DIM}提示: 可直接复制上方配置到 Surge / Stash / Shadowrocket 中使用。${PLAIN}"
}

show_single_config() {
    local port=$1
    local conf="${SNELL_CONF_DIR}/${port}.conf"
    local ip
    ip=$(curl -s4m3 ip.sb || curl -s4m3 api.ipify.org || echo "YOUR_IP")
    local key
    key=$(grep '^psk *=' "$conf" | cut -d= -f2 | tr -d '[:space:]' || true)
    local snell_ver
    snell_ver=$(get_installed_major_ver)
    
    echo -e " ────────────────────────────────────────────────────────────────"
    echo -e " ${GREEN}▶ 端口 ${port} 客户端配置:${PLAIN}"
    echo -e "   snell-$port = snell, $ip, $port, psk=$key, version=${snell_ver}, tfo=true, reuse=true"
    echo -e " ────────────────────────────────────────────────────────────────"
}

# 防火墙工具
open_port() {
    local port=$1
    if command -v ufw >/dev/null 2>&1; then
        ufw allow "$port" >/dev/null 2>&1
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1
        firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    elif command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -I INPUT -p udp --dport "$port" -j ACCEPT
        # 尝试持久化 (可能不存在)
        if command -v iptables-save >/dev/null 2>&1; then
            mkdir -p /etc/iptables 2>/dev/null || true
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    fi
}

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

# 更新管理脚本
update_script() {
    echo
    echo -e " ${BLUE}>>> 更新管理脚本${PLAIN}"
    echo -e " 当前版本: v${SCRIPT_VERSION}"
    echo -e " 远程地址: ${DIM}${SCRIPT_URL}${PLAIN}"
    echo

    local tmp_script
    tmp_script=$(mktemp /tmp/snell_update.XXXXXX.sh)
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

# 彻底卸载
uninstall_all() {
    echo
    echo -e " ${RED}════════════════════════════════════════${PLAIN}"
    echo -e " ${RED}  警告: 即将卸载 Snell 核心及所有实例!${PLAIN}"
    echo -e " ${RED}════════════════════════════════════════${PLAIN}"
    echo
    read -rp " 确认执行? (输入 yes 确认): " confirm
    confirm=$(strip_cr "$confirm")
    [[ "${confirm,,}" != "yes" ]] && { echo " 已取消。"; return; }
    
    # 停止并删除所有实例服务
    local port conf
    if ls "${SNELL_CONF_DIR}"/*.conf >/dev/null 2>&1; then
        for conf in "${SNELL_CONF_DIR}"/*.conf; do
            port=$(basename "$conf" .conf)
            systemctl stop "snell@${port}" 2>/dev/null || true
            systemctl disable "snell@${port}" >/dev/null 2>&1 || true
        done
    fi
    
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    
    rm -rf "$SNELL_CONF_DIR"
    rm -f "$SNELL_BIN"
    rm -f "$SCRIPT_PATH"
    
    userdel snell >/dev/null 2>&1 || true
    
    info "Snell 已彻底卸载。"
    exit 0
}

# ==================== 菜单 ====================
menu() {
    clear
    echo -e "========================================================================================="
    echo -e "   Snell 多实例管理脚本 (v${SCRIPT_VERSION})"
    echo -e "========================================================================================="

    # ---- 状态面板 ----
    local core_status="${RED}未安装${PLAIN}"
    if [ -f "$SNELL_BIN" ]; then
        local full_ver
        full_ver=$(get_installed_full_ver)
        if [[ -n "$full_ver" ]]; then
            core_status="${GREEN}v${full_ver}${PLAIN}"
        else
            core_status="${GREEN}已安装${PLAIN} ${DIM}(版本未知)${PLAIN}"
        fi
    fi
    echo -e " 核心状态: ${core_status}    架构: $(uname -m)"
    echo -e "-----------------------------------------------------------------------------------------"

    # ---- 实例列表 ----
    if ls "${SNELL_CONF_DIR}"/*.conf >/dev/null 2>&1; then
        printf " %-6s %-10s %-12s %-8s %-8s %-s\n" "序号" "端口" "状态" "IPv6" "混淆" "PSK"
        echo -e " ─────────────────────────────────────────────────────────────────────────────────────"

        local i=1
        for conf in "${SNELL_CONF_DIR}"/*.conf; do
            local p
            p=$(basename "$conf" .conf)
            local status
            status=$(get_instance_status "$p")
            local key
            key=$(grep '^psk *=' "$conf" | cut -d= -f2 | tr -d '[:space:]' || true)
            local obfs
            obfs=$(grep '^obfs *=' "$conf" | cut -d= -f2 | tr -d '[:space:]' || true)
            local ipv6
            ipv6=$(grep '^ipv6 *=' "$conf" | cut -d= -f2 | tr -d '[:space:]' || true)
            local psk_short="${key:0:8}..."

            printf " [%d]    %-10s %b  %-8s %-8s %-s\n" \
                $i "$p" "$status" "${ipv6:-true}" "${obfs:-off}" "$psk_short"
            i=$((i+1))
        done
    else
        echo -e " ${DIM}暂无实例，请先安装核心并添加实例。${PLAIN}"
    fi

    echo -e "========================================================================================="
    echo
    echo -e " 1. 安装 / 更新 Snell 核心"
    echo -e " 2. ${GREEN}添加实例 (新端口)${PLAIN}"
    echo -e " 3. 删除实例"
    echo -e " 4. 查看客户端配置"
    echo -e " 5. 更新管理脚本"
    echo -e " 6. ${RED}卸载全部${PLAIN}"
    echo -e " 0. 退出"
    echo -e "========================================================================================="
    read -rp " 请输入选项: " choice
    choice=$(strip_cr "$choice")
    
    case $choice in
        1) install_core; read -rp " 按回车返回..." ;;
        2) add_instance; read -rp " 按回车返回..." ;;
        3) del_instance; read -rp " 按回车返回..." ;;
        4) show_all_configs; read -rp " 按回车返回..." ;;
        5) update_script; read -rp " 按回车返回..." ;;
        6) uninstall_all ;;
        0) exit 0 ;;
        *) ;;
    esac
}

# ==================== 入口 ====================
check_root
sync_script

if [[ $# -gt 0 ]]; then
    case "$1" in
        install) install_core ;;
        add)     add_instance ;;
        update)  update_script ;;
        *)       menu ;;
    esac
else
    while true; do
        menu
    done
fi