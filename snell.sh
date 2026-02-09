#!/bin/bash
#
# Snell 多实例管理脚本 (星辰大海架构复刻版 v4.1)
# - 支持单机运行多个 Snell 实例 (不同端口)
# - 支持 Systemd 模板化管理 (snell@port)
# - 自动配置快捷命令 'snell'

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
PLAIN="\033[0m"

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
            yum install -y "${deps[@]}"
        elif [ -f /etc/alpine-release ]; then
            apk add "${deps[@]}"
        else
            err "无法自动安装依赖，请手动安装: curl wget unzip"
        fi
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
    
    # 安装快捷命令 (Self-Install)
    if [[ -f "$0" ]] && [[ "$(basename "$0")" != "bash" ]] && [[ "$(basename "$0")" != "sh" ]]; then
        # 文件模式: 直接复制
        if [[ ! -f "$SCRIPT_PATH" ]] || [[ "$(realpath "$0")" != "$SCRIPT_PATH" ]]; then
            cp "$0" "$SCRIPT_PATH"
            chmod +x "$SCRIPT_PATH"
            info "快捷命令 'snell' 已安装，以后可直接运行。"
        fi
    else
        # 管道/进程替换模式: 从远程下载
        if [[ ! -f "$SCRIPT_PATH" ]]; then
            info "管道运行模式，正在从远程下载脚本安装快捷命令..."
            if curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH" 2>/dev/null; then
                chmod +x "$SCRIPT_PATH"
                info "快捷命令 'snell' 已安装，以后可直接运行。"
            else
                warn "快捷命令安装失败 (网络问题)，核心功能不受影响。"
            fi
        fi
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
    
    echo -e "${BLUE}>>> 删除 Snell 实例${PLAIN}"
    echo "当前运行的实例:"
    
    local i=1
    local ports=()
    for conf in "${configs[@]}"; do
        local p
        p=$(basename "$conf" .conf)
        ports+=("$p")
        echo -e "  $i. 端口: ${GREEN}$p${PLAIN}"
        i=$((i+1))
    done
    
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
    
    echo -e "${BLUE}=== Snell 节点配置清单 ===${PLAIN}"
    for conf in "${configs[@]}"; do
        local p
        p=$(basename "$conf" .conf)
        # 读取 PSK
        local key
        key=$(grep '^psk *=' "$conf" | cut -d= -f2 | tr -d '[:space:]' || true)
        
        echo -e "${GREEN}端口: $p${PLAIN}"
        echo -e "Surge/Shadowrocket:"
        echo -e "snell-$p = snell, $ip, $p, psk=$key, version=${snell_ver}, tfo=true, reuse=true, ipv6=true"
        echo "---------------------------------------------------"
    done
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
    
    echo
    echo -e "--- 端口 ${port} 配置 ---"
    echo -e "snell-$port = snell, $ip, $port, psk=$key, version=${snell_ver}, tfo=true, reuse=true, ipv6=true"
    echo
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

# 彻底卸载
uninstall_all() {
    echo -e "${RED}警告: 即将卸载 Snell 核心及所有实例配置!${PLAIN}"
    read -rp "确认执行? [y/N]: " confirm
    confirm=$(strip_cr "$confirm")
    [[ "${confirm,,}" != "y" ]] && return
    
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
    echo -e "${BLUE}########## Snell 多实例管理脚本 v4.1 ##########${PLAIN}"
    echo -e "------------------------------------------------"
    
    local core_ver="未安装"
    if [ -f "$SNELL_BIN" ]; then
        if [[ -f "${SNELL_CONF_DIR}/.version" ]]; then
            core_ver="v$(cat "${SNELL_CONF_DIR}/.version")"
        else
            core_ver="已安装 (版本未知)"
        fi
    fi
    
    echo -e "核心状态: ${GREEN}${core_ver}${PLAIN}"
    echo
    echo -e "1. 安装 / 更新 Snell 核心"
    echo -e "2. ${GREEN}添加新的 Snell 实例 (端口)${PLAIN}"
    echo -e "3. 删除已有实例"
    echo -e "4. 查看所有配置链接"
    echo -e "5. 卸载全部 (Core + 所有实例)"
    echo -e "0. 退出"
    echo
    read -rp "请输入选项: " choice
    choice=$(strip_cr "$choice")
    
    case $choice in
        1) install_core; read -rp "按回车返回..." ;;
        2) add_instance; read -rp "按回车返回..." ;;
        3) del_instance; read -rp "按回车返回..." ;;
        4) show_all_configs; read -rp "按回车返回..." ;;
        5) uninstall_all ;;
        0) exit 0 ;;
        *) warn "无效选项, 请重新输入" ;;
    esac
}

# 入口判断
if [[ $# -gt 0 ]]; then
    # 命令行参数: 单次执行
    case "$1" in
        install) install_core ;;
        add) add_instance ;;
        *) menu ;;
    esac
else
    # 交互模式: 循环菜单
    while true; do
        menu
    done
fi