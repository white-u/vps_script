#!/bin/bash
# ============================================================================
# VPS Manager - 公共模块 (完整版)
# ============================================================================

# 防止重复加载
[[ "${XXX_LOADED:-}" == "true" ]] && return 0
XXX_LOADED=true

# ============================================================================
# 版本和路径
# ============================================================================
readonly VPS_VERSION="1.0.0"
readonly VPS_NAME="VPS Manager"
readonly VPS_REPO="white-u/vps_script"
readonly VPS_BRANCH="main"

readonly VPS_DIR="/etc/vps-manager"
readonly VPS_CONFIG="$VPS_DIR/config.json"
readonly VPS_BACKUP_DIR="/var/backups/vps-manager"
readonly VPS_BIN="/usr/local/bin/vps"
readonly VPS_LIB="/usr/local/lib/vps-manager"
readonly VPS_LOCK="/var/run/vps-manager.lock"

# ============================================================================
# 颜色函数
# ============================================================================
_red()    { echo -e "\033[31m$*\033[0m"; }
_green()  { echo -e "\033[32m$*\033[0m"; }
_yellow() { echo -e "\033[33m$*\033[0m"; }
_blue()   { echo -e "\033[34m$*\033[0m"; }
_cyan()   { echo -e "\033[36m$*\033[0m"; }
_bold()   { echo -e "\033[1m$*\033[0m"; }

# 带标签的日志
log_info()  { echo -e "\033[32m[INFO]\033[0m $*"; }
log_warn()  { echo -e "\033[33m[WARN]\033[0m $*"; }
log_error() { echo -e "\033[31m[ERROR]\033[0m $*" >&2; }
log_debug() { [[ ${DEBUG:-0} -eq 1 ]] && echo -e "\033[90m[DEBUG]\033[0m $*"; }

err() {
    echo -e "\n\033[41m 错误 \033[0m $*\n" >&2
    exit 1
}

# ============================================================================
# 锁机制 (防并发)
# ============================================================================
acquire_lock() {
    local timeout=${1:-30}
    local waited=0
    
    while [[ -f "$VPS_LOCK" ]]; do
        if [[ $waited -ge $timeout ]]; then
            log_error "获取锁超时，另一个实例正在运行"
            return 1
        fi
        sleep 1
        ((waited++))
    done
    
    echo $$ > "$VPS_LOCK"
    trap "rm -f '$VPS_LOCK'" EXIT
    return 0
}

release_lock() {
    rm -f "$VPS_LOCK"
}

# ============================================================================
# 系统检测
# ============================================================================
check_root() {
    [[ $EUID -ne 0 ]] && err "请使用 root 用户运行此脚本"
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$PRETTY_NAME"
    elif [[ -f /etc/debian_version ]]; then
        OS_ID="debian"
        OS_VERSION=$(cat /etc/debian_version)
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="centos"
    else
        OS_ID="unknown"
    fi
    
    # 包管理器
    if command -v apt-get &>/dev/null; then
        PKG_CMD="apt-get"
        PKG_UPDATE="apt-get update -y"
        PKG_INSTALL="apt-get install -y"
    elif command -v dnf &>/dev/null; then
        PKG_CMD="dnf"
        PKG_UPDATE="dnf makecache"
        PKG_INSTALL="dnf install -y"
    elif command -v yum &>/dev/null; then
        PKG_CMD="yum"
        PKG_UPDATE="yum makecache"
        PKG_INSTALL="yum install -y"
    elif command -v apk &>/dev/null; then
        PKG_CMD="apk"
        PKG_UPDATE="apk update"
        PKG_INSTALL="apk add"
    else
        PKG_CMD=""
    fi
    
    export OS_ID OS_VERSION OS_NAME PKG_CMD PKG_UPDATE PKG_INSTALL
}

detect_arch() {
    case $(uname -m) in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
        i386|i686) ARCH="386" ;;
        *) ARCH="unknown" ;;
    esac
    export ARCH
}

detect_init_system() {
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null; then
        INIT_SYSTEM="systemd"
    elif [[ -f /etc/init.d/cron && ! -h /etc/init.d/cron ]]; then
        INIT_SYSTEM="sysvinit"
    elif command -v rc-service &>/dev/null; then
        INIT_SYSTEM="openrc"
    else
        INIT_SYSTEM="unknown"
    fi
    export INIT_SYSTEM
}

# ============================================================================
# 依赖安装
# ============================================================================
ensure_deps() {
    local deps=("$@")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_info "安装依赖: ${missing[*]}"
        $PKG_UPDATE &>/dev/null
        for dep in "${missing[@]}"; do
            local pkg="$dep"
            case $dep in
                jq) pkg="jq" ;;
                curl) pkg="curl" ;;
                wget) pkg="wget" ;;
                tar) pkg="tar" ;;
                unzip) pkg="unzip" ;;
                nft) pkg="nftables" ;;
                ss|ip) pkg="iproute2" ;;
                tc) pkg="iproute2" ;;
                bc) pkg="bc" ;;
                openssl) pkg="openssl" ;;
            esac
            $PKG_INSTALL "$pkg" &>/dev/null || log_warn "安装 $pkg 失败"
        done
    fi
}

# ============================================================================
# 版本比较
# ============================================================================
# 返回: 0=相等, 1=v1>v2, 2=v1<v2
compare_versions() {
    local v1="${1#v}" v2="${2#v}"
    
    [[ "$v1" == "$v2" ]] && return 0
    
    # 使用 sort -V 比较
    local smaller
    smaller=$(printf '%s\n%s' "$v1" "$v2" | sort -V | head -n1)
    
    [[ "$smaller" == "$v1" ]] && return 2 || return 1
}

# ============================================================================
# 备份/回滚机制
# ============================================================================
backup_file() {
    local file="$1"
    local service="${2:-general}"
    local backup_dir="$VPS_BACKUP_DIR/$service"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    
    [[ ! -f "$file" ]] && return 1
    
    mkdir -p "$backup_dir"
    
    local filename=$(basename "$file")
    local backup_path="$backup_dir/${filename}.${timestamp}"
    
    cp -f "$file" "$backup_path"
    log_info "已备份: $file -> $backup_path"
    
    # 保留最近5个备份
    local backups=($(ls -t "$backup_dir/${filename}."* 2>/dev/null))
    if [[ ${#backups[@]} -gt 5 ]]; then
        for old in "${backups[@]:5}"; do
            rm -f "$old"
        done
    fi
    
    echo "$backup_path"
}

restore_file() {
    local file="$1"
    local service="${2:-general}"
    local backup_dir="$VPS_BACKUP_DIR/$service"
    
    local filename=$(basename "$file")
    local latest=$(ls -t "$backup_dir/${filename}."* 2>/dev/null | head -n1)
    
    if [[ -n "$latest" && -f "$latest" ]]; then
        cp -f "$latest" "$file"
        log_info "已恢复: $latest -> $file"
        return 0
    else
        log_error "未找到备份文件"
        return 1
    fi
}

backup_binary() {
    local bin="$1"
    local service="${2:-general}"
    
    [[ ! -f "$bin" ]] && return 1
    
    local backup_dir="$VPS_BACKUP_DIR/$service"
    mkdir -p "$backup_dir"
    
    local filename=$(basename "$bin")
    local backup_path="$backup_dir/${filename}.bak"
    
    cp -f "$bin" "$backup_path"
    log_info "已备份二进制: $bin"
    echo "$backup_path"
}

restore_binary() {
    local bin="$1"
    local service="${2:-general}"
    
    local backup_dir="$VPS_BACKUP_DIR/$service"
    local filename=$(basename "$bin")
    local backup_path="$backup_dir/${filename}.bak"
    
    if [[ -f "$backup_path" ]]; then
        cp -f "$backup_path" "$bin"
        chmod +x "$bin"
        log_info "已恢复二进制: $bin"
        return 0
    else
        log_error "未找到二进制备份"
        return 1
    fi
}

# ============================================================================
# 配置管理
# ============================================================================
init_config() {
    mkdir -p "$VPS_DIR" "$VPS_BACKUP_DIR"
    
    if [[ ! -f "$VPS_CONFIG" ]]; then
        cat > "$VPS_CONFIG" <<'EOF'
{
  "telegram": {
    "enabled": false,
    "bot_token": "",
    "chat_id": "",
    "server_name": ""
  },
  "settings": {
    "auto_traffic_monitor": true,
    "auto_firewall": true,
    "auto_network_optimize": true
  },
  "version_cache": {
    "snell": {"version": "", "updated": ""},
    "singbox": {"version": "", "updated": ""}
  }
}
EOF
    fi
}

# 读取配置
config_get() {
    local key="$1"
    local default="${2:-}"
    local value
    value=$(jq -r "$key // empty" "$VPS_CONFIG" 2>/dev/null)
    echo "${value:-$default}"
}

# 写入配置
config_set() {
    local expr="$1"
    local tmp="${VPS_CONFIG}.tmp"
    if jq "$expr" "$VPS_CONFIG" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$VPS_CONFIG"
        return 0
    else
        rm -f "$tmp"
        return 1
    fi
}

# ============================================================================
# Telegram 通知
# ============================================================================
telegram_send() {
    local message="$1"
    local bot_token chat_id
    
    bot_token=$(config_get '.telegram.bot_token')
    chat_id=$(config_get '.telegram.chat_id')
    
    [[ -z "$bot_token" || -z "$chat_id" ]] && return 1
    
    curl -s --max-time 10 \
        "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -d "chat_id=${chat_id}" \
        -d "text=${message}" \
        -d "parse_mode=HTML" &>/dev/null
}

telegram_test() {
    local bot_token="$1"
    local chat_id="$2"
    local result
    
    result=$(curl -s --max-time 10 \
        "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -d "chat_id=${chat_id}" \
        -d "text=🔔 VPS Manager 测试消息 - $(date '+%Y-%m-%d %H:%M:%S')" 2>&1)
    
    echo "$result" | grep -q '"ok":true'
}

telegram_setup() {
    echo
    _cyan "=== Telegram 通知设置 ==="
    echo
    
    local enabled=$(config_get '.telegram.enabled' 'false')
    local token=$(config_get '.telegram.bot_token')
    local chat=$(config_get '.telegram.chat_id')
    local server=$(config_get '.telegram.server_name' "$(hostname)")
    
    echo "当前状态: $([ "$enabled" = "true" ] && _green "已启用" || _yellow "未启用")"
    [[ -n "$token" ]] && echo "Bot Token: ${token:0:10}..."
    [[ -n "$chat" ]] && echo "Chat ID: $chat"
    echo "服务器名: $server"
    echo
    echo "1. 配置 Bot Token 和 Chat ID"
    echo "2. 发送测试消息"
    echo "3. $([ "$enabled" = "true" ] && echo "禁用" || echo "启用")通知"
    echo "4. 设置服务器名称"
    echo "0. 返回"
    echo
    read -rp "选择: " choice
    
    case $choice in
        1)
            read -rp "Bot Token: " new_token
            read -rp "Chat ID: " new_chat
            if [[ -n "$new_token" && -n "$new_chat" ]]; then
                config_set ".telegram.bot_token = \"$new_token\" | .telegram.chat_id = \"$new_chat\""
                _green "✓ 已保存"
            fi
            ;;
        2)
            if [[ -n "$token" && -n "$chat" ]]; then
                telegram_test "$token" "$chat" && _green "✓ 发送成功" || _red "✗ 发送失败"
            else
                _yellow "请先配置 Bot Token 和 Chat ID"
            fi
            ;;
        3)
            if [[ "$enabled" = "true" ]]; then
                config_set ".telegram.enabled = false"
                _yellow "已禁用"
            else
                config_set ".telegram.enabled = true"
                _green "已启用"
            fi
            ;;
        4)
            read -rp "服务器名称 [$server]: " new_name
            [[ -n "$new_name" ]] && config_set ".telegram.server_name = \"$new_name\"" && _green "✓ 已设置"
            ;;
    esac
}

# ============================================================================
# 防火墙管理
# ============================================================================
firewall_allow() {
    local port="$1"
    local proto="${2:-tcp}"
    
    [[ $(config_get '.settings.auto_firewall' 'true') != "true" ]] && return 0
    
    # UFW
    if command -v ufw &>/dev/null; then
        if ufw status 2>/dev/null | grep -q "^Status: active"; then
            ufw allow "$port/$proto" &>/dev/null
            log_info "UFW: 已放行 $port/$proto"
        fi
    fi
    
    # Firewalld
    if command -v firewall-cmd &>/dev/null; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            firewall-cmd --permanent --add-port="$port/$proto" &>/dev/null
            firewall-cmd --reload &>/dev/null
            log_info "Firewalld: 已放行 $port/$proto"
        fi
    fi
    
    # iptables (fallback)
    if command -v iptables &>/dev/null && [[ ! -x $(command -v ufw) ]] && [[ ! -x $(command -v firewall-cmd) ]]; then
        iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT &>/dev/null || \
        iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT &>/dev/null
    fi
}

firewall_remove() {
    local port="$1"
    local proto="${2:-tcp}"
    
    if command -v ufw &>/dev/null; then
        ufw delete allow "$port/$proto" &>/dev/null 2>&1
    fi
    
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --remove-port="$port/$proto" &>/dev/null 2>&1
        firewall-cmd --reload &>/dev/null 2>&1
    fi
    
    if command -v iptables &>/dev/null; then
        iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT &>/dev/null 2>&1
    fi
}

# ============================================================================
# 网络优化
# ============================================================================
check_bbr() {
    sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null
}

check_tfo() {
    local tfo=$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null)
    [[ "$tfo" == "3" ]] && echo "enabled" || echo "disabled"
}

enable_bbr() {
    local kernel_major kernel_minor
    kernel_major=$(uname -r | cut -d. -f1)
    kernel_minor=$(uname -r | cut -d. -f2)
    
    if [[ $kernel_major -lt 4 ]] || [[ $kernel_major -eq 4 && $kernel_minor -lt 9 ]]; then
        log_error "BBR 需要 Linux 4.9+ 内核，当前: $(uname -r)"
        return 1
    fi
    
    if [[ $(check_bbr) == "bbr" ]]; then
        log_info "BBR 已启用"
        return 0
    fi
    
    # 检查是否已有配置
    if ! grep -q "net.core.default_qdisc" /etc/sysctl.conf 2>/dev/null; then
        cat >> /etc/sysctl.conf <<EOF

# BBR - Added by VPS Manager
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    else
        sed -i 's/^net.core.default_qdisc=.*/net.core.default_qdisc=fq/' /etc/sysctl.conf
        sed -i 's/^net.ipv4.tcp_congestion_control=.*/net.ipv4.tcp_congestion_control=bbr/' /etc/sysctl.conf
    fi
    
    sysctl -p &>/dev/null
    
    [[ $(check_bbr) == "bbr" ]] && _green "BBR 启用成功" || _red "BBR 启用失败"
}

enable_tfo() {
    if [[ $(check_tfo) == "enabled" ]]; then
        log_info "TFO 已启用"
        return 0
    fi
    
    if ! grep -q "net.ipv4.tcp_fastopen" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.tcp_fastopen=3" >> /etc/sysctl.conf
    else
        sed -i 's/^net.ipv4.tcp_fastopen=.*/net.ipv4.tcp_fastopen=3/' /etc/sysctl.conf
    fi
    
    sysctl -p &>/dev/null
    
    [[ $(check_tfo) == "enabled" ]] && _green "TFO 启用成功" || _red "TFO 启用失败"
}

optimize_network() {
    [[ $(config_get '.settings.auto_network_optimize' 'true') != "true" ]] && return 0
    
    log_info "优化网络参数..."
    
    # 优化参数
    local sysctl_params="
# Network Optimization - Added by VPS Manager
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.netdev_max_backlog=250000
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
"
    
    # 检查并添加
    if ! grep -q "Network Optimization - Added by VPS Manager" /etc/sysctl.conf 2>/dev/null; then
        echo "$sysctl_params" >> /etc/sysctl.conf
    fi
    
    sysctl -p &>/dev/null
    
    # 启用 BBR 和 TFO
    enable_bbr
    enable_tfo
}

# ============================================================================
# 工具函数
# ============================================================================
get_ip() {
    local ipv4 ipv6
    ipv4=$(curl -s4m5 ip.sb 2>/dev/null || curl -s4m5 api.ipify.org 2>/dev/null || curl -s4m5 ifconfig.me 2>/dev/null)
    ipv6=$(curl -s6m5 ip.sb 2>/dev/null)
    SERVER_IP="${ipv4:-$ipv6}"
    SERVER_IP="${SERVER_IP:-<未知>}"
    export SERVER_IP
}

is_port_used() {
    if command -v ss &>/dev/null; then
        ss -tuln 2>/dev/null | grep -qE "(:|])$1\b"
    elif command -v netstat &>/dev/null; then
        netstat -tuln 2>/dev/null | grep -qE ":$1\b"
    else
        return 1
    fi
}

rand_port() {
    local port min=${1:-10000} max=${2:-60000}
    local attempts=0
    while :; do
        port=$((RANDOM % (max - min) + min))
        is_port_used "$port" || break
        ((attempts++))
        [[ $attempts -gt 100 ]] && { echo "$((RANDOM % (max - min) + min))"; return; }
    done
    echo "$port"
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [[ $1 -ge 1 && $1 -le 65535 ]]
}

confirm() {
    local prompt="${1:-确认操作?}"
    local default="${2:-n}"
    local yn
    
    if [[ "$default" == "y" ]]; then
        read -rp "$prompt [Y/n]: " yn
        yn=${yn:-y}
    else
        read -rp "$prompt [y/N]: " yn
        yn=${yn:-n}
    fi
    
    [[ $yn =~ ^[Yy]$ ]]
}

# 等待按键继续
pause() {
    read -rp "按 Enter 继续..." _
}

# 下载文件 (带重试)
download_file() {
    local url="$1"
    local output="$2"
    local retries=${3:-3}
    
    for ((i=1; i<=retries; i++)); do
        if wget -q --show-progress -O "$output" "$url" 2>/dev/null || \
           curl -fSL# -o "$output" "$url" 2>/dev/null; then
            return 0
        fi
        log_warn "下载失败，重试 $i/$retries..."
        sleep 2
    done
    
    log_error "下载失败: $url"
    return 1
}

# ============================================================================
# 脚本自更新
# ============================================================================
check_self_update() {
    local remote_version
    remote_version=$(curl -sfm10 "https://raw.githubusercontent.com/$VPS_REPO/$VPS_BRANCH/vps-manager/version.txt" 2>/dev/null)
    
    [[ -z "$remote_version" ]] && return 1
    
    compare_versions "$VPS_VERSION" "$remote_version"
    local result=$?
    
    if [[ $result -eq 2 ]]; then
        echo "$remote_version"
        return 0
    fi
    
    return 1
}

self_update() {
    log_info "检查更新..."
    
    local new_version
    new_version=$(check_self_update)
    
    if [[ -n "$new_version" ]]; then
        _yellow "发现新版本: $VPS_VERSION -> $new_version"
        
        if confirm "是否更新?"; then
            log_info "下载更新..."
            local tmp_script="/tmp/vps-install-$$.sh"
            
            if download_file "https://raw.githubusercontent.com/$VPS_REPO/$VPS_BRANCH/vps-manager/install.sh" "$tmp_script"; then
                chmod +x "$tmp_script"
                exec bash "$tmp_script" --upgrade
            else
                _red "下载更新失败"
            fi
        fi
    else
        _green "当前已是最新版本 ($VPS_VERSION)"
    fi
}

# ============================================================================
# 初始化
# ============================================================================
common_init() {
    detect_os
    detect_arch
    detect_init_system
    init_config
    get_ip
}

# 模块加载完成
log_debug "公共模块已加载"
