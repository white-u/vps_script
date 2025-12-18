#!/bin/bash

# sing-box 单文件管理脚本 (UI美化版 v2.3)
# https://github.com/white-u/vps_script
# Usage: bash <(curl -sL url) [args]

is_sh_ver=v2.3

# ==================== 颜色函数 ====================
_red() { echo -e "\e[31m$@\e[0m"; }
_green() { echo -e "\e[32m$@\e[0m"; }
_yellow() { echo -e "\e[33m$@\e[0m"; }
_blue_bg() { echo -e "\033[44;37m$@\033[0m"; }
_gray() { echo -e "\033[90m$@\033[0m"; }

err() {
    echo -e "\n\e[41m 错误 \e[0m $@\n"
    exit 1
}

# ==================== 模块加载 ====================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="https://raw.githubusercontent.com/white-u/vps_script/main"

# ==================== 环境检测 ====================
[[ $EUID != 0 ]] && err "请使用 root 用户运行此脚本"

cmd=$(type -P apt-get || type -P yum)
[[ ! $cmd ]] && err "此脚本仅支持 Ubuntu/Debian/CentOS 系统"

case $(uname -m) in
    amd64 | x86_64) is_arch=amd64 ;;
    *aarch64* | *armv8*) is_arch=arm64 ;;
    *) err "此脚本仅支持 64 位系统" ;;
esac

# ==================== 全局变量 ====================
is_core=sing-box
is_core_dir=/etc/$is_core
is_core_bin=$is_core_dir/bin/$is_core
is_core_repo=SagerNet/$is_core
is_conf_dir=$is_core_dir/conf
is_config_json=$is_core_dir/config.json
is_log_dir=/var/log/$is_core
is_sh_bin=/usr/local/bin/$is_core
is_sh_url="https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh"
is_version_cache="/var/tmp/singbox_version_cache"

# ==================== 常量定义 ====================
readonly PORT_MIN=1
readonly PORT_MAX=65535
readonly RANDOM_PORT_MIN=10000
readonly RANDOM_PORT_MAX=40000
readonly CURL_MAX_RETRIES=3
readonly CURL_RETRY_DELAY=2
readonly WGET_MAX_RETRIES=3
readonly WGET_RETRY_DELAY=2
readonly VERSION_CACHE_TIME=3600
readonly NETWORK_TIMEOUT=5
readonly UPDATE_TIMEOUT=120

# ==================== 网络请求重试 ====================
curl_retry() {
    local attempt=1
    while [ $attempt -le "$CURL_MAX_RETRIES" ]; do
        if curl "$@"; then return 0; fi
        if [ $attempt -lt "$CURL_MAX_RETRIES" ]; then
            _yellow "curl 请求失败，${CURL_RETRY_DELAY}秒后重试 ($attempt/$CURL_MAX_RETRIES)..."
            sleep "$CURL_RETRY_DELAY"
        fi
        attempt=$((attempt + 1))
    done
    return 1
}

wget_retry() {
    local attempt=1
    while [ $attempt -le "$WGET_MAX_RETRIES" ]; do
        if wget "$@"; then return 0; fi
        if [ $attempt -lt "$WGET_MAX_RETRIES" ]; then
            _yellow "wget 请求失败，${WGET_RETRY_DELAY}秒后重试 ($attempt/$WGET_MAX_RETRIES)..."
            sleep "$WGET_RETRY_DELAY"
        fi
        attempt=$((attempt + 1))
    done
    return 1
}

# ==================== IP 地址验证 ====================
is_valid_ip() {
    local ip="$1"
    local ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    local ipv6_regex='^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'

    if [[ "$ip" =~ $ipv4_regex ]]; then
        local IFS='.'
        local -a segments=($ip)
        for seg in "${segments[@]}"; do
            if [ "$seg" -gt 255 ] 2>/dev/null; then return 1; fi
        done
        return 0
    elif [[ "$ip" =~ $ipv6_regex ]]; then
        return 0
    else
        return 1
    fi
}

# ==================== 状态检测 ====================
refresh_status() {
    [[ -f $is_core_bin ]] && is_core_ver=$($is_core_bin version 2>/dev/null | head -n1 | cut -d' ' -f3)
    if systemctl is-active --quiet $is_core 2>/dev/null; then
        is_core_status=$(_green "运行中")
        is_core_stop=0
    else
        is_core_status=$(_red "未运行")
        is_core_stop=1
    fi
}

get_ip() {
    local ipv4 ipv6
    ipv4=$(curl_retry -s4m${NETWORK_TIMEOUT} ip.sb 2>/dev/null || curl_retry -s4m${NETWORK_TIMEOUT} api.ipify.org 2>/dev/null)
    if [ -n "$ipv4" ] && is_valid_ip "$ipv4"; then
        is_addr="$ipv4"
        return 0
    fi

    ipv6=$(curl_retry -s6m${NETWORK_TIMEOUT} ip.sb 2>/dev/null)
    if [ -n "$ipv6" ] && is_valid_ip "$ipv6"; then
        is_addr="$ipv6"
        return 0
    fi

    # 静默处理，不再报错，用于生成链接
    is_addr="<未知IP>"
}

# ==================== 安装功能 ====================
install_singbox() {
    echo
    echo ">>> 安装 $is_core..."
    
    # 安装依赖
    echo ">>> 安装依赖..."
    $cmd update -y &>/dev/null
    $cmd install -y wget tar jq openssl &>/dev/null || err "依赖安装失败"
    
    # 获取版本
    echo ">>> 下载 $is_core 核心..."
    local version
    version=$(wget_retry -qO- "https://api.github.com/repos/$is_core_repo/releases/latest" | grep tag_name | grep -oE "v[0-9.]+")
    [[ -z $version ]] && err "获取最新版本失败"
    echo "    版本: $version"

    # 下载核心
    local tmp_dir; tmp_dir=$(mktemp -d) || err "创建临时目录失败"
    local core_url="https://github.com/$is_core_repo/releases/download/$version/$is_core-${version#v}-linux-$is_arch.tar.gz"
    wget_retry --no-check-certificate -q -O "$tmp_dir/core.tar.gz" "$core_url" || err "下载失败"
    
    # 检查文件完整性
    if ! gzip -t "$tmp_dir/core.tar.gz" &>/dev/null; then
        rm -rf "$tmp_dir"
        err "下载的文件损坏，请检查网络连接"
    fi
    
    # 创建目录
    mkdir -p $is_core_dir/bin $is_conf_dir $is_log_dir
    
    # 解压核心
    tar -xzf "$tmp_dir/core.tar.gz" -C $is_core_dir/bin --strip-components=1
    rm -rf "$tmp_dir"
    
    # 安装脚本
    echo ">>> 安装管理脚本..."
    local script_path=$(realpath "$0" 2>/dev/null || echo "$0")
    
    # 如果是从 stdin 运行 (curl | bash)，则下载脚本
    if [[ ! -f "$script_path" || "$script_path" =~ bash$ || "$script_path" == "/dev/stdin" ]]; then
        wget_retry --no-check-certificate -q -O "$is_sh_bin" "$is_sh_url" || err "脚本下载失败"
    else
        cp "$script_path" "$is_sh_bin"
    fi
    
    # 创建链接
    ln -sf $is_sh_bin /usr/local/bin/sb
    chmod +x $is_core_bin $is_sh_bin /usr/local/bin/sb
    
    # 创建 systemd 服务
    echo ">>> 创建服务..."
    cat > /etc/systemd/system/$is_core.service <<EOF
[Unit]
Description=$is_core Service
After=network.target

[Service]
User=root
ExecStart=$is_core_bin run -c $is_config_json -C $is_conf_dir
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    singbox_service_control daemon-reload
    singbox_service_control enable false

    # 创建默认配置
    echo ">>> 创建配置..."
    cat > $is_config_json <<EOF
{
    "log": {
        "level": "info",
        "output": "$is_log_dir/sing-box.log",
        "timestamp": true
    },
    "dns": {},
    "outbounds": [
        {"type": "direct", "tag": "direct"}
    ]
}
EOF
    
    echo
    _green "安装完成!"
    echo "版本: $version"
    echo "命令: sb 或 $is_core"
    echo
    echo "快速开始: sb add"
    echo
}

# ==================== 防火墙管理 ====================
firewall_allow_port() {
    local port="$1"
    # UFW
    if command -v ufw >/dev/null 2>&1; then
        if ! ufw status 2>/dev/null | grep -q inactive; then
            ufw allow "$port"/tcp >/dev/null 2>&1 || true
            ufw allow "$port"/udp >/dev/null 2>&1 || true
            _green "防火墙: ufw 已放行端口 $port"
        fi
    fi
    # Firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        _green "防火墙: firewalld 已放行端口 $port"
    fi
}

firewall_remove_port() {
    local port="$1"
    # UFW
    if command -v ufw >/dev/null 2>&1; then
        if ! ufw status 2>/dev/null | grep -q inactive; then
            ufw delete allow "$port"/tcp >/dev/null 2>&1 || true
            ufw delete allow "$port"/udp >/dev/null 2>&1 || true
            _green "防火墙: ufw 已移除端口 $port"
        fi
    fi
    # Firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --permanent --remove-port="${port}/udp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        _green "防火墙: firewalld 已移除端口 $port"
    fi
}

# 向后兼容别名
ufw_allow() { firewall_allow_port "$1"; }
ufw_remove() { firewall_remove_port "$1"; }
firewalld_allow() { firewall_allow_port "$1"; }
firewalld_remove() { firewall_remove_port "$1"; }

# ==================== 配置读取函数 ====================
read_inbound_type() { jq -r '.inbounds[0].type' "$1" 2>/dev/null; }
read_listen_port() { jq -r '.inbounds[0].listen_port' "$1" 2>/dev/null; }
read_uuid() { jq -r '.inbounds[0].users[0].uuid' "$1" 2>/dev/null; }
read_password() { jq -r '.inbounds[0].password' "$1" 2>/dev/null; }
read_method() { jq -r '.inbounds[0].method' "$1" 2>/dev/null; }
read_server_name() { jq -r '.inbounds[0].tls.server_name // empty' "$1" 2>/dev/null; }

# ==================== 配置管理 ====================
get_conf_list() {
    conf_list=()
    while IFS= read -r -d '' file; do
        conf_list+=("$(basename "$file")")
    done < <(find "$is_conf_dir" -maxdepth 1 -name "*.json" -print0 2>/dev/null)
}

select_conf() {
    get_conf_list
    [[ ${#conf_list[@]} -eq 0 ]] && { _yellow "没有找到配置文件"; return 1; }
    
    if [[ ${#conf_list[@]} -eq 1 ]]; then
        is_conf_file=${conf_list[0]}
        echo "自动选择: $is_conf_file"
        return 0
    fi
    
    echo
    echo "请选择配置:"
    echo
    for i in "${!conf_list[@]}"; do
        local f=${conf_list[$i]}
        local conf_path="$is_conf_dir/$f"
        local proto=$(read_inbound_type "$conf_path")
        local port=$(read_listen_port "$conf_path")
        printf "  %2d. %-30s [%s:%s]\n" "$((i+1))" "$f" "$proto" "$port"
    done
    echo
    echo "   0. 返回"
    echo
    read -rp "请输入序号: " pick
    [[ -z $pick || $pick == "0" ]] && return 1
    [[ ! $pick =~ ^[0-9]+$ ]] && { _yellow "请输入数字"; return 1; }
    [[ $pick -lt 1 || $pick -gt ${#conf_list[@]} ]] && { _yellow "序号超出范围"; return 1; }
    is_conf_file=${conf_list[$((pick-1))]}
    return 0
}

# 协议列表
protocols=("VLESS-Reality" "Shadowsocks")

# 检查端口是否被占用
is_port_used() {
    if command -v ss >/dev/null 2>&1; then
        ss -tuln | grep -qE "(:|])$1\b"
    elif command -v lsof >/dev/null 2>&1; then
        lsof -i :"$1" >/dev/null 2>&1
    else
        return 1
    fi
}

rand_port() {
    local port
    while :; do
        port=$((RANDOM % (RANDOM_PORT_MAX - RANDOM_PORT_MIN + 1) + RANDOM_PORT_MIN))
        is_port_used $port || break
    done
    echo $port
}

rand_uuid() { cat /proc/sys/kernel/random/uuid; }
gen_reality_keys() {
    local keys=$($is_core_bin generate reality-keypair 2>/dev/null)
    is_private_key=$(echo "$keys" | grep PrivateKey | awk '{print $2}')
    is_public_key=$(echo "$keys" | grep PublicKey | awk '{print $2}')
}
gen_short_id() { openssl rand -hex 8; }

# ==================== 自动流量监控 ====================
auto_add_traffic_monitor() {
    local port="$1"
    local remark="${2:-sing-box}"
    local ptm_config="/etc/port-traffic-monitor/config.json"
    
    [[ ! -f "$ptm_config" ]] && return 0
    ! command -v jq >/dev/null 2>&1 && { _yellow "缺少 jq，跳过监控添加"; return 1; }
    jq -e ".ports.\"$port\"" "$ptm_config" >/dev/null 2>&1 && { _green "端口 $port 已在监控中"; return 0; }

    _green "自动添加端口 $port 到流量监控..."
    local nft_table=$(jq -r '.nftables.table_name // "port_monitor"' "$ptm_config")
    local nft_family=$(jq -r '.nftables.family // "inet"' "$ptm_config")
    local timestamp=$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
    local config_json
    config_json=$(cat <<EOF
{
  "billing": "single",
  "quota": { "limit": "unlimited", "reset_day": null },
  "bandwidth": { "rate": "unlimited" },
  "remark": "$remark",
  "created": "$timestamp"
}
EOF
)
    local tmp_config="${ptm_config}.tmp.$$"
    if jq ".ports.\"$port\" = $config_json" "$ptm_config" > "$tmp_config" 2>/dev/null; then
        mv "$tmp_config" "$ptm_config" || rm -f "$tmp_config"
    else
        rm -f "$tmp_config"
        return 1
    fi

    local port_safe=$(echo "$port" | tr '-' '_')
    nft list counter "$nft_family" "$nft_table" "port_${port_safe}_in" >/dev/null 2>&1 || nft add counter "$nft_family" "$nft_table" "port_${port_safe}_in" 2>/dev/null || true
    nft list counter "$nft_family" "$nft_table" "port_${port_safe}_out" >/dev/null 2>&1 || nft add counter "$nft_family" "$nft_table" "port_${port_safe}_out" 2>/dev/null || true
    for proto in tcp udp; do
        nft add rule "$nft_family" "$nft_table" input "$proto" dport "$port" counter name "port_${port_safe}_in" 2>/dev/null || true
        nft add rule "$nft_family" "$nft_table" output "$proto" sport "$port" counter name "port_${port_safe}_out" 2>/dev/null || true
    done
    _green "✓ 已自动添加端口 $port 到流量监控"
}

auto_remove_traffic_monitor() {
    local port="$1"
    local ptm_config="/etc/port-traffic-monitor/config.json"
    [[ ! -f "$ptm_config" ]] && return 0
    ! command -v jq >/dev/null 2>&1 && return 0
    ! jq -e ".ports.\"$port\"" "$ptm_config" >/dev/null 2>&1 && return 0

    _green "自动移除端口 $port 的流量监控..."
    local tmp_config="${ptm_config}.tmp.$$"
    if jq "del(.ports.\"$port\")" "$ptm_config" > "$tmp_config" 2>/dev/null; then
        mv "$tmp_config" "$ptm_config" || rm -f "$tmp_config"
    else
        rm -f "$tmp_config"
    fi
    _green "✓ 已移除端口 $port 的流量监控"
}

input_port() {
    local default_port=$(rand_port)
    read -rp "端口 [$default_port]: " is_port
    is_port=${is_port:-$default_port}
    [[ ! $is_port =~ ^[0-9]+$ ]] && { _yellow "端口必须是数字"; input_port; return; }
    [[ $is_port -lt $PORT_MIN || $is_port -gt $PORT_MAX ]] && { _yellow "端口范围: $PORT_MIN-$PORT_MAX"; input_port; return; }
    is_port_used $is_port && { _yellow "端口 $is_port 已被占用"; input_port; return; }
}

input_uuid() {
    local default_uuid=$(rand_uuid)
    read -rp "UUID [$default_uuid]: " is_uuid
    is_uuid=${is_uuid:-$default_uuid}
}

input_sni() {
    local default_sni="www.time.is"
    read -rp "SNI [$default_sni]: " is_sni
    is_sni=${is_sni:-$default_sni}
}

input_remark() {
    local default_remark=$(hostname)
    read -rp "备注 [$default_remark]: " is_remark
    is_remark=${is_remark:-$default_remark}
}

# 添加配置
add() {
    if [[ $1 ]]; then
        case ${1,,} in
            r|reality|vless|vless-reality) is_protocol="VLESS-Reality" ;;
            ss|shadowsocks) is_protocol="Shadowsocks" ;;
            *) _yellow "未找到匹配的协议: $1"; return 1 ;;
        esac
    else
        echo
        echo "请选择协议:"
        echo
        for i in "${!protocols[@]}"; do
            printf "  %2d. %s\n" $((i+1)) "${protocols[$i]}"
        done
        echo
        echo "   0. 返回"
        echo
        read -rp "请输入序号: " pick
        [[ -z $pick || $pick == "0" ]] && return 0
        [[ ! $pick =~ ^[0-9]+$ ]] && { _yellow "请输入数字"; return 1; }
        [[ $pick -lt 1 || $pick -gt ${#protocols[@]} ]] && { _yellow "序号超出范围"; return 1; }
        is_protocol=${protocols[$((pick-1))]}
    fi
    
    echo
    _green ">>> 配置 $is_protocol"
    echo
    
    input_port
    
    case $is_protocol in
        VLESS-Reality) add_vless_reality ;;
        Shadowsocks) add_shadowsocks ;;
    esac
    
    if save_conf; then
        ufw_allow "$is_port"
        firewalld_allow "$is_port"
        singbox_service_control restart false
        is_conf_file=$is_conf_name.json
        info_show
        echo
        auto_add_traffic_monitor "$is_port" "sing-box ($is_protocol)"
    fi
}

add_vless_reality() {
    input_uuid
    input_sni
    input_remark
    gen_reality_keys
    is_short_id=$(gen_short_id)
    is_conf_name="vless-reality-${is_port}"
    
    is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "vless",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "users": [{
            "uuid": "$is_uuid",
            "flow": "xtls-rprx-vision"
        }],
        "tls": {
            "enabled": true,
            "server_name": "$is_sni",
            "reality": {
                "enabled": true,
                "handshake": {
                    "server": "$is_sni",
                    "server_port": 443
                },
                "private_key": "$is_private_key",
                "short_id": ["$is_short_id"]
            }
        }
    }],
    "outbounds": [
        {"type": "direct"},
        {"type": "direct", "tag": "public_key_$is_public_key"}
    ]
}
EOF
)
}

add_shadowsocks() {
    echo
    echo "加密方式:"
    echo "  1. 2022-blake3-aes-128-gcm (推荐)"
    echo "  2. 2022-blake3-aes-256-gcm"
    echo "  3. 2022-blake3-chacha20-poly1305"
    echo
    read -rp "选择 [1]: " method_pick
    case ${method_pick:-1} in
        1) is_method="2022-blake3-aes-128-gcm"; is_ss_pass=$(openssl rand -base64 16) ;;
        2) is_method="2022-blake3-aes-256-gcm"; is_ss_pass=$(openssl rand -base64 32) ;;
        3) is_method="2022-blake3-chacha20-poly1305"; is_ss_pass=$(openssl rand -base64 32) ;;
        *) is_method="2022-blake3-aes-128-gcm"; is_ss_pass=$(openssl rand -base64 16) ;;
    esac
    
    input_remark
    is_conf_name="shadowsocks-${is_port}"
    
    is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "shadowsocks",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "method": "$is_method",
        "password": "$is_ss_pass"
    }]
}
EOF
)
}

save_conf() {
    local tmp_file="$is_conf_dir/$is_conf_name.json"
    echo "$is_conf" | jq . > "$tmp_file" 2>/dev/null
    if [[ $? -ne 0 ]]; then
        _red "配置保存失败，JSON 格式错误"
        return 1
    fi
    
    local check_result
    check_result=$($is_core_bin check -c "$is_config_json" -C "$is_conf_dir" 2>&1)
    if [[ $? -ne 0 ]]; then
        echo
        _red "配置验证失败:"
        echo "$check_result"
        rm -f "$tmp_file"
        return 1
    fi
    
    _green "配置已保存: $is_conf_name.json"
    return 0
}

# 列出配置
list() {
    get_conf_list
    if [[ ${#conf_list[@]} -eq 0 ]]; then
        echo
        _yellow "暂无配置"
        echo
        return
    fi
    
    echo
    printf "%-3s %-30s %-12s %-6s\n" "#" "名称" "协议" "端口"
    echo "------------------------------------------------------"
    
    for i in "${!conf_list[@]}"; do
        local f=${conf_list[$i]}
        local conf_path="$is_conf_dir/$f"
        local proto=$(read_inbound_type "$conf_path")
        local port=$(read_listen_port "$conf_path")
        printf "%-3s %-30s %-12s %-6s\n" "$((i+1))" "$f" "$proto" "$port"
    done
    echo
}

# 修改配置
change() {
    if [[ $1 ]]; then
        get_conf_list
        for f in "${conf_list[@]}"; do
            [[ $f =~ $1 ]] && is_conf_file=$f && break
        done
        [[ -z $is_conf_file ]] && { _yellow "未找到匹配的配置: $1"; return 1; }
    else
        select_conf || return 1
    fi

    local conf_path="$is_conf_dir/$is_conf_file"
    local proto=$(read_inbound_type "$conf_path")

    echo
    echo "修改: $is_conf_file ($proto)"
    echo
    echo "可修改项:"
    echo "  1. 端口"
    echo "  2. 主要凭证 (UUID/密码)"

    local has_sni=false
    if [[ $proto == "vless" ]]; then
        local server_name=$(read_server_name "$conf_path")
        if [[ -n $server_name ]]; then
            echo "  3. SNI (Server Name)"
            has_sni=true
        fi
    fi

    echo
    echo "  0. 返回"
    echo
    read -rp "请选择: " change_pick

    case $change_pick in
        1) change_port "$conf_path" ;;
        2) change_cred "$conf_path" "$proto" ;;
        3)
            if [[ $has_sni == true ]]; then
                change_sni "$conf_path" "$proto"
            else
                _yellow "无效选择"
            fi
            ;;
        0|"") return 0 ;;
        *) _yellow "无效选择" ;;
    esac
}

change_port() {
    local conf_path=$1
    local old_port=$(read_listen_port "$conf_path")

    echo "当前端口: $old_port"
    read -rp "新端口: " new_port
    
    [[ -z $new_port ]] && { echo "已取消"; return; }
    [[ ! $new_port =~ ^[0-9]+$ ]] && { _yellow "端口必须是数字"; return; }
    [[ $new_port -lt $PORT_MIN || $new_port -gt $PORT_MAX ]] && { _yellow "端口范围: $PORT_MIN-$PORT_MAX"; return; }
    is_port_used $new_port && { _yellow "端口 $new_port 已被占用"; return; }
    
    jq ".inbounds[0].listen_port = $new_port" "$conf_path" > "${conf_path}.tmp"
    if $is_core_bin check -c "$is_config_json" -C "$is_conf_dir" &>/dev/null; then
        mv "${conf_path}.tmp" "$conf_path"
        _green "端口已修改: $old_port -> $new_port"

        if [ -n "$old_port" ]; then
            ufw_remove "$old_port"
            firewalld_remove "$old_port"
        fi
        ufw_allow "$new_port"
        firewalld_allow "$new_port"

        if restart_check; then
            if [ -n "$old_port" ]; then
                auto_remove_traffic_monitor "$old_port"
            fi
            auto_add_traffic_monitor "$new_port" "sing-box"
        else
            _red "端口修改后服务启动失败，请检查配置"
        fi
    else
        rm -f "${conf_path}.tmp"
        _red "配置验证失败"
    fi
}

change_cred() {
    local conf_path=$1
    local proto=$2

    case $proto in
        vless)
            local old_uuid=$(read_uuid "$conf_path")
            echo "当前 UUID: $old_uuid"
            local default_uuid=$(rand_uuid)
            read -rp "新 UUID [$default_uuid]: " new_uuid
            new_uuid=${new_uuid:-$default_uuid}
            jq ".inbounds[0].users[0].uuid = \"$new_uuid\"" "$conf_path" > "${conf_path}.tmp" && mv "${conf_path}.tmp" "$conf_path"
            _green "UUID 已修改"
            restart_check
            ;;
        shadowsocks)
            local old_pass=$(read_password "$conf_path")
            local method=$(read_method "$conf_path")
            echo "当前密码: $old_pass"
            echo "加密方式: $method"
            local key_len=16
            [[ $method =~ "256" || $method =~ "chacha20" ]] && key_len=32
            local default_pass=$(openssl rand -base64 $key_len)
            read -rp "新密码 [$default_pass]: " new_pass
            new_pass=${new_pass:-$default_pass}
            jq ".inbounds[0].password = \"$new_pass\"" "$conf_path" > "${conf_path}.tmp" && mv "${conf_path}.tmp" "$conf_path"
            _green "密码已修改"
            restart_check
            ;;
        *) _yellow "此协议暂不支持修改凭证" ;;
    esac
}

change_sni() {
    local conf_path=$1
    local proto=$2
    [[ $proto != "vless" ]] && return 1

    local old_sni=$(read_server_name "$conf_path")
    echo "当前 SNI: $old_sni"
    read -rp "新 SNI: " new_sni
    [[ -z $new_sni ]] && { echo "已取消"; return; }

    jq ".inbounds[0].tls.server_name = \"$new_sni\"" "$conf_path" > "${conf_path}.tmp"
    if $is_core_bin check -c "$is_config_json" -C "$is_conf_dir" &>/dev/null; then
        mv "${conf_path}.tmp" "$conf_path"
        _green "SNI 已修改"
        restart_check
    else
        rm -f "${conf_path}.tmp"
        _red "配置验证失败"
    fi
}

# 删除配置
del() {
    if [[ $1 ]]; then
        get_conf_list
        for f in "${conf_list[@]}"; do
            [[ $f =~ $1 ]] && is_conf_file=$f && break
        done
        [[ -z $is_conf_file ]] && { _yellow "未找到匹配的配置: $1"; return 1; }
    else
        select_conf || return 1
    fi
    
    echo
    read -rp "确认删除 $is_conf_file? [y/N]: " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && { echo "已取消"; return 0; }

    local port=$(read_listen_port "$is_conf_dir/$is_conf_file")
    rm -f "$is_conf_dir/$is_conf_file"
    _green "已删除: $is_conf_file"

    if [ -n "$port" ]; then
        ufw_remove "$port"
        firewalld_remove "$port"
        auto_remove_traffic_monitor "$port"
    fi
    singbox_service_control restart false
}

# 查看配置
info() {
    if [[ $1 ]]; then
        get_conf_list
        for f in "${conf_list[@]}"; do
            [[ $f =~ $1 ]] && is_conf_file=$f && break
        done
        [[ -z $is_conf_file ]] && { _yellow "未找到匹配的配置: $1"; return 1; }
    else
        select_conf || return 1
    fi
    info_show
}

info_show() {
    local conf_path="$is_conf_dir/$is_conf_file"
    local proto=$(read_inbound_type "$conf_path")
    local port=$(read_listen_port "$conf_path")

    echo
    echo "============================================"
    echo "             配置信息"
    echo "============================================"
    echo
    echo "配置文件: $is_conf_file"
    echo "协议类型: $proto"
    echo "监听端口: $port"
    echo "服务地址: $is_addr"
    echo
    
    case $proto in
        vless)
            local uuid=$(read_uuid "$conf_path")
            local flow=$(jq -r '.inbounds[0].users[0].flow // empty' "$conf_path")
            local reality=$(jq -r '.inbounds[0].tls.reality.enabled // false' "$conf_path")
            echo "UUID: $uuid"
            [[ $flow ]] && echo "Flow: $flow"
            if [[ $reality == "true" ]]; then
                local sni=$(read_server_name "$conf_path")
                local pbk=$(jq -r '.outbounds[1].tag // empty' "$conf_path" | sed 's/public_key_//')
                local sid=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "$conf_path")
                echo "SNI: $sni"
                [[ $pbk ]] && echo "PublicKey: $pbk"
                echo "ShortID: $sid"
                echo "Fingerprint: chrome"
            fi
            ;;
        shadowsocks)
            local method=$(read_method "$conf_path")
            local password=$(read_password "$conf_path")
            echo "加密方式: $method"
            echo "密码: $password"
            ;;
    esac
    
    echo
    echo "============================================"
    echo "             分享链接"
    echo "============================================"
    echo
    gen_link
    echo
    echo "============================================"
}

gen_link() {
    local conf_path="$is_conf_dir/$is_conf_file"
    local proto=$(read_inbound_type "$conf_path")
    local port=$(read_listen_port "$conf_path")
    local remark="${is_remark:-$(hostname)}"

    case $proto in
        vless)
            local uuid=$(read_uuid "$conf_path")
            local flow=$(jq -r '.inbounds[0].users[0].flow // empty' "$conf_path")
            local reality=$(jq -r '.inbounds[0].tls.reality.enabled // false' "$conf_path")

            if [[ $reality == "true" ]]; then
                local sni=$(read_server_name "$conf_path")
                local pbk=$(jq -r '.outbounds[1].tag // empty' "$conf_path" | sed 's/public_key_//')
                local sid=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "$conf_path")
                local fp="chrome"
                
                if [[ -z $pbk ]]; then
                    _red "错误: 未找到 PublicKey，请重新创建配置"
                elif [[ $flow ]]; then
                    echo "vless://${uuid}@${is_addr}:${port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=tcp#${remark}"
                else
                    echo "vless://${uuid}@${is_addr}:${port}?encryption=none&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=tcp#${remark}"
                fi
            else
                echo "vless://${uuid}@${is_addr}:${port}?encryption=none&type=tcp#${remark}"
            fi
            ;;
        shadowsocks)
            local method=$(read_method "$conf_path")
            local password=$(read_password "$conf_path")
            local encoded=$(echo -n "${method}:${password}" | base64 -w 0)
            echo "ss://${encoded}@${is_addr}:${port}#${remark}"
            ;;
        *) echo "暂不支持生成 $proto 的分享链接" ;;
    esac
}

# ==================== 服务管理 ====================
singbox_service_control() {
    local action="$1"
    local show_log="${2:-true}"

    case "$action" in
        start|stop|restart|enable|disable|reload)
            if systemctl "$action" "$is_core" 2>&1; then
                [ "$show_log" = "true" ] && _green "$is_core 服务 $action 成功"
                return 0
            else
                [ "$show_log" = "true" ] && _red "$is_core 服务 $action 失败"
                return 1
            fi
            ;;
        status)
            systemctl status "$is_core" --no-pager
            return $?
            ;;
        is-active)
            systemctl is-active --quiet "$is_core" 2>/dev/null
            return $?
            ;;
        daemon-reload)
            systemctl daemon-reload
            return $?
            ;;
        *)
            _red "未知的服务操作: $action"
            return 1
            ;;
    esac
}

restart_check() {
    singbox_service_control restart false
    sleep 2
    if singbox_service_control is-active; then
        _green "$is_core 已成功启动"
        return 0
    else
        _red "$is_core 启动失败，请查看日志"
        echo ""
        echo "查看日志: $is_core log 50"
        echo "或使用: journalctl -u $is_core -n 50"
        return 1
    fi
}

manage() {
    case $1 in
        start|stop|restart)
            singbox_service_control $1
            refresh_status
            ;;
        status)
            refresh_status
            echo
            echo "$is_core 状态: $is_core_status"
            [[ $is_core_ver ]] && echo "版本: $is_core_ver"
            echo
            ;;
    esac
}

# ==================== 日志管理 ====================
show_log() {
    local lines=${1:-50}
    local log_file="$is_log_dir/sing-box.log"
    [[ ! -f $log_file ]] && { _yellow "日志文件不存在"; return; }
    echo
    echo "--- 最近 $lines 行 ---"
    tail -n $lines "$log_file"
    echo
}

follow_log() {
    local log_file="$is_log_dir/sing-box.log"
    [[ ! -f $log_file ]] && { _yellow "日志文件不存在"; return; }
    echo "实时日志 (Ctrl+C 退出):"
    echo
    tail -f "$log_file"
}

clear_log() {
    local log_file="$is_log_dir/sing-box.log"
    read -rp "确认清空日志? [y/N]: " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && { echo "已取消"; return; }
    > "$log_file"
    _green "日志已清空"
}

# ==================== 更新管理 ====================
get_latest_version() {
    local repo=$1
    local current_time=$(date +%s)
    if [ -f "$is_version_cache" ]; then
        local cache_timestamp=$(head -1 "$is_version_cache" 2>/dev/null || echo "0")
        local cached_version=$(sed -n '2p' "$is_version_cache" 2>/dev/null || echo "")
        if [ -n "$cache_timestamp" ] && [ -n "$cached_version" ]; then
            if [ $((current_time - cache_timestamp)) -lt $VERSION_CACHE_TIME ]; then
                echo "$cached_version"
                return 0
            fi
        fi
    fi
    local version
    version=$(curl_retry -sfm10 "https://api.github.com/repos/$repo/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
    if [ -n "$version" ]; then
        echo "$current_time" > "$is_version_cache"
        echo "$version" >> "$is_version_cache"
    fi
    echo "$version"
}

update_core() {
    echo
    echo "检查 sing-box 更新..."
    local latest=$(get_latest_version $is_core_repo)
    [[ -z $latest ]] && { _red "无法获取最新版本"; return 1; }
    local current=${is_core_ver:-未安装}
    echo "当前版本: $current"
    echo "最新版本: $latest"
    if [[ $current == $latest ]]; then
        _green "已是最新版本"
        return 0
    fi
    echo
    read -rp "是否更新? [Y/n]: " confirm
    [[ $confirm =~ ^[Nn]$ ]] && { echo "已取消"; return 0; }
    
    local url="https://github.com/$is_core_repo/releases/download/v${latest}/sing-box-${latest}-linux-${is_arch}.tar.gz"
    local tmp_file; tmp_file=$(mktemp) || { _red "创建临时文件失败"; return 1; }
    local tmp_dir; tmp_dir=$(mktemp -d) || { _red "创建临时目录失败"; rm -f "$tmp_file"; return 1; }

    echo "下载中..."
    if ! curl_retry -fLm${UPDATE_TIMEOUT} -o "$tmp_file" "$url"; then
        _red "下载失败"
        rm -rf "$tmp_file" "$tmp_dir"
        return 1
    fi
    if ! gzip -t "$tmp_file" &>/dev/null; then
         rm -rf "$tmp_file" "$tmp_dir"
         _red "下载文件损坏"
         return 1
    fi

    singbox_service_control stop false
    tar -xzf "$tmp_file" -C "$tmp_dir"
    cp "$tmp_dir/sing-box-${latest}-linux-${is_arch}/sing-box" "$is_core_bin"
    chmod +x "$is_core_bin"
    rm -rf "$tmp_file" "$tmp_dir"
    singbox_service_control start false
    _green "更新完成: $current -> $latest"
}

update_sh() {
    echo
    echo "更新脚本..."
    local tmp_file; tmp_file=$(mktemp) || { _red "创建临时文件失败"; return 1; }
    if ! curl_retry -sfLm30 -o "$tmp_file" "$is_sh_url"; then
        _red "下载失败"
        rm -f "$tmp_file"
        return 1
    fi
    cp "$tmp_file" "$is_sh_bin"
    chmod +x "$is_sh_bin"
    rm -f "$tmp_file"
    _green "脚本更新完成"
}

# ==================== 卸载 ====================
uninstall() {
    echo
    _yellow "警告: 即将卸载 sing-box"
    echo
    echo "将删除以下内容:"
    echo "  - $is_core_dir (配置、核心)"
    echo "  - $is_log_dir (日志)"
    echo "  - /etc/systemd/system/${is_core}.service"
    echo "  - /usr/local/bin/sb, /usr/local/bin/$is_core"
    echo
    read -rp "确认卸载? [y/N]: " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && { echo "已取消"; return 0; }
    
    echo
    echo "正在卸载..."
    singbox_service_control stop false
    singbox_service_control disable false
    rm -rf "$is_core_dir"
    rm -rf "$is_log_dir"
    rm -f /etc/systemd/system/${is_core}.service
    singbox_service_control daemon-reload
    rm -f /usr/local/bin/sb
    rm -f /usr/local/bin/$is_core
    rm -f /etc/resolv.conf.bak
    echo
    _green "sing-box 已完全卸载"
}

# ==================== 帮助 ====================
show_help() {
    echo
    echo "Usage: $is_core <command>"
    echo
    echo "配置管理:"
    echo "  add [r|ss]  添加配置 (r=Reality, ss=Shadowsocks)"
    echo "  change      修改配置"
    echo "  del         删除配置"
    echo "  list        列出配置"
    echo "  info        查看配置详情"
    echo
    echo "服务管理:"
    echo "  start       启动服务"
    echo "  stop        停止服务"
    echo "  restart     重启服务"
    echo "  status      查看状态"
    echo
    echo "日志管理:"
    echo "  log [n]     查看最近 n 行日志"
    echo "  log-f       实时查看日志"
    echo "  log-clear   清空日志"
    echo
    echo "更新管理:"
    echo "  update      更新核心"
    echo "  update sh   更新脚本"
    echo "  uninstall   卸载"
    echo
    echo "其他:"
    echo "  version     查看版本"
    echo "  help        显示帮助"
    echo
}

# ==================== 菜单 ====================
pause_return() {
    echo
    read -rp "按 Enter 返回主菜单..."
}

show_menu() {
    while true; do
        refresh_status
        get_conf_list
        local count=${#conf_list[@]}
        
        clear
        echo
        echo -e " $(_blue_bg "          Sing-box 管理面板 $is_sh_ver           ")"
        echo
        
        # 状态区
        echo -e " 🟢 运行状态"
        echo " ------------------------------------------------"
        echo -e "  服务状态: $is_core_status      核心版本: ${is_core_ver:-$(_red "未安装")}"
        echo -e "  配置数量: $(_green "$count 个")"
        echo

        # 配置管理区
        echo -e " ⚙️  配置管理"
        echo " ------------------------------------------------"
        echo -e "  1. 添加配置 $(_green "+")        2. 修改配置 📝"
        echo -e "     $(_gray "(Reality/Shadowsocks)")"
        echo -e "  3. 删除配置 🗑️         4. 查看详情 👁️"
        echo -e "  5. 配置列表 📋"
        echo

        # 服务控制区
        echo -e " 🚀 服务控制"
        echo " ------------------------------------------------"
        echo -e "  6. 启动服务 ▶️         7. 停止服务 ⏹️"
        echo -e "  8. 重启服务 🔄"
        echo

        # 维护更新区
        echo -e " 📦 维护与更新"
        echo " ------------------------------------------------"
        echo -e "  9. 实时日志 📜"
        echo -e " 10. 更新核心 🆙        11. 更新脚本 🔄"
        echo -e " 12. 卸载脚本 ❌"
        echo
        echo " ------------------------------------------------"
        echo "  0. 退出"
        echo
        read -rp " 请输入序号: " menu_pick
        
        case $menu_pick in
            1) add; pause_return ;;
            2) change; pause_return ;;
            3) del; pause_return ;;
            4) info; pause_return ;;
            5) list; pause_return ;;
            6) manage start; pause_return ;;
            7) manage stop; pause_return ;;
            8) manage restart; pause_return ;;
            9) show_log; pause_return ;;
            10) update_core; pause_return ;;
            11) update_sh; pause_return ;;
            12) uninstall; break ;;
            0) echo; echo "再见!"; echo; exit 0 ;;
            "") ;;
            *) _yellow "无效选择"; sleep 1 ;;
        esac
    done
}

# ==================== 主入口 ====================
main() {
    case $1 in
        # 配置管理
        a|add) add $2 ;;
        c|change) change $2 ;;
        d|del|rm) del $2 ;;
        l|list|ls) list ;;
        i|info) info $2 ;;
        # 服务管理
        start|stop|restart) manage $1 ;;
        s|status) manage status ;;
        # 日志管理
        log) show_log ${2:-50} ;;
        log-f|logf) follow_log ;;
        log-clear) clear_log ;;
        # 更新管理
        update)
            case $2 in
                sh|script) update_sh ;;
                *) update_core ;;
            esac
            ;;
        un|uninstall) uninstall ;;
        # 其他
        v|version)
            echo
            echo "$is_core 版本: $(_green ${is_core_ver:-未安装})"
            echo "脚本版本: $(_green $is_sh_ver)"
            echo
            ;;
        h|help) show_help ;;
        "") show_menu ;;
        *) _yellow "未知命令: $1"; echo "使用 '$is_core help' 查看帮助" ;;
    esac
}

# ==================== 启动 ====================
if [[ -f $is_sh_bin && -d $is_core_dir && -f $is_core_bin ]]; then
    # 已安装，正常运行
    refresh_status
    get_ip
    main "$@"
else
    # 未安装，执行安装
    get_ip
    install_singbox
fi