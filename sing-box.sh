#!/bin/bash
#
# Sing-box 管理脚本 (完美导出版 v2.7.3)
# - 优化: 导出链接的备注 (Remark) 现在与配置名称保持一致，不再是死板的 "sing-box"
# - 继承: 自定义名称、卸载清理、API限流保护、管道运行支持等所有特性
#
# Usage: sudo bash sing-box.sh

set -euo pipefail
IFS=$'\n\t'

# ==================== 版本配置 ====================
SCRIPT_VERSION="v2.7.3"

# ==================== 颜色函数 ====================
_red() { echo -e "\e[31m$@\e[0m"; }
_green() { echo -e "\e[32m$@\e[0m"; }
_yellow() { echo -e "\e[33m$@\e[0m"; }
_blue_bg() { echo -e "\033[44;37m$@\033[0m"; }
_gray() { echo -e "\033[90m$@\033[0m"; }

err() { echo -e "\n\e[41m 错误 \e[0m $@\n" >&2; exit 1; }

# ==================== 路径与变量 ====================
IS_CORE=sing-box
IS_CORE_DIR=/etc/$IS_CORE
IS_CORE_BIN=$IS_CORE_DIR/bin/$IS_CORE
IS_CORE_REPO=SagerNet/$IS_CORE
IS_CONF_DIR=$IS_CORE_DIR/conf
IS_CONFIG_JSON=$IS_CORE_DIR/config.json
IS_LOG_DIR=/var/log/$IS_CORE

# 脚本安装路径
IS_SH_BIN="/usr/local/bin/sing-box"  # 实体文件
IS_LINK_BIN="/usr/local/bin/sb"      # 快捷软链
IS_SH_URL="https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh"

IS_VERSION_CACHE="/var/tmp/singbox_version_cache"

# 临时文件
TMP_DOWNLOAD="/tmp/sing-box-core.tar.gz"
TMP_DIR="/tmp/sing-box-extract"

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

# ==================== 资源清理 ====================
cleanup() {
    rm -f "$TMP_DOWNLOAD"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# ==================== 环境与依赖 ====================
check_root() {
    if [[ $EUID != 0 ]]; then err "请使用 root 用户运行此脚本"; fi
}

map_arch() {
    case $(uname -m) in
        amd64 | x86_64) echo "amd64" ;;
        *aarch64* | *armv8*) echo "arm64" ;;
        *) echo "unsupported" ;;
    esac
}

ensure_dependencies() {
    local missing_deps=0
    for cmd in curl wget tar jq openssl; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing_deps=1
            break
        fi
    done

    if [ $missing_deps -eq 1 ]; then
        echo "正在安装依赖 (curl, wget, jq, openssl, tar)..."
        if [ -f /etc/debian_version ]; then
            apt-get update -y >/dev/null && apt-get install -y wget curl tar jq openssl >/dev/null
        elif [ -f /etc/redhat-release ]; then
            yum -y install wget curl tar jq openssl >/dev/null
        elif [ -f /etc/alpine-release ]; then
            apk add --no-cache wget curl tar jq openssl >/dev/null
        else
            _yellow "无法自动安装依赖，请手动安装: wget curl tar jq openssl"
        fi
    fi
}

# ==================== 网络请求 ====================
curl_retry() {
    local attempt=1
    while [ $attempt -le "$CURL_MAX_RETRIES" ]; do
        if curl -L -f --progress-bar "$@"; then return 0; fi
        if [ $attempt -lt "$CURL_MAX_RETRIES" ]; then
            _yellow "curl 请求失败，${CURL_RETRY_DELAY}秒后重试..."
            sleep "$CURL_RETRY_DELAY"
        fi
        attempt=$((attempt + 1))
    done
    return 1
}

wget_retry() {
    local attempt=1
    while [ $attempt -le "$WGET_MAX_RETRIES" ]; do
        if wget --no-check-certificate "$@"; then return 0; fi
        if [ $attempt -lt "$WGET_MAX_RETRIES" ]; then
            _yellow "wget 请求失败，${WGET_RETRY_DELAY}秒后重试..."
            sleep "$WGET_RETRY_DELAY"
        fi
        attempt=$((attempt + 1))
    done
    return 1
}

download_file() {
    local url="$1"
    local dest="$2"
    echo "正在下载: $url"
    if command -v curl >/dev/null 2>&1; then
        if curl_retry -o "$dest" "$url"; then return 0; fi
    fi
    if command -v wget >/dev/null 2>&1; then
        if wget_retry -O "$dest" "$url"; then return 0; fi
    fi
    return 1
}

# ==================== IP 获取 ====================
is_valid_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]; then
        return 0
    else
        return 1
    fi
}

get_ip() {
    local ip
    ip=$(curl -s4m3 ip.sb 2>/dev/null || curl -s4m3 api.ipify.org 2>/dev/null || echo "")
    if is_valid_ip "$ip"; then
        echo "$ip"
    else
        echo "<服务器IP>"
    fi
}

# ==================== 状态检测 ====================
refresh_status() {
    if [[ -f $IS_CORE_BIN ]]; then
        is_core_ver=$($IS_CORE_BIN version 2>/dev/null | head -n1 | awk '{print $3}')
    else
        is_core_ver=""
    fi
    
    if systemctl is-active --quiet $IS_CORE 2>/dev/null; then
        is_core_status=$(_green "运行中")
    else
        is_core_status=$(_red "未运行")
    fi
}

# ==================== 安装功能 ====================
install_singbox() {
    check_root
    ensure_dependencies
    
    local arch; arch=$(map_arch)
    if [ "$arch" = "unsupported" ]; then err "不支持的架构: $(uname -m)"; fi

    echo
    _green ">>> 准备安装 $IS_CORE ..."

    local version
    local api_json
    api_json=$(curl -sL --retry 2 "https://api.github.com/repos/$IS_CORE_REPO/releases/latest" || echo "{}")
    version=$(echo "$api_json" | jq -r .tag_name 2>/dev/null || echo "null")
    
    if [[ "$version" == "null" || -z "$version" ]]; then
        _yellow "获取版本失败，使用后备版本 v1.10.1"
        version="v1.10.1" 
    fi
    echo "    版本: $version"

    local core_url="https://github.com/$IS_CORE_REPO/releases/download/$version/$IS_CORE-${version#v}-linux-$arch.tar.gz"
    rm -f "$TMP_DOWNLOAD"
    if ! download_file "$core_url" "$TMP_DOWNLOAD"; then
        err "核心下载失败"
    fi
    
    if ! gzip -t "$TMP_DOWNLOAD" >/dev/null 2>&1; then
        err "文件校验失败"
    fi
    
    mkdir -p "$TMP_DIR"
    tar -xzf "$TMP_DOWNLOAD" -C "$TMP_DIR" --strip-components=1
    mkdir -p $IS_CORE_DIR/bin $IS_CONF_DIR $IS_LOG_DIR
    
    systemctl stop $IS_CORE 2>/dev/null || true
    cp "$TMP_DIR/sing-box" "$IS_CORE_BIN"
    chmod +x "$IS_CORE_BIN"
    
    # 脚本安装
    local current_path; current_path=$(realpath "$0" 2>/dev/null || echo "$0")
    if [[ ! -f "$current_path" ]] || [[ "$current_path" == "/dev/fd/"* ]] || [[ "$current_path" == "/proc/"* ]]; then
        echo "正在下载管理脚本..."
        if download_file "$IS_SH_URL" "$IS_SH_BIN"; then
            chmod +x "$IS_SH_BIN"
            ln -sf "$IS_SH_BIN" "$IS_LINK_BIN"
        else
            _yellow "脚本下载失败"
        fi
    elif [[ "$current_path" != "$IS_SH_BIN" ]]; then
        cp "$current_path" "$IS_SH_BIN"
        chmod +x "$IS_SH_BIN"
        ln -sf "$IS_SH_BIN" "$IS_LINK_BIN"
    fi

    # Systemd
    cat > /etc/systemd/system/$IS_CORE.service <<EOF
[Unit]
Description=$IS_CORE Service
After=network.target

[Service]
User=root
ExecStart=$IS_CORE_BIN run -c $IS_CONFIG_JSON -C $IS_CONF_DIR
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable $IS_CORE >/dev/null 2>&1

    # 默认配置
    if [ ! -f "$IS_CONFIG_JSON" ]; then
        cat > $IS_CONFIG_JSON <<EOF
{
    "log": {
        "level": "info",
        "output": "$IS_LOG_DIR/sing-box.log",
        "timestamp": true
    },
    "dns": {},
    "outbounds": [
        {"type": "direct", "tag": "direct"}
    ]
}
EOF
    fi
    
    echo
    _green "安装完成!"
    echo "命令: sb"
    echo
}

# ==================== 卸载功能 ====================
uninstall() {
    echo
    _yellow "警告: 即将卸载 Sing-box"
    read -rp "确认卸载? [y/N]: " confirm
    if [[ "${confirm,,}" == "y" ]]; then
        systemctl stop $IS_CORE 2>/dev/null || true
        systemctl disable $IS_CORE 2>/dev/null || true
        rm -f /etc/systemd/system/$IS_CORE.service
        systemctl daemon-reload
        
        rm -rf $IS_CORE_DIR
        rm -rf $IS_LOG_DIR
        rm -f "$IS_SH_BIN" "$IS_LINK_BIN"
        rm -f "$IS_VERSION_CACHE"
        
        _green "Sing-box 已彻底卸载"
        exit 0
    else
        echo "已取消"
    fi
}

# ==================== 辅助函数 ====================
is_port_used() {
    local port=$1
    if command -v ss >/dev/null 2>&1; then
        ss -tuln | grep -qE "(:|])$port\b"
    elif command -v lsof >/dev/null 2>&1; then
        lsof -i :"$port" >/dev/null 2>&1
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

# ==================== 配置管理 ====================
get_conf_list() {
    conf_list=()
    while IFS= read -r -d '' file; do
        conf_list+=("$(basename "$file")")
    done < <(find "$IS_CONF_DIR" -maxdepth 1 -name "*.json" -print0 2>/dev/null)
}

read_json_val() {
    jq -r "$2" "$1" 2>/dev/null
}

save_conf() {
    local target_file="$IS_CONF_DIR/$is_conf_name.json"
    local tmp_file="${target_file}.tmp"
    
    if ! echo "$is_conf" | jq . > "$tmp_file" 2>/dev/null; then
        rm -f "$tmp_file"
        _red "JSON 格式错误"
        return 1
    fi
    
    if ! $IS_CORE_BIN check -c "$IS_CONFIG_JSON" -C "$IS_CONF_DIR" >/dev/null 2>&1; then
        _yellow "警告: 配置校验未通过 (可能是端口冲突)"
    fi

    if [ -f "$target_file" ]; then cp "$target_file" "${target_file}.bak"; fi
    mv "$tmp_file" "$target_file"
    _green "配置已保存: $is_conf_name.json"
    return 0
}

# ==================== 功能操作 ====================
add() {
    if [[ -z "${1:-}" ]]; then
        echo
        echo "请选择协议:"
        echo "  1. VLESS-Reality"
        echo "  2. Shadowsocks"
        echo "  0. 返回"
        read -rp "序号: " p
        case $p in
            1) is_protocol="VLESS-Reality" ;;
            2) is_protocol="Shadowsocks" ;;
            *) return 0 ;;
        esac
    else
        case ${1,,} in
            r|reality) is_protocol="VLESS-Reality" ;;
            ss|shadowsocks) is_protocol="Shadowsocks" ;;
            *) _yellow "未知协议"; return 1 ;;
        esac
    fi
    
    echo
    _green ">>> 添加 $is_protocol"
    
    local default_port=$(rand_port)
    read -rp "端口 [$default_port]: " port
    is_port=${port:-$default_port}
    
    if ! [[ "$is_port" =~ ^[0-9]+$ ]] || [ "$is_port" -lt 1 ] || [ "$is_port" -gt 65535 ]; then
        err "端口无效"
    fi
    if is_port_used "$is_port"; then err "端口被占用"; fi
    
    # === 自定义名称逻辑 ===
    local def_prefix="vless"
    if [[ "$is_protocol" == "Shadowsocks" ]]; then def_prefix="ss"; fi
    local def_name="${def_prefix}-${is_port}"
    
    read -rp "配置名称 (用于链接备注) [$def_name]: " input_name
    is_conf_name=${input_name:-$def_name}
    
    if [[ ! "$is_conf_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        _yellow "名称包含非法字符，将使用默认名称: $def_name"
        is_conf_name="$def_name"
    fi
    # ===============================

    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local sni="www.time.is"
    
    if [[ "$is_protocol" == "VLESS-Reality" ]]; then
        read -rp "UUID [$uuid]: " u; uuid=${u:-$uuid}
        read -rp "SNI [$sni]: " s; sni=${s:-$sni}
        
        local keys=$($IS_CORE_BIN generate reality-keypair)
        local pk=$(echo "$keys" | grep PrivateKey | awk '{print $2}' || true)
        local pub=$(echo "$keys" | grep PublicKey | awk '{print $2}' || true)
        local sid=$(openssl rand -hex 8)
        
        if [[ -z "$pk" || -z "$pub" ]]; then err "密钥生成失败"; fi

        is_conf=$(jq -n --arg port "$is_port" --arg uuid "$uuid" --arg sni "$sni" --arg pk "$pk" --arg pub "$pub" --arg sid "$sid" --arg tag "$is_conf_name" \
                  '{inbounds: [{type: "vless", tag: $tag, listen: "::", listen_port: ($port|tonumber), users: [{uuid: $uuid, flow: "xtls-rprx-vision"}], tls: {enabled: true, server_name: $sni, reality: {enabled: true, handshake: {server: $sni, server_port: 443}, private_key: $pk, short_id: [$sid]}}}], outbounds: [{type: "direct"}, {type: "direct", tag: ("public_key_"+$pub)}] }')
    else
        local method="2022-blake3-aes-128-gcm"
        local pass=$(openssl rand -base64 16)
        is_conf=$(jq -n --arg port "$is_port" --arg pass "$pass" --arg method "$method" --arg tag "$is_conf_name" \
                  '{inbounds: [{type: "shadowsocks", tag: $tag, listen: "::", listen_port: ($port|tonumber), method: $method, password: $pass}]}')
    fi

    if save_conf; then
        firewall_allow "$is_port"
        systemctl restart $IS_CORE
        is_conf_file="$is_conf_name.json"
        info_show
    fi
}

# ==================== 其他管理 ====================
firewall_allow() {
    local p=$1
    if command -v ufw >/dev/null 2>&1; then ufw allow "$p" >/dev/null 2>&1 || true; fi
    if command -v firewall-cmd >/dev/null 2>&1; then 
        firewall-cmd --permanent --add-port="$p/tcp" >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port="$p/udp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
}

firewall_remove() {
    local p=$1
    if command -v ufw >/dev/null 2>&1; then ufw delete allow "$p" >/dev/null 2>&1 || true; fi
    if command -v firewall-cmd >/dev/null 2>&1; then 
        firewall-cmd --permanent --remove-port="$p/tcp" >/dev/null 2>&1 || true
        firewall-cmd --permanent --remove-port="$p/udp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
}

del() {
    get_conf_list
    if [[ ${#conf_list[@]} -eq 0 ]]; then _yellow "无配置"; return; fi
    
    echo "选择删除:"
    for i in "${!conf_list[@]}"; do
        printf " %2d. %s\n" "$((i+1))" "${conf_list[$i]}"
    done
    read -rp "序号: " idx
    
    if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "${#conf_list[@]}" ]; then
        local file="${conf_list[$((idx-1))]}"
        local path="$IS_CONF_DIR/$file"
        local port=$(read_json_val "$path" '.inbounds[0].listen_port')
        
        rm -f "$path"
        if [ -n "$port" ] && [ "$port" != "null" ]; then firewall_remove "$port"; fi
        systemctl restart $IS_CORE
        _green "已删除: $file"
    else
        _yellow "取消"
    fi
}

info_show() {
    local path="$IS_CONF_DIR/$is_conf_file"
    local type=$(read_json_val "$path" '.inbounds[0].type')
    local port=$(read_json_val "$path" '.inbounds[0].listen_port')
    local ip=$(get_ip)
    
    # 提取备注名 (去掉 .json 后缀)
    local remark="${is_conf_file%.*}"
    
    echo
    echo "=== 配置: $is_conf_file ==="
    echo "类型: $type"
    echo "端口: $port"
    echo "IP  : $ip"
    echo "备注: $remark"
    
    if [[ "$type" == "vless" ]]; then
        local uuid=$(read_json_val "$path" '.inbounds[0].users[0].uuid')
        local sni=$(read_json_val "$path" '.inbounds[0].tls.server_name')
        local sid=$(read_json_val "$path" '.inbounds[0].tls.reality.short_id[0]')
        local pub=$(read_json_val "$path" '.outbounds[1].tag' | sed 's/public_key_//')
        
        echo "UUID: $uuid"
        echo "SNI : $sni"
        echo "PBK : $pub"
        echo "SID : $sid"
        echo
        echo "链接:"
        echo "vless://$uuid@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$sni&fp=chrome&pbk=$pub&sid=$sid&type=tcp#$remark"
    elif [[ "$type" == "shadowsocks" ]]; then
        local method=$(read_json_val "$path" '.inbounds[0].method')
        local pass=$(read_json_val "$path" '.inbounds[0].password')
        local ss_str=$(echo -n "$method:$pass" | base64 -w 0)
        echo "Method: $method"
        echo "Pass  : $pass"
        echo
        echo "链接:"
        echo "ss://$ss_str@$ip:$port#$remark"
    fi
    echo
}

info() {
    get_conf_list
    if [[ ${#conf_list[@]} -eq 0 ]]; then _yellow "无配置"; return; fi
    
    if [[ ${#conf_list[@]} -eq 1 ]]; then
        is_conf_file="${conf_list[0]}"
    else
        echo "选择配置:"
        for i in "${!conf_list[@]}"; do
            printf " %2d. %s\n" "$((i+1))" "${conf_list[$i]}"
        done
        read -rp "序号: " idx
        if [[ ! "$idx" =~ ^[0-9]+$ ]] || [ "$idx" -lt 1 ] || [ "$idx" -gt "${#conf_list[@]}" ]; then return; fi
        is_conf_file="${conf_list[$((idx-1))]}"
    fi
    info_show
}

# ==================== 菜单逻辑 ====================
pause_return() { echo; read -rp "按回车返回..."; }

show_menu() {
    while true; do
        refresh_status
        get_conf_list
        clear
        echo
        echo -e " $(_blue_bg "          Sing-box 面板 $SCRIPT_VERSION           ")"
        echo
        echo -e " 🟢 状态: $is_core_status      版本: ${is_core_ver:-$(_red "未安装")}"
        echo -e " 📋 配置: ${#conf_list[@]} 个"
        echo
        echo -e "  1. 添加配置 $(_green "+")         2. 删除配置 🗑️"
        echo -e "  3. 查看详情 👁️          4. 更新核心 🆙"
        echo
        echo -e "  5. 启动服务 ▶️          6. 停止服务 ⏹️"
        echo -e "  7. 重启服务 🔄          8. 查看日志 📜"
        echo
        echo -e "  9. 更新脚本 🔄         10. 卸载脚本 ❌"
        echo -e "  0. 退出"
        echo
        read -rp " 请输入序号: " pick
        case "$pick" in
            1) add; pause_return ;;
            2) del; pause_return ;;
            3) info; pause_return ;;
            4) install_singbox; pause_return ;;
            5) systemctl start $IS_CORE; pause_return ;;
            6) systemctl stop $IS_CORE; pause_return ;;
            7) systemctl restart $IS_CORE; pause_return ;;
            8) tail -n 50 "$IS_LOG_DIR/sing-box.log"; pause_return ;;
            9) 
                if download_file "$IS_SH_URL" "$IS_SH_BIN"; then
                    chmod +x "$IS_SH_BIN"
                    _green "脚本已更新，请重新运行"
                    exit 0
                else
                    _red "更新失败"
                    pause_return
                fi
                ;;
            10) uninstall ;;
            0) exit 0 ;;
            *) ;;
        esac
    done
}

# ==================== 入口 ====================
if [ -f "$IS_SH_BIN" ] && [ -d "$IS_CORE_DIR" ]; then
    check_root
    if [[ -n "${1:-}" ]]; then
        case "$1" in
            add) add ;;
            info) info ;;
            uninstall) uninstall ;;
            *) show_menu ;;
        esac
    else
        show_menu
    fi
else
    install_singbox
fi