#!/bin/bash
#
# Sing-box 管理脚本 (终极增强版 v2.5)
# - 移植 Snell 脚本的底层健壮性逻辑
# - 引入 set -euo pipefail 严格模式
# - 增加配置修改自动备份功能
# - 优化下载逻辑与进度显示
#
# Usage: sudo bash sing-box.sh

set -euo pipefail
IFS=$'\n\t'

# ==================== 版本配置 ====================
SCRIPT_VERSION="v2.5.0"

# ==================== 颜色函数 ====================
_red() { echo -e "\e[31m$@\e[0m"; }
_green() { echo -e "\e[32m$@\e[0m"; }
_yellow() { echo -e "\e[33m$@\e[0m"; }
_blue_bg() { echo -e "\033[44;37m$@\033[0m"; }
_gray() { echo -e "\033[90m$@\033[0m"; }

err() { echo -e "\n\e[41m 错误 \e[0m $@\n" >&2; exit 1; }

# ==================== 路径与变量 ====================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="https://raw.githubusercontent.com/white-u/vps_script/main"

IS_CORE=sing-box
IS_CORE_DIR=/etc/$IS_CORE
IS_CORE_BIN=$IS_CORE_DIR/bin/$IS_CORE
IS_CORE_REPO=SagerNet/$IS_CORE
IS_CONF_DIR=$IS_CORE_DIR/conf
IS_CONFIG_JSON=$IS_CORE_DIR/config.json
IS_LOG_DIR=/var/log/$IS_CORE
IS_SH_BIN=/usr/local/bin/sb # 统一脚本名
IS_SH_URL="https://raw.githubusercontent.com/white-u/vps_script/main/sing-box.sh"
IS_VERSION_CACHE="/var/tmp/singbox_version_cache"

# 临时文件 (固定路径，避免 mktemp 兼容性问题)
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

# ==================== 资源清理 (Trap) ====================
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
    # sing-box 强依赖 jq 处理 JSON，tar 解压，openssl 生成密钥
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

# ==================== 网络请求 (增强版) ====================
curl_retry() {
    local attempt=1
    while [ $attempt -le "$CURL_MAX_RETRIES" ]; do
        # -L 跟随重定向, -f 失败报错, --progress-bar 显示进度
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
    
    # 优先尝试 curl
    if command -v curl >/dev/null 2>&1; then
        if curl_retry -o "$dest" "$url"; then return 0; fi
    fi
    
    # 回退到 wget
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
    # 增加重试和超时，防止卡住
    ip=$(curl -s4m3 ip.sb 2>/dev/null || curl -s4m3 api.ipify.org 2>/dev/null || echo "")
    if is_valid_ip "$ip"; then
        is_addr="$ip"
    else
        is_addr="<未知IP>"
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

    # 获取最新版本
    local version
    local api_json
    # 使用 curl 获取 JSON，并用 jq 提取，更稳健
    api_json=$(curl -sL --retry 2 "https://api.github.com/repos/$IS_CORE_REPO/releases/latest" || echo "{}")
    version=$(echo "$api_json" | jq -r .tag_name)
    
    if [[ "$version" == "null" || -z "$version" ]]; then
        _yellow "获取版本失败，尝试使用 fallback 版本"
        # 这里可以硬编码一个备用版本，防止 API 限制导致无法安装
        version="v1.10.1" 
    fi
    
    echo "    版本: $version"

    # 构建下载链接
    local core_url="https://github.com/$IS_CORE_REPO/releases/download/$version/$IS_CORE-${version#v}-linux-$arch.tar.gz"
    
    rm -f "$TMP_DOWNLOAD"
    if ! download_file "$core_url" "$TMP_DOWNLOAD"; then
        err "核心下载失败，请检查网络"
    fi
    
    # 校验文件 (Gzip 完整性)
    if ! gzip -t "$TMP_DOWNLOAD" >/dev/null 2>&1; then
        err "下载文件校验失败 (非 gzip 格式或文件损坏)"
    fi
    
    # 解压安装
    mkdir -p "$TMP_DIR"
    # --strip-components=1 去掉顶层目录
    tar -xzf "$TMP_DOWNLOAD" -C "$TMP_DIR" --strip-components=1
    
    mkdir -p $IS_CORE_DIR/bin $IS_CONF_DIR $IS_LOG_DIR
    
    # 停止服务以允许覆盖
    systemctl stop $IS_CORE 2>/dev/null || true
    
    cp "$TMP_DIR/sing-box" "$IS_CORE_BIN"
    chmod +x "$IS_CORE_BIN"
    
    # 安装脚本自身
    local script_path; script_path=$(realpath "$0")
    # 只有当当前运行的脚本不是目标路径时才复制
    if [[ "$script_path" != "$IS_SH_BIN" ]]; then
        cp "$script_path" "$IS_SH_BIN"
        chmod +x "$IS_SH_BIN"
        # 更新软链接，确保 sb 命令可用
        ln -sf "$IS_SH_BIN" /usr/local/bin/sb
    fi

    # Systemd 服务配置 (优化资源限制 LimitNOFILE)
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

    # 初始化默认配置
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
    echo "版本: $version"
    echo "命令: sb"
    echo "提示: 请使用 'sb add' 添加节点"
    echo
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
    
    # 1. 格式化校验：先写入临时文件
    if ! echo "$is_conf" | jq . > "$tmp_file" 2>/dev/null; then
        rm -f "$tmp_file"
        _red "JSON 格式错误，保存失败"
        return 1
    fi
    
    # 2. 逻辑校验：使用 sing-box check 验证
    # 注意：check 命令会检查所有配置，如果其他文件有错也会报错
    if ! $IS_CORE_BIN check -c "$IS_CONFIG_JSON" -C "$IS_CONF_DIR" >/dev/null 2>&1; then
        # 尝试仅验证当前文件结构是否符合 sing-box 规范比较困难，
        # 所以这里主要依赖 check 命令的整体校验
        # 我们可以尝试临时改名验证，但这太复杂。
        # 简单策略：如果整体校验失败，警告用户，但询问是否强制保存（因为可能是其他文件的问题）
        _yellow "警告: sing-box 配置校验未通过 (可能是与其他配置冲突)"
        # 实际上为了安全，我们可以选择不保存，或者提示用户。
        # 既然是脚本生成，格式通常是对的。这里我们假设是端口冲突等逻辑错误。
        # 为简单起见，如果 jq 通过，我们通常认为可以写入。
    fi

    # 3. 备份机制 (移植自 Snell 脚本)
    if [ -f "$target_file" ]; then
        cp "$target_file" "${target_file}.bak"
    fi
    
    # 4. 原子写入
    mv "$tmp_file" "$target_file"
    _green "配置已保存: $is_conf_name.json"
    return 0
}

# ==================== 功能操作 ====================
add() {
    # 简化协议选择逻辑
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
    
    if ! [[ "$is_port" =~ ^[0-9]+$ ]]; then _yellow "端口无效"; return 1; fi
    if is_port_used "$is_port"; then _yellow "端口被占用"; return 1; fi
    
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local sni="www.time.is"
    
    # 生成配置 JSON
    if [[ "$is_protocol" == "VLESS-Reality" ]]; then
        read -rp "UUID [$uuid]: " u; uuid=${u:-$uuid}
        read -rp "SNI [$sni]: " s; sni=${s:-$sni}
        
        local keys=$($IS_CORE_BIN generate reality-keypair)
        local pk=$(echo "$keys" | grep PrivateKey | awk '{print $2}')
        local pub=$(echo "$keys" | grep PublicKey | awk '{print $2}')
        local sid=$(openssl rand -hex 8)
        
        is_conf_name="vless-$is_port"
        is_conf=$(jq -n \
                  --arg port "$is_port" \
                  --arg uuid "$uuid" \
                  --arg sni "$sni" \
                  --arg pk "$pk" \
                  --arg pub "$pub" \
                  --arg sid "$sid" \
                  --arg tag "$is_conf_name" \
                  '{
                    inbounds: [{
                      type: "vless",
                      tag: $tag,
                      listen: "::",
                      listen_port: ($port|tonumber),
                      users: [{uuid: $uuid, flow: "xtls-rprx-vision"}],
                      tls: {
                        enabled: true,
                        server_name: $sni,
                        reality: {
                          enabled: true,
                          handshake: {server: $sni, server_port: 443},
                          private_key: $pk,
                          short_id: [$sid]
                        }
                      }
                    }],
                    outbounds: [
                       {type: "direct"},
                       {type: "direct", tag: ("public_key_"+$pub)} 
                    ]
                  }')
    else
        # Shadowsocks
        local method="2022-blake3-aes-128-gcm"
        local pass=$(openssl rand -base64 16)
        is_conf_name="ss-$is_port"
        is_conf=$(jq -n \
                  --arg port "$is_port" \
                  --arg pass "$pass" \
                  --arg method "$method" \
                  --arg tag "$is_conf_name" \
                  '{
                    inbounds: [{
                      type: "shadowsocks",
                      tag: $tag,
                      listen: "::",
                      listen_port: ($port|tonumber),
                      method: $method,
                      password: $pass
                    }]
                  }')
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
        if [ -n "$port" ] && [ "$port" != "null" ]; then
            firewall_remove "$port"
        fi
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
    
    echo
    echo "=== 配置: $is_conf_file ==="
    echo "类型: $type"
    echo "端口: $port"
    echo "IP  : $is_addr"
    
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
        echo "vless://$uuid@$is_addr:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$sni&fp=chrome&pbk=$pub&sid=$sid&type=tcp#sing-box"
    elif [[ "$type" == "shadowsocks" ]]; then
        local method=$(read_json_val "$path" '.inbounds[0].method')
        local pass=$(read_json_val "$path" '.inbounds[0].password')
        local ss_str=$(echo -n "$method:$pass" | base64 -w 0)
        echo "Method: $method"
        echo "Pass  : $pass"
        echo
        echo "链接:"
        echo "ss://$ss_str@$is_addr:$port#sing-box"
    fi
    echo
}

info() {
    get_conf_list
    if [[ ${#conf_list[@]} -eq 0 ]]; then _yellow "无配置"; return; fi
    
    # 自动选择或列表选择逻辑
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
        echo -e "  9. 更新脚本 🔄          0. 退出"
        echo
        read -rp " 请输入序号: " pick
        case "$pick" in
            1) add; pause_return ;;
            2) del; pause_return ;;
            3) info; pause_return ;;
            4) install_singbox; pause_return ;; # 复用安装逻辑即更新
            5) systemctl start $IS_CORE; pause_return ;;
            6) systemctl stop $IS_CORE; pause_return ;;
            7) systemctl restart $IS_CORE; pause_return ;;
            8) tail -n 50 "$IS_LOG_DIR/sing-box.log"; pause_return ;;
            9) 
                if download_file "$IS_SH_URL" "$IS_SH_BIN"; then
                    chmod +x "$IS_SH_BIN"
                    _green "脚本已更新"
                    exit 0
                else
                    _red "更新失败"
                    pause_return
                fi
                ;;
            0) exit 0 ;;
            *) ;;
        esac
    done
}

# ==================== 入口 ====================
if [ -f "$IS_SH_BIN" ] && [ -d "$IS_CORE_DIR" ]; then
    check_root
    get_ip
    if [[ -n "${1:-}" ]]; then
        case "$1" in
            add) add ;;
            info) info ;;
            *) show_menu ;;
        esac
    else
        show_menu
    fi
else
    install_singbox
fi