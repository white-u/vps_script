#!/bin/bash
#
# Xray 多协议管理脚本 (星辰大海架构复刻版 v1.3)
# v1.3:
# - 修复: publicKey 存入配置(不再运行时计算), 兼容 Xray 26.x (Password=PublicKey)
# - 修复: freedom outbound 加 domainStrategy:UseIPv4v6 (修复部分站点不通)
# - 修复: SS inbound 移除不必要的 sniffing
# - 安全: 配置文件 chmod 640 权限保护
# - 增强: 端口三重校验(范围+占用+配置冲突), 多源IP获取+IPv6, 分享链接IPv6方括号
#
# Usage: sudo bash x-sb.sh

# 注意: 不使用 set -euo pipefail, 交互式菜单脚本需要容错而非崩溃退出

# ==================== 全局变量 ====================
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[36m'
PLAIN='\033[0m'

SCRIPT_VERSION="1.3.0"
SHORTCUT_NAME="x-sb"
INSTALL_PATH="/usr/local/bin/$SHORTCUT_NAME"
# 脚本自身的下载地址
SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/x-sb.sh"

# Xray 官方标准路径
XRAY_BIN="/usr/local/bin/xray"
XRAY_CONF_DIR="/usr/local/etc/xray"
XRAY_CONF_FILE="$XRAY_CONF_DIR/config.json"
SYSTEMD_FILE="/etc/systemd/system/xray.service"
DAT_DIR="/usr/local/share/xray"

# 默认 SNI 列表
SNI_LIST=(
    "addons.mozilla.org"
    "www.microsoft.com"
    "www.amazon.com"
    "swdist.apple.com"
    "updates.cdn-apple.com"
)

# 临时资源清理
_CLEANUP_FILES=()
cleanup() {
    for f in "${_CLEANUP_FILES[@]+"${_CLEANUP_FILES[@]}"}"; do
        rm -rf "$f" 2>/dev/null
    done
}
trap cleanup EXIT INT TERM

# Windows 换行符清洗
strip_cr() { echo "${1//$'\r'/}"; }

# ==================== 基础检查 ====================
check_root() {
    [[ $EUID -ne 0 ]] && { echo -e "${RED}错误: 必须使用 root 权限运行。${PLAIN}"; exit 1; }
}

map_arch() {
    case $(uname -m) in
        x86_64) echo "64" ;;
        aarch64|armv8*) echo "arm64-v8a" ;;
        *) echo -e "${RED}不支持的架构: $(uname -m)${PLAIN}"; exit 1 ;;
    esac
}

check_deps() {
    local deps=("curl" "wget" "unzip" "jq" "openssl" "qrencode")
    local need_install=0
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then need_install=1; break; fi
    done
    
    if [[ $need_install -eq 1 ]]; then
        echo -e "${YELLOW}安装必要依赖 (${deps[*]})...${PLAIN}"
        if [ -f /etc/debian_version ]; then
            apt-get update && apt-get install -y "${deps[@]}"
        elif [ -f /etc/redhat-release ]; then
            yum install -y "${deps[@]}"
        elif [ -f /etc/alpine-release ]; then
            # Alpine: qrencode 命令在 libqrencode-tools 包中
            apk add curl wget unzip jq openssl libqrencode-tools
        fi
    fi
}

# ==================== Xray 核心管理 ====================

install_xray() {
    echo -e "${BLUE}>>> 检查 Xray 核心...${PLAIN}"
    mkdir -p "$XRAY_CONF_DIR" "$DAT_DIR"
    
    local arch=$(map_arch)
    local latest_tag
    latest_tag=$(curl -sL https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    local latest_ver="${latest_tag#v}"  # 去掉 v 前缀, 对齐 xray version 输出格式
    
    if [[ -z "$latest_tag" || "$latest_tag" == "null" ]]; then
        echo -e "${RED}无法获取 Xray 最新版本。${PLAIN}"
        if [[ -f "$XRAY_BIN" ]]; then return; else exit 1; fi
    fi
    
    local curr_ver="none"
    [[ -f "$XRAY_BIN" ]] && curr_ver=$($XRAY_BIN version | head -1 | awk '{print $2}')
    
    if [[ "$curr_ver" == "$latest_ver" ]]; then
        echo -e "${GREEN}当前已是最新版 ($curr_ver)，跳过安装。${PLAIN}"
    else
        echo -e "${YELLOW}正在安装 Xray $latest_ver ($arch)...${PLAIN}"
        local zip_url="https://github.com/XTLS/Xray-core/releases/download/${latest_tag}/Xray-linux-${arch}.zip"
        local tmp_file=$(mktemp)
        local tmp_dir=$(mktemp -d)
        _CLEANUP_FILES+=("$tmp_file" "$tmp_dir")
        
        if ! curl -L --max-time 120 -o "$tmp_file" --progress-bar "$zip_url"; then
            echo -e "${RED}下载失败。${PLAIN}"; exit 1
        fi
        
        unzip -q "$tmp_file" -d "$tmp_dir"
        
        systemctl stop xray 2>/dev/null || true
        mv "$tmp_dir/xray" "$XRAY_BIN"
        mv "$tmp_dir/geoip.dat" "$DAT_DIR/" 2>/dev/null || true
        mv "$tmp_dir/geosite.dat" "$DAT_DIR/" 2>/dev/null || true
        chmod +x "$XRAY_BIN"
        echo -e "${GREEN}Xray 核心更新成功。${PLAIN}"
    fi
    
    cat > "$SYSTEMD_FILE" <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_BIN run -c $XRAY_CONF_FILE
Restart=on-failure
RestartSec=10
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    
    init_config_if_missing
    install_shortcut_cmd
}

install_shortcut_cmd() {
    if [[ "$(realpath "$0" 2>/dev/null)" == "$INSTALL_PATH" ]]; then return; fi
    
    # 优先从远程下载(防止管道运行时 $0 指向 /dev/fd/XX)
    local tmp_dl=$(mktemp /tmp/x-sb_install.XXXXXX.sh)
    _CLEANUP_FILES+=("$tmp_dl")
    if curl -fsSL --max-time 15 "$SCRIPT_URL" -o "$tmp_dl" 2>/dev/null && [ -s "$tmp_dl" ]; then
        mv -f "$tmp_dl" "$INSTALL_PATH"
        chmod +x "$INSTALL_PATH"
        echo -e "${GREEN}快捷命令 '$SHORTCUT_NAME' 已安装。${PLAIN}"
    elif [[ -f "$0" ]]; then
        # 降级: 本地复制
        cp "$0" "$INSTALL_PATH" && chmod +x "$INSTALL_PATH"
        echo -e "${GREEN}快捷命令 '$SHORTCUT_NAME' 已安装 (本地)。${PLAIN}"
    fi
}

init_config_if_missing() {
    if [[ ! -f "$XRAY_CONF_FILE" ]] || [[ ! -s "$XRAY_CONF_FILE" ]]; then
        cat > "$XRAY_CONF_FILE" <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "settings": {
        "domainStrategy": "UseIPv4v6"
      }
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      }
    ]
  }
}
EOF
        mkdir -p /var/log/xray
        echo -e "${GREEN}初始化默认配置完成。${PLAIN}"
    fi
}

# ==================== JSON 辅助操作 ====================

safe_save_config() {
    local tmp_json=$1
    
    # 1. JSON 语法校验
    if ! jq . "$tmp_json" >/dev/null 2>&1; then
        echo -e "${RED}JSON 语法校验失败，未保存。${PLAIN}"
        return 1
    fi
    
    # 2. Xray 语义校验 (不启动服务, 仅验证配置)
    if [[ -f "$XRAY_BIN" ]]; then
        local test_output
        test_output=$("$XRAY_BIN" run -test -c "$tmp_json" 2>&1)
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}Xray 配置校验失败，未保存。错误信息:${PLAIN}"
            echo "$test_output" | tail -5
            return 1
        fi
    fi
    
    # 3. 备份旧配置
    local backup=""
    if [[ -f "$XRAY_CONF_FILE" ]] && [[ -s "$XRAY_CONF_FILE" ]]; then
        backup="${XRAY_CONF_FILE}.bak"
        cp "$XRAY_CONF_FILE" "$backup"
    fi
    
    # 4. 写入新配置并重启
    cp "$tmp_json" "$XRAY_CONF_FILE"
    chmod 640 "$XRAY_CONF_FILE"
    systemctl restart xray
    sleep 1
    
    if systemctl is-active --quiet xray; then
        echo -e "${GREEN}配置已应用，服务已重启。${PLAIN}"
        rm -f "$backup"
    else
        echo -e "${RED}Xray 启动失败! 正在回滚...${PLAIN}"
        # 显示失败原因
        journalctl -u xray --no-pager -n 5 2>/dev/null | grep -i "failed\|error" | head -3
        if [[ -n "$backup" ]] && [[ -f "$backup" ]]; then
            cp "$backup" "$XRAY_CONF_FILE"
            systemctl restart xray 2>/dev/null
            sleep 1
            if systemctl is-active --quiet xray; then
                echo -e "${YELLOW}已回滚到上一份有效配置，服务已恢复。${PLAIN}"
            else
                echo -e "${RED}回滚后仍无法启动，请手动检查: journalctl -u xray -n 20${PLAIN}"
            fi
        fi
        rm -f "$backup"
        return 1
    fi
}

get_random_port() {
    local port
    while true; do
        port=$((RANDOM % 55000 + 10000))
        if is_port_available "$port"; then
            echo $port
            return
        fi
    done
}

# 端口可用性检查: 范围 + 系统占用 + 配置冲突
is_port_available() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "${RED}端口号无效 (1-65535)。${PLAIN}"; return 1
    fi
    if ss -tuln | grep -q ":$port "; then
        echo -e "${RED}端口 $port 已被系统占用。${PLAIN}"; return 1
    fi
    if [[ -f "$XRAY_CONF_FILE" ]]; then
        local existing
        existing=$(jq -r '.inbounds[]?.port // empty' "$XRAY_CONF_FILE" 2>/dev/null)
        if echo "$existing" | grep -q "^${port}$"; then
            echo -e "${RED}端口 $port 已在 Xray 配置中使用。${PLAIN}"; return 1
        fi
    fi
    return 0
}

# ==================== 节点管理逻辑 ====================

add_reality() {
    echo -e "${BLUE}>>> 添加 VLESS-Vision-Reality 节点 (⭐ 推荐)${PLAIN}"
    
    read -p "请输入端口 [默认443]: " port
    port=$(strip_cr "$port")
    [[ -z "$port" ]] && port=443
    if ! is_port_available "$port"; then return; fi
    
    echo -e "正在测试 SNI 连通性..."
    local valid_snis=()
    for sni in "${SNI_LIST[@]}"; do
        if curl -m 3 -sI "https://$sni" >/dev/null 2>&1; then
            valid_snis+=("$sni")
            echo -e " ${#valid_snis[@]}. $sni \t${GREEN}[可用]${PLAIN}"
        else
            echo -e "    $sni \t${RED}[失败,已跳过]${PLAIN}"
        fi
    done
    local manual_idx=$(( ${#valid_snis[@]} + 1 ))
    echo -e " $manual_idx. 手动输入"
    
    read -p "请选择目标域名 [1]: " sni_idx
    sni_idx=$(strip_cr "$sni_idx")
    [[ -z "$sni_idx" ]] && sni_idx=1
    
    local target_dest=""
    local target_sni=""
    
    if [[ "$sni_idx" =~ ^[0-9]+$ ]] && [ "$sni_idx" -ge 1 ] && [ "$sni_idx" -le "${#valid_snis[@]}" ]; then
        target_sni="${valid_snis[$((sni_idx-1))]}"
    else
        read -p "请输入域名 (如 www.apple.com): " target_sni
        target_sni=$(strip_cr "$target_sni")
    fi
    
    if [[ -z "$target_sni" ]]; then
        echo -e "${RED}未选择有效域名。${PLAIN}"; return
    fi
    target_dest="${target_sni}:443"
    
    local uuid=$($XRAY_BIN uuid)
    local keys=$($XRAY_BIN x25519)
    local pk=$(echo "$keys" | awk '/PrivateKey:/{print $2}')
    local pubk=$(echo "$keys" | awk '/Password:/{print $2}')
    if [[ -z "$pk" || -z "$pubk" ]]; then
        # 兼容旧版 Xray (Private key: / Public key:)
        pk=$(echo "$keys" | grep -i "private" | awk '{print $NF}')
        pubk=$(echo "$keys" | grep -i "public" | awk '{print $NF}')
    fi
    if [[ -z "$pk" || -z "$pubk" ]]; then
        echo -e "${RED}错误: 无法生成 Reality 密钥对，请检查 Xray 版本。${PLAIN}"
        echo -e "${YELLOW}x25519 输出: ${keys}${PLAIN}"
        return
    fi
    local short_id=$(openssl rand -hex 4)
    local tag="reality_$port"
    
    local chain_setting=$(ask_chain_proxy)
    local tmp=$(mktemp /tmp/xray_XXXXXX.json)
    _CLEANUP_FILES+=("$tmp")
    cp "$XRAY_CONF_FILE" "$tmp"
    
    jq --arg port "$port" --arg uuid "$uuid" --arg pk "$pk" --arg pubk "$pubk" --arg sni "$target_sni" --arg dest "$target_dest" --arg sid "$short_id" --arg tag "$tag" \
    '.inbounds += [{
      "tag": $tag,
      "port": ($port|tonumber),
      "protocol": "vless",
      "settings": {
        "clients": [{"id": $uuid, "flow": "xtls-rprx-vision"}],
        "decryption": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": $dest,
          "xver": 0,
          "serverNames": [$sni],
          "privateKey": $pk,
          "publicKey": $pubk,
          "shortIds": [$sid]
        }
      }
    }]' "$tmp" > "${tmp}.1" && mv "${tmp}.1" "$tmp"
    
    if [[ -n "$chain_setting" ]]; then
        apply_chain_routing "$tmp" "$tag"
    fi
    
    if safe_save_config "$tmp"; then
        rm -f "$tmp"
        show_node_info "$tag"
    else
        rm -f "$tmp"
    fi
}

add_ss2022() {
    echo -e "${BLUE}>>> 添加 Shadowsocks-2022 节点${PLAIN}"
    local port=$(get_random_port)
    read -p "请输入端口 [随机 $port]: " input_port
    input_port=$(strip_cr "$input_port")
    [[ -n "$input_port" ]] && port=$input_port
    if ! is_port_available "$port"; then return; fi
    
    local key=$(openssl rand -base64 16)
    local tag="ss_$port"
    
    local chain_setting=$(ask_chain_proxy)
    local tmp=$(mktemp /tmp/xray_XXXXXX.json)
    _CLEANUP_FILES+=("$tmp")
    cp "$XRAY_CONF_FILE" "$tmp"
    
    jq --arg port "$port" --arg key "$key" --arg tag "$tag" \
    '.inbounds += [{
      "tag": $tag,
      "port": ($port|tonumber),
      "protocol": "shadowsocks",
      "settings": {
        "method": "2022-blake3-aes-128-gcm",
        "password": $key,
        "network": "tcp,udp"
      }
    }]' "$tmp" > "${tmp}.1" && mv "${tmp}.1" "$tmp"
    
    if [[ -n "$chain_setting" ]]; then
        apply_chain_routing "$tmp" "$tag"
    fi
    
    if safe_save_config "$tmp"; then
        rm -f "$tmp"
        show_node_info "$tag"
    else
        rm -f "$tmp"
    fi
}

# ==================== 进阶功能：链式代理与路由 ====================

ask_chain_proxy() {
    local has_chain=$(jq '.outbounds[] | select(.tag=="chain_proxy")' "$XRAY_CONF_FILE")
    if [[ -z "$has_chain" ]]; then echo ""; return; fi
    
    echo -e "${YELLOW}进阶: 是否为此节点启用 SOCKS5 链式转发 (解锁/分流)? [y/N]${PLAIN}" >&2
    read -p "选择: " sel
    [[ "${sel,,}" == "y" ]] && echo "yes"
}

apply_chain_routing() {
    local json_file=$1
    local inbound_tag=$2
    jq --arg itag "$inbound_tag" \
    '.routing.rules = ([{
      "type": "field",
      "inboundTag": [$itag],
      "outboundTag": "chain_proxy"
    }] + .routing.rules)' "$json_file" > "${json_file}.r" && mv "${json_file}.r" "$json_file"
}

configure_advanced() {
    while true; do
        clear
        echo -e "${BLUE}=== 进阶功能配置 (Advanced) ===${PLAIN}"
        local chain_out=$(jq -r '.outbounds[] | select(.tag=="chain_proxy") | .settings.servers[0] | "\(.address):\(.port)"' "$XRAY_CONF_FILE" 2>/dev/null)
        
        echo -e " 1. 配置上游 SOCKS5 代理 (Chain Proxy)"
        echo -e "    当前状态: $([[ -n "$chain_out" ]] && echo "${GREEN}开启 -> $chain_out${PLAIN}" || echo "${YELLOW}未配置${PLAIN}")"
        echo -e " 2. 配置 全局路由规则 (屏蔽广告/回国流量)"
        echo -e " 0. 返回"
        echo -e "----------------------------------------"
        read -p "请选择: " choice
        
        case $choice in
            1) 
                read -p "请输入上游 SOCKS5 地址 (如 127.0.0.1:40000): " addr
                addr=$(strip_cr "$addr")
                if [[ -z "$addr" ]]; then
                    local tmp=$(mktemp /tmp/xray_XXXXXX.json)
                    _CLEANUP_FILES+=("$tmp")
                    # 同时删除 outbound 和引用它的路由规则
                    jq 'del(.outbounds[] | select(.tag=="chain_proxy")) |
                        .routing.rules |= [.[] | select(.outboundTag != "chain_proxy")]
                    ' "$XRAY_CONF_FILE" > "$tmp"
                    safe_save_config "$tmp" && rm -f "$tmp"
                else
                    local ip=${addr%:*}
                    local port=${addr#*:}
                    local tmp=$(mktemp /tmp/xray_XXXXXX.json)
                    _CLEANUP_FILES+=("$tmp")
                    jq 'del(.outbounds[] | select(.tag=="chain_proxy"))' "$XRAY_CONF_FILE" > "$tmp"
                    jq --arg ip "$ip" --arg port "$port" \
                    '.outbounds += [{
                        "tag": "chain_proxy",
                        "protocol": "socks",
                        "settings": {
                            "servers": [{"address": $ip, "port": ($port|tonumber)}]
                        }
                    }]' "$tmp" > "${tmp}.1" && mv "${tmp}.1" "$tmp"
                    safe_save_config "$tmp" && rm -f "$tmp"
                fi
                ;;
            2)
                local tmp=$(mktemp /tmp/xray_XXXXXX.json)
                _CLEANUP_FILES+=("$tmp")
                echo -e "正在应用: 屏蔽广告 + 屏蔽CN + 屏蔽局域网..."
                # 先删除已有的同类规则(幂等), 再追加
                jq '
                  .routing.rules |= [.[] | select(
                    (.domain // [] | any(startswith("geosite:"))) or
                    (.ip // [] | any(startswith("geoip:")))
                    | not
                  )] |
                  .routing.rules = [
                    {
                        "type": "field",
                        "outboundTag": "block",
                        "domain": ["geosite:category-ads-all", "geosite:cn"]
                    },
                    {
                        "type": "field",
                        "outboundTag": "block",
                        "ip": ["geoip:private", "geoip:cn"]
                    }
                  ] + .routing.rules
                ' "$XRAY_CONF_FILE" > "$tmp"
                safe_save_config "$tmp" && rm -f "$tmp"
                sleep 1
                ;;
            0) return ;;
        esac
    done
}

# ==================== 查看与分享 ====================

# 全局节点计数 (list_nodes 设置)
_NODE_COUNT=0

list_nodes() {
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e "   当前已配置节点列表"
    echo -e "${BLUE}================================================================${PLAIN}"
    printf " %-4s %-20s %-12s %-8s\n" "ID" "标签(Tag)" "协议" "端口"
    echo -e "----------------------------------------------------------------"
    
    _NODE_COUNT=0
    local nodes
    nodes=$(jq -c '.inbounds[]' "$XRAY_CONF_FILE" 2>/dev/null) || true
    [ -z "$nodes" ] && { echo -e " (无节点)"; echo -e "----------------------------------------------------------------"; return; }
    
    while IFS= read -r node; do
        [ -z "$node" ] && continue
        local tag=$(echo "$node" | jq -r '.tag' 2>/dev/null)
        local proto=$(echo "$node" | jq -r '.protocol' 2>/dev/null)
        local port=$(echo "$node" | jq -r '.port' 2>/dev/null)
        if [[ "$tag" == *"reality"* || "$tag" == *"ss"* ]]; then
            _NODE_COUNT=$((_NODE_COUNT+1))
            printf " [%d]  %-20s %-12s %-8s\n" "$_NODE_COUNT" "$tag" "$proto" "$port"
        fi
    done <<< "$nodes"
    echo -e "----------------------------------------------------------------"
}

# 按编号获取节点 tag (编号从 1 开始, 与 list_nodes 一致)
get_node_tag_by_id() {
    local target_id=$1
    local i=0
    local nodes
    nodes=$(jq -c '.inbounds[]' "$XRAY_CONF_FILE" 2>/dev/null) || true
    [ -z "$nodes" ] && return
    
    while IFS= read -r node; do
        [ -z "$node" ] && continue
        local tag=$(echo "$node" | jq -r '.tag' 2>/dev/null)
        if [[ "$tag" == *"reality"* || "$tag" == *"ss"* ]]; then
            i=$((i+1))
            if [ "$i" -eq "$target_id" ]; then
                echo "$tag"
                return
            fi
        fi
    done <<< "$nodes"
}

# 用 openssl 从 x25519 私钥推算公钥 (兼容所有 Xray 版本)
# Xray 26.x 移除了 PublicKey 输出, 必须自行计算
get_x25519_pubkey() {
    local priv_key=$1
    # base64url → standard base64 (补 padding)
    local b64=$(echo "$priv_key" | tr '_-' '/+')
    local mod=$((${#b64} % 4))
    if [[ $mod -eq 2 ]]; then b64="${b64}=="
    elif [[ $mod -eq 3 ]]; then b64="${b64}="
    fi
    # 构建 DER: RFC 8410 ASN.1 header (16 bytes) + 32 bytes raw key
    local tmp_der=$(mktemp)
    printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20' > "$tmp_der"
    echo "$b64" | base64 -d >> "$tmp_der" 2>/dev/null
    # openssl 提取公钥 → DER → 取末尾 32 字节 → base64url
    local pubk
    pubk=$(openssl pkey -inform DER -in "$tmp_der" -pubout -outform DER 2>/dev/null | \
           tail -c 32 | base64 | tr '/+' '_-' | tr -d '=\n')
    rm -f "$tmp_der"
    echo "$pubk"
}

show_node_info() {
    local tag=$1
    local ip=""
    local url
    for url in "https://api.ipify.org" "https://ip.sb" "https://checkip.amazonaws.com"; do
        ip=$(curl -4s --max-time 3 "$url" 2>/dev/null) && [[ -n "$ip" ]] && break
    done
    # IPv6 fallback
    if [[ -z "$ip" ]]; then
        for url in "https://api64.ipify.org" "https://ip.sb"; do
            ip=$(curl -6s --max-time 3 "$url" 2>/dev/null) && [[ -n "$ip" ]] && break
        done
    fi
    [[ -z "$ip" ]] && ip="YOUR_IP"
    # IPv6 地址在 URI 中需要方括号
    local display_ip="$ip"
    [[ "$ip" == *:* ]] && display_ip="[$ip]"
    local node=$(jq -c --arg t "$tag" '.inbounds[] | select(.tag==$t)' "$XRAY_CONF_FILE")
    local port=$(echo "$node" | jq -r '.port')
    local proto=$(echo "$node" | jq -r '.protocol')
    
    echo -e "\n${BLUE}--- 节点详情: $tag ---${PLAIN}"
    
    if [[ "$proto" == "vless" ]]; then
        local uuid=$(echo "$node" | jq -r '.settings.clients[0].id')
        local flow=$(echo "$node" | jq -r '.settings.clients[0].flow')
        local sni=$(echo "$node" | jq -r '.streamSettings.realitySettings.serverNames[0]')
        local pbk=$(echo "$node" | jq -r '.streamSettings.realitySettings.privateKey')
        # 优先读配置中的 publicKey, 降级用 openssl 计算 (兼容旧配置)
        local pubk=$(echo "$node" | jq -r '.streamSettings.realitySettings.publicKey // empty')
        if [[ -z "$pubk" ]]; then
            pubk=$(get_x25519_pubkey "$pbk")
        fi
        local sid=$(echo "$node" | jq -r '.streamSettings.realitySettings.shortIds[0]')
        
        local link="vless://${uuid}@${display_ip}:${port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=chrome&pbk=${pubk}&sid=${sid}&type=tcp&headerType=none#${tag}"
        
        echo -e "地址: $ip"
        echo -e "端口: $port"
        echo -e "UUID: $uuid"
        echo -e "流控: $flow"
        echo -e "SNI : $sni"
        echo -e "PbKey: $pubk"
        echo -e "\n${GREEN}>>> 分享链接:${PLAIN}"
        echo "$link"
        echo -e "\n${YELLOW}>>> 二维码:${PLAIN}"
        qrencode -t ANSIUTF8 "$link"
        
    elif [[ "$proto" == "shadowsocks" ]]; then
        local method=$(echo "$node" | jq -r '.settings.method')
        local pass=$(echo "$node" | jq -r '.settings.password')
        local raw="${method}:${pass}"
        local link="ss://$(echo -n "$raw" | base64 | tr -d '\n')@${display_ip}:${port}#${tag}"
        
        echo -e "地址: $ip"
        echo -e "端口: $port"
        echo -e "加密: $method"
        echo -e "密码: $pass"
        echo -e "\n${GREEN}>>> 分享链接:${PLAIN}"
        echo "$link"
        echo -e "\n${YELLOW}>>> 二维码:${PLAIN}"
        qrencode -t ANSIUTF8 "$link"
    fi
    echo
}

delete_node() {
    list_nodes
    [[ "$_NODE_COUNT" -eq 0 ]] && return
    read -p "请输入要删除的节点 ID (0 返回): " id
    id=$(strip_cr "$id")
    if [[ "$id" =~ ^[0-9]+$ ]] && [ "$id" -gt 0 ] && [ "$id" -le "$_NODE_COUNT" ]; then
        local target_tag
        target_tag=$(get_node_tag_by_id "$id")
        
        if [[ -n "$target_tag" ]]; then
            echo -e "${YELLOW}正在删除节点: $target_tag ...${PLAIN}"
            local tmp=$(mktemp /tmp/xray_XXXXXX.json)
            _CLEANUP_FILES+=("$tmp")
            jq --arg t "$target_tag" 'del(.inbounds[] | select(.tag==$t))' "$XRAY_CONF_FILE" > "$tmp"
            jq --arg t "$target_tag" 'del(.routing.rules[] | select(.inboundTag and (.inboundTag[] == $t)))' "$tmp" > "${tmp}.1" && mv "${tmp}.1" "$tmp"
            safe_save_config "$tmp" && rm -f "$tmp"
        fi
    fi
}

# ==================== 主菜单 & 更新 ====================

update_script() {
    echo -e "\n ${BLUE}>>> 更新管理脚本${PLAIN}"
    local tmp_script=$(mktemp)
    _CLEANUP_FILES+=("$tmp_script")

    if ! curl -fsSL --max-time 15 "$SCRIPT_URL" -o "$tmp_script" 2>/dev/null; then
        echo -e "${RED}下载失败。${PLAIN}"; return
    fi
    
    if [ ! -s "$tmp_script" ]; then
        echo -e "${RED}下载文件为空。${PLAIN}"; return
    fi

    # 简单版本校验
    local remote_ver=$(grep '^SCRIPT_VERSION=' "$tmp_script" | head -1 | cut -d'"' -f2)
    if [ "$remote_ver" == "$SCRIPT_VERSION" ]; then
        echo -e "${GREEN}已是最新 (v${SCRIPT_VERSION})。${PLAIN}"; return
    fi

    mv -f "$tmp_script" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    echo -e "${GREEN}更新完成 (v${remote_ver})! 请重新运行。${PLAIN}"
    exit 0
}

uninstall_script() {
    echo -e "${RED}!!! 危险操作警告 !!!${PLAIN}"
    read -p "确认彻底卸载 Xray 及所有配置? (输入 yes 确认): " cf
    cf=$(strip_cr "$cf")
    if [[ "${cf,,}" == "yes" ]]; then
       systemctl stop xray 2>/dev/null
       systemctl disable xray 2>/dev/null
       rm -f "$SYSTEMD_FILE"
       systemctl daemon-reload
       rm -rf "$XRAY_CONF_DIR" "$XRAY_BIN" "$DAT_DIR" /var/log/xray
       rm -f "$INSTALL_PATH"
       echo -e "${GREEN}卸载完成。${PLAIN}"
       exit 0
    fi
}

main_menu() {
    check_deps
    while true; do
        clear
        echo -e "${BLUE}================================================================${PLAIN}"
        echo -e "   Xray 多协议管理脚本 (v${SCRIPT_VERSION}) - 星辰大海复刻版"
        echo -e "${BLUE}================================================================${PLAIN}"
        
        local status="${RED}未运行${PLAIN}"
        if systemctl is-active --quiet xray; then
            local ver=$($XRAY_BIN version 2>/dev/null | head -1 | awk '{print $2}')
            status="${GREEN}✅ 运行中 ($ver)${PLAIN}"
        fi
        
        echo -e " 核心状态: $status"
        echo -e " 配置文件: $XRAY_CONF_FILE"
        echo -e "----------------------------------------------------------------"
        echo -e "  1. 安装 / 更新 Xray 核心"
        echo -e "  2. 添加 VLESS-Vision-Reality 节点 (⭐ 推荐)"
        echo -e "  3. 添加 Shadowsocks-2022 节点 (🚀 性能)"
        echo -e "  4. 查看节点配置 / 分享链接"
        echo -e "  5. 删除节点"
        echo -e "  6. 进阶配置 (链式代理 / 路由)"
        echo -e "  7. 更新脚本"
        echo -e "  8. 卸载脚本"
        echo -e "  0. 退出"
        echo -e "${BLUE}================================================================${PLAIN}"
        read -p "请输入选项: " choice
        
        case $choice in
            1) install_xray; read -p "按回车继续..." ;;
            2) add_reality; read -p "按回车继续..." ;;
            3) add_ss2022; read -p "按回车继续..." ;;
            4) 
                list_nodes
                read -p "输入节点 ID 查看详情 (0 返回): " nid
                nid=$(strip_cr "$nid")
                if [[ "$nid" =~ ^[0-9]+$ ]] && [ "$nid" -gt 0 ] && [ "$nid" -le "$_NODE_COUNT" ]; then
                    local target_tag
                    target_tag=$(get_node_tag_by_id "$nid")
                    [[ -n "$target_tag" ]] && show_node_info "$target_tag"
                fi
                read -p "按回车继续..."
                ;;
            5) delete_node; read -p "按回车继续..." ;;
            6) configure_advanced ;;
            7) update_script ;;
            8) uninstall_script ;;
            0) exit 0 ;;
            *) ;;
        esac
    done
}

# 入口
check_root
if [[ "${1:-}" == "install" ]]; then
    install_xray
else
    main_menu
fi