#!/bin/bash
#
# Xray 多协议管理脚本
#

# 注意: 不使用 set -euo pipefail, 交互式菜单脚本需要容错而非崩溃退出

# ==================== 全局变量 ====================
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[36m'
PLAIN='\033[0m'

SCRIPT_VERSION="1.0.0"
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
read_prompt() {
    local rc
    if read "$@"; then return 0; else rc=$?; fi
    if [[ "$rc" -ne 1 ]]; then
        echo "读取输入失败（退出码 ${rc}）。" >&2
        exit "$rc"
    fi
    echo
    echo "输入已结束，退出管理。"
    exit 0
}

strip_cr() { echo "${1//$'\r'/}"; }

fresh_script_url() {
    printf '%s?t=%s-%s' "$SCRIPT_URL" "$(date +%s)" "$$"
}

validate_script_candidate() {
    local file=$1
    local version
    [[ -s "$file" ]] || return 1
    head -n 1 "$file" | grep -qx '#!/bin/bash' || return 1
    grep -q '^SCRIPT_VERSION="' "$file" || return 1
    version=$(grep '^SCRIPT_VERSION=' "$file" | head -1 | cut -d'"' -f2)
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
        candidate_part=${candidate_parts[i]:-0}; current_part=${current_parts[i]:-0}
        ((10#$candidate_part < 10#$current_part)) && return 0
        ((10#$candidate_part > 10#$current_part)) && return 1
    done
    return 1
}

run_menu_action() {
    local label=$1
    shift
    local rc=0
    "$@" || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo -e "${RED}❌ ${label}失败（退出码 ${rc}）。服务日志: journalctl -u xray -n 30 --no-pager${PLAIN}" >&2
    fi
    return 0
}

# ==================== 基础检查 ====================
check_root() {
    [[ $EUID -ne 0 ]] && { echo -e "${RED}错误: 必须使用 root 权限运行。${PLAIN}"; exit 1; }
    if [ ! -f /etc/debian_version ]; then
        echo -e "${RED}错误：本脚本仅支持 Debian/Ubuntu 系统。${PLAIN}"
        exit 1
    fi
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
            if ! apt-get update; then
                echo -e "${YELLOW}警告: 部分 APT 软件源刷新失败；将使用现有索引继续安装依赖。请检查上方报错的软件源。${PLAIN}" >&2
            fi
            apt-get install -y "${deps[@]}" || true
        elif [ -f /etc/redhat-release ]; then
            yum install -y "${deps[@]}"
        elif [ -f /etc/alpine-release ]; then
            # Alpine: qrencode 命令在 libqrencode-tools 包中
            apk add curl wget unzip jq openssl libqrencode-tools
        fi
        # 验证关键依赖是否真正可用
        local failed=()
        for dep in "curl" "jq" "openssl"; do
            command -v "$dep" &>/dev/null || failed+=("$dep")
        done
        if [[ ${#failed[@]} -gt 0 ]]; then
            echo -e "${RED}依赖安装失败: ${failed[*]}，请手动安装后重试。${PLAIN}"
            exit 1
        fi
    fi
}

# ==================== 防火墙工具 ====================

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
        if command -v iptables-save >/dev/null 2>&1; then
            mkdir -p /etc/iptables 2>/dev/null || true
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    fi
}

close_port() {
    local port=$1 mode=${2:-both} proto rc=0 query_rc
    local protocols=(tcp udp)
    [[ "$mode" != tcp ]] || protocols=(tcp)
    if command -v ufw >/dev/null 2>&1; then
        ufw --force delete allow "$port" >/dev/null 2>&1 || rc=1
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || rc=1
        firewall-cmd --permanent --remove-port="${port}/udp" >/dev/null 2>&1 || rc=1
        firewall-cmd --reload >/dev/null 2>&1 || rc=1
    elif command -v iptables >/dev/null 2>&1; then
        for proto in "${protocols[@]}"; do
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
    
    local was_active=false
    systemctl is-active --quiet xray 2>/dev/null && was_active=true
    local binary_backup=""
    local binary_updated=false

    if [[ "$curr_ver" == "$latest_ver" ]]; then
        echo -e "${GREEN}当前已是最新版 ($curr_ver)，跳过安装。${PLAIN}"
    else
        echo -e "${YELLOW}正在安装 Xray $latest_ver ($arch)...${PLAIN}"
        local zip_url="https://github.com/XTLS/Xray-core/releases/download/${latest_tag}/Xray-linux-${arch}.zip"
        local tmp_file=$(mktemp)
        local tmp_dir=$(mktemp -d)
        _CLEANUP_FILES+=("$tmp_file" "$tmp_dir")
        
        if ! curl -L --max-time 120 -o "$tmp_file" --progress-bar "$zip_url"; then
            echo -e "${RED}下载失败。${PLAIN}"; return 1
        fi
        
        if ! unzip -q "$tmp_file" -d "$tmp_dir" || [[ ! -x "$tmp_dir/xray" ]]; then
            echo -e "${RED}安装包无效或缺少 Xray 二进制。${PLAIN}"
            return 1
        fi

        if [[ -f "$XRAY_BIN" ]]; then
            binary_backup=$(mktemp /tmp/xray_binary_backup.XXXXXX)
            _CLEANUP_FILES+=("$binary_backup")
            cp -p "$XRAY_BIN" "$binary_backup" || return 1
        fi

        systemctl stop xray 2>/dev/null || true
        local staged_bin="${XRAY_BIN}.new.$$"
        if ! install -m 755 "$tmp_dir/xray" "$staged_bin" || ! mv -f "$staged_bin" "$XRAY_BIN"; then
            rm -f "$staged_bin"
            if [[ -n "$binary_backup" ]]; then cp -p "$binary_backup" "$XRAY_BIN"; else rm -f "$XRAY_BIN"; fi
            [[ "$was_active" == "true" ]] && systemctl start xray 2>/dev/null || true
            echo -e "${RED}Xray 核心安装失败，已恢复旧版本。${PLAIN}"
            return 1
        fi
        binary_updated=true
        mv "$tmp_dir/geoip.dat" "$DAT_DIR/" 2>/dev/null || true
        mv "$tmp_dir/geosite.dat" "$DAT_DIR/" 2>/dev/null || true
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
    systemctl enable xray 2>/dev/null
    
    init_config_if_missing

    if [[ "$binary_updated" == "true" ]]; then
        local update_error=""
        update_error=$("$XRAY_BIN" run -test -c "$XRAY_CONF_FILE" 2>&1) || {
            echo -e "${RED}新 Xray 无法加载现有配置，正在回滚:${PLAIN}"
            echo "$update_error" | tail -5
            if [[ -n "$binary_backup" ]]; then cp -p "$binary_backup" "$XRAY_BIN"; else rm -f "$XRAY_BIN"; fi
            [[ "$was_active" == "true" ]] && systemctl start xray 2>/dev/null || true
            return 1
        }
        if [[ "$was_active" == "true" ]]; then
            if ! systemctl restart xray || ! systemctl is-active --quiet xray; then
                if [[ -n "$binary_backup" ]]; then cp -p "$binary_backup" "$XRAY_BIN"; else rm -f "$XRAY_BIN"; fi
                systemctl restart xray 2>/dev/null || true
                echo -e "${RED}新 Xray 启动失败，已回滚旧版本。${PLAIN}"
                return 1
            fi
        fi
        echo -e "${GREEN}Xray 核心更新成功。${PLAIN}"
    fi
    install_shortcut_cmd
}

install_shortcut_cmd() {
    if [[ "$(realpath "$0" 2>/dev/null)" == "$INSTALL_PATH" ]]; then return; fi
    
    # 优先从远程下载(防止管道运行时 $0 指向 /dev/fd/XX)
    local tmp_dl
    tmp_dl=$(mktemp "${INSTALL_PATH}.install.XXXXXX") || {
        echo -e "${RED}无法创建快捷命令安装临时文件。${PLAIN}" >&2
        return 1
    }
    _CLEANUP_FILES+=("$tmp_dl")
    if curl -fsSLo "$tmp_dl" --connect-timeout 8 --max-time 15 "$(fresh_script_url)" \
        && validate_script_candidate "$tmp_dl"; then
        if ! chmod 755 "$tmp_dl" || ! mv -f "$tmp_dl" "$INSTALL_PATH"; then
            echo -e "${RED}快捷命令安装失败，现有文件未被覆盖。${PLAIN}" >&2
            return 1
        fi
        echo -e "${GREEN}快捷命令 '$SHORTCUT_NAME' 已安装。${PLAIN}"
    elif [[ -f "$0" ]]; then
        # 降级: 本地复制
        if ! cp "$0" "$tmp_dl" || ! validate_script_candidate "$tmp_dl" \
            || ! chmod 755 "$tmp_dl" || ! mv -f "$tmp_dl" "$INSTALL_PATH"; then
            echo -e "${RED}快捷命令本地安装失败，现有文件未被覆盖。${PLAIN}" >&2
            return 1
        fi
        echo -e "${GREEN}快捷命令 '$SHORTCUT_NAME' 已安装 (本地)。${PLAIN}"
    else
        echo -e "${RED}快捷命令安装失败，现有文件未被覆盖。${PLAIN}" >&2
        return 1
    fi
}

init_config_if_missing() {
    if [[ ! -f "$XRAY_CONF_FILE" ]] || [[ ! -s "$XRAY_CONF_FILE" ]]; then
        cat > "$XRAY_CONF_FILE" <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/dev/null",
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

replace_xray_config() {
    local source=$1 stage
    stage=$(mktemp "${XRAY_CONF_FILE}.new.XXXXXX") || return 1
    if ! cp "$source" "$stage" || ! chmod 640 "$stage" || ! mv -f "$stage" "$XRAY_CONF_FILE"; then
        rm -f "$stage"
        return 1
    fi
}

safe_save_config() {
    local tmp_json=$1 backup="" test_output
    if ! jq . "$tmp_json" >/dev/null 2>&1; then
        echo -e "${RED}JSON 语法校验失败，未保存。${PLAIN}" >&2
        return 1
    fi
    if [[ -f "$XRAY_BIN" ]] && ! test_output=$("$XRAY_BIN" run -test -c "$tmp_json" 2>&1); then
        echo -e "${RED}Xray 配置校验失败，未保存。${PLAIN}" >&2
        printf '%s\n' "$test_output" | tail -5 >&2
        return 1
    fi
    if [[ -s "$XRAY_CONF_FILE" ]]; then
        backup=$(mktemp "${XRAY_CONF_FILE}.bak.XXXXXX") || {
            echo "无法创建配置备份，未保存。" >&2; return 1;
        }
        if ! cp -p "$XRAY_CONF_FILE" "$backup"; then
            rm -f "$backup"
            echo "配置备份失败，未保存。" >&2
            return 1
        fi
    fi
    if ! replace_xray_config "$tmp_json"; then
        echo "配置写入失败，现有配置未被替换。" >&2
        [[ -z "$backup" ]] || rm -f "$backup"
        return 1
    fi
    if systemctl restart xray && sleep 1 && systemctl is-active --quiet xray; then
        echo -e "${GREEN}配置已应用，服务已重启。${PLAIN}"
        [[ -z "$backup" ]] || rm -f "$backup" || echo "配置已生效，但旧备份清理失败: $backup" >&2
        return 0
    fi
    echo -e "${RED}Xray 重启失败，正在回滚...${PLAIN}" >&2
    journalctl -u xray --no-pager -n 5 >&2 || true
    if [[ -z "$backup" ]]; then
        echo "没有旧配置可回滚，当前配置已保留供排查。" >&2
        return 1
    fi
    if ! replace_xray_config "$backup"; then
        echo "配置恢复失败，恢复备份已保留: $backup" >&2
        return 1
    fi
    if systemctl restart xray && sleep 1 && systemctl is-active --quiet xray; then
        echo "已回滚到上一份配置，服务已恢复。" >&2
        rm -f "$backup" || echo "恢复成功，但备份清理失败: $backup" >&2
    else
        echo "旧配置已恢复，但服务启动失败；备份已保留: $backup" >&2
    fi
    return 1
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
    
    read_prompt -p "请输入端口 [默认443]: " port
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
    
    read_prompt -p "请选择目标域名 [1]: " sni_idx
    sni_idx=$(strip_cr "$sni_idx")
    [[ -z "$sni_idx" ]] && sni_idx=1
    
    local target_dest=""
    local target_sni=""
    
    if [[ "$sni_idx" =~ ^[0-9]+$ ]] && [ "$sni_idx" -ge 1 ] && [ "$sni_idx" -le "${#valid_snis[@]}" ]; then
        target_sni="${valid_snis[$((sni_idx-1))]}"
    else
        read_prompt -p "请输入域名 (如 www.apple.com): " target_sni
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
    
    local chain_setting
    chain_setting=$(ask_chain_proxy) || return 1
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
        open_port "$port"
        show_node_info "$tag"
    else
        rm -f "$tmp"
        return 1
    fi
}

add_ss2022() {
    echo -e "${BLUE}>>> 添加 Shadowsocks-2022 节点${PLAIN}"
    local port=$(get_random_port)
    read_prompt -p "请输入端口 [随机 $port]: " input_port
    input_port=$(strip_cr "$input_port")
    [[ -n "$input_port" ]] && port=$input_port
    if ! is_port_available "$port"; then return; fi
    
    local key=$(openssl rand -base64 16)
    local tag="ss_$port"
    
    local chain_setting
    chain_setting=$(ask_chain_proxy) || return 1
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
        open_port "$port"
        show_node_info "$tag"
    else
        rm -f "$tmp"
        return 1
    fi
}

# ==================== 进阶功能：链式代理与路由 ====================

ask_chain_proxy() {
    local has_chain=$(jq '.outbounds[] | select(.tag=="chain_proxy")' "$XRAY_CONF_FILE")
    if [[ -z "$has_chain" ]]; then echo ""; return; fi
    
    echo -e "${YELLOW}进阶: 是否为此节点启用 SOCKS5 链式转发 (解锁/分流)? [y/N]${PLAIN}" >&2
    if ! read -rp "选择: " sel; then
        echo "输入已结束，未创建节点。" >&2
        return 1
    fi
    sel=$(strip_cr "$sel")
    if [[ "${sel,,}" == y ]]; then echo yes; fi
    return 0
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
        read_prompt -p "请选择: " choice
        choice=$(strip_cr "$choice")
        
        case $choice in
            1) 
                read_prompt -p "请输入上游 SOCKS5 地址 (如 127.0.0.1:40000): " addr
                addr=$(strip_cr "$addr")
                if [[ -z "$addr" ]]; then
                    local tmp=$(mktemp /tmp/xray_XXXXXX.json)
                    _CLEANUP_FILES+=("$tmp")
                    # 同时删除 outbound 和引用它的路由规则
                    jq 'del(.outbounds[] | select(.tag=="chain_proxy")) |
                        .routing.rules |= [.[] | select(.outboundTag != "chain_proxy")]
                    ' "$XRAY_CONF_FILE" > "$tmp"
                    if ! safe_save_config "$tmp"; then read_prompt -rp "配置未应用，按回车继续..."; fi
                    rm -f "$tmp"
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
                    if ! safe_save_config "$tmp"; then read_prompt -rp "配置未应用，按回车继续..."; fi
                    rm -f "$tmp"
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
                if ! safe_save_config "$tmp"; then read_prompt -rp "配置未应用，按回车继续..."; fi
                rm -f "$tmp"
                sleep 1
                ;;
            0) return ;;
            *) echo "无效选项，请输入 0-2。"; read_prompt -rp "按回车继续..." ;;
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

# 用 OpenSSL 从配置中的 X25519 私钥推导分享链接所需的公钥。
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

urlencode() {
    local LC_ALL=C input="$1" output="" char encoded byte i
    for ((i=0; i<${#input}; i++)); do
        char=${input:i:1}
        case "$char" in
            [a-zA-Z0-9.~_-]) output+="$char" ;;
            *)
                printf -v byte '%d' "'$char"
                printf -v encoded '%%%02X' "$((byte & 255))"
                output+="$encoded"
                ;;
        esac
    done
    printf '%s' "$output"
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
        # 优先读取 publicKey；未保存公钥时从 privateKey 推导。
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
        # SIP022: Shadowsocks 2022 userinfo 使用明文方法名和百分号编码密码。
        local link="ss://$(urlencode "$method"):$(urlencode "$pass")@${display_ip}:${port}#$(urlencode "$tag")"
        
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
    read_prompt -p "请输入要删除的节点 ID (0 返回): " id
    id=$(strip_cr "$id")
    if [[ "$id" =~ ^[0-9]+$ ]] && [ "$id" -gt 0 ] && [ "$id" -le "$_NODE_COUNT" ]; then
        local target_tag
        target_tag=$(get_node_tag_by_id "$id")
        
        if [[ -n "$target_tag" ]]; then
            echo -e "${YELLOW}正在删除节点: $target_tag ...${PLAIN}"
            # 先取端口号 (删除后就拿不到了)
            local del_port
            del_port=$(jq -r --arg t "$target_tag" '.inbounds[] | select(.tag==$t) | .port' "$XRAY_CONF_FILE" 2>/dev/null)
            local tmp=$(mktemp /tmp/xray_XXXXXX.json)
            _CLEANUP_FILES+=("$tmp")
            jq --arg t "$target_tag" 'del(.inbounds[] | select(.tag==$t))' "$XRAY_CONF_FILE" > "$tmp"
            jq --arg t "$target_tag" 'del(.routing.rules[] | select(.inboundTag and (.inboundTag[] == $t)))' "$tmp" > "${tmp}.1" && mv "${tmp}.1" "$tmp"
            if safe_save_config "$tmp"; then
                rm -f "$tmp"
                if [[ -n "$del_port" && "$del_port" != null ]] && ! close_port "$del_port"; then
                    echo "节点配置已删除，但端口防火墙清理失败。" >&2
                    return 1
                fi
            else
                rm -f "$tmp"
                return 1
            fi
        fi
    fi
}

# ==================== 主菜单 & 更新 ====================

update_script() {
    echo -e "\n ${BLUE}>>> 更新管理脚本${PLAIN}"
    local tmp_script
    tmp_script=$(mktemp "${INSTALL_PATH}.update.XXXXXX") || {
        echo -e "${RED}无法创建更新临时文件，现有脚本未被覆盖。${PLAIN}" >&2
        return 1
    }
    _CLEANUP_FILES+=("$tmp_script")

    if ! curl -fsSLo "$tmp_script" --connect-timeout 8 --max-time 20 "$(fresh_script_url)"; then
        echo -e "${RED}下载失败，现有脚本未被覆盖。${PLAIN}"; return 1
    fi
    if ! validate_script_candidate "$tmp_script"; then
        echo -e "${RED}远程脚本格式或 Bash 语法校验失败，现有脚本未被覆盖。${PLAIN}"; return 1
    fi

    # 简单版本校验
    local remote_ver=$(grep '^SCRIPT_VERSION=' "$tmp_script" | head -1 | cut -d'"' -f2)
    if version_is_older "$remote_ver" "$SCRIPT_VERSION"; then
        echo -e "${RED}拒绝降级：远端 v${remote_ver} 低于当前 v${SCRIPT_VERSION}。${PLAIN}" >&2
        return 1
    fi
    if [ "$remote_ver" == "$SCRIPT_VERSION" ] && cmp -s "$tmp_script" "$INSTALL_PATH"; then
        echo -e "${GREEN}已是最新 (v${SCRIPT_VERSION})。${PLAIN}"; return
    fi

    if [ "$remote_ver" == "$SCRIPT_VERSION" ]; then
        echo -e "${YELLOW}检测到同版本内容修订，将继续更新。${PLAIN}"
    fi

    if ! chmod 755 "$tmp_script" || ! mv -f "$tmp_script" "$INSTALL_PATH"; then
        echo -e "${RED}替换脚本失败，现有脚本保持不变。${PLAIN}" >&2
        return 1
    fi
    echo -e "${GREEN}更新完成 (v${remote_ver})! 正在重新加载...${PLAIN}"
    exec "$INSTALL_PATH"
}

uninstall_script() {
    echo -e "${RED}!!! 危险操作警告 !!!${PLAIN}"
    local cf state ports p
    read_prompt -rp "确认彻底卸载 Xray 及所有配置? (输入 yes 确认): " cf
    cf=$(strip_cr "$cf")
    [[ "${cf,,}" == yes ]] || { echo "已取消。"; return 0; }
    if ! systemctl stop xray; then
        state=$(systemctl show xray -p LoadState -p ActiveState 2>/dev/null) || state=""
        if ! grep -Fqx 'LoadState=not-found' <<< "$state" || ! grep -Fqx 'ActiveState=inactive' <<< "$state"; then
            echo "Xray 停止失败，文件和防火墙规则已保留。" >&2
            return 1
        fi
    fi
    if systemctl is-active --quiet xray; then
        echo "Xray 仍在运行，已停止卸载。" >&2
        return 1
    fi
    if [[ -f "$XRAY_CONF_FILE" ]]; then
        ports=$(jq -r '.inbounds[]?.port // empty' "$XRAY_CONF_FILE") || {
            echo "无法读取端口配置，已停止卸载。" >&2; return 1;
        }
        for p in $ports; do
            close_port "$p" || { echo "端口 $p 的防火墙清理失败，文件已保留。" >&2; return 1; }
        done
    fi
    if [[ -f "$SYSTEMD_FILE" ]]; then
        systemctl disable xray || { echo "取消开机启动失败，文件已保留。" >&2; return 1; }
        rm -f "$SYSTEMD_FILE" || { echo "服务文件删除失败，卸载未完成。" >&2; return 1; }
        systemctl daemon-reload || { echo "服务配置重载失败，卸载未完成。" >&2; return 1; }
    fi
    if ! rm -rf "$XRAY_CONF_DIR" "$XRAY_BIN" "$DAT_DIR" /var/log/xray; then
        echo "Xray 文件删除失败，卸载未完成，请排查后重试。" >&2
        return 1
    fi
    rm -f "$INSTALL_PATH" || { echo "快捷命令删除失败，卸载未完成。" >&2; return 1; }
    echo -e "${GREEN}卸载完成。${PLAIN}"
    exit 0
}

main_menu() {
    check_deps
    while true; do
        clear
        echo -e "${BLUE}================================================================${PLAIN}"
        echo -e "   Xray 多协议管理脚本 (v${SCRIPT_VERSION})"
        echo -e "${BLUE}================================================================${PLAIN}"
        
        local status="${RED}未运行${PLAIN}"
        if systemctl is-active --quiet xray; then
            local ver output
            output=$("$XRAY_BIN" version 2>/dev/null) || output=""
            ver=$(printf '%s\n' "$output" | head -n 1 | awk '{print $2}')
            ver=${ver:-?}
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
        read_prompt -p "请输入选项: " choice
        choice=$(strip_cr "$choice")
        
        case $choice in
            1) run_menu_action "安装或更新 Xray" install_xray; read_prompt -p "按回车继续..." ;;
            2) run_menu_action "添加 Reality 节点" add_reality; read_prompt -p "按回车继续..." ;;
            3) run_menu_action "添加 Shadowsocks 节点" add_ss2022; read_prompt -p "按回车继续..." ;;
            4) 
                list_nodes
                read_prompt -p "输入节点 ID 查看详情 (0 返回): " nid
                nid=$(strip_cr "$nid")
                if [[ "$nid" =~ ^[0-9]+$ ]] && [ "$nid" -gt 0 ] && [ "$nid" -le "$_NODE_COUNT" ]; then
                    local target_tag
                    target_tag=$(get_node_tag_by_id "$nid")
                    [[ -n "$target_tag" ]] && show_node_info "$target_tag"
                fi
                read_prompt -p "按回车继续..."
                ;;
            5) run_menu_action "删除节点" delete_node; read_prompt -p "按回车继续..." ;;
            6) configure_advanced ;;
            7) run_menu_action "更新 x-sb 管理脚本" update_script; read_prompt -rp "按回车继续..." ;;
            8) run_menu_action "卸载 Xray" uninstall_script; read_prompt -rp "按回车继续..." ;;
            0) exit 0 ;;
            *) echo -e "${RED}无效选项，请输入 0-8。${PLAIN}"; read_prompt -rp "按回车继续..." ;;
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
