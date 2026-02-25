#!/bin/bash
# sb (sing-box edition) - multi-protocol manager
# - VLESS Vision REALITY (TCP)
# - Shadowsocks 2022
# - Optional chain SOCKS5 outbound + per-inbound routing
# - Safe config check + rollback
# - Script self-update (GitHub raw)

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[36m'
PLAIN='\033[0m'

SCRIPT_VERSION="1.0.3"
SHORTCUT_NAME="sb"
INSTALL_PATH="/usr/local/bin/${SHORTCUT_NAME}"

# ✅ your GitHub raw
SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/sb.sh"

SB_BIN="/usr/local/bin/sing-box"
SB_CONF_DIR="/usr/local/etc/sing-box"
SB_CONF_FILE="${SB_CONF_DIR}/config.json"
SYSTEMD_FILE="/etc/systemd/system/sing-box.service"
WORK_DIR="/var/lib/sing-box"

# ✅ store metadata (pbk etc.) OUTSIDE sing-box config to avoid schema/strict parsing issues
META_FILE="${SB_CONF_DIR}/nodes_meta.json"

# If not empty, force install this sing-box version (without v prefix), e.g. "1.12.22"
PINNED_SB_VERSION=""

SNI_LIST=(
  "addons.mozilla.org"
  "www.microsoft.com"
  "www.amazon.com"
  "swdist.apple.com"
  "updates.cdn-apple.com"
)

_CLEANUP_FILES=()
cleanup() { for f in "${_CLEANUP_FILES[@]+"${_CLEANUP_FILES[@]}"}"; do rm -rf "$f" 2>/dev/null; done; }
trap cleanup EXIT INT TERM

strip_cr() { echo "${1//$'\r'/}"; }

check_root() {
  [[ $EUID -ne 0 ]] && { echo -e "${RED}错误: 必须使用 root 权限运行。${PLAIN}"; exit 1; }
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then echo "apt"; return; fi
  if command -v yum >/dev/null 2>&1; then echo "yum"; return; fi
  if command -v dnf >/dev/null 2>&1; then echo "dnf"; return; fi
  if command -v apk >/dev/null 2>&1; then echo "apk"; return; fi
  echo "unknown"
}

check_deps() {
  local deps=("curl" "tar" "jq" "openssl" "qrencode" "ss")
  local missing=()
  for d in "${deps[@]}"; do
    command -v "$d" >/dev/null 2>&1 || missing+=("$d")
  done

  if [[ ${#missing[@]} -eq 0 ]]; then return; fi

  echo -e "${YELLOW}缺少依赖: ${missing[*]}，正在安装...${PLAIN}"
  local pm
  pm=$(detect_pkg_mgr)

  case "$pm" in
    apt)
      apt-get update -y
      apt-get install -y curl tar jq openssl qrencode iproute2
      ;;
    yum)
      yum install -y curl tar jq openssl qrencode iproute
      ;;
    dnf)
      dnf install -y curl tar jq openssl qrencode iproute
      ;;
    apk)
      apk add --no-cache curl tar jq openssl libqrencode-tools iproute2
      ;;
    *)
      echo -e "${RED}无法识别包管理器，请手动安装: curl tar jq openssl qrencode iproute2${PLAIN}"
      ;;
  esac

  local hard=("curl" "tar" "jq" "openssl")
  local failed=()
  for d in "${hard[@]}"; do command -v "$d" >/dev/null 2>&1 || failed+=("$d"); done
  if [[ ${#failed[@]} -gt 0 ]]; then
    echo -e "${RED}依赖安装失败: ${failed[*]}，请手动安装后重试。${PLAIN}"
    exit 1
  fi
}

map_arch_sb() {
  case $(uname -m) in
    x86_64) echo "amd64" ;;
    aarch64|armv8*) echo "arm64" ;;
    *) echo -e "${RED}不支持的架构: $(uname -m)${PLAIN}"; exit 1 ;;
  esac
}

open_port() {
  local port=$1
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$port" >/dev/null 2>&1
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1
    firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
  elif command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
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

get_current_sb_ver() {
  [[ -x "$SB_BIN" ]] || { echo "none"; return; }
  "$SB_BIN" version 2>/dev/null | head -1 | grep -Eo 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | tr -d 'v' || echo "unknown"
}

get_latest_sb_tag() {
  local tag=""
  tag=$(curl -sL --max-time 8 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r .tag_name 2>/dev/null)
  if [[ -n "$tag" && "$tag" != "null" ]]; then
    echo "$tag"
    return 0
  fi

  local final
  final=$(curl -sI --max-time 8 -o /dev/null -w "%{url_effective}" "https://github.com/SagerNet/sing-box/releases/latest")
  tag="${final##*/}"
  if [[ "$tag" == v* ]]; then
    echo "$tag"
    return 0
  fi
  return 1
}

init_meta_if_missing() {
  mkdir -p "$SB_CONF_DIR" "$WORK_DIR"
  if [[ ! -f "$META_FILE" ]] || [[ ! -s "$META_FILE" ]]; then
    echo '{}' > "$META_FILE"
    chmod 600 "$META_FILE"
  fi
}

# Ensure route.rules contains a leading {"action":"sniff"} (only once)
ensure_route_sniff_rule() {
  local json_file=$1
  jq '
    .route.rules = (
      if ((.route.rules // []) | any(.action? == "sniff")) then
        (.route.rules // [])
      else
        ([{"action":"sniff"}] + (.route.rules // []))
      end
    )
  ' "$json_file" > "${json_file}.sn" && mv "${json_file}.sn" "$json_file"
}

init_config_if_missing() {
  mkdir -p "$SB_CONF_DIR" "$WORK_DIR"
  if [[ ! -f "$SB_CONF_FILE" ]] || [[ ! -s "$SB_CONF_FILE" ]]; then
    cat > "$SB_CONF_FILE" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block" }
  ],
  "route": {
    "final": "direct",
    "rules": [
      { "action": "sniff" },
      { "ip_is_private": true, "action": "route", "outbound": "block" }
    ]
  }
}
EOF
    chmod 640 "$SB_CONF_FILE"
  else
    # If config exists, still ensure sniff rule exists (non-destructive)
    local tmp
    tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json)
    _CLEANUP_FILES+=("$tmp")
    cp "$SB_CONF_FILE" "$tmp"
    ensure_route_sniff_rule "$tmp"
    # write back only if valid JSON
    if jq . "$tmp" >/dev/null 2>&1; then
      cp "$tmp" "$SB_CONF_FILE"
      chmod 640 "$SB_CONF_FILE"
    fi
  fi
}

write_systemd() {
  cat > "$SYSTEMD_FILE" <<EOF
[Unit]
Description=sing-box Service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=$WORK_DIR
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$SB_BIN run -c $SB_CONF_FILE
Restart=on-failure
RestartSec=10
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable sing-box >/dev/null 2>&1 || true
}

safe_save_config() {
  local tmp_json=$1

  if ! jq . "$tmp_json" >/dev/null 2>&1; then
    echo -e "${RED}JSON 语法校验失败，未保存。${PLAIN}"
    return 1
  fi

  if [[ -x "$SB_BIN" ]]; then
    local out
    out=$("$SB_BIN" check -c "$tmp_json" 2>&1)
    if [[ $? -ne 0 ]]; then
      echo -e "${RED}sing-box 配置校验失败，未保存。错误信息:${PLAIN}"
      echo "$out" | tail -12
      return 1
    fi
  fi

  local backup=""
  if [[ -f "$SB_CONF_FILE" ]] && [[ -s "$SB_CONF_FILE" ]]; then
    backup="${SB_CONF_FILE}.bak"
    cp "$SB_CONF_FILE" "$backup"
  fi

  cp "$tmp_json" "$SB_CONF_FILE"
  chmod 640 "$SB_CONF_FILE"

  systemctl restart sing-box >/dev/null 2>&1 || true
  sleep 1

  if systemctl is-active --quiet sing-box; then
    echo -e "${GREEN}配置已应用，服务已重启。${PLAIN}"
    rm -f "$backup"
    return 0
  fi

  echo -e "${RED}sing-box 启动失败! 正在回滚...${PLAIN}"
  journalctl -u sing-box --no-pager -n 20 2>/dev/null | tail -20

  if [[ -n "$backup" && -f "$backup" ]]; then
    cp "$backup" "$SB_CONF_FILE"
    systemctl restart sing-box >/dev/null 2>&1 || true
    sleep 1
    if systemctl is-active --quiet sing-box; then
      echo -e "${YELLOW}已回滚到上一份有效配置，服务已恢复。${PLAIN}"
    else
      echo -e "${RED}回滚后仍无法启动，请手动检查: journalctl -u sing-box -n 80${PLAIN}"
    fi
    rm -f "$backup"
  fi
  return 1
}

install_shortcut_cmd() {
  if [[ "$(realpath "$0" 2>/dev/null)" == "$INSTALL_PATH" ]]; then return; fi
  cp "$0" "$INSTALL_PATH" 2>/dev/null && chmod +x "$INSTALL_PATH" && \
    echo -e "${GREEN}快捷命令 '${SHORTCUT_NAME}' 已安装到 ${INSTALL_PATH}${PLAIN}"
}

install_singbox() {
  echo -e "${BLUE}>>> 安装/更新 sing-box 核心...${PLAIN}"
  init_meta_if_missing
  init_config_if_missing

  local arch
  arch=$(map_arch_sb)

  local latest_tag=""
  local latest_ver=""

  if [[ -n "$PINNED_SB_VERSION" ]]; then
    latest_ver="$PINNED_SB_VERSION"
    latest_tag="v${PINNED_SB_VERSION}"
    echo -e "${YELLOW}使用固定版本: ${latest_tag}${PLAIN}"
  else
    latest_tag=$(get_latest_sb_tag) || true
    if [[ -z "$latest_tag" ]]; then
      echo -e "${RED}无法获取 sing-box 最新版本（API/重定向都失败）。${PLAIN}"
      echo -e "${YELLOW}你可以在脚本里设置 PINNED_SB_VERSION=\"x.y.z\" 后重试。${PLAIN}"
      return 1
    fi
    latest_ver="${latest_tag#v}"
  fi

  local curr_ver
  curr_ver=$(get_current_sb_ver)

  if [[ "$curr_ver" == "$latest_ver" ]]; then
    echo -e "${GREEN}当前已是最新版 (${curr_ver})，跳过更新。${PLAIN}"
    write_systemd
    systemctl restart sing-box >/dev/null 2>&1 || true
    install_shortcut_cmd
    return 0
  fi

  echo -e "${YELLOW}正在下载 sing-box ${latest_ver} (${arch})...${PLAIN}"
  local url="https://github.com/SagerNet/sing-box/releases/download/${latest_tag}/sing-box-${latest_ver}-linux-${arch}.tar.gz"
  local tmp_tgz tmp_dir
  tmp_tgz=$(mktemp /tmp/sb_XXXXXX.tgz)
  tmp_dir=$(mktemp -d /tmp/sb_XXXXXX.dir)
  _CLEANUP_FILES+=("$tmp_tgz" "$tmp_dir")

  if ! curl -L --max-time 120 --progress-bar "${url}?t=$(date +%s)" -o "$tmp_tgz"; then
    echo -e "${RED}下载失败：${url}${PLAIN}"
    return 1
  fi

  if ! tar -xzf "$tmp_tgz" -C "$tmp_dir"; then
    echo -e "${RED}解压失败。${PLAIN}"
    return 1
  fi

  local extracted
  extracted=$(find "$tmp_dir" -type f -name "sing-box" | head -1)
  if [[ -z "$extracted" ]]; then
    echo -e "${RED}未找到 sing-box 可执行文件。${PLAIN}"
    return 1
  fi

  systemctl stop sing-box >/dev/null 2>&1 || true
  install -m 755 "$extracted" "$SB_BIN"

  write_systemd
  systemctl restart sing-box >/dev/null 2>&1 || true

  if systemctl is-active --quiet sing-box; then
    echo -e "${GREEN}sing-box 已更新到 ${latest_ver} 并启动成功。${PLAIN}"
  else
    echo -e "${RED}sing-box 启动失败，请查看：journalctl -u sing-box -n 80${PLAIN}"
  fi

  install_shortcut_cmd
}

gen_uuid() {
  if [[ -r /proc/sys/kernel/random/uuid ]]; then cat /proc/sys/kernel/random/uuid; return; fi
  openssl rand -hex 16 | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/'
}

get_random_port() {
  local port
  while true; do
    port=$((RANDOM % 55000 + 10000))
    if is_port_available "$port"; then echo "$port"; return; fi
  done
}

is_port_available() {
  local port=$1
  if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo -e "${RED}端口号无效 (1-65535)。${PLAIN}"
    return 1
  fi
  if ss -tuln | grep -q ":$port "; then
    echo -e "${RED}端口 $port 已被系统占用。${PLAIN}"
    return 1
  fi
  if [[ -f "$SB_CONF_FILE" ]]; then
    local existing
    existing=$(jq -r '.inbounds[]?.listen_port // empty' "$SB_CONF_FILE" 2>/dev/null)
    if echo "$existing" | grep -q "^${port}$"; then
      echo -e "${RED}端口 $port 已在 sing-box 配置中使用。${PLAIN}"
      return 1
    fi
  fi
  return 0
}

pick_sni() {
  echo -e "${YELLOW}测试 SNI 连通性 (仅用于挑选域名)...${PLAIN}" >&2
  local valid=()
  for sni in "${SNI_LIST[@]}"; do
    if curl -m 3 -sI "https://${sni}" >/dev/null 2>&1; then
      valid+=("$sni")
      echo -e " ${#valid[@]}. ${sni}  ${GREEN}[OK]${PLAIN}" >&2
    else
      echo -e "    ${sni}  ${RED}[FAIL]${PLAIN}" >&2
    fi
  done
  local manual=$(( ${#valid[@]} + 1 ))
  echo -e " ${manual}. 手动输入" >&2

  read -p "请选择 [1]: " idx
  idx=$(strip_cr "$idx")
  [[ -z "$idx" ]] && idx=1

  local target=""
  if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "${#valid[@]}" ]; then
    target="${valid[$((idx-1))]}"
  else
    read -p "请输入域名 (如 www.apple.com): " target
    target=$(strip_cr "$target")
  fi
  [[ -z "$target" ]] && return 1
  echo "$target"
}

gen_reality_keypair() {
  [[ -x "$SB_BIN" ]] || return 1
  "$SB_BIN" generate reality-keypair 2>/dev/null
}

ask_chain_proxy() {
  local has
  has=$(jq -r '.outbounds[]? | select(.tag=="chain_proxy") | .tag' "$SB_CONF_FILE" 2>/dev/null)
  [[ -z "$has" ]] && { echo ""; return; }
  echo -e "${YELLOW}是否为此节点启用 SOCKS5 链式转发? [y/N]${PLAIN}" >&2
  read -p "选择: " sel
  sel=$(strip_cr "$sel")
  [[ "${sel,,}" == "y" ]] && echo "yes" || echo ""
}

apply_chain_routing() {
  local json_file=$1
  local inbound_tag=$2
  # Ensure sniff rule exists (recommended approach)
  ensure_route_sniff_rule "$json_file"
  jq --arg itag "$inbound_tag" '
    .route.rules = ([{
      "inbound": [$itag],
      "action": "route",
      "outbound": "chain_proxy"
    }] + (.route.rules // []))
  ' "$json_file" > "${json_file}.r" && mv "${json_file}.r" "$json_file"
}

# ---- metadata helpers (pbk storage) ----
meta_set_pubkey() {
  local tag=$1
  local pubk=$2
  init_meta_if_missing
  local tmp
  tmp=$(mktemp /tmp/sb_meta.XXXXXX.json)
  _CLEANUP_FILES+=("$tmp")
  jq --arg t "$tag" --arg pk "$pubk" '
    .[$t] = (.[$t] // {}) | .[$t].public_key = $pk
  ' "$META_FILE" > "$tmp" && mv "$tmp" "$META_FILE"
  chmod 600 "$META_FILE"
}

meta_get_pubkey() {
  local tag=$1
  [[ -f "$META_FILE" ]] || { echo ""; return; }
  jq -r --arg t "$tag" '.[$t].public_key // empty' "$META_FILE" 2>/dev/null
}

meta_del_tag() {
  local tag=$1
  [[ -f "$META_FILE" ]] || return
  local tmp
  tmp=$(mktemp /tmp/sb_meta.XXXXXX.json)
  _CLEANUP_FILES+=("$tmp")
  jq --arg t "$tag" 'del(.[$t])' "$META_FILE" > "$tmp" && mv "$tmp" "$META_FILE"
  chmod 600 "$META_FILE"
}

get_public_ip() {
  local ip=""
  for url in "https://api.ipify.org" "https://ip.sb" "https://checkip.amazonaws.com"; do
    ip=$(curl -4s --max-time 3 "$url" 2>/dev/null) && [[ -n "$ip" ]] && break
  done
  if [[ -z "$ip" ]]; then
    for url in "https://api64.ipify.org" "https://ip.sb"; do
      ip=$(curl -6s --max-time 3 "$url" 2>/dev/null) && [[ -n "$ip" ]] && break
    done
  fi
  [[ -z "$ip" ]] && ip="YOUR_IP"
  echo "$ip"
}

show_node_info() {
  local tag=$1
  local ip; ip=$(get_public_ip)
  local display_ip="$ip"
  [[ "$ip" == *:* ]] && display_ip="[$ip]"

  local node; node=$(jq -c --arg t "$tag" '.inbounds[] | select(.tag==$t)' "$SB_CONF_FILE" 2>/dev/null)
  [[ -z "$node" ]] && { echo -e "${RED}未找到节点: $tag${PLAIN}"; return; }

  local port proto
  port=$(echo "$node" | jq -r '.listen_port')
  proto=$(echo "$node" | jq -r '.type')

  echo -e "\n${BLUE}--- 节点详情: ${tag} ---${PLAIN}"
  echo -e "地址: ${ip}"
  echo -e "端口: ${port}"
  echo -e "协议: ${proto}"

  if [[ "$proto" == "vless" ]]; then
    local uuid flow sni sid pubk
    uuid=$(echo "$node" | jq -r '.users[0].uuid')
    flow=$(echo "$node" | jq -r '.users[0].flow')
    sni=$(echo "$node" | jq -r '.tls.reality.handshake.server')
    sid=$(echo "$node" | jq -r '.tls.reality.short_id[0]')
    pubk=$(meta_get_pubkey "$tag")

    echo -e "UUID: ${uuid}"
    echo -e "Flow: ${flow}"
    echo -e "SNI : ${sni}"
    echo -e "SID : ${sid}"
    echo -e "PBK : ${pubk:-<未保存>}"

    if [[ -n "$pubk" ]]; then
      local link="vless://${uuid}@${display_ip}:${port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=chrome&pbk=${pubk}&sid=${sid}&type=tcp&headerType=none#${tag}"
      echo -e "\n${GREEN}>>> 分享链接:${PLAIN}\n${link}"
      if command -v qrencode >/dev/null 2>&1; then
        echo -e "\n${YELLOW}>>> 二维码:${PLAIN}"
        qrencode -t ANSIUTF8 "$link"
      fi
    else
      echo -e "${YELLOW}提示：该节点未在 ${META_FILE} 中找到 public_key(pbK)，无法生成完整 vless:// 链接。${PLAIN}"
    fi

  elif [[ "$proto" == "shadowsocks" ]]; then
    local method pass raw link
    method=$(echo "$node" | jq -r '.method')
    pass=$(echo "$node" | jq -r '.password')
    raw="${method}:${pass}"
    link="ss://$(echo -n "$raw" | base64 | tr -d '\n')@${display_ip}:${port}#${tag}"
    echo -e "Method: ${method}"
    echo -e "Pass  : ${pass}"
    echo -e "\n${GREEN}>>> 分享链接:${PLAIN}\n${link}"
    if command -v qrencode >/dev/null 2>&1; then
      echo -e "\n${YELLOW}>>> 二维码:${PLAIN}"
      qrencode -t ANSIUTF8 "$link"
    fi
  fi
  echo
}

add_reality() {
  echo -e "${BLUE}>>> 添加 VLESS-Vision-REALITY 节点${PLAIN}"
  [[ -x "$SB_BIN" ]] || { echo -e "${RED}未安装 sing-box，请先选择菜单 1 安装。${PLAIN}"; return; }

  read -p "请输入端口 [默认443]: " port
  port=$(strip_cr "$port")
  [[ -z "$port" ]] && port=443
  is_port_available "$port" || return

  local sni; sni=$(pick_sni) || { echo -e "${RED}未选择有效域名。${PLAIN}"; return; }
  local uuid; uuid=$(gen_uuid)

  local keypair; keypair=$(gen_reality_keypair)
  [[ -z "$keypair" ]] && { echo -e "${RED}生成 Reality keypair 失败。${PLAIN}"; return; }

  local privk pubk
  privk=$(echo "$keypair" | awk -F': *' 'tolower($1)~/(privatekey|private key)/{print $2}' | head -1 | tr -d '\r" ')
  pubk=$(echo "$keypair" | awk -F': *' 'tolower($1)~/(publickey|public key)/{print $2}' | head -1 | tr -d '\r" ')
  [[ -z "$privk" || -z "$pubk" ]] && { echo -e "${RED}解析 Reality keypair 失败。${PLAIN}"; echo "$keypair"; return; }

  local sid; sid=$(openssl rand -hex 4)
  local tag="reality_${port}"

  local chain; chain=$(ask_chain_proxy)

  local tmp; tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json)
  _CLEANUP_FILES+=("$tmp")
  cp "$SB_CONF_FILE" "$tmp"

  # ensure sniff action exists globally
  ensure_route_sniff_rule "$tmp"

  jq --arg tag "$tag" --arg port "$port" --arg uuid "$uuid" --arg sni "$sni" --arg privk "$privk" --arg sid "$sid" '
    .inbounds += [{
      "type": "vless",
      "tag": $tag,
      "listen": "::",
      "listen_port": ($port|tonumber),
      "users": [{
        "uuid": $uuid,
        "flow": "xtls-rprx-vision"
      }],
      "tls": {
        "enabled": true,
        "server_name": $sni,
        "reality": {
          "enabled": true,
          "handshake": { "server": $sni, "server_port": 443 },
          "private_key": $privk,
          "short_id": [$sid]
        }
      }
    }]
  ' "$tmp" > "${tmp}.1" && mv "${tmp}.1" "$tmp"

  if [[ -n "$chain" ]]; then
    apply_chain_routing "$tmp" "$tag"
  fi

  if safe_save_config "$tmp"; then
    rm -f "$tmp"
    meta_set_pubkey "$tag" "$pubk"
    open_port "$port"
    show_node_info "$tag"
  else
    rm -f "$tmp"
  fi
}

add_ss2022() {
  echo -e "${BLUE}>>> 添加 Shadowsocks-2022 节点${PLAIN}"
  local port; port=$(get_random_port)
  read -p "请输入端口 [随机 ${port}]: " inport
  inport=$(strip_cr "$inport")
  [[ -n "$inport" ]] && port="$inport"
  is_port_available "$port" || return

  local method="2022-blake3-aes-128-gcm"
  local key; key=$(openssl rand -base64 16)
  local tag="ss_${port}"

  local chain; chain=$(ask_chain_proxy)

  local tmp; tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json)
  _CLEANUP_FILES+=("$tmp")
  cp "$SB_CONF_FILE" "$tmp"

  # ensure sniff action exists globally
  ensure_route_sniff_rule "$tmp"

  # ✅ FIX P0-1: DO NOT set network: "tcp,udp" (invalid in sing-box). Leave empty -> TCP+UDP by default.
  jq --arg tag "$tag" --arg port "$port" --arg method "$method" --arg key "$key" '
    .inbounds += [{
      "type": "shadowsocks",
      "tag": $tag,
      "listen": "::",
      "listen_port": ($port|tonumber),
      "method": $method,
      "password": $key
    }]
  ' "$tmp" > "${tmp}.1" && mv "${tmp}.1" "$tmp"

  if [[ -n "$chain" ]]; then
    apply_chain_routing "$tmp" "$tag"
  fi

  if safe_save_config "$tmp"; then
    rm -f "$tmp"
    open_port "$port"
    show_node_info "$tag"
  else
    rm -f "$tmp"
  fi
}

_NODE_COUNT=0

list_nodes() {
  echo -e "${BLUE}================================================================${PLAIN}"
  echo -e "   当前节点列表"
  echo -e "${BLUE}================================================================${PLAIN}"
  printf " %-4s %-20s %-12s %-8s\n" "ID" "Tag" "Type" "Port"
  echo -e "----------------------------------------------------------------"
  _NODE_COUNT=0

  local nodes; nodes=$(jq -c '.inbounds[]?' "$SB_CONF_FILE" 2>/dev/null) || true
  if [[ -z "$nodes" ]]; then
    echo -e " (无节点)"
    echo -e "----------------------------------------------------------------"
    return
  fi

  while IFS= read -r node; do
    [[ -z "$node" ]] && continue
    local tag type port
    tag=$(echo "$node" | jq -r '.tag')
    type=$(echo "$node" | jq -r '.type')
    port=$(echo "$node" | jq -r '.listen_port')
    if [[ "$tag" == reality_* || "$tag" == ss_* ]]; then
      _NODE_COUNT=$((_NODE_COUNT+1))
      printf " [%d]  %-20s %-12s %-8s\n" "$_NODE_COUNT" "$tag" "$type" "$port"
    fi
  done <<< "$nodes"
  echo -e "----------------------------------------------------------------"
}

get_node_tag_by_id() {
  local target=$1
  local i=0
  local nodes; nodes=$(jq -c '.inbounds[]?' "$SB_CONF_FILE" 2>/dev/null) || true
  [[ -z "$nodes" ]] && return
  while IFS= read -r node; do
    [[ -z "$node" ]] && continue
    local tag
    tag=$(echo "$node" | jq -r '.tag')
    if [[ "$tag" == reality_* || "$tag" == ss_* ]]; then
      i=$((i+1))
      if [[ "$i" -eq "$target" ]]; then echo "$tag"; return; fi
    fi
  done <<< "$nodes"
}

delete_node() {
  list_nodes
  [[ "$_NODE_COUNT" -eq 0 ]] && return

  read -p "请输入要删除的节点 ID (0 返回): " id
  id=$(strip_cr "$id")
  [[ "$id" == "0" ]] && return
  if ! [[ "$id" =~ ^[0-9]+$ ]] || [[ "$id" -lt 1 ]] || [[ "$id" -gt "$_NODE_COUNT" ]]; then
    echo -e "${RED}ID 无效。${PLAIN}"
    return
  fi

  local tag; tag=$(get_node_tag_by_id "$id")
  [[ -z "$tag" ]] && { echo -e "${RED}未找到节点。${PLAIN}"; return; }

  local port; port=$(jq -r --arg t "$tag" '.inbounds[] | select(.tag==$t) | .listen_port' "$SB_CONF_FILE" 2>/dev/null)
  echo -e "${YELLOW}正在删除: ${tag} ...${PLAIN}"

  local tmp; tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json)
  _CLEANUP_FILES+=("$tmp")
  jq --arg t "$tag" '
    del(.inbounds[] | select(.tag==$t)) |
    .route.rules |= [ .[] | select((.inbound // [] | index($t)) | not) ]
  ' "$SB_CONF_FILE" > "$tmp"

  if safe_save_config "$tmp"; then
    rm -f "$tmp"
    [[ -n "$port" && "$port" != "null" ]] && close_port "$port"
    meta_del_tag "$tag"
    echo -e "${GREEN}删除完成。${PLAIN}"
  else
    rm -f "$tmp"
  fi
}

configure_advanced() {
  while true; do
    clear
    echo -e "${BLUE}=== 进阶功能 (Advanced) ===${PLAIN}"
    local chain
    chain=$(jq -r '.outbounds[]? | select(.tag=="chain_proxy") | "\(.server):\(.server_port)"' "$SB_CONF_FILE" 2>/dev/null)
    if [[ -n "$chain" && "$chain" != "null:null" ]]; then
      echo -e " 当前 SOCKS5 链: ${GREEN}${chain}${PLAIN}"
    else
      echo -e " 当前 SOCKS5 链: ${YELLOW}未配置${PLAIN}"
    fi
    echo
    echo " 1) 配置/删除 上游 SOCKS5 链式代理"
    echo " 2) 恢复默认路由规则(保留 sniff + 屏蔽私网IP)"
    echo " 0) 返回"
    echo "----------------------------------------"
    read -p "请选择: " choice
    choice=$(strip_cr "$choice")
    case "$choice" in
      1)
        read -p "输入上游 SOCKS5 (如 127.0.0.1:40000)，留空=删除: " addr
        addr=$(strip_cr "$addr")
        local tmp; tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json)
        _CLEANUP_FILES+=("$tmp")

        if [[ -z "$addr" ]]; then
          jq '
            del(.outbounds[] | select(.tag=="chain_proxy")) |
            .route.rules |= [ .[] | select(.outbound != "chain_proxy") ]
          ' "$SB_CONF_FILE" > "$tmp"
          safe_save_config "$tmp" && rm -f "$tmp"
        else
          local host="${addr%:*}"
          local port="${addr#*:}"
          jq 'del(.outbounds[] | select(.tag=="chain_proxy"))' "$SB_CONF_FILE" > "$tmp"
          jq --arg h "$host" --arg p "$port" '
            .outbounds += [{
              "type": "socks",
              "tag": "chain_proxy",
              "server": $h,
              "server_port": ($p|tonumber)
            }]
          ' "$tmp" > "${tmp}.1" && mv "${tmp}.1" "$tmp"
          safe_save_config "$tmp" && rm -f "$tmp"
        fi
        read -p "按回车继续..." ;;
      2)
        local tmp; tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json)
        _CLEANUP_FILES+=("$tmp")
        jq '
          .route.rules = [
            { "action":"sniff" },
            { "ip_is_private": true, "action": "route", "outbound": "block" }
          ] + ([.route.rules[]?] | map(select(.action? != "sniff" and .ip_is_private? != true and .outbound? != "chain_proxy")))
        ' "$SB_CONF_FILE" > "$tmp"
        safe_save_config "$tmp" && rm -f "$tmp"
        read -p "按回车继续..." ;;
      0) return ;;
    esac
  done
}

update_script() {
  echo -e "${BLUE}>>> 更新脚本...${PLAIN}"
  local tmp; tmp=$(mktemp /tmp/xsb_upd.XXXXXX.sh)
  _CLEANUP_FILES+=("$tmp")

  if ! curl -fsSL --max-time 20 "${SCRIPT_URL}?t=$(date +%s)" -o "$tmp"; then
    echo -e "${RED}下载失败：${SCRIPT_URL}${PLAIN}"
    return 1
  fi
  if [[ ! -s "$tmp" ]]; then
    echo -e "${RED}下载文件为空。${PLAIN}"
    return 1
  fi

  local new_ver
  new_ver=$(grep -E '^SCRIPT_VERSION=' "$tmp" | head -1 | cut -d'"' -f2)
  [[ -z "$new_ver" ]] && new_ver="unknown"

  local target="$INSTALL_PATH"
  if [[ ! -f "$target" ]]; then
    target="$(realpath "$0" 2>/dev/null)"
    [[ -z "$target" ]] && target="$0"
  fi

  mv -f "$tmp" "$target"
  chmod +x "$target"
  echo -e "${GREEN}更新完成：v${SCRIPT_VERSION} -> v${new_ver}${PLAIN}"
  exec "$target"
}

uninstall_all() {
  echo -e "${RED}!!! 危险操作：卸载 sing-box + 删除全部配置 !!!${PLAIN}"
  read -p "确认请输入 yes: " cf
  cf=$(strip_cr "$cf")
  [[ "${cf,,}" != "yes" ]] && return

  if [[ -f "$SB_CONF_FILE" ]]; then
    for p in $(jq -r '.inbounds[]?.listen_port // empty' "$SB_CONF_FILE" 2>/dev/null); do
      close_port "$p"
    done
  fi

  systemctl stop sing-box >/dev/null 2>&1 || true
  systemctl disable sing-box >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true

  rm -rf "$SB_CONF_DIR" "$WORK_DIR"
  rm -f "$SB_BIN"
  rm -f "$INSTALL_PATH"

  echo -e "${GREEN}卸载完成。${PLAIN}"
  exit 0
}

main_menu() {
  check_deps
  init_meta_if_missing
  while true; do
    clear
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e "  sb (sing-box)  v${SCRIPT_VERSION}"
    echo -e "  Script update URL: ${SCRIPT_URL}"
    echo -e "  Meta file: ${META_FILE}"
    echo -e "${BLUE}================================================================${PLAIN}"

    local st="${RED}未运行${PLAIN}"
    local ver; ver=$(get_current_sb_ver)
    if systemctl is-active --quiet sing-box; then st="${GREEN}✅ 运行中 (core ${ver})${PLAIN}"; fi

    echo -e " 核心状态: ${st}"
    echo -e " 配置文件: ${SB_CONF_FILE}"
    echo "----------------------------------------------------------------"
    echo " 1) 安装/更新 sing-box 核心"
    echo " 2) 添加 VLESS-Vision-REALITY 节点"
    echo " 3) 添加 Shadowsocks-2022 节点"
    echo " 4) 查看节点/导出分享链接"
    echo " 5) 删除节点"
    echo " 6) 进阶配置(链式代理/路由)"
    echo " 7) 更新脚本"
    echo " 8) 卸载 sing-box + 删除全部配置"
    echo " 0) 退出"
    echo "----------------------------------------------------------------"
    read -p "请选择: " choice
    choice=$(strip_cr "$choice")

    case "$choice" in
      1) install_singbox; read -p "按回车继续..." ;;
      2) add_reality; read -p "按回车继续..." ;;
      3) add_ss2022; read -p "按回车继续..." ;;
      4)
        list_nodes
        read -p "输入节点 ID 查看详情(0返回): " id
        id=$(strip_cr "$id")
        if [[ "$id" =~ ^[0-9]+$ ]] && [[ "$id" -ge 1 ]] && [[ "$id" -le "$_NODE_COUNT" ]]; then
          t=$(get_node_tag_by_id "$id")
          [[ -n "$t" ]] && show_node_info "$t"
        fi
        read -p "按回车继续..." ;;
      5) delete_node; read -p "按回车继续..." ;;
      6) configure_advanced ;;
      7) update_script ;;
      8) uninstall_all ;;
      0) exit 0 ;;
    esac
  done
}

check_root
init_meta_if_missing
init_config_if_missing
main_menu