#!/bin/bash
# sb (sing-box edition) - multi-protocol manager
# - VLESS Vision REALITY (TCP)
# - Shadowsocks 2022
# - Optional encrypted Shadowsocks 2022 relay / legacy SOCKS5 chain
# - Safe config check + rollback
# - Script self-update (GitHub raw)

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[36m'
PLAIN='\033[0m'

SCRIPT_VERSION="1.2.2"
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
SS2022_METHOD="2022-blake3-aes-128-gcm"
SS2022_KEY_BYTES=16

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
  if [[ $rc -ne 0 ]]; then
    echo -e "${RED}❌ ${label}失败（退出码 ${rc}）。服务日志: journalctl -u sing-box -n 30 --no-pager${PLAIN}" >&2
  fi
  return 0
}

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
      if ! apt-get update -y; then
        echo -e "${YELLOW}警告: 部分 APT 软件源刷新失败；将使用现有索引继续安装依赖。请检查上方报错的软件源。${PLAIN}" >&2
      fi
      apt-get install -y curl tar jq openssl qrencode iproute2 || true
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

  local hard=("curl" "tar" "jq" "openssl" "ss")
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
  local mode=${2:-both}
  local protocols=(tcp udp)
  [[ "$mode" == "tcp" ]] && protocols=(tcp)
  local proto rc=0

  if command -v ufw >/dev/null 2>&1; then
    for proto in "${protocols[@]}"; do
      ufw allow "${port}/${proto}" >/dev/null 2>&1 || rc=1
    done
  elif command -v firewall-cmd >/dev/null 2>&1; then
    for proto in "${protocols[@]}"; do
      firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 || rc=1
    done
    firewall-cmd --reload >/dev/null 2>&1 || rc=1
  elif command -v iptables >/dev/null 2>&1; then
    for proto in "${protocols[@]}"; do
      iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || rc=1
    done
    if command -v iptables-save >/dev/null 2>&1; then
      mkdir -p /etc/iptables 2>/dev/null || true
      iptables-save > /etc/iptables/rules.v4 2>/dev/null || rc=1
    fi
  fi
  return "$rc"
}

close_port() {
  local port=$1
  local mode=${2:-both}
  local protocols=(tcp udp)
  [[ "$mode" == "tcp" ]] && protocols=(tcp)
  local proto

  if command -v ufw >/dev/null 2>&1; then
    for proto in "${protocols[@]}"; do
      ufw delete allow "${port}/${proto}" >/dev/null 2>&1 || true
    done
  elif command -v firewall-cmd >/dev/null 2>&1; then
    for proto in "${protocols[@]}"; do
      firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1 || true
    done
    firewall-cmd --reload >/dev/null 2>&1 || true
  elif command -v iptables >/dev/null 2>&1; then
    for proto in "${protocols[@]}"; do
      iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
    done
    if command -v iptables-save >/dev/null 2>&1; then
      iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
  fi
}

network_mode_for_type() {
  [[ "$1" == "vless" ]] && echo "tcp" || echo "both"
}

get_sb_ver_from_bin() {
  local bin=$1
  local ver
  [[ -x "$bin" ]] || return 1
  ver=$("$bin" version 2>/dev/null | sed -nE 's/^sing-box version v?([^[:space:]]+).*/\1/p' | head -1)
  [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || return 1
  echo "$ver"
}

get_current_sb_ver() {
  [[ -x "$SB_BIN" ]] || { echo "none"; return; }
  get_sb_ver_from_bin "$SB_BIN" || echo "unknown"
}

get_latest_sb_tag() {
  local tag=""
  tag=$(curl -sL --max-time 8 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r .tag_name 2>/dev/null)
  if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$tag"
    return 0
  fi

  local final
  final=$(curl -sI --max-time 8 -o /dev/null -w "%{url_effective}" "https://github.com/SagerNet/sing-box/releases/latest")
  tag="${final##*/}"
  if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$tag"
    return 0
  fi
  return 1
}

get_release_asset_digest() {
  local tag=$1 asset_name=$2 digest
  digest=$(curl -fsSL --max-time 10 "https://api.github.com/repos/SagerNet/sing-box/releases/tags/${tag}" |
    jq -r --arg name "$asset_name" '.assets[]? | select(.name == $name) | .digest // empty' 2>/dev/null) || return 1
  digest=${digest#sha256:}
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  echo "$digest"
}

init_meta_if_missing() {
  mkdir -p "$SB_CONF_DIR" "$WORK_DIR" || return 1
  if [[ ! -f "$META_FILE" ]] || [[ ! -s "$META_FILE" ]]; then
    echo '{}' > "$META_FILE" || return 1
    chmod 600 "$META_FILE" || return 1
  fi
}

# Resolve domains, reject private targets, then apply final routing actions.
ensure_private_reject_rule() {
  local json_file=$1
  local stage="${json_file}.guard"
  if jq '
    (.route.rules // []) as $rules |
    ($rules | map(select(.action? == "resolve" and (keys == ["action"]))) | first
      // {"action": "resolve"}) as $resolver |
    ($rules | map(select(
      .ip_is_private? == true and .action? == "reject" and
      (keys == ["action", "ip_is_private"])
    )) | first
      // {"ip_is_private": true, "action": "reject"}) as $guard |
    .route.rules = ([$resolver, $guard] +
      ($rules | map(select(
        ((.action? == "resolve" and (keys == ["action"])) or
         (.ip_is_private? == true and .action? == "reject" and
          (keys == ["action", "ip_is_private"]))) | not
      ))))
  ' "$json_file" > "$stage" && mv "$stage" "$json_file"; then
    return
  fi
  rm -f "$stage"
  return 1
}

init_config_if_missing() {
  mkdir -p "$SB_CONF_DIR" "$WORK_DIR" || return 1
  if [[ ! -f "$SB_CONF_FILE" ]] || [[ ! -s "$SB_CONF_FILE" ]]; then
    cat > "$SB_CONF_FILE" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "final": "direct",
    "rules": [
      { "action": "resolve" },
      { "ip_is_private": true, "action": "reject" }
    ]
  }
}
EOF
    chmod 640 "$SB_CONF_FILE" || return 1
  fi
}

write_systemd() {
  local tmp_service
  tmp_service=$(mktemp "${SYSTEMD_FILE}.new.XXXXXX") || {
    echo -e "${RED}无法创建 systemd 服务临时文件。${PLAIN}" >&2
    return 1
  }
  _CLEANUP_FILES+=("$tmp_service")
  cat > "$tmp_service" <<EOF
[Unit]
Description=sing-box Service
Documentation=https://sing-box.sagernet.org
After=network-online.target nss-lookup.target
Wants=network-online.target

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
  chmod 644 "$tmp_service" || return 1
  mv -f "$tmp_service" "$SYSTEMD_FILE" || return 1
  if ! systemctl daemon-reload; then
    echo -e "${RED}systemd 配置重载失败。${PLAIN}" >&2
    return 1
  fi
  if ! systemctl enable sing-box >/dev/null 2>&1; then
    echo -e "${RED}sing-box 开机启动设置失败。${PLAIN}" >&2
    return 1
  fi
}

atomic_replace_file() {
  local source=$1 destination=$2 mode=$3
  local stage
  stage=$(mktemp "${destination}.new.XXXXXX") || return 1
  _CLEANUP_FILES+=("$stage")
  install -m "$mode" "$source" "$stage" || return 1
  mv -f "$stage" "$destination"
}

show_service_logs() {
  journalctl -u sing-box --no-pager -n 30 2>/dev/null | tail -30
}

restart_singbox_checked() {
  if ! systemctl restart sing-box; then
    echo -e "${RED}sing-box 重启命令失败。${PLAIN}" >&2
    show_service_logs
    return 1
  fi
  sleep 1
  if ! systemctl is-active --quiet sing-box; then
    echo -e "${RED}sing-box 重启后未处于运行状态。${PLAIN}" >&2
    show_service_logs
    return 1
  fi
  return 0
}

migrate_route_guard_if_needed() {
  [[ -x "$SB_BIN" && -s "$SB_CONF_FILE" ]] || return 0
  jq -e '
    (.route.rules[0] | .action? == "resolve" and (keys == ["action"])) and
    (.route.rules[1] | .ip_is_private? == true and .action? == "reject" and
      (keys == ["action", "ip_is_private"]))
  ' "$SB_CONF_FILE" >/dev/null 2>&1 && return 0

  local tmp
  tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json) || return 1
  _CLEANUP_FILES+=("$tmp")
  cp "$SB_CONF_FILE" "$tmp" || return 1
  ensure_private_reject_rule "$tmp" || return 1
  echo -e "${YELLOW}检测到旧版安全路由，正在补充域名解析和私网保护...${PLAIN}"
  if systemctl is-active --quiet sing-box 2>/dev/null; then
    safe_save_config "$tmp"
    return
  fi

  local out
  out=$("$SB_BIN" check -c "$tmp" 2>&1) || {
    echo -e "${RED}安全路由迁移校验失败，原配置未改动:${PLAIN}" >&2
    echo "$out" | tail -12
    return 1
  }
  atomic_replace_file "$tmp" "$SB_CONF_FILE" 640 || return 1
  echo -e "${GREEN}安全路由已在服务停止状态下更新。${PLAIN}"
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
    backup=$(mktemp "${SB_CONF_FILE}.bak.XXXXXX") || return 1
    _CLEANUP_FILES+=("$backup")
    cp -p "$SB_CONF_FILE" "$backup" || return 1
  fi

  if ! atomic_replace_file "$tmp_json" "$SB_CONF_FILE" 640; then
    echo -e "${RED}配置文件原子替换失败，现有配置未改动。${PLAIN}" >&2
    return 1
  fi

  if restart_singbox_checked; then
    echo -e "${GREEN}配置已应用，服务已重启。${PLAIN}"
    [[ -n "$backup" ]] && rm -f "$backup"
    return 0
  fi

  echo -e "${RED}sing-box 启动失败! 正在回滚...${PLAIN}"

  if [[ -n "$backup" && -f "$backup" ]]; then
    if atomic_replace_file "$backup" "$SB_CONF_FILE" 640 && restart_singbox_checked; then
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
  local tmp_script remote_ver
  tmp_script=$(mktemp "${INSTALL_PATH}.install.XXXXXX") || {
    echo -e "${RED}无法创建快捷命令安装临时文件。${PLAIN}" >&2
    return 1
  }
  _CLEANUP_FILES+=("$tmp_script")
  if curl -fsSLo "$tmp_script" --connect-timeout 8 --max-time 20 "$(fresh_script_url)" \
      && validate_script_candidate "$tmp_script"; then
    remote_ver=$(grep '^SCRIPT_VERSION=' "$tmp_script" | head -1 | cut -d'"' -f2)
    if ! version_is_older "$remote_ver" "$SCRIPT_VERSION"; then
      if ! chmod 755 "$tmp_script" || ! mv -f "$tmp_script" "$INSTALL_PATH"; then
        echo -e "${RED}快捷命令安装失败，现有文件未被覆盖。${PLAIN}" >&2
        return 1
      fi
      echo -e "${GREEN}快捷命令 '${SHORTCUT_NAME}' 已安装到 ${INSTALL_PATH}${PLAIN}"
      return 0
    fi
    echo -e "${YELLOW}远端脚本 v${remote_ver} 低于当前 v${SCRIPT_VERSION}，改用当前脚本安装。${PLAIN}"
  fi
  if [[ -f "$0" ]] && validate_script_candidate "$0"; then
    if ! cp "$0" "$tmp_script" || ! chmod 755 "$tmp_script" \
        || ! mv -f "$tmp_script" "$INSTALL_PATH"; then
      echo -e "${RED}快捷命令本地安装失败，现有文件未被覆盖。${PLAIN}" >&2
      return 1
    fi
    echo -e "${YELLOW}快捷命令已从当前脚本安装。${PLAIN}"
  else
    echo -e "${RED}快捷命令安装失败，现有文件未被覆盖。${PLAIN}" >&2
    return 1
  fi
}

install_singbox() {
  echo -e "${BLUE}>>> 安装/更新 sing-box 核心...${PLAIN}"
  init_meta_if_missing || return 1
  init_config_if_missing || return 1

  local arch
  arch=$(map_arch_sb)

  local latest_tag=""
  local latest_ver=""

  if [[ -n "$PINNED_SB_VERSION" ]]; then
    if ! [[ "$PINNED_SB_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo -e "${RED}固定版本格式无效: ${PINNED_SB_VERSION}${PLAIN}" >&2
      return 1
    fi
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

  if [[ -z "$PINNED_SB_VERSION" && "$curr_ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] &&
     version_is_older "$latest_ver" "$curr_ver"; then
    echo -e "${RED}拒绝核心降级：远端稳定版 ${latest_ver} 低于当前 ${curr_ver}。${PLAIN}" >&2
    return 1
  fi

  if [[ "$curr_ver" == "$latest_ver" ]]; then
    echo -e "${GREEN}当前已是目标版本 (${curr_ver})，正在验证配置和服务。${PLAIN}"
    local current_check
    current_check=$("$SB_BIN" check -c "$SB_CONF_FILE" 2>&1) || {
      echo -e "${RED}现有配置无法通过 sing-box ${curr_ver} 校验，未重启服务:${PLAIN}" >&2
      echo "$current_check" | tail -20
      return 1
    }
    write_systemd || return 1
    restart_singbox_checked || return 1
    migrate_route_guard_if_needed || return 1
    install_shortcut_cmd || return 1
    return
  fi

  echo -e "${YELLOW}正在下载 sing-box ${latest_ver} (${arch})...${PLAIN}"
  local asset_name="sing-box-${latest_ver}-linux-${arch}.tar.gz"
  local url="https://github.com/SagerNet/sing-box/releases/download/${latest_tag}/${asset_name}"
  local tmp_tgz tmp_dir
  tmp_tgz=$(mktemp /tmp/sb_XXXXXX.tgz)
  tmp_dir=$(mktemp -d /tmp/sb_XXXXXX.dir)
  _CLEANUP_FILES+=("$tmp_tgz" "$tmp_dir")

  if ! curl -fL --max-time 120 --progress-bar "${url}?t=$(date +%s)" -o "$tmp_tgz"; then
    echo -e "${RED}下载失败：${url}${PLAIN}"
    return 1
  fi

  local expected_digest actual_digest
  expected_digest=$(get_release_asset_digest "$latest_tag" "$asset_name") || expected_digest=""
  if [[ -n "$expected_digest" ]]; then
    actual_digest=$(openssl dgst -sha256 "$tmp_tgz" 2>/dev/null | awk '{print $NF}')
    if [[ "$actual_digest" != "$expected_digest" ]]; then
      echo -e "${RED}下载文件 SHA-256 校验失败，拒绝安装。${PLAIN}" >&2
      return 1
    fi
    echo -e "${GREEN}发布文件 SHA-256 校验通过。${PLAIN}"
  else
    echo -e "${YELLOW}警告: 无法取得 GitHub 发布文件摘要，将继续执行版本和配置校验。${PLAIN}" >&2
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

  chmod 755 "$extracted" || {
    echo -e "${RED}无法设置候选核心的执行权限。${PLAIN}" >&2
    return 1
  }

  local candidate_ver
  candidate_ver=$(get_sb_ver_from_bin "$extracted") || {
    echo -e "${RED}无法读取候选核心版本，拒绝安装。${PLAIN}" >&2
    return 1
  }
  if [[ "$candidate_ver" != "$latest_ver" ]]; then
    echo -e "${RED}候选核心版本不匹配: 期望 ${latest_ver}，实际 ${candidate_ver}。${PLAIN}" >&2
    return 1
  fi

  local candidate_check
  candidate_check=$("$extracted" check -c "$SB_CONF_FILE" 2>&1) || {
    echo -e "${RED}现有配置无法通过 sing-box ${candidate_ver} 校验，旧核心保持运行:${PLAIN}" >&2
    echo "$candidate_check" | tail -20
    return 1
  }

  local old_binary=""
  if [[ -x "$SB_BIN" ]]; then
    old_binary=$(mktemp "${SB_BIN}.bak.XXXXXX") || return 1
    _CLEANUP_FILES+=("$old_binary")
    cp -p "$SB_BIN" "$old_binary" || return 1
  fi

  if ! atomic_replace_file "$extracted" "$SB_BIN" 755; then
    echo -e "${RED}核心文件原子替换失败，旧核心保持不变。${PLAIN}" >&2
    return 1
  fi

  if write_systemd && restart_singbox_checked; then
    echo -e "${GREEN}sing-box 已更新到 ${latest_ver} 并启动成功。${PLAIN}"
    [[ -n "$old_binary" ]] && rm -f "$old_binary"
    migrate_route_guard_if_needed || return 1
    install_shortcut_cmd || return 1
    return
  fi

  echo -e "${RED}新核心启动失败，正在回滚核心...${PLAIN}" >&2
  if [[ -n "$old_binary" && -f "$old_binary" ]]; then
    if atomic_replace_file "$old_binary" "$SB_BIN" 755 && restart_singbox_checked; then
      echo -e "${YELLOW}已恢复 sing-box ${curr_ver}，服务重新运行。${PLAIN}"
    else
      echo -e "${RED}旧核心恢复失败，请立即检查: journalctl -u sing-box -n 80${PLAIN}" >&2
    fi
  else
    rm -f "$SB_BIN"
    systemctl stop sing-box >/dev/null 2>&1 || true
    systemctl disable sing-box >/dev/null 2>&1 || true
    rm -f "$SYSTEMD_FILE"
    systemctl daemon-reload >/dev/null 2>&1 || true
    echo -e "${RED}首次安装失败，已移除不可用核心。${PLAIN}" >&2
  fi
  return 1
}

gen_uuid() {
  if [[ -x "$SB_BIN" ]]; then
    "$SB_BIN" generate uuid 2>/dev/null && return
  fi
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
  local has type label
  has=$(jq -r '.outbounds[]? | select(.tag=="chain_proxy") | .tag' "$SB_CONF_FILE" 2>/dev/null)
  [[ -z "$has" ]] && { echo ""; return; }
  type=$(jq -r '.outbounds[]? | select(.tag=="chain_proxy") | .type' "$SB_CONF_FILE" 2>/dev/null)
  [[ "$type" == "shadowsocks" ]] && label="B 机出口" || label="SOCKS5 出口"
  echo -e "${YELLOW}是否让此节点使用 ${label}? [y/N]${PLAIN}" >&2
  read -p "选择: " sel
  sel=$(strip_cr "$sel")
  [[ "${sel,,}" == "y" ]] && echo "yes" || echo ""
}

apply_chain_routing() {
  local json_file=$1
  local inbound_tag=$2
  ensure_private_reject_rule "$json_file" || return 1
  local stage="${json_file}.route"
  if jq --arg itag "$inbound_tag" '
    .route.rules = (
      ((.route.rules // []) | map(select(
        ((.action? == "route") and (.outbound? == "chain_proxy") and
         ((.inbound? // []) | index($itag) != null)) | not
      ))) + [{
        "inbound": [$itag],
        "action": "route",
        "outbound": "chain_proxy"
      }]
    )
  ' "$json_file" > "$stage" && mv "$stage" "$json_file"; then
    return
  fi
  rm -f "$stage"
  return 1
}

remove_chain_routing() {
  local json_file=$1
  local inbound_tag=$2
  local stage="${json_file}.route"
  if jq --arg itag "$inbound_tag" '
    .route.rules = ((.route.rules // []) | map(select(
      ((.action? == "route") and (.outbound? == "chain_proxy") and
       ((.inbound? // []) | index($itag) != null)) | not
    )))
  ' "$json_file" > "$stage" && mv "$stage" "$json_file"; then
    return
  fi
  rm -f "$stage"
  return 1
}

# ---- metadata helpers (pbk storage) ----
meta_set_pubkey() {
  local tag=$1
  local pubk=$2
  init_meta_if_missing || return 1
  local tmp
  tmp=$(mktemp "${META_FILE}.new.XXXXXX")
  _CLEANUP_FILES+=("$tmp")
  if ! jq --arg t "$tag" --arg pk "$pubk" '
    .[$t] = (.[$t] // {}) | .[$t].public_key = $pk
  ' "$META_FILE" > "$tmp"; then
    echo -e "${RED}节点元数据更新失败。${PLAIN}" >&2
    return 1
  fi
  chmod 600 "$tmp" && mv -f "$tmp" "$META_FILE"
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
  tmp=$(mktemp "${META_FILE}.new.XXXXXX")
  _CLEANUP_FILES+=("$tmp")
  jq --arg t "$tag" 'del(.[$t])' "$META_FILE" > "$tmp" || return 1
  chmod 600 "$tmp" && mv -f "$tmp" "$META_FILE"
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
    local method pass link
    method=$(echo "$node" | jq -r '.method')
    pass=$(echo "$node" | jq -r '.password')
    # SIP022: Shadowsocks 2022 userinfo 使用明文方法名和百分号编码密码。
    link="ss://$(urlencode "$method"):$(urlencode "$pass")@${display_ip}:${port}#$(urlencode "$tag")"
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
  _CLEANUP_FILES+=("${tmp}.1")
  cp "$SB_CONF_FILE" "$tmp"

  ensure_private_reject_rule "$tmp" || {
    echo -e "${RED}无法生成基础安全路由规则。${PLAIN}" >&2
    return 1
  }

  if ! jq --arg tag "$tag" --arg port "$port" --arg uuid "$uuid" --arg sni "$sni" --arg privk "$privk" --arg sid "$sid" '
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
  ' "$tmp" > "${tmp}.1" || ! mv "${tmp}.1" "$tmp"; then
    echo -e "${RED}Reality 配置生成失败。${PLAIN}" >&2
    return 1
  fi

  if [[ -n "$chain" ]]; then
    apply_chain_routing "$tmp" "$tag" || {
      echo -e "${RED}Reality 链式转发规则生成失败。${PLAIN}" >&2
      return 1
    }
  fi

  if safe_save_config "$tmp"; then
    rm -f "$tmp"
    if ! meta_set_pubkey "$tag" "$pubk"; then
      echo -e "${YELLOW}节点已运行，但 Public Key 元数据保存失败，分享链接暂不可用。${PLAIN}" >&2
    fi
    if ! open_port "$port" tcp; then
      echo -e "${YELLOW}Reality 节点已运行，但 TCP/${port} 防火墙规则添加失败，请手动放行。${PLAIN}" >&2
    fi
    show_node_info "$tag"
  else
    rm -f "$tmp"
  fi
}

add_ss2022() {
  echo -e "${BLUE}>>> 添加 Shadowsocks-2022 节点${PLAIN}"
  [[ -x "$SB_BIN" ]] || { echo -e "${RED}未安装 sing-box，请先选择菜单 1 安装。${PLAIN}"; return 1; }
  local port; port=$(get_random_port)
  read -p "请输入端口 [随机 ${port}]: " inport
  inport=$(strip_cr "$inport")
  [[ -n "$inport" ]] && port="$inport"
  is_port_available "$port" || return

  local method="$SS2022_METHOD"
  local key; key=$("$SB_BIN" generate rand --base64 "$SS2022_KEY_BYTES" 2>/dev/null)
  [[ -n "$key" ]] || { echo -e "${RED}生成 Shadowsocks-2022 密钥失败。${PLAIN}"; return 1; }
  local tag="ss_${port}"

  local chain; chain=$(ask_chain_proxy)

  local tmp; tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json)
  _CLEANUP_FILES+=("$tmp")
  _CLEANUP_FILES+=("${tmp}.1")
  cp "$SB_CONF_FILE" "$tmp"

  ensure_private_reject_rule "$tmp" || {
    echo -e "${RED}无法生成基础安全路由规则。${PLAIN}" >&2
    return 1
  }

  # Official schema: omitting network enables both TCP and UDP.
  if ! jq --arg tag "$tag" --arg port "$port" --arg method "$method" --arg key "$key" '
    .inbounds += [{
      "type": "shadowsocks",
      "tag": $tag,
      "listen": "::",
      "listen_port": ($port|tonumber),
      "method": $method,
      "password": $key
    }]
  ' "$tmp" > "${tmp}.1" || ! mv "${tmp}.1" "$tmp"; then
    echo -e "${RED}Shadowsocks-2022 配置生成失败。${PLAIN}" >&2
    return 1
  fi

  if [[ -n "$chain" ]]; then
    apply_chain_routing "$tmp" "$tag" || {
      echo -e "${RED}Shadowsocks 链式转发规则生成失败。${PLAIN}" >&2
      return 1
    }
  fi

  if safe_save_config "$tmp"; then
    rm -f "$tmp"
    if ! open_port "$port" both; then
      echo -e "${YELLOW}Shadowsocks 节点已运行，但 TCP/UDP ${port} 防火墙规则添加失败，请手动放行。${PLAIN}" >&2
    fi
    show_node_info "$tag"
  else
    rm -f "$tmp"
  fi
}

_RELAY_COUNT=0

list_ss2022_relays() {
  echo -e "${BLUE}================================================================${PLAIN}"
  echo -e "   本机 SS2022 专用出口中继"
  echo -e "${BLUE}================================================================${PLAIN}"
  printf " %-4s %-20s %-8s\n" "ID" "Tag" "Port"
  echo -e "----------------------------------------------------------------"
  _RELAY_COUNT=0

  local tag port
  while IFS=$'\t' read -r tag port; do
    [[ -n "$tag" ]] || continue
    _RELAY_COUNT=$((_RELAY_COUNT+1))
    printf " [%d]  %-20s %-8s\n" "$_RELAY_COUNT" "$tag" "$port"
  done < <(jq -r '.inbounds[]? | select((.tag // "") | startswith("relay_")) | [.tag, .listen_port] | @tsv' "$SB_CONF_FILE" 2>/dev/null)

  [[ "$_RELAY_COUNT" -gt 0 ]] || echo " (无专用中继)"
  echo -e "----------------------------------------------------------------"
}

get_relay_tag_by_id() {
  local target=$1 i=0 tag
  while IFS= read -r tag; do
    [[ -n "$tag" ]] || continue
    i=$((i+1))
    [[ "$i" -eq "$target" ]] && { echo "$tag"; return; }
  done < <(jq -r '.inbounds[]? | select((.tag // "") | startswith("relay_")) | .tag' "$SB_CONF_FILE" 2>/dev/null)
}

show_ss2022_relay_info() {
  local tag=$1 node ip display_ip
  node=$(jq -c --arg t "$tag" '.inbounds[]? | select(.tag==$t)' "$SB_CONF_FILE" 2>/dev/null)
  [[ -n "$node" ]] || return 1
  ip=$(get_public_ip)
  display_ip="$ip"
  [[ "$ip" == *:* ]] && display_ip="[$ip]"
  echo -e "${GREEN}SS2022 专用中继已就绪。请在 A 机配置以下上游:${PLAIN}"
  echo " 地址: ${display_ip}:$(echo "$node" | jq -r '.listen_port')"
  echo " 方法: $(echo "$node" | jq -r '.method')"
  echo " 密钥: $(echo "$node" | jq -r '.password')"
  echo -e "${YELLOW}脚本未修改防火墙。请自行放行该 TCP/UDP 端口；如需来源限制，请在云安全组中只允许 A 机 IP。${PLAIN}"
}

create_ss2022_relay() {
  echo -e "${BLUE}>>> 在 B 机创建 SS2022 专用出口中继${PLAIN}"
  [[ -x "$SB_BIN" ]] || { echo -e "${RED}未安装 sing-box，请先选择菜单 1 安装。${PLAIN}"; return 1; }

  local port default_port method key tag tmp
  default_port=$(get_random_port)
  read -p "中继端口 [随机 ${default_port}]: " port
  port=$(strip_cr "$port")
  [[ -n "$port" ]] || port="$default_port"
  is_port_available "$port" || return 1

  method="$SS2022_METHOD"
  key=$("$SB_BIN" generate rand --base64 "$SS2022_KEY_BYTES" 2>/dev/null)
  [[ -n "$key" ]] || { echo -e "${RED}生成中继密钥失败。${PLAIN}" >&2; return 1; }
  tag="relay_${port}"
  tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json) || return 1
  _CLEANUP_FILES+=("$tmp" "${tmp}.1")
  cp "$SB_CONF_FILE" "$tmp" || return 1
  ensure_private_reject_rule "$tmp" || return 1

  if ! jq --arg tag "$tag" --arg port "$port" --arg method "$method" --arg key "$key" '
    .inbounds += [{
      "type": "shadowsocks",
      "tag": $tag,
      "listen": "::",
      "listen_port": ($port|tonumber),
      "method": $method,
      "password": $key
    }]
  ' "$tmp" > "${tmp}.1" || ! mv "${tmp}.1" "$tmp"; then
    echo -e "${RED}中继配置生成失败。${PLAIN}" >&2
    return 1
  fi

  if ! safe_save_config "$tmp"; then
    return 1
  fi

  rm -f "$tmp"
  show_ss2022_relay_info "$tag"
}

delete_ss2022_relay() {
  list_ss2022_relays
  [[ "$_RELAY_COUNT" -gt 0 ]] || return

  local id tag tmp
  read -p "输入要删除的中继 ID (0 返回): " id
  id=$(strip_cr "$id")
  [[ "$id" == "0" ]] && return
  if ! [[ "$id" =~ ^[0-9]+$ ]] || [[ "$id" -lt 1 ]] || [[ "$id" -gt "$_RELAY_COUNT" ]]; then
    echo -e "${RED}ID 无效。${PLAIN}"
    return 1
  fi
  tag=$(get_relay_tag_by_id "$id")
  [[ -n "$tag" ]] || return 1
  tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json) || return 1
  _CLEANUP_FILES+=("$tmp")
  if ! jq --arg t "$tag" 'del(.inbounds[] | select(.tag==$t))' "$SB_CONF_FILE" > "$tmp"; then
    echo -e "${RED}中继删除配置生成失败。${PLAIN}" >&2
    return 1
  fi
  if safe_save_config "$tmp"; then
    rm -f "$tmp"
    echo -e "${GREEN}中继已删除。${PLAIN}"
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

  local port proto
  port=$(jq -r --arg t "$tag" '.inbounds[] | select(.tag==$t) | .listen_port' "$SB_CONF_FILE" 2>/dev/null)
  proto=$(jq -r --arg t "$tag" '.inbounds[] | select(.tag==$t) | .type' "$SB_CONF_FILE" 2>/dev/null)
  echo -e "${YELLOW}正在删除: ${tag} ...${PLAIN}"

  local tmp; tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json)
  _CLEANUP_FILES+=("$tmp")
  if ! jq --arg t "$tag" '
    del(.inbounds[] | select(.tag==$t)) |
    .route.rules |= [ .[] | select((.inbound // [] | index($t)) | not) ]
  ' "$SB_CONF_FILE" > "$tmp"; then
    echo -e "${RED}节点删除配置生成失败。${PLAIN}" >&2
    return 1
  fi

  if safe_save_config "$tmp"; then
    rm -f "$tmp"
    [[ -n "$port" && "$port" != "null" ]] && close_port "$port" "$(network_mode_for_type "$proto")"
    meta_del_tag "$tag" || echo -e "${YELLOW}警告: 节点已删除，但元数据清理失败。${PLAIN}" >&2
    echo -e "${GREEN}删除完成。${PLAIN}"
  else
    rm -f "$tmp"
  fi
}

CHAIN_HOST=""
CHAIN_PORT=""

parse_chain_address() {
  local address=$1
  CHAIN_HOST=""
  CHAIN_PORT=""
  if [[ "$address" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
    CHAIN_HOST=${BASH_REMATCH[1]}
    CHAIN_PORT=${BASH_REMATCH[2]}
  elif [[ "$address" =~ ^([^:]+):([0-9]+)$ ]]; then
    CHAIN_HOST=${BASH_REMATCH[1]}
    CHAIN_PORT=${BASH_REMATCH[2]}
  else
    return 1
  fi
  [[ -n "$CHAIN_HOST" && ! "$CHAIN_HOST" =~ [[:space:]] &&
     "$CHAIN_PORT" -ge 1 && "$CHAIN_PORT" -le 65535 ]]
}

manage_node_forwarding() {
  if ! jq -e '.outbounds[]? | select(.tag == "chain_proxy")' "$SB_CONF_FILE" >/dev/null 2>&1; then
    echo -e "${YELLOW}请先配置出口连接（推荐连接 B 机，或使用兼容 SOCKS5）。${PLAIN}"
    return 1
  fi

  list_nodes
  [[ "$_NODE_COUNT" -eq 0 ]] && return
  local id tag enabled choice tmp
  read -p "输入要设置的节点 ID (0 返回): " id
  id=$(strip_cr "$id")
  [[ "$id" == "0" ]] && return
  if ! [[ "$id" =~ ^[0-9]+$ ]] || [[ "$id" -lt 1 ]] || [[ "$id" -gt "$_NODE_COUNT" ]]; then
    echo -e "${RED}ID 无效。${PLAIN}"
    return 1
  fi
  tag=$(get_node_tag_by_id "$id")
  [[ -n "$tag" ]] || return 1

  enabled=$(jq -r --arg t "$tag" 'any(.route.rules[]?;
    .action? == "route" and .outbound? == "chain_proxy" and ((.inbound? // []) | index($t) != null))'
    "$SB_CONF_FILE" 2>/dev/null)
  if [[ "$enabled" == "true" ]]; then
    echo -e "当前 ${tag}: ${GREEN}使用已配置出口${PLAIN}"
  else
    echo -e "当前 ${tag}: ${YELLOW}使用本机出口${PLAIN}"
  fi
  read -p "输入 y 使用已配置出口，n 使用本机出口，其他键取消: " choice
  choice=$(strip_cr "$choice")
  [[ "${choice,,}" == "y" || "${choice,,}" == "n" ]] || return

  tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json) || return 1
  _CLEANUP_FILES+=("$tmp")
  cp "$SB_CONF_FILE" "$tmp" || return 1
  ensure_private_reject_rule "$tmp" || return 1
  if [[ "${choice,,}" == "y" ]]; then
    apply_chain_routing "$tmp" "$tag" || return 1
  else
    remove_chain_routing "$tmp" "$tag" || return 1
  fi
  safe_save_config "$tmp"
}

delete_chain_proxy() {
  local tmp
  tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json) || return 1
  _CLEANUP_FILES+=("$tmp")
  if ! jq '
    del(.outbounds[] | select(.tag=="chain_proxy")) |
    .route.rules = ([.route.rules[]?] | map(select(.outbound? != "chain_proxy")))
  ' "$SB_CONF_FILE" > "$tmp"; then
    echo -e "${RED}删除出口连接失败。${PLAIN}" >&2
    return 1
  fi
  if safe_save_config "$tmp"; then
    rm -f "$tmp"
    echo -e "${GREEN}出口连接已断开，相关节点已改回本机出口。${PLAIN}"
  fi
}

configure_ss2022_chain() {
  local addr method password tmp
  echo -e "${BLUE}>>> 在 A 机连接 B 机出口${PLAIN}"
  read -p "输入 B 机给出的中继地址 (如 203.0.113.20:40000)，留空=断开连接: " addr
  addr=$(strip_cr "$addr")
  [[ -n "$addr" ]] || { delete_chain_proxy; return; }
  if ! parse_chain_address "$addr"; then
    echo -e "${RED}B 机地址格式或端口无效。${PLAIN}" >&2
    return 1
  fi

  method="$SS2022_METHOD"
  read -s -p "输入 B 机中继密钥: " password
  echo
  password=$(strip_cr "$password")
  [[ -n "$password" ]] || { echo -e "${RED}SS2022 中继密钥不能为空。${PLAIN}" >&2; return 1; }

  tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json) || return 1
  _CLEANUP_FILES+=("$tmp")
  if ! jq --arg h "$CHAIN_HOST" --arg p "$CHAIN_PORT" --arg method "$method" --arg password "$password" '
    del(.outbounds[] | select(.tag=="chain_proxy")) |
    .outbounds += [{
      "type": "shadowsocks",
      "tag": "chain_proxy",
      "server": $h,
      "server_port": ($p|tonumber),
      "method": $method,
      "password": $password
    }]
  ' "$SB_CONF_FILE" > "$tmp"; then
    echo -e "${RED}SS2022 上游配置生成失败。${PLAIN}" >&2
    return 1
  fi
  if safe_save_config "$tmp"; then
    rm -f "$tmp"
    echo -e "${GREEN}B 机出口连接已保存；请继续选择哪些节点使用该出口。${PLAIN}"
  fi
}

configure_socks5_chain() {
  local addr username password tmp
  echo -e "${YELLOW}SOCKS5 仅为旧配置兼容；公网跨机转发推荐使用 SS2022。${PLAIN}"
  read -p "输入 SOCKS5 出口地址 (如 127.0.0.1:40000)，留空=断开连接: " addr
  addr=$(strip_cr "$addr")
  [[ -n "$addr" ]] || { delete_chain_proxy; return; }
  if ! parse_chain_address "$addr"; then
    echo -e "${RED}SOCKS5 地址格式或端口无效。${PLAIN}" >&2
    return 1
  fi

  read -p "SOCKS5 用户名（无认证请留空）: " username
  username=$(strip_cr "$username")
  password=""
  if [[ -n "$username" ]]; then
    read -s -p "SOCKS5 密码: " password
    echo
    password=$(strip_cr "$password")
  fi

  tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json) || return 1
  _CLEANUP_FILES+=("$tmp")
  if ! jq --arg h "$CHAIN_HOST" --arg p "$CHAIN_PORT" --arg u "$username" --arg pw "$password" '
    del(.outbounds[] | select(.tag=="chain_proxy")) |
    .outbounds += [({
      "type": "socks",
      "tag": "chain_proxy",
      "server": $h,
      "server_port": ($p|tonumber),
      "version": "5"
    } + (if $u != "" then {"username": $u, "password": $pw} else {} end))]
  ' "$SB_CONF_FILE" > "$tmp"; then
    echo -e "${RED}SOCKS5 出口配置生成失败。${PLAIN}" >&2
    return 1
  fi
  if safe_save_config "$tmp"; then
    rm -f "$tmp"
    echo -e "${GREEN}SOCKS5 出口连接已保存。${PLAIN}"
  fi
}

clear_chain_routes() {
  local tmp
  tmp=$(mktemp /tmp/sb_cfg.XXXXXX.json) || return 1
  _CLEANUP_FILES+=("$tmp")
  if ! jq '
    .route.rules = ([.route.rules[]?] | map(select(.outbound? != "chain_proxy")))
  ' "$SB_CONF_FILE" > "$tmp"; then
    echo -e "${RED}默认路由配置生成失败。${PLAIN}" >&2
    return 1
  fi
  ensure_private_reject_rule "$tmp" || return 1
  if safe_save_config "$tmp"; then
    rm -f "$tmp"
    echo -e "${GREEN}所有节点已改回本机出口，出口连接仍保留。${PLAIN}"
  fi
}

chain_proxy_summary() {
  jq -r '.outbounds[]? | select(.tag=="chain_proxy") |
    (if .type == "shadowsocks" then "SS2022" elif .type == "socks" then "SOCKS5 兼容" else .type end) +
    " · " +
    (if (.server | contains(":")) then "[\(.server)]:\(.server_port)" else "\(.server):\(.server_port)" end)
  ' "$SB_CONF_FILE" 2>/dev/null
}

configure_advanced() {
  while true; do
    clear
    echo -e "${BLUE}=== 跨机出口（A → B）===${PLAIN}"
    echo " 用途: 让 A 机上的指定节点从 B 机访问网站"
    echo " 步骤: 先在 B 机选 1，再在 A 机选 4 和 5"
    echo
    local chain relay_count routed_count choice
    chain=$(chain_proxy_summary)
    relay_count=$(jq '[.inbounds[]? | select((.tag // "") | startswith("relay_"))] | length' "$SB_CONF_FILE" 2>/dev/null)
    routed_count=$(jq '[.route.rules[]? | select(.action? == "route" and .outbound? == "chain_proxy") | .inbound[]?] | unique | length' "$SB_CONF_FILE" 2>/dev/null)
    if [[ -n "$chain" ]]; then
      echo -e " 出口连接: ${GREEN}${chain}${PLAIN}"
    else
      echo -e " 出口连接: ${YELLOW}未配置${PLAIN}"
    fi
    echo -e " 使用该出口: ${GREEN}${routed_count:-0} 个节点${PLAIN}"
    echo -e " 本机中继: ${GREEN}${relay_count:-0} 个${PLAIN}"
    echo
    echo " [B 机：提供出口]"
    echo " 1) 创建中继"
    echo " 2) 查看中继连接信息"
    echo " 3) 删除中继"
    echo
    echo " [A 机：使用 B 机出口]"
    echo " 4) 连接、更换或断开 B 机"
    echo " 5) 选择要走 B 机的节点"
    echo " 6) 所有节点改回本机出口（保留连接）"
    echo
    echo " [兼容功能]"
    echo " 7) 配置旧 SOCKS5 出口"
    echo " 0) 返回"
    echo "----------------------------------------"
    read -p "请选择: " choice
    choice=$(strip_cr "$choice")
    case "$choice" in
      1) run_menu_action "创建 SS2022 专用中继" create_ss2022_relay; read -p "按回车继续..." ;;
      2)
        list_ss2022_relays
        if [[ "$_RELAY_COUNT" -gt 0 ]]; then
          read -p "输入中继 ID 查看连接信息 (0 返回): " choice
          choice=$(strip_cr "$choice")
          if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "$_RELAY_COUNT" ]]; then
            show_ss2022_relay_info "$(get_relay_tag_by_id "$choice")"
          fi
        fi
        read -p "按回车继续..." ;;
      3) run_menu_action "删除 SS2022 中继" delete_ss2022_relay; read -p "按回车继续..." ;;
      4) run_menu_action "连接 B 机出口" configure_ss2022_chain; read -p "按回车继续..." ;;
      5) run_menu_action "选择节点出口" manage_node_forwarding; read -p "按回车继续..." ;;
      6) run_menu_action "节点改回本机出口" clear_chain_routes; read -p "按回车继续..." ;;
      7) run_menu_action "配置 SOCKS5 兼容出口" configure_socks5_chain; read -p "按回车继续..." ;;
      0) return ;;
    esac
  done
}

update_script() {
  echo -e "${BLUE}>>> 更新脚本...${PLAIN}"
  local tmp
  tmp=$(mktemp "${INSTALL_PATH}.update.XXXXXX") || {
    echo -e "${RED}无法创建更新临时文件，现有脚本未被覆盖。${PLAIN}" >&2
    return 1
  }
  _CLEANUP_FILES+=("$tmp")

  if ! curl -fsSLo "$tmp" --connect-timeout 8 --max-time 20 "$(fresh_script_url)"; then
    echo -e "${RED}下载失败：${SCRIPT_URL}，现有脚本未被覆盖。${PLAIN}"
    return 1
  fi
  if ! validate_script_candidate "$tmp"; then
    echo -e "${RED}远程脚本格式或 Bash 语法校验失败，现有脚本未被覆盖。${PLAIN}"
    return 1
  fi

  local new_ver
  new_ver=$(grep -E '^SCRIPT_VERSION=' "$tmp" | head -1 | cut -d'"' -f2)
  if version_is_older "$new_ver" "$SCRIPT_VERSION"; then
    echo -e "${RED}拒绝降级：远端 v${new_ver} 低于当前 v${SCRIPT_VERSION}。${PLAIN}" >&2
    return 1
  fi
  if [[ "$new_ver" == "$SCRIPT_VERSION" ]] && cmp -s "$tmp" "$INSTALL_PATH"; then
    echo -e "${GREEN}已是最新版本 (v${SCRIPT_VERSION})。${PLAIN}"
    return 0
  fi
  if [[ "$new_ver" == "$SCRIPT_VERSION" ]]; then
    echo -e "${YELLOW}检测到同版本内容修订，将继续更新。${PLAIN}"
  fi

  if ! chmod 755 "$tmp" || ! mv -f "$tmp" "$INSTALL_PATH"; then
    echo -e "${RED}替换脚本失败，现有脚本保持不变。${PLAIN}" >&2
    return 1
  fi
  echo -e "${GREEN}更新完成：v${SCRIPT_VERSION} -> v${new_ver}${PLAIN}"
  exec "$INSTALL_PATH"
}

uninstall_all() {
  echo -e "${RED}!!! 危险操作：卸载 sing-box + 删除全部配置 !!!${PLAIN}"
  read -p "确认请输入 yes: " cf
  cf=$(strip_cr "$cf")
  [[ "${cf,,}" != "yes" ]] && return

  if systemctl is-active --quiet sing-box 2>/dev/null && ! systemctl stop sing-box; then
    echo -e "${RED}sing-box 停止失败；为避免中继端口在清理防火墙时暴露，已取消卸载。${PLAIN}" >&2
    return 1
  fi

  if [[ -f "$SB_CONF_FILE" ]]; then
    while IFS=$'\t' read -r p proto tag; do
      [[ -n "$p" ]] || continue
      if [[ "$tag" == relay_* ]]; then
        continue
      else
        close_port "$p" "$(network_mode_for_type "$proto")"
      fi
    done < <(jq -r '.inbounds[]? | select(.listen_port != null) | [.listen_port, .type, .tag] | @tsv' "$SB_CONF_FILE" 2>/dev/null)
  fi

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
  init_meta_if_missing || exit 1
  if [[ -x "$SB_BIN" ]]; then
    migrate_route_guard_if_needed || {
      echo -e "${RED}旧版安全路由迁移失败，现有配置未被静默覆盖。${PLAIN}" >&2
      read -p "按回车继续..."
    }
  fi
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
    echo " 6) 跨机出口（A → B）"
    echo " 7) 更新脚本"
    echo " 8) 卸载 sing-box + 删除全部配置"
    echo " 0) 退出"
    echo "----------------------------------------------------------------"
    read -p "请选择: " choice
    choice=$(strip_cr "$choice")

    case "$choice" in
      1) run_menu_action "安装或更新 sing-box" install_singbox; read -p "按回车继续..." ;;
      2) run_menu_action "添加 Reality 节点" add_reality; read -p "按回车继续..." ;;
      3) run_menu_action "添加 Shadowsocks 节点" add_ss2022; read -p "按回车继续..." ;;
      4)
        list_nodes
        read -p "输入节点 ID 查看详情(0返回): " id
        id=$(strip_cr "$id")
        if [[ "$id" =~ ^[0-9]+$ ]] && [[ "$id" -ge 1 ]] && [[ "$id" -le "$_NODE_COUNT" ]]; then
          t=$(get_node_tag_by_id "$id")
          [[ -n "$t" ]] && show_node_info "$t"
        fi
        read -p "按回车继续..." ;;
      5) run_menu_action "删除节点" delete_node; read -p "按回车继续..." ;;
      6) configure_advanced ;;
      7) run_menu_action "更新 sb 管理脚本" update_script ;;
      8) run_menu_action "卸载 sing-box" uninstall_all ;;
      0) exit 0 ;;
    esac
  done
}

check_root
init_meta_if_missing || exit 1
init_config_if_missing || exit 1
main_menu
