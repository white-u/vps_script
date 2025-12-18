#!/bin/bash
#
# Snell 管理脚本 (增强版 v2.4)
# - 引入网络重试机制 (借鉴 sing-box.sh)
# - 优化系统资源限制
# - 配置文件修改自动备份
#
# 用法：sudo bash snell.sh

set -euo pipefail
IFS=$'\n\t'

# =====================================
# 版本配置
# =====================================
SCRIPT_VERSION="2.4.0"
FALLBACK_VERSION="4.1.0"
VERSION=""

# 脚本更新源
SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/refs/heads/main/snell.sh"

# =====================================
# 颜色和路径
# =====================================
_red() { echo -e "\e[31m$@\e[0m"; }
_green() { echo -e "\e[32m$@\e[0m"; }
_yellow() { echo -e "\e[33m$@\e[0m"; }
_blue_bg() { echo -e "\033[44;37m$@\033[0m"; }

SNELL_BIN="/usr/local/bin/snell-server"
SNELL_DIR="/etc/snell"
SNELL_CONF="${SNELL_DIR}/snell-server.conf"
SNELL_CFGTXT="${SNELL_DIR}/config.txt"
SNELL_VERSION_FILE="${SNELL_DIR}/ver.txt"
SYSTEMD_SERVICE="/etc/systemd/system/snell.service"
DL_BASE="https://dl.nssurge.com/snell"
SNELL_LOG="/var/log/snell.log"

# 临时文件
TMP_DOWNLOAD="/tmp/snell-install.zip"
VERSION_CACHE_FILE="/var/tmp/snell_version_cache"

# =====================================
# 常量定义
# =====================================
readonly PORT_MIN=1
readonly PORT_MAX=65535
readonly RANDOM_PORT_MIN=30000
readonly RANDOM_PORT_MAX=65000
readonly PSK_RANDOM_LENGTH=20
readonly VERSION_CACHE_TIME=3600

# 网络重试配置 (借鉴 sing-box.sh)
readonly CURL_MAX_RETRIES=3
readonly CURL_RETRY_DELAY=2
readonly WGET_MAX_RETRIES=3
readonly WGET_RETRY_DELAY=2

# =====================================
# 辅助函数
# =====================================
cleanup_temp_files() {
    rm -f "$TMP_DOWNLOAD"
}
trap cleanup_temp_files EXIT INT TERM

check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "\n\e[41m 错误 \e[0m 请以 root 身份运行此脚本\n" >&2
    exit 1
  fi
}

ensure_dependencies() {
    local missing_deps=0
    for cmd in curl unzip; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing_deps=1
            break
        fi
    done

    if [ $missing_deps -eq 1 ]; then
        echo "正在安装依赖 (curl, unzip)..."
        if [ -f /etc/debian_version ]; then
            apt-get update -y >/dev/null && apt-get install -y curl unzip >/dev/null
        elif [ -f /etc/redhat-release ]; then
            yum -y install curl unzip >/dev/null
        elif [ -f /etc/alpine-release ]; then
            apk add --no-cache curl unzip >/dev/null
        else
            _yellow "无法自动安装依赖，请手动安装: curl unzip"
        fi
    fi
}

map_arch() {
  local m; m=$(uname -m)
  case "$m" in
    x86_64|amd64) echo "amd64" ;;
    i386|i686)    echo "i386" ;;
    aarch64)      echo "aarch64" ;;
    armv7l)       echo "armv7l" ;;
    *) echo "unsupported" ;;
  esac
}

# =====================================
# 网络请求 (增强稳定性)
# =====================================
curl_retry() {
    local attempt=1
    while [ $attempt -le "$CURL_MAX_RETRIES" ]; do
        if curl -L -f --progress-bar "$@"; then return 0; fi
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
        if wget --no-check-certificate "$@"; then return 0; fi
        if [ $attempt -lt "$WGET_MAX_RETRIES" ]; then
            _yellow "wget 请求失败，${WGET_RETRY_DELAY}秒后重试 ($attempt/$WGET_MAX_RETRIES)..."
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

# =====================================
# 版本检测
# =====================================
get_latest_version_from_web() {
  local kb_page="https://kb.nssurge.com/surge-knowledge-base/release-notes/snell"
  local content
  # 增加重试机制
  content=$(curl -sL --retry 2 --max-time 10 "$kb_page" 2>/dev/null || true)
  
  if [ -n "$content" ]; then
    echo "$content" | grep -oE 'snell-server-v[0-9]+\.[0-9]+\.[0-9]+-linux' | \
      sed 's/snell-server-v//g; s/-linux//g' | sort -V | tail -1
  fi
}

detect_latest_version() {
  local current_time; current_time=$(date +%s)
  
  if [ -f "$VERSION_CACHE_FILE" ]; then
    local cache_time; cache_time=$(head -1 "$VERSION_CACHE_FILE" 2>/dev/null || echo "0")
    local cache_ver; cache_ver=$(sed -n '2p' "$VERSION_CACHE_FILE" 2>/dev/null || echo "")
    if [ $((current_time - cache_time)) -lt "$VERSION_CACHE_TIME" ] && [ -n "$cache_ver" ]; then
        VERSION="$cache_ver"
        return 0
    fi
  fi

  echo "正在检测最新版本..."
  local web_ver
  web_ver=$(get_latest_version_from_web)
  
  if [ -n "$web_ver" ]; then
    VERSION="$web_ver"
    echo "$current_time" > "$VERSION_CACHE_FILE"
    echo "$VERSION" >> "$VERSION_CACHE_FILE"
    _green "检测到最新版本: v${VERSION}"
  else
    VERSION="$FALLBACK_VERSION"
    _yellow "无法获取最新版本，使用后备版本: v${VERSION}"
  fi
}

get_installed_version() {
  if [ -f "$SNELL_VERSION_FILE" ]; then
    cat "$SNELL_VERSION_FILE" | sed 's/^v//'
  elif [ -f "$SNELL_BIN" ]; then
    echo "未知"
  else
    echo ""
  fi
}

# =====================================
# 端口与防火墙
# =====================================
is_valid_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  [ "$p" -ge "$PORT_MIN" ] && [ "$p" -le "$PORT_MAX" ]
}

is_port_free() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ! ss -lnt "( sport = :$port )" | awk 'NR>1{print}' | grep -q .
  elif command -v lsof >/dev/null 2>&1; then
    ! lsof -iTCP -sTCP:LISTEN -P | grep -w ":$port" >/dev/null 2>&1
  else
    return 0 
  fi
}

firewall_allow_port() {
  local port="$1"
  if command -v ufw >/dev/null 2>&1; then
    if ! ufw status | grep -q inactive; then
      ufw allow "$port"/tcp >/dev/null 2>&1 || true
      ufw allow "$port"/udp >/dev/null 2>&1 || true
    fi
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

firewall_remove_port() {
  local port="$1"
  if command -v ufw >/dev/null 2>&1; then
    if ! ufw status | grep -q inactive; then
      ufw delete allow "$port"/tcp >/dev/null 2>&1 || true
      ufw delete allow "$port"/udp >/dev/null 2>&1 || true
    fi
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --remove-port="${port}/udp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

# =====================================
# 配置管理
# =====================================
read_snell_port() {
  [ -f "$SNELL_CONF" ] && grep -E '^listen' "$SNELL_CONF" 2>/dev/null | head -n1 | sed -E 's/.*:([0-9]+)$/\1/' || echo ""
}

read_snell_psk() {
  [ -f "$SNELL_CONF" ] && grep -E '^psk' "$SNELL_CONF" 2>/dev/null | head -n1 | awk -F'=' '{print $2}' | xargs || echo ""
}

read_node_name() {
  [ -f "${SNELL_DIR}/node_name.txt" ] && cat "${SNELL_DIR}/node_name.txt" || uname -n
}

# 优化 IP 获取，增加超时控制
get_ip() {
  local ip
  ip=$(curl -s4m3 ip.sb 2>/dev/null || curl -s4m3 api.ipify.org 2>/dev/null || echo "<服务器IP>")
  echo "$ip"
}

generate_psk() {
  tr -dc A-Za-z0-9 </dev/urandom 2>/dev/null | head -c "$PSK_RANDOM_LENGTH" || echo "psk$(date +%s)"
}

update_config_txt() {
  local port="${1:-$(read_snell_port)}"
  local psk="${2:-$(read_snell_psk)}"
  local node_name="${3:-$(read_node_name)}"
  local ip=$(get_ip)
  cat > "$SNELL_CFGTXT" <<EOF
${node_name} = snell, ${ip}, ${port}, psk=${psk}, version=5, tfo=true, reuse=true, ecn=true
EOF
}

# =====================================
# 服务管理
# =====================================
snell_service_control() {
  local action="$1"
  local show_log="${2:-true}"
  case "$action" in
    start)
      systemctl start snell
      [ "$show_log" = "true" ] && { systemctl is-active --quiet snell && _green "Snell 已启动" || _red "启动失败"; }
      ;;
    stop)
      systemctl stop snell 2>/dev/null
      [ "$show_log" = "true" ] && _green "Snell 已停止"
      ;;
    restart)
      systemctl restart snell
      sleep 1
      [ "$show_log" = "true" ] && { systemctl is-active --quiet snell && _green "Snell 已重启" || _red "重启失败"; }
      ;;
    reload) systemctl daemon-reload ;;
    enable) systemctl enable snell >/dev/null 2>&1 ;;
    disable) systemctl disable snell >/dev/null 2>&1 ;;
    status) systemctl is-active --quiet snell; return $? ;;
  esac
}

# =====================================
# 核心功能
# =====================================
install_snell() {
  ensure_dependencies
  detect_latest_version || return 1
  
  local arch; arch=$(map_arch)
  if [ "$arch" = "unsupported" ]; then
    echo -e "\n\e[41m 错误 \e[0m 不支持的架构: $(uname -m)\n" >&2
    exit 1
  fi

  echo
  _green ">>> 准备安装 Snell v${VERSION} (${arch})"
  
  local default_name; default_name=$(uname -n)
  read -rp "请输入节点名称 [${default_name}]: " node_name
  node_name=${node_name:-$default_name}

  local port
  port=$(shuf -i "$RANDOM_PORT_MIN"-"$RANDOM_PORT_MAX" -n 1)
  read -rp "请输入端口 [${port}]: " user_port
  port=${user_port:-$port}
  
  if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
     _red "错误: 端口无效"
     return 1
  fi

  if ! is_port_free "$port"; then _yellow "错误: 端口被占用"; return 1; fi

  # 下载
  local url="${DL_BASE}/snell-server-v${VERSION}-linux-${arch}.zip"
  rm -f "$TMP_DOWNLOAD"
  
  if ! download_file "$url" "$TMP_DOWNLOAD"; then
      echo
      _red "错误: 下载失败"
      echo "请检查网络，或尝试访问: $url"
      return 1
  fi
  
  if ! unzip -t "$TMP_DOWNLOAD" >/dev/null 2>&1; then
      _red "错误: 文件校验失败"
      return 1
  fi
  
  systemctl stop snell 2>/dev/null || true

  if ! unzip -o "$TMP_DOWNLOAD" -d /usr/local/bin >/dev/null; then
      _red "错误: 解压失败"
      return 1
  fi
  chmod +x "$SNELL_BIN"

  if ! id -u snell >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin snell || true
  fi
  mkdir -p "$(dirname "$SNELL_LOG")"
  touch "$SNELL_LOG"
  chown snell:snell "$SNELL_LOG" 2>/dev/null || true

  # 配置
  local psk
  psk=$(generate_psk)
  
  mkdir -p "$SNELL_DIR"
  echo "$node_name" > "${SNELL_DIR}/node_name.txt"
  echo "v${VERSION}" > "$SNELL_VERSION_FILE"
  
  # 备份旧配置 (如果存在)
  if [ -f "$SNELL_CONF" ]; then
      cp "$SNELL_CONF" "${SNELL_CONF}.bak"
  fi

  cat > "$SNELL_CONF" <<EOF
[snell-server]
listen = ::0:${port}
psk = ${psk}
ipv6 = true
tfo = true
EOF
  chown -R snell:snell "$SNELL_DIR" 2>/dev/null || true
  chmod 640 "$SNELL_CONF"

  # Systemd (优化 LimitNOFILE)
  cat > "$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=Snell Proxy Service
After=network.target

[Service]
Type=simple
User=snell
Group=snell
LimitNOFILE=1048576
ExecStart=${SNELL_BIN} -c ${SNELL_CONF}
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
Restart=on-failure
RestartSec=5s
StandardOutput=append:${SNELL_LOG}
StandardError=append:${SNELL_LOG}
SyslogIdentifier=snell-server

[Install]
WantedBy=multi-user.target
EOF

  firewall_allow_port "$port"
  update_config_txt "$port" "$psk" "$node_name"
  
  systemctl daemon-reload
  systemctl enable snell >/dev/null 2>&1
  systemctl start snell

  echo
  _green "安装完成!"
  echo
  echo "=== Surge 配置 ==="
  cat "$SNELL_CFGTXT"
  echo
}

# =====================================
# 其他功能
# =====================================
uninstall_snell() {
  read -rp "确认卸载? [y/N]: " confirm
  [[ "${confirm,,}" != "y" ]] && return 0
  
  systemctl stop snell 2>/dev/null || true
  systemctl disable snell 2>/dev/null || true
  rm -f "$SYSTEMD_SERVICE" "$SNELL_BIN"
  rm -rf "$SNELL_DIR"
  systemctl daemon-reload
  rm -f "$VERSION_CACHE_FILE"
  _green "Snell 已卸载"
}

update_snell() {
  if [ ! -f "$SNELL_BIN" ]; then _yellow "未安装 Snell"; return 1; fi
  rm -f "$VERSION_CACHE_FILE"
  detect_latest_version
  local installed; installed=$(get_installed_version)
  
  if [ "$installed" == "$VERSION" ]; then
     read -rp "已是最新版 (v$installed)，强制重装? [y/N]: " cf
     [[ "${cf,,}" != "y" ]] && return 0
  fi
  
  _green "正在更新 v$installed -> v$VERSION ..."
  systemctl stop snell 2>/dev/null || true
  
  local arch; arch=$(map_arch)
  local url="${DL_BASE}/snell-server-v${VERSION}-linux-${arch}.zip"
  
  if download_file "$url" "$TMP_DOWNLOAD" && unzip -o "$TMP_DOWNLOAD" -d /usr/local/bin >/dev/null; then
      chmod +x "$SNELL_BIN"
      echo "v${VERSION}" > "$SNELL_VERSION_FILE"
      systemctl start snell
      _green "更新成功"
  else
      _red "更新失败"
      systemctl start snell 
  fi
}

show_config_info() {
    if [ ! -f "$SNELL_CFGTXT" ]; then _yellow "未找到配置"; return; fi
    echo; cat "$SNELL_CFGTXT"; echo
}

# =====================================
# 菜单
# =====================================
pause_return() { echo; read -rp "按回车返回..."; }

menu() {
  while true; do
    clear
    local installed_ver; installed_ver=$(get_installed_version)
    local status_text="$(_red "未运行")"
    if systemctl is-active --quiet snell 2>/dev/null; then status_text="$(_green "运行中")"; fi
    
    echo
    echo -e " $(_blue_bg "          Snell 管理面板 $SCRIPT_VERSION           ")"
    echo
    echo -e "  状态: $status_text        版本: ${installed_ver:-$(_red "未安装")}"
    echo
    echo -e "  1. 安装 Snell $(_green "+")         2. 卸载 Snell 🗑️"
    echo -e "  3. 查看配置 👁️          4. 更新核心 🆙"
    echo -e "  5. 启动服务 ▶️          6. 停止服务 ⏹️"
    echo -e "  7. 重启服务 🔄          8. 查看日志 📜"
    echo -e "  9. 更新脚本 🔄          0. 退出"
    echo
    read -rp " 请输入序号: " pick
    case "$pick" in
        1) install_snell; pause_return ;;
        2) uninstall_snell; pause_return ;;
        3) show_config_info; pause_return ;;
        4) update_snell; pause_return ;;
        5) systemctl start snell; _green "已执行启动"; pause_return ;;
        6) systemctl stop snell; _green "已执行停止"; pause_return ;;
        7) systemctl restart snell; _green "已执行重启"; pause_return ;;
        8) tail -n 50 "$SNELL_LOG"; pause_return ;;
        9) 
           if download_file "$SCRIPT_URL" "/usr/local/bin/snell-manager.sh"; then
              chmod +x /usr/local/bin/snell-manager.sh
              _green "脚本已更新，请重新运行"
              exit 0
           else
              _red "脚本更新失败"
              pause_return
           fi
           ;;
        0) exit 0 ;;
        *) ;;
    esac
  done
}

if [ -n "${1:-}" ]; then
    case "$1" in
        start|stop|restart|status) systemctl "$1" snell ;;
        install) install_snell ;;
        *) menu ;;
    esac
else
    menu
fi