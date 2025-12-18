#!/bin/bash
#
# Snell 管理脚本 (纯净版 v2.2)
# - 支持架构：amd64, i386, aarch64, armv7l
# - 自动检测最新版本
# - 不修改任何系统网络参数 (无 BBR/TFO 优化)
# - 无流量监控集成
# - 统一 UI 风格
#
# 用法：sudo bash snell.sh

set -euo pipefail
IFS=$'\n\t'

# =====================================
# 版本配置
# =====================================
SCRIPT_VERSION="2.2.0"
FALLBACK_VERSION="4.1.0"  # Snell v4 目前最稳定，v5 暂无正式 release note
VERSION=""                # 运行时检测

# 脚本更新源
SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/refs/heads/main/snell.sh"

# =====================================
# 颜色和路径
# =====================================
_red() { echo -e "\e[31m$@\e[0m"; }
_green() { echo -e "\e[32m$@\e[0m"; }
_yellow() { echo -e "\e[33m$@\e[0m"; }
_blue_bg() { echo -e "\033[44;37m$@\033[0m"; }
_gray() { echo -e "\033[90m$@\033[0m"; }

SNELL_BIN="/usr/local/bin/snell-server"
SNELL_DIR="/etc/snell"
SNELL_CONF="${SNELL_DIR}/snell-server.conf"
SNELL_CFGTXT="${SNELL_DIR}/config.txt"
SNELL_VERSION_FILE="${SNELL_DIR}/ver.txt"
SYSTEMD_SERVICE="/etc/systemd/system/snell.service"
BACKUP_DIR="/var/backups/snell-manager"
DL_BASE="https://dl.nssurge.com/snell"
SNELL_LOG="/var/log/snell.log"

# =====================================
# 常量定义
# =====================================
readonly PORT_MIN=1
readonly PORT_MAX=65535
readonly RANDOM_PORT_MIN=30000
readonly RANDOM_PORT_MAX=65000
readonly PORT_RETRY_MAX=5
readonly PSK_RANDOM_LENGTH=20
readonly VERSION_CACHE_TIME=3600

# 临时文件
TMP_DOWNLOAD=""
VERSION_CACHE_FILE="/var/tmp/snell_version_cache"

# =====================================
# 临时文件管理
# =====================================
init_temp_files() {
    TMP_DOWNLOAD=$(mktemp /tmp/snell-server.XXXXXX.zip) || {
        echo "无法创建临时文件" >&2
        exit 1
    }
}

cleanup_temp_files() {
    [ -n "$TMP_DOWNLOAD" ] && rm -f "$TMP_DOWNLOAD"
}

trap cleanup_temp_files EXIT INT TERM

# =====================================
# 日志函数
# =====================================
log()    { echo -e "${GREEN}[INFO]${RESET} $*"; } # 保留旧调用兼容
warn()   { echo -e "\e[33m[WARN]\e[0m $*"; }
err()    { echo -e "\n\e[41m 错误 \e[0m $@\n" >&2; exit 1; }

# =====================================
# 系统检查
# =====================================
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "请以 root 身份运行此脚本。"
  fi
}

check_snell_installed() {
  local exit_on_fail="${1:-true}"
  if [ ! -f "$SNELL_BIN" ]; then
    if [ "$exit_on_fail" = "true" ]; then
        _yellow "Snell 未安装"
        return 1
    fi
    return 1
  fi
  return 0
}

check_snell_configured() {
  if [ ! -f "$SNELL_CONF" ]; then
    _yellow "未检测到配置文件"
    return 1
  fi
  return 0
}

ensure_cmd() {
  local cmd="$1"; local pkg="${2:-$1}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    _yellow "缺少命令：$cmd，尝试自动安装..."
    if [ -f /etc/debian_version ]; then
        apt-get update -y >/dev/null && apt-get install -y "$pkg" >/dev/null
    elif [ -f /etc/redhat-release ]; then
        yum -y install "$pkg" >/dev/null
    else
        err "无法自动安装 $cmd，请手动安装。"
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
# 版本检测
# =====================================
get_latest_version_from_web() {
  # 优先从 Knowledge Base 页面获取
  local kb_page="https://kb.nssurge.com/surge-knowledge-base/release-notes/snell"
  local page_content
  page_content=$(curl -s -L --max-time 10 "$kb_page" 2>/dev/null)
  
  if [ -n "$page_content" ]; then
    local latest_version
    # 优化正则匹配 v4/v5 版本
    latest_version=$(echo "$page_content" | grep -oE 'snell-server-v[0-9]+\.[0-9]+\.[0-9]+-linux' | \
      sed 's/snell-server-v//g; s/-linux//g' | sort -V | tail -1)
    
    if [ -n "$latest_version" ]; then
      echo "$latest_version"
      return 0
    fi
  fi
  
  # 备用：DL 页面
  local dl_page="https://dl.nssurge.com/snell/"
  page_content=$(curl -s -L --max-time 10 "$dl_page" 2>/dev/null)
  if [ -n "$page_content" ]; then
    local latest_version
    latest_version=$(echo "$page_content" | grep -oE 'snell-server-v[0-9]+\.[0-9]+\.[0-9]+-linux' | \
      sed 's/snell-server-v//g; s/-linux//g' | sort -V | tail -1)
    if [ -n "$latest_version" ]; then
      echo "$latest_version"
      return 0
    fi
  fi
  return 1
}

detect_latest_version() {
  local silent="${1:-}"
  local current_time; current_time=$(date +%s)

  # 检查缓存
  if [ -f "$VERSION_CACHE_FILE" ]; then
    local cache_timestamp; cache_timestamp=$(head -1 "$VERSION_CACHE_FILE" 2>/dev/null || echo "0")
    local cached_version; cached_version=$(sed -n '2p' "$VERSION_CACHE_FILE" 2>/dev/null || echo "")

    if [ -n "$cache_timestamp" ] && [ -n "$cached_version" ]; then
      if [ $((current_time - cache_timestamp)) -lt "$VERSION_CACHE_TIME" ]; then
        VERSION="$cached_version"
        return 0
      fi
    fi
  fi

  [ "$silent" != "silent" ] && echo "正在检测最新版本..."
  local web_version
  web_version=$(get_latest_version_from_web) || web_version=""

  if [ -n "$web_version" ]; then
    VERSION="$web_version"
    echo "$current_time" > "$VERSION_CACHE_FILE"
    echo "$VERSION" >> "$VERSION_CACHE_FILE"
    [ "$silent" != "silent" ] && _green "检测到最新版本: v${VERSION}"
    return 0
  fi

  VERSION="$FALLBACK_VERSION"
  [ "$silent" != "silent" ] && warn "无法获取最新版本，使用后备版本: v${VERSION}"
  return 0
}

get_installed_version() {
  if [ -f "$SNELL_VERSION_FILE" ]; then
    cat "$SNELL_VERSION_FILE" | sed 's/^v//'
  else
    echo ""
  fi
}

compare_versions() {
  local v1="$1" v2="$2"
  v1=$(echo "$v1" | sed 's/^v//')
  v2=$(echo "$v2" | sed 's/^v//')
  if [ "$v1" = "$v2" ]; then return 0; fi
  local smaller
  smaller=$(printf '%s\n%s' "$v1" "$v2" | sort -V | head -n1)
  if [ "$smaller" = "$v1" ]; then return 2; else return 1; fi
}

# =====================================
# 端口验证与防火墙
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
    return 0 # 无法检测则假设空闲
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
# 辅助函数
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

get_ip() {
  local ip
  ip=$(curl -s4m5 ip.sb 2>/dev/null || curl -s4m5 api.ipify.org 2>/dev/null)
  if [ -z "$ip" ]; then
    ip="<服务器IP>"
  fi
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
  # tfo=true 参数保留，指示客户端尝试TFO连接
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
  detect_latest_version || return 1
  echo
  _green ">>> 安装 Snell v${VERSION} ..."
  
  ensure_cmd wget wget
  ensure_cmd unzip unzip
  ensure_cmd curl curl
  
  local arch; arch=$(map_arch)
  [ "$arch" = "unsupported" ] && err "不支持的架构"

  # 交互输入
  local default_name; default_name=$(uname -n)
  read -rp "请输入节点名称 [${default_name}]: " node_name
  node_name=${node_name:-$default_name}

  local port
  port=$(shuf -i "$RANDOM_PORT_MIN"-"$RANDOM_PORT_MAX" -n 1)
  read -rp "请输入端口 [${port}]: " user_port
  port=${user_port:-$port}
  
  if ! is_valid_port "$port"; then _yellow "端口无效"; return 1; fi
  if ! is_port_free "$port"; then _yellow "端口被占用"; return 1; fi

  # 下载
  local url="${DL_BASE}/snell-server-v${VERSION}-linux-${arch}.zip"
  echo "下载: $url"
  if ! wget -q -O "$TMP_DOWNLOAD" "$url"; then
    err "下载失败"
  fi
  
  if ! unzip -o "$TMP_DOWNLOAD" -d /usr/local/bin >/dev/null 2>&1; then
    err "解压失败"
  fi
  rm -f "$TMP_DOWNLOAD"
  chmod +x "$SNELL_BIN"

  # 安装脚本自身
  local script_path; script_path=$(realpath "$0")
  if [[ "$script_path" != "/usr/local/bin/snell-manager.sh" ]]; then
     cp "$script_path" "/usr/local/bin/snell-manager.sh"
     chmod +x "/usr/local/bin/snell-manager.sh"
     ln -sf "/usr/local/bin/snell-manager.sh" /usr/local/bin/snell
  fi

  # 用户与日志
  if ! id -u snell >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin snell || true
  fi
  mkdir -p "$(dirname "$SNELL_LOG")"
  touch "$SNELL_LOG"
  chown snell:snell "$SNELL_LOG" 2>/dev/null || true

  # 配置
  local psk; psk=$(generate_psk)
  mkdir -p "$SNELL_DIR"
  echo "$node_name" > "${SNELL_DIR}/node_name.txt"
  echo "v${VERSION}" > "$SNELL_VERSION_FILE"
  
  # 配置文件
  cat > "$SNELL_CONF" <<EOF
[snell-server]
listen = ::0:${port}
psk = ${psk}
ipv6 = true
tfo = true
EOF
  chown -R snell:snell "$SNELL_DIR" 2>/dev/null || true
  chmod 640 "$SNELL_CONF"

  # Systemd
  cat > "$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=Snell Proxy Service
After=network.target

[Service]
Type=simple
User=snell
Group=snell
LimitNOFILE=32768
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
  
  snell_service_control reload
  snell_service_control enable
  snell_service_control start

  echo
  _green "安装完成!"
  echo
  echo "=== Surge 配置 ==="
  cat "$SNELL_CFGTXT"
  echo
}

update_snell() {
  check_snell_installed || return 1
  force_detect_version() { rm -f "$VERSION_CACHE_FILE"; detect_latest_version; }
  force_detect_version
  
  local installed_ver; installed_ver=$(get_installed_version)
  echo "当前: v${installed_ver}  最新: v${VERSION}"
  
  if [ "$installed_ver" = "$VERSION" ]; then
    read -rp "已是最新，是否强制重装? [y/N]: " confirm
    [[ "${confirm,,}" != "y" ]] && return 0
  else
    read -rp "确认更新? [Y/n]: " confirm
    [[ "${confirm,,}" == "n" ]] && return 0
  fi
  
  _green "正在更新..."
  local arch; arch=$(map_arch)
  local url="${DL_BASE}/snell-server-v${VERSION}-linux-${arch}.zip"
  
  snell_service_control stop
  if ! wget -q -O "$TMP_DOWNLOAD" "$url"; then
    snell_service_control start
    err "下载失败"
  fi
  
  if ! unzip -o "$TMP_DOWNLOAD" -d /usr/local/bin >/dev/null 2>&1; then
    snell_service_control start
    err "解压失败"
  fi
  rm -f "$TMP_DOWNLOAD"
  chmod +x "$SNELL_BIN"
  echo "v${VERSION}" > "$SNELL_VERSION_FILE"
  
  snell_service_control start
  _green "更新成功"
}

uninstall_snell() {
  check_snell_installed || return 1
  read -rp "确认卸载 Snell? [y/N]: " confirm
  [[ "${confirm,,}" != "y" ]] && return 0
  
  local port; port=$(read_snell_port)
  snell_service_control stop
  snell_service_control disable
  rm -f "$SYSTEMD_SERVICE"
  rm -f "$SNELL_BIN"
  rm -rf "$SNELL_DIR"
  snell_service_control reload
  
  [ -n "$port" ] && firewall_remove_port "$port"
  rm -f "$VERSION_CACHE_FILE"
  _green "Snell 已卸载"
}

# =====================================
# 菜单逻辑
# =====================================
show_config_info() {
    if [ ! -f "$SNELL_CONF" ]; then
        _yellow "未找到配置"
        return
    fi
    local port; port=$(read_snell_port)
    local psk; psk=$(read_snell_psk)
    local name; name=$(read_node_name)
    echo
    echo "配置名称: $name"
    echo "监听端口: $port"
    echo "PSK 密钥: $psk"
    echo
    echo "=== Surge 字符串 ==="
    cat "$SNELL_CFGTXT" 2>/dev/null
    echo
}

pause_return() { echo; read -rp "按回车返回..."; }

menu() {
  while true; do
    clear
    local installed_ver; installed_ver=$(get_installed_version)
    local status_text
    if snell_service_control status 2>/dev/null; then
        status_text="$(_green "运行中")"
    else
        status_text="$(_red "未运行")"
    fi
    
    echo
    echo -e " $(_blue_bg "          Snell 管理面板 $SCRIPT_VERSION           ")"
    echo
    echo -e " 🟢 运行状态"
    echo " ------------------------------------------------"
    echo -e "  服务状态: $status_text        版本: ${installed_ver:-$(_red "未安装")}"
    echo

    echo -e " ⚙️  配置管理"
    echo " ------------------------------------------------"
    echo -e "  1. 安装 Snell $(_green "+")         2. 卸载 Snell 🗑️"
    echo -e "  3. 查看配置 👁️          4. 更新核心 🆙"
    echo

    echo -e " 🚀 服务控制"
    echo " ------------------------------------------------"
    echo -e "  5. 启动服务 ▶️          6. 停止服务 ⏹️"
    echo -e "  7. 重启服务 🔄          8. 查看日志 📜"
    echo

    echo -e " 🛠️  其他选项"
    echo " ------------------------------------------------"
    echo -e "  9. 修改配置 (端口/PSK)  10. 更新脚本 🔄"
    echo
    echo " ------------------------------------------------"
    echo "  0. 退出"
    echo
    read -rp " 请输入序号: " pick
    case "$pick" in
        1) install_snell; pause_return ;;
        2) uninstall_snell; pause_return ;;
        3) show_config_info; pause_return ;;
        4) update_snell; pause_return ;;
        5) snell_service_control start; pause_return ;;
        6) snell_service_control stop; pause_return ;;
        7) snell_service_control restart; pause_return ;;
        8) tail -n 50 "$SNELL_LOG"; pause_return ;;
        9) 
           read -rp "修改端口(1) 或 PSK(2)? " sub
           if [[ "$sub" == "1" ]]; then
              read -rp "新端口: " np
              sed -i -E "s/listen = .*:[0-9]+/listen = ::0:$np/" "$SNELL_CONF"
              firewall_allow_port "$np"
              update_config_txt "$np"
              snell_service_control restart
              _green "端口已修改"
           elif [[ "$sub" == "2" ]]; then
              read -rp "新PSK: " npsk
              sed -i "s/psk = .*/psk = $npsk/" "$SNELL_CONF"
              update_config_txt "" "$npsk"
              snell_service_control restart
              _green "PSK 已修改"
           fi
           pause_return
           ;;
        10) 
           wget -q -O /usr/local/bin/snell-manager.sh "$SCRIPT_URL"
           chmod +x /usr/local/bin/snell-manager.sh
           _green "脚本已更新"
           sleep 1; exit 0
           ;;
        0) exit 0 ;;
        *) ;;
    esac
  done
}

# 命令行入口
if [ -n "${1:-}" ]; then
    case "$1" in
        start|stop|restart|status) snell_service_control "$1" ;;
        install) install_snell ;;
        *) menu ;;
    esac
else
    menu
fi