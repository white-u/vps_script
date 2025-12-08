#!/usr/bin/env bash
#
# Snell 管理脚本（增强版）
# - 支持架构：amd64, i386, aarch64, armv7l
# - 安装时可手动输入端口（回车使用随机端口）
# - 自动在 ufw/firewalld 放行端口（并在修改时回收旧端口）
# - 自动检测最新版本（从官网获取）
# - TCP Fast Open + BBR 网络优化
# - 支持更新/备份/回滚/配置校验/显示 port & psk
#
# 用法：以 root 运行
#   chmod +x snell-manager.sh
#   sudo ./snell-manager.sh

set -euo pipefail
IFS=$'\n\t'

# =====================================
# 版本配置
# =====================================
SCRIPT_VERSION="1.0.0"
FALLBACK_VERSION="5.0.1"  # 后备版本（无法获取最新版时使用）
VERSION=""                # 运行时检测

# 脚本更新源（请根据实际托管地址修改）
SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/refs/heads/main/snell.sh"

# =====================================
# 常量定义
# =====================================
# 端口范围
readonly PORT_MIN=1
readonly PORT_MAX=65535
readonly RANDOM_PORT_MIN=30000
readonly RANDOM_PORT_MAX=65000

# 端口冲突重试次数（用户要求保持 5 次）
readonly PORT_RETRY_MAX=5

# PSK 长度要求
readonly PSK_MIN_LENGTH=8
readonly PSK_RANDOM_LENGTH=20

# 网络请求配置
readonly CURL_MAX_RETRIES=3
readonly CURL_RETRY_DELAY=2
readonly WGET_MAX_RETRIES=3
readonly WGET_RETRY_DELAY=2
readonly NETWORK_TIMEOUT=10

# 版本缓存时间（秒）
readonly VERSION_CACHE_TIME=3600

# =====================================
# 颜色和路径
# =====================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

SNELL_BIN="/usr/local/bin/snell-server"
SNELL_DIR="/etc/snell"
SNELL_CONF="${SNELL_DIR}/snell-server.conf"
SNELL_CFGTXT="${SNELL_DIR}/config.txt"
SNELL_VERSION_FILE="${SNELL_DIR}/ver.txt"
SYSTEMD_SERVICE="/etc/systemd/system/snell.service"
SYSCTL_CONF="/etc/sysctl.d/99-snell.conf"
BACKUP_DIR="/var/backups/snell-manager"
DL_BASE="https://dl.nssurge.com/snell"
SNELL_LOG="/var/log/snell.log"

# 临时文件（将在脚本初始化时创建）
TMP_DOWNLOAD=""
VERSION_CACHE_FILE=""

# =====================================
# 临时文件管理
# =====================================
init_temp_files() {
    TMP_DOWNLOAD=$(mktemp /tmp/snell-server.XXXXXX.zip) || {
        echo "无法创建临时文件" >&2
        exit 1
    }
    VERSION_CACHE_FILE=$(mktemp /tmp/snell_version_cache.XXXXXX) || {
        echo "无法创建临时文件" >&2
        exit 1
    }
}

cleanup_temp_files() {
    [ -n "$TMP_DOWNLOAD" ] && rm -f "$TMP_DOWNLOAD"
    [ -n "$VERSION_CACHE_FILE" ] && rm -f "$VERSION_CACHE_FILE"
}

# 设置清理陷阱
trap cleanup_temp_files EXIT INT TERM

# =====================================
# 日志函数
# =====================================
log()    { echo -e "${GREEN}[INFO]${RESET} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err()    { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

# =====================================
# 模块加载
# =====================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="https://raw.githubusercontent.com/white-u/vps_script/main"

load_system_optimize_module() {
    local module_file="${SCRIPT_DIR}/system-optimize.sh"

    # 如果已经加载过，直接返回
    if type enable_network_optimization >/dev/null 2>&1; then
        return 0
    fi

    # 本地存在，直接加载
    if [ -f "$module_file" ]; then
        if source "$module_file" 2>/dev/null; then
            return 0
        fi
    fi

    # 本地不存在或加载失败，尝试下载
    warn "system-optimize.sh 模块未找到，尝试自动下载..."

    # 尝试使用 curl 下载
    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL "${REPO_URL}/system-optimize.sh" -o "$module_file" 2>/dev/null; then
            chmod +x "$module_file"
            if [ -s "$module_file" ] && source "$module_file" 2>/dev/null; then
                log "system-optimize.sh 模块下载并加载成功"
                return 0
            fi
        fi
    fi

    # 尝试使用 wget 下载
    if command -v wget >/dev/null 2>&1; then
        if wget -q "${REPO_URL}/system-optimize.sh" -O "$module_file" 2>/dev/null; then
            chmod +x "$module_file"
            if [ -s "$module_file" ] && source "$module_file" 2>/dev/null; then
                log "system-optimize.sh 模块下载并加载成功"
                return 0
            fi
        fi
    fi

    # 下载失败，清理并返回错误
    [ -f "$module_file" ] && rm -f "$module_file"
    warn "无法加载 system-optimize.sh 模块，将使用内置功能"
    warn "提示：如需完整功能，请手动下载模块文件："
    warn "  curl -O ${REPO_URL}/system-optimize.sh"
    return 1
}

# =====================================
# 网络请求重试辅助函数
# =====================================
# curl 带重试机制
curl_retry() {
  local attempt=1

  while [ $attempt -le "$CURL_MAX_RETRIES" ]; do
    if curl "$@"; then
      return 0
    fi
    if [ $attempt -lt "$CURL_MAX_RETRIES" ]; then
      warn "curl 请求失败，${CURL_RETRY_DELAY}秒后重试 ($attempt/$CURL_MAX_RETRIES)..."
      sleep "$CURL_RETRY_DELAY"
    fi
    attempt=$((attempt + 1))
  done

  return 1
}

# wget 带重试机制
wget_retry() {
  local attempt=1

  while [ $attempt -le "$WGET_MAX_RETRIES" ]; do
    if wget "$@"; then
      return 0
    fi
    if [ $attempt -lt "$WGET_MAX_RETRIES" ]; then
      warn "wget 下载失败，${WGET_RETRY_DELAY}秒后重试 ($attempt/$WGET_MAX_RETRIES)..."
      sleep "$WGET_RETRY_DELAY"
    fi
    attempt=$((attempt + 1))
  done

  return 1
}

# =====================================
# 系统检查
# =====================================
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "请以 root 身份运行此脚本。"
    exit 1
  fi
}

# 检查 Snell 是否已安装
check_snell_installed() {
  local exit_on_fail="${1:-true}"

  if [ ! -f "$SNELL_BIN" ]; then
    err "Snell 未安装"
    [ "$exit_on_fail" = "true" ] && exit 1
    return 1
  fi
  return 0
}

# 检查 Snell 配置文件是否存在
check_snell_configured() {
  if [ ! -f "$SNELL_CONF" ]; then
    err "未检测到安装或配置文件，请先安装"
    return 1
  fi
  return 0
}

get_system_type() {
  if [ -f /etc/debian_version ]; then echo "debian"
  elif [ -f /etc/redhat-release ]; then echo "centos"
  else echo "unknown"; fi
}

ensure_cmd() {
  local cmd="$1"; local pkg="${2:-$1}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    warn "缺少命令：$cmd，尝试自动安装..."
    local stype; stype=$(get_system_type)
    if [ "$stype" = "debian" ]; then apt-get update -y >/dev/null; apt-get install -y "$pkg" >/dev/null
    elif [ "$stype" = "centos" ]; then yum -y install "$pkg" >/dev/null
    else
      err "无法自动安装 $cmd，请手动安装后重试。"
      exit 1
    fi
  fi
}

# =====================================
# 架构检测
# =====================================
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
# 版本检测（从 V3 移植）
# =====================================

# 从官网获取最新版本
get_latest_version_from_web() {
  # 优先从 Knowledge Base 页面获取（结构更稳定）
  local kb_page="https://kb.nssurge.com/surge-knowledge-base/release-notes/snell"
  local page_content
  
  page_content=$(curl -s -L --max-time 10 "$kb_page" 2>/dev/null)
  
  if [ -n "$page_content" ]; then
    # KB 页面格式：snell-server-v5.0.1-linux-amd64.zip
    local latest_version
    latest_version=$(echo "$page_content" | grep -oE 'snell-server-v[0-9]+\.[0-9]+\.[0-9]+-linux' | \
      sed 's/snell-server-v//g; s/-linux//g' | sort -V | tail -1)
    
    if [ -n "$latest_version" ]; then
      echo "$latest_version"
      return 0
    fi
  fi
  
  # 备用：从下载目录页获取
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

# 验证版本 URL 是否有效
validate_version_url() {
  local version="$1"
  local arch; arch=$(map_arch)
  local url="${DL_BASE}/snell-server-v${version}-linux-${arch}.zip"
  
  if curl -I -s --max-time 10 "$url" | head -1 | grep -q "200"; then
    return 0
  else
    return 1
  fi
}

# 检测最新版本（带缓存）
# 参数: $1 = "silent" 时静默模式
detect_latest_version() {
  local silent="${1:-}"
  local current_time; current_time=$(date +%s)

  # 使用持久化缓存文件（不是临时文件）
  local version_cache="/var/tmp/snell_version_cache"

  # 检查缓存
  if [ -f "$version_cache" ]; then
    local cache_timestamp; cache_timestamp=$(head -1 "$version_cache" 2>/dev/null || echo "0")
    local cached_version; cached_version=$(sed -n '2p' "$version_cache" 2>/dev/null || echo "")

    if [ -n "$cache_timestamp" ] && [ -n "$cached_version" ]; then
      if [ $((current_time - cache_timestamp)) -lt "$VERSION_CACHE_TIME" ]; then
        VERSION="$cached_version"
        return 0
      fi
    fi
  fi

  # 从网页获取
  [ "$silent" != "silent" ] && log "正在检测最新版本..."
  local web_version
  web_version=$(get_latest_version_from_web) || web_version=""

  if [ -n "$web_version" ] && validate_version_url "$web_version"; then
    VERSION="$web_version"
    # 更新缓存
    echo "$current_time" > "$version_cache"
    echo "$VERSION" >> "$version_cache"
    [ "$silent" != "silent" ] && log "检测到最新版本: v${VERSION}"
    return 0
  fi

  # 使用后备版本
  if validate_version_url "$FALLBACK_VERSION"; then
    VERSION="$FALLBACK_VERSION"
    [ "$silent" != "silent" ] && warn "无法获取最新版本，使用后备版本: v${VERSION}"
    return 0
  fi

  [ "$silent" != "silent" ] && err "无法确定可用版本"
  return 1
}

# 强制刷新版本检测
force_detect_version() {
  rm -f "/var/tmp/snell_version_cache"
  detect_latest_version
}

# 获取已安装版本
get_installed_version() {
  if [ -f "$SNELL_VERSION_FILE" ]; then
    cat "$SNELL_VERSION_FILE" | sed 's/^v//'
  else
    echo ""
  fi
}

# 版本号比较 (返回: 0=相等, 1=v1>v2, 2=v1<v2)
compare_versions() {
  local v1="$1" v2="$2"
  
  # 移除 v 前缀
  v1=$(echo "$v1" | sed 's/^v//')
  v2=$(echo "$v2" | sed 's/^v//')
  
  if [ "$v1" = "$v2" ]; then
    return 0
  fi
  
  # 使用 sort -V 比较
  local smaller
  smaller=$(printf '%s\n%s' "$v1" "$v2" | sort -V | head -n1)
  
  if [ "$smaller" = "$v1" ]; then
    return 2  # v1 < v2
  else
    return 1  # v1 > v2
  fi
}

# =====================================
# TCP Fast Open + BBR 优化（使用统一模块）
# =====================================
enable_tcp_fastopen() {
  # 尝试使用统一的系统优化模块
  if load_system_optimize_module; then
    # 使用模块提供的功能
    enable_network_optimization "$SYSCTL_CONF" true true
    return $?
  fi

  # 模块加载失败，使用内置实现（向后兼容）
  local kernel_major kernel_minor
  kernel_major=$(uname -r | awk -F . '{print $1}')
  kernel_minor=$(uname -r | awk -F . '{print $2}')

  if [ "$kernel_major" -lt 3 ]; then
    warn "内核版本过低 (${kernel_major}.x)，无法支持 TCP Fast Open"
    return 1
  fi

  # 检查 BBR 支持 (需要内核 >= 4.9)
  local bbr_supported="false"
  if [ "$kernel_major" -gt 4 ] || { [ "$kernel_major" -eq 4 ] && [ "$kernel_minor" -ge 9 ]; }; then
    if grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
      bbr_supported="true"
    fi
  fi

  echo 3 > /proc/sys/net/ipv4/tcp_fastopen 2>/dev/null || true

  # 创建 Snell 专用的 sysctl 配置文件
  cat > "$SYSCTL_CONF" << 'SYSCTL_EOF'
# Snell Server 网络优化配置
# 由 Snell 管理脚本自动生成

fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096

net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
SYSCTL_EOF

  # 如果支持 BBR，添加 BBR 配置
  if [ "$bbr_supported" = "true" ]; then
    cat >> "$SYSCTL_CONF" << 'BBR_EOF'

# BBR 拥塞控制
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
BBR_EOF
    log "TCP Fast Open 和 BBR 已启用"
  else
    log "TCP Fast Open 已启用 (BBR 需要内核 >= 4.9)"
  fi

  # 应用配置
  sysctl --system >/dev/null 2>&1 || true
}

# 移除网络优化配置
remove_tcp_optimization() {
  # 尝试使用统一的系统优化模块
  if load_system_optimize_module; then
    remove_network_optimization "$SYSCTL_CONF"
    return $?
  fi

  # 模块加载失败，使用内置实现
  if [ -f "$SYSCTL_CONF" ]; then
    rm -f "$SYSCTL_CONF"
    sysctl --system >/dev/null 2>&1 || true
    log "已移除网络优化配置"
  fi
}

# =====================================
# 端口验证
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
    warn "系统缺少 ss/lsof，无法检测端口占用，跳过占用检测。"
    return 0
  fi
}

# =====================================
# 备份和恢复
# =====================================
backup_binary() {
  mkdir -p "$BACKUP_DIR"
  if [ -f "$SNELL_BIN" ]; then
    cp -f "$SNELL_BIN" "${BACKUP_DIR}/snell-server.bak.$(date +%s)" || warn "备份二进制失败（非致命）"
  fi
}

restore_binary_from_backup() {
  local latest
  # 使用 find 替代 ls，更安全
  latest=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'snell-server.bak.*' -printf '%T@ %p\n' 2>/dev/null | \
           sort -rn | head -n1 | cut -d' ' -f2-)

  # 验证路径在预期目录内
  if [ -n "$latest" ] && [[ "$latest" == "$BACKUP_DIR"/* ]] && [ -f "$latest" ]; then
    cp -f "$latest" "$SNELL_BIN"
    chmod +x "$SNELL_BIN" || true
    warn "已从备份恢复二进制：$latest"
    return 0
  else
    warn "没有可用的备份可恢复。"
    return 1
  fi
}

# 备份配置文件
backup_config() {
  if [ -f "$SNELL_CONF" ]; then
    cp -f "$SNELL_CONF" "${SNELL_CONF}.bak.$(date +%s)" || warn "配置备份失败（非致命）"
  fi
}

# 从备份恢复配置文件
restore_config_from_backup() {
  local latest
  # 使用 find 查找最新备份
  latest=$(find "$(dirname "$SNELL_CONF")" -maxdepth 1 -type f -name "$(basename "$SNELL_CONF").bak.*" -printf '%T@ %p\n' 2>/dev/null | \
           sort -rn | head -n1 | cut -d' ' -f2-)

  if [ -n "$latest" ] && [ -f "$latest" ]; then
    cp -f "$latest" "$SNELL_CONF"
    warn "已从备份恢复配置：$latest"
    return 0
  else
    warn "没有可用的配置备份"
    return 1
  fi
}

# =====================================
# systemd 服务
# =====================================
write_systemd() {
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
  systemctl daemon-reload || true
  systemctl enable snell || warn "启用 systemd 服务失败（非致命）"
}

# =====================================
# PSK 和配置文件
# =====================================
# 验证 IP 地址格式（IPv4 或 IPv6）
is_valid_ip() {
  local ip="$1"
  # IPv4 正则
  local ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  # IPv6 简化正则（包含 :: 或完整格式）
  local ipv6_regex='^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'

  if [[ "$ip" =~ $ipv4_regex ]]; then
    # 验证 IPv4 每段不超过 255
    local IFS='.'
    local -a segments=($ip)
    for seg in "${segments[@]}"; do
      if [ "$seg" -gt 255 ] 2>/dev/null; then
        return 1
      fi
    done
    return 0
  elif [[ "$ip" =~ $ipv6_regex ]]; then
    return 0
  else
    return 1
  fi
}

get_ip() {
  local ipv4 ipv6 addr

  # 尝试获取 IPv4
  ipv4=$(curl -s4m5 ip.sb 2>/dev/null || curl -s4m5 api.ipify.org 2>/dev/null || curl -s4m5 checkip.amazonaws.com 2>/dev/null)
  # 验证 IPv4
  if [ -n "$ipv4" ] && is_valid_ip "$ipv4"; then
    echo "$ipv4"
    return 0
  fi

  # 尝试获取 IPv6
  ipv6=$(curl -s6m5 ip.sb 2>/dev/null)
  # 验证 IPv6
  if [ -n "$ipv6" ] && is_valid_ip "$ipv6"; then
    echo "$ipv6"
    return 0
  fi

  # 无法获取有效 IP，返回默认值
  warn "无法获取有效的公网 IP 地址，使用默认值 0.0.0.0"
  echo "0.0.0.0"
}

generate_psk() {
  local psk
  psk=$(tr -dc A-Za-z0-9 </dev/urandom 2>/dev/null | head -c "$PSK_RANDOM_LENGTH")
  if [ -n "$psk" ]; then
    echo "$psk"
  else
    echo "psk$(date +%s)"
  fi
}

write_snell_config() {
  local port="$1" psk="$2" node_name="$3"
  mkdir -p "$SNELL_DIR"
  cat > "$SNELL_CONF" <<EOF
[snell-server]
listen = ::0:${port}
psk = ${psk}
ipv6 = true
tfo = true
EOF

  # 记录版本
  echo "v${VERSION}" > "$SNELL_VERSION_FILE"

  # 记录节点名称
  echo "$node_name" > "${SNELL_DIR}/node_name.txt"

  # 更新 Surge 配置文件
  update_config_txt "$port" "$psk" "$node_name"
}

# =====================================
# 防火墙（统一管理）
# =====================================
# 统一的防火墙端口放行函数
firewall_allow_port() {
  local port="$1"

  # UFW
  if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q inactive; then
      warn "UFW 未启用，跳过 ufw 放行"
    else
      ufw allow "$port"/tcp >/dev/null 2>&1 || warn "ufw 放行 tcp:$port 失败"
      ufw allow "$port"/udp >/dev/null 2>&1 || warn "ufw 放行 udp:$port 失败"
      log "ufw: 已放行端口 $port"
    fi
  fi

  # Firewalld
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || warn "firewalld 放行 tcp:$port 失败"
    firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 || warn "firewalld 放行 udp:$port 失败"
    firewall-cmd --reload >/dev/null 2>&1 || warn "firewalld reload 失败"
    log "firewalld: 已放行端口 $port"
  fi
}

# 统一的防火墙端口移除函数
firewall_remove_port() {
  local port="$1"

  # UFW
  if command -v ufw >/dev/null 2>&1; then
    if ! ufw status | grep -q inactive; then
      ufw delete allow "$port"/tcp >/dev/null 2>&1 || true
      ufw delete allow "$port"/udp >/dev/null 2>&1 || true
      log "ufw: 已移除端口 $port（如果存在）"
    fi
  fi

  # Firewalld
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --remove-port="${port}/udp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    log "firewalld: 已移除端口 $port（如果存在）"
  fi
}

# 向后兼容的函数别名（保留旧名称）
ufw_allow() { firewall_allow_port "$1"; }
ufw_remove() { firewall_remove_port "$1"; }
firewalld_allow() { firewall_allow_port "$1"; }
firewalld_remove() { firewall_remove_port "$1"; }

# =====================================
# 自动流量监控 (port-manage.sh 集成)
# =====================================
auto_add_traffic_monitor() {
  local port="$1"
  local remark="${2:-Snell Server}"

  # 检查 port-manage.sh 是否已安装
  local ptm_config="/etc/port-traffic-monitor/config.json"
  if [[ ! -f "$ptm_config" ]]; then
    return 0  # 未安装，静默跳过
  fi

  # 检查 jq 是否可用
  if ! command -v jq >/dev/null 2>&1; then
    warn "缺少 jq 命令，无法自动添加流量监控"
    return 1
  fi

  # 检查端口是否已存在
  if jq -e ".ports.\"$port\"" "$ptm_config" >/dev/null 2>&1; then
    log "端口 $port 已在流量监控中"
    return 0
  fi

  log "自动添加端口 $port 到流量监控..."

  # 读取 nftables 配置
  local nft_table nft_family
  nft_table=$(jq -r '.nftables.table_name // "port_monitor"' "$ptm_config")
  nft_family=$(jq -r '.nftables.family // "inet"' "$ptm_config")

  # 构建配置 JSON
  local timestamp; timestamp=$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
  local config_json
  config_json=$(cat <<EOF
{
  "billing": "single",
  "quota": {
    "limit": "unlimited",
    "reset_day": null
  },
  "bandwidth": {
    "rate": "unlimited"
  },
  "remark": "$remark",
  "created": "$timestamp"
}
EOF
)

  # 更新配置文件
  local tmp_config
  tmp_config=$(mktemp "${ptm_config}.XXXXXX") || {
    warn "无法创建临时文件"
    return 1
  }

  if jq ".ports.\"$port\" = $config_json" "$ptm_config" > "$tmp_config" 2>/dev/null; then
    # 保持原文件权限
    chmod --reference="$ptm_config" "$tmp_config" 2>/dev/null || chmod 644 "$tmp_config"
    # 原子性移动
    mv -f "$tmp_config" "$ptm_config" || {
      rm -f "$tmp_config"
      warn "更新流量监控配置失败"
      return 1
    }
  else
    rm -f "$tmp_config"
    warn "生成流量监控配置失败"
    return 1
  fi

  # 添加 nftables 规则
  local port_safe; port_safe=$(echo "$port" | tr '-' '_')

  # 创建计数器
  nft list counter "$nft_family" "$nft_table" "port_${port_safe}_in" >/dev/null 2>&1 || \
    nft add counter "$nft_family" "$nft_table" "port_${port_safe}_in" 2>/dev/null || true
  nft list counter "$nft_family" "$nft_table" "port_${port_safe}_out" >/dev/null 2>&1 || \
    nft add counter "$nft_family" "$nft_table" "port_${port_safe}_out" 2>/dev/null || true

  # 添加规则
  local proto
  for proto in tcp udp; do
    nft add rule "$nft_family" "$nft_table" input "$proto" dport "$port" counter name "port_${port_safe}_in" 2>/dev/null || true
    nft add rule "$nft_family" "$nft_table" forward "$proto" dport "$port" counter name "port_${port_safe}_in" 2>/dev/null || true
    nft add rule "$nft_family" "$nft_table" output "$proto" sport "$port" counter name "port_${port_safe}_out" 2>/dev/null || true
    nft add rule "$nft_family" "$nft_table" forward "$proto" sport "$port" counter name "port_${port_safe}_out" 2>/dev/null || true
  done

  log "✓ 已自动添加端口 $port 到流量监控（仅统计，无限制）"
  echo "  使用 'ptm' 命令查看流量统计"
}

auto_remove_traffic_monitor() {
  local port="$1"

  # 检查 port-manage.sh 是否已安装
  local ptm_config="/etc/port-traffic-monitor/config.json"
  if [[ ! -f "$ptm_config" ]]; then
    return 0  # 未安装，跳过
  fi

  # 检查 jq 是否可用
  if ! command -v jq >/dev/null 2>&1; then
    return 0
  fi

  # 检查端口是否存在
  if ! jq -e ".ports.\"$port\"" "$ptm_config" >/dev/null 2>&1; then
    return 0  # 端口不存在，跳过
  fi

  log "自动移除端口 $port 的流量监控..."

  # 读取 nftables 配置
  local nft_table nft_family
  nft_table=$(jq -r '.nftables.table_name // "port_monitor"' "$ptm_config")
  nft_family=$(jq -r '.nftables.family // "inet"' "$ptm_config")
  local port_safe; port_safe=$(echo "$port" | tr '-' '_')

  # 删除 nftables 规则（优化：批量获取所有 handle）
  local handles chain
  for chain in input output forward; do
    handles=$(nft -a list chain "$nft_family" "$nft_table" "$chain" 2>/dev/null | \
              grep -E "port_${port_safe}_" | sed -n 's/.*# handle \([0-9]\+\)$/\1/p')
    if [ -n "$handles" ]; then
      while IFS= read -r handle; do
        [ -n "$handle" ] && nft delete rule "$nft_family" "$nft_table" "$chain" handle "$handle" 2>/dev/null || true
      done <<< "$handles"
    fi
  done

  # 删除计数器
  nft delete counter "$nft_family" "$nft_table" "port_${port_safe}_in" 2>/dev/null || true
  nft delete counter "$nft_family" "$nft_table" "port_${port_safe}_out" 2>/dev/null || true

  # 更新配置文件
  local tmp_config
  tmp_config=$(mktemp "${ptm_config}.XXXXXX") || return 0

  if jq "del(.ports.\"$port\")" "$ptm_config" > "$tmp_config" 2>/dev/null; then
    chmod --reference="$ptm_config" "$tmp_config" 2>/dev/null || chmod 644 "$tmp_config"
    mv -f "$tmp_config" "$ptm_config" || rm -f "$tmp_config"
  else
    rm -f "$tmp_config"
  fi

  log "✓ 已移除端口 $port 的流量监控"
}

# =====================================
# 配置读取辅助函数
# =====================================
read_snell_port() {
  if [ -f "$SNELL_CONF" ]; then
    grep -E '^listen' "$SNELL_CONF" 2>/dev/null | head -n1 | sed -E 's/.*:([0-9]+)$/\1/' || echo ""
  else
    echo ""
  fi
}

read_snell_psk() {
  if [ -f "$SNELL_CONF" ]; then
    grep -E '^psk' "$SNELL_CONF" 2>/dev/null | head -n1 | awk -F'=' '{print $2}' | xargs || echo ""
  else
    echo ""
  fi
}

read_node_name() {
  if [ -f "${SNELL_DIR}/node_name.txt" ]; then
    cat "${SNELL_DIR}/node_name.txt"
  else
    uname -n
  fi
}

# 更新 config.txt（Surge 配置文件）
update_config_txt() {
  local port="${1:-$(read_snell_port)}"
  local psk="${2:-$(read_snell_psk)}"
  local node_name="${3:-$(read_node_name)}"
  local ip
  ip=$(get_ip)

  cat > "$SNELL_CFGTXT" <<EOF
${node_name} = snell, ${ip}, ${port}, psk=${psk}, version=5, tfo=true, reuse=true, ecn=true
EOF
}

# =====================================
# 显示配置
# =====================================
show_port_psk() {
  if [ -f "$SNELL_CONF" ]; then
    local port psk installed_ver node_name
    port=$(read_snell_port)
    psk=$(read_snell_psk)
    installed_ver=$(get_installed_version)
    node_name=$(read_node_name)
    echo "=== Snell 当前配置 ==="
    printf "Snell: v%s\n" "${installed_ver:-未知}"
    printf "名称 : %s\n" "${node_name}"
    printf "端口 : %s\n" "${port:-<未检测到>}"
    printf "PSK  : %s\n" "${psk:-<未检测到>}"
  else
    warn "未找到配置文件：${SNELL_CONF}"
  fi
}

show_config() {
  if [ -f "$SNELL_CFGTXT" ]; then
    cat "$SNELL_CFGTXT"
  else
    warn "找不到配置文件：$SNELL_CFGTXT"
  fi
}

# =====================================
# 日志管理
# =====================================
show_log() {
  local lines="${1:-50}"
  if [ ! -f "$SNELL_LOG" ]; then
    warn "日志文件不存在：$SNELL_LOG"
    echo "您可以使用 journalctl 查看系统日志："
    echo "  journalctl -u snell -n 50"
    return 1
  fi
  echo "--- 最近 $lines 行日志 ---"
  tail -n "$lines" "$SNELL_LOG"
}

follow_log() {
  if [ ! -f "$SNELL_LOG" ]; then
    warn "日志文件不存在，使用 journalctl 实时查看"
    echo "按 Ctrl+C 退出..."
    sleep 1
    journalctl -u snell -f
    return
  fi
  echo "实时日志 (Ctrl+C 退出):"
  echo ""
  tail -f "$SNELL_LOG"
}

clear_log() {
  if [ -f "$SNELL_LOG" ]; then
    > "$SNELL_LOG"
    log "日志已清空"
  else
    warn "日志文件不存在"
  fi
}

# =====================================
# systemd 服务管理统一函数
# =====================================
# 统一的 systemd 服务控制函数
# 用法: snell_service_control start|stop|restart|enable|disable|status
snell_service_control() {
  local action="$1"
  local show_log="${2:-true}"

  case "$action" in
    start)
      systemctl start snell
      [ "$show_log" = "true" ] && sleep 1
      if systemctl is-active --quiet snell; then
        [ "$show_log" = "true" ] && log "Snell 已启动"
        return 0
      else
        [ "$show_log" = "true" ] && err "Snell 启动失败"
        return 1
      fi
      ;;
    stop)
      systemctl stop snell 2>/dev/null || true
      [ "$show_log" = "true" ] && log "Snell 已停止"
      return 0
      ;;
    restart)
      systemctl restart snell
      sleep 2
      if systemctl is-active --quiet snell; then
        [ "$show_log" = "true" ] && log "Snell 已成功重启"
        return 0
      else
        [ "$show_log" = "true" ] && err "Snell 重启失败，请查看日志: journalctl -u snell -n 50 --no-pager"
        return 1
      fi
      ;;
    enable)
      systemctl enable snell 2>/dev/null || warn "启用 systemd 服务失败"
      ;;
    disable)
      systemctl disable snell 2>/dev/null || true
      ;;
    reload)
      systemctl daemon-reload || true
      ;;
    status)
      systemctl is-active --quiet snell
      return $?
      ;;
    *)
      err "未知的服务操作: $action"
      return 1
      ;;
  esac
}

# 重启检查（保留向后兼容）
restart_check() {
  snell_service_control restart
}

# =====================================
# 构建下载 URL
# =====================================
make_download_url() {
  local arch="$1"
  printf "%s/snell-server-v%s-linux-%s.zip" "$DL_BASE" "$VERSION" "$arch"
}

# =====================================
# 核心操作：安装
# =====================================
install_snell() {
  # 检测最新版本
  detect_latest_version || { err "无法确定安装版本"; return 1; }
  
  log "开始安装 Snell v${VERSION} ..."
  ensure_cmd wget wget
  ensure_cmd unzip unzip
  ensure_cmd curl curl
  
  # ss/lsof 是可选的，用于端口检测
  if ! command -v ss >/dev/null 2>&1 && ! command -v lsof >/dev/null 2>&1; then
    warn "缺少 ss/lsof，端口占用检测将跳过"
  fi

  local arch; arch=$(map_arch)
  if [ "$arch" = "unsupported" ]; then err "不支持的架构: $(uname -m)"; return 1; fi

  # 询问节点名称
  local default_name; default_name=$(uname -n)
  printf "${BLUE}请输入节点名称（回车使用 ${default_name}）:${RESET} "
  read -r user_name || user_name=""
  local node_name
  if [ -z "${user_name:-}" ]; then
    node_name="$default_name"
  else
    node_name="$user_name"
  fi

  # 询问端口
  printf "${BLUE}请输入 Snell 端口（回车随机）:${RESET} "
  read -r user_port || user_port=""
  local port
  if [ -z "${user_port:-}" ]; then
    port=$(shuf -i "$RANDOM_PORT_MIN"-"$RANDOM_PORT_MAX" -n 1)
    log "未输入端口 → 使用随机端口：${port}"
  else
    if ! is_valid_port "$user_port"; then err "输入端口不合法（${PORT_MIN}-${PORT_MAX}）"; return 1; fi
    if ! is_port_free "$user_port"; then err "端口 ${user_port} 已被占用"; return 1; fi
    port="$user_port"
  fi

  # 检查随机端口是否可用（用户要求保持 5 次重试）
  if [ -z "${user_port:-}" ] && ! is_port_free "$port"; then
    warn "随机端口 ${port} 被占用，重新生成..."
    local retry=1
    while [ $retry -le "$PORT_RETRY_MAX" ]; do
      port=$(shuf -i "$RANDOM_PORT_MIN"-"$RANDOM_PORT_MAX" -n 1)
      is_port_free "$port" && break
      retry=$((retry + 1))
    done
    if ! is_port_free "$port"; then
      err "重试 ${PORT_RETRY_MAX} 次后仍无法找到可用端口"
      return 1
    fi
    log "使用随机端口：${port}"
  fi

  local url; url=$(make_download_url "$arch")
  log "下载 URL: $url"

  backup_binary

  rm -f "$TMP_DOWNLOAD"
  if ! wget_retry -q -O "$TMP_DOWNLOAD" "$url"; then
    err "下载失败（已重试）：$url"
    restore_binary_from_backup || true
    return 1
  fi

  if ! unzip -o "$TMP_DOWNLOAD" -d /usr/local/bin >/dev/null 2>&1; then
    err "解压失败"
    restore_binary_from_backup || true
    return 1
  fi
  rm -f "$TMP_DOWNLOAD"
  chmod +x "$SNELL_BIN" || warn "设置执行位失败"

  # 安装管理脚本
  log "安装管理脚本..."
  local script_path; script_path=$(readlink -f "$0" 2>/dev/null || echo "$0")
  local script_target="/usr/local/bin/snell-manager.sh"

  # 如果是从 stdin 运行 (curl | bash)，则下载脚本
  if [[ ! -f "$script_path" || "$script_path" =~ bash$ || "$script_path" == "/dev/stdin" ]]; then
    if wget_retry --no-check-certificate -q -O "$script_target" "$SCRIPT_URL"; then
      log "管理脚本已下载"
    else
      warn "管理脚本下载失败（已重试），将无法使用快捷命令"
    fi
  else
    cp "$script_path" "$script_target" || warn "复制管理脚本失败"
  fi

  # 创建快捷别名
  if [ -f "$script_target" ]; then
    chmod +x "$script_target"
    ln -sf "$script_target" /usr/local/bin/snell
    log "已创建快捷命令：snell"
  fi

  # 创建用户
  if ! id -u snell >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin snell || warn "创建 snell 用户失败（非致命）"
  fi

  local psk; psk=$(generate_psk)
  write_systemd
  write_snell_config "$port" "$psk" "$node_name"

  # 启用 TCP Fast Open 和网络优化
  enable_tcp_fastopen

  # 防火墙
  ufw_allow "$port"
  firewalld_allow "$port"

  # 启动服务
  snell_service_control reload
  snell_service_control enable
  if snell_service_control start; then
    log "安装完成！"
    echo ""
    echo "=== Surge 配置（可直接复制） ==="
    cat "$SNELL_CFGTXT"

    # 自动添加流量监控
    echo ""
    auto_add_traffic_monitor "$port" "Snell Server"
  else
    err "服务未能启动，尝试回滚二进制并输出日志"
    journalctl -u snell -n 50 --no-pager || true
    restore_binary_from_backup || true
    return 1
  fi
}

# =====================================
# 核心操作：更新
# =====================================
update_snell() {
  check_snell_installed "false" || { warn "无法更新"; return 1; }
  
  local installed_ver; installed_ver=$(get_installed_version)
  
  # 如果没有版本记录，尝试从二进制获取或标记为未知
  if [ -z "$installed_ver" ]; then
    installed_ver="未知"
    warn "未找到版本记录文件，当前版本未知"
  fi
  
  # 强制刷新版本
  force_detect_version || { err "无法检测最新版本"; return 1; }
  
  # 版本比较
  if [ "$installed_ver" != "未知" ] && [ "$installed_ver" = "$VERSION" ]; then
    log "当前已是最新版本 v${VERSION}"
    printf "${BLUE}是否强制重新安装？(y/n): ${RESET}"
    read -r force_reinstall || force_reinstall=""
    if [ "${force_reinstall:-}" != "y" ] && [ "${force_reinstall:-}" != "Y" ]; then
      return 0
    fi
  else
    log "发现新版本: v${installed_ver} -> v${VERSION}"
    printf "${BLUE}是否更新？(y/n): ${RESET}"
    read -r confirm_update || confirm_update=""
    if [ "${confirm_update:-}" = "n" ] || [ "${confirm_update:-}" = "N" ]; then
      log "已取消更新"
      return 0
    fi
  fi
  
  log "开始更新 Snell 到 v${VERSION} ..."
  ensure_cmd wget wget
  ensure_cmd unzip unzip
  ensure_cmd curl curl

  local arch; arch=$(map_arch)
  if [ "$arch" = "unsupported" ]; then err "不支持架构"; return 1; fi

  local url; url=$(make_download_url "$arch")
  log "更新 URL: $url"

  backup_binary
  snell_service_control stop

  rm -f "$TMP_DOWNLOAD"
  if ! wget_retry -q -O "$TMP_DOWNLOAD" "$url"; then
    err "下载更新包失败（已重试）"
    restore_binary_from_backup || true
    snell_service_control start
    return 1
  fi

  if ! unzip -o "$TMP_DOWNLOAD" -d /usr/local/bin >/dev/null 2>&1; then
    err "解压更新包失败"
    restore_binary_from_backup || true
    snell_service_control start
    return 1
  fi
  rm -f "$TMP_DOWNLOAD"
  chmod +x "$SNELL_BIN" || warn "设置执行位失败"
  
  # 更新版本记录
  mkdir -p "$SNELL_DIR"
  echo "v${VERSION}" > "$SNELL_VERSION_FILE"

  if snell_service_control restart; then
    log "更新成功: v${installed_ver} -> v${VERSION}"
    echo ""
    echo "=== Surge 配置 ==="
    [ -f "$SNELL_CFGTXT" ] && cat "$SNELL_CFGTXT"
  else
    err "更新后 Snell 无法启动，尝试回滚"
    restore_binary_from_backup || true
    if [ "$installed_ver" != "未知" ]; then
      echo "v${installed_ver}" > "$SNELL_VERSION_FILE"
    fi
    snell_service_control reload
    snell_service_control restart
    journalctl -u snell -n 50 --no-pager || true
    return 1
  fi
}

# =====================================
# 核心操作：卸载
# =====================================
uninstall_snell() {
  check_snell_installed "false" || { warn "无需卸载"; return 1; }
  
  printf "${YELLOW}确定要卸载 Snell 吗？(y/n): ${RESET}"
  read -r confirm || confirm=""
  if [ "${confirm:-}" != "y" ] && [ "${confirm:-}" != "Y" ]; then
    log "已取消卸载"
    return 0
  fi
  
  log "卸载 Snell ..."
  
  # 获取当前端口用于清理防火墙
  local cur_port
  cur_port=$(read_snell_port)
  
  snell_service_control stop
  snell_service_control disable
  rm -f "$SYSTEMD_SERVICE"
  snell_service_control reload
  rm -f "$SNELL_BIN"
  rm -rf "$SNELL_DIR"
  
  # 清理防火墙规则
  if [ -n "$cur_port" ]; then
    ufw_remove "$cur_port"
    firewalld_remove "$cur_port"

    # 移除流量监控
    auto_remove_traffic_monitor "$cur_port"
  fi

  # 移除网络优化配置
  remove_tcp_optimization

  # 清理缓存
  rm -f "/var/tmp/snell_version_cache"

  log "卸载完成"
}

# =====================================
# 核心操作：修改端口
# =====================================
modify_port() {
  check_snell_configured || return 1
  printf "${BLUE}请输入新的端口（1-65535）: ${RESET}"
  read -r new_port || true
  if ! is_valid_port "$new_port"; then err "端口不合法"; return 1; fi

  local cur_port cur_psk
  cur_port=$(read_snell_port)
  cur_psk=$(read_snell_psk)

  if [ "$new_port" = "$cur_port" ]; then warn "新端口与当前端口一致"; return 0; fi
  if ! is_port_free "$new_port"; then err "端口 ${new_port} 已被占用"; return 1; fi

  # 备份配置
  backup_config

  # 替换 listen 行（使用 | 作为分隔符避免 @ 冲突）
  if grep -qE '^listen' "$SNELL_CONF"; then
    sed -E -i "s|^listen.*|listen = ::0:${new_port}|" "$SNELL_CONF"
  else
    sed -i "1i listen = ::0:${new_port}" "$SNELL_CONF"
  fi

  # 更新人类可读配置
  update_config_txt "$new_port" "$cur_psk"

  # 防火墙调整
  if [ -n "$cur_port" ]; then
    ufw_remove "$cur_port"
    firewalld_remove "$cur_port"
  fi
  ufw_allow "$new_port"
  firewalld_allow "$new_port"

  # 重启验证
  if restart_check; then
    log "端口修改成功：${cur_port} -> ${new_port}"

    # 更新流量监控
    if [ -n "$cur_port" ]; then
      auto_remove_traffic_monitor "$cur_port"
    fi
    auto_add_traffic_monitor "$new_port" "Snell Server"
  else
    err "修改端口失败，正在回滚配置..."
    if restore_config_from_backup; then
      # 回滚防火墙规则
      ufw_remove "$new_port"
      firewalld_remove "$new_port"
      if [ -n "$cur_port" ]; then
        ufw_allow "$cur_port"
        firewalld_allow "$cur_port"
      fi
      snell_service_control restart
    else
      warn "需要手动修复配置"
    fi
    return 1
  fi
}

# =====================================
# 核心操作：修改名称
# =====================================
modify_name() {
  check_snell_configured || return 1

  local cur_name
  cur_name=$(read_node_name)
  
  printf "${BLUE}当前名称: ${cur_name}\n请输入新的名称: ${RESET}"
  read -r new_name || true
  
  if [ -z "${new_name:-}" ]; then
    warn "名称不能为空"
    return 1
  fi
  
  if [ "$new_name" = "$cur_name" ]; then
    warn "新名称与当前名称一致"
    return 0
  fi
  
  # 保存新名称
  echo "$new_name" > "${SNELL_DIR}/node_name.txt"

  # 更新 config.txt
  update_config_txt "" "" "$new_name"
  
  log "名称修改成功：${cur_name} -> ${new_name}"
}

# =====================================
# 核心操作：修改 PSK
# =====================================
modify_psk() {
  check_snell_configured || return 1

  local cur_psk
  cur_psk=$(read_snell_psk)
  
  printf "${BLUE}当前 PSK: ${cur_psk}\n请输入新的 PSK（回车随机生成）: ${RESET}"
  read -r new_psk || true
  
  # 如果为空则随机生成
  if [ -z "${new_psk:-}" ]; then
    new_psk=$(generate_psk)
    log "随机生成 PSK: ${new_psk}"
  else
    # 简单检查：长度至少 PSK_MIN_LENGTH 位，只允许字母数字
    if [ ${#new_psk} -lt "$PSK_MIN_LENGTH" ]; then
      err "PSK 长度至少 ${PSK_MIN_LENGTH} 位"
      return 1
    fi
    if ! [[ "$new_psk" =~ ^[A-Za-z0-9]+$ ]]; then
      err "PSK 只能包含字母和数字"
      return 1
    fi
  fi
  
  if [ "$new_psk" = "$cur_psk" ]; then
    warn "新 PSK 与当前 PSK 一致"
    return 0
  fi

  # 备份配置
  backup_config

  # 替换 psk 行（使用 | 作为分隔符）
  sed -i "s|^psk = .*|psk = ${new_psk}|" "$SNELL_CONF"

  # 更新 config.txt
  update_config_txt "" "$new_psk"
  
  # 重启服务
  if restart_check; then
    log "PSK 修改成功"
  else
    err "修改 PSK 后服务启动失败，正在回滚..."
    if restore_config_from_backup; then
      snell_service_control restart
    fi
    return 1
  fi
}

# =====================================
# 修改配置菜单
# =====================================
modify_config() {
  check_snell_configured || return 1

  echo ""
  echo "1) 修改端口"
  echo "2) 修改名称"
  echo "3) 修改 PSK"
  echo "0) 返回"
  printf "${BLUE}请选择: ${RESET}"
  read -r sub_opt || true

  case "$sub_opt" in
    1) modify_port ;;
    2) modify_name ;;
    3) modify_psk ;;
    0) return 0 ;;
    *) warn "无效选项" ;;
  esac
}

# =====================================
# 网络优化开关
# =====================================
toggle_tcp_optimization() {
  if [ -f "$SYSCTL_CONF" ]; then
    printf "${BLUE}TCP Fast Open 已启用，是否禁用？(y/n): ${RESET}"
    read -r disable_tfo || disable_tfo=""
    if [ "${disable_tfo:-}" = "y" ] || [ "${disable_tfo:-}" = "Y" ]; then
      remove_tcp_optimization
      log "已禁用 TCP Fast Open"
    fi
  else
    printf "${BLUE}TCP Fast Open 未启用，是否启用？(y/n): ${RESET}"
    read -r enable_tfo || enable_tfo=""
    if [ "${enable_tfo:-}" != "n" ] && [ "${enable_tfo:-}" != "N" ]; then
      enable_tcp_fastopen
    fi
  fi
}

# =====================================
# 更新脚本
# =====================================
update_script() {
  log "检查脚本更新..."
  
  if [ -z "$SCRIPT_URL" ]; then
    err "未配置脚本更新源"
    return 1
  fi
  
  # 获取远程版本
  log "当前版本: v${SCRIPT_VERSION}"
  log "正在获取最新版本..."
  
  local remote_version
  remote_version=$(curl -s --max-time 10 "$SCRIPT_URL" | grep -E '^SCRIPT_VERSION=' | head -1 | cut -d'"' -f2)
  
  if [ -z "$remote_version" ]; then
    err "无法获取远程版本信息"
    return 1
  fi
  
  log "远程版本: v${remote_version}"
  
  # 比较版本
  if [ "$SCRIPT_VERSION" = "$remote_version" ]; then
    log "当前已是最新版本"
    return 0
  fi
  
  compare_versions "$SCRIPT_VERSION" "$remote_version" || true
  local cmp=$?
  
  if [ $cmp -eq 1 ]; then
    warn "远程版本 (v${remote_version}) 比当前版本 (v${SCRIPT_VERSION}) 旧"
    printf "${BLUE}是否仍要下载？(y/n): ${RESET}"
    read -r force_down || force_down=""
    if [ "${force_down:-}" != "y" ] && [ "${force_down:-}" != "Y" ]; then
      return 0
    fi
  else
    log "发现新版本: v${SCRIPT_VERSION} -> v${remote_version}"
    printf "${BLUE}是否更新？(y/n): ${RESET}"
    read -r confirm || confirm=""
    if [ "${confirm:-}" = "n" ] || [ "${confirm:-}" = "N" ]; then
      log "已取消更新"
      return 0
    fi
  fi
  
  # 使用固定路径
  local script_path="/usr/local/bin/snell-manager.sh"
  
  # 下载新脚本
  log "正在下载新版本..."
  local tmp_script
  tmp_script=$(mktemp /tmp/snell-manager-new.XXXXXX.sh) || {
    err "无法创建临时文件"
    return 1
  }

  if ! curl_retry -fsSL -o "$tmp_script" "$SCRIPT_URL"; then
    err "下载失败（已重试）"
    rm -f "$tmp_script"
    return 1
  fi
  
  # 验证下载的脚本
  if ! bash -n "$tmp_script" 2>/dev/null; then
    err "下载的脚本语法错误，取消更新"
    rm -f "$tmp_script"
    return 1
  fi
  
  # 备份当前脚本
  if [ -f "$script_path" ]; then
    cp -f "$script_path" "${script_path}.bak" || true
  fi
  
  # 替换脚本
  chmod +x "$tmp_script"
  mv -f "$tmp_script" "$script_path"

  # 确保快捷别名存在
  if [ ! -L /usr/local/bin/snell ]; then
    ln -sf "$script_path" /usr/local/bin/snell
    log "已创建快捷命令：snell"
  fi

  log "脚本已更新到 v${remote_version}"
  log "保存位置: $script_path"
  log "3 秒后重新执行..."
  sleep 3
  exec bash "$script_path"
}

# =====================================
# 菜单辅助函数
# =====================================
pause_return() {
  echo ""
  echo -e "${YELLOW}按回车返回菜单...${RESET}"
  read -r _
}

# =====================================
# 菜单
# =====================================
menu() {
  while true; do
    clear
    echo -e "${GREEN}=== Snell 管理脚本 v${SCRIPT_VERSION} ===${RESET}"
    
    # 显示更新提示
    local update_hint=""
    if [ -f "$SNELL_BIN" ]; then
      local installed_ver; installed_ver=$(get_installed_version)
      # 静默检测（使用缓存）
      detect_latest_version "silent" || true
      if [ -n "$VERSION" ] && [ -n "$installed_ver" ]; then
        compare_versions "$installed_ver" "$VERSION" || true
        local cmp_result=$?
        if [ $cmp_result -eq 2 ]; then  # installed < latest
          update_hint=" ${YELLOW}(可更新到 v${VERSION})${RESET}"
        fi
      fi
    fi
    
    if [ -f "$SNELL_BIN" ]; then
      echo -e "安装状态: ${GREEN}已安装${RESET}${update_hint}"
      if snell_service_control status 2>/dev/null; then
        echo -e "运行状态: ${GREEN}已启动${RESET}"
      else
        echo -e "运行状态: ${YELLOW}未启动${RESET}"
      fi
      # TFO 状态
      if [ -f "$SYSCTL_CONF" ]; then
        echo -e "网络优化: ${GREEN}已启用${RESET} (TCP Fast Open + BBR)"
      else
        echo -e "网络优化: ${YELLOW}未启用${RESET}"
      fi
      echo ""
      show_port_psk
    else
      echo -e "安装状态: ${RED}未安装${RESET}"
    fi
    echo ""
    echo -e "${GREEN}--- Snell 管理 ---${RESET}"
    echo "1) 安装 Snell"
    echo "2) 卸载 Snell"
    echo "3) 启动 Snell"
    echo "4) 停止 Snell"
    echo "5) 更新 Snell"
    echo "6) 查看配置"
    echo "7) 修改配置"
    echo "8) 查看日志"
    echo -e "${GREEN}--- 系统设置 ---${RESET}"
    echo "9) 网络优化开关 (TCP Fast Open + BBR)"
    echo "10) 更新脚本"
    echo "0) 退出"
    printf "${BLUE}请选择: ${RESET}"
    read -r opt || true
    case "$opt" in
      1) install_snell; pause_return ;;
      2) uninstall_snell; pause_return ;;
      3)
        if check_snell_installed "false"; then
          snell_service_control start
        fi
        pause_return
        ;;
      4)
        if check_snell_installed "false"; then
          snell_service_control stop
        fi
        pause_return
        ;;
      5) update_snell; pause_return ;;
      6) show_config; pause_return ;;
      7) modify_config; pause_return ;;
      8)
        echo ""
        echo "1) 查看最近日志"
        echo "2) 实时查看日志"
        echo "3) 清空日志"
        echo "0) 返回"
        printf "${BLUE}请选择: ${RESET}"
        read -r log_opt || true
        case "$log_opt" in
          1) show_log 100 ;;
          2) follow_log ;;
          3) clear_log ;;
        esac
        pause_return
        ;;
      9) toggle_tcp_optimization; pause_return ;;
      10) update_script; pause_return ;;
      0) log "退出"; exit 0 ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

# =====================================
# 帮助信息
# =====================================
show_help() {
  cat <<EOF

${GREEN}Snell 管理脚本 v${SCRIPT_VERSION}${RESET}

用法: $(basename "$0") [命令]

${GREEN}服务管理:${RESET}
  start           启动 Snell 服务
  stop            停止 Snell 服务
  restart         重启 Snell 服务
  status          查看服务状态

${GREEN}配置管理:${RESET}
  install         安装 Snell
  uninstall       卸载 Snell
  update          更新 Snell
  info            查看配置信息
  config          显示 Surge 配置

${GREEN}修改配置:${RESET}
  change-port     修改端口
  change-name     修改名称
  change-psk      修改 PSK

${GREEN}日志管理:${RESET}
  log [n]         查看最近 n 行日志（默认 50）
  log-f           实时查看日志
  log-clear       清空日志

${GREEN}系统设置:${RESET}
  enable-tfo      启用 TCP Fast Open
  disable-tfo     禁用 TCP Fast Open
  update-script   更新脚本

${GREEN}其他:${RESET}
  version         显示版本信息
  help            显示此帮助

不带参数运行进入交互式菜单。

EOF
}

# =====================================
# Main
# =====================================
main() {
  check_root
  init_temp_files

  case "${1:-}" in
    # 服务管理
    start)
      check_snell_installed
      snell_service_control start || exit 1
      ;;
    stop)
      check_snell_installed
      snell_service_control stop
      ;;
    restart)
      check_snell_installed
      snell_service_control restart || exit 1
      ;;
    status)
      check_snell_installed
      echo ""
      if snell_service_control status; then
        echo -e "状态: ${GREEN}运行中${RESET}"
      else
        echo -e "状态: ${RED}未运行${RESET}"
      fi
      local ver; ver=$(get_installed_version)
      [ -n "$ver" ] && echo "版本: v$ver"
      echo ""
      ;;
    # 配置管理
    install)
      install_snell
      ;;
    uninstall)
      uninstall_snell
      ;;
    update)
      update_snell
      ;;
    info)
      show_port_psk
      ;;
    config)
      show_config
      ;;
    # 修改配置
    change-port)
      modify_port
      ;;
    change-name)
      modify_name
      ;;
    change-psk)
      modify_psk
      ;;
    # 日志管理
    log)
      show_log "${2:-50}"
      ;;
    log-f)
      follow_log
      ;;
    log-clear)
      clear_log
      ;;
    # 系统设置
    enable-tfo)
      enable_tcp_fastopen
      ;;
    disable-tfo)
      remove_tcp_optimization
      ;;
    update-script)
      update_script
      ;;
    # 其他
    version)
      echo ""
      echo "脚本版本: v${SCRIPT_VERSION}"
      local ver; ver=$(get_installed_version)
      if [ -n "$ver" ]; then
        echo "Snell 版本: v$ver"
      else
        echo "Snell: 未安装"
      fi
      echo ""
      ;;
    help|--help|-h)
      show_help
      ;;
    "")
      # 无参数，显示菜单
      menu
      ;;
    *)
      warn "未知命令: $1"
      echo "使用 '$0 help' 查看帮助"
      exit 1
      ;;
  esac
}

main "$@"
