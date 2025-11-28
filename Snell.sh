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
SCRIPT_URL="https://sub.zuowo.de/AUZqCdPALIIowSPTYlxoTO/api/file/Snell.sh"

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
TMP_DOWNLOAD="/tmp/snell-server.zip"
VERSION_CACHE="/tmp/snell_version_cache"
DL_BASE="https://dl.nssurge.com/snell"

# =====================================
# 日志函数
# =====================================
log()    { echo -e "${GREEN}[INFO]${RESET} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err()    { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

# =====================================
# 系统检查
# =====================================
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "请以 root 身份运行此脚本。"
    exit 1
  fi
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
  local release_page="https://dl.nssurge.com/snell/"
  local page_content
  
  page_content=$(curl -s -L --max-time 10 "$release_page" 2>/dev/null) || return 1
  
  if [ -z "$page_content" ]; then
    return 1
  fi
  
  # 提取 v5 版本号
  local latest_v5
  latest_v5=$(echo "$page_content" | grep -oE 'snell-server-v5\.[0-9]+\.[0-9]+[a-z]*[0-9]*-linux' | head -1 | sed 's/snell-server-v//g' | sed 's/-linux//g')
  
  if [ -n "$latest_v5" ]; then
    echo "$latest_v5"
    return 0
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
  local cache_time=3600  # 1 小时缓存
  local current_time; current_time=$(date +%s)
  
  # 检查缓存
  if [ -f "$VERSION_CACHE" ]; then
    local cache_timestamp; cache_timestamp=$(head -1 "$VERSION_CACHE" 2>/dev/null || echo "0")
    local cached_version; cached_version=$(sed -n '2p' "$VERSION_CACHE" 2>/dev/null || echo "")
    
    if [ -n "$cache_timestamp" ] && [ -n "$cached_version" ]; then
      if [ $((current_time - cache_timestamp)) -lt $cache_time ]; then
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
    echo "$current_time" > "$VERSION_CACHE"
    echo "$VERSION" >> "$VERSION_CACHE"
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
  rm -f "$VERSION_CACHE"
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
# TCP Fast Open + BBR 优化（从 V3 移植）
# =====================================
enable_tcp_fastopen() {
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
  [ "$p" -ge 1 ] && [ "$p" -le 65535 ]
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
  local latest; latest=$(ls -1t ${BACKUP_DIR}/snell-server.bak.* 2>/dev/null | head -n1 || true)
  if [ -n "$latest" ]; then
    cp -f "$latest" "$SNELL_BIN"
    chmod +x "$SNELL_BIN" || true
    warn "已从备份恢复二进制：$latest"
    return 0
  else
    warn "没有可用的备份可恢复。"
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
StandardOutput=journal
StandardError=journal
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
generate_psk() {
  local psk
  psk=$(tr -dc A-Za-z0-9 </dev/urandom 2>/dev/null | head -c 20)
  if [ -n "$psk" ]; then
    echo "$psk"
  else
    echo "psk$(date +%s)"
  fi
}

write_snell_config() {
  local port="$1" psk="$2"
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

  local ip hostname
  ip=$(curl -s --max-time 5 http://checkip.amazonaws.com || echo "0.0.0.0")
  hostname=$(uname -n)
  cat > "$SNELL_CFGTXT" <<EOF
${hostname} = snell, ${ip}, ${port}, psk=${psk}, version=5, tfo=true, reuse=true, ecn=true
EOF
}

# =====================================
# 防火墙
# =====================================
ufw_allow() {
  local p="$1"
  if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q inactive; then
      warn "UFW 未启用，跳过 ufw 放行"
    else
      ufw allow "$p"/tcp >/dev/null 2>&1 || warn "ufw 放行 tcp:$p 失败"
      ufw allow "$p"/udp >/dev/null 2>&1 || warn "ufw 放行 udp:$p 失败"
      log "ufw: 已放行端口 $p"
    fi
  fi
}

ufw_remove() {
  local p="$1"
  if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q inactive; then
      : # skip
    else
      ufw delete allow "$p"/tcp >/dev/null 2>&1 || true
      ufw delete allow "$p"/udp >/dev/null 2>&1 || true
      log "ufw: 已移除端口 $p（如果存在）"
    fi
  fi
}

firewalld_allow() {
  local p="$1"
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=${p}/tcp >/dev/null 2>&1 || warn "firewalld 放行 tcp:$p 失败"
    firewall-cmd --permanent --add-port=${p}/udp >/dev/null 2>&1 || warn "firewalld 放行 udp:$p 失败"
    firewall-cmd --reload >/dev/null 2>&1 || warn "firewalld reload 失败"
    log "firewalld: 已放行端口 $p"
  fi
}

firewalld_remove() {
  local p="$1"
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port=${p}/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --remove-port=${p}/udp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    log "firewalld: 已移除端口 $p（如果存在）"
  fi
}

# =====================================
# 显示配置
# =====================================
show_port_psk() {
  if [ -f "$SNELL_CONF" ]; then
    local port psk installed_ver
    port=$(grep -E '^listen' "$SNELL_CONF" 2>/dev/null | head -n1 | sed -E 's/.*:([0-9]+)$/\1/' || echo "")
    psk=$(grep -E '^psk' "$SNELL_CONF" 2>/dev/null | head -n1 | awk -F'=' '{print $2}' | xargs || echo "")
    installed_ver=$(get_installed_version)
    echo "=== Snell 当前配置 ==="
    printf "版本: %s\n" "${installed_ver:-<未知>}"
    printf "端口: %s\n" "${port:-<未检测到>}"
    printf "PSK : %s\n" "${psk:-<未检测到>}"
  else
    warn "未找到配置文件：${SNELL_CONF}"
  fi
}

show_config() {
  if [ -f "$SNELL_CONF" ]; then
    echo "=== $SNELL_CONF ==="
    cat "$SNELL_CONF"
  else
    warn "找不到 $SNELL_CONF"
  fi
  echo ""
  if [ -f "$SNELL_CFGTXT" ]; then
    echo "=== $SNELL_CFGTXT (Surge 配置) ==="
    cat "$SNELL_CFGTXT"
  fi
}

# =====================================
# 重启检查
# =====================================
restart_check() {
  systemctl restart snell
  sleep 2
  if systemctl is-active --quiet snell; then
    log "Snell 已成功启动"
    return 0
  else
    err "Snell 启动失败，请查看日志: journalctl -u snell -n 50 --no-pager"
    return 1
  fi
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

  # 询问端口
  printf "${BLUE}请输入 Snell 端口（回车随机）:${RESET} "
  read -r user_port || user_port=""
  local port
  if [ -z "${user_port:-}" ]; then
    port=$(shuf -i 30000-65000 -n 1)
    log "未输入端口 → 使用随机端口：${port}"
  else
    if ! is_valid_port "$user_port"; then err "输入端口不合法（1-65535）"; return 1; fi
    if ! is_port_free "$user_port"; then err "端口 ${user_port} 已被占用"; return 1; fi
    port="$user_port"
    log "使用用户端口：${port}"
  fi

  # 检查随机端口是否可用
  if [ -z "${user_port:-}" ] && ! is_port_free "$port"; then
    warn "随机端口 ${port} 被占用，重新生成..."
    for _ in {1..5}; do
      port=$(shuf -i 30000-65000 -n 1)
      is_port_free "$port" && break
    done
    if ! is_port_free "$port"; then
      err "多次尝试后仍无法找到可用端口"
      return 1
    fi
    log "使用随机端口：${port}"
  fi

  local url; url=$(make_download_url "$arch")
  log "下载 URL: $url"

  backup_binary

  rm -f "$TMP_DOWNLOAD"
  if ! wget -q -O "$TMP_DOWNLOAD" "$url"; then
    err "下载失败：$url"
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

  # 创建用户
  if ! id -u snell >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin snell || warn "创建 snell 用户失败（非致命）"
  fi

  local psk; psk=$(generate_psk)
  write_systemd
  write_snell_config "$port" "$psk"

  # 启用 TCP Fast Open 和网络优化
  enable_tcp_fastopen

  # 防火墙
  ufw_allow "$port"
  firewalld_allow "$port"

  # 启动服务
  systemctl daemon-reload || true
  systemctl enable snell || true
  systemctl start snell || true
  sleep 2
  if systemctl is-active --quiet snell; then
    log "安装完成！"
    echo ""
    echo "=== Surge 配置（可直接复制） ==="
    cat "$SNELL_CFGTXT"
    echo ""
    journalctl -u snell -n 5 --no-pager || true
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
  if [ ! -f "$SNELL_BIN" ]; then warn "Snell 未安装，无法更新"; return 1; fi
  
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
    printf "${BLUE}是否强制重新安装？(y/N): ${RESET}"
    read -r force_reinstall || force_reinstall=""
    if [ "${force_reinstall:-}" != "y" ] && [ "${force_reinstall:-}" != "Y" ]; then
      return 0
    fi
  else
    log "发现新版本: v${installed_ver} -> v${VERSION}"
    printf "${BLUE}是否更新？(Y/n): ${RESET}"
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
  systemctl stop snell || true

  rm -f "$TMP_DOWNLOAD"
  if ! wget -q -O "$TMP_DOWNLOAD" "$url"; then
    err "下载更新包失败"
    restore_binary_from_backup || true
    systemctl start snell || true
    return 1
  fi

  if ! unzip -o "$TMP_DOWNLOAD" -d /usr/local/bin >/dev/null 2>&1; then
    err "解压更新包失败"
    restore_binary_from_backup || true
    systemctl start snell || true
    return 1
  fi
  rm -f "$TMP_DOWNLOAD"
  chmod +x "$SNELL_BIN" || warn "设置执行位失败"
  
  # 更新版本记录
  mkdir -p "$SNELL_DIR"
  echo "v${VERSION}" > "$SNELL_VERSION_FILE"

  systemctl restart snell || true
  sleep 2
  if systemctl is-active --quiet snell; then
    log "更新成功: v${installed_ver} -> v${VERSION}"
    journalctl -u snell -n 8 --no-pager || true
    [ -f "$SNELL_CFGTXT" ] && cat "$SNELL_CFGTXT"
  else
    err "更新后 Snell 无法启动，尝试回滚"
    restore_binary_from_backup || true
    if [ "$installed_ver" != "未知" ]; then
      echo "v${installed_ver}" > "$SNELL_VERSION_FILE"
    fi
    systemctl daemon-reload || true
    systemctl restart snell || true
    journalctl -u snell -n 50 --no-pager || true
    return 1
  fi
}

# =====================================
# 核心操作：卸载
# =====================================
uninstall_snell() {
  if [ ! -f "$SNELL_BIN" ]; then
    warn "Snell 未安装"
    return 1
  fi
  
  printf "${YELLOW}确定要卸载 Snell 吗？(y/N): ${RESET}"
  read -r confirm || confirm=""
  if [ "${confirm:-}" != "y" ] && [ "${confirm:-}" != "Y" ]; then
    log "已取消卸载"
    return 0
  fi
  
  log "卸载 Snell ..."
  
  # 获取当前端口用于清理防火墙
  local cur_port=""
  if [ -f "$SNELL_CONF" ]; then
    cur_port=$(grep -E '^listen' "$SNELL_CONF" 2>/dev/null | head -n1 | sed -E 's/.*:([0-9]+)$/\1/' || echo "")
  fi
  
  systemctl stop snell 2>/dev/null || true
  systemctl disable snell 2>/dev/null || true
  rm -f "$SYSTEMD_SERVICE"
  systemctl daemon-reload || true
  rm -f "$SNELL_BIN"
  rm -rf "$SNELL_DIR"
  
  # 清理防火墙规则
  if [ -n "$cur_port" ]; then
    ufw_remove "$cur_port"
    firewalld_remove "$cur_port"
  fi
  
  # 移除网络优化配置
  remove_tcp_optimization
  
  # 清理缓存
  rm -f "$VERSION_CACHE"
  
  log "卸载完成"
}

# =====================================
# 核心操作：修改端口
# =====================================
modify_port() {
  if [ ! -f "$SNELL_CONF" ]; then err "未检测到安装或配置文件，请先安装"; return 1; fi
  printf "${BLUE}请输入新的端口（1-65535）: ${RESET}"
  read -r new_port || true
  if ! is_valid_port "$new_port"; then err "端口不合法"; return 1; fi

  local cur_port cur_psk
  cur_port=$(grep -E '^listen' "$SNELL_CONF" | sed -E 's/.*:([0-9]+)$/\1/' || echo "")
  cur_psk=$(grep -E '^psk' "$SNELL_CONF" | awk -F'=' '{print $2}' | xargs || echo "")

  if [ "$new_port" = "$cur_port" ]; then warn "新端口与当前端口一致"; return 0; fi
  if ! is_port_free "$new_port"; then err "端口 ${new_port} 已被占用"; return 1; fi

  # 备份配置
  cp -f "$SNELL_CONF" "${SNELL_CONF}.bak.$(date +%s)" || warn "配置备份失败（非致命）"

  # 替换 listen 行
  if grep -qE '^listen' "$SNELL_CONF"; then
    sed -E -i "s@^listen.*@listen = ::0:${new_port}@" "$SNELL_CONF"
  else
    sed -i "1i listen = ::0:${new_port}" "$SNELL_CONF"
  fi

  # 更新人类可读配置
  local ip hostname
  ip=$(curl -s --max-time 5 http://checkip.amazonaws.com || echo "0.0.0.0")
  hostname=$(uname -n)
  cat > "$SNELL_CFGTXT" <<EOF
${hostname} = snell, ${ip}, ${new_port}, psk=${cur_psk}, version=5, tfo=true, reuse=true, ecn=true
EOF

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
  else
    err "修改端口失败，正在回滚配置..."
    local lastbak; lastbak=$(ls -1t ${SNELL_CONF}.bak.* 2>/dev/null | head -n1 || true)
    if [ -n "$lastbak" ]; then
      cp -f "$lastbak" "$SNELL_CONF"
      # 回滚防火墙规则
      ufw_remove "$new_port"
      firewalld_remove "$new_port"
      if [ -n "$cur_port" ]; then
        ufw_allow "$cur_port"
        firewalld_allow "$cur_port"
      fi
      systemctl restart snell || true
      err "已回滚到备份：$lastbak"
    else
      warn "找不到备份，需要手动修复配置"
    fi
    return 1
  fi
}

# =====================================
# 网络优化开关
# =====================================
toggle_tcp_optimization() {
  if [ -f "$SYSCTL_CONF" ]; then
    printf "${BLUE}TCP Fast Open 已启用，是否禁用？(y/N): ${RESET}"
    read -r disable_tfo || disable_tfo=""
    if [ "${disable_tfo:-}" = "y" ] || [ "${disable_tfo:-}" = "Y" ]; then
      remove_tcp_optimization
      log "已禁用 TCP Fast Open"
    fi
  else
    printf "${BLUE}TCP Fast Open 未启用，是否启用？(Y/n): ${RESET}"
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
    printf "${BLUE}是否仍要下载？(y/N): ${RESET}"
    read -r force_down || force_down=""
    if [ "${force_down:-}" != "y" ] && [ "${force_down:-}" != "Y" ]; then
      return 0
    fi
  else
    log "发现新版本: v${SCRIPT_VERSION} -> v${remote_version}"
    printf "${BLUE}是否更新？(Y/n): ${RESET}"
    read -r confirm || confirm=""
    if [ "${confirm:-}" = "n" ] || [ "${confirm:-}" = "N" ]; then
      log "已取消更新"
      return 0
    fi
  fi
  
  # 确定脚本路径
  local script_path
  script_path=$(readlink -f "$0" 2>/dev/null || echo "")
  
  # 检查是否通过管道执行 (curl | bash)
  if [ -z "$script_path" ] || [ "$script_path" = "bash" ] || [ ! -f "$script_path" ]; then
    warn "检测到通过管道执行，将保存到 /usr/local/bin/snell-manager.sh"
    script_path="/usr/local/bin/snell-manager.sh"
  fi
  
  # 下载新脚本
  log "正在下载新版本..."
  local tmp_script="/tmp/snell-manager-new.sh"
  
  if ! curl -fsSL -o "$tmp_script" "$SCRIPT_URL"; then
    err "下载失败"
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
  
  log "脚本已更新到 v${remote_version}"
  log "保存位置: $script_path"
  log "3 秒后重新执行..."
  sleep 3
  exec bash "$script_path"
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
      if systemctl is-active --quiet snell 2>/dev/null; then 
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
    echo "7) 修改端口"
    echo -e "${GREEN}--- 系统设置 ---${RESET}"
    echo "8) 网络优化开关 (TCP Fast Open + BBR)"
    echo "9) 更新脚本"
    echo "0) 退出"
    printf "${BLUE}请选择: ${RESET}"
    read -r opt || true
    case "$opt" in
      1) install_snell ;;
      2) uninstall_snell ;;
      3) 
        if [ ! -f "$SNELL_BIN" ]; then
          err "Snell 未安装"
        else
          systemctl start snell && sleep 1 && (systemctl is-active --quiet snell && log "已启动" || err "启动失败")
        fi
        ;;
      4)
        if [ ! -f "$SNELL_BIN" ]; then
          err "Snell 未安装"
        else
          systemctl stop snell && log "已停止"
        fi
        ;;
      5) update_snell ;;
      6) show_config ;;
      7) modify_port ;;
      8) toggle_tcp_optimization ;;
      9) update_script ;;
      0) log "退出"; exit 0 ;;
      *) warn "无效选项" ;;
    esac
    echo -e "${YELLOW}\n按回车返回菜单...${RESET}"
    read -r _
  done
}

# =====================================
# Main
# =====================================
check_root
menu