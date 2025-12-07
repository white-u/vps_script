#!/bin/bash
# ============================================================================
# VPS Manager 安装脚本
# Usage: bash <(curl -sL URL/install.sh)
# ============================================================================

set -e

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
NC='\033[0m'

INSTALL_DIR="/usr/local/lib/vps-manager"
BIN_LINK="/usr/local/bin/vps"
REPO_URL="https://raw.githubusercontent.com/white-u/vps_script/main/vps-manager"

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# 检查 root
if [[ $EUID -ne 0 ]]; then
    log_error "请使用 root 用户运行"
    exit 1
fi

echo
echo "============================================"
echo "        VPS Manager 安装程序"
echo "============================================"
echo

# 检测系统和包管理器
PKG_UPDATE="true"
PKG_INSTALL="true"

if command -v apt-get &>/dev/null; then
    PKG_UPDATE="apt-get update -y"
    PKG_INSTALL="apt-get install -y"
elif command -v dnf &>/dev/null; then
    PKG_UPDATE="dnf makecache"
    PKG_INSTALL="dnf install -y"
elif command -v yum &>/dev/null; then
    PKG_UPDATE="yum makecache"
    PKG_INSTALL="yum install -y"
elif command -v apk &>/dev/null; then
    PKG_UPDATE="apk update"
    PKG_INSTALL="apk add"
fi

# 安装依赖
log_info "安装依赖..."
$PKG_UPDATE &>/dev/null || true

for pkg in curl wget jq bc nftables; do
    if ! command -v "$pkg" &>/dev/null; then
        case "$pkg" in
            nftables) $PKG_INSTALL nftables &>/dev/null || true ;;
            *) $PKG_INSTALL "$pkg" &>/dev/null || true ;;
        esac
    fi
done

# 创建目录
log_info "创建目录..."
mkdir -p "$INSTALL_DIR/modules"
mkdir -p /etc/vps-manager
mkdir -p /var/backups/vps-manager

# 下载文件
log_info "下载文件..."

FILES=(
    "vps.sh"
    "modules/common.sh"
    "modules/snell.sh"
    "modules/singbox.sh"
    "modules/traffic.sh"
)

for file in "${FILES[@]}"; do
    log_info "  下载 $file..."
    if ! curl -sfL --connect-timeout 30 --max-time 60 -o "$INSTALL_DIR/$file" "$REPO_URL/$file"; then
        log_error "下载失败: $file"
        exit 1
    fi
done

# 设置权限
chmod +x "$INSTALL_DIR/vps.sh"
chmod +x "$INSTALL_DIR/modules/"*.sh

# 创建命令链接
ln -sf "$INSTALL_DIR/vps.sh" "$BIN_LINK"

# 验证安装
if [[ -x "$BIN_LINK" ]]; then
    echo
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}        安装完成!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo
    echo "使用方法:"
    echo "  vps              打开主菜单"
    echo "  vps snell        Snell 管理"
    echo "  vps sb           sing-box 管理"
    echo "  vps traffic      流量监控"
    echo "  vps help         查看帮助"
    echo
else
    log_error "安装失败"
    exit 1
fi
