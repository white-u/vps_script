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
[[ $EUID -ne 0 ]] && { log_error "请使用 root 用户运行"; exit 1; }

echo
echo "============================================"
echo "        VPS Manager 安装程序"
echo "============================================"
echo

# 检测系统
if command -v apt-get &>/dev/null; then
    PKG_INSTALL="apt-get install -y"
    apt-get update -y &>/dev/null || true
elif command -v yum &>/dev/null; then
    PKG_INSTALL="yum install -y"
else
    log_error "不支持的系统"
    exit 1
fi

# 安装依赖
log_info "安装依赖..."
for pkg in curl wget jq bc nftables; do
    command -v $pkg &>/dev/null || $PKG_INSTALL $pkg &>/dev/null || true
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
    if ! curl -sfL -o "$INSTALL_DIR/$file" "$REPO_URL/$file"; then
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
