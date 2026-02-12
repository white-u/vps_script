#!/bin/bash

# 定义颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查 Root 权限
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}错误：请使用 root 权限运行此脚本。${NC}" 
   exit 1
fi

clear
echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}   Linux 服务器初始化 (纯净版)   ${NC}"
echo -e "${BLUE}=================================================${NC}"

# ==============================
# 1. 系统更新与清理
# ==============================
echo -e "${YELLOW}[1/6] 正在更新系统并清理旧依赖...${NC}"
apt update -y && apt upgrade -y
apt autoremove -y
apt clean
echo -e "${GREEN}系统更新完成。${NC}"

# ==============================
# 2. 修改主机名
# ==============================
echo -e "${YELLOW}[2/6] 主机名设置${NC}"
CURRENT_HOSTNAME=$(hostname)
echo -e "当前主机名: ${BLUE}${CURRENT_HOSTNAME}${NC}"
read -r -p "请输入新的主机名 (直接回车跳过): " NEW_HOSTNAME
if [ ! -z "$NEW_HOSTNAME" ]; then
    hostnamectl set-hostname "$NEW_HOSTNAME"
    sed -i "s/127.0.1.1.*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts
    if ! grep -q "127.0.1.1" /etc/hosts; then
        echo -e "127.0.1.1\t$NEW_HOSTNAME" >> /etc/hosts
    fi
    echo -e "${GREEN}主机名已修改为: ${NEW_HOSTNAME}${NC}"
else
    NEW_HOSTNAME="$CURRENT_HOSTNAME"
    echo -e "跳过主机名修改，保持: ${BLUE}${CURRENT_HOSTNAME}${NC}"
fi

# ==============================
# 3. 安装必备工具 (无 ufw/net-tools)
# ==============================
echo -e "${YELLOW}[3/6] 正在安装必备工具 (curl, wget, vim, unzip, nano)...${NC}"
apt install -y curl wget unzip nano vim
echo -e "${GREEN}工具安装完成。${NC}"

# ==============================
# 4. 内核 BBR 加速
# ==============================
echo -e "${YELLOW}[4/6] 检查并开启 BBR 加速...${NC}"
if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf; then
    if ! grep -q "net.core.default_qdisc = fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    fi
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p
    echo -e "${GREEN}BBR 已开启。${NC}"
else
    echo -e "${GREEN}BBR 已经开启，无需重复操作。${NC}"
fi

# ==============================
# 5. SSH 安全加固 (交互式)
# ==============================
echo -e "${YELLOW}[5/6] SSH 安全配置${NC}"

# 备份配置
SSHD_BACKUP="/etc/ssh/sshd_config.bak.$(date +%F_%T)"
cp /etc/ssh/sshd_config "$SSHD_BACKUP"
echo -e "已备份 SSH 配置文件至 ${SSHD_BACKUP}。"

# 辅助函数：替换或追加 sshd_config 配置项
# 用法: sshd_set "Key" "Value"
sshd_set() {
    local key="$1"
    local value="$2"
    if grep -qE "^#?\s*${key}\b" /etc/ssh/sshd_config; then
        sed -i "s/^#\?\s*${key}\b.*/${key} ${value}/" /etc/ssh/sshd_config
    else
        echo "${key} ${value}" >> /etc/ssh/sshd_config
    fi
}

# --- 修改端口 ---
while true; do
    read -p "请输入新的 SSH 端口号 (建议 10000-65535): " SSH_PORT
    if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ]; then
        if [ "$SSH_PORT" -eq 22 ]; then
            echo -e "${RED}不允许使用默认端口 22，请重新输入。${NC}"
            continue
        else
            break
        fi
    else
        echo -e "${RED}无效端口，请输入 1-65535 之间的数字。${NC}"
    fi
done

# --- 配置密钥登录 ---
echo -e "${YELLOW}--- 密钥登录设置 ---${NC}"
read -p "是否导入 SSH 公钥 (Public Key)? [y/n]: " IMPORT_KEY
if [[ "$IMPORT_KEY" =~ ^[Yy]$ ]]; then
    echo -e "请粘贴您的公钥 (ssh-rsa AAAA...):"
    read -r PUB_KEY
    if [ ! -z "$PUB_KEY" ]; then
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        if ! grep -qF "$PUB_KEY" ~/.ssh/authorized_keys 2>/dev/null; then
            printf '%s\n' "$PUB_KEY" >> ~/.ssh/authorized_keys
            chmod 600 ~/.ssh/authorized_keys
            echo -e "${GREEN}公钥已导入。${NC}"
        else
            echo -e "${YELLOW}该公钥已存在。${NC}"
        fi
        
    else
        echo -e "${RED}未输入公钥，跳过密钥设置。${NC}"
    fi
else
    echo -e "跳过密钥导入，保留默认设置。"
fi

# --- 禁用密码登录 (独立判断) ---
if [ -s ~/.ssh/authorized_keys ]; then
    echo -e "${GREEN}检测到已有 SSH 密钥。${NC}"
    read -p "是否禁用密码登录 (推荐)? [y/n]: " DISABLE_PWD
    if [[ "$DISABLE_PWD" =~ ^[Yy]$ ]]; then
        sshd_set "PasswordAuthentication" "no"
        sshd_set "ChallengeResponseAuthentication" "no"
        echo -e "${GREEN}密码登录已禁用。${NC}"
    else
        echo -e "${YELLOW}保留密码登录。${NC}"
    fi
else
    echo -e "${YELLOW}未检测到 SSH 密钥，保留密码登录。${NC}"
fi

# 应用 SSH 配置
sshd_set "Port" "$SSH_PORT"
sshd_set "PermitRootLogin" "yes"
sshd_set "PubkeyAuthentication" "yes"

# ==============================
# 6. 重启服务与提示
# ==============================
echo -e "${YELLOW}[6/6] 正在重启 SSH 服务以应用更改...${NC}"
systemctl restart sshd

if [ $? -eq 0 ]; then
    echo -e "${GREEN}SSH 服务重启成功。${NC}"
else
    echo -e "${RED}SSH 服务重启失败！配置可能出错，正在恢复备份...${NC}"
    cp "$SSHD_BACKUP" /etc/ssh/sshd_config
    systemctl restart sshd
    exit 1
fi

echo -e "${BLUE}=================================================${NC}"
echo -e "${GREEN}   配置已完成   ${NC}"
echo -e "${BLUE}=================================================${NC}"
echo -e "1. 主机名: ${BLUE}$NEW_HOSTNAME${NC}"
echo -e "2. 新 SSH 端口: ${RED}$SSH_PORT${NC}"
echo -e "3. BBR 加速: ${GREEN}已开启${NC}"
echo -e "4. 系统更新: ${GREEN}已完成${NC}"

if [[ "$DISABLE_PWD" =~ ^[Yy]$ ]]; then
    echo -e "5. 登录方式: ${GREEN}仅密钥${NC}"
else
    echo -e "5. 登录方式: ${YELLOW}密码 + 密钥${NC}"
fi

echo -e "${RED}!!! 特别注意 !!!${NC}"
echo -e "请务必在【云服务商安全组】中放行端口 ${RED}$SSH_PORT${NC} 之后再关闭当前会话。"

read -p "是否立即重启服务器? [y/n]: " REBOOT_NOW
if [[ "$REBOOT_NOW" =~ ^[Yy]$ ]]; then
    echo -e "正在重启..."
    reboot
else
    echo -e "请记得稍后手动重启以生效内核设置。"
fi