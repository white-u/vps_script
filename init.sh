#!/bin/bash
# 系统初始化脚本 v1.0.0

# 定义颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

fail() {
    echo -e "${RED}❌ 错误: $1${NC}" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}⚠️ 警告: $1${NC}" >&2
}

# 先完整下载并检查语法，失败时不执行不完整的远程内容。
install_nexttrace() {
    (
        local installer
        installer=$(mktemp) || return 1
        trap 'rm -f "$installer"' EXIT
        if ! curl -q -fsSL --proto '=https' --proto-redir '=https' \
            --connect-timeout 10 --max-time 30 -o "$installer" https://nxtrace.org/nt \
            || [ ! -s "$installer" ] || ! bash -n "$installer"; then
            warn "NextTrace 安装脚本下载或语法检查失败，未执行。"
            return 1
        fi
        bash "$installer"
    )
}

configure_network_time() {
    local service="" candidate load_state sync_status attempt
    local -a candidates=(chrony.service chronyd.service ntpsec.service ntp.service openntpd.service systemd-timesyncd.service)
    command -v timedatectl >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1 \
        || fail "网络校时需要 systemd、systemctl 和 timedatectl"
    systemctl show --property=Version --value >/dev/null \
        || fail "无法连接 systemd，网络校时配置已停止"

    # 优先复用正在运行的服务，避免替换已有 chrony/NTP 配置。
    for candidate in "${candidates[@]}"; do
        if systemctl is-active --quiet "$candidate"; then
            service=$candidate
            break
        fi
    done
    if [ -z "$service" ]; then
        for candidate in "${candidates[@]}"; do
            load_state=$(systemctl show --property=LoadState --value "$candidate" 2>/dev/null)
            if [[ "$load_state" == "loaded" || "$load_state" == "masked" ]]; then
                service=$candidate
                break
            fi
        done
    fi
    if [ -z "$service" ]; then
        echo -e "${YELLOW}未检测到校时服务，正在安装 systemd-timesyncd...${NC}"
        apt install -y systemd-timesyncd || fail "校时服务安装失败，请检查 APT 源和网络"
        service=systemd-timesyncd.service
    fi
    systemctl enable --now "$service" \
        || fail "无法启用校时服务 ${service}，请检查服务是否被屏蔽及 journalctl 日志"
    systemctl is-active --quiet "$service" || fail "校时服务 ${service} 未正常运行"

    TIME_SYNC_STATUS="已启用（等待同步）"
    echo -e "${YELLOW}校时服务 ${service} 已启用并设为开机启动，最多等待 30 秒确认同步...${NC}"
    for ((attempt=0; attempt<=6; attempt++)); do
        if ! sync_status=$(timedatectl show --property=NTPSynchronized --value 2>&1); then
            warn "无法读取时间同步状态: ${sync_status}"
            break
        fi
        if [ "$sync_status" == "yes" ]; then
            TIME_SYNC_STATUS="已同步（${service}，开机自动校时）"
            echo -e "${GREEN}网络时间同步成功。${NC}"
            return 0
        fi
        if [ "$attempt" -lt 6 ]; then sleep 5; fi
    done
    systemctl is-active --quiet "$service" || fail "校时服务 ${service} 已停止，请检查服务日志"
    warn "自动校时已启用，但尚未确认同步。请检查 timedatectl status 和 journalctl -u ${service} -n 30 --no-pager；确认 DNS、NTP 服务器及 UDP 123 网络可达。"
}

# ==============================
# 0. 环境预检
# ==============================
if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}错误：本脚本仅支持 Debian/Ubuntu 系统。${NC}"
    exit 1
fi

# Windows 终端兼容: 清洗 \r (定义在开头，确保全局可用)
strip_cr() { echo "${1//$'\r'/}"; }

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
echo -e "${YELLOW}[1/7] 正在更新系统并清理旧依赖...${NC}"
apt update -y && apt upgrade -y || fail "系统软件包更新失败，请检查 APT 源和网络"
apt autoremove -y || warn "apt autoremove 执行失败，可稍后手动运行"
apt clean || warn "apt clean 执行失败"
echo -e "${GREEN}系统更新完成。${NC}"

# ==============================
# 2. 网络时间同步
# ==============================
echo -e "${YELLOW}[2/7] 配置网络自动校时...${NC}"
configure_network_time

# ==============================
# 3. 修改主机名
# ==============================
echo -e "${YELLOW}[3/7] 主机名设置${NC}"
CURRENT_HOSTNAME=$(hostname)
echo -e "当前主机名: ${BLUE}${CURRENT_HOSTNAME}${NC}"
read -r -p "请输入新的主机名 (直接回车跳过): " NEW_HOSTNAME
NEW_HOSTNAME=$(strip_cr "$NEW_HOSTNAME")
if [ ! -z "$NEW_HOSTNAME" ]; then
    hostnamectl set-hostname "$NEW_HOSTNAME" || fail "主机名修改失败"
    sed -i "s/127.0.1.1.*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts || fail "/etc/hosts 更新失败"
    if ! grep -q "127.0.1.1" /etc/hosts; then
        echo -e "127.0.1.1\t$NEW_HOSTNAME" >> /etc/hosts || fail "/etc/hosts 写入失败"
    fi
    echo -e "${GREEN}主机名已修改为: ${NEW_HOSTNAME}${NC}"
else
    NEW_HOSTNAME="$CURRENT_HOSTNAME"
    echo -e "跳过主机名修改，保持: ${BLUE}${CURRENT_HOSTNAME}${NC}"
fi

# ==============================
# 4. 安装必备工具 (无 ufw/net-tools)
# ==============================
echo -e "${YELLOW}[4/7] 正在安装必备工具 (curl, wget, vim, unzip, nano, iperf3)...${NC}"
apt install -y curl wget unzip nano vim iperf3 || fail "基础工具安装失败"

echo -e "${YELLOW}正在安装 nexttrace...${NC}"
if install_nexttrace; then
    echo -e "${GREEN}nexttrace 安装完成。${NC}"
else
    warn "nexttrace 安装失败，请检查网络后重新运行初始化脚本。"
fi

echo -e "${GREEN}工具安装完成。${NC}"

# ==============================
# 5. 内核 BBR 加速
# ==============================
echo -e "${YELLOW}[5/7] 检查并开启 BBR 加速...${NC}"
if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf; then
    if ! grep -q "net.core.default_qdisc = fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    fi
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p || fail "内核参数加载失败，请检查 /etc/sysctl.conf"
    echo -e "${GREEN}BBR 已开启。${NC}"
else
    echo -e "${GREEN}BBR 已经开启，无需重复操作。${NC}"
fi

# ==============================
# 6. SSH 安全加固 (交互式)
# ==============================
echo -e "${YELLOW}[6/7] SSH 安全配置${NC}"

# 备份配置
SSHD_BACKUP="/etc/ssh/sshd_config.bak.$(date +%F_%T)"
cp /etc/ssh/sshd_config "$SSHD_BACKUP" || fail "SSH 配置备份失败，已停止修改"
echo -e "已备份 SSH 配置文件至 ${SSHD_BACKUP}。"

# 全局设置放在 Include 和 Match 之前，避免云镜像的前置配置抢先生效。
# 保留 Match 内的现有策略；稍后验证当前 root 连接的最终生效配置。
sshd_set() {
    local key="$1" value="$2" tmp
    tmp=$(mktemp /etc/ssh/sshd_config.new.XXXXXX) || fail "SSH 配置临时文件创建失败"
    if ! cp -p /etc/ssh/sshd_config "$tmp"; then
        rm -f "$tmp"
        fail "SSH 配置元数据复制失败"
    fi
    if ! awk -v key="$key" -v value="$value" '
        BEGIN { print key " " value }
        {
            option = $0
            sub(/^[ \t]+/, "", option)
            sub(/[ \t=].*$/, "", option)
            option = tolower(option)
            if (option == "match") in_match = 1
            if (!in_match && option == tolower(key)) next
            print
        }
    ' /etc/ssh/sshd_config > "$tmp"; then
        rm -f "$tmp"
        fail "SSH 配置项 ${key} 生成失败"
    fi
    if ! mv -f "$tmp" /etc/ssh/sshd_config; then
        rm -f "$tmp"
        fail "SSH 配置项 ${key} 写入失败"
    fi
    rm -f "$tmp"
}

resolve_ssh_client_host() {
    local rc=0
    command -v python3 >/dev/null 2>&1 || {
        warn "UseDNS yes 的客户端域名验证需要 Python 3，未重载服务。"
        return 1
    }
    command -v timeout >/dev/null 2>&1 || {
        warn "UseDNS yes 的客户端域名验证需要 GNU timeout，未重载服务。"
        return 1
    }
    # 使用系统解析器，验证 PTR 与正向地址一致；失败时不能把域名规则当作已验证。
    # 由外部进程计时并强制终止；不能依赖 Python 在阻塞的 NSS 调用内处理信号。
    timeout --foreground --signal=KILL 10s python3 -I - "$1" <<'PY' || rc=$?
import ipaddress
import re
import socket
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    peer = (str(address), 0) if address.version == 4 else (str(address), 0, 0, 0)
    hostname = socket.getnameinfo(peer, socket.NI_NAMEREQD)[0].lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", hostname):
        raise ValueError("客户端域名格式无法可靠验证")
    try:
        socket.getaddrinfo(hostname, None, flags=socket.AI_NUMERICHOST)
    except socket.gaierror:
        pass
    else:
        raise ValueError("反向解析返回了数字地址而非域名")
    records = socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)
    if not any(ipaddress.ip_address(record[4][0]) == address for record in records):
        raise ValueError("客户端域名的正反向解析不一致")
    print(hostname)
except (OSError, ValueError) as error:
    print(f"SSH 客户端域名验证失败: {error}", file=sys.stderr)
    sys.exit(1)
PY
    if [ "$rc" -ne 0 ]; then
        case "$rc" in
            124|137) warn "SSH 客户端域名验证失败: DNS 查询超时或解析进程被终止（限制 10 秒）。" ;;
        esac
        return 1
    fi
}

validate_sshd_settings() {
    local effective global_effective context client_ip client_port server_ip server_port client_host use_dns
    local -a contexts=(global root)
    read -r client_ip client_port server_ip server_port <<< "${SSH_CONNECTION:-127.0.0.1 0 127.0.0.1 0}"
    global_effective=$(sshd -T) || return 1
    use_dns=$(awk '$1 == "usedns" {print $2}' <<< "$global_effective")
    case "$use_dns" in
        yes)
            if [ -z "${SSH_CONNECTION:-}" ]; then
                warn "UseDNS yes 时需要 SSH_CONNECTION 才能验证当前客户端域名，未重载服务。"
                return 1
            fi
            client_host=$(resolve_ssh_client_host "$client_ip") || return 1
            contexts+=(root-dns)
            ;;
        no) ;;
        *) warn "无法确定 SSH UseDNS 生效配置，未重载服务。"; return 1 ;;
    esac
    # DNS 成功时检查域名；也检查以 IP 匹配的情形，避免 DNS 失败时绕过验证。
    for context in "${contexts[@]}"; do
        if [ "$context" = global ]; then
            effective=$global_effective
        elif [ "$context" = root-dns ]; then
            effective=$(sshd -T -C "user=root,host=${client_host},addr=${client_ip},laddr=${server_ip},lport=${SSH_PORT}") || return 1
        else
            effective=$(sshd -T -C "user=root,host=${client_ip},addr=${client_ip},laddr=${server_ip},lport=${SSH_PORT}") || return 1
        fi
        if ! awk -v port="$SSH_PORT" -v disable_pwd="${DISABLE_PWD:-n}" '
            $1 == "port" { if ($2 == port) port_ok = 1; else unexpected_port = 1 }
            $1 == "permitrootlogin" && $2 == "yes" { root_ok = 1 }
            $1 == "pubkeyauthentication" && $2 == "yes" { key_ok = 1 }
            $1 == "passwordauthentication" && $2 == "no" { password_off = 1 }
            $1 ~ /^(kbdinteractiveauthentication|challengeresponseauthentication)$/ && $2 == "no" { interactive_off = 1 }
            END { exit !(port_ok && !unexpected_port && root_ok && key_ok &&
                (tolower(disable_pwd) != "y" || (password_off && interactive_off))) }
        ' <<< "$effective"; then
            warn "SSH 生效配置与所选设置不符（${context}），未重载服务。"
            return 1
        fi
    done
}

# --- 修改端口 ---
while true; do
    read -p "请输入新的 SSH 端口号 (建议 10000-65535): " SSH_PORT
    SSH_PORT=$(strip_cr "$SSH_PORT")
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

echo -e "${YELLOW}切换 SSH 端口前，请先在云服务商安全组中放行 TCP ${SSH_PORT}。${NC}"
read -p "确认安全组已放行该端口？请输入 yes 继续: " PORT_READY
PORT_READY=$(strip_cr "$PORT_READY")
if [ "$PORT_READY" != "yes" ]; then
    echo -e "${YELLOW}已取消 SSH 配置，当前 SSH 服务未改动。${NC}"
    exit 0
fi

# 先放行主机本地防火墙，再修改 sshd，避免正确配置也被本机规则拦截。
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow "${SSH_PORT}/tcp" >/dev/null || { echo -e "${RED}UFW 放行失败，已停止。${NC}"; exit 1; }
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" >/dev/null && firewall-cmd --reload >/dev/null || {
        echo -e "${RED}firewalld 放行失败，已停止。${NC}"; exit 1;
    }
fi

# --- 配置密钥登录 ---
echo -e "${YELLOW}--- 密钥登录设置 ---${NC}"
read -p "是否导入 SSH 公钥 (Public Key)? [y/n]: " IMPORT_KEY
IMPORT_KEY=$(strip_cr "$IMPORT_KEY")
if [[ "$IMPORT_KEY" =~ ^[Yy]$ ]]; then
    echo -e "请粘贴您的公钥 (ssh-rsa AAAA...):"
    read -r PUB_KEY
    PUB_KEY=$(strip_cr "$PUB_KEY")
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
    DISABLE_PWD=$(strip_cr "$DISABLE_PWD")
    if [[ "$DISABLE_PWD" =~ ^[Yy]$ ]]; then
        sshd_set "PasswordAuthentication" "no"
        sshd_set "ChallengeResponseAuthentication" "no"
        echo -e "${YELLOW}已设置禁用密码登录，稍后验证最终生效配置。${NC}"
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
# 7. 重启服务与提示
# ==============================
echo -e "${YELLOW}[7/7] 正在验证 SSH 配置并重启服务...${NC}"

# 验证配置语法 (防止重启失败导致失联)
if ! sshd -t; then
    echo -e "${RED}错误：SSH 配置文件语法校验失败！${NC}"
    echo -e "${RED}正在回滚配置至备份...${NC}"
    cp "$SSHD_BACKUP" /etc/ssh/sshd_config || fail "SSH 配置回滚失败，请从备份手动恢复"
    echo -e "${YELLOW}配置已回滚。请检查输入是否正确后重试。${NC}"
    exit 1
fi

if ! validate_sshd_settings; then
    echo -e "${RED}错误：SSH 最终生效配置校验失败，正在回滚...${NC}"
    cp "$SSHD_BACKUP" /etc/ssh/sshd_config || fail "SSH 配置回滚失败，请从备份手动恢复"
    exit 1
fi

SSH_SERVICE="sshd"
systemctl cat sshd.service >/dev/null 2>&1 || SSH_SERVICE="ssh"
if systemctl reload "$SSH_SERVICE" && sleep 1 && ss -lntH | awk '{print $4}' | grep -Eq "(^|\]):${SSH_PORT}$|(^|[^0-9])${SSH_PORT}$"; then
    echo -e "${GREEN}SSH 服务已安全重载，并确认监听新端口。${NC}"
else
    echo -e "${RED}SSH 新端口未成功监听，正在恢复备份...${NC}"
    cp "$SSHD_BACKUP" /etc/ssh/sshd_config || fail "SSH 配置回滚失败，请从备份手动恢复"
    systemctl reload "$SSH_SERVICE" 2>/dev/null || systemctl restart "$SSH_SERVICE" 2>/dev/null
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

echo -e "6. 网络校时: ${BLUE}${TIME_SYNC_STATUS}${NC}"

echo -e "${RED}!!! 特别注意 !!!${NC}"
echo -e "请先从一个新的终端测试端口 ${RED}$SSH_PORT${NC} 登录成功，再关闭当前会话。"

read -p "是否立即重启服务器? [y/n]: " REBOOT_NOW
REBOOT_NOW=$(strip_cr "$REBOOT_NOW")
if [[ "$REBOOT_NOW" =~ ^[Yy]$ ]]; then
    echo -e "正在重启..."
    reboot || fail "系统重启命令执行失败"
else
    echo -e "请记得稍后手动重启以生效内核设置。"
fi
