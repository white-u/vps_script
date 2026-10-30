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

install_base_tools() {
    local iperf_status query_status=0
    iperf_status=$(dpkg-query -W -f='${Status}' iperf3 2>/dev/null) || query_status=$?
    [[ "$query_status" == 0 || "$query_status" == 1 ]] || fail "无法读取 iperf3 安装状态"
    if [[ "$iperf_status" != 'install ok installed' ]]; then
        printf '%s\n' 'iperf3 iperf3/start_daemon boolean false' | debconf-set-selections \
            || fail "iperf3 默认不启动后台服务的设置失败，未继续安装"
    fi
    # 首次安装不询问是否启动测速服务；已安装的服务沿用管理员原设置。
    DEBIAN_FRONTEND=noninteractive apt install -y curl ca-certificates tzdata python3 wget unzip nano vim iperf3 \
        || fail "基础工具安装失败"
}

configure_timezone() {
    local current inferred zones provider response
    current=$(timedatectl show --property=Timezone --value) || fail "无法读取系统时区"
    zones=$(timedatectl list-timezones) || fail "无法读取系统时区列表，请检查 tzdata"
    echo "当前系统时区: ${current}"
    echo "正在根据服务器出口公网 IP 自动设置时区（IP 定位可能有误）..."
    inferred=""
    for provider in 'https://ipwho.is/?fields=success,timezone' 'https://ipinfo.io/json'; do
        if response=$(curl -q -fsSL --proto '=https' --proto-redir '=https' \
            --connect-timeout 5 --max-time 10 "$provider"); then
            inferred=$(python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    if sys.argv[1].startswith("https://ipwho.is/"):
        if data["success"] is not True:
            raise ValueError("IP 定位服务报告失败")
        zone = data["timezone"]["id"]
    else:
        zone = data["timezone"]
    if not isinstance(zone, str) or not zone or any(c.isspace() for c in zone):
        raise ValueError("时区格式无效")
    print(zone)
except (ValueError, KeyError, TypeError) as error:
    print("时区查询解析失败: " + str(error), file=sys.stderr)
    sys.exit(1)
' "$provider" <<< "$response") || inferred=""
            if [[ -n "$inferred" ]] && grep -qxF -- "$inferred" <<< "$zones"; then
                echo "推断时区: ${inferred}（来源: ${provider}）"
                break
            fi
        fi
        inferred=""
        warn "时区查询 ${provider} 失败或返回无效时区。"
        if [[ "$provider" == https://ipwho.is/* ]]; then
            warn "尝试备用服务 ipinfo.io。"
        fi
    done
    if [[ -z "$inferred" ]]; then
        warn "公网 IP 时区查询均不可用，保留 ${current}。"
        inferred=$current
    fi
    if [[ "$inferred" != "$current" ]]; then
        timedatectl set-timezone "$inferred" || fail "时区设置失败"
    fi
    SYSTEM_TIMEZONE=$(timedatectl show --property=Timezone --value) || fail "无法确认系统时区"
    [[ "$SYSTEM_TIMEZONE" == "$inferred" ]] || fail "时区设置未生效"
    echo "系统时区: ${SYSTEM_TIMEZONE}"
}

configure_ip_preference() {
    local choice stage backup source=/etc/gai.conf
    while true; do
        read_prompt -r -p "网络地址优先级（1 = IPv4 优先 / 2 = IPv6 优先，回车默认 1）: " choice
        choice=$(strip_cr "$choice")
        case "${choice:-1}" in
            1|4) choice=4; break ;;
            2|6) choice=6; break ;;
            keep) IP_PREFERENCE="保留系统配置"; return 0 ;;
            *) warn "请输入 1（IPv4 优先）或 2（IPv6 优先）。" ;;
        esac
    done
    [[ ! -L "$source" && ( ! -e "$source" || -f "$source" ) ]] || fail "gai.conf 不是普通文件，未修改"
    stage=$(mktemp /etc/gai.conf.new.XXXXXX) || fail "无法创建地址优先级配置临时文件"
    if [[ -e "$source" ]]; then
        backup=$(mktemp /etc/gai.conf.bak.XXXXXX) || { rm -f "$stage"; fail "无法创建 gai.conf 备份"; }
        if ! cp -p "$source" "$backup" || ! cp -p "$source" "$stage"; then
            rm -f "$stage"; fail "gai.conf 备份失败"
        fi
        echo "原地址优先级配置已备份至 ${backup}"
    else
        source=/dev/null
        chmod 644 "$stage" || { rm -f "$stage"; fail "gai.conf 权限设置失败"; }
    fi
    # 一旦指定 precedence，glibc 就不再使用默认表，因此写入完整表。
    if ! awk -v family="$choice" '
        /^[ \t]*precedence[ \t]/ { next }
        /^# BEGIN vps-init precedence$/ { managed=1; next }
        /^# END vps-init precedence$/ { managed=0; next }
        !managed { print }
        END {
            print "# BEGIN vps-init precedence"
            print "precedence ::1/128 50"
            print "precedence ::/0 40"
            print "precedence 2002::/16 30"
            print "precedence ::/96 20"
            print "precedence ::ffff:0:0/96 " (family == 4 ? 100 : 10)
            print "# END vps-init precedence"
        }
    ' "$source" > "$stage" || ! mv -f "$stage" /etc/gai.conf; then
        rm -f "$stage"; fail "地址优先级配置写入失败"
    fi
    IP_PREFERENCE="IPv${choice} 优先"
    echo "已设置 ${IP_PREFERENCE}。不禁用另一协议。"
}

valid_public_key() {
    [[ "$1" != *$'\n'* && "$1" =~ ^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh.com)[[:blank:]] ]] || return 1
    ssh-keygen -lf - <<< "$1" >/dev/null 2>&1
}

import_public_key() {
    local key="$1" file="$2" directory stage
    valid_public_key "$key" || { warn "无效公钥：请粘贴完整的一行 OpenSSH 公钥，未写入。"; return 1; }
    directory=$(dirname "$file")
    [[ ! -L "$directory" && ! -L "$file" && ( ! -e "$file" || -f "$file" ) ]] || {
        warn "公钥路径包含符号链接或不是普通文件，未写入。"; return 1;
    }
    if [[ ! -d "$directory" ]]; then
        mkdir -m 700 -p "$directory" || return 1
    fi
    stage=$(mktemp "${directory}/authorized_keys.new.XXXXXX") || return 1
    if [[ -f "$file" ]] && ! cp -p "$file" "$stage"; then rm -f "$stage"; return 1; fi
    if ! grep -qxF -- "$key" "$stage"; then
        # 为已有文件补换行，避免与最后一条密钥拼接。
        if ! { printf '\n%s\n' "$key" >> "$stage"; }; then rm -f "$stage"; return 1; fi
    fi
    if ! chmod 600 "$stage" || ! mv -f "$stage" "$file"; then rm -f "$stage"; return 1; fi
    echo "公钥已导入（或已存在）。"
}

begin_ssh_transaction() {
    local tool
    for tool in sshd ssh-keygen ss python3; do command -v "$tool" >/dev/null 2>&1 || fail "SSH 配置需要 ${tool}"; done
    SSH_ROOT_HOME=$(getent passwd root | cut -d: -f6)
    [[ "$SSH_ROOT_HOME" == /* && -d "$SSH_ROOT_HOME" ]] || fail "无法确定 root 主目录"
    SSH_KEY_FILE="${SSH_ROOT_HOME}/.ssh/authorized_keys"
    [[ ! -L "$SSH_KEY_FILE" && ( ! -e "$SSH_KEY_FILE" || -f "$SSH_KEY_FILE" ) ]] || fail "authorized_keys 不是普通文件"
    SSH_BACKUP_DIR=$(mktemp -d /etc/ssh/init-backup.XXXXXX) || fail "SSH 备份目录创建失败"
    chmod 700 "$SSH_BACKUP_DIR" || fail "SSH 备份目录权限设置失败"
    SSHD_BACKUP="${SSH_BACKUP_DIR}/sshd_config"
    cp -p /etc/ssh/sshd_config "$SSHD_BACKUP" || fail "SSH 配置备份失败"
    SSH_KEY_EXISTED=0
    if [[ -f "$SSH_KEY_FILE" ]]; then
        cp -p "$SSH_KEY_FILE" "${SSH_BACKUP_DIR}/authorized_keys" || fail "公钥备份失败"
        SSH_KEY_EXISTED=1
    fi
    SSH_KEY_CHANGED=0
    SSH_EXPECTED_KEY_FILE=""
    SSH_RELOAD_ATTEMPTED=0
    SSH_TX_ACTIVE=1
    trap 'ssh_transaction_exit $?' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    echo "SSH 配置已备份至 ${SSH_BACKUP_DIR}"
}

rollback_ssh_transaction() {
    local stage status=0 config_restored=0
    if stage=$(mktemp /etc/ssh/sshd_config.restore.XXXXXX) && \
        cp -p "$SSHD_BACKUP" "$stage" && mv -f "$stage" /etc/ssh/sshd_config; then
        config_restored=1
    else
        [[ -z "$stage" ]] || rm -f "$stage"
        status=1
    fi
    if [[ "${SSH_KEY_CHANGED:-0}" == 1 ]]; then
        if [[ "$SSH_KEY_EXISTED" == 1 ]]; then
            if ! stage=$(mktemp "$(dirname "$SSH_KEY_FILE")/authorized_keys.restore.XXXXXX") || \
                ! cp -p "${SSH_BACKUP_DIR}/authorized_keys" "$stage" || ! mv -f "$stage" "$SSH_KEY_FILE"; then
                [[ -z "$stage" ]] || rm -f "$stage"
                status=1
            fi
        else
            rm -f "$SSH_KEY_FILE" || status=1
        fi
    fi
    if [[ "${SSH_RELOAD_ATTEMPTED:-0}" == 1 && "$config_restored" == 1 ]]; then
        if ! sshd -t || ! systemctl reload "$SSH_SERVICE" || ! systemctl is-active --quiet "$SSH_SERVICE"; then
            warn "SSH 服务恢复失败，请通过当前会话或控制台检查。"; status=1
        fi
    fi
    return "$status"
}

ssh_transaction_exit() {
    local status="$1"
    trap - EXIT
    trap '' INT TERM HUP
    if [[ "${SSH_TX_ACTIVE:-0}" == 1 ]]; then
        if rollback_ssh_transaction; then
            warn "SSH 操作未完成，原配置及公钥已恢复。备份: ${SSH_BACKUP_DIR}"
        else
            warn "SSH 回滚失败！请保留当前会话，通过备份 ${SSH_BACKUP_DIR} 手动恢复。"
        fi
        [[ "$status" != 0 ]] || status=1
    fi
    exit "$status"
}

activate_ssh_settings() {
    SSH_RELOAD_ATTEMPTED=1
    if systemctl reload "$SSH_SERVICE" && sleep 1 && systemctl is-active --quiet "$SSH_SERVICE" && \
        ss -lntpH | awk -v port="$SSH_PORT" '$4 ~ (":" port "$") && /"sshd"/ {found=1} END {exit !found}'; then
        echo "SSH 服务已重载，并确认 sshd 正在监听新端口。"
    else
        fail "SSH 新端口未成功由 sshd 监听，将恢复备份"
    fi
    SSH_TX_ACTIVE=0
    trap - EXIT INT TERM HUP
}

validate_root_access() {
    # sshd -T 展开 Match，但不会判断用户准入规则和磁盘上的公钥是否可用。
    python3 -c '
import fnmatch, ipaddress, os, pathlib, pwd, grp, re, shlex, subprocess, sys
settings = {}
for line in sys.stdin:
    name, _, value = line.rstrip().partition(" ")
    settings[name] = value
home, expected_file, peer, hostname = sys.argv[1:]
def reject(message):
    print("SSH root 登录条件验证失败: " + message, file=sys.stderr)
    sys.exit(1)
def glob(pattern, value):
    if any(c in pattern for c in "[]\\"):
        reject("无法可靠验证的访问规则: " + pattern)
    return fnmatch.fnmatchcase(value, pattern)
def host_matches(patterns):
    positive = False
    for item in patterns.split(","):
        negative = item.startswith("!")
        pattern = item[1:] if negative else item
        if "/" in pattern:
            try:
                matches = ipaddress.ip_address(peer) in ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                reject("无效的地址访问规则: " + item)
        else:
            matches = glob(pattern.lower(), peer.lower()) or glob(pattern.lower(), hostname.lower())
        if matches and negative:
            return False
        positive |= matches
    return positive
def user_matches(pattern):
    user, sep, host = pattern.partition("@")
    if user.startswith("!"):
        reject("无法可靠验证的用户规则: " + pattern)
    return glob(user, "root") and (not sep or host_matches(host))
for directive in ("denyusers", "allowusers"):
    patterns = settings.get(directive, "").split()
    matched = any(user_matches(p) for p in patterns)
    if patterns and (matched if directive == "denyusers" else not matched):
        reject(directive + " 阻止当前 root 客户端登录")
account = pwd.getpwnam("root")
groups = [grp.getgrgid(gid).gr_name for gid in os.getgrouplist("root", account.pw_gid)]
for directive in ("denygroups", "allowgroups"):
    patterns = settings.get(directive, "").split()
    matched = any(glob(p, g) for p in patterns for g in groups)
    if patterns and (matched if directive == "denygroups" else not matched):
        reject(directive + " 阻止 root 所属组登录")
if settings.get("forcecommand", "none") != "none" or settings.get("chrootdirectory", "none") != "none":
    reject("存在 ForceCommand 或 ChrootDirectory，无法确认普通交互登录")
methods = settings.get("authenticationmethods", "any").split()
key_only = settings.get("passwordauthentication") == "no" and settings.get("kbdinteractiveauthentication", "no") == "no"
if key_only and not any(m in ("any", "publickey") for m in methods):
    reject("AuthenticationMethods 不允许单公钥登录")
paths = []
for item in shlex.split(settings.get("authorizedkeysfile", "none")):
    if item == "none":
        continue
    # 一次替换，防止 %%h 被错误展开为主目录。
    item = re.sub(r"%[%huU]", lambda m: {"%%":"%", "%h":home, "%u":"root", "%U":"0"}[m[0]], item)
    paths.append(pathlib.Path(item) if item.startswith("/") else pathlib.Path(home, item))
if not paths:
    reject("AuthorizedKeysFile 未启用公钥文件")
if expected_file and pathlib.Path(expected_file) not in paths:
    reject("AuthorizedKeysFile 不读取导入的文件 " + expected_file)
if not (expected_file or key_only):
    sys.exit(0)
accepted = settings.get("pubkeyacceptedalgorithms", "").split(",")
for path in paths:
    try:
        if not path.is_file():
            continue
        if settings.get("strictmodes", "yes") == "yes":
            for entry in (path, path.parent, pathlib.Path(home)):
                info = entry.stat()
                if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                    raise ValueError("公钥文件或目录权限不安全: " + str(entry))
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) < 2 or "-cert-" in parts[0]:
                continue
            algorithms = ["rsa-sha2-512", "rsa-sha2-256"] if parts[0] == "ssh-rsa" else [parts[0]]
            if not any(a in accepted for a in algorithms):
                continue
            # 不把带 from/command 等限制的旧密钥当作已确认可用的普通登录密钥。
            result = subprocess.run(["ssh-keygen", "-lf", "-"], input=line + "\n", text=True, capture_output=True)
            if result.returncode == 0:
                sys.exit(0)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
reject("未找到权限正确、算法受支持的有效普通公钥；请检查公钥文件及限制选项")
' "${SSH_ROOT_HOME:-$HOME}" "${SSH_EXPECTED_KEY_FILE:-}" "$1" "$2"
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

configure_bbr() {
    local congestion qdisc stage source=/etc/sysctl.d/99-vps-init-bbr.conf
    congestion=$(sysctl -n net.ipv4.tcp_congestion_control) || fail "无法读取拥塞控制运行状态"
    qdisc=$(sysctl -n net.core.default_qdisc) || fail "无法读取队列运行状态"
    if [[ "$congestion" != bbr || "$qdisc" != fq ]]; then
        sysctl -w net.core.default_qdisc=fq net.ipv4.tcp_congestion_control=bbr \
            || fail "BBR 运行参数应用失败，未报告开启成功"
    fi
    congestion=$(sysctl -n net.ipv4.tcp_congestion_control) || fail "无法确认 BBR 运行状态"
    qdisc=$(sysctl -n net.core.default_qdisc) || fail "无法确认队列运行状态"
    [[ "$congestion" == bbr && "$qdisc" == fq ]] || fail "BBR 运行参数未生效"
    mkdir -p /etc/sysctl.d || fail "无法创建 sysctl.d 配置目录"
    stage=$(mktemp /etc/sysctl.d/99-vps-init-bbr.conf.new.XXXXXX) || fail "无法创建 BBR 配置临时文件"
    if [[ -e "$source" ]]; then
        if ! cp -p "$source" "$stage"; then rm -f "$stage"; fail "BBR 配置备份失败"; fi
    else
        source=/dev/null
        if ! chmod 644 "$stage"; then rm -f "$stage"; fail "BBR 配置权限设置失败"; fi
    fi
    if ! awk '
        {
            key=$0; sub(/^[ \t]+/, "", key); sub(/[ \t=].*$/, "", key)
            if (key == "net.core.default_qdisc") {
                if (!fq++) print "net.core.default_qdisc = fq"; next
            }
            if (key == "net.ipv4.tcp_congestion_control") {
                if (!bbr++) print "net.ipv4.tcp_congestion_control = bbr"; next
            }
            print
        }
        END {
            if (!fq) print "net.core.default_qdisc = fq"
            if (!bbr) print "net.ipv4.tcp_congestion_control = bbr"
        }
    ' "$source" > "$stage" || ! mv -f "$stage" /etc/sysctl.d/99-vps-init-bbr.conf; then
        rm -f "$stage"
        fail "BBR 运行参数已应用，但持久化配置写入失败"
    fi
    echo -e "${GREEN}BBR 已开启，并确认运行参数与持久化配置。${NC}"
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

# Windows 终端兼容: 清洗 \r (定义在开头，确保全局可用)
read_prompt() {
    local rc
    if read "$@"; then return 0; else rc=$?; fi
    if [[ "$rc" -ne 1 ]]; then
        echo "读取输入失败（退出码 ${rc}）。" >&2
        exit "$rc"
    fi
    echo
    echo "输入已结束，退出管理。"
    exit 0
}

strip_cr() { echo "${1//$'\r'/}"; }

# 全局设置放在 Include 和 Match 之前，避免云镜像的前置配置抢先生效。
# 保留 Match 内的现有策略；稍后验证当前 root 连接的最终生效配置。
sshd_set() {
    local settings tmp
    (( $# >= 2 && $# % 2 == 0 )) || fail "SSH 设置必须成对提供配置项和值"
    settings=$(printf '%s %s\n' "$@") || fail "SSH 配置项生成失败"
    tmp=$(mktemp /etc/ssh/sshd_config.new.XXXXXX) || fail "SSH 配置临时文件创建失败"
    if ! cp -p /etc/ssh/sshd_config "$tmp"; then
        rm -f "$tmp"
        fail "SSH 配置元数据复制失败"
    fi
    if ! SSH_INIT_SETTINGS="$settings" awk '
        BEGIN {
            count = split(ENVIRON["SSH_INIT_SETTINGS"], lines, "\n")
            for (i = 1; i <= count; i++) {
                print lines[i]
                split(lines[i], fields, " ")
                replaced[tolower(fields[1])] = 1
            }
        }
        {
            option = $0
            sub(/^[ \t]+/, "", option)
            sub(/[ \t=].*$/, "", option)
            option = tolower(option)
            if (option == "match") in_match = 1
            if (!in_match && (option in replaced)) next
            print
        }
    ' /etc/ssh/sshd_config > "$tmp"; then
        rm -f "$tmp"
        fail "SSH 配置生成失败"
    fi
    if ! mv -f "$tmp" /etc/ssh/sshd_config; then
        rm -f "$tmp"
        fail "SSH 配置写入失败"
    fi
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
    SSH_AUTH_SUMMARY="未知（未完成验证）"
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
        if [[ "$context" != global ]]; then
            validate_root_access "$client_ip" "${client_host:-$client_ip}" <<< "$effective" || return 1
        fi
    done
    SSH_AUTH_SUMMARY="公钥已启用"
    if grep -qx 'passwordauthentication yes' <<< "$effective"; then
        SSH_AUTH_SUMMARY+=" · 密码已启用"
    else
        SSH_AUTH_SUMMARY+=" · 密码已禁用"
    fi
    if grep -Eq '^(kbdinteractiveauthentication|challengeresponseauthentication) yes$' <<< "$effective"; then
        SSH_AUTH_SUMMARY+=" · 交互式认证已启用"
    else
        SSH_AUTH_SUMMARY+=" · 交互式认证已禁用"
    fi
}

# ==============================
# 0. 环境预检
# ==============================
if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}错误：本脚本仅支持 Debian/Ubuntu 系统。${NC}"
    exit 1
fi

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
# 1. 系统更新与基础工具
# ==============================
echo -e "${YELLOW}[1/7] 正在更新系统并安装基础工具...${NC}"
apt update -y && apt upgrade -y || fail "系统软件包更新失败，请检查 APT 源和网络"
install_base_tools
echo -e "${GREEN}系统更新及基础工具安装完成。${NC}"

# ==============================
# 2. 网络时间同步
# ==============================
echo -e "${YELLOW}[2/7] 配置网络优先级、时区及自动校时...${NC}"
configure_ip_preference
configure_timezone
configure_network_time

# ==============================
# 3. 修改主机名
# ==============================
echo -e "${YELLOW}[3/7] 主机名设置${NC}"
CURRENT_HOSTNAME=$(hostname)
echo -e "当前主机名: ${BLUE}${CURRENT_HOSTNAME}${NC}"
read_prompt -r -p "请输入新的主机名 (直接回车跳过): " NEW_HOSTNAME
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
# 4. 安装 NextTrace
# ==============================
echo -e "${YELLOW}[4/7] 正在安装 NextTrace...${NC}"
if install_nexttrace; then
    echo -e "${GREEN}nexttrace 安装完成。${NC}"
else
    warn "nexttrace 安装失败，请检查网络后重新运行初始化脚本。"
fi

# ==============================
# 5. 内核 BBR 加速
# ==============================
echo -e "${YELLOW}[5/7] 检查并开启 BBR 加速...${NC}"
configure_bbr

# ==============================
# 6. SSH 安全加固 (交互式)
# ==============================
echo -e "${YELLOW}[6/7] SSH 安全配置${NC}"

# --- 修改端口 ---
while true; do
    read_prompt -p "请输入新的 SSH 端口号 (建议 10000-65535): " SSH_PORT
    SSH_PORT=$(strip_cr "$SSH_PORT")
    if [[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$SSH_PORT >= 1 && 10#$SSH_PORT <= 65535 )); then
        SSH_PORT=$((10#$SSH_PORT))
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
read_prompt -p "确认安全组已放行该端口？请输入 yes 继续: " PORT_READY
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

if systemctl is-active --quiet ssh.socket || systemctl is-active --quiet sshd.socket; then
    fail "检测到 SSH socket 激活，当前脚本不修改其监听端口。请先由管理员切换为常规 SSH 服务。"
fi
SSH_SERVICE="sshd"
systemctl cat sshd.service >/dev/null 2>&1 || SSH_SERVICE="ssh"
begin_ssh_transaction

# --- 配置密钥登录 ---
echo -e "${YELLOW}--- 密钥登录设置 ---${NC}"
read_prompt -p "是否导入 SSH 公钥 (Public Key)? [y/n]: " IMPORT_KEY
IMPORT_KEY=$(strip_cr "$IMPORT_KEY")
if [[ "$IMPORT_KEY" =~ ^[Yy]$ ]]; then
    echo -e "请粘贴完整的一行 SSH 公钥（支持 ssh-ed25519、ssh-rsa 等类型）:"
    read_prompt -r PUB_KEY
    PUB_KEY=$(strip_cr "$PUB_KEY")
    if [ -n "$PUB_KEY" ]; then
        SSH_KEY_CHANGED=1
        import_public_key "$PUB_KEY" "$SSH_KEY_FILE" || fail "公钥导入失败，停止 SSH 配置"
        SSH_EXPECTED_KEY_FILE=$SSH_KEY_FILE
    else
        echo -e "${RED}未输入公钥，跳过密钥设置。${NC}"
    fi
else
    echo -e "跳过密钥导入，保留默认设置。"
fi

# --- 禁用密码登录 (独立判断) ---
if [[ -f "$SSH_KEY_FILE" ]] && ssh-keygen -lf "$SSH_KEY_FILE" >/dev/null 2>&1; then
    echo -e "${GREEN}检测到有效 SSH 公钥。${NC}"
    read_prompt -p "是否禁用密码登录 (推荐)? [y/n]: " DISABLE_PWD
    DISABLE_PWD=$(strip_cr "$DISABLE_PWD")
    if [[ "$DISABLE_PWD" =~ ^[Yy]$ ]]; then
        SSH_EXPECTED_KEY_FILE=$SSH_KEY_FILE
        echo -e "${YELLOW}将禁用密码登录，稍后统一写入并验证 SSH 配置。${NC}"
    else
        echo -e "${YELLOW}保留原有密码认证设置，稍后显示实际生效状态。${NC}"
    fi
else
    DISABLE_PWD=n
    echo -e "${YELLOW}未检测到有效 SSH 公钥，保留原有密码认证设置。${NC}"
fi

# 应用 SSH 配置
SSH_SETTINGS=(Port "$SSH_PORT" PermitRootLogin yes PubkeyAuthentication yes)
if [[ "$DISABLE_PWD" =~ ^[Yy]$ ]]; then
    SSH_SETTINGS+=(PasswordAuthentication no KbdInteractiveAuthentication no ChallengeResponseAuthentication no)
fi
sshd_set "${SSH_SETTINGS[@]}"

# ==============================
# 7. 重启服务与提示
# ==============================
echo -e "${YELLOW}[7/7] 正在验证 SSH 配置并重启服务...${NC}"

# 验证配置语法 (防止重启失败导致失联)
if ! sshd -t; then
    fail "SSH 配置文件语法校验失败，将恢复备份"
fi

if ! validate_sshd_settings; then
    fail "SSH 最终生效配置校验失败，将恢复备份"
fi

activate_ssh_settings

echo -e "${BLUE}=================================================${NC}"
echo -e "${GREEN}   配置已完成   ${NC}"
echo -e "${BLUE}=================================================${NC}"
echo -e "1. 主机名: ${BLUE}$NEW_HOSTNAME${NC}"
echo -e "2. 新 SSH 端口: ${RED}$SSH_PORT${NC}"
echo -e "3. BBR 加速: ${GREEN}已开启${NC}"
echo -e "4. 系统更新: ${GREEN}已完成${NC}"

echo -e "5. 登录认证: ${GREEN}${SSH_AUTH_SUMMARY:-未知（未完成验证）}${NC}"

echo -e "6. 网络校时: ${BLUE}${TIME_SYNC_STATUS}${NC}"
echo -e "7. 系统时区: ${BLUE}${SYSTEM_TIMEZONE}${NC}"
echo -e "8. 网络地址优先级: ${BLUE}${IP_PREFERENCE}${NC}"

read_prompt -p "是否立即重启服务器? [y/n]: " REBOOT_NOW
REBOOT_NOW=$(strip_cr "$REBOOT_NOW")
if [[ "$REBOOT_NOW" =~ ^[Yy]$ ]]; then
    echo -e "正在重启..."
    reboot || fail "系统重启命令执行失败"
else
    echo -e "请记得稍后手动重启以生效内核设置。"
fi
