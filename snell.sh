#!/bin/bash
#
# Snell 多实例管理脚本 v5.3.2
# - 支持单机运行多个 Snell 实例 (不同端口)
# - 支持 Systemd 模板化管理 (snell@port)
# - 自动配置快捷命令 'snell'
#
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh)

set -Eeuo pipefail

# 临时资源清理 (Ctrl+C / 异常退出时自动清理)
_CLEANUP_FILES=()
cleanup() {
    for f in "${_CLEANUP_FILES[@]+"${_CLEANUP_FILES[@]}"}"; do
        rm -rf "$f" 2>/dev/null
    done
}
trap cleanup EXIT INT TERM

CURRENT_ACTION="初始化"
unexpected_error() {
    local rc=${1:-1} line=${2:-?}
    printf '\n%b❌ 未预期错误: %s（第 %s 行，退出码 %s）%b\n' \
        "${RED:-}" "${CURRENT_ACTION:-脚本执行}" "$line" "$rc" "${PLAIN:-}" >&2
    echo "请保留以上信息，并执行: journalctl -xe --no-pager | tail -50" >&2
}
trap 'unexpected_error "$?" "$LINENO"' ERR

# ==================== 变量定义 ====================
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
DIM="\033[2m"
PLAIN="\033[0m"

SCRIPT_VERSION="5.3.2"
SNELL_VERSION="5.0.1"

SNELL_BIN="/usr/local/bin/snell-server"
SNELL_CONF_DIR="/etc/snell"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_FILE="${SYSTEMD_DIR}/snell@.service"
DL_BASE="https://dl.nssurge.com/snell"
USER_MARKER="${SNELL_CONF_DIR}/.user-created-by-snell-script"

# Snell v5.0.1 官方发行包 SHA256（固定稳定版，拒绝静默切换测试版）
SNELL_AMD64_ARCHIVE_SHA256="9bea1c2b9e35b73b31634856c04d18c393072b9e5dcde6a32781d8b8f908c539"
SNELL_AMD64_BINARY_SHA256="5b2e221f2c6e29b1db8e47053e1221be29d5627da807cb932b089f514a3609f0"
SNELL_AARCH64_ARCHIVE_SHA256="2f178bf5ac468ce1a130454efa40a0603fbbe4e47ecc4880a989f4abc7f824cf"
SNELL_AARCH64_BINARY_SHA256="c9e1cc1f1a86e7d2958f2bc41ff9dc668edf479455a651ea05c6db2c18cd2e4e"

# 快捷命令路径
SCRIPT_PATH="/usr/local/bin/snell"
# 脚本远程地址 (用于管道运行时自动下载安装快捷命令)
SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/snell.sh"
FIREWALL_BACKEND=""

# 读取已安装的 Snell 主版本号
get_installed_major_ver() {
    local full_ver
    full_ver=$(get_installed_full_ver)
    if [[ "$full_ver" =~ ^([0-9]+) ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    # 兼容旧安装：元数据缺失时只在二进制与官方稳定版完全一致时识别为 v5。
    local arch archive_sha binary_sha
    if [[ -x "$SNELL_BIN" ]] \
        && IFS=$'\t' read -r arch archive_sha binary_sha < <(get_stable_asset_info) \
        && printf '%s  %s\n' "$binary_sha" "$SNELL_BIN" | sha256sum -c - >/dev/null 2>&1; then
        echo "5"
    fi
}

# 读取完整版本号
get_installed_full_ver() {
    local ver_file="${SNELL_CONF_DIR}/.version"
    if [[ -f "$ver_file" && ! -L "$ver_file" ]]; then
        local ver
        ver=$(head -n 1 "$ver_file" | tr -d '\r[:space:]')
        if [[ "$ver" =~ ^[0-9]+([.][0-9]+)+([a-z]+[0-9]*)?$ ]]; then
            echo "$ver"
        else
            echo ""
        fi
    else
        echo ""
    fi
}

# 获取实例运行状态
get_instance_status() {
    local port=$1
    if systemctl is-active --quiet "snell@${port}" 2>/dev/null; then
        echo -e "${GREEN}运行中${PLAIN}"
    else
        echo -e "${RED}已停止${PLAIN}"
    fi
}

# ==================== 基础函数 ====================
err() { echo -e "${RED}❌ 错误: $1${PLAIN}"; exit 1; }
info() { echo -e "${GREEN}INFO: $1${PLAIN}"; }
warn() { echo -e "${YELLOW}警告: $1${PLAIN}"; }
strip_cr() { echo "${1//$'\r'/}"; }

open_port() {
    local port=$1 proto rc=0
    local protocols=(tcp udp)
    FIREWALL_BACKEND=""

    if command -v ufw >/dev/null 2>&1; then
        FIREWALL_BACKEND="ufw"
        for proto in "${protocols[@]}"; do
            ufw allow "${port}/${proto}" >/dev/null 2>&1 || rc=1
        done
    elif command -v firewall-cmd >/dev/null 2>&1; then
        FIREWALL_BACKEND="firewalld"
        for proto in "${protocols[@]}"; do
            firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 || rc=1
        done
        firewall-cmd --reload >/dev/null 2>&1 || rc=1
    elif command -v iptables >/dev/null 2>&1; then
        FIREWALL_BACKEND="iptables"
        for proto in "${protocols[@]}"; do
            if ! iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT >/dev/null 2>&1; then
                iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || rc=1
            fi
        done
        if command -v iptables-save >/dev/null 2>&1; then
            mkdir -p /etc/iptables 2>/dev/null || true
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || rc=1
        fi
    fi
    return "$rc"
}

close_port() {
    local port=$1 proto rc=0
    local protocols=(tcp udp)
    FIREWALL_BACKEND=""

    if command -v ufw >/dev/null 2>&1; then
        FIREWALL_BACKEND="ufw"
        for proto in "${protocols[@]}"; do
            ufw --force delete allow "${port}/${proto}" >/dev/null 2>&1 || rc=1
        done
    elif command -v firewall-cmd >/dev/null 2>&1; then
        FIREWALL_BACKEND="firewalld"
        for proto in "${protocols[@]}"; do
            firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1 || rc=1
        done
        firewall-cmd --reload >/dev/null 2>&1 || rc=1
    elif command -v iptables >/dev/null 2>&1; then
        FIREWALL_BACKEND="iptables"
        for proto in "${protocols[@]}"; do
            if iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT >/dev/null 2>&1; then
                iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || rc=1
            fi
        done
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || rc=1
        fi
    fi
    return "$rc"
}

run_menu_action() {
    local label=$1
    shift
    local rc=0
    "$@" || rc=$?
    if [[ $rc -ne 0 ]]; then
        echo -e "${RED}❌ ${label}失败（退出码 ${rc}），请查看上方错误信息。${PLAIN}" >&2
    fi
    return 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "请使用 root 用户运行此脚本: sudo bash snell.sh"
    fi
}

check_platform() {
    [[ "$(uname -s)" == "Linux" ]] || err "Snell 服务端脚本仅支持 Linux"
    [[ ! -f /etc/alpine-release ]] || err "Snell 依赖 systemd 与 glibc，不支持 Alpine/OpenRC"
    case $(uname -m) in x86_64|amd64|aarch64|arm64) ;; *) err "不支持的架构: $(uname -m)" ;; esac
    command -v systemctl &>/dev/null || err "未找到 systemctl，当前系统不支持"
    [[ -d /run/systemd/system ]] || err "systemd 未运行，无法管理 Snell 服务"
}

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

# 同步快捷命令 (入口处调用, 确保 /usr/local/bin/snell 与运行版本一致)
sync_script() {
    local current_real target_real
    current_real=$(realpath "$0" 2>/dev/null || true)
    target_real=$(realpath "$SCRIPT_PATH" 2>/dev/null || true)
    if [[ "$0" == "$SCRIPT_PATH" ]] || \
       [[ -n "$current_real" && -n "$target_real" && "$current_real" == "$target_real" ]]; then
        return 0
    fi

    local tmp_script
    tmp_script=$(mktemp "${SCRIPT_PATH}.sync.XXXXXX") || {
        warn "无法创建快捷命令同步临时文件，继续运行当前脚本。"
        return 0
    }
    _CLEANUP_FILES+=("$tmp_script")

    if [[ -f "$0" ]] && [[ "$(basename "$0")" != "bash" ]] && [[ "$(basename "$0")" != "sh" ]]; then
        cp "$0" "$tmp_script" 2>/dev/null || true
    else
        curl -fsSLo "$tmp_script" --connect-timeout 8 --max-time 20 "$(fresh_script_url)" || true
    fi

    local candidate_ver installed_ver=""
    candidate_ver=$(grep '^SCRIPT_VERSION=' "$tmp_script" 2>/dev/null | head -1 | cut -d'"' -f2 || true)
    if [[ -f "$SCRIPT_PATH" ]]; then
        installed_ver=$(grep '^SCRIPT_VERSION=' "$SCRIPT_PATH" 2>/dev/null | head -1 | cut -d'"' -f2 || true)
    fi

    if validate_script_candidate "$tmp_script" \
        && { [[ -z "$installed_ver" ]] || ! version_is_older "$candidate_ver" "$installed_ver"; } \
        && chmod 755 "$tmp_script" && mv -f "$tmp_script" "$SCRIPT_PATH"; then
        return 0
    fi
    if [[ "$installed_ver" =~ ^[0-9]+([.][0-9]+)*$ ]] \
        && [[ "$candidate_ver" =~ ^[0-9]+([.][0-9]+)*$ ]] \
        && version_is_older "$candidate_ver" "$installed_ver"; then
        warn "拒绝用旧脚本 v${candidate_ver} 覆盖现有快捷命令 v${installed_ver}。"
    else
        warn "快捷命令同步失败，继续运行当前脚本；现有快捷命令未被覆盖。"
    fi
    return 0
}

# 稳定版发行资产信息：架构、压缩包 SHA256、二进制 SHA256
get_stable_asset_info() {
    case $(uname -m) in
        x86_64|amd64)
            printf '%s\t%s\t%s\n' "amd64" "$SNELL_AMD64_ARCHIVE_SHA256" "$SNELL_AMD64_BINARY_SHA256" ;;
        aarch64|arm64)
            printf '%s\t%s\t%s\n' "aarch64" "$SNELL_AARCH64_ARCHIVE_SHA256" "$SNELL_AARCH64_BINARY_SHA256" ;;
        *) return 1 ;;
    esac
}

# 依赖检查
check_deps() {
    local deps=(curl unzip ss sha256sum install realpath cmp find getent useradd userdel groupdel)
    local missing=() dep
    for dep in "${deps[@]}"; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done
    [[ ${#missing[@]} -eq 0 ]] && return 0

    info "安装必要依赖 (${missing[*]})..."
    if [[ -f /etc/debian_version ]]; then
        if ! apt-get update; then
            warn "部分 APT 软件源刷新失败；将使用现有索引继续安装依赖。请检查上方报错的软件源。"
        fi
        apt-get install -y curl unzip iproute2 coreutils diffutils findutils libc-bin passwd || true
    elif [[ -f /etc/redhat-release ]]; then
        local rpm_pm=yum
        command -v dnf &>/dev/null && rpm_pm=dnf
        "$rpm_pm" install -y curl unzip iproute coreutils diffutils findutils glibc-common shadow-utils || true
    else
        err "不支持当前系统的自动依赖安装，缺少: ${missing[*]}"
    fi

    missing=()
    for dep in "${deps[@]}"; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done
    [[ ${#missing[@]} -eq 0 ]] || err "依赖安装失败，缺少: ${missing[*]}"
}

# ==================== 核心逻辑 ====================

remove_created_account() {
    local failed=false
    if id -u snell &>/dev/null; then userdel snell >/dev/null 2>&1 || failed=true; fi
    if getent group snell >/dev/null 2>&1; then groupdel snell >/dev/null 2>&1 || failed=true; fi
    [[ "$failed" == "false" ]]
}

ensure_snell_user() {
    local user_created=false had_conf_dir=false
    if [[ -L "$SNELL_CONF_DIR" || ( -e "$SNELL_CONF_DIR" && ! -d "$SNELL_CONF_DIR" ) ]]; then
        warn "拒绝使用非普通目录: ${SNELL_CONF_DIR}"
        return 1
    fi
    [[ -d "$SNELL_CONF_DIR" ]] && had_conf_dir=true
    if ! id -u snell &>/dev/null; then
        local nologin_shell
        nologin_shell=$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)
        if ! useradd -r -U -s "$nologin_shell" snell; then
            warn "创建 snell 系统用户失败"
            return 1
        fi
        user_created=true
    fi
    if ! getent group snell >/dev/null 2>&1; then
        warn "snell 用户存在但缺少同名用户组，未修改现有账户。"
        if [[ "$user_created" == "true" ]]; then
            remove_created_account || warn "清理刚创建的 Snell 账户失败"
        fi
        return 1
    fi

    if ! mkdir -p "$SNELL_CONF_DIR"; then
        warn "创建 Snell 配置目录失败"
        if [[ "$user_created" == "true" ]]; then
            remove_created_account || warn "清理刚创建的 Snell 账户失败"
        fi
        return 1
    fi
    if [[ "$user_created" == "true" ]]; then
        if [[ -e "$USER_MARKER" || -L "$USER_MARKER" ]]; then
            warn "用户归属标记已异常存在，未覆盖该文件。"
            [[ "$had_conf_dir" == "true" ]] || rmdir "$SNELL_CONF_DIR" >/dev/null 2>&1 || true
            remove_created_account || warn "清理刚创建的 Snell 账户失败"
            return 1
        fi
        if ! : > "$USER_MARKER" || ! chown root:root "$USER_MARKER" || ! chmod 600 "$USER_MARKER"; then
            warn "记录 Snell 用户归属失败"
            rm -f "$USER_MARKER" || true
            [[ "$had_conf_dir" == "true" ]] || rmdir "$SNELL_CONF_DIR" >/dev/null 2>&1 || true
            remove_created_account || warn "清理刚创建的 Snell 账户失败"
            return 1
        fi
    fi
    if ! install -d -o root -g snell -m 750 "$SNELL_CONF_DIR"; then
        warn "设置 Snell 配置目录权限失败"
        if [[ "$user_created" == "true" ]]; then
            if [[ "$had_conf_dir" == "true" ]]; then
                warn "已保留新建 snell 用户及归属标记，避免现有配置的用户组失效。"
            else
                rm -f "$USER_MARKER" || true
                rmdir "$SNELL_CONF_DIR" >/dev/null 2>&1 || true
                remove_created_account || warn "清理刚创建的 Snell 账户失败"
            fi
        fi
        return 1
    fi
}

secure_config_permissions() {
    install -d -o root -g snell -m 750 "$SNELL_CONF_DIR" || return 1
    local configs=() conf
    shopt -s nullglob
    configs=("$SNELL_CONF_DIR"/*.conf)
    shopt -u nullglob
    for conf in "${configs[@]+"${configs[@]}"}"; do
        if [[ ! -f "$conf" || -L "$conf" ]]; then
            warn "拒绝处理非普通配置文件: ${conf}"
            return 1
        fi
        chown root:snell "$conf" || return 1
        chmod 640 "$conf" || return 1
    done
    if [[ -f "${SNELL_CONF_DIR}/.version" ]]; then
        [[ ! -L "${SNELL_CONF_DIR}/.version" ]] || { warn "版本文件不能是符号链接"; return 1; }
        chown root:root "${SNELL_CONF_DIR}/.version" || return 1
        chmod 644 "${SNELL_CONF_DIR}/.version" || return 1
    fi
    if [[ -f "$USER_MARKER" ]]; then
        [[ ! -L "$USER_MARKER" ]] || { warn "用户归属标记不能是符号链接"; return 1; }
        chown root:root "$USER_MARKER" || return 1
        chmod 600 "$USER_MARKER" || return 1
    fi
}

remove_new_user_on_abort() {
    local had_user=$1 had_conf_dir=$2
    [[ "$had_user" == "false" ]] || return 0
    if [[ "$had_conf_dir" == "false" ]]; then
        rm -f "$USER_MARKER" || true
        if rmdir "$SNELL_CONF_DIR" >/dev/null 2>&1; then
            remove_created_account || warn "清理刚创建的 Snell 账户失败"
        else
            : > "$USER_MARKER" 2>/dev/null || true
        fi
    else
        warn "配置目录原已存在，保留新建 snell 用户及归属标记以维持配置权限。"
    fi
}

write_service_candidate() {
    local file=$1
    if ! cat > "$file" <<EOF
[Unit]
Description=Snell Proxy Service on Port %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=snell
Group=snell
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=${SNELL_BIN} -c ${SNELL_CONF_DIR}/%i.conf
Restart=on-failure
RestartSec=3
LimitNOFILE=51200
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
    then
        return 1
    fi
    chmod 644 "$file"
}

rollback_core_install() {
    local backup_dir=$1 had_bin=$2 had_service=$3 had_version=$4
    local had_user=$5 had_conf_dir=$6
    shift 6
    local active_ports=("$@") port failed=false

    for port in "${active_ports[@]+"${active_ports[@]}"}"; do
        systemctl stop "snell@${port}" >/dev/null 2>&1 || true
    done

    if [[ "$had_bin" == "true" ]]; then
        cp -a "${backup_dir}/snell-server" "$SNELL_BIN" || failed=true
    else
        rm -f "$SNELL_BIN" || failed=true
    fi
    if [[ "$had_service" == "true" ]]; then
        cp -a "${backup_dir}/snell@.service" "$SERVICE_FILE" || failed=true
    else
        rm -f "$SERVICE_FILE" || failed=true
    fi
    if [[ "$had_version" == "true" ]]; then
        cp -a "${backup_dir}/version" "${SNELL_CONF_DIR}/.version" || failed=true
    else
        rm -f "${SNELL_CONF_DIR}/.version" || failed=true
    fi

    systemctl daemon-reload >/dev/null 2>&1 || failed=true
    for port in "${active_ports[@]+"${active_ports[@]}"}"; do
        systemctl start "snell@${port}" >/dev/null 2>&1 || failed=true
    done

    if [[ "$had_user" == "false" ]]; then
        if [[ "$had_conf_dir" == "false" ]]; then
            rm -f "$USER_MARKER" || true
            if rmdir "$SNELL_CONF_DIR" >/dev/null 2>&1; then
                remove_created_account || failed=true
            else
                : > "$USER_MARKER" 2>/dev/null || true
                failed=true
            fi
        else
            warn "已保留新建 snell 用户及归属标记，以维持原配置目录的权限。"
        fi
    fi

    [[ "$failed" == "false" ]]
}

# 1. 安装/更新 Snell 核心二进制
install_core() {
    CURRENT_ACTION="安装或更新 Snell 核心"
    local arch archive_sha binary_sha
    if ! IFS=$'\t' read -r arch archive_sha binary_sha < <(get_stable_asset_info) \
        || [[ -z "$arch" || -z "$archive_sha" || -z "$binary_sha" ]]; then
        warn "当前架构没有 Snell v${SNELL_VERSION} 官方稳定版。"
        return 1
    fi

    local current_ver current_binary_sha=""
    current_ver=$(get_installed_full_ver)
    if [[ -x "$SNELL_BIN" ]]; then
        current_binary_sha=$(sha256sum "$SNELL_BIN" 2>/dev/null | awk '{print $1}' || true)
    fi

    local expected_service
    expected_service=$(mktemp /tmp/snell_service.XXXXXX) || { warn "无法创建服务临时文件"; return 1; }
    _CLEANUP_FILES+=("$expected_service")
    write_service_candidate "$expected_service" || { warn "无法生成 systemd 服务"; return 1; }

    if [[ "$current_ver" == "$SNELL_VERSION" ]] \
        && [[ "$current_binary_sha" == "$binary_sha" ]] \
        && [[ -f "$SERVICE_FILE" ]] && cmp -s "$expected_service" "$SERVICE_FILE"; then
        ensure_snell_user || return 1
        secure_config_permissions || { warn "修复配置权限失败"; return 1; }
        info "Snell 稳定版 v${SNELL_VERSION} 已是最新，无需更新。"
        return 0
    fi

    local current_is_newer=false
    if [[ "$current_ver" =~ ^([0-9]+) ]] && [[ "${BASH_REMATCH[1]}" -gt 5 ]]; then
        current_is_newer=true
    elif [[ "$current_ver" =~ ^[0-9]+([.][0-9]+)*$ ]] \
        && version_is_older "$SNELL_VERSION" "$current_ver"; then
        current_is_newer=true
    fi

    if [[ -x "$SNELL_BIN" && -z "$current_ver" ]]; then
        warn "已安装核心版本未知，将使用官方稳定版 v${SNELL_VERSION} 替换。"
        local confirm_unknown
        read -rp " 是否继续? [y/N] " confirm_unknown || return 0
        confirm_unknown=$(strip_cr "$confirm_unknown")
        [[ "$confirm_unknown" =~ ^[yY]$ ]] || return 0
    elif [[ "$current_is_newer" == "true" ]]; then
        warn "当前为 v${current_ver}，稳定通道为 v${SNELL_VERSION}；继续将切换回稳定版。"
        local confirm_stable
        read -rp " 确认切换? [y/N] " confirm_stable || return 0
        confirm_stable=$(strip_cr "$confirm_stable")
        [[ "$confirm_stable" =~ ^[yY]$ ]] || return 0
    fi

    echo -e "${BLUE}>>> 准备安装 Snell 稳定版 v${SNELL_VERSION} (${arch})${PLAIN}"
    local tmp_dir archive candidate
    tmp_dir=$(mktemp -d /tmp/snell_install.XXXXXX) || { warn "无法创建安装临时目录"; return 1; }
    _CLEANUP_FILES+=("$tmp_dir")
    archive="${tmp_dir}/snell.zip"
    candidate="${tmp_dir}/snell-server"

    local url="${DL_BASE}/snell-server-v${SNELL_VERSION}-linux-${arch}.zip"
    if ! curl -fsSL --connect-timeout 15 --max-time 120 -o "$archive" "$url"; then
        warn "Snell 下载失败；现有核心和实例未改动。"
        return 1
    fi
    if ! printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum -c - >/dev/null 2>&1; then
        warn "Snell 官方发行包 SHA256 校验失败，已拒绝安装。"
        return 1
    fi
    if ! unzip -q "$archive" snell-server -d "$tmp_dir" || [[ ! -s "$candidate" ]]; then
        warn "Snell 发行包解压失败或缺少二进制。"
        return 1
    fi
    if ! printf '%s  %s\n' "$binary_sha" "$candidate" | sha256sum -c - >/dev/null 2>&1; then
        warn "Snell 二进制 SHA256 校验失败，已拒绝安装。"
        return 1
    fi
    chmod 755 "$candidate" || { warn "无法设置 Snell 二进制权限"; return 1; }

    local had_bin=false had_service=false had_version=false had_user=false had_conf_dir=false
    [[ -f "$SNELL_BIN" ]] && had_bin=true
    [[ -f "$SERVICE_FILE" ]] && had_service=true
    [[ -f "${SNELL_CONF_DIR}/.version" ]] && had_version=true
    id -u snell &>/dev/null && had_user=true
    [[ -d "$SNELL_CONF_DIR" ]] && had_conf_dir=true

    local backup_dir="${tmp_dir}/backup"
    mkdir -p "$backup_dir" || { warn "无法创建核心备份目录"; return 1; }
    if [[ "$had_bin" == "true" ]] && ! cp -a "$SNELL_BIN" "${backup_dir}/snell-server"; then
        warn "无法备份现有 Snell 核心"; return 1
    fi
    if [[ "$had_service" == "true" ]] && ! cp -a "$SERVICE_FILE" "${backup_dir}/snell@.service"; then
        warn "无法备份现有 systemd 服务"; return 1
    fi
    if [[ "$had_version" == "true" ]] && ! cp -a "${SNELL_CONF_DIR}/.version" "${backup_dir}/version"; then
        warn "无法备份现有版本记录"; return 1
    fi

    # 所有待替换文件先在目标文件系统中准备好，停服后只执行原子重命名。
    local new_bin new_service new_version
    new_bin=$(mktemp "$(dirname "$SNELL_BIN")/.snell-server.new.XXXXXX") \
        || { warn "无法创建核心临时文件"; return 1; }
    new_service=$(mktemp "${SYSTEMD_DIR}/.snell@.service.XXXXXX") \
        || { rm -f "$new_bin"; warn "无法创建服务临时文件"; return 1; }
    _CLEANUP_FILES+=("$new_bin" "$new_service")
    if ! install -m 755 "$candidate" "$new_bin" \
        || ! install -m 644 "$expected_service" "$new_service"; then
        rm -f "$new_bin" "$new_service"
        warn "准备 Snell 核心或 systemd 服务失败"
        return 1
    fi

    if ! ensure_snell_user; then
        rm -f "$new_bin" "$new_service"
        return 1
    fi
    if ! secure_config_permissions; then
        rm -f "$new_bin" "$new_service"
        remove_new_user_on_abort "$had_user" "$had_conf_dir"
        warn "配置目录或权限检查失败，现有核心和服务未改动。"
        return 1
    fi
    new_version=$(mktemp "${SNELL_CONF_DIR}/.version.new.XXXXXX") \
        || {
            rm -f "$new_bin" "$new_service"
            remove_new_user_on_abort "$had_user" "$had_conf_dir"
            warn "无法创建版本临时文件"
            return 1
        }
    _CLEANUP_FILES+=("$new_version")
    if ! printf '%s\n' "$SNELL_VERSION" > "$new_version" || ! chmod 644 "$new_version"; then
        rm -f "$new_bin" "$new_service" "$new_version"
        remove_new_user_on_abort "$had_user" "$had_conf_dir"
        warn "准备版本文件失败"
        return 1
    fi

    local configs=() active_ports=() conf port
    shopt -s nullglob
    configs=("$SNELL_CONF_DIR"/*.conf)
    shopt -u nullglob
    for conf in "${configs[@]+"${configs[@]}"}"; do
        [[ -f "$conf" && ! -L "$conf" ]] || continue
        port=$(basename "$conf" .conf)
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        systemctl is-active --quiet "snell@${port}" 2>/dev/null && active_ports+=("$port")
    done

    if [[ ${#active_ports[@]} -gt 0 ]]; then
        warn "正在短暂停止 ${#active_ports[@]} 个运行实例以更新核心..."
        for port in "${active_ports[@]+"${active_ports[@]}"}"; do
            if ! systemctl stop "snell@${port}"; then
                warn "实例 ${port} 停止失败，已取消更新。"
                local restore_failed=false
                for port in "${active_ports[@]+"${active_ports[@]}"}"; do
                    systemctl start "snell@${port}" >/dev/null 2>&1 || restore_failed=true
                done
                [[ "$restore_failed" == "true" ]] && warn "部分实例运行状态恢复失败，请立即检查。"
                return 1
            fi
        done
    fi

    local install_failed=false
    mv -f "$new_bin" "$SNELL_BIN" || install_failed=true
    [[ "$install_failed" == "false" ]] && mv -f "$new_service" "$SERVICE_FILE" || install_failed=true
    [[ "$install_failed" == "false" ]] && mv -f "$new_version" "${SNELL_CONF_DIR}/.version" || install_failed=true
    [[ "$install_failed" == "false" ]] && systemctl daemon-reload || install_failed=true

    if [[ "$install_failed" == "false" ]]; then
        for port in "${active_ports[@]+"${active_ports[@]}"}"; do
            if ! systemctl start "snell@${port}"; then install_failed=true; fi
        done
    fi
    if [[ ${#active_ports[@]} -gt 0 ]]; then sleep 1; fi
    if [[ "$install_failed" == "false" ]]; then
        for port in "${active_ports[@]+"${active_ports[@]}"}"; do
            systemctl is-active --quiet "snell@${port}" || install_failed=true
        done
    fi

    if [[ "$install_failed" == "true" ]]; then
        warn "新核心或服务启动失败，正在恢复更新前状态..."
        journalctl -u 'snell@*' -n 20 --no-pager 2>/dev/null | sed 's/^/  /' >&2 || true
        rm -f "$new_bin" "$new_service" "$new_version" || true
        if rollback_core_install "$backup_dir" "$had_bin" "$had_service" "$had_version" \
            "$had_user" "$had_conf_dir" "${active_ports[@]+"${active_ports[@]}"}"; then
            warn "更新失败，已恢复旧核心及原运行状态。"
        else
            warn "自动回滚不完整，请立即检查 Snell 文件和服务。"
        fi
        return 1
    fi

    info "Snell 稳定版 v${SNELL_VERSION} 安装/更新完成。"
}

# 2. 添加新实例 (多实例逻辑)
add_instance() {
    CURRENT_ACTION="添加 Snell 实例"
    if [[ ! -x "$SNELL_BIN" || ! -f "$SERVICE_FILE" ]]; then
        warn "Snell 核心或 systemd 服务未安装，请先选择菜单 1。"
        return 1
    fi
    ensure_snell_user || return 1
    secure_config_permissions || { warn "无法确认配置目录权限"; return 1; }

    echo -e "${BLUE}>>> 添加新的 Snell 实例${PLAIN}"

    # 端口输入与检查
    local port conf existing=false occupied
    while true; do
        read -rp "请输入端口号 (1-65535): " port || return
        port=$(strip_cr "$port")
        [[ "$port" =~ ^[0-9]+$ ]] || { echo "输入无效"; continue; }
        port=$((10#$port))
        if [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then echo "范围无效"; continue; fi
        conf="${SNELL_CONF_DIR}/${port}.conf"

        if [[ -f "$conf" ]]; then
            warn "端口 $port 的配置文件已存在!"
            local override
            read -rp "是否覆盖? [y/N]: " override
            override=$(strip_cr "$override")
            if [[ "$override" =~ ^[yY]$ ]]; then
                existing=true
                break
            fi
        else
            if ! occupied=$(ss -H -ltnup "sport = :${port}" 2>/dev/null); then
                warn "无法检查端口 ${port} 是否被占用"
                return 1
            fi
            if [[ -n "$occupied" ]]; then
                warn "端口 ${port} 已被其他进程占用，未创建实例。"
                printf '%s\n' "$occupied" | sed 's/^/  /'
                return 1
            fi
            break
        fi
    done

    # 生成 PSK
    local psk
    psk=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 32 || true)
    if [[ ${#psk} -ne 32 ]]; then
        warn "PSK 生成失败，请检查 /dev/urandom 是否可用。"
        return 1
    fi

    local tmp_conf backup_conf
    tmp_conf=$(mktemp "${SNELL_CONF_DIR}/.${port}.conf.new.XXXXXX") \
        || { warn "无法创建配置临时文件"; return 1; }
    backup_conf=$(mktemp /tmp/snell_conf_backup.XXXXXX) \
        || { warn "无法创建配置备份"; return 1; }
    _CLEANUP_FILES+=("$tmp_conf" "$backup_conf")

    if [[ "$existing" == "true" ]] && ! cp -a "$conf" "$backup_conf"; then
        warn "无法备份端口 ${port} 的原配置"
        return 1
    fi

    if ! cat > "$tmp_conf" <<EOF
[snell-server]
listen = ::0:${port}
psk = ${psk}
ipv6 = true
tfo = true
obfs = off
dns = 1.1.1.1, 8.8.8.8, 2001:4860:4860::8888
EOF
    then
        warn "生成端口 ${port} 配置失败"
        return 1
    fi
    if ! chown root:snell "$tmp_conf" || ! chmod 640 "$tmp_conf"; then
        warn "设置端口 ${port} 配置权限失败"
        return 1
    fi

    local was_active=false was_enabled=false
    systemctl is-active --quiet "snell@${port}" 2>/dev/null && was_active=true
    systemctl is-enabled --quiet "snell@${port}" 2>/dev/null && was_enabled=true

    if ! mv -f "$tmp_conf" "$conf"; then
        warn "替换端口 ${port} 配置失败"
        return 1
    fi

    local start_failed=false
    systemctl enable "snell@${port}" >/dev/null 2>&1 || start_failed=true
    [[ "$start_failed" == "false" ]] && systemctl restart "snell@${port}" || start_failed=true
    sleep 1
    [[ "$start_failed" == "false" ]] \
        && systemctl is-active --quiet "snell@${port}" || start_failed=true

    if [[ "$start_failed" == "true" ]]; then
        warn "实例 ${port} 启动失败，正在恢复原状态..."
        systemctl stop "snell@${port}" >/dev/null 2>&1 || true
        if [[ "$existing" == "true" ]]; then
            cp -a "$backup_conf" "$conf" || warn "原配置恢复失败"
        else
            rm -f "$conf" || warn "失败配置清理失败"
        fi
        if [[ "$was_enabled" == "true" ]]; then
            systemctl enable "snell@${port}" >/dev/null 2>&1 || warn "原开机启动状态恢复失败"
        else
            systemctl disable "snell@${port}" >/dev/null 2>&1 || true
        fi
        if [[ "$was_active" == "true" ]]; then
            systemctl start "snell@${port}" >/dev/null 2>&1 || warn "原实例运行状态恢复失败"
        fi
        journalctl -u "snell@${port}" -n 20 --no-pager 2>/dev/null | sed 's/^/  /' >&2 || true
        return 1
    fi

    info "实例 (端口: $port) 启动成功!"
    [[ "$existing" == "true" ]] && warn "PSK 已更换，请同步更新客户端配置。"
    show_single_config "$port" || warn "实例已运行，但客户端配置展示失败。"
    if open_port "$port"; then
        if [[ -n "$FIREWALL_BACKEND" ]]; then
            info "已通过 ${FIREWALL_BACKEND} 放行 TCP/UDP ${port}。"
        fi
    else
        warn "实例已运行，但 TCP/UDP ${port} 防火墙规则添加失败，请手动放行。"
        return 1
    fi
}

# 3. 删除实例
del_instance() {
    CURRENT_ACTION="删除 Snell 实例"
    local configs=()
    shopt -s nullglob
    configs=("$SNELL_CONF_DIR"/*.conf)
    shopt -u nullglob
    if [[ ${#configs[@]} -eq 0 ]]; then
        warn "没有找到任何运行的实例。"
        return 0
    fi

    echo -e " ${BLUE}>>> 删除 Snell 实例${PLAIN}"
    echo -e " ─────────────────────────────────────"

    local i=1
    local ports=()
    for conf in "${configs[@]+"${configs[@]}"}"; do
        [[ -f "$conf" && ! -L "$conf" ]] || continue
        local p
        p=$(basename "$conf" .conf)
        [[ "$p" =~ ^[0-9]+$ ]] || continue
        ports+=("$p")
        local status
        status=$(get_instance_status "$p")
        printf "  [%d]  端口: %-8s  状态: %b\n" $i "$p" "$status"
        i=$((i+1))
    done
    if [[ ${#ports[@]} -eq 0 ]]; then
        warn "没有找到有效的实例配置。"
        return 0
    fi
    echo -e " ─────────────────────────────────────"

    read -rp "请选择要删除的序号 (输入 0 取消): " choice
    choice=$(strip_cr "$choice")
    [[ "$choice" == "0" ]] && return
    [[ "$choice" =~ ^[0-9]+$ ]] || { warn "输入无效"; return; }
    choice=$((10#$choice))

    local idx=$((choice - 1))
    if [[ $idx -lt 0 || $idx -ge ${#ports[@]} ]]; then
        warn "序号超出范围"
        return
    fi
    local target_port="${ports[$idx]}"

    read -rp "确认删除端口 $target_port 的实例? [y/N]: " confirm
    confirm=$(strip_cr "$confirm")
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        local was_active=false was_enabled=false
        systemctl is-active --quiet "snell@${target_port}" 2>/dev/null && was_active=true
        systemctl is-enabled --quiet "snell@${target_port}" 2>/dev/null && was_enabled=true

        if [[ "$was_active" == "true" ]] && ! systemctl stop "snell@${target_port}"; then
            warn "实例 ${target_port} 停止失败，配置未删除。"
            return 1
        fi
        if [[ "$was_enabled" == "true" ]] \
            && ! systemctl disable "snell@${target_port}" >/dev/null 2>&1; then
            warn "实例 ${target_port} 取消开机启动失败，配置未删除。"
            if [[ "$was_active" == "true" ]] \
                && ! systemctl start "snell@${target_port}" >/dev/null 2>&1; then
                warn "实例 ${target_port} 原运行状态恢复失败，请立即检查。"
            fi
            return 1
        fi
        if ! close_port "$target_port"; then
            warn "TCP/UDP ${target_port} 防火墙规则清理失败，配置未删除。"
            open_port "$target_port" || warn "防火墙规则恢复失败，请立即检查。"
            if [[ "$was_enabled" == "true" ]]; then
                systemctl enable "snell@${target_port}" >/dev/null 2>&1 || warn "原开机启动状态恢复失败"
            fi
            if [[ "$was_active" == "true" ]]; then
                systemctl start "snell@${target_port}" >/dev/null 2>&1 || warn "原运行状态恢复失败"
            fi
            return 1
        fi
        if ! rm -f "${SNELL_CONF_DIR}/${target_port}.conf"; then
            warn "实例 ${target_port} 配置删除失败，正在恢复服务状态。"
            open_port "$target_port" || warn "防火墙规则恢复失败，请立即检查。"
            if [[ "$was_enabled" == "true" ]]; then
                systemctl enable "snell@${target_port}" >/dev/null 2>&1 || warn "原开机启动状态恢复失败"
            fi
            if [[ "$was_active" == "true" ]]; then
                systemctl start "snell@${target_port}" >/dev/null 2>&1 || warn "原运行状态恢复失败"
            fi
            return 1
        fi
        info "实例 $target_port 已删除。"
    else
        echo "已取消。"
    fi
}

validate_ipv4() {
    local ip=$1 octet
    [[ "$ip" =~ ^[0-9]+([.][0-9]+){3}$ ]] || return 1
    local IFS=.
    local -a octets
    read -ra octets <<< "$ip"
    [[ ${#octets[@]} -eq 4 ]] || return 1
    for octet in "${octets[@]}"; do
        [[ ${#octet} -le 3 ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
}

get_public_ipv4() {
    local endpoint ip
    for endpoint in https://api.ipify.org https://ip.sb; do
        ip=$(curl -fsS4 --connect-timeout 3 --max-time 5 "$endpoint" 2>/dev/null || true)
        ip=$(printf '%s' "$ip" | tr -d '\r\n[:space:]')
        if validate_ipv4 "$ip"; then
            echo "$ip"
            return 0
        fi
    done
    echo "YOUR_IP"
}

read_config_value() {
    local file=$1 key=$2
    grep -m1 -E "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null \
        | cut -d= -f2- | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' || true
}

format_client_config() {
    local port=$1 ip=$2 conf="${SNELL_CONF_DIR}/${port}.conf"
    local key snell_ver obfs extra=""
    key=$(read_config_value "$conf" psk)
    snell_ver=$(get_installed_major_ver)
    obfs=$(read_config_value "$conf" obfs)

    if [[ -z "$key" || "$snell_ver" != "5" ]]; then
        warn "端口 ${port} 的 PSK 无效或核心不是受支持的稳定版 v5，请先检查并更新核心。" >&2
        return 1
    fi
    case "${obfs:-off}" in
        off) ;;
        http) extra=", obfs=http" ;;
        *) warn "端口 ${port} 使用稳定版 v5 不支持的混淆模式: ${obfs}" >&2; return 1 ;;
    esac

    printf 'snell-%s = snell, %s, %s, psk=%s, version=%s, tfo=true, reuse=true%s\n' \
        "$port" "$ip" "$port" "$key" "$snell_ver" "$extra"
}

# 4. 查看所有配置
show_all_configs() {
    local configs=()
    shopt -s nullglob
    configs=("$SNELL_CONF_DIR"/*.conf)
    shopt -u nullglob
    if [[ ${#configs[@]} -eq 0 ]]; then
        warn "暂无实例配置。"
        return 0
    fi

    local ip
    ip=$(get_public_ipv4)

    echo -e " ${BLUE}>>> Snell 节点配置清单${PLAIN}"
    echo -e " ════════════════════════════════════════════════════════════════"
    for conf in "${configs[@]+"${configs[@]}"}"; do
        [[ -f "$conf" && ! -L "$conf" ]] || continue
        local p
        p=$(basename "$conf" .conf)
        [[ "$p" =~ ^[0-9]+$ ]] || continue
        local status
        status=$(get_instance_status "$p")

        echo -e " ${GREEN}▶ 端口: $p${PLAIN}  状态: $status"
        local client_config
        if client_config=$(format_client_config "$p" "$ip"); then
            echo -e "   ${DIM}${client_config}${PLAIN}"
        fi
        echo -e " ────────────────────────────────────────────────────────────────"
    done
    [[ "$ip" == "YOUR_IP" ]] && warn "未能获取公网 IPv4，请手动替换配置中的 YOUR_IP。"
    echo -e " ${DIM}提示: 上方格式严格按 Surge 官方 Snell 配置生成。${PLAIN}"
}

show_single_config() {
    local port=$1
    local conf="${SNELL_CONF_DIR}/${port}.conf"
    local ip
    ip=$(get_public_ipv4)

    echo -e " ────────────────────────────────────────────────────────────────"
    echo -e " ${GREEN}▶ 端口 ${port} 客户端配置:${PLAIN}"
    local client_config
    if client_config=$(format_client_config "$port" "$ip"); then
        echo -e "   ${client_config}"
    else
        return 1
    fi
    echo -e " ────────────────────────────────────────────────────────────────"
    if [[ "$ip" == "YOUR_IP" ]]; then
        warn "未能获取公网 IPv4，请手动替换 YOUR_IP。"
    fi
    return 0
}

# 更新管理脚本
update_script() {
    CURRENT_ACTION="更新 Snell 管理脚本"
    echo
    echo -e " ${BLUE}>>> 更新管理脚本${PLAIN}"
    echo -e " 当前版本: v${SCRIPT_VERSION}"
    echo -e " 远程地址: ${DIM}${SCRIPT_URL}${PLAIN}"
    echo

    local tmp_script
    tmp_script=$(mktemp "${SCRIPT_PATH}.update.XXXXXX") \
        || { warn "无法创建更新临时文件"; return 1; }
    _CLEANUP_FILES+=("$tmp_script")

    if ! curl -fsSLo "$tmp_script" --connect-timeout 8 --max-time 30 "$(fresh_script_url)"; then
        warn "下载失败，请检查网络；现有脚本未被覆盖。"
        return 1
    fi
    if ! validate_script_candidate "$tmp_script"; then
        warn "远程脚本格式或 Bash 语法校验失败，现有脚本未被覆盖。"
        return 1
    fi

    # 提取远程版本号
    local remote_ver installed_ver=""
    remote_ver=$(grep '^SCRIPT_VERSION=' "$tmp_script" | head -1 | cut -d'"' -f2 || true)
    if [[ -f "$SCRIPT_PATH" ]]; then
        installed_ver=$(grep '^SCRIPT_VERSION=' "$SCRIPT_PATH" 2>/dev/null | head -1 | cut -d'"' -f2 || true)
    fi

    if version_is_older "$remote_ver" "$SCRIPT_VERSION" \
        || { [[ "$installed_ver" =~ ^[0-9]+([.][0-9]+)*$ ]] \
            && version_is_older "$remote_ver" "$installed_ver"; }; then
        rm -f "$tmp_script"
        warn "拒绝降级：远端 v${remote_ver} 低于当前或已安装版本。"
        return 1
    fi

    if [[ "$remote_ver" == "$SCRIPT_VERSION" ]] && cmp -s "$tmp_script" "$SCRIPT_PATH"; then
        info "已是最新版本 (v${SCRIPT_VERSION})，无需更新。"
        rm -f "$tmp_script"
        return
    elif [[ "$remote_ver" == "$SCRIPT_VERSION" ]]; then
        warn "检测到同版本内容修订，将继续更新。"
    else
        echo -e " 发现新版本: ${GREEN}v${remote_ver}${PLAIN}"
    fi

    if ! chmod 755 "$tmp_script" || ! mv -f "$tmp_script" "$SCRIPT_PATH"; then
        warn "脚本替换失败，原快捷命令未完整更新。"
        return 1
    fi
    info "脚本已更新完成! 正在重新加载..."
    echo
    exec "$SCRIPT_PATH" || { warn "新脚本启动失败，请手动运行: ${SCRIPT_PATH}"; return 1; }
}

# 彻底卸载
uninstall_all() {
    CURRENT_ACTION="卸载 Snell"
    if [[ -L "$SNELL_CONF_DIR" || ( -e "$SNELL_CONF_DIR" && ! -d "$SNELL_CONF_DIR" ) ]]; then
        warn "拒绝卸载：Snell 配置路径不是普通目录，请先人工检查 ${SNELL_CONF_DIR}。"
        return 1
    fi
    echo
    echo -e " ${RED}════════════════════════════════════════${PLAIN}"
    echo -e " ${RED}  警告: 即将卸载 Snell 核心及所有实例!${PLAIN}"
    echo -e " ${RED}════════════════════════════════════════${PLAIN}"
    echo
    read -rp " 确认执行? (输入 yes 确认): " confirm
    confirm=$(strip_cr "$confirm")
    [[ ! "$confirm" =~ ^([yY][eE][sS])$ ]] && { echo " 已取消。"; return; }
    
    local configs=() ports=() active_ports=() enabled_ports=() conf port
    shopt -s nullglob
    configs=("$SNELL_CONF_DIR"/*.conf)
    shopt -u nullglob
    for conf in "${configs[@]+"${configs[@]}"}"; do
        [[ -f "$conf" && ! -L "$conf" ]] || continue
        port=$(basename "$conf" .conf)
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        ports+=("$port")
    done
    local unit link
    while read -r link; do
        unit=$(basename "$link")
        if [[ "$unit" =~ ^snell@([0-9]+)[.]service$ ]]; then
            port="${BASH_REMATCH[1]}"
            local known=false known_port
            for known_port in "${ports[@]+"${ports[@]}"}"; do
                [[ "$known_port" == "$port" ]] && known=true
            done
            [[ "$known" == "true" ]] || ports+=("$port")
        fi
    done < <(find "$SYSTEMD_DIR" -type l -name 'snell@*.service' 2>/dev/null)
    while read -r unit; do
        if [[ "$unit" =~ ^snell@([0-9]+)[.]service$ ]]; then
            port="${BASH_REMATCH[1]}"
            local known=false known_port
            for known_port in "${ports[@]+"${ports[@]}"}"; do
                [[ "$known_port" == "$port" ]] && known=true
            done
            [[ "$known" == "true" ]] || ports+=("$port")
        fi
    done < <(systemctl list-units 'snell@*.service' --all --no-legend 2>/dev/null | awk '{print $1}')
    for port in "${ports[@]+"${ports[@]}"}"; do
        systemctl is-active --quiet "snell@${port}" 2>/dev/null && active_ports+=("$port")
        systemctl is-enabled --quiet "snell@${port}" 2>/dev/null && enabled_ports+=("$port")
    done

    for port in "${active_ports[@]+"${active_ports[@]}"}"; do
        if ! systemctl stop "snell@${port}"; then
            warn "实例 ${port} 停止失败，已取消卸载；任何文件都未删除。"
            local restore_failed=false
            for port in "${active_ports[@]+"${active_ports[@]}"}"; do
                systemctl start "snell@${port}" >/dev/null 2>&1 || restore_failed=true
            done
            [[ "$restore_failed" == "true" ]] && warn "部分实例运行状态恢复失败，请立即检查。"
            return 1
        fi
    done
    for port in "${enabled_ports[@]+"${enabled_ports[@]}"}"; do
        if ! systemctl disable "snell@${port}" >/dev/null 2>&1; then
            warn "实例 ${port} 取消开机启动失败，已取消卸载。"
            local restore_failed=false
            for port in "${enabled_ports[@]+"${enabled_ports[@]}"}"; do
                systemctl enable "snell@${port}" >/dev/null 2>&1 || restore_failed=true
            done
            for port in "${active_ports[@]+"${active_ports[@]}"}"; do
                systemctl start "snell@${port}" >/dev/null 2>&1 || restore_failed=true
            done
            [[ "$restore_failed" == "true" ]] && warn "部分实例原状态恢复失败，请立即检查。"
            return 1
        fi
    done

    local firewall_failed=false
    for port in "${ports[@]+"${ports[@]}"}"; do
        if ! close_port "$port"; then
            warn "TCP/UDP ${port} 防火墙规则清理失败，已取消卸载。"
            firewall_failed=true
        fi
    done
    if [[ "$firewall_failed" == "true" ]]; then
        local restore_failed=false
        for port in "${ports[@]+"${ports[@]}"}"; do
            open_port "$port" || restore_failed=true
        done
        for port in "${enabled_ports[@]+"${enabled_ports[@]}"}"; do
            systemctl enable "snell@${port}" >/dev/null 2>&1 || restore_failed=true
        done
        for port in "${active_ports[@]+"${active_ports[@]}"}"; do
            systemctl start "snell@${port}" >/dev/null 2>&1 || restore_failed=true
        done
        [[ "$restore_failed" == "true" ]] && warn "部分防火墙或服务状态恢复失败，请立即检查。"
        return 1
    fi

    local remove_user=false failed=false
    [[ -f "$USER_MARKER" && ! -L "$USER_MARKER" ]] && remove_user=true

    rm -f "$SERVICE_FILE" || failed=true
    systemctl daemon-reload >/dev/null 2>&1 || failed=true
    systemctl reset-failed 'snell@*' >/dev/null 2>&1 || true
    rm -rf "$SNELL_CONF_DIR" || failed=true
    rm -f "$SNELL_BIN" || failed=true
    rm -f "$SCRIPT_PATH" || failed=true

    if [[ "$remove_user" == "true" ]]; then
        if ! remove_created_account; then
            warn "删除脚本创建的 snell 系统账户失败，已保留归属标记供重试。"
            if install -d -o root -g root -m 700 "$SNELL_CONF_DIR" \
                && : > "$USER_MARKER" \
                && chown root:root "$USER_MARKER" \
                && chmod 600 "$USER_MARKER"; then
                :
            else
                warn "恢复 Snell 用户归属标记失败，请手动检查 snell 用户和用户组。"
            fi
            failed=true
        fi
    elif id -u snell &>/dev/null; then
        info "保留既有 snell 用户（无法确认由本脚本创建）。"
    fi

    [[ ! -e "$SERVICE_FILE" && ! -e "$SNELL_CONF_DIR" \
        && ! -e "$SNELL_BIN" && ! -e "$SCRIPT_PATH" ]] || failed=true
    for port in "${ports[@]+"${ports[@]}"}"; do
        systemctl is-active --quiet "snell@${port}" 2>/dev/null && failed=true
    done
    if find "$SYSTEMD_DIR" -type l -name 'snell@*.service' -print -quit 2>/dev/null | grep -q .; then
        warn "检测到 Snell 实例开机启动链接残留。"
        failed=true
    fi

    if [[ "$failed" == "true" ]]; then
        warn "Snell 卸载未完全完成，请根据上方信息检查残留。"
        return 1
    fi

    info "Snell 核心、实例、服务和快捷命令已卸载。"
    exit 0
}

show_service_status() {
    CURRENT_ACTION="查看 Snell 服务状态与日志"
    echo -e " ${BLUE}>>> Snell 服务状态${PLAIN}"
    echo -e " ────────────────────────────────────────────────────────────────"

    local configs=() conf port found=false
    shopt -s nullglob
    configs=("$SNELL_CONF_DIR"/*.conf)
    shopt -u nullglob
    for conf in "${configs[@]+"${configs[@]}"}"; do
        [[ -f "$conf" && ! -L "$conf" ]] || continue
        port=$(basename "$conf" .conf)
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        found=true
        printf '  %-8s %b\n' "$port" "$(get_instance_status "$port")"
    done
    if [[ "$found" == "false" ]]; then
        echo -e " ${DIM}暂无实例。${PLAIN}"
    fi

    echo -e " ────────────────────────────────────────────────────────────────"
    echo -e " ${DIM}最近日志:${PLAIN}"
    if ! journalctl -u 'snell@*' -n 20 --no-pager 2>/dev/null | sed 's/^/  /'; then
        warn "无法读取 Snell 服务日志。"
    fi
}

# ==================== 菜单 ====================
menu() {
    CURRENT_ACTION="读取 Snell 管理菜单"
    clear || true
    echo -e "========================================================================"
    echo -e "  Snell 多实例管理 · v${SCRIPT_VERSION}"
    echo -e "========================================================================"

    # ---- 状态面板 ----
    local core_status="${RED}未安装${PLAIN}"
    if [[ -x "$SNELL_BIN" ]]; then
        local full_ver
        full_ver=$(get_installed_full_ver)
        if [[ -n "$full_ver" ]]; then
            core_status="${GREEN}v${full_ver}${PLAIN}"
        else
            core_status="${GREEN}已安装${PLAIN} ${DIM}(版本未知)${PLAIN}"
        fi
    fi
    echo -e " 核心: ${core_status}    稳定通道: v${SNELL_VERSION}    架构: $(uname -m)"
    echo -e "------------------------------------------------------------------------"

    # ---- 实例列表 ----
    local configs=()
    shopt -s nullglob
    configs=("$SNELL_CONF_DIR"/*.conf)
    shopt -u nullglob
    if [[ ${#configs[@]} -gt 0 ]]; then
        printf " %-6s %-10s %-12s %-8s %-8s %-s\n" "序号" "端口" "状态" "IPv6" "混淆" "PSK"
        echo -e " ------------------------------------------------------------------------"

        local i=1
        local conf
        for conf in "${configs[@]+"${configs[@]}"}"; do
            [[ -f "$conf" && ! -L "$conf" ]] || continue
            local p
            p=$(basename "$conf" .conf)
            [[ "$p" =~ ^[0-9]+$ ]] || continue
            local status
            status=$(get_instance_status "$p")
            local key
            key=$(read_config_value "$conf" psk)
            local obfs
            obfs=$(read_config_value "$conf" obfs)
            local ipv6
            ipv6=$(read_config_value "$conf" ipv6)
            local psk_short="${key:0:8}..."

            printf " [%d]    %-10s %b  %-8s %-8s %-s\n" \
                $i "$p" "$status" "${ipv6:-true}" "${obfs:-off}" "$psk_short"
            i=$((i+1))
        done
    else
        echo -e " ${DIM}暂无实例，请先安装核心并添加实例。${PLAIN}"
    fi

    echo -e "========================================================================"
    echo
    if [[ -x "$SNELL_BIN" ]]; then
        echo -e " 1. 检查或更新 Snell"
    else
        echo -e " 1. ${GREEN}安装 Snell${PLAIN}"
    fi
    echo -e " 2. ${GREEN}添加实例 (新端口)${PLAIN}"
    echo -e " 3. 服务状态与日志"
    echo -e " 4. 查看客户端配置"
    echo -e " 5. 删除实例"
    echo -e " 6. 更新 Snell 脚本"
    echo -e " 7. ${RED}卸载全部${PLAIN}"
    echo -e " 0. 退出"
    echo -e "========================================================================"
    read -rp " 请输入选项: " choice
    choice=$(strip_cr "$choice")
    
    case $choice in
        1) run_menu_action "安装或更新 Snell" install_core; read -rp " 按回车返回..." ;;
        2) run_menu_action "添加 Snell 实例" add_instance; read -rp " 按回车返回..." ;;
        3) run_menu_action "读取 Snell 状态" show_service_status; read -rp " 按回车返回..." ;;
        4) run_menu_action "查看客户端配置" show_all_configs; read -rp " 按回车返回..." ;;
        5) run_menu_action "删除 Snell 实例" del_instance; read -rp " 按回车返回..." ;;
        6) run_menu_action "更新 Snell 脚本" update_script; read -rp " 按回车返回..." ;;
        7) run_menu_action "卸载 Snell" uninstall_all; read -rp " 按回车返回..." ;;
        0) exit 0 ;;
        *) warn "无效选项，请输入 0-7。"; read -rp " 按回车返回..." ;;
    esac
}

show_help() {
    echo
    echo " snell.sh — Snell v${SNELL_VERSION} 稳定版多实例管理器 v${SCRIPT_VERSION}"
    echo
    echo " 用法:"
    echo "   snell                交互菜单"
    echo "   snell install        检查或更新 Snell 核心"
    echo "   snell add            添加实例"
    echo "   snell list           查看客户端配置"
    echo "   snell status         查看服务状态与日志"
    echo "   snell delete         删除实例"
    echo "   snell update         更新 Snell 脚本"
    echo "   snell uninstall      卸载全部"
    echo
}

# ==================== 入口 ====================
if [[ "${1:-}" =~ ^(-h|--help|help)$ ]]; then
    show_help
    exit 0
fi

check_root
check_platform
check_deps
sync_script

if [[ $# -gt 0 ]]; then
    case "$1" in
        install)   install_core || exit $? ;;
        add)       add_instance || exit $? ;;
        list|ls)   show_all_configs || exit $? ;;
        status)    show_service_status || exit $? ;;
        delete|del|rm) del_instance || exit $? ;;
        update)    update_script || exit $? ;;
        uninstall) uninstall_all || exit $? ;;
        *)         warn "未知命令: $1（使用 snell help 查看帮助）"; exit 1 ;;
    esac
else
    while true; do
        menu
    done
fi
