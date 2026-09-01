#!/bin/bash
#
# 端口转发管理脚本 (基于 realm) v2.3.0
# - 支持 TCP/UDP 端口转发
# - 与 pm.sh 流量监控无缝协作
# - 基于 realm 用户态转发，无需内核 FORWARD 链
#
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/white-u/vps_script/main/fw.sh)

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

SCRIPT_VERSION="2.3.0"
REALM_VERSION="2.9.6"

REALM_BIN="/usr/local/bin/realm"
CONFIG_DIR="/etc/realm"
CONFIG_TOML="${CONFIG_DIR}/config.toml"
META_FILE="${CONFIG_DIR}/fw.json"
SERVICE_NAME="realm"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# 快捷命令路径
SCRIPT_PATH="/usr/local/bin/fw"
# 脚本远程地址 (用于管道运行时自动下载安装快捷命令)
SCRIPT_URL="https://raw.githubusercontent.com/white-u/vps_script/main/fw.sh"

# ==================== 基础函数 ====================
err() { echo -e "${RED}❌ 错误: $1${PLAIN}"; exit 1; }
info() { echo -e "${GREEN}INFO: $1${PLAIN}"; }
warn() { echo -e "${YELLOW}警告: $1${PLAIN}"; }
strip_cr() { echo "${1//$'\r'/}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "请使用 root 用户运行此脚本: sudo bash fw.sh"
    fi
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

# 同步快捷命令 (入口处调用, 确保 /usr/local/bin/fw 与运行版本一致)
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

# 依赖检查
check_deps() {
    local commands=(jq curl tar find ss sha256sum install realpath cmp)
    local missing=() cmd
    for cmd in "${commands[@]}"; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    [[ ${#missing[@]} -eq 0 ]] && return 0

    info "安装必要依赖..."
    if [ -f /etc/debian_version ]; then
        if ! apt-get update -qq; then
            warn "部分 APT 软件源刷新失败；将使用现有索引继续安装。请检查上方报错的软件源。"
        fi
        apt-get install -y -qq jq curl tar findutils iproute2 coreutils diffutils || true
    elif [ -f /etc/redhat-release ]; then
        local rpm_pm="yum"
        command -v dnf &>/dev/null && rpm_pm="dnf"
        "$rpm_pm" install -y jq curl tar findutils iproute coreutils diffutils || true
    else
        err "不支持当前系统的自动依赖安装，缺少: ${missing[*]}"
    fi

    missing=()
    for cmd in "${commands[@]}"; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    [[ ${#missing[@]} -eq 0 ]] || err "依赖安装失败，缺少: ${missing[*]}"
}

check_platform() {
    [[ "$(uname -s)" == "Linux" ]] || err "fw 仅支持 Linux"
    [[ ! -f /etc/alpine-release ]] || err "fw 依赖 systemd，当前不支持 Alpine/OpenRC"
    command -v systemctl &>/dev/null || err "未找到 systemctl，当前系统不支持"
    [[ -d /run/systemd/system ]] || err "systemd 未运行，无法管理 realm 服务"
}

# Realm 发行资产与官方 SHA256（glibc 2.28 兼容 Debian 10+）
detect_realm_asset() {
    case $(uname -m) in
        x86_64|amd64)
            printf '%s\t%s\n' "x86_64-unknown-linux-gnu-glibc2.28" \
                "a85652b940fa23bf08fd29582e33e87ea9c940a71bcc7d21df9c0bd03f351149" ;;
        aarch64|arm64)
            printf '%s\t%s\n' "aarch64-unknown-linux-gnu-glibc2.28" \
                "0e277d58df7a9ee9eaca1277223b54b29b1af27a1fad04ae83c7b938d451c5f8" ;;
        armv7*)
            printf '%s\t%s\n' "armv7-unknown-linux-gnueabihf-glibc2.28" \
                "cb7058702c1f74bcbd45920cd778c2c5e7db98c3944ac6e05910b0e1386e4c4b" ;;
        *) err "不支持的架构: $(uname -m)" ;;
    esac
}

realm_installed() { [[ -x "$REALM_BIN" ]]; }
realm_running()   { systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; }

# 获取 realm 运行状态 (带颜色)
get_realm_status() {
    if ! realm_installed; then
        echo -e "${RED}未安装${PLAIN}"
    elif realm_running; then
        echo -e "${GREEN}运行中${PLAIN}"
    else
        echo -e "${YELLOW}已停止${PLAIN}"
    fi
}

# 获取已安装的 realm 版本
get_realm_version() {
    if realm_installed; then
        "$REALM_BIN" --version 2>/dev/null | grep -Eo '[0-9]+([.][0-9]+)+' | head -1 || true
    fi
}

# ==================== JSON 元数据 ====================

init_meta() {
    mkdir -p "$CONFIG_DIR"
    if [[ ! -f "$META_FILE" ]]; then
        local tmp_meta
        tmp_meta=$(mktemp "${META_FILE}.init.XXXXXX") || err "无法创建规则文件"
        _CLEANUP_FILES+=("$tmp_meta")
        if ! printf '%s\n' '{"rules":[]}' > "$tmp_meta" \
            || ! chmod 600 "$tmp_meta" || ! mv -f "$tmp_meta" "$META_FILE"; then
            err "初始化规则文件失败"
        fi
        return
    fi
    # 同时校验 JSON 语法、字段类型和端口唯一性。
    if ! jq -e '
        type == "object" and (.rules | type == "array") and
        all(.rules[];
            . as $r |
            ($r | type == "object") and
            ($r.src_port | type == "number" and . == floor and . >= 1 and . <= 65535) and
            ($r.dst_port | type == "number" and . == floor and . >= 1 and . <= 65535) and
            ($r.dst_ip | type == "string" and
                test("^[0-9]{1,3}([.][0-9]{1,3}){3}$") and
                (split(".") | all(.[]; (tonumber >= 0 and tonumber <= 255)))) and
            (($r.comment // "") | type == "string")
        ) and
        (([.rules[].src_port] | length) == ([.rules[].src_port] | unique | length))
    ' "$META_FILE" >/dev/null 2>&1; then
        local backup="${META_FILE}.corrupt.$(date +%Y%m%d%H%M%S)"
        if ! cp -p "$META_FILE" "$backup" 2>/dev/null; then
            err "fw.json 结构无效，且无法创建备份；原文件保持不变"
        fi
        err "fw.json 格式或规则结构无效，已保留为 ${backup}，请修复后重试"
    fi
    chmod 600 "$META_FILE" 2>/dev/null || warn "无法将 fw.json 权限设为 600"
}

rule_count() {
    [[ -f "$META_FILE" ]] || { echo 0; return; }
    jq '.rules | length' "$META_FILE" 2>/dev/null || echo 0
}

# ==================== 输入校验 ====================

validate_port() {
    local port=$1 label=$2
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        warn "无效${label}: $port"; return 1
    fi
    # 去掉前导零 (jq --argjson 不接受 JSON 非法数字如 "08080")
    port=$((10#$port))
    if [[ $port -lt 1 || $port -gt 65535 ]]; then
        warn "无效${label}: $port (范围 1-65535)"; return 1
    fi
}

validate_ipv4() {
    local ip=$1
    if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        warn "无效 IP: $ip"; return 1
    fi
    local IFS='.'; local -a parts=($ip); IFS=' '
    local p; for p in "${parts[@]}"; do
        if [[ $((10#$p)) -gt 255 ]]; then
            warn "无效 IP: $ip"; return 1
        fi
    done
}

# ==================== IPv6 检测 ====================

# 检测监听地址: IPv6 可用则双栈 [::], 否则仅 IPv4
detect_listen_addr() {
    if [[ -f /proc/net/if_inet6 ]] && \
       [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" != "1" ]]; then
        echo "[::]"
    else
        echo "0.0.0.0"
    fi
}

# ==================== 核心逻辑 ====================

rollback_realm_install() {
    local backup_dir=$1 had_bin=$2 had_service=$3
    warn "Realm 更新失败，正在恢复旧版本..."
    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true

    if [[ "$had_bin" == "true" ]]; then
        cp -p "${backup_dir}/backup.realm" "$REALM_BIN" || return 1
    else
        rm -f "$REALM_BIN"
    fi
    if [[ "$had_service" == "true" ]]; then
        cp -p "${backup_dir}/backup.realm.service" "$SERVICE_FILE" || return 1
    else
        rm -f "$SERVICE_FILE"
    fi
    systemctl daemon-reload >/dev/null 2>&1 || return 1

    if [[ "$had_bin" == "true" ]] && [[ "$(rule_count)" -gt 0 ]]; then
        reload_realm true || return 1
    fi
    info "已恢复更新前的 Realm"
}

# 1. 安装/更新 realm 核心二进制
install_realm() {
    CURRENT_ACTION="安装或更新 realm"
    if realm_installed; then
        local cur_ver
        cur_ver=$(get_realm_version)
        echo -e " 当前版本: ${GREEN}v${cur_ver:-unknown}${PLAIN}"
        read -rp " 是否重新安装 v${REALM_VERSION}? [y/N] " confirm || return 0
        confirm=$(strip_cr "$confirm")
        [[ "$confirm" =~ ^[yY] ]] || return 0
    fi

    echo -e "${BLUE}>>> 准备安装 realm v${REALM_VERSION}${PLAIN}"

    local asset_name expected_sha url tmp_dir
    IFS=$'\t' read -r asset_name expected_sha < <(detect_realm_asset)
    [[ -n "$asset_name" && -n "$expected_sha" ]] || err "无法确定 Realm 发行资产"
    url="https://github.com/zhboner/realm/releases/download/v${REALM_VERSION}/realm-${asset_name}.tar.gz"

    tmp_dir=$(mktemp -d /tmp/realm_install.XXXXXX)
    _CLEANUP_FILES+=("$tmp_dir")

    if ! curl -fsSL --connect-timeout 15 --max-time 120 -o "${tmp_dir}/realm.tar.gz" "$url"; then
        err "下载失败，请检查网络。"
    fi
    if ! printf '%s  %s\n' "$expected_sha" "${tmp_dir}/realm.tar.gz" | sha256sum -c - >/dev/null 2>&1; then
        err "Realm 官方 SHA256 校验失败，已拒绝安装"
    fi

    # 解压到临时目录，只提取二进制
    if ! tar -xzf "${tmp_dir}/realm.tar.gz" -C "$tmp_dir"; then
        err "解压失败。"
    fi

    local bin_path
    bin_path=$(find "$tmp_dir" -name "realm" -type f -perm -111 2>/dev/null | head -1)
    [[ -n "$bin_path" ]] || err "解压后未找到 realm 二进制"
    chmod 755 "$bin_path"

    local candidate_ver
    candidate_ver=$("$bin_path" --version 2>/dev/null | grep -Eo '[0-9]+([.][0-9]+)+' | head -1 || true)
    [[ "$candidate_ver" == "$REALM_VERSION" ]] \
        || err "Realm 二进制验证失败（期望 v${REALM_VERSION}，实际 v${candidate_ver:-unknown}）"

    local had_bin=false had_service=false
    if [[ -f "$REALM_BIN" ]]; then
        cp -p "$REALM_BIN" "${tmp_dir}/backup.realm" || err "无法备份旧 Realm 二进制"
        had_bin=true
    fi
    if [[ -f "$SERVICE_FILE" ]]; then
        cp -p "$SERVICE_FILE" "${tmp_dir}/backup.realm.service" || err "无法备份 Realm 服务文件"
        had_service=true
    fi

    local new_bin new_service
    new_bin=$(mktemp "$(dirname "$REALM_BIN")/.realm.new.XXXXXX") || err "无法创建 Realm 二进制临时文件"
    new_service=$(mktemp "$(dirname "$SERVICE_FILE")/.realm.service.XXXXXX") || err "无法创建 Realm 服务临时文件"
    _CLEANUP_FILES+=("$new_bin" "$new_service")
    install -m 755 "$bin_path" "$new_bin" || err "准备 Realm 二进制失败"

    cat > "$new_service" <<EOF
[Unit]
Description=Realm Port Forwarding
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${REALM_BIN} -c ${CONFIG_TOML}
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$new_service"

    if ! mv -f "$new_bin" "$REALM_BIN" || ! mv -f "$new_service" "$SERVICE_FILE"; then
        rollback_realm_install "$tmp_dir" "$had_bin" "$had_service" || true
        err "Realm 文件安装失败，已尝试回滚"
    fi
    if ! systemctl daemon-reload; then
        rollback_realm_install "$tmp_dir" "$had_bin" "$had_service" || true
        err "systemctl daemon-reload 失败，已尝试回滚"
    fi

    if ! reload_realm true; then
        if ! rollback_realm_install "$tmp_dir" "$had_bin" "$had_service"; then
            err "Realm 启动失败，且自动回滚失败，请立即检查 journalctl -u ${SERVICE_NAME}"
        fi
        err "Realm v${REALM_VERSION} 启动失败，已恢复旧版本"
    fi

    info "realm v${REALM_VERSION} 已安装完成"
}

# 2. 配置生成
generate_config() {
    init_meta
    local tmp_config
    tmp_config=$(mktemp "${CONFIG_TOML}.new.XXXXXX") || {
        warn "无法创建 Realm 配置临时文件"
        return 1
    }
    _CLEANUP_FILES+=("$tmp_config")

    if ! printf '%s\n' \
        '# 由 fw.sh 自动生成，请勿手动编辑' \
        '[log]' 'level = "warn"' 'output = "stdout"' '' \
        '[network]' 'use_udp = true' > "$tmp_config"; then
        warn "Realm 配置写入失败"
        return 1
    fi

    local count
    count=$(rule_count)
    if [[ "$count" -gt 0 ]]; then
        local rules
        if ! rules=$(jq -r '.rules[] | [.src_port, .dst_ip, .dst_port] | @tsv' "$META_FILE"); then
            warn "无法读取 Realm 转发规则"
            return 1
        fi

        local listen_addr
        listen_addr=$(detect_listen_addr)

        while IFS=$'\t' read -r sp dip dp; do
            [[ -n "$sp" ]] || continue
            if ! printf '\n%s\n%s\n%s\n' '[[endpoints]]' \
                "listen = \"${listen_addr}:${sp}\"" \
                "remote = \"${dip}:${dp}\"" >> "$tmp_config"; then
                warn "Realm 端点配置写入失败"
                return 1
            fi
        done <<< "$rules"
    fi

    if ! chmod 644 "$tmp_config" || ! mv -f "$tmp_config" "$CONFIG_TOML"; then
        warn "Realm 配置替换失败"
        return 1
    fi
}

# 3. 重载 realm
reload_realm() {
    local quiet=${1:-false}
    generate_config || return 1

    local count
    count=$(rule_count)

    if [[ "$count" -eq 0 ]]; then
        if realm_running; then
            if ! systemctl stop "$SERVICE_NAME"; then
                warn "realm 停止失败"
                return 1
            fi
            [[ "$quiet" == "true" ]] || info "无转发规则，realm 已停止"
        fi
        if ! systemctl disable "$SERVICE_NAME" >/dev/null 2>&1; then
            warn "realm 取消开机启动失败"
            return 1
        fi
        return 0
    fi

    if ! realm_installed; then
        warn "realm 未安装，配置已保存，请先运行: fw install"
        return 1
    fi

    # 有规则, 确保开机自启
    if ! systemctl enable "$SERVICE_NAME" >/dev/null 2>&1; then
        warn "realm 设置开机启动失败"
        return 1
    fi

    local service_command_ok=true
    if realm_running; then
        systemctl restart "$SERVICE_NAME" || service_command_ok=false
    else
        systemctl start "$SERVICE_NAME" || service_command_ok=false
    fi

    sleep 1
    if [[ "$service_command_ok" == "true" ]] && realm_running; then
        [[ "$quiet" == "true" ]] || info "realm 已重载 (${count} 条规则)"
    else
        warn "realm 启动失败，最近日志如下:"
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null | sed 's/^/  /' >&2 || true
        return 1
    fi

    return 0
}

# 4. 添加转发规则
add_forward() {
    CURRENT_ACTION="添加 realm 转发规则"
    local src_port=$1 dst_ip=$2 dst_port=$3 comment=${4:-""}

    validate_port "$src_port" "源端口" || return 1
    validate_port "$dst_port" "目标端口" || return 1
    validate_ipv4 "$dst_ip" || return 1

    # 规范化端口
    src_port=$((10#$src_port))
    dst_port=$((10#$dst_port))

    init_meta
    if jq -e --argjson p "$src_port" '.rules[] | select(.src_port == $p)' "$META_FILE" &>/dev/null; then
        warn "源端口 ${src_port} 已存在"; return 1
    fi

    # 精确检查 TCP 和 UDP 监听，避免重启 Realm 时影响已有规则。
    local occupied
    if ! occupied=$(ss -H -ltnup "sport = :${src_port}" 2>/dev/null); then
        warn "无法检查端口占用，未添加规则"
        return 1
    fi
    if [[ -n "$occupied" ]]; then
        warn "端口 ${src_port} 已被其他进程占用"
        printf '%s\n' "$occupied" | sed 's/^/  /'
        return 1
    fi

    # JSON 本身会转义引号，只需删除可破坏终端显示的控制字符。
    comment=$(printf '%s' "$comment" | LC_ALL=C tr -d '\000-\037\177')

    local backup_file tmp_file
    backup_file=$(mktemp /tmp/fw_meta_backup.XXXXXX) || { warn "无法创建规则备份"; return 1; }
    tmp_file=$(mktemp /tmp/fw_meta_new.XXXXXX) || { warn "无法创建规则临时文件"; return 1; }
    _CLEANUP_FILES+=("$backup_file" "$tmp_file")
    if ! cp -p "$META_FILE" "$backup_file"; then
        warn "无法备份当前规则"
        return 1
    fi
    if ! jq --argjson sp "$src_port" --arg di "$dst_ip" --argjson dp "$dst_port" --arg c "$comment" \
        '.rules += [{"src_port":$sp, "dst_ip":$di, "dst_port":$dp, "comment":$c}]' "$META_FILE" > "$tmp_file"; then
        warn "规则写入失败"
        return 1
    fi
    if ! chmod 600 "$tmp_file" || ! mv -f "$tmp_file" "$META_FILE"; then
        warn "规则文件替换失败"
        return 1
    fi

    if ! reload_realm true; then
        if ! cp -p "$backup_file" "$META_FILE"; then
            warn "转发启动失败，且规则回滚失败"
            return 1
        fi
        if ! reload_realm true; then
            warn "新增规则已回滚，但 Realm 恢复启动失败"
            return 1
        fi
        warn "转发启动失败，新增规则已回滚"
        return 1
    fi
    echo ""
    info "转发已添加: :${src_port} → ${dst_ip}:${dst_port}"
    echo -e " ${YELLOW}注意: FW 不会修改防火墙；如外部无法连接，请自行放行 TCP/UDP ${src_port}${PLAIN}"
    echo -e " ${DIM}提示: 如需配额/限速，在 pm.sh 中为端口 ${src_port} 添加监控${PLAIN}"
}

# 5. 删除转发规则
delete_forward() {
    CURRENT_ACTION="删除 realm 转发规则"
    local src_port=$1

    validate_port "$src_port" "源端口" || return 1
    src_port=$((10#$src_port))
    init_meta

    if ! jq -e --argjson p "$src_port" '.rules[] | select(.src_port == $p)' "$META_FILE" &>/dev/null; then
        warn "源端口 ${src_port} 不存在"; return 1
    fi

    local backup_file tmp_file
    backup_file=$(mktemp /tmp/fw_meta_backup.XXXXXX) || { warn "无法创建规则备份"; return 1; }
    tmp_file=$(mktemp /tmp/fw_meta_new.XXXXXX) || { warn "无法创建规则临时文件"; return 1; }
    _CLEANUP_FILES+=("$backup_file" "$tmp_file")
    if ! cp -p "$META_FILE" "$backup_file"; then
        warn "无法备份当前规则"
        return 1
    fi
    if ! jq --argjson sp "$src_port" '.rules = [.rules[] | select(.src_port != $sp)]' "$META_FILE" > "$tmp_file"; then
        warn "规则写入失败"
        return 1
    fi
    if ! chmod 600 "$tmp_file" || ! mv -f "$tmp_file" "$META_FILE"; then
        warn "规则文件替换失败"
        return 1
    fi

    if ! reload_realm true; then
        if ! cp -p "$backup_file" "$META_FILE"; then
            warn "realm 重载失败，且规则回滚失败"
            return 1
        fi
        if ! reload_realm true; then
            warn "删除操作已回滚，但 Realm 恢复启动失败"
            return 1
        fi
        warn "realm 重载失败，删除操作已回滚"
        return 1
    fi
    info "转发已删除: 源端口 ${src_port}"
    echo -e " ${DIM}提示: 如在 pm.sh 中有对应监控，请手动移除${PLAIN}"
}

print_rule_table() {
    local rules i=1 sp dip dp cmt
    if ! rules=$(jq -r '.rules[] | [.src_port, .dst_ip, .dst_port, (.comment // "")] | @tsv' "$META_FILE"); then
        warn "无法读取规则"
        return 1
    fi
    printf " %-4s %-10s %-25s %s\n" "序号" "监听" "目标" "备注"
    echo -e " ─────────────────────────────────────────────────────────────────────"
    while IFS=$'\t' read -r sp dip dp cmt; do
        [[ -n "$sp" ]] || continue
        printf " [%d]  %-10s %-25s %s\n" "$i" ":${sp}" "${dip}:${dp}" "$cmt"
        i=$((i + 1))
    done <<< "$rules"
}

# 6. 查看所有配置
show_all_configs() {
    init_meta
    local count
    count=$(rule_count)

    if [[ "$count" -eq 0 ]]; then
        warn "暂无转发规则。"
        return
    fi

    echo -e " ${BLUE}>>> 转发规则清单${PLAIN}"
    echo -e " ════════════════════════════════════════════════════════════════"

    print_rule_table || return

    echo -e " ${DIM}提示: 配额/限速请在 pm.sh 中为对应端口添加监控。${PLAIN}"
}

# 7. 更新管理脚本
update_script() {
    CURRENT_ACTION="更新 fw 管理脚本"
    local mode=${1:-menu}
    echo
    echo -e " ${BLUE}>>> 更新管理脚本${PLAIN}"
    echo -e " 当前版本: v${SCRIPT_VERSION}"
    echo -e " 远程地址: ${DIM}${SCRIPT_URL}${PLAIN}"
    echo

    local tmp_script
    tmp_script=$(mktemp "${SCRIPT_PATH}.update.XXXXXX") || err "无法创建更新临时文件"
    _CLEANUP_FILES+=("$tmp_script")

    if ! curl -fsSLo "$tmp_script" --connect-timeout 8 --max-time 30 "$(fresh_script_url)"; then
        err "下载失败，请检查网络；现有脚本未被覆盖。"
    fi
    if ! validate_script_candidate "$tmp_script"; then
        err "远程脚本格式或 Bash 语法校验失败，现有脚本未被覆盖。"
    fi

    # 提取远程版本号
    local remote_ver
    remote_ver=$(grep '^SCRIPT_VERSION=' "$tmp_script" | head -1 | cut -d'"' -f2 || true)

    if version_is_older "$remote_ver" "$SCRIPT_VERSION"; then
        rm -f "$tmp_script"
        err "拒绝降级：远端 v${remote_ver} 低于当前 v${SCRIPT_VERSION}"
    fi

    if [[ -z "$remote_ver" ]]; then
        warn "无法解析远程版本号，继续更新..."
    elif [[ "$remote_ver" == "$SCRIPT_VERSION" ]] && cmp -s "$tmp_script" "$SCRIPT_PATH"; then
        info "已是最新版本 (v${SCRIPT_VERSION})，无需更新。"
        rm -f "$tmp_script"
        return
    elif [[ "$remote_ver" == "$SCRIPT_VERSION" ]]; then
        warn "检测到同版本内容修订，将继续更新。"
    else
        echo -e " 发现新版本: ${GREEN}v${remote_ver}${PLAIN}"
    fi

    chmod 755 "$tmp_script"
    mv -f "$tmp_script" "$SCRIPT_PATH"
    info "脚本已更新完成!"
    echo
    [[ "$mode" == "menu" ]] && exec "$SCRIPT_PATH"
}

# 8. 完整卸载
uninstall_all() {
    CURRENT_ACTION="卸载 realm"
    echo
    echo -e " ${RED}════════════════════════════════════════${PLAIN}"
    echo -e " ${RED}  警告: 即将卸载 realm 并清除全部配置!${PLAIN}"
    echo -e " ${RED}════════════════════════════════════════${PLAIN}"
    echo
    read -rp " 确认执行? (输入 yes 确认): " confirm
    confirm=$(strip_cr "$confirm")
    [[ "${confirm,,}" != "yes" ]] && { echo " 已取消。"; return; }

    if realm_running && ! systemctl stop "$SERVICE_NAME"; then
        err "realm 停止失败，未继续删除文件"
    fi

    if [[ -f "$SERVICE_FILE" ]]; then
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 \
            || err "realm 取消开机启动失败"
        rm -f "$SERVICE_FILE" || err "Realm 服务文件删除失败"
        systemctl daemon-reload || err "systemd 重载失败"
    fi

    rm -f "$REALM_BIN" || err "Realm 二进制删除失败"
    rm -rf "$CONFIG_DIR" || err "Realm 配置目录删除失败"
    rm -f "$SCRIPT_PATH" || err "FW 快捷命令删除失败"

    info "realm 已彻底卸载。"
    warn "未修改防火墙；如旧版 FW 曾自动放行端口，请手动检查和清理。"
    exit 0
}

# ==================== 交互菜单 ====================

menu_add() {
    echo -e "\n${BLUE}>>> 添加转发规则${PLAIN}\n"
    local src_port dst_ip dst_port comment="" confirm

    read -rp " 源端口 (本机监听): " src_port || return 0
    src_port=$(strip_cr "$src_port")
    [[ -n "$src_port" ]] || return 0

    read -rp " 目标 IP: " dst_ip || return 0
    dst_ip=$(strip_cr "$dst_ip")
    [[ -n "$dst_ip" ]] || return 0

    read -rp " 目标端口 [${src_port}]: " dst_port || return 0
    dst_port=$(strip_cr "$dst_port")
    [[ -n "$dst_port" ]] || dst_port="$src_port"

    read -rp " 备注 (可选): " comment || true
    comment=$(strip_cr "$comment")

    printf '\n :%s → %s:%s  %b%s%b\n' "$src_port" "$dst_ip" "$dst_port" "$DIM" "$comment" "$PLAIN"
    read -rp " 确认? [Y/n] " confirm || return 0
    confirm=$(strip_cr "$confirm")
    [[ "$confirm" =~ ^[nN] ]] && { echo " 已取消"; return; }

    echo
    if ! add_forward "$src_port" "$dst_ip" "$dst_port" "$comment"; then
        warn "添加失败，请查看上方信息"
    fi
    return 0
}

menu_delete() {
    local count
    count=$(rule_count)

    if [[ "$count" -eq 0 ]]; then
        warn "暂无转发规则。"
        return
    fi

    echo -e "\n${BLUE}>>> 删除转发规则${PLAIN}\n"

    print_rule_table || return 0

    echo
    read -rp " 请选择要删除的序号 (输入 0 取消): " choice
    choice=$(strip_cr "$choice")
    [[ "$choice" == "0" ]] && return
    [[ "$choice" =~ ^[0-9]+$ ]] || { warn "输入无效"; return; }

    local idx=$((choice - 1))
    if [[ $idx -ge $count ]]; then
        warn "序号超出范围"
        return
    fi

    local target_port
    target_port=$(jq -r ".rules[$idx].src_port" "$META_FILE")

    read -rp " 确认删除源端口 $target_port 的转发? [y/N]: " confirm
    confirm=$(strip_cr "$confirm")
    if [[ "${confirm,,}" == "y" ]]; then
        echo
        if ! delete_forward "$target_port"; then
            warn "删除失败，请查看上方信息"
        fi
    else
        echo " 已取消。"
    fi
}

menu_status() {
    echo
    echo -e " ${BLUE}>>> 服务状态${PLAIN}"
    echo

    if ! realm_installed; then
        echo -e " realm: ${RED}未安装${PLAIN}"
        return
    fi

    local ver
    ver=$(get_realm_version)
    echo -e " 版本:  v${ver:-unknown}"
    echo -e " 二进制: ${REALM_BIN}"
    echo -e " 配置:  ${CONFIG_TOML}"
    echo

    if realm_running; then
        echo -e " 状态: ${GREEN}● 运行中${PLAIN}"
        local pid mem
        pid=$(systemctl show -p MainPID "$SERVICE_NAME" 2>/dev/null | cut -d= -f2)
        if [[ -n "$pid" && "$pid" != "0" ]]; then
            mem=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
            echo -e " PID: ${pid}  内存: ${mem}"
        fi
        echo
        echo -e " ${DIM}监听端口:${PLAIN}"
        ss -H -ltnup 2>/dev/null | awk '/realm/ {print "   " $1 "  " $5}' | head -40 || true
    else
        echo -e " 状态: ${YELLOW}● 已停止${PLAIN}"
        echo
        if journalctl -u "$SERVICE_NAME" -n 1 &>/dev/null 2>&1; then
            echo -e " ${DIM}最近日志:${PLAIN}"
            journalctl -u "$SERVICE_NAME" -n 5 --no-pager 2>/dev/null | sed 's/^/   /' || true
        fi
    fi
}

# ==================== 菜单 ====================
menu() {
    CURRENT_ACTION="读取 fw 管理菜单"
    clear
    echo -e "========================================================================"
    echo -e "  FW 端口转发 · v${SCRIPT_VERSION}"
    echo -e "========================================================================"

    # ---- 状态面板 ----
    local realm_status
    realm_status=$(get_realm_status)
    local ver_str=""
    if realm_installed; then
        local ver
        ver=$(get_realm_version)
        [[ -n "$ver" ]] && ver_str=" v${ver}"
    fi
    echo -e " Realm: ${realm_status}${ver_str}    规则: $(rule_count) 条"
    echo -e "------------------------------------------------------------------------"

    # ---- 规则列表 ----
    local count
    count=$(rule_count)
    if [[ "$count" -gt 0 ]]; then
        print_rule_table || true
    else
        echo -e " ${DIM}暂无转发规则，请先安装 realm 并添加规则。${PLAIN}"
    fi

    echo -e "========================================================================"
    echo
    echo -e " 1. ${GREEN}添加转发规则${PLAIN}"
    echo -e " 2. 删除转发规则"
    echo -e " 3. 服务状态与日志"

    if ! realm_installed; then
        echo -e " 4. ${GREEN}安装 Realm${PLAIN}"
    else
        echo -e " 4. 更新或重装 Realm"
    fi

    echo -e " 5. 更新 FW 脚本"
    echo -e " 6. ${RED}卸载全部${PLAIN}"
    echo -e " 0. 退出"
    echo -e "========================================================================"
    read -rp " 请输入选项: " choice
    choice=$(strip_cr "$choice")

    case $choice in
        1)
            if ! realm_installed; then
                warn "realm 未安装"
                read -rp " 现在安装? [Y/n] " c || return
                c=$(strip_cr "$c")
                [[ "$c" =~ ^[nN] ]] && return
                install_realm
            fi
            menu_add; read -rp " 按回车返回..." ;;
        2) menu_delete; read -rp " 按回车返回..." ;;
        3) menu_status; read -rp " 按回车返回..." ;;
        4) install_realm; read -rp " 按回车返回..." ;;
        5) update_script menu; read -rp " 按回车返回..." ;;
        6) uninstall_all ;;
        0) exit 0 ;;
        *) ;;
    esac
}

show_help() {
    echo
    echo " fw.sh — 端口转发管理器 (基于 Realm) v${SCRIPT_VERSION}"
    echo
    echo " 用法:"
    echo "   fw                交互菜单"
    echo "   fw install        安装/更新 Realm"
    echo "   fw list           列出转发规则"
    echo "   fw add SP DIP DP [备注]"
    echo "   fw del SP         删除转发"
    echo "   fw status         服务状态"
    echo "   fw update         更新 FW 脚本"
    echo "   fw uninstall      完整卸载"
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
init_meta

if [[ $# -gt 0 ]]; then
    case "$1" in
        install)   install_realm ;;
        uninstall) uninstall_all ;;
        list|ls)   show_all_configs ;;
        status)    menu_status ;;
        update)    update_script cli ;;
        add)
            realm_installed || err "realm 未安装，请先: $0 install"
            [[ $# -ge 4 ]] || err "用法: $0 add <源端口> <目标IP> <目标端口> [备注]"
            if ! add_forward "$2" "$3" "$4" "${5:-}"; then exit 1; fi
            ;;
        del|delete|rm)
            [[ $# -ge 2 ]] || err "用法: $0 del <源端口>"
            if ! delete_forward "$2"; then exit 1; fi
            ;;
        *) err "未知命令: $1 ($0 help 查看帮助)" ;;
    esac
else
    while true; do
        menu
    done
fi
