#!/usr/bin/env bash
# GitHub download entry; the installed task remains a single Python script.
set -euo pipefail
umask 077

# Keep the executable payload identical across download channels.
SOURCE_REF='traffic-balance-v1.0.1'
SOURCE_SHA256='94572dbe661f25640c8ed70a3cbd55f967df293b3705a934e1c690609855d0c3'
SOURCE_URLS=(
    "https://raw.githubusercontent.com/white-u/vps_script/$SOURCE_REF/traffic_balance.py"
    "https://api.github.com/repos/white-u/vps_script/contents/traffic_balance.py?ref=$SOURCE_REF"
    "https://cdn.jsdelivr.net/gh/white-u/vps_script@$SOURCE_REF/traffic_balance.py"
)
TASK_TMP=''

cleanup() {
    if [[ -n "$TASK_TMP" && -d "$TASK_TMP" ]]; then
        rm -rf -- "$TASK_TMP"
    fi
}

check_platform() {
    if [[ $EUID -ne 0 ]]; then
        echo '需要 root 安装依赖与管理服务；尚未安装，请用 root 重新运行。' >&2
        return 1
    fi
    if [[ $(uname -s) != Linux || ! -f /etc/os-release || ! -d /run/systemd/system ]]; then
        echo '仅支持使用 systemd 的 Debian/Ubuntu；尚未安装，请在支持的服务器上运行。' >&2
        return 1
    fi
    # This is the operating system's own metadata, not downloaded content.
    . /etc/os-release
    if [[ ${ID:-} != debian && ${ID:-} != ubuntu ]]; then
        echo '仅支持 Debian/Ubuntu；尚未安装，请在支持的服务器上运行。' >&2
        return 1
    fi
}

ensure_dependencies() {
    local -a packages=()
    command -v python3 >/dev/null 2>&1 || packages+=(python3)
    command -v ip >/dev/null 2>&1 || packages+=(iproute2)
    command -v curl >/dev/null 2>&1 || packages+=(curl)
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || packages+=(ca-certificates)
    if (( ${#packages[@]} )); then
        echo '正在安装启动菜单所需的基础工具……'
        if ! apt-get update || ! apt-get install -y "${packages[@]}"; then
            echo '基础工具安装失败；未启动任务，请检查 APT 软件源后重试。' >&2
            return 1
        fi
    fi
    if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
        echo '需要 Python 3.8 或以上版本；未启动任务，请升级 Python 或使用较新的系统。' >&2
        return 1
    fi
}

download_script() {
    local target=$1 url attempt=0
    for url in "${SOURCE_URLS[@]}"; do
        attempt=$((attempt+1))
        printf '正在尝试下载通道 %d/%d……\n' "$attempt" "${#SOURCE_URLS[@]}"
        : > "$target"
        if curl -q --fail --show-error --location --progress-bar \
            --proto '=https' --proto-redir '=https' --connect-timeout 5 --max-time 20 \
            --header 'Accept: application/vnd.github.raw+json' \
            --output "$target" "$url" && [[ -s "$target" ]] && python3 -c \
            'import hashlib,pathlib,sys; p=pathlib.Path(sys.argv[1]); data=p.read_bytes();
if hashlib.sha256(data).hexdigest()!=sys.argv[2]: sys.exit("脚本摘要不匹配")
compile(data,str(p),"exec")' "$target" "$SOURCE_SHA256"; then
            return 0
        fi
        echo '当前通道下载或校验未成功，尝试下一通道。' >&2
    done
    echo '所有通道均下载失败或校验不通过；未执行脚本，请更换网络或手动上传。' >&2
    return 1
}

main() {
    check_platform
    ensure_dependencies
    TASK_TMP=$(mktemp -d "${TMPDIR:-/tmp}/tb-install.XXXXXXXX")
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    download_script "$TASK_TMP/traffic_balance.py"
    echo '下载校验通过。进入菜单后选 2，可配置并启动；保存配置后可用 tb 调起。'
    python3 "$TASK_TMP/traffic_balance.py"
}

main "$@"
