#!/usr/bin/env bash
# GitHub download entry; the installed task remains a single Python script.
set -euo pipefail
umask 077

SOURCE_URL='https://raw.githubusercontent.com/white-u/vps_script/main/traffic_balance.py'
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
    local target=$1
    if ! curl -q --fail --show-error --location --progress-bar \
        --proto '=https' --proto-redir '=https' --connect-timeout 5 --max-time 60 \
        --output "$target" "$SOURCE_URL"; then
        echo 'GitHub 脚本下载失败；未修改已有任务，请检查网络后重新运行。' >&2
        return 1
    fi
    if [[ ! -s "$target" ]] || ! python3 -c \
        'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_text(),str(p),"exec")' "$target"; then
        echo '下载内容为空或 Python 校验失败；未执行脚本，请重新下载。' >&2
        return 1
    fi
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
