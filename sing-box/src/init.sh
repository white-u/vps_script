#!/bin/bash

# ============ 颜色函数 ============
_red() { echo -e "\e[31m$@\e[0m"; }
_green() { echo -e "\e[32m$@\e[0m"; }
_yellow() { echo -e "\e[33m$@\e[0m"; }

# ============ 输出函数 ============
err() {
    echo -e "\n\e[41m 错误 \e[0m $@\n"
    exit 1
}

warn() {
    echo -e "\n\e[43m 警告 \e[0m $@\n"
}

# ============ 工具函数 ============
_wget() {
    wget --no-check-certificate "$@"
}

load() {
    . $is_sh_dir/src/$1
}

# ============ 环境检测 ============
# root 权限
[[ $EUID != 0 ]] && err "请使用 root 用户运行此脚本"

# 包管理器
cmd=$(type -P apt-get || type -P yum)
[[ ! $cmd ]] && err "此脚本仅支持 Ubuntu/Debian/CentOS 系统"

# 系统架构
case $(uname -m) in
    amd64 | x86_64)
        is_arch=amd64
        ;;
    *aarch64* | *armv8*)
        is_arch=arm64
        ;;
    *)
        err "此脚本仅支持 64 位系统"
        ;;
esac

# ============ 全局变量 ============
is_core=sing-box
is_core_dir=/etc/$is_core
is_core_bin=$is_core_dir/bin/$is_core
is_core_repo=SagerNet/$is_core
is_conf_dir=$is_core_dir/conf
is_config_json=$is_core_dir/config.json
is_log_dir=/var/log/$is_core
is_sh_dir=$is_core_dir/sh
is_sh_bin=/usr/local/bin/$is_core
is_sh_url="https://raw.githubusercontent.com/white-u/vps_script/main/sing-box"

# ============ 状态检测 ============
# 核心版本
[[ -f $is_core_bin ]] && is_core_ver=$($is_core_bin version 2>/dev/null | head -n1 | cut -d' ' -f3)

# 运行状态
if systemctl is-active --quiet $is_core 2>/dev/null; then
    is_core_status=$(_green "运行中")
else
    is_core_status=$(_red "未运行")
    is_core_stop=1
fi

# 服务器 IP
get_ip() {
    is_ipv4=$(curl -s4m5 ip.sb 2>/dev/null || curl -s4m5 api.ipify.org 2>/dev/null)
    is_ipv6=$(curl -s6m5 ip.sb 2>/dev/null)
    is_addr=${is_ipv4:-$is_ipv6}
    [[ -z $is_addr ]] && is_addr="<未知IP>"
}
get_ip

# ============ 入口 ============
load core.sh
main "$@"
