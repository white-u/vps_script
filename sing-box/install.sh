#!/bin/bash

# ============ 颜色函数 ============
_red() { echo -e "\e[31m$@\e[0m"; }
_green() { echo -e "\e[32m$@\e[0m"; }
_yellow() { echo -e "\e[33m$@\e[0m"; }

err() {
    echo -e "\n\e[41m 错误 \e[0m $@\n"
    exit 1
}

# ============ 环境检测 ============
[[ $EUID != 0 ]] && err "请使用 root 用户运行此脚本"

cmd=$(type -P apt-get || type -P yum)
[[ ! $cmd ]] && err "此脚本仅支持 Ubuntu/Debian/CentOS 系统"

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
# 脚本下载基础 URL
is_sh_url="https://raw.githubusercontent.com/white-u/vps_script/main/sing-box"

# ============ 显示帮助 ============
show_help() {
    echo "Usage: $0 [-p proxy] [-v version] [-h]"
    echo
    echo "  -p <proxy>    使用代理下载, 例如: -p http://127.0.0.1:7890"
    echo "  -v <version>  指定 $is_core 版本, 例如: -v 1.8.0"
    echo "  -h            显示此帮助"
    echo
    exit 0
}

# ============ 参数解析 ============
while [[ $# -gt 0 ]]; do
    case $1 in
        -p)
            [[ -z $2 ]] && err "(-p) 缺少代理地址"
            proxy=$2
            shift 2
            ;;
        -v)
            [[ -z $2 ]] && err "(-v) 缺少版本号"
            is_core_ver="v${2#v}"
            shift 2
            ;;
        -h)
            show_help
            ;;
        *)
            err "未知参数: $1"
            ;;
    esac
done

# ============ 检查已安装 ============
[[ -f $is_sh_bin && -d $is_core_dir ]] && err "已安装，如需重装请先卸载: $is_core uninstall"

# ============ 开始安装 ============
echo
echo ">>> 安装 $is_core..."

# ============ 安装依赖 ============
echo ">>> 安装依赖..."
$cmd update -y &>/dev/null
$cmd install -y wget tar jq &>/dev/null || err "依赖安装失败"

# ============ 下载函数 ============
download() {
    [[ $proxy ]] && export https_proxy=$proxy
    wget --no-check-certificate -t 3 -q -O "$1" "$2" || err "下载失败: $2"
}

# ============ 下载核心 ============
echo ">>> 下载 $is_core 核心..."
if [[ -z $is_core_ver ]]; then
    is_core_ver=$(wget -qO- "https://api.github.com/repos/$is_core_repo/releases/latest" | grep tag_name | grep -oE "v[0-9.]+")
    [[ -z $is_core_ver ]] && err "获取最新版本失败"
fi
echo "    版本: $is_core_ver"

tmp_dir=$(mktemp -d)
core_tar="$tmp_dir/core.tar.gz"
core_url="https://github.com/$is_core_repo/releases/download/$is_core_ver/$is_core-${is_core_ver#v}-linux-$is_arch.tar.gz"
download "$core_tar" "$core_url"

# ============ 下载脚本 ============
echo ">>> 下载管理脚本..."

# ============ 创建目录 ============
mkdir -p $is_core_dir/bin $is_conf_dir $is_sh_dir/src $is_log_dir

# 解压核心
tar -xzf "$core_tar" -C $is_core_dir/bin --strip-components=1

# 脚本文件列表
sh_files=("sing-box.sh" "src/init.sh" "src/core.sh" "src/dns.sh" "src/bbr.sh" "src/log.sh" "src/download.sh")

for f in "${sh_files[@]}"; do
    download "$is_sh_dir/$f" "$is_sh_url/$f"
done

# 清理临时文件
rm -rf "$tmp_dir"

# ============ 创建命令链接 ============
ln -sf $is_sh_dir/$is_core.sh $is_sh_bin
ln -sf $is_sh_dir/$is_core.sh /usr/local/bin/sb
chmod +x $is_core_bin $is_sh_bin /usr/local/bin/sb $is_sh_dir/*.sh $is_sh_dir/src/*.sh

# ============ 创建 systemd 服务 ============
echo ">>> 创建服务..."
cat > /etc/systemd/system/$is_core.service <<EOF
[Unit]
Description=$is_core Service
After=network.target

[Service]
User=root
ExecStart=$is_core_bin run -c $is_config_json -C $is_conf_dir
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $is_core &>/dev/null

# ============ 创建默认配置 ============
echo ">>> 创建配置..."
cat > $is_config_json <<EOF
{
    "log": {
        "level": "info",
        "output": "$is_log_dir/sing-box.log",
        "timestamp": true
    },
    "dns": {},
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        }
    ]
}
EOF

# ============ 完成 ============
echo
_green "安装完成!"
echo "版本: $is_core_ver"
echo "命令: sb 或 $is_core"
echo
echo "快速开始: sb add"
echo
