#!/bin/bash

# 更新模块

# 代理设置（可通过环境变量 PROXY 设置）
is_proxy=${PROXY:-}

# 获取最新版本号
get_latest_version() {
    local repo=$1
    local api="https://api.github.com/repos/$repo/releases/latest"
    local ver=$(curl -sfm10 "$api" | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
    echo $ver
}

# 更新核心
update_core() {
    echo
    echo "检查 sing-box 更新..."
    
    local latest=$(get_latest_version $is_core_repo)
    [[ -z $latest ]] && err "无法获取最新版本"
    
    local current=${is_core_ver:-未安装}
    
    echo "当前版本: $current"
    echo "最新版本: $latest"
    
    if [[ $current == $latest ]]; then
        _green "已是最新版本"
        return
    fi
    
    echo
    read -p "是否更新? [Y/n]: " confirm
    [[ $confirm =~ ^[Nn]$ ]] && { echo "已取消"; return; }
    
    # 下载新版本
    local url="https://github.com/$is_core_repo/releases/download/v${latest}/sing-box-${latest}-linux-${is_arch}.tar.gz"
    local tmp_file="/tmp/sing-box.tar.gz"
    
    echo "下载中..."
    if [[ $is_proxy ]]; then
        curl -x "$is_proxy" -fLm120 -o "$tmp_file" "$url"
    else
        curl -fLm120 -o "$tmp_file" "$url"
    fi
    
    [[ $? -ne 0 ]] && err "下载失败"
    
    # 停止服务
    systemctl stop $is_core
    
    # 解压并替换
    tar -xzf "$tmp_file" -C /tmp
    cp "/tmp/sing-box-${latest}-linux-${is_arch}/sing-box" "$is_core_bin"
    chmod +x "$is_core_bin"
    
    # 清理
    rm -rf "$tmp_file" "/tmp/sing-box-${latest}-linux-${is_arch}"
    
    # 启动服务
    systemctl start $is_core
    
    _green "更新完成: $current -> $latest"
}

# 更新脚本
update_sh() {
    echo
    echo "更新脚本..."
    
    local tmp_dir="/tmp/sing-box-sh"
    mkdir -p "$tmp_dir/src"
    
    # 脚本文件列表
    local files=("sing-box.sh" "src/init.sh" "src/core.sh" "src/dns.sh" "src/bbr.sh" "src/log.sh" "src/download.sh")
    
    for f in "${files[@]}"; do
        if [[ $is_proxy ]]; then
            curl -x "$is_proxy" -sfLm30 -o "$tmp_dir/$f" "$is_sh_url/$f" || { _red "下载失败: $f"; return 1; }
        else
            curl -sfLm30 -o "$tmp_dir/$f" "$is_sh_url/$f" || { _red "下载失败: $f"; return 1; }
        fi
    done
    
    # 复制到目标目录
    cp -r "$tmp_dir"/* "$is_sh_dir/"
    chmod +x "$is_sh_dir/sing-box.sh" "$is_sh_dir/src/"*.sh
    
    # 清理
    rm -rf "$tmp_dir"
    
    _green "脚本更新完成"
}

# 卸载
uninstall() {
    echo
    _yellow "警告: 即将卸载 sing-box"
    echo
    read -p "确认卸载? [y/N]: " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && { echo "已取消"; return; }
    
    # 停止服务
    systemctl stop $is_core &>/dev/null
    systemctl disable $is_core &>/dev/null
    
    # 删除文件
    rm -rf "$is_core_dir"
    rm -rf "$is_log_dir"
    rm -f /etc/systemd/system/${is_core}.service
    rm -f /usr/local/bin/sb
    rm -f /usr/local/bin/$is_core
    
    systemctl daemon-reload
    
    _green "sing-box 已卸载"
}
