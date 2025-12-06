#!/bin/bash

# BBR 优化模块

check_bbr() {
    local current=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    local available=$(sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | awk '{print $3}')
    
    echo
    echo "BBR 状态:"
    echo "  当前算法: ${current:-未知}"
    echo "  可用算法: ${available:-未知}"
    
    if [[ $current == "bbr" ]]; then
        echo
        _green "BBR 已启用"
    else
        echo
        _yellow "BBR 未启用"
    fi
    echo
}

enable_bbr() {
    # 检查内核版本
    local kernel_ver=$(uname -r | cut -d. -f1)
    if [[ $kernel_ver -lt 4 ]]; then
        err "BBR 需要 Linux 4.9+ 内核，当前: $(uname -r)"
    fi
    
    # 检查是否已启用
    local current=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    if [[ $current == "bbr" ]]; then
        _green "BBR 已经启用"
        return
    fi
    
    # 先删除旧配置，避免重复
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    
    # 启用 BBR
    cat >> /etc/sysctl.conf <<EOF

# BBR
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    
    sysctl -p &>/dev/null
    
    # 验证
    current=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    if [[ $current == "bbr" ]]; then
        _green "BBR 启用成功"
    else
        err "BBR 启用失败"
    fi
}
