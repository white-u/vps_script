#!/bin/bash

# DNS 配置模块

set_dns() {
    echo
    echo "设置 DNS 服务器"
    echo
    echo "  1. Cloudflare (1.1.1.1)"
    echo "  2. Google (8.8.8.8)"
    echo "  3. 阿里云 (223.5.5.5)"
    echo "  4. 自定义"
    echo "  0. 取消"
    echo
    read -rp "请选择: " dns_pick
    
    case $dns_pick in
        1) dns1="1.1.1.1"; dns2="1.0.0.1" ;;
        2) dns1="8.8.8.8"; dns2="8.8.4.4" ;;
        3) dns1="223.5.5.5"; dns2="223.6.6.6" ;;
        4)
            read -rp "主 DNS: " dns1
            read -rp "备 DNS: " dns2
            [[ -z $dns1 ]] && { _yellow "DNS 不能为空"; return; }
            ;;
        0) echo "已取消"; return ;;
        *) _yellow "无效选择"; return ;;
    esac
    
    # 备份原配置
    [[ -f /etc/resolv.conf ]] && cp /etc/resolv.conf /etc/resolv.conf.bak
    
    # 写入新配置
    cat > /etc/resolv.conf <<EOFDNS
nameserver $dns1
nameserver $dns2
EOFDNS
    
    _green "DNS 已设置: $dns1, $dns2"
}

show_dns() {
    echo
    echo "当前 DNS 配置:"
    echo
    cat /etc/resolv.conf | grep nameserver
    echo
}
