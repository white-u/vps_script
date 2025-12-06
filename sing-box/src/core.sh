#!/bin/bash

# ==================== 获取配置文件 ====================
# 获取配置文件列表
get_conf_list() {
    conf_list=()
    while IFS= read -r -d '' file; do
        conf_list+=("$(basename "$file")")
    done < <(find "$is_conf_dir" -maxdepth 1 -name "*.json" -print0 2>/dev/null)
}

# 选择配置文件
select_conf() {
    get_conf_list
    if [[ ${#conf_list[@]} -eq 0 ]]; then
        _yellow "没有找到配置文件"
        return 1
    fi
    # 如果只有一个配置，直接使用
    if [[ ${#conf_list[@]} -eq 1 ]]; then
        is_conf_file=${conf_list[0]}
        echo "自动选择: $is_conf_file"
        return 0
    fi
    # 多个配置，让用户选择
    echo
    echo "请选择配置:"
    echo
    for i in "${!conf_list[@]}"; do
        local f=${conf_list[$i]}
        local proto=$(jq -r '.inbounds[0].type' "$is_conf_dir/$f" 2>/dev/null)
        local port=$(jq -r '.inbounds[0].listen_port' "$is_conf_dir/$f" 2>/dev/null)
        printf "  %2d. %-30s [%s:%s]\n" "$((i+1))" "$f" "$proto" "$port"
    done
    echo
    echo "   0. 返回"
    echo
    read -rp "请输入序号: " pick
    [[ -z $pick || $pick == "0" ]] && return 1
    [[ ! $pick =~ ^[0-9]+$ ]] && { _yellow "请输入数字"; return 1; }
    [[ $pick -lt 1 || $pick -gt ${#conf_list[@]} ]] && { _yellow "序号超出范围"; return 1; }
    is_conf_file=${conf_list[$((pick-1))]}
    return 0
}

# ==================== 添加配置 ====================
# 协议列表 (只保留 VLESS-Reality 和 Shadowsocks)
protocols=(
    "VLESS-Reality"
    "Shadowsocks"
)

# 生成随机端口
rand_port() {
    local port
    while :; do
        port=$((RANDOM % 30000 + 10000))
        # 使用精确匹配端口
        [[ ! $(ss -tuln | awk '{print $5}' | grep -E ":${port}$") ]] && break
    done
    echo $port
}

# 生成 UUID
rand_uuid() {
    cat /proc/sys/kernel/random/uuid
}

# 生成随机密码
rand_pass() {
    # 生成足够长的随机字符串再截取
    openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 16
}

# 生成 Reality 密钥对
gen_reality_keys() {
    local keys=$($is_core_bin generate reality-keypair 2>/dev/null)
    is_private_key=$(echo "$keys" | grep PrivateKey | awk '{print $2}')
    is_public_key=$(echo "$keys" | grep PublicKey | awk '{print $2}')
}

# 生成 ShortID
gen_short_id() {
    openssl rand -hex 8
}

# 输入端口
input_port() {
    local default_port=$(rand_port)
    read -rp "端口 [$default_port]: " is_port
    is_port=${is_port:-$default_port}
    [[ ! $is_port =~ ^[0-9]+$ ]] && { _yellow "端口必须是数字"; input_port; return; }
    [[ $is_port -lt 1 || $is_port -gt 65535 ]] && { _yellow "端口范围: 1-65535"; input_port; return; }
    # 精确匹配端口
    [[ $(ss -tuln | awk '{print $5}' | grep -E ":${is_port}$") ]] && { _yellow "端口 $is_port 已被占用"; input_port; return; }
}

# 输入 UUID
input_uuid() {
    local default_uuid=$(rand_uuid)
    read -rp "UUID [$default_uuid]: " is_uuid
    is_uuid=${is_uuid:-$default_uuid}
}

# 输入密码
input_pass() {
    local default_pass=$(rand_pass)
    read -rp "密码 [$default_pass]: " is_pass
    is_pass=${is_pass:-$default_pass}
}

# 输入 SNI (默认 www.time.is)
input_sni() {
    local default_sni="www.time.is"
    read -rp "SNI [$default_sni]: " is_sni
    is_sni=${is_sni:-$default_sni}
}

# 输入备注 (默认服务器地址)
input_remark() {
    local default_remark="$is_addr"
    read -rp "备注 [$default_remark]: " is_remark
    is_remark=${is_remark:-$default_remark}
}

# 添加配置主函数
add() {
    # 如果传入参数，按名称匹配协议
    if [[ $1 ]]; then
        case ${1,,} in
            r|reality|vless|vless-reality)
                is_protocol="VLESS-Reality"
                ;;
            ss|shadowsocks)
                is_protocol="Shadowsocks"
                ;;
            *)
                _yellow "未找到匹配的协议: $1"
                _yellow "可用: reality (r), ss"
                return 1
                ;;
        esac
    else
        # 显示协议菜单
        echo
        echo "请选择协议:"
        echo
        for i in "${!protocols[@]}"; do
            printf "  %2d. %s\n" $((i+1)) "${protocols[$i]}"
        done
        echo
        echo "   0. 返回"
        echo
        read -rp "请输入序号: " pick
        [[ -z $pick || $pick == "0" ]] && return 0
        [[ ! $pick =~ ^[0-9]+$ ]] && { _yellow "请输入数字"; return 1; }
        [[ $pick -lt 1 || $pick -gt ${#protocols[@]} ]] && { _yellow "序号超出范围"; return 1; }
        is_protocol=${protocols[$((pick-1))]}
    fi
    
    echo
    _green ">>> 配置 $is_protocol"
    echo
    
    # 输入通用参数
    input_port
    
    # 根据协议类型调用对应函数
    case $is_protocol in
        VLESS-Reality)
            add_vless_reality
            ;;
        Shadowsocks)
            add_shadowsocks
            ;;
    esac
    
    # 保存配置
    if save_conf; then
        # 重启服务
        systemctl restart $is_core &>/dev/null
        # 显示配置信息
        is_conf_file=$is_conf_name.json
        info_show
    fi
}

# ==================== 协议配置函数 ====================
# VLESS Reality
add_vless_reality() {
    input_uuid
    input_sni
    input_remark
    gen_reality_keys
    is_short_id=$(gen_short_id)
    is_conf_name="vless-reality-${is_port}"
    
    is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "vless",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "users": [{
            "uuid": "$is_uuid",
            "flow": "xtls-rprx-vision"
        }],
        "tls": {
            "enabled": true,
            "server_name": "$is_sni",
            "reality": {
                "enabled": true,
                "handshake": {
                    "server": "$is_sni",
                    "server_port": 443
                },
                "private_key": "$is_private_key",
                "short_id": ["$is_short_id"]
            }
        }
    }],
    "outbounds": [
        {"type": "direct"},
        {"type": "direct", "tag": "public_key_$is_public_key"}
    ]
}
EOF
)
}

# Shadowsocks
add_shadowsocks() {
    echo
    echo "加密方式:"
    echo "  1. 2022-blake3-aes-128-gcm (推荐)"
    echo "  2. 2022-blake3-aes-256-gcm"
    echo "  3. 2022-blake3-chacha20-poly1305"
    echo
    read -rp "选择 [1]: " method_pick
    case ${method_pick:-1} in
        1) is_method="2022-blake3-aes-128-gcm"; is_ss_pass=$(openssl rand -base64 16) ;;
        2) is_method="2022-blake3-aes-256-gcm"; is_ss_pass=$(openssl rand -base64 32) ;;
        3) is_method="2022-blake3-chacha20-poly1305"; is_ss_pass=$(openssl rand -base64 32) ;;
        *) is_method="2022-blake3-aes-128-gcm"; is_ss_pass=$(openssl rand -base64 16) ;;
    esac
    
    input_remark
    is_conf_name="shadowsocks-${is_port}"
    
    is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "shadowsocks",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "method": "$is_method",
        "password": "$is_ss_pass"
    }]
}
EOF
)
}

# 保存配置
save_conf() {
    local tmp_file="$is_conf_dir/$is_conf_name.json"
    echo "$is_conf" | jq . > "$tmp_file" 2>/dev/null
    if [[ $? -ne 0 ]]; then
        _red "配置保存失败，JSON 格式错误"
        return 1
    fi
    
    # 验证配置
    local check_result
    check_result=$($is_core_bin check -c "$is_config_json" -C "$is_conf_dir" 2>&1)
    if [[ $? -ne 0 ]]; then
        echo
        _red "配置验证失败:"
        echo "$check_result"
        rm -f "$tmp_file"
        return 1
    fi
    
    _green "配置已保存: $is_conf_name.json"
    return 0
}

# ==================== 列出配置 ====================
list() {
    local files=($(ls $is_conf_dir 2>/dev/null | grep '\.json$'))
    if [[ ${#files[@]} -eq 0 ]]; then
        echo
        _yellow "暂无配置"
        echo
        return
    fi
    
    echo
    printf "%-3s %-30s %-12s %-6s\n" "#" "名称" "协议" "端口"
    echo "------------------------------------------------------"
    
    for i in "${!files[@]}"; do
        local f=${files[$i]}
        local proto=$(jq -r '.inbounds[0].type' "$is_conf_dir/$f")
        local port=$(jq -r '.inbounds[0].listen_port' "$is_conf_dir/$f")
        printf "%-3s %-30s %-12s %-6s\n" "$((i+1))" "$f" "$proto" "$port"
    done
    echo
}

# ==================== 修改配置 ====================
change() {
    # 选择配置
    if [[ $1 ]]; then
        get_conf_list
        for f in "${conf_list[@]}"; do
            [[ $f =~ $1 ]] && is_conf_file=$f && break
        done
        [[ -z $is_conf_file ]] && { _yellow "未找到匹配的配置: $1"; return 1; }
    else
        select_conf || return 1
    fi
    
    local conf_path="$is_conf_dir/$is_conf_file"
    local proto=$(jq -r '.inbounds[0].type' "$conf_path")
    
    echo
    echo "修改: $is_conf_file ($proto)"
    echo
    echo "可修改项:"
    echo "  1. 端口"
    echo "  2. 主要凭证 (UUID/密码)"
    echo
    echo "  0. 返回"
    echo
    read -rp "请选择: " change_pick
    
    case $change_pick in
        1) change_port "$conf_path" ;;
        2) change_cred "$conf_path" "$proto" ;;
        0|"") return 0 ;;
        *) _yellow "无效选择" ;;
    esac
}

# 修改端口
change_port() {
    local conf_path=$1
    local old_port=$(jq -r '.inbounds[0].listen_port' "$conf_path")
    
    echo "当前端口: $old_port"
    read -rp "新端口: " new_port
    
    [[ -z $new_port ]] && { echo "已取消"; return; }
    [[ ! $new_port =~ ^[0-9]+$ ]] && { _yellow "端口必须是数字"; return; }
    [[ $new_port -lt 1 || $new_port -gt 65535 ]] && { _yellow "端口范围: 1-65535"; return; }
    [[ $(ss -tuln | awk '{print $5}' | grep -E ":${new_port}$") ]] && { _yellow "端口 $new_port 已被占用"; return; }
    
    # 修改并验证
    jq ".inbounds[0].listen_port = $new_port" "$conf_path" > "${conf_path}.tmp"
    if $is_core_bin check -c "$is_config_json" -C "$is_conf_dir" &>/dev/null; then
        mv "${conf_path}.tmp" "$conf_path"
        _green "端口已修改: $old_port -> $new_port"
        systemctl restart $is_core &>/dev/null
    else
        rm -f "${conf_path}.tmp"
        _red "配置验证失败"
    fi
}

# 修改凭证
change_cred() {
    local conf_path=$1
    local proto=$2
    
    case $proto in
        vless)
            local old_uuid=$(jq -r '.inbounds[0].users[0].uuid' "$conf_path")
            echo "当前 UUID: $old_uuid"
            local default_uuid=$(rand_uuid)
            read -rp "新 UUID [$default_uuid]: " new_uuid
            new_uuid=${new_uuid:-$default_uuid}
            jq ".inbounds[0].users[0].uuid = \"$new_uuid\"" "$conf_path" > "${conf_path}.tmp" && mv "${conf_path}.tmp" "$conf_path"
            _green "UUID 已修改"
            systemctl restart $is_core &>/dev/null
            ;;
        shadowsocks)
            local old_pass=$(jq -r '.inbounds[0].password' "$conf_path")
            local method=$(jq -r '.inbounds[0].method' "$conf_path")
            echo "当前密码: $old_pass"
            echo "加密方式: $method"
            local key_len=16
            [[ $method =~ "256" || $method =~ "chacha20" ]] && key_len=32
            local default_pass=$(openssl rand -base64 $key_len)
            read -rp "新密码 [$default_pass]: " new_pass
            new_pass=${new_pass:-$default_pass}
            jq ".inbounds[0].password = \"$new_pass\"" "$conf_path" > "${conf_path}.tmp" && mv "${conf_path}.tmp" "$conf_path"
            _green "密码已修改"
            systemctl restart $is_core &>/dev/null
            ;;
        *)
            _yellow "此协议暂不支持修改凭证"
            ;;
    esac
}

# ==================== 删除配置 ====================
del() {
    # 如果传入参数，按名称匹配
    if [[ $1 ]]; then
        get_conf_list
        for f in "${conf_list[@]}"; do
            [[ $f =~ $1 ]] && is_conf_file=$f && break
        done
        [[ -z $is_conf_file ]] && { _yellow "未找到匹配的配置: $1"; return 1; }
    else
        select_conf || return 1
    fi
    
    # 确认删除
    echo
    read -rp "确认删除 $is_conf_file? [y/N]: " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && { echo "已取消"; return 0; }
    
    # 删除文件
    rm -f "$is_conf_dir/$is_conf_file"
    _green "已删除: $is_conf_file"
    
    # 重启服务
    systemctl restart $is_core &>/dev/null
}

# ==================== 查看配置 ====================
info() {
    # 如果传入参数，按名称匹配
    if [[ $1 ]]; then
        get_conf_list
        for f in "${conf_list[@]}"; do
            [[ $f =~ $1 ]] && is_conf_file=$f && break
        done
        [[ -z $is_conf_file ]] && { _yellow "未找到匹配的配置: $1"; return 1; }
    else
        select_conf || return 1
    fi
    
    info_show
}

# 显示配置信息
info_show() {
    local conf_path="$is_conf_dir/$is_conf_file"
    
    # 解析配置
    local proto=$(jq -r '.inbounds[0].type' "$conf_path")
    local port=$(jq -r '.inbounds[0].listen_port' "$conf_path")
    local tag=$(jq -r '.inbounds[0].tag' "$conf_path")
    
    echo
    echo "============================================"
    echo "             配置信息"
    echo "============================================"
    echo
    echo "配置文件: $is_conf_file"
    echo "协议类型: $proto"
    echo "监听端口: $port"
    echo "服务地址: $is_addr"
    echo
    
    # 根据协议显示不同信息
    case $proto in
        vless)
            local uuid=$(jq -r '.inbounds[0].users[0].uuid' "$conf_path")
            local flow=$(jq -r '.inbounds[0].users[0].flow // empty' "$conf_path")
            local reality=$(jq -r '.inbounds[0].tls.reality.enabled // false' "$conf_path")
            echo "UUID: $uuid"
            [[ $flow ]] && echo "Flow: $flow"
            if [[ $reality == "true" ]]; then
                local sni=$(jq -r '.inbounds[0].tls.server_name' "$conf_path")
                local pbk=$(jq -r '.outbounds[1].tag // empty' "$conf_path" | sed 's/public_key_//')
                local sid=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "$conf_path")
                echo "SNI: $sni"
                [[ $pbk ]] && echo "PublicKey: $pbk"
                echo "ShortID: $sid"
                echo "Fingerprint: chrome"
            fi
            ;;
        shadowsocks)
            local method=$(jq -r '.inbounds[0].method' "$conf_path")
            local password=$(jq -r '.inbounds[0].password' "$conf_path")
            echo "加密方式: $method"
            echo "密码: $password"
            ;;
    esac
    
    echo
    echo "============================================"
    echo "             分享链接"
    echo "============================================"
    echo
    gen_link
    echo
    echo "============================================"
}

# 生成分享链接
gen_link() {
    local conf_path="$is_conf_dir/$is_conf_file"
    local proto=$(jq -r '.inbounds[0].type' "$conf_path")
    local port=$(jq -r '.inbounds[0].listen_port' "$conf_path")
    
    # 备注：优先使用 is_remark，否则使用服务器地址
    local remark="${is_remark:-${is_addr}}"
    
    case $proto in
        vless)
            local uuid=$(jq -r '.inbounds[0].users[0].uuid' "$conf_path")
            local flow=$(jq -r '.inbounds[0].users[0].flow // empty' "$conf_path")
            local reality=$(jq -r '.inbounds[0].tls.reality.enabled // false' "$conf_path")
            
            if [[ $reality == "true" ]]; then
                local sni=$(jq -r '.inbounds[0].tls.server_name' "$conf_path")
                local pbk=$(jq -r '.outbounds[1].tag // empty' "$conf_path" | sed 's/public_key_//')
                local sid=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "$conf_path")
                local fp="chrome"
                
                if [[ -z $pbk ]]; then
                    _red "错误: 未找到 PublicKey，请重新创建配置"
                elif [[ $flow ]]; then
                    echo "vless://${uuid}@${is_addr}:${port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=tcp#${remark}"
                else
                    echo "vless://${uuid}@${is_addr}:${port}?encryption=none&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=tcp#${remark}"
                fi
            else
                echo "vless://${uuid}@${is_addr}:${port}?encryption=none&type=tcp#${remark}"
            fi
            ;;
        shadowsocks)
            local method=$(jq -r '.inbounds[0].method' "$conf_path")
            local password=$(jq -r '.inbounds[0].password' "$conf_path")
            local encoded=$(echo -n "${method}:${password}" | base64 -w 0)
            echo "ss://${encoded}@${is_addr}:${port}#${remark}"
            ;;
        *)
            echo "暂不支持生成 $proto 的分享链接"
            ;;
    esac
}

# ==================== 服务管理 ====================
manage() {
    case $1 in
        start)
            systemctl start $is_core
            [[ $? -eq 0 ]] && _green "$is_core 已启动" || _red "启动失败"
            ;;
        stop)
            systemctl stop $is_core
            [[ $? -eq 0 ]] && _green "$is_core 已停止" || _red "停止失败"
            ;;
        restart)
            systemctl restart $is_core
            [[ $? -eq 0 ]] && _green "$is_core 已重启" || _red "重启失败"
            ;;
        status)
            echo
            echo "$is_core 状态: $is_core_status"
            [[ $is_core_ver ]] && echo "版本: $is_core_ver"
            echo
            ;;
    esac
}

# ==================== 主入口 ====================
main() {
    case $1 in
        # 配置管理
        a | add)
            add $2
            ;;
        c | change)
            change $2
            ;;
        d | del | rm)
            del $2
            ;;
        l | list | ls)
            list
            ;;
        i | info)
            info $2
            ;;
        # 服务管理
        start | stop | restart)
            manage $1
            ;;
        s | status)
            manage status
            ;;
        # 日志管理
        log)
            load log.sh
            show_log ${2:-50}
            ;;
        log-f | logf)
            load log.sh
            follow_log
            ;;
        log-clear)
            load log.sh
            clear_log
            ;;
        # DNS 管理
        dns)
            load dns.sh
            show_dns
            ;;
        set-dns)
            load dns.sh
            set_dns
            ;;
        # BBR 管理
        bbr)
            load bbr.sh
            check_bbr
            ;;
        set-bbr)
            load bbr.sh
            enable_bbr
            ;;
        # 更新管理
        update)
            load download.sh
            case $2 in
                sh | script)
                    update_sh
                    ;;
                *)
                    update_core
                    ;;
            esac
            ;;
        un | uninstall)
            load download.sh
            uninstall
            ;;
        # 其他
        v | version)
            echo
            echo "$is_core 版本: $(_green ${is_core_ver:-未安装})"
            echo "脚本版本: $(_green $is_sh_ver)"
            echo
            ;;
        h | help)
            show_help
            ;;
        "")
            show_menu
            ;;
        *)
            _yellow "未知命令: $1"
            echo "使用 '$is_core help' 查看帮助"
            ;;
    esac
}

# 显示帮助
show_help() {
    echo
    echo "Usage: $is_core <command>"
    echo
    echo "配置管理:"
    echo "  add [r|ss]  添加配置 (r=Reality, ss=Shadowsocks)"
    echo "  change      修改配置"
    echo "  del         删除配置"
    echo "  list        列出配置"
    echo "  info        查看配置详情"
    echo
    echo "服务管理:"
    echo "  start       启动服务"
    echo "  stop        停止服务"
    echo "  restart     重启服务"
    echo "  status      查看状态"
    echo
    echo "日志管理:"
    echo "  log [n]     查看最近 n 行日志"
    echo "  log-f       实时查看日志"
    echo "  log-clear   清空日志"
    echo
    echo "系统优化:"
    echo "  dns         查看 DNS"
    echo "  set-dns     设置 DNS"
    echo "  bbr         查看 BBR 状态"
    echo "  set-bbr     启用 BBR"
    echo
    echo "更新管理:"
    echo "  update      更新核心"
    echo "  update sh   更新脚本"
    echo "  uninstall   卸载"
    echo
    echo "其他:"
    echo "  version     查看版本"
    echo "  help        显示帮助"
    echo
}

# 暂停返回菜单
pause_return() {
    echo
    read -rp "按 Enter 返回主菜单..."
}

# 交互式菜单 (循环模式)
show_menu() {
    while true; do
        clear
        echo
        echo "============================================"
        echo "          sing-box 管理脚本"
        echo "============================================"
        echo
        echo "  状态: $is_core_status    版本: ${is_core_ver:-未安装}"
        echo "  地址: $is_addr"
        echo
        echo "--------------------------------------------"
        echo
        echo "  1. 添加配置       2. 修改配置"
        echo "  3. 删除配置       4. 查看配置"
        echo "  5. 配置列表"
        echo
        echo "  6. 启动服务       7. 停止服务       8. 重启服务"
        echo
        echo "  9. 查看日志      10. BBR 优化"
        echo " 11. 更新核心      12. 更新脚本"
        echo " 13. 卸载"
        echo
        echo "  0. 退出"
        echo
        echo "============================================"
        echo
        read -rp "请选择: " menu_pick
        
        case $menu_pick in
            1) add; pause_return ;;
            2) change; pause_return ;;
            3) del; pause_return ;;
            4) info; pause_return ;;
            5) list; pause_return ;;
            6) manage start; pause_return ;;
            7) manage stop; pause_return ;;
            8) manage restart; pause_return ;;
            9) load log.sh; show_log; pause_return ;;
            10) load bbr.sh; enable_bbr; pause_return ;;
            11) load download.sh; update_core; pause_return ;;
            12) load download.sh; update_sh; pause_return ;;
            13) load download.sh; uninstall; break ;;
            0) echo; echo "再见!"; echo; exit 0 ;;
            "") ;;
            *) _yellow "无效选择"; sleep 1 ;;
        esac
    done
}
