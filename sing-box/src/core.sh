#!/bin/bash

# ==================== 获取配置文件 ====================
# 获取配置文件列表
get_conf_list() {
    conf_list=()
    while IFS= read -r -d '' file; do
        conf_list+=("$(basename "$file")")
    done < <(find "$is_conf_dir" -maxdepth 1 -name "*.json" -print0 2>/dev/null)
    [[ ${#conf_list[@]} -eq 0 ]] && err "没有找到配置文件"
}

# 选择配置文件
select_conf() {
    get_conf_list
    # 如果只有一个配置，直接使用
    if [[ ${#conf_list[@]} -eq 1 ]]; then
        is_conf_file=${conf_list[0]}
        echo "自动选择: $is_conf_file"
        return
    fi
    # 多个配置，让用户选择
    echo
    echo "请选择配置:"
    echo
    for i in "${!conf_list[@]}"; do
        echo "  $((i+1)). ${conf_list[$i]}"
    done
    echo
    read -p "请输入序号 [1-${#conf_list[@]}]: " pick
    [[ -z $pick ]] && err "未选择配置"
    [[ ! $pick =~ ^[0-9]+$ ]] && err "请输入数字"
    [[ $pick -lt 1 || $pick -gt ${#conf_list[@]} ]] && err "序号超出范围"
    is_conf_file=${conf_list[$((pick-1))]}
}

# ==================== 添加配置 ====================
# 协议列表
protocols=(
    "VLESS-Reality"
    "VLESS-HTTP2-Reality"
    "VMess-TCP"
    "VMess-WS"
    "VMess-HTTP"
    "VMess-QUIC"
    "Trojan"
    "Hysteria2"
    "TUIC"
    "Shadowsocks"
    "Socks"
    "Direct"
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

# 生成自签证书
gen_self_cert() {
    local cert_dir=$is_core_dir/cert
    is_cert_file=$cert_dir/cert.pem
    is_key_file=$cert_dir/key.pem
    
    # 如果证书已存在且有效，跳过生成
    if [[ -f $is_cert_file && -f $is_key_file ]]; then
        # 检查证书是否过期（30天内）
        if openssl x509 -checkend 2592000 -noout -in "$is_cert_file" 2>/dev/null; then
            return
        fi
    fi
    
    mkdir -p $cert_dir
    openssl ecparam -genkey -name prime256v1 -out $is_key_file 2>/dev/null
    openssl req -new -x509 -days 3650 -key $is_key_file -out $is_cert_file -subj "/CN=bing.com" 2>/dev/null
}

# 输入端口
input_port() {
    local default_port=$(rand_port)
    read -p "端口 [$default_port]: " is_port
    is_port=${is_port:-$default_port}
    [[ ! $is_port =~ ^[0-9]+$ ]] && err "端口必须是数字"
    [[ $is_port -lt 1 || $is_port -gt 65535 ]] && err "端口范围: 1-65535"
    # 精确匹配端口
    [[ $(ss -tuln | awk '{print $5}' | grep -E ":${is_port}$") ]] && err "端口 $is_port 已被占用"
}

# 输入 UUID
input_uuid() {
    local default_uuid=$(rand_uuid)
    read -p "UUID [$default_uuid]: " is_uuid
    is_uuid=${is_uuid:-$default_uuid}
}

# 输入密码
input_pass() {
    local default_pass=$(rand_pass)
    read -p "密码 [$default_pass]: " is_pass
    is_pass=${is_pass:-$default_pass}
}

# 输入 SNI
input_sni() {
    read -p "SNI [www.apple.com]: " is_sni
    is_sni=${is_sni:-www.apple.com}
}

# 添加配置主函数
add() {
    # 如果传入参数，按名称匹配协议
    if [[ $1 ]]; then
        local found=0
        for i in "${!protocols[@]}"; do
            if [[ ${protocols[$i],,} =~ ${1,,} ]]; then
                is_protocol=${protocols[$i]}
                found=1
                break
            fi
        done
        [[ $found -eq 0 ]] && err "未找到匹配的协议: $1"
    else
        # 显示协议菜单
        echo
        echo "请选择协议:"
        echo
        for i in "${!protocols[@]}"; do
            printf "  %2d. %s\n" $((i+1)) "${protocols[$i]}"
        done
        echo
        read -p "请输入序号 [1-${#protocols[@]}]: " pick
        [[ -z $pick ]] && err "未选择协议"
        [[ ! $pick =~ ^[0-9]+$ ]] && err "请输入数字"
        [[ $pick -lt 1 || $pick -gt ${#protocols[@]} ]] && err "序号超出范围"
        is_protocol=${protocols[$((pick-1))]}
    fi
    
    echo
    _green "配置 $is_protocol"
    echo
    
    # 输入通用参数
    input_port
    
    # 根据协议类型调用对应函数
    case $is_protocol in
        VLESS-Reality)
            add_vless_reality tcp
            ;;
        VLESS-HTTP2-Reality)
            add_vless_reality h2
            ;;
        VMess-TCP)
            add_vmess tcp
            ;;
        VMess-WS)
            add_vmess ws
            ;;
        VMess-HTTP)
            add_vmess http
            ;;
        VMess-QUIC)
            add_vmess quic
            ;;
        Trojan)
            add_trojan
            ;;
        Hysteria2)
            add_hysteria2
            ;;
        TUIC)
            add_tuic
            ;;
        Shadowsocks)
            add_shadowsocks
            ;;
        Socks)
            add_socks
            ;;
        Direct)
            add_direct
            ;;
    esac
    
    # 保存配置
    save_conf
    
    # 重启服务
    systemctl restart $is_core &>/dev/null
    
    # 显示配置信息
    is_conf_file=$is_conf_name.json
    info
}

# ==================== 协议配置函数 ====================
# VLESS Reality
add_vless_reality() {
    local transport=$1
    input_uuid
    input_sni
    gen_reality_keys
    is_short_id=$(gen_short_id)
    is_conf_name="vless-reality-${transport}-${is_port}"
    
    if [[ $transport == "tcp" ]]; then
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
        {"type": "direct", "tag": "direct"},
        {"type": "direct", "tag": "public_key_$is_public_key"}
    ]
}
EOF
)
    else
        is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "vless",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "users": [{
            "uuid": "$is_uuid"
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
        },
        "transport": {
            "type": "http"
        }
    }],
    "outbounds": [
        {"type": "direct", "tag": "direct"},
        {"type": "direct", "tag": "public_key_$is_public_key"}
    ]
}
EOF
)
    fi
}

# VMess
add_vmess() {
    local transport=$1
    input_uuid
    is_conf_name="vmess-${transport}-${is_port}"
    
    local transport_conf=""
    case $transport in
        ws)
            read -p "WebSocket 路径 [/ws]: " is_ws_path
            is_ws_path=${is_ws_path:-/ws}
            transport_conf='"transport": {"type": "ws", "path": "'$is_ws_path'"}'
            ;;
        http)
            transport_conf='"transport": {"type": "http"}'
            ;;
        quic)
            gen_self_cert
            transport_conf='"transport": {"type": "quic"}, "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "'$is_cert_file'", "key_path": "'$is_key_file'"}'
            ;;
    esac
    
    if [[ $transport_conf ]]; then
        is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "vmess",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "users": [{
            "uuid": "$is_uuid",
            "alterId": 0
        }],
        $transport_conf
    }]
}
EOF
)
    else
        is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "vmess",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "users": [{
            "uuid": "$is_uuid",
            "alterId": 0
        }]
    }]
}
EOF
)
    fi
}

# Trojan
add_trojan() {
    input_pass
    gen_self_cert
    is_conf_name="trojan-${is_port}"
    
    is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "trojan",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "users": [{
            "password": "$is_pass"
        }],
        "tls": {
            "enabled": true,
            "certificate_path": "$is_cert_file",
            "key_path": "$is_key_file"
        }
    }]
}
EOF
)
}

# Hysteria2
add_hysteria2() {
    input_pass
    gen_self_cert
    is_conf_name="hysteria2-${is_port}"
    
    is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "hysteria2",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "users": [{
            "password": "$is_pass"
        }],
        "tls": {
            "enabled": true,
            "alpn": ["h3"],
            "certificate_path": "$is_cert_file",
            "key_path": "$is_key_file"
        }
    }]
}
EOF
)
}

# TUIC
add_tuic() {
    input_uuid
    input_pass
    gen_self_cert
    is_conf_name="tuic-${is_port}"
    
    is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "tuic",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "users": [{
            "uuid": "$is_uuid",
            "password": "$is_pass"
        }],
        "congestion_control": "bbr",
        "tls": {
            "enabled": true,
            "alpn": ["h3"],
            "certificate_path": "$is_cert_file",
            "key_path": "$is_key_file"
        }
    }]
}
EOF
)
}

# Shadowsocks
add_shadowsocks() {
    echo "加密方式:"
    echo "  1. 2022-blake3-aes-128-gcm"
    echo "  2. 2022-blake3-aes-256-gcm"
    echo "  3. 2022-blake3-chacha20-poly1305"
    read -p "选择 [1]: " method_pick
    case ${method_pick:-1} in
        1) is_method="2022-blake3-aes-128-gcm"; is_ss_pass=$(openssl rand -base64 16) ;;
        2) is_method="2022-blake3-aes-256-gcm"; is_ss_pass=$(openssl rand -base64 32) ;;
        3) is_method="2022-blake3-chacha20-poly1305"; is_ss_pass=$(openssl rand -base64 32) ;;
        *) err "无效选择" ;;
    esac
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

# Socks
add_socks() {
    read -p "用户名 (留空无认证): " is_user
    if [[ $is_user ]]; then
        input_pass
        is_conf_name="socks-${is_port}"
        is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "socks",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "users": [{
            "username": "$is_user",
            "password": "$is_pass"
        }]
    }]
}
EOF
)
    else
        is_conf_name="socks-${is_port}"
        is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "socks",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port
    }]
}
EOF
)
    fi
}

# Direct
add_direct() {
    read -p "覆盖目标地址 (可选): " is_override_addr
    read -p "覆盖目标端口 (可选): " is_override_port
    is_conf_name="direct-${is_port}"
    
    local override=""
    [[ $is_override_addr ]] && override="\"override_address\": \"$is_override_addr\","
    [[ $is_override_port ]] && override="$override \"override_port\": $is_override_port,"
    
    if [[ $override ]]; then
        is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "direct",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        $override
        "sniff": true
    }]
}
EOF
)
    else
        is_conf=$(cat <<EOF
{
    "inbounds": [{
        "type": "direct",
        "tag": "$is_conf_name",
        "listen": "::",
        "listen_port": $is_port,
        "sniff": true
    }]
}
EOF
)
    fi
}

# 保存配置
save_conf() {
    local tmp_file="$is_conf_dir/$is_conf_name.json"
    echo "$is_conf" | jq . > "$tmp_file" 2>/dev/null
    [[ $? -ne 0 ]] && err "配置保存失败，JSON 格式错误"
    
    # 验证配置
    if ! $is_core_bin check -c "$is_config_json" -C "$is_conf_dir" &>/dev/null; then
        rm -f "$tmp_file"
        err "配置验证失败，请检查参数"
    fi
    
    _green "配置已保存: $is_conf_name.json"
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
    printf "%-3s %-28s %-10s %-6s\n" "#" "名称" "协议" "端口"
    echo "------------------------------------------------"
    
    for i in "${!files[@]}"; do
        local f=${files[$i]}
        local proto=$(jq -r '.inbounds[0].type' "$is_conf_dir/$f")
        local port=$(jq -r '.inbounds[0].listen_port' "$is_conf_dir/$f")
        printf "%-3s %-28s %-10s %-6s\n" "$((i+1))" "$f" "$proto" "$port"
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
        [[ -z $is_conf_file ]] && err "未找到匹配的配置: $1"
    else
        select_conf
    fi
    
    local conf_path="$is_conf_dir/$is_conf_file"
    local proto=$(jq -r '.inbounds[0].type' "$conf_path")
    
    echo
    echo "修改 $is_conf_file ($proto)"
    echo
    echo "可修改项:"
    echo "  1. 端口"
    echo "  2. 主要凭证 (UUID/密码)"
    echo "  0. 取消"
    echo
    read -p "请选择: " change_pick
    
    case $change_pick in
        1) change_port "$conf_path" ;;
        2) change_cred "$conf_path" "$proto" ;;
        0) echo "已取消" ;;
        *) err "无效选择" ;;
    esac
}

# 修改端口
change_port() {
    local conf_path=$1
    local old_port=$(jq -r '.inbounds[0].listen_port' "$conf_path")
    
    echo "当前端口: $old_port"
    read -p "新端口: " new_port
    
    [[ -z $new_port ]] && { echo "已取消"; return; }
    [[ ! $new_port =~ ^[0-9]+$ ]] && err "端口必须是数字"
    [[ $new_port -lt 1 || $new_port -gt 65535 ]] && err "端口范围: 1-65535"
    [[ $(ss -tuln | awk '{print $5}' | grep -E ":${new_port}$") ]] && err "端口 $new_port 已被占用"
    
    # 修改并验证
    jq ".inbounds[0].listen_port = $new_port" "$conf_path" > "${conf_path}.tmp"
    if $is_core_bin check -c "$is_config_json" -C "$is_conf_dir" &>/dev/null; then
        mv "${conf_path}.tmp" "$conf_path"
        _green "端口已修改: $old_port -> $new_port"
        systemctl restart $is_core &>/dev/null
    else
        rm -f "${conf_path}.tmp"
        err "配置验证失败"
    fi
}

# 修改凭证
change_cred() {
    local conf_path=$1
    local proto=$2
    
    case $proto in
        vless | vmess)
            local old_uuid=$(jq -r '.inbounds[0].users[0].uuid' "$conf_path")
            echo "当前 UUID: $old_uuid"
            local default_uuid=$(rand_uuid)
            read -p "新 UUID [$default_uuid]: " new_uuid
            new_uuid=${new_uuid:-$default_uuid}
            jq ".inbounds[0].users[0].uuid = \"$new_uuid\"" "$conf_path" > "${conf_path}.tmp" && mv "${conf_path}.tmp" "$conf_path"
            _green "UUID 已修改"
            ;;
        trojan | hysteria2)
            local old_pass=$(jq -r '.inbounds[0].users[0].password' "$conf_path")
            echo "当前密码: $old_pass"
            local default_pass=$(rand_pass)
            read -p "新密码 [$default_pass]: " new_pass
            new_pass=${new_pass:-$default_pass}
            jq ".inbounds[0].users[0].password = \"$new_pass\"" "$conf_path" > "${conf_path}.tmp" && mv "${conf_path}.tmp" "$conf_path"
            _green "密码已修改"
            ;;
        tuic)
            echo "  1. 修改 UUID"
            echo "  2. 修改密码"
            read -p "请选择: " tuic_pick
            case $tuic_pick in
                1)
                    local old_uuid=$(jq -r '.inbounds[0].users[0].uuid' "$conf_path")
                    echo "当前 UUID: $old_uuid"
                    local default_uuid=$(rand_uuid)
                    read -p "新 UUID [$default_uuid]: " new_uuid
                    new_uuid=${new_uuid:-$default_uuid}
                    jq ".inbounds[0].users[0].uuid = \"$new_uuid\"" "$conf_path" > "${conf_path}.tmp" && mv "${conf_path}.tmp" "$conf_path"
                    _green "UUID 已修改"
                    ;;
                2)
                    local old_pass=$(jq -r '.inbounds[0].users[0].password' "$conf_path")
                    echo "当前密码: $old_pass"
                    local default_pass=$(rand_pass)
                    read -p "新密码 [$default_pass]: " new_pass
                    new_pass=${new_pass:-$default_pass}
                    jq ".inbounds[0].users[0].password = \"$new_pass\"" "$conf_path" > "${conf_path}.tmp" && mv "${conf_path}.tmp" "$conf_path"
                    _green "密码已修改"
                    ;;
            esac
            ;;
        shadowsocks)
            local old_pass=$(jq -r '.inbounds[0].password' "$conf_path")
            local method=$(jq -r '.inbounds[0].method' "$conf_path")
            echo "当前密码: $old_pass"
            echo "加密方式: $method"
            local key_len=16
            [[ $method =~ "256" || $method =~ "chacha20" ]] && key_len=32
            local default_pass=$(openssl rand -base64 $key_len)
            read -p "新密码 [$default_pass]: " new_pass
            new_pass=${new_pass:-$default_pass}
            jq ".inbounds[0].password = \"$new_pass\"" "$conf_path" > "${conf_path}.tmp" && mv "${conf_path}.tmp" "$conf_path"
            _green "密码已修改"
            ;;
        socks)
            local has_user=$(jq -r '.inbounds[0].users[0].username // empty' "$conf_path")
            if [[ $has_user ]]; then
                echo "  1. 修改用户名"
                echo "  2. 修改密码"
                read -p "请选择: " socks_pick
                case $socks_pick in
                    1)
                        local old_user=$(jq -r '.inbounds[0].users[0].username' "$conf_path")
                        echo "当前用户名: $old_user"
                        read -p "新用户名: " new_user
                        [[ -z $new_user ]] && { echo "已取消"; return; }
                        jq ".inbounds[0].users[0].username = \"$new_user\"" "$conf_path" > "${conf_path}.tmp" && mv "${conf_path}.tmp" "$conf_path"
                        _green "用户名已修改"
                        ;;
                    2)
                        local old_pass=$(jq -r '.inbounds[0].users[0].password' "$conf_path")
                        echo "当前密码: $old_pass"
                        local default_pass=$(rand_pass)
                        read -p "新密码 [$default_pass]: " new_pass
                        new_pass=${new_pass:-$default_pass}
                        jq ".inbounds[0].users[0].password = \"$new_pass\"" "$conf_path" > "${conf_path}.tmp" && mv "${conf_path}.tmp" "$conf_path"
                        _green "密码已修改"
                        ;;
                esac
            else
                _yellow "此 Socks 配置无认证信息"
            fi
            ;;
        *)
            _yellow "此协议暂不支持修改凭证"
            ;;
    esac
    
    systemctl restart $is_core &>/dev/null
}

# ==================== 删除配置 ====================
del() {
    # 如果传入参数，按名称匹配
    if [[ $1 ]]; then
        get_conf_list
        for f in "${conf_list[@]}"; do
            [[ $f =~ $1 ]] && is_conf_file=$f && break
        done
        [[ -z $is_conf_file ]] && err "未找到匹配的配置: $1"
    else
        select_conf
    fi
    
    # 确认删除
    echo
    read -p "确认删除 $is_conf_file? [y/N]: " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && { echo "已取消"; return; }
    
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
        [[ -z $is_conf_file ]] && err "未找到匹配的配置: $1"
    else
        select_conf
    fi
    
    local conf_path="$is_conf_dir/$is_conf_file"
    
    # 解析配置
    local proto=$(jq -r '.inbounds[0].type' "$conf_path")
    local port=$(jq -r '.inbounds[0].listen_port // .inbounds[0].listen' "$conf_path")
    local tag=$(jq -r '.inbounds[0].tag' "$conf_path")
    
    echo
    echo "--- 配置: $is_conf_file ---"
    echo "协议: $proto | 端口: $port"
    [[ $tag != "null" ]] && echo "标签: $tag"
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
                # 从 outbounds tag 中提取 public_key
                local pbk=$(jq -r '.outbounds[1].tag // empty' "$conf_path" | sed 's/public_key_//')
                local sid=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "$conf_path")
                echo "SNI: $sni"
                [[ $pbk ]] && echo "PublicKey: $pbk"
                echo "ShortID: $sid"
            fi
            ;;
        vmess)
            local uuid=$(jq -r '.inbounds[0].users[0].uuid' "$conf_path")
            local transport=$(jq -r '.inbounds[0].transport.type // "tcp"' "$conf_path")
            local tls_enabled=$(jq -r '.inbounds[0].tls.enabled // false' "$conf_path")
            echo "UUID: $uuid"
            echo "传输: $transport"
            [[ $tls_enabled == "true" ]] && echo "TLS: 已启用"
            if [[ $transport == "ws" ]]; then
                local path=$(jq -r '.inbounds[0].transport.path // "/"' "$conf_path")
                echo "Path: $path"
            fi
            ;;
        trojan)
            local password=$(jq -r '.inbounds[0].users[0].password' "$conf_path")
            echo "密码: $password"
            ;;
        shadowsocks)
            local method=$(jq -r '.inbounds[0].method' "$conf_path")
            local password=$(jq -r '.inbounds[0].password' "$conf_path")
            echo "加密: $method"
            echo "密码: $password"
            ;;
        hysteria2)
            local password=$(jq -r '.inbounds[0].users[0].password' "$conf_path")
            echo "密码: $password"
            ;;
        tuic)
            local uuid=$(jq -r '.inbounds[0].users[0].uuid' "$conf_path")
            local password=$(jq -r '.inbounds[0].users[0].password' "$conf_path")
            echo "UUID: $uuid"
            echo "密码: $password"
            ;;
        socks)
            local user=$(jq -r '.inbounds[0].users[0].username // empty' "$conf_path")
            local pass=$(jq -r '.inbounds[0].users[0].password // empty' "$conf_path")
            if [[ $user ]]; then
                echo "用户名: $user"
                echo "密码: $pass"
            else
                echo "认证: 无"
            fi
            ;;
        direct)
            local override_addr=$(jq -r '.inbounds[0].override_address // empty' "$conf_path")
            local override_port=$(jq -r '.inbounds[0].override_port // empty' "$conf_path")
            [[ $override_addr ]] && echo "覆盖地址: $override_addr"
            [[ $override_port ]] && echo "覆盖端口: $override_port"
            [[ -z $override_addr && -z $override_port ]] && echo "无覆盖设置"
            ;;
    esac
    
    echo
    echo "服务器: $is_addr"
    echo
    echo "--- 分享链接 ---"
    echo
    gen_link
    echo
}

# 生成分享链接
gen_link() {
    local conf_path="$is_conf_dir/$is_conf_file"
    local proto=$(jq -r '.inbounds[0].type' "$conf_path")
    local port=$(jq -r '.inbounds[0].listen_port' "$conf_path")
    
    case $proto in
        vless)
            local uuid=$(jq -r '.inbounds[0].users[0].uuid' "$conf_path")
            local flow=$(jq -r '.inbounds[0].users[0].flow // empty' "$conf_path")
            local reality=$(jq -r '.inbounds[0].tls.reality.enabled // false' "$conf_path")
            local transport=$(jq -r '.inbounds[0].transport.type // "tcp"' "$conf_path")
            
            if [[ $reality == "true" ]]; then
                local sni=$(jq -r '.inbounds[0].tls.server_name' "$conf_path")
                # 从 outbounds tag 中提取 public_key
                local pbk=$(jq -r '.outbounds[1].tag // empty' "$conf_path" | sed 's/public_key_//')
                local sid=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "$conf_path")
                # fingerprint 固定为 chrome
                local fp="chrome"
                # 检测传输类型
                local type_param="tcp"
                [[ $transport == "http" ]] && type_param="h2"
                
                if [[ -z $pbk ]]; then
                    echo "错误: 未找到 PublicKey，请重新创建配置"
                elif [[ $flow ]]; then
                    echo "vless://${uuid}@${is_addr}:${port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=${type_param}#VLESS-Reality"
                else
                    echo "vless://${uuid}@${is_addr}:${port}?encryption=none&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=${type_param}#VLESS-Reality-H2"
                fi
            else
                echo "vless://${uuid}@${is_addr}:${port}?encryption=none&type=tcp#VLESS"
            fi
            ;;
        vmess)
            local uuid=$(jq -r '.inbounds[0].users[0].uuid' "$conf_path")
            local transport=$(jq -r '.inbounds[0].transport.type // "tcp"' "$conf_path")
            local tls_enabled=$(jq -r '.inbounds[0].tls.enabled // false' "$conf_path")
            local tls_val=""
            [[ $tls_enabled == "true" ]] && tls_val="tls"
            # http transport 在 vmess 中也叫 h2
            [[ $transport == "http" ]] && transport="h2"
            local json="{\"v\":\"2\",\"ps\":\"VMess\",\"add\":\"$is_addr\",\"port\":\"$port\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"$transport\",\"type\":\"none\",\"tls\":\"$tls_val\"}"
            echo "vmess://$(echo -n "$json" | base64 -w 0)"
            ;;
        trojan)
            local password=$(jq -r '.inbounds[0].users[0].password' "$conf_path")
            echo "trojan://${password}@${is_addr}:${port}?security=tls&allowInsecure=1#Trojan"
            ;;
        shadowsocks)
            local method=$(jq -r '.inbounds[0].method' "$conf_path")
            local password=$(jq -r '.inbounds[0].password' "$conf_path")
            local encoded=$(echo -n "${method}:${password}" | base64 -w 0)
            echo "ss://${encoded}@${is_addr}:${port}#Shadowsocks"
            ;;
        hysteria2)
            local password=$(jq -r '.inbounds[0].users[0].password' "$conf_path")
            echo "hysteria2://${password}@${is_addr}:${port}?insecure=1#Hysteria2"
            ;;
        tuic)
            local uuid=$(jq -r '.inbounds[0].users[0].uuid' "$conf_path")
            local password=$(jq -r '.inbounds[0].users[0].password' "$conf_path")
            echo "tuic://${uuid}:${password}@${is_addr}:${port}?alpn=h3&allow_insecure=1#TUIC"
            ;;
        socks)
            local user=$(jq -r '.inbounds[0].users[0].username // empty' "$conf_path")
            local pass=$(jq -r '.inbounds[0].users[0].password // empty' "$conf_path")
            if [[ $user && $pass ]]; then
                echo "socks://$(echo -n "${user}:${pass}" | base64 -w 0)@${is_addr}:${port}#Socks"
            else
                echo "socks://${is_addr}:${port}#Socks"
            fi
            ;;
        direct)
            local override_addr=$(jq -r '.inbounds[0].override_address // empty' "$conf_path")
            local override_port=$(jq -r '.inbounds[0].override_port // empty' "$conf_path")
            echo "Direct 协议无标准分享链接格式"
            [[ $override_addr ]] && echo "  覆盖地址: $override_addr"
            [[ $override_port ]] && echo "  覆盖端口: $override_port"
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
            [[ $? -eq 0 ]] && _green "$is_core 已启动" || err "启动失败"
            ;;
        stop)
            systemctl stop $is_core
            [[ $? -eq 0 ]] && _green "$is_core 已停止" || err "停止失败"
            ;;
        restart)
            systemctl restart $is_core
            [[ $? -eq 0 ]] && _green "$is_core 已重启" || err "重启失败"
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
            err "未知命令: $1，使用 '$is_core help' 查看帮助"
            ;;
    esac
}

# 显示帮助
show_help() {
    echo
    echo "Usage: $is_core <command>"
    echo
    echo "配置管理:"
    echo "  add         添加配置"
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

# 交互式菜单
show_menu() {
    clear
    echo
    echo "=== Sing-Box 管理 ==="
    echo
    echo "状态: $is_core_status  版本: ${is_core_ver:-未安装}"
    [[ $is_addr ]] && echo "地址: $is_addr"
    echo
    echo " 1. 添加    2. 修改    3. 删除"
    echo " 4. 查看    5. 列表"
    echo " 6. 启动    7. 停止    8. 重启"
    echo " 9. 日志   10. 更新   11. 卸载"
    echo " 0. 退出"
    echo
    read -p "选择: " menu_pick
    
    case $menu_pick in
        1) add ;;
        2) change ;;
        3) del ;;
        4) info ;;
        5) list ;;
        6) manage start ;;
        7) manage stop ;;
        8) manage restart ;;
        9) load log.sh; show_log ;;
        10) load download.sh; update_core ;;
        11) load download.sh; uninstall ;;
        0) exit 0 ;;
        *) err "无效选择" ;;
    esac
}
