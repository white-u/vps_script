#!/bin/bash
# ============================================================================
# VPS Manager - sing-box 模块
# ============================================================================

[[ "${SINGBOX_LOADED:-}" == "true" ]] && return 0
SINGBOX_LOADED=true

# ============================================================================
# sing-box 配置
# ============================================================================
readonly SINGBOX_REPO="SagerNet/sing-box"
readonly SINGBOX_DIR="/etc/sing-box"
readonly SINGBOX_BIN="$SINGBOX_DIR/sing-box"
readonly SINGBOX_CONF="$SINGBOX_DIR/config.json"
readonly SINGBOX_CONF_DIR="$SINGBOX_DIR/conf"
readonly SINGBOX_LOG="$SINGBOX_DIR/sing-box.log"
readonly SINGBOX_SERVICE="/etc/systemd/system/sing-box.service"

# ============================================================================
# 状态检测
# ============================================================================
singbox_check_installed() {
    [[ -f "$SINGBOX_BIN" ]]
}

singbox_get_status() {
    if singbox_check_installed; then
        if systemctl is-active --quiet sing-box 2>/dev/null; then
            echo "running"
        else
            echo "stopped"
        fi
    else
        echo "not_installed"
    fi
}

singbox_get_version() {
    if [[ -f "$SINGBOX_BIN" ]]; then
        "$SINGBOX_BIN" version 2>/dev/null | head -n1 | awk '{print $3}' || echo ""
    else
        echo ""
    fi
}

singbox_get_latest_version() {
    curl -sfm10 "https://api.github.com/repos/$SINGBOX_REPO/releases/latest" 2>/dev/null | \
        grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/' || echo ""
}

singbox_get_conf_count() {
    find "$SINGBOX_CONF_DIR" -maxdepth 1 -name "*.json" 2>/dev/null | wc -l || echo "0"
}

# ============================================================================
# 安装
# ============================================================================
singbox_install() {
    if singbox_check_installed; then
        _yellow "sing-box 已安装"
        return 1
    fi
    
    log_info "获取最新版本..."
    local version
    version=$(singbox_get_latest_version)
    
    if [[ -z "$version" ]]; then
        log_error "无法获取最新版本"
        return 1
    fi
    
    log_info "开始安装 sing-box v$version..."
    
    ensure_deps wget tar jq curl openssl
    
    # 下载
    local url tmp_file tmp_dir
    url="https://github.com/$SINGBOX_REPO/releases/download/v${version}/sing-box-${version}-linux-${ARCH:-amd64}.tar.gz"
    tmp_file="/tmp/sing-box-$$.tar.gz"
    tmp_dir="/tmp/sing-box-$$"
    
    log_info "下载: $url"
    if ! download_file "$url" "$tmp_file"; then
        rm -f "$tmp_file"
        return 1
    fi
    
    # 解压安装
    mkdir -p "$tmp_dir" "$SINGBOX_DIR" "$SINGBOX_CONF_DIR"
    
    if ! tar -xzf "$tmp_file" -C "$tmp_dir" 2>/dev/null; then
        log_error "解压失败"
        rm -rf "$tmp_file" "$tmp_dir"
        return 1
    fi
    
    cp "$tmp_dir/sing-box-${version}-linux-${ARCH:-amd64}/sing-box" "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    rm -rf "$tmp_file" "$tmp_dir"
    
    # 创建默认配置
    cat > "$SINGBOX_CONF" <<'EOF'
{
    "log": {
        "level": "info",
        "timestamp": true
    },
    "dns": {},
    "outbounds": [
        {"type": "direct", "tag": "direct"}
    ]
}
EOF
    
    # 创建服务
    cat > "$SINGBOX_SERVICE" <<EOF
[Unit]
Description=sing-box Service
After=network.target

[Service]
Type=simple
ExecStart=$SINGBOX_BIN run -c $SINGBOX_CONF -C $SINGBOX_CONF_DIR
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sing-box &>/dev/null || true
    
    _green "sing-box v$version 安装完成!"
    echo
    echo "使用 'vps sb add' 添加配置"
    
    if [[ "$(config_get '.telegram.enabled' 'false')" == "true" ]]; then
        local server_name
        server_name=$(config_get '.telegram.server_name' "$(hostname)")
        telegram_send "✅ <b>sing-box 已安装</b>
服务器: $server_name
版本: v$version"
    fi
}

# ============================================================================
# 协议添加
# ============================================================================
singbox_add() {
    if ! singbox_check_installed; then
        _yellow "请先安装 sing-box"
        return 1
    fi
    
    local proto="${1:-}"
    
    if [[ -z "$proto" ]]; then
        echo
        echo "选择协议:"
        echo "  1. VLESS-Reality"
        echo "  2. Shadowsocks"
        echo "  0. 返回"
        echo
        read -rp "选择: " pick || pick=""
        
        case "$pick" in
            1) proto="reality" ;;
            2) proto="ss" ;;
            0|"") return 0 ;;
            *) _yellow "无效选择"; return 1 ;;
        esac
    fi
    
    case "${proto,,}" in
        r|reality|vless|vless-reality) singbox_add_reality ;;
        ss|shadowsocks) singbox_add_shadowsocks ;;
        *) _yellow "未知协议: $proto" ;;
    esac
}

singbox_add_reality() {
    echo
    _cyan ">>> 配置 VLESS-Reality"
    echo
    
    # 端口
    local default_port
    default_port=$(rand_port)
    read -rp "端口 [$default_port]: " port || port=""
    port="${port:-$default_port}"
    
    if ! is_valid_port "$port"; then
        _red "端口无效"
        return 1
    fi
    
    if is_port_used "$port"; then
        _red "端口 $port 已被占用"
        return 1
    fi
    
    # UUID
    local uuid
    uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(uuidgen 2>/dev/null || echo "00000000-0000-0000-0000-000000000000")")
    read -rp "UUID [$uuid]: " input_uuid || input_uuid=""
    uuid="${input_uuid:-$uuid}"
    
    # SNI
    read -rp "SNI [www.apple.com]: " sni || sni=""
    sni="${sni:-www.apple.com}"
    
    # 备注
    local default_remark
    default_remark=$(hostname)
    read -rp "备注 [$default_remark]: " remark || remark=""
    remark="${remark:-$default_remark}"
    
    # 生成密钥
    local keys private_key public_key short_id
    keys=$("$SINGBOX_BIN" generate reality-keypair 2>/dev/null)
    private_key=$(echo "$keys" | grep PrivateKey | awk '{print $2}')
    public_key=$(echo "$keys" | grep PublicKey | awk '{print $2}')
    short_id=$(openssl rand -hex 8 2>/dev/null || echo "0123456789abcdef")
    
    # 创建配置
    local conf_name="vless-reality-${port}"
    cat > "$SINGBOX_CONF_DIR/${conf_name}.json" <<EOF
{
    "inbounds": [{
        "type": "vless",
        "tag": "$conf_name",
        "listen": "::",
        "listen_port": $port,
        "users": [{"uuid": "$uuid", "flow": "xtls-rprx-vision"}],
        "tls": {
            "enabled": true,
            "server_name": "$sni",
            "reality": {
                "enabled": true,
                "handshake": {"server": "$sni", "server_port": 443},
                "private_key": "$private_key",
                "short_id": ["$short_id"]
            }
        }
    }],
    "outbounds": [
        {"type": "direct"},
        {"type": "direct", "tag": "pbk_$public_key"}
    ]
}
EOF
    
    # 验证配置
    if ! "$SINGBOX_BIN" check -c "$SINGBOX_CONF" -C "$SINGBOX_CONF_DIR" &>/dev/null; then
        log_error "配置验证失败"
        rm -f "$SINGBOX_CONF_DIR/${conf_name}.json"
        return 1
    fi
    
    # 防火墙
    firewall_allow "$port" tcp
    firewall_allow "$port" udp
    
    # 联动流量监控
    if [[ "$(config_get '.settings.auto_traffic_monitor' 'true')" == "true" ]]; then
        if declare -f traffic_add_port &>/dev/null; then
            traffic_add_port "$port" "Reality-$remark"
        fi
    fi
    
    systemctl restart sing-box &>/dev/null || systemctl start sing-box &>/dev/null || true
    
    echo
    _green "配置已添加: ${conf_name}.json"
    echo
    echo "=== 配置信息 ==="
    echo "协议: VLESS-Reality"
    echo "地址: ${SERVER_IP:-IP}"
    echo "端口: $port"
    echo "UUID: $uuid"
    echo "SNI: $sni"
    echo "PublicKey: $public_key"
    echo "ShortID: $short_id"
    echo
    echo "=== 分享链接 ==="
    echo "vless://${uuid}@${SERVER_IP:-IP}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp#${remark}"
    echo
}

singbox_add_shadowsocks() {
    echo
    _cyan ">>> 配置 Shadowsocks"
    echo
    
    # 端口
    local default_port
    default_port=$(rand_port)
    read -rp "端口 [$default_port]: " port || port=""
    port="${port:-$default_port}"
    
    if ! is_valid_port "$port"; then
        _red "端口无效"
        return 1
    fi
    
    if is_port_used "$port"; then
        _red "端口 $port 已被占用"
        return 1
    fi
    
    # 加密方式
    echo
    echo "加密方式:"
    echo "  1. 2022-blake3-aes-128-gcm (推荐)"
    echo "  2. 2022-blake3-aes-256-gcm"
    echo "  3. 2022-blake3-chacha20-poly1305"
    echo
    read -rp "选择 [1]: " method_pick || method_pick=""
    
    local method password
    case "${method_pick:-1}" in
        2) method="2022-blake3-aes-256-gcm"; password=$(openssl rand -base64 32 2>/dev/null || echo "defaultpassword32chars!!") ;;
        3) method="2022-blake3-chacha20-poly1305"; password=$(openssl rand -base64 32 2>/dev/null || echo "defaultpassword32chars!!") ;;
        *) method="2022-blake3-aes-128-gcm"; password=$(openssl rand -base64 16 2>/dev/null || echo "defaultpass16ch") ;;
    esac
    
    # 备注
    local default_remark
    default_remark=$(hostname)
    read -rp "备注 [$default_remark]: " remark || remark=""
    remark="${remark:-$default_remark}"
    
    # 创建配置
    local conf_name="shadowsocks-${port}"
    cat > "$SINGBOX_CONF_DIR/${conf_name}.json" <<EOF
{
    "inbounds": [{
        "type": "shadowsocks",
        "tag": "$conf_name",
        "listen": "::",
        "listen_port": $port,
        "method": "$method",
        "password": "$password"
    }]
}
EOF
    
    # 验证配置
    if ! "$SINGBOX_BIN" check -c "$SINGBOX_CONF" -C "$SINGBOX_CONF_DIR" &>/dev/null; then
        log_error "配置验证失败"
        rm -f "$SINGBOX_CONF_DIR/${conf_name}.json"
        return 1
    fi
    
    # 防火墙
    firewall_allow "$port" tcp
    firewall_allow "$port" udp
    
    # 联动流量监控
    if [[ "$(config_get '.settings.auto_traffic_monitor' 'true')" == "true" ]]; then
        if declare -f traffic_add_port &>/dev/null; then
            traffic_add_port "$port" "SS-$remark"
        fi
    fi
    
    systemctl restart sing-box &>/dev/null || systemctl start sing-box &>/dev/null || true
    
    echo
    _green "配置已添加: ${conf_name}.json"
    echo
    echo "=== 配置信息 ==="
    echo "协议: Shadowsocks"
    echo "地址: ${SERVER_IP:-IP}"
    echo "端口: $port"
    echo "加密: $method"
    echo "密码: $password"
    echo
    echo "=== 分享链接 ==="
    local encoded
    encoded=$(echo -n "${method}:${password}" | base64 -w 0 2>/dev/null || echo -n "${method}:${password}" | base64)
    echo "ss://${encoded}@${SERVER_IP:-IP}:${port}#${remark}"
    echo
}

# ============================================================================
# 配置列表
# ============================================================================
singbox_list() {
    if ! singbox_check_installed; then
        _yellow "sing-box 未安装"
        return 1
    fi
    
    local files
    mapfile -t files < <(find "$SINGBOX_CONF_DIR" -maxdepth 1 -name "*.json" -printf "%f\n" 2>/dev/null | sort)
    
    if [[ ${#files[@]} -eq 0 ]]; then
        echo
        _yellow "暂无配置"
        return 0
    fi
    
    echo
    printf "%-3s %-30s %-15s %-6s\n" "#" "名称" "协议" "端口"
    echo "------------------------------------------------------"
    
    local i=0
    for f in "${files[@]}"; do
        ((i++))
        local proto port
        proto=$(jq -r '.inbounds[0].type // "?"' "$SINGBOX_CONF_DIR/$f" 2>/dev/null)
        port=$(jq -r '.inbounds[0].listen_port // "?"' "$SINGBOX_CONF_DIR/$f" 2>/dev/null)
        printf "%-3s %-30s %-15s %-6s\n" "$i" "$f" "$proto" "$port"
    done
    echo
}

# ============================================================================
# 查看配置详情
# ============================================================================
singbox_select_conf() {
    local -a files
    mapfile -t files < <(find "$SINGBOX_CONF_DIR" -maxdepth 1 -name "*.json" -printf "%f\n" 2>/dev/null | sort)
    
    if [[ ${#files[@]} -eq 0 ]]; then
        _yellow "没有配置文件"
        return 1
    fi
    
    if [[ ${#files[@]} -eq 1 ]]; then
        SINGBOX_SELECTED_CONF="${files[0]}"
        return 0
    fi
    
    echo
    echo "选择配置:"
    echo
    local i=0
    for f in "${files[@]}"; do
        ((i++))
        local proto port
        proto=$(jq -r '.inbounds[0].type // "?"' "$SINGBOX_CONF_DIR/$f" 2>/dev/null)
        port=$(jq -r '.inbounds[0].listen_port // "?"' "$SINGBOX_CONF_DIR/$f" 2>/dev/null)
        printf "  %2d. %-30s [%s:%s]\n" "$i" "$f" "$proto" "$port"
    done
    echo
    echo "   0. 返回"
    echo
    read -rp "选择: " pick || pick=""
    
    [[ -z "$pick" || "$pick" == "0" ]] && return 1
    [[ ! "$pick" =~ ^[0-9]+$ ]] && return 1
    [[ $pick -lt 1 || $pick -gt ${#files[@]} ]] && return 1
    
    SINGBOX_SELECTED_CONF="${files[$((pick-1))]}"
    return 0
}

singbox_info() {
    if ! singbox_check_installed; then
        _yellow "sing-box 未安装"
        return 1
    fi
    
    singbox_select_conf || return 1
    
    local conf_path="$SINGBOX_CONF_DIR/$SINGBOX_SELECTED_CONF"
    local proto port
    proto=$(jq -r '.inbounds[0].type' "$conf_path" 2>/dev/null)
    port=$(jq -r '.inbounds[0].listen_port' "$conf_path" 2>/dev/null)
    
    echo
    echo "============================================"
    echo "             配置信息"
    echo "============================================"
    echo
    echo "配置文件: $SINGBOX_SELECTED_CONF"
    echo "协议类型: $proto"
    echo "监听端口: $port"
    echo "服务地址: ${SERVER_IP:-IP}"
    echo
    
    case "$proto" in
        vless)
            local uuid flow reality sni pbk sid
            uuid=$(jq -r '.inbounds[0].users[0].uuid' "$conf_path" 2>/dev/null)
            flow=$(jq -r '.inbounds[0].users[0].flow // empty' "$conf_path" 2>/dev/null)
            reality=$(jq -r '.inbounds[0].tls.reality.enabled // false' "$conf_path" 2>/dev/null)
            
            echo "UUID: $uuid"
            [[ -n "$flow" ]] && echo "Flow: $flow"
            
            if [[ "$reality" == "true" ]]; then
                sni=$(jq -r '.inbounds[0].tls.server_name' "$conf_path" 2>/dev/null)
                pbk=$(jq -r '.outbounds[1].tag // empty' "$conf_path" 2>/dev/null | sed 's/pbk_//')
                sid=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "$conf_path" 2>/dev/null)
                echo "SNI: $sni"
                [[ -n "$pbk" ]] && echo "PublicKey: $pbk"
                echo "ShortID: $sid"
                echo
                echo "=== 分享链接 ==="
                echo "vless://${uuid}@${SERVER_IP:-IP}:${port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#$(hostname)"
            fi
            ;;
        shadowsocks)
            local method password
            method=$(jq -r '.inbounds[0].method' "$conf_path" 2>/dev/null)
            password=$(jq -r '.inbounds[0].password' "$conf_path" 2>/dev/null)
            echo "加密方式: $method"
            echo "密码: $password"
            echo
            echo "=== 分享链接 ==="
            local encoded
            encoded=$(echo -n "${method}:${password}" | base64 -w 0 2>/dev/null || echo -n "${method}:${password}" | base64)
            echo "ss://${encoded}@${SERVER_IP:-IP}:${port}#$(hostname)"
            ;;
    esac
    echo
}

# ============================================================================
# 删除配置
# ============================================================================
singbox_del() {
    if ! singbox_check_installed; then
        _yellow "sing-box 未安装"
        return 1
    fi
    
    singbox_select_conf || return 1
    
    local conf_path="$SINGBOX_CONF_DIR/$SINGBOX_SELECTED_CONF"
    local port
    port=$(jq -r '.inbounds[0].listen_port' "$conf_path" 2>/dev/null)
    
    echo
    confirm "确认删除 $SINGBOX_SELECTED_CONF?" || return 0
    
    rm -f "$conf_path"
    
    if [[ -n "$port" && "$port" != "null" ]]; then
        firewall_remove "$port" tcp
        firewall_remove "$port" udp
        if declare -f traffic_remove_port &>/dev/null; then
            traffic_remove_port "$port"
        fi
    fi
    
    systemctl restart sing-box &>/dev/null || true
    
    _green "已删除: $SINGBOX_SELECTED_CONF"
}

# ============================================================================
# 更新
# ============================================================================
singbox_update() {
    if ! singbox_check_installed; then
        _yellow "sing-box 未安装"
        return 1
    fi
    
    log_info "检查更新..."
    
    local current latest
    current=$(singbox_get_version)
    latest=$(singbox_get_latest_version)
    
    [[ -z "$latest" ]] && { log_error "无法获取最新版本"; return 1; }
    
    echo "当前版本: ${current:-未知}"
    echo "最新版本: $latest"
    
    if [[ "$current" == "$latest" ]]; then
        _green "已是最新版本"
        return 0
    fi
    
    confirm "是否更新?" || return 0
    
    local url tmp_file tmp_dir
    url="https://github.com/$SINGBOX_REPO/releases/download/v${latest}/sing-box-${latest}-linux-${ARCH:-amd64}.tar.gz"
    tmp_file="/tmp/sing-box-$$.tar.gz"
    tmp_dir="/tmp/sing-box-$$"
    
    backup_binary "$SINGBOX_BIN" "sing-box"
    
    log_info "下载中..."
    if ! download_file "$url" "$tmp_file"; then
        rm -f "$tmp_file"
        return 1
    fi
    
    systemctl stop sing-box &>/dev/null || true
    
    mkdir -p "$tmp_dir"
    if ! tar -xzf "$tmp_file" -C "$tmp_dir" 2>/dev/null; then
        log_error "解压失败"
        rm -rf "$tmp_file" "$tmp_dir"
        restore_binary "$SINGBOX_BIN" "sing-box"
        systemctl start sing-box &>/dev/null || true
        return 1
    fi
    
    cp "$tmp_dir/sing-box-${latest}-linux-${ARCH:-amd64}/sing-box" "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    rm -rf "$tmp_file" "$tmp_dir"
    
    systemctl start sing-box &>/dev/null || true
    
    _green "更新完成: ${current:-?} -> $latest"
    
    if [[ "$(config_get '.telegram.enabled' 'false')" == "true" ]]; then
        local server_name
        server_name=$(config_get '.telegram.server_name' "$(hostname)")
        telegram_send "🔄 <b>sing-box 已更新</b>
服务器: $server_name
版本: ${current:-?} -> $latest"
    fi
}

# ============================================================================
# 卸载
# ============================================================================
singbox_uninstall() {
    if ! singbox_check_installed; then
        _yellow "sing-box 未安装"
        return 1
    fi
    
    confirm "确认卸载 sing-box?" || return 0
    
    # 收集端口
    local -a ports
    while IFS= read -r f; do
        local port
        port=$(jq -r '.inbounds[0].listen_port // empty' "$f" 2>/dev/null)
        [[ -n "$port" && "$port" != "null" ]] && ports+=("$port")
    done < <(find "$SINGBOX_CONF_DIR" -maxdepth 1 -name "*.json" 2>/dev/null)
    
    systemctl stop sing-box &>/dev/null || true
    systemctl disable sing-box &>/dev/null || true
    rm -f "$SINGBOX_SERVICE"
    rm -rf "$SINGBOX_DIR"
    systemctl daemon-reload
    
    # 清理
    for port in "${ports[@]}"; do
        firewall_remove "$port" tcp
        firewall_remove "$port" udp
        if declare -f traffic_remove_port &>/dev/null; then
            traffic_remove_port "$port"
        fi
    done
    
    _green "sing-box 已卸载"
}

# ============================================================================
# 服务管理
# ============================================================================
singbox_start() {
    systemctl start sing-box && _green "sing-box 已启动" || _red "启动失败"
}

singbox_stop() {
    systemctl stop sing-box && _green "sing-box 已停止" || _red "停止失败"
}

singbox_restart() {
    systemctl restart sing-box && _green "sing-box 已重启" || _red "重启失败"
}

singbox_logs() {
    if [[ -f "$SINGBOX_LOG" ]]; then
        tail -n 50 "$SINGBOX_LOG"
    else
        journalctl -u sing-box -n 50 --no-pager
    fi
}

# ============================================================================
# 菜单
# ============================================================================
singbox_menu() {
    while true; do
        local status version
        status=$(singbox_get_status)
        version=$(singbox_get_version)
        
        clear
        echo
        echo "============================================"
        echo "           sing-box 管理"
        echo "============================================"
        echo
        
        case "$status" in
            running)
                local conf_count
                conf_count=$(singbox_get_conf_count)
                echo "  状态: $(_green "运行中")"
                echo "  版本: ${version:-未知}"
                echo "  配置: $conf_count 个"
                ;;
            stopped)
                echo "  状态: $(_yellow "已停止")"
                echo "  版本: ${version:-未知}"
                ;;
            *)
                echo "  状态: $(_red "未安装")"
                ;;
        esac
        
        echo
        echo "--------------------------------------------"
        echo
        
        if [[ "$status" == "not_installed" ]]; then
            echo "  1. 安装 sing-box"
        else
            echo "  1. 添加配置"
            echo "  2. 配置列表"
            echo "  3. 查看详情"
            echo "  4. 删除配置"
            echo "  ---"
            echo "  5. 启动服务"
            echo "  6. 停止服务"
            echo "  7. 重启服务"
            echo "  8. 查看日志"
            echo "  ---"
            echo "  9. 更新 sing-box"
            echo "  10. 卸载 sing-box"
        fi
        
        echo
        echo "  0. 返回主菜单"
        echo
        echo "============================================"
        echo
        read -rp "请选择: " choice || choice=""
        
        if [[ "$status" == "not_installed" ]]; then
            case "$choice" in
                1) singbox_install; pause ;;
                0|"") return ;;
                *) _yellow "无效选择"; sleep 0.5 ;;
            esac
        else
            case "$choice" in
                1) singbox_add; pause ;;
                2) singbox_list; pause ;;
                3) singbox_info; pause ;;
                4) singbox_del; pause ;;
                5) singbox_start; sleep 1 ;;
                6) singbox_stop; sleep 1 ;;
                7) singbox_restart; sleep 1 ;;
                8) singbox_logs; pause ;;
                9) singbox_update; pause ;;
                10) singbox_uninstall; pause; singbox_check_installed || return ;;
                0|"") return ;;
                *) _yellow "无效选择"; sleep 0.5 ;;
            esac
        fi
    done
}
