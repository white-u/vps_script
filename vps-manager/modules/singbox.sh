#!/bin/bash
# ============================================================================
# VPS Manager - sing-box 模块 (完整版)
# ============================================================================

# 防止重复加载
[[ "${XXX_LOADED:-}" == "true" ]] && return 0
XXX_LOADED=true

# ============================================================================
# sing-box 配置
# ============================================================================
readonly SINGBOX_REPO="SagerNet/sing-box"
readonly SINGBOX_DIR="/etc/sing-box"
readonly SINGBOX_BIN="$SINGBOX_DIR/sing-box"
readonly SINGBOX_CONF="$SINGBOX_DIR/config.json"
readonly SINGBOX_CONF_DIR="$SINGBOX_DIR/conf"
readonly SINGBOX_LOG_DIR="/var/log/sing-box"
readonly SINGBOX_SERVICE="/etc/systemd/system/sing-box.service"
readonly SINGBOX_VERSION_CACHE_TTL=3600

# ============================================================================
# 版本检测
# ============================================================================
singbox_detect_version() {
    local silent="${1:-}"
    local cached_ver cached_time current_time
    
    # 检查缓存
    cached_ver=$(config_get '.version_cache.singbox.version')
    cached_time=$(config_get '.version_cache.singbox.updated')
    current_time=$(date +%s)
    
    if [[ -n "$cached_ver" && -n "$cached_time" ]]; then
        local age=$((current_time - cached_time))
        if [[ $age -lt $SINGBOX_VERSION_CACHE_TTL ]]; then
            SINGBOX_VERSION="$cached_ver"
            [[ -z "$silent" ]] && log_debug "使用缓存版本: $SINGBOX_VERSION"
            return 0
        fi
    fi
    
    [[ -z "$silent" ]] && log_info "检测最新版本..."
    
    # 从 GitHub API 获取
    local version
    version=$(curl -sfm15 "https://api.github.com/repos/$SINGBOX_REPO/releases/latest" 2>/dev/null | \
              grep '"tag_name"' | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    
    if [[ -z "$version" ]]; then
        # 备用：直接访问 releases 页面
        version=$(curl -sfm15 "https://github.com/$SINGBOX_REPO/releases/latest" 2>/dev/null | \
                  grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi
    
    if [[ -z "$version" ]]; then
        version="v1.10.0"  # 回退版本
        [[ -z "$silent" ]] && log_warn "无法检测版本，使用默认: $version"
    fi
    
    SINGBOX_VERSION="${version#v}"
    
    # 更新缓存
    config_set ".version_cache.singbox.version = \"$SINGBOX_VERSION\" | .version_cache.singbox.updated = $current_time" &>/dev/null
    
    return 0
}

singbox_get_download_url() {
    local version="${1:-$SINGBOX_VERSION}"
    local arch
    
    case $ARCH in
        amd64) arch="amd64" ;;
        arm64) arch="arm64" ;;
        armv7) arch="armv7" ;;
        386)   arch="386" ;;
        *)     arch="amd64" ;;
    esac
    
    echo "https://github.com/$SINGBOX_REPO/releases/download/v${version}/sing-box-${version}-linux-${arch}.tar.gz"
}

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
    [[ -f "$SINGBOX_BIN" ]] && $SINGBOX_BIN version 2>/dev/null | head -n1 | awk '{print $3}'
}

# ============================================================================
# 安装
# ============================================================================
singbox_install() {
    if singbox_check_installed; then
        _yellow "sing-box 已安装，版本: $(singbox_get_version)"
        return 1
    fi
    
    singbox_detect_version || { log_error "无法确定安装版本"; return 1; }
    
    log_info "开始安装 sing-box v$SINGBOX_VERSION..."
    
    ensure_deps wget tar jq curl openssl
    
    # 下载
    local url=$(singbox_get_download_url)
    local tmp_file="/tmp/sing-box-$$.tar.gz"
    local tmp_dir="/tmp/sing-box-extract-$$"
    
    log_info "下载: $url"
    if ! download_file "$url" "$tmp_file"; then
        rm -f "$tmp_file"
        return 1
    fi
    
    # 解压
    mkdir -p "$tmp_dir"
    if ! tar -xzf "$tmp_file" -C "$tmp_dir" 2>/dev/null; then
        _red "解压失败"
        rm -rf "$tmp_file" "$tmp_dir"
        return 1
    fi
    
    # 安装二进制
    mkdir -p "$SINGBOX_DIR" "$SINGBOX_CONF_DIR" "$SINGBOX_LOG_DIR"
    local bin_path=$(find "$tmp_dir" -name "sing-box" -type f | head -1)
    
    if [[ -z "$bin_path" ]]; then
        _red "未找到 sing-box 二进制文件"
        rm -rf "$tmp_file" "$tmp_dir"
        return 1
    fi
    
    cp "$bin_path" "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    rm -rf "$tmp_file" "$tmp_dir"
    
    # 创建默认配置
    cat > "$SINGBOX_CONF" <<EOF
{
  "log": {
    "level": "info",
    "output": "$SINGBOX_LOG_DIR/sing-box.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {"tag": "google", "address": "8.8.8.8"},
      {"tag": "local", "address": "223.5.5.5", "detour": "direct"}
    ]
  },
  "inbounds": [],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ]
}
EOF
    
    # 创建服务
    cat > "$SINGBOX_SERVICE" <<EOF
[Unit]
Description=sing-box Service
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=$SINGBOX_BIN run -c $SINGBOX_CONF -C $SINGBOX_CONF_DIR
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sing-box &>/dev/null
    systemctl start sing-box
    
    sleep 2
    
    if ! systemctl is-active --quiet sing-box; then
        log_warn "服务启动失败（可能是配置为空），但安装已完成"
    fi
    
    # 网络优化
    if [[ $(config_get '.settings.auto_network_optimize' 'true') == "true" ]]; then
        enable_bbr &>/dev/null
    fi
    
    # Telegram 通知
    if [[ $(config_get '.telegram.enabled' 'false') == "true" ]]; then
        local server_name=$(config_get '.telegram.server_name' "$(hostname)")
        telegram_send "✅ <b>sing-box 已安装</b>
服务器: $server_name
版本: v$SINGBOX_VERSION"
    fi
    
    echo
    _green "sing-box v$SINGBOX_VERSION 安装完成!"
    echo "使用 'vps sb' 进入管理菜单添加配置"
    echo
}

# ============================================================================
# 更新
# ============================================================================
singbox_update() {
    if ! singbox_check_installed; then
        _yellow "sing-box 未安装"
        return 1
    fi
    
    local installed_ver=$(singbox_get_version)
    
    # 刷新版本缓存
    config_set ".version_cache.singbox.updated = 0" &>/dev/null
    singbox_detect_version
    
    if [[ -n "$installed_ver" ]]; then
        compare_versions "$installed_ver" "$SINGBOX_VERSION"
        local cmp=$?
        
        if [[ $cmp -eq 0 ]]; then
            _green "当前已是最新版本 (v$installed_ver)"
            return 0
        elif [[ $cmp -eq 1 ]]; then
            _yellow "当前版本 ($installed_ver) 比远程版本 ($SINGBOX_VERSION) 新"
            confirm "是否强制更新?" || return 0
        fi
    fi
    
    log_info "更新 sing-box: ${installed_ver:-未知} -> $SINGBOX_VERSION"
    
    # 备份
    backup_binary "$SINGBOX_BIN" "singbox"
    
    systemctl stop sing-box &>/dev/null
    
    # 下载
    local url=$(singbox_get_download_url)
    local tmp_file="/tmp/sing-box-$$.tar.gz"
    local tmp_dir="/tmp/sing-box-extract-$$"
    
    if ! download_file "$url" "$tmp_file"; then
        _red "下载失败，回滚中..."
        restore_binary "$SINGBOX_BIN" "singbox"
        systemctl start sing-box
        rm -f "$tmp_file"
        return 1
    fi
    
    mkdir -p "$tmp_dir"
    if ! tar -xzf "$tmp_file" -C "$tmp_dir" 2>/dev/null; then
        _red "解压失败，回滚中..."
        restore_binary "$SINGBOX_BIN" "singbox"
        systemctl start sing-box
        rm -rf "$tmp_file" "$tmp_dir"
        return 1
    fi
    
    local bin_path=$(find "$tmp_dir" -name "sing-box" -type f | head -1)
    cp "$bin_path" "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    rm -rf "$tmp_file" "$tmp_dir"
    
    systemctl start sing-box
    sleep 2
    
    if systemctl is-active --quiet sing-box; then
        _green "更新成功: ${installed_ver:-未知} -> $SINGBOX_VERSION"
        
        if [[ $(config_get '.telegram.enabled' 'false') == "true" ]]; then
            local server_name=$(config_get '.telegram.server_name' "$(hostname)")
            telegram_send "🔄 <b>sing-box 已更新</b>
服务器: $server_name
版本: ${installed_ver:-未知} -> v$SINGBOX_VERSION"
        fi
    else
        _red "更新后启动失败，回滚中..."
        restore_binary "$SINGBOX_BIN" "singbox"
        systemctl start sing-box
        return 1
    fi
}

# ============================================================================
# 配置管理
# ============================================================================
singbox_add() {
    if ! singbox_check_installed; then
        _yellow "请先安装 sing-box"
        return 1
    fi
    
    echo
    echo "选择协议:"
    echo "  1. VLESS-Reality"
    echo "  2. Shadowsocks (2022)"
    echo "  0. 返回"
    echo
    read -rp "选择: " choice
    
    case $choice in
        1) singbox_add_reality ;;
        2) singbox_add_shadowsocks ;;
        0) return ;;
    esac
}

singbox_add_reality() {
    log_info "配置 VLESS-Reality..."
    
    # 端口
    local default_port=$(rand_port)
    read -rp "端口 [$default_port]: " port
    port=${port:-$default_port}
    
    if ! is_valid_port "$port"; then
        _red "无效端口"
        return 1
    fi
    
    if is_port_used "$port"; then
        _red "端口 $port 已被占用"
        return 1
    fi
    
    # UUID
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    read -rp "UUID [$uuid]: " input_uuid
    uuid=${input_uuid:-$uuid}
    
    # SNI
    read -rp "SNI [www.apple.com]: " sni
    sni=${sni:-www.apple.com}
    
    # 备注
    local default_remark=$(hostname)
    read -rp "备注 [$default_remark]: " remark
    remark=${remark:-$default_remark}
    
    # 生成密钥
    local keys=$($SINGBOX_BIN generate reality-keypair 2>/dev/null)
    local private_key=$(echo "$keys" | grep PrivateKey | awk '{print $2}')
    local public_key=$(echo "$keys" | grep PublicKey | awk '{print $2}')
    
    if [[ -z "$private_key" || -z "$public_key" ]]; then
        # 备用方法
        private_key=$(openssl rand -base64 32 | tr -d '\n')
        public_key=$(openssl rand -base64 32 | tr -d '\n')
    fi
    
    local short_id=$(openssl rand -hex 8)
    
    # 创建配置
    local conf_file="$SINGBOX_CONF_DIR/reality-${port}.json"
    cat > "$conf_file" <<EOF
{
  "_remark": "$remark",
  "_public_key": "$public_key",
  "inbounds": [{
    "type": "vless",
    "tag": "vless-reality-$port",
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
  }]
}
EOF
    
    # 验证配置
    if ! $SINGBOX_BIN check -c "$SINGBOX_CONF" -C "$SINGBOX_CONF_DIR" &>/dev/null; then
        _red "配置验证失败"
        rm -f "$conf_file"
        return 1
    fi
    
    # 防火墙
    firewall_allow "$port" tcp
    
    # 联动流量监控
    if [[ $(config_get '.settings.auto_traffic_monitor' 'true') == "true" ]]; then
        if declare -f traffic_add_port &>/dev/null; then
            traffic_add_port "$port" "Reality-$remark"
        fi
    fi
    
    systemctl restart sing-box
    sleep 2
    
    echo
    _green "VLESS-Reality 配置已添加"
    echo
    echo "=== 分享链接 ==="
    local link="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp#${remark}"
    echo "$link"
    echo
}

singbox_add_shadowsocks() {
    log_info "配置 Shadowsocks..."
    
    local default_port=$(rand_port)
    read -rp "端口 [$default_port]: " port
    port=${port:-$default_port}
    
    if ! is_valid_port "$port"; then
        _red "无效端口"
        return 1
    fi
    
    if is_port_used "$port"; then
        _red "端口 $port 已被占用"
        return 1
    fi
    
    # 加密方式
    echo "加密方式:"
    echo "  1. 2022-blake3-aes-128-gcm (推荐)"
    echo "  2. 2022-blake3-aes-256-gcm"
    echo "  3. 2022-blake3-chacha20-poly1305"
    read -rp "选择 [1]: " method_choice
    
    local method password
    case ${method_choice:-1} in
        1) method="2022-blake3-aes-128-gcm"; password=$(openssl rand -base64 16) ;;
        2) method="2022-blake3-aes-256-gcm"; password=$(openssl rand -base64 32) ;;
        3) method="2022-blake3-chacha20-poly1305"; password=$(openssl rand -base64 32) ;;
        *) method="2022-blake3-aes-128-gcm"; password=$(openssl rand -base64 16) ;;
    esac
    
    local default_remark=$(hostname)
    read -rp "备注 [$default_remark]: " remark
    remark=${remark:-$default_remark}
    
    local conf_file="$SINGBOX_CONF_DIR/ss-${port}.json"
    cat > "$conf_file" <<EOF
{
  "_remark": "$remark",
  "inbounds": [{
    "type": "shadowsocks",
    "tag": "ss-$port",
    "listen": "::",
    "listen_port": $port,
    "method": "$method",
    "password": "$password"
  }]
}
EOF
    
    if ! $SINGBOX_BIN check -c "$SINGBOX_CONF" -C "$SINGBOX_CONF_DIR" &>/dev/null; then
        _red "配置验证失败"
        rm -f "$conf_file"
        return 1
    fi
    
    firewall_allow "$port" tcp
    firewall_allow "$port" udp
    
    if [[ $(config_get '.settings.auto_traffic_monitor' 'true') == "true" ]]; then
        if declare -f traffic_add_port &>/dev/null; then
            traffic_add_port "$port" "SS-$remark"
        fi
    fi
    
    systemctl restart sing-box
    sleep 2
    
    echo
    _green "Shadowsocks 配置已添加"
    echo
    echo "=== 分享链接 ==="
    local encoded=$(echo -n "${method}:${password}" | base64 -w 0)
    echo "ss://${encoded}@${SERVER_IP}:${port}#${remark}"
    echo
}

# ============================================================================
# 列出配置
# ============================================================================
singbox_list() {
    if ! singbox_check_installed; then
        _yellow "sing-box 未安装"
        return 1
    fi
    
    local files=($(ls "$SINGBOX_CONF_DIR"/*.json 2>/dev/null))
    
    if [[ ${#files[@]} -eq 0 ]]; then
        _yellow "暂无配置"
        return 0
    fi
    
    echo
    printf "%-3s %-25s %-15s %-6s %-20s\n" "#" "文件" "协议" "端口" "备注"
    echo "------------------------------------------------------------------------"
    
    local idx=1
    for f in "${files[@]}"; do
        local filename=$(basename "$f")
        local proto=$(jq -r '.inbounds[0].type // "unknown"' "$f" 2>/dev/null)
        local port=$(jq -r '.inbounds[0].listen_port // "?"' "$f" 2>/dev/null)
        local remark=$(jq -r '._remark // ""' "$f" 2>/dev/null)
        printf "%-3s %-25s %-15s %-6s %-20s\n" "$idx" "$filename" "$proto" "$port" "$remark"
        ((idx++))
    done
    echo
}

# ============================================================================
# 删除配置
# ============================================================================
singbox_delete() {
    if ! singbox_check_installed; then
        _yellow "sing-box 未安装"
        return 1
    fi
    
    local files=($(ls "$SINGBOX_CONF_DIR"/*.json 2>/dev/null))
    
    if [[ ${#files[@]} -eq 0 ]]; then
        _yellow "暂无配置"
        return 0
    fi
    
    singbox_list
    
    read -rp "选择要删除的配置编号 (0 取消): " choice
    [[ -z "$choice" || "$choice" == "0" ]] && return 0
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 && $choice -le ${#files[@]} ]]; then
        local file="${files[$((choice-1))]}"
        local filename=$(basename "$file")
        local port=$(jq -r '.inbounds[0].listen_port' "$file" 2>/dev/null)
        
        confirm "确认删除 $filename?" || return 0
        
        rm -f "$file"
        
        # 清理防火墙和流量监控
        if [[ -n "$port" && "$port" != "null" ]]; then
            firewall_remove "$port" tcp
            firewall_remove "$port" udp
            if declare -f traffic_remove_port &>/dev/null; then
                traffic_remove_port "$port"
            fi
        fi
        
        systemctl restart sing-box &>/dev/null
        _green "已删除: $filename"
    else
        _red "无效选择"
    fi
}

# ============================================================================
# 查看分享链接
# ============================================================================
singbox_show_link() {
    if ! singbox_check_installed; then
        _yellow "sing-box 未安装"
        return 1
    fi
    
    local files=($(ls "$SINGBOX_CONF_DIR"/*.json 2>/dev/null))
    
    if [[ ${#files[@]} -eq 0 ]]; then
        _yellow "暂无配置"
        return 0
    fi
    
    singbox_list
    
    read -rp "选择配置编号 (0 取消): " choice
    [[ -z "$choice" || "$choice" == "0" ]] && return 0
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 && $choice -le ${#files[@]} ]]; then
        local file="${files[$((choice-1))]}"
        local proto=$(jq -r '.inbounds[0].type' "$file" 2>/dev/null)
        local port=$(jq -r '.inbounds[0].listen_port' "$file" 2>/dev/null)
        local remark=$(jq -r '._remark // ""' "$file" 2>/dev/null)
        
        echo
        echo "=== 分享链接 ==="
        
        case $proto in
            vless)
                local uuid=$(jq -r '.inbounds[0].users[0].uuid' "$file" 2>/dev/null)
                local sni=$(jq -r '.inbounds[0].tls.server_name' "$file" 2>/dev/null)
                local public_key=$(jq -r '._public_key' "$file" 2>/dev/null)
                local short_id=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "$file" 2>/dev/null)
                
                echo "vless://${uuid}@${SERVER_IP}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp#${remark}"
                ;;
            shadowsocks)
                local method=$(jq -r '.inbounds[0].method' "$file" 2>/dev/null)
                local password=$(jq -r '.inbounds[0].password' "$file" 2>/dev/null)
                local encoded=$(echo -n "${method}:${password}" | base64 -w 0)
                echo "ss://${encoded}@${SERVER_IP}:${port}#${remark}"
                ;;
            *)
                _yellow "不支持的协议类型: $proto"
                ;;
        esac
        echo
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
    
    # 获取所有端口
    local ports=()
    for f in $(ls "$SINGBOX_CONF_DIR"/*.json 2>/dev/null); do
        local port=$(jq -r '.inbounds[0].listen_port' "$f" 2>/dev/null)
        [[ -n "$port" && "$port" != "null" ]] && ports+=("$port")
    done
    
    systemctl stop sing-box &>/dev/null
    systemctl disable sing-box &>/dev/null
    rm -f "$SINGBOX_SERVICE"
    rm -rf "$SINGBOX_DIR"
    rm -rf "$SINGBOX_LOG_DIR"
    systemctl daemon-reload
    
    # 清理防火墙和流量监控
    for port in "${ports[@]}"; do
        firewall_remove "$port" tcp
        firewall_remove "$port" udp
        if declare -f traffic_remove_port &>/dev/null; then
            traffic_remove_port "$port"
        fi
    done
    
    if [[ $(config_get '.telegram.enabled' 'false') == "true" ]]; then
        local server_name=$(config_get '.telegram.server_name' "$(hostname)")
        telegram_send "❌ <b>sing-box 已卸载</b>
服务器: $server_name"
    fi
    
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
    journalctl -u sing-box -n 50 --no-pager
}

# ============================================================================
# 菜单
# ============================================================================
singbox_menu() {
    while true; do
        local status=$(singbox_get_status)
        local version=$(singbox_get_version)
        
        clear
        echo
        echo "============================================"
        echo "            sing-box 管理"
        echo "============================================"
        echo
        
        case $status in
            running)
                echo "  状态: $(_green "运行中")"
                echo "  版本: ${version:-未知}"
                local conf_count=$(ls "$SINGBOX_CONF_DIR"/*.json 2>/dev/null | wc -l)
                echo "  配置: ${conf_count} 个"
                
                singbox_detect_version "silent"
                if [[ -n "$version" && -n "$SINGBOX_VERSION" ]]; then
                    compare_versions "$version" "$SINGBOX_VERSION" || true
                    local cmp=$?
                    [[ $cmp -eq 2 ]] && echo "  $(_yellow "有新版本: v$SINGBOX_VERSION")"
                fi
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
        
        if [[ $status == "not_installed" ]]; then
            echo "  1. 安装 sing-box"
        else
            echo "  1. 添加配置"
            echo "  2. 配置列表"
            echo "  3. 删除配置"
            echo "  4. 查看分享链接"
            echo "  5. 更新 sing-box"
            echo "  ---"
            echo "  6. 启动服务"
            echo "  7. 停止服务"
            echo "  8. 重启服务"
            echo "  9. 查看日志"
            echo "  ---"
            echo "  10. 卸载"
        fi
        
        echo
        echo "  0. 返回主菜单"
        echo
        echo "============================================"
        echo
        read -rp "请选择: " choice
        
        if [[ $status == "not_installed" ]]; then
            case $choice in
                1) singbox_install; pause ;;
                0) return ;;
            esac
        else
            case $choice in
                1) singbox_add; pause ;;
                2) singbox_list; pause ;;
                3) singbox_delete; pause ;;
                4) singbox_show_link; pause ;;
                5) singbox_update; pause ;;
                6) singbox_start; sleep 1 ;;
                7) singbox_stop; sleep 1 ;;
                8) singbox_restart; sleep 1 ;;
                9) singbox_logs; pause ;;
                10) singbox_uninstall; pause; [[ ! -f "$SINGBOX_BIN" ]] && return ;;
                0) return ;;
            esac
        fi
    done
}

log_debug "sing-box 模块已加载"
