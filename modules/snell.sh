#!/bin/bash
# ============================================================================
# VPS Manager - Snell 模块 (完整版)
# ============================================================================

# 防止重复加载
[[ $SNELL_LOADED ]] && return 0
SNELL_LOADED=true

# ============================================================================
# Snell 配置
# ============================================================================
readonly SNELL_FALLBACK_VERSION="4.1.1"
readonly SNELL_BIN="/usr/local/bin/snell-server"
readonly SNELL_DIR="/etc/snell"
readonly SNELL_CONF="$SNELL_DIR/snell-server.conf"
readonly SNELL_SERVICE="/etc/systemd/system/snell.service"
readonly SNELL_DL_BASE="https://dl.nssurge.com/snell"
readonly SNELL_KB_URL="https://kb.nssurge.com/surge-knowledge-base/guidelines/snell"
readonly SNELL_VERSION_CACHE_TTL=3600  # 1小时缓存

# ============================================================================
# 版本检测
# ============================================================================
snell_detect_version() {
    local silent="${1:-}"
    local cached_ver cached_time current_time
    
    # 检查缓存
    cached_ver=$(config_get '.version_cache.snell.version')
    cached_time=$(config_get '.version_cache.snell.updated')
    current_time=$(date +%s)
    
    if [[ -n "$cached_ver" && -n "$cached_time" ]]; then
        local age=$((current_time - cached_time))
        if [[ $age -lt $SNELL_VERSION_CACHE_TTL ]]; then
            SNELL_VERSION="$cached_ver"
            [[ -z "$silent" ]] && log_debug "使用缓存版本: $SNELL_VERSION"
            return 0
        fi
    fi
    
    [[ -z "$silent" ]] && log_info "检测最新版本..."
    
    # 方法1: 从 KB 页面获取 (结构稳定)
    local version
    version=$(curl -sfm10 "$SNELL_KB_URL" 2>/dev/null | \
              grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | \
              sort -V | tail -1 | sed 's/^v//')
    
    # 方法2: 从下载目录获取 (备用)
    if [[ -z "$version" ]]; then
        version=$(curl -sfm10 "${SNELL_DL_BASE}/" 2>/dev/null | \
                  grep -oE 'snell-server-v[0-9]+\.[0-9]+\.[0-9]+' | \
                  grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | \
                  sort -V | tail -1)
    fi
    
    # 使用回退版本
    if [[ -z "$version" ]]; then
        version="$SNELL_FALLBACK_VERSION"
        [[ -z "$silent" ]] && log_warn "无法检测版本，使用默认: $version"
    fi
    
    SNELL_VERSION="$version"
    
    # 更新缓存
    config_set ".version_cache.snell.version = \"$version\" | .version_cache.snell.updated = $current_time" &>/dev/null
    
    return 0
}

snell_get_download_url() {
    local version="${1:-$SNELL_VERSION}"
    local arch
    
    case $ARCH in
        amd64) arch="amd64" ;;
        arm64) arch="aarch64" ;;
        armv7) arch="armv7l" ;;
        386)   arch="i386" ;;
        *)     arch="amd64" ;;
    esac
    
    echo "${SNELL_DL_BASE}/snell-server-v${version}-linux-${arch}.zip"
}

# ============================================================================
# 状态检测
# ============================================================================
snell_check_installed() {
    [[ -f "$SNELL_BIN" ]]
}

snell_get_status() {
    if snell_check_installed; then
        if systemctl is-active --quiet snell 2>/dev/null; then
            echo "running"
        else
            echo "stopped"
        fi
    else
        echo "not_installed"
    fi
}

snell_get_installed_version() {
    [[ -f "$SNELL_DIR/version" ]] && cat "$SNELL_DIR/version" || echo ""
}

snell_get_port() {
    [[ -f "$SNELL_CONF" ]] && grep -E '^listen' "$SNELL_CONF" | sed -E 's/.*:([0-9]+)$/\1/'
}

snell_get_psk() {
    [[ -f "$SNELL_CONF" ]] && grep -E '^psk' "$SNELL_CONF" | awk -F'=' '{print $2}' | xargs
}

snell_get_node_name() {
    [[ -f "$SNELL_DIR/node_name" ]] && cat "$SNELL_DIR/node_name" || hostname
}

# ============================================================================
# 安装
# ============================================================================
snell_install() {
    if snell_check_installed; then
        _yellow "Snell 已安装，版本: $(snell_get_installed_version)"
        return 1
    fi
    
    # 检测版本
    snell_detect_version || { log_error "无法确定安装版本"; return 1; }
    
    log_info "开始安装 Snell v$SNELL_VERSION..."
    
    # 检查依赖
    ensure_deps wget unzip curl
    
    # 询问端口
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
    
    # 询问节点名称
    local default_name=$(hostname)
    read -rp "节点名称 [$default_name]: " node_name
    node_name=${node_name:-$default_name}
    
    # 生成 PSK
    local psk=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
    
    # 下载
    local url=$(snell_get_download_url)
    local tmp_zip="/tmp/snell-server-$$.zip"
    
    log_info "下载: $url"
    if ! download_file "$url" "$tmp_zip"; then
        rm -f "$tmp_zip"
        return 1
    fi
    
    # 解压安装
    mkdir -p "$SNELL_DIR"
    if ! unzip -o "$tmp_zip" -d /usr/local/bin &>/dev/null; then
        _red "解压失败"
        rm -f "$tmp_zip"
        return 1
    fi
    rm -f "$tmp_zip"
    chmod +x "$SNELL_BIN"
    
    # 保存版本和节点名
    echo "$SNELL_VERSION" > "$SNELL_DIR/version"
    echo "$node_name" > "$SNELL_DIR/node_name"
    
    # 创建配置
    cat > "$SNELL_CONF" <<EOF
[snell-server]
listen = ::0:${port}
psk = ${psk}
ipv6 = true
tfo = true
EOF
    
    # 创建服务
    cat > "$SNELL_SERVICE" <<EOF
[Unit]
Description=Snell Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=$SNELL_BIN -c $SNELL_CONF
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable snell &>/dev/null
    systemctl start snell
    
    sleep 2
    
    if ! systemctl is-active --quiet snell; then
        _red "服务启动失败"
        journalctl -u snell -n 20 --no-pager
        return 1
    fi
    
    # 防火墙
    firewall_allow "$port" tcp
    firewall_allow "$port" udp
    
    # 联动流量监控
    if [[ $(config_get '.settings.auto_traffic_monitor' 'true') == "true" ]]; then
        if declare -f traffic_add_port &>/dev/null; then
            log_info "联动: 添加端口流量监控..."
            traffic_add_port "$port" "Snell-$node_name"
        fi
    fi
    
    # 网络优化
    if [[ $(config_get '.settings.auto_network_optimize' 'true') == "true" ]]; then
        enable_tfo &>/dev/null
        enable_bbr &>/dev/null
    fi
    
    # Telegram 通知
    if [[ $(config_get '.telegram.enabled' 'false') == "true" ]]; then
        local server_name=$(config_get '.telegram.server_name' "$(hostname)")
        telegram_send "✅ <b>Snell 已安装</b>
服务器: $server_name
版本: v$SNELL_VERSION
端口: $port
节点: $node_name"
    fi
    
    echo
    _green "Snell v$SNELL_VERSION 安装完成!"
    echo
    snell_show_config
}

# ============================================================================
# 更新
# ============================================================================
snell_update() {
    if ! snell_check_installed; then
        _yellow "Snell 未安装"
        return 1
    fi
    
    local installed_ver=$(snell_get_installed_version)
    
    # 强制刷新版本缓存
    config_set ".version_cache.snell.updated = 0" &>/dev/null
    snell_detect_version
    
    if [[ -z "$installed_ver" ]]; then
        log_warn "无法获取已安装版本，继续更新..."
    else
        compare_versions "$installed_ver" "$SNELL_VERSION"
        local cmp_result=$?
        
        if [[ $cmp_result -eq 0 ]]; then
            _green "当前已是最新版本 (v$installed_ver)"
            return 0
        elif [[ $cmp_result -eq 1 ]]; then
            _yellow "当前版本 ($installed_ver) 比远程版本 ($SNELL_VERSION) 新"
            confirm "是否强制更新?" || return 0
        fi
    fi
    
    log_info "更新 Snell: ${installed_ver:-未知} -> $SNELL_VERSION"
    
    # 备份当前二进制
    backup_binary "$SNELL_BIN" "snell"
    backup_file "$SNELL_CONF" "snell"
    
    # 停止服务
    systemctl stop snell &>/dev/null
    
    # 下载新版本
    local url=$(snell_get_download_url)
    local tmp_zip="/tmp/snell-server-$$.zip"
    
    if ! download_file "$url" "$tmp_zip"; then
        _red "下载失败，回滚中..."
        restore_binary "$SNELL_BIN" "snell"
        systemctl start snell
        rm -f "$tmp_zip"
        return 1
    fi
    
    # 安装
    if ! unzip -o "$tmp_zip" -d /usr/local/bin &>/dev/null; then
        _red "解压失败，回滚中..."
        restore_binary "$SNELL_BIN" "snell"
        systemctl start snell
        rm -f "$tmp_zip"
        return 1
    fi
    rm -f "$tmp_zip"
    chmod +x "$SNELL_BIN"
    
    # 更新版本记录
    echo "$SNELL_VERSION" > "$SNELL_DIR/version"
    
    # 启动服务
    systemctl start snell
    sleep 2
    
    if systemctl is-active --quiet snell; then
        _green "更新成功: ${installed_ver:-未知} -> $SNELL_VERSION"
        
        # Telegram 通知
        if [[ $(config_get '.telegram.enabled' 'false') == "true" ]]; then
            local server_name=$(config_get '.telegram.server_name' "$(hostname)")
            telegram_send "🔄 <b>Snell 已更新</b>
服务器: $server_name
版本: ${installed_ver:-未知} -> v$SNELL_VERSION"
        fi
    else
        _red "更新后启动失败，回滚中..."
        restore_binary "$SNELL_BIN" "snell"
        echo "$installed_ver" > "$SNELL_DIR/version"
        systemctl start snell
        journalctl -u snell -n 20 --no-pager
        return 1
    fi
}

# ============================================================================
# 显示配置
# ============================================================================
snell_show_config() {
    if ! snell_check_installed; then
        _yellow "Snell 未安装"
        return 1
    fi
    
    local port=$(snell_get_port)
    local psk=$(snell_get_psk)
    local node_name=$(snell_get_node_name)
    local version=$(snell_get_installed_version)
    local status=$(snell_get_status)
    
    echo
    echo "=== Snell 配置 ==="
    echo "状态: $([ "$status" = "running" ] && _green "运行中" || _yellow "已停止")"
    echo "版本: ${version:-未知}"
    echo "节点: $node_name"
    echo "端口: $port"
    echo "PSK:  $psk"
    echo
    echo "=== Surge 配置 (可直接复制) ==="
    echo "${node_name} = snell, ${SERVER_IP}, ${port}, psk=${psk}, version=4, tfo=true, reuse=true"
    echo
}

# ============================================================================
# 修改配置
# ============================================================================
snell_modify_port() {
    if ! snell_check_installed; then
        _yellow "Snell 未安装"
        return 1
    fi
    
    local old_port=$(snell_get_port)
    echo "当前端口: $old_port"
    
    read -rp "新端口: " new_port
    [[ -z "$new_port" ]] && return 0
    
    if ! is_valid_port "$new_port"; then
        _red "无效端口"
        return 1
    fi
    
    if [[ "$new_port" != "$old_port" ]] && is_port_used "$new_port"; then
        _red "端口 $new_port 已被占用"
        return 1
    fi
    
    # 备份配置
    backup_file "$SNELL_CONF" "snell"
    
    # 修改配置
    sed -i "s/^listen = .*:${old_port}$/listen = ::0:${new_port}/" "$SNELL_CONF"
    
    # 更新防火墙
    firewall_remove "$old_port"
    firewall_allow "$new_port" tcp
    firewall_allow "$new_port" udp
    
    # 更新流量监控
    if declare -f traffic_remove_port &>/dev/null; then
        traffic_remove_port "$old_port"
    fi
    if declare -f traffic_add_port &>/dev/null; then
        traffic_add_port "$new_port" "Snell-$(snell_get_node_name)"
    fi
    
    systemctl restart snell
    sleep 2
    
    if systemctl is-active --quiet snell; then
        _green "端口已修改: $old_port -> $new_port"
    else
        _red "修改后启动失败，回滚中..."
        restore_file "$SNELL_CONF" "snell"
        firewall_remove "$new_port"
        firewall_allow "$old_port" tcp
        firewall_allow "$old_port" udp
        systemctl restart snell
    fi
}

snell_modify_psk() {
    if ! snell_check_installed; then
        _yellow "Snell 未安装"
        return 1
    fi
    
    local old_psk=$(snell_get_psk)
    echo "当前 PSK: $old_psk"
    
    local new_psk=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
    read -rp "新 PSK [$new_psk]: " input_psk
    new_psk=${input_psk:-$new_psk}
    
    backup_file "$SNELL_CONF" "snell"
    sed -i "s/^psk = .*/psk = ${new_psk}/" "$SNELL_CONF"
    
    systemctl restart snell
    sleep 2
    
    if systemctl is-active --quiet snell; then
        _green "PSK 已修改"
        snell_show_config
    else
        _red "修改后启动失败，回滚中..."
        restore_file "$SNELL_CONF" "snell"
        systemctl restart snell
    fi
}

snell_modify_name() {
    if ! snell_check_installed; then
        _yellow "Snell 未安装"
        return 1
    fi
    
    local old_name=$(snell_get_node_name)
    echo "当前名称: $old_name"
    
    read -rp "新名称: " new_name
    [[ -z "$new_name" ]] && return 0
    
    echo "$new_name" > "$SNELL_DIR/node_name"
    
    # 更新流量监控备注
    if declare -f traffic_add_port &>/dev/null; then
        local port=$(snell_get_port)
        # 更新备注逻辑可以在 traffic 模块中实现
    fi
    
    _green "名称已修改: $old_name -> $new_name"
}

# ============================================================================
# 卸载
# ============================================================================
snell_uninstall() {
    if ! snell_check_installed; then
        _yellow "Snell 未安装"
        return 1
    fi
    
    confirm "确认卸载 Snell?" || return 0
    
    local port=$(snell_get_port)
    
    systemctl stop snell &>/dev/null
    systemctl disable snell &>/dev/null
    rm -f "$SNELL_SERVICE"
    rm -f "$SNELL_BIN"
    rm -rf "$SNELL_DIR"
    systemctl daemon-reload
    
    # 清理防火墙
    [[ -n "$port" ]] && {
        firewall_remove "$port" tcp
        firewall_remove "$port" udp
    }
    
    # 联动移除流量监控
    if declare -f traffic_remove_port &>/dev/null && [[ -n "$port" ]]; then
        log_info "联动: 移除端口流量监控..."
        traffic_remove_port "$port"
    fi
    
    # Telegram 通知
    if [[ $(config_get '.telegram.enabled' 'false') == "true" ]]; then
        local server_name=$(config_get '.telegram.server_name' "$(hostname)")
        telegram_send "❌ <b>Snell 已卸载</b>
服务器: $server_name"
    fi
    
    _green "Snell 已卸载"
}

# ============================================================================
# 服务管理
# ============================================================================
snell_start() {
    systemctl start snell && _green "Snell 已启动" || _red "启动失败"
}

snell_stop() {
    systemctl stop snell && _green "Snell 已停止" || _red "停止失败"
}

snell_restart() {
    systemctl restart snell && _green "Snell 已重启" || _red "重启失败"
}

snell_logs() {
    journalctl -u snell -n 50 --no-pager
}

# ============================================================================
# 菜单
# ============================================================================
snell_menu() {
    while true; do
        local status=$(snell_get_status)
        local installed_ver=$(snell_get_installed_version)
        
        clear
        echo
        echo "============================================"
        echo "            Snell 管理"
        echo "============================================"
        echo
        
        case $status in
            running)
                echo "  状态: $(_green "运行中")"
                echo "  版本: ${installed_ver:-未知}"
                echo "  端口: $(snell_get_port)"
                
                # 检查更新提示
                snell_detect_version "silent"
                if [[ -n "$installed_ver" && -n "$SNELL_VERSION" ]]; then
                    compare_versions "$installed_ver" "$SNELL_VERSION" || true
                    local cmp=$?
                    [[ $cmp -eq 2 ]] && echo "  $(_yellow "有新版本: v$SNELL_VERSION")"
                fi
                ;;
            stopped)
                echo "  状态: $(_yellow "已停止")"
                echo "  版本: ${installed_ver:-未知}"
                ;;
            *)
                echo "  状态: $(_red "未安装")"
                ;;
        esac
        
        echo
        echo "--------------------------------------------"
        echo
        
        if [[ $status == "not_installed" ]]; then
            echo "  1. 安装 Snell"
        else
            echo "  1. 查看配置"
            echo "  2. 修改端口"
            echo "  3. 修改 PSK"
            echo "  4. 修改名称"
            echo "  5. 更新 Snell"
            echo "  ---"
            echo "  6. 启动服务"
            echo "  7. 停止服务"
            echo "  8. 重启服务"
            echo "  9. 查看日志"
            echo "  ---"
            echo "  10. 卸载 Snell"
        fi
        
        echo
        echo "  0. 返回主菜单"
        echo
        echo "============================================"
        echo
        read -rp "请选择: " choice
        
        if [[ $status == "not_installed" ]]; then
            case $choice in
                1) snell_install; pause ;;
                0) return ;;
            esac
        else
            case $choice in
                1) snell_show_config; pause ;;
                2) snell_modify_port; pause ;;
                3) snell_modify_psk; pause ;;
                4) snell_modify_name; pause ;;
                5) snell_update; pause ;;
                6) snell_start; sleep 1 ;;
                7) snell_stop; sleep 1 ;;
                8) snell_restart; sleep 1 ;;
                9) snell_logs; pause ;;
                10) snell_uninstall; pause; [[ ! -f "$SNELL_BIN" ]] && return ;;
                0) return ;;
            esac
        fi
    done
}

log_debug "Snell 模块已加载"
