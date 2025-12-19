# 1. 停止并禁用服务
systemctl stop sing-box
systemctl disable sing-box

# 2. 删除系统服务文件
rm -f /etc/systemd/system/sing-box.service
systemctl daemon-reload

# 3. 删除核心文件、配置文件和所有证书
rm -rf /etc/sing-box

# 4. 删除日志文件
rm -rf /var/log/sing-box

# 5. 删除快捷指令 (sb)
rm -f /usr/local/bin/sb

# 6. 删除版本缓存
rm -f /var/tmp/singbox_version_cache

echo "Sing-box 清理完毕。"


# 1. 停止并禁用服务
systemctl stop snell
systemctl disable snell

# 2. 删除系统服务文件
rm -f /etc/systemd/system/snell.service
systemctl daemon-reload

# 3. 删除配置文件目录 (包含配置和 ver.txt)
rm -rf /etc/snell

# 4. 删除核心程序和管理脚本
rm -f /usr/local/bin/snell-server
rm -f /usr/local/bin/snell-manager.sh
# 删除快捷方式
rm -f /usr/local/bin/snell

# 5. 删除日志文件
rm -f /var/log/snell.log

# 6. 删除版本缓存和下载缓存
rm -f /var/tmp/snell_version_cache
rm -f /tmp/snell-server.zip

# 7. 删除 snell 用户 (脚本安装时创建的专用用户)
userdel snell 2>/dev/null || true

echo "Snell 清理完毕。"