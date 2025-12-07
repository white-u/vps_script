#!/usr/bin/env bash
#
# Telegram 通知统一模块
# 提供 Telegram Bot API 消息发送功能
# 供各脚本调用
#
# 使用方式:
#   source telegram-notify.sh
#   telegram_send "消息内容" "$BOT_TOKEN" "$CHAT_ID"
#   telegram_send_html "<b>HTML消息</b>" "$BOT_TOKEN" "$CHAT_ID"
#

# =====================================
# 配置
# =====================================
TELEGRAM_API_URL="https://api.telegram.org"
CONNECT_TIMEOUT=10
MAX_TIMEOUT=30

# =====================================
# 颜色定义
# =====================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# =====================================
# 日志函数
# =====================================
_log()   { echo -e "${GREEN}[INFO]${NC} $*"; }
_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# =====================================
# 发送文本消息
# =====================================
# 参数:
#   $1 - 消息内容
#   $2 - Bot Token
#   $3 - Chat ID
#   $4 - 解析模式 (可选，默认: text)
# 返回:
#   0 - 成功
#   1 - 失败
telegram_send() {
    local message="$1"
    local bot_token="$2"
    local chat_id="$3"
    local parse_mode="${4:-text}"

    # 参数检查
    if [ -z "$message" ]; then
        _error "消息内容不能为空"
        return 1
    fi

    if [ -z "$bot_token" ]; then
        _error "Bot Token 不能为空"
        return 1
    fi

    if [ -z "$chat_id" ]; then
        _error "Chat ID 不能为空"
        return 1
    fi

    # URL 编码消息（简单处理）
    local encoded_message=$(echo -n "$message" | jq -sRr @uri 2>/dev/null || echo "$message")

    # 发送消息
    local response=$(curl -s --connect-timeout $CONNECT_TIMEOUT --max-time $MAX_TIMEOUT \
        -X POST \
        "${TELEGRAM_API_URL}/bot${bot_token}/sendMessage" \
        -d "chat_id=${chat_id}" \
        -d "text=${encoded_message}" \
        -d "parse_mode=${parse_mode}" \
        2>&1)

    # 检查结果
    if echo "$response" | grep -q '"ok":true'; then
        return 0
    else
        _error "发送失败: $(echo "$response" | jq -r '.description' 2>/dev/null || echo "$response")"
        return 1
    fi
}

# =====================================
# 发送 HTML 格式消息
# =====================================
telegram_send_html() {
    local message="$1"
    local bot_token="$2"
    local chat_id="$3"

    telegram_send "$message" "$bot_token" "$chat_id" "HTML"
}

# =====================================
# 发送 Markdown 格式消息
# =====================================
telegram_send_markdown() {
    local message="$1"
    local bot_token="$2"
    local chat_id="$3"

    telegram_send "$message" "$bot_token" "$chat_id" "Markdown"
}

# =====================================
# 测试 Telegram 配置
# =====================================
telegram_test() {
    local bot_token="$1"
    local chat_id="$2"
    local test_message="${3:-🔔 Telegram 通知测试消息}"

    _log "正在测试 Telegram 配置..."

    # 获取当前时间
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local full_message="${test_message}

📅 时间: ${timestamp}
🖥️  主机: $(hostname)
"

    if telegram_send "$full_message" "$bot_token" "$chat_id"; then
        echo -e "${GREEN}✓ 测试成功！消息已发送${NC}"
        return 0
    else
        echo -e "${RED}✗ 测试失败${NC}"
        return 1
    fi
}

# =====================================
# 验证 Bot Token 格式
# =====================================
validate_bot_token() {
    local bot_token="$1"

    # Bot Token 格式: 数字:字母数字组合
    # 例如: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz
    if [[ "$bot_token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
        return 0
    else
        _error "Bot Token 格式无效"
        return 1
    fi
}

# =====================================
# 验证 Chat ID 格式
# =====================================
validate_chat_id() {
    local chat_id="$1"

    # Chat ID 可以是:
    # - 正数 (用户ID)
    # - 负数 (群组ID)
    # - @开头 (频道用户名)
    if [[ "$chat_id" =~ ^-?[0-9]+$ ]] || [[ "$chat_id" =~ ^@.+ ]]; then
        return 0
    else
        _error "Chat ID 格式无效"
        return 1
    fi
}

# =====================================
# 获取 Bot 信息
# =====================================
telegram_get_me() {
    local bot_token="$1"

    if [ -z "$bot_token" ]; then
        _error "Bot Token 不能为空"
        return 1
    fi

    local response=$(curl -s --connect-timeout $CONNECT_TIMEOUT --max-time $MAX_TIMEOUT \
        "${TELEGRAM_API_URL}/bot${bot_token}/getMe" 2>&1)

    if echo "$response" | grep -q '"ok":true'; then
        echo "$response" | jq -r '.result | "Bot名称: \(.first_name)\nBot用户名: @\(.username)\nBot ID: \(.id)"' 2>/dev/null
        return 0
    else
        _error "获取 Bot 信息失败"
        return 1
    fi
}

# =====================================
# 发送通知（带重试）
# =====================================
telegram_send_with_retry() {
    local message="$1"
    local bot_token="$2"
    local chat_id="$3"
    local max_retries="${4:-3}"
    local retry_delay="${5:-2}"

    local attempt=1

    while [ $attempt -le $max_retries ]; do
        if telegram_send "$message" "$bot_token" "$chat_id"; then
            return 0
        fi

        if [ $attempt -lt $max_retries ]; then
            _warn "发送失败，${retry_delay}秒后重试 ($attempt/$max_retries)..."
            sleep $retry_delay
        fi

        ((attempt++))
    done

    _error "重试 $max_retries 次后仍然失败"
    return 1
}

# =====================================
# 格式化告警消息
# =====================================
format_alert_message() {
    local title="$1"
    local content="$2"
    local level="${3:-info}"  # info, warning, critical
    local server_name="${4:-$(hostname)}"

    local emoji icon_line
    case "$level" in
        warning)
            emoji="⚠️"
            ;;
        critical|error)
            emoji="🚨"
            ;;
        success)
            emoji="✅"
            ;;
        *)
            emoji="ℹ️"
            ;;
    esac

    cat << EOF
${emoji} <b>${title}</b>

${content}

🖥️ 服务器: ${server_name}
📅 时间: $(date '+%Y-%m-%d %H:%M:%S')
EOF
}

# =====================================
# 发送告警消息
# =====================================
telegram_send_alert() {
    local title="$1"
    local content="$2"
    local level="${3:-info}"
    local bot_token="$4"
    local chat_id="$5"
    local server_name="${6:-$(hostname)}"

    local message=$(format_alert_message "$title" "$content" "$level" "$server_name")

    telegram_send_html "$message" "$bot_token" "$chat_id"
}

# =====================================
# 显示帮助信息
# =====================================
show_telegram_help() {
    cat << EOF
Telegram 通知统一模块

使用方式:
  source telegram-notify.sh

函数列表:
  telegram_send <msg> <token> <chat_id> [parse_mode]
                                    - 发送文本消息
  telegram_send_html <msg> <token> <chat_id>
                                    - 发送 HTML 消息
  telegram_send_markdown <msg> <token> <chat_id>
                                    - 发送 Markdown 消息
  telegram_test <token> <chat_id> [msg]
                                    - 测试配置
  telegram_send_with_retry <msg> <token> <chat_id> [retries] [delay]
                                    - 带重试的发送
  telegram_send_alert <title> <content> <level> <token> <chat_id> [server]
                                    - 发送告警消息
  telegram_get_me <token>           - 获取 Bot 信息
  validate_bot_token <token>        - 验证 Token 格式
  validate_chat_id <chat_id>        - 验证 Chat ID 格式

示例:
  # 发送简单消息
  telegram_send "测试消息" "123:ABC" "456789"

  # 发送 HTML 消息
  telegram_send_html "<b>重要通知</b>" "123:ABC" "456789"

  # 测试配置
  telegram_test "123:ABC" "456789"

  # 发送告警
  telegram_send_alert "流量告警" "端口 443 流量超限" "warning" "123:ABC" "456789"
EOF
}

# =====================================
# 主函数（命令行模式）
# =====================================
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    case "${1:-help}" in
        send)
            telegram_send "${2}" "${3}" "${4}" "${5:-text}"
            ;;
        test)
            telegram_test "${2}" "${3}" "${4}"
            ;;
        getme)
            telegram_get_me "${2}"
            ;;
        help|--help|-h)
            show_telegram_help
            ;;
        *)
            echo "用法: $0 {send|test|getme|help}"
            echo "  send <msg> <token> <chat_id> [parse_mode]"
            echo "  test <token> <chat_id> [msg]"
            echo "  getme <token>"
            exit 1
            ;;
    esac
fi
