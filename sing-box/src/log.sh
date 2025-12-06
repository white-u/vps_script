#!/bin/bash

# 日志管理模块

show_log() {
    local lines=${1:-50}
    local log_file="$is_log_dir/sing-box.log"
    
    if [[ ! -f $log_file ]]; then
        _yellow "日志文件不存在"
        return
    fi
    
    echo
    echo "---------- 最近 $lines 行日志 ----------"
    echo
    tail -n $lines "$log_file"
    echo
}

follow_log() {
    local log_file="$is_log_dir/sing-box.log"
    
    if [[ ! -f $log_file ]]; then
        _yellow "日志文件不存在"
        return
    fi
    
    echo "实时日志 (Ctrl+C 退出):"
    echo
    tail -f "$log_file"
}

clear_log() {
    local log_file="$is_log_dir/sing-box.log"
    
    read -p "确认清空日志? [y/N]: " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && { echo "已取消"; return; }
    
    > "$log_file"
    _green "日志已清空"
}
