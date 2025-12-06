# sing-box 优化版管理脚本

基于原脚本优化，精简协议，优化交互体验。

## 主要改动

### 1. 协议精简
只保留两个常用协议：
- **VLESS-Reality** - 推荐，抗检测能力强
- **Shadowsocks** - 2022 新加密，速度快

### 2. 默认 SNI 改为 `www.time.is`

### 3. 自定义备注
- 创建配置时可输入备注名称
- 默认使用服务器 IP 作为备注
- 分享链接使用自定义备注

### 4. 交互优化
- 操作完成后返回主菜单，无需重新运行脚本
- 选择配置时支持 `0` 返回
- 错误提示更友好，不会直接退出

### 5. 快捷命令
```bash
sb add r      # 快速添加 VLESS-Reality
sb add ss     # 快速添加 Shadowsocks
```

## 安装

```bash
bash install.sh
```

或指定版本：
```bash
bash install.sh -v 1.11.0
```

## 使用

```bash
sb          # 打开菜单
sb add      # 添加配置
sb list     # 列出配置
sb info     # 查看配置详情
sb del      # 删除配置
sb help     # 查看帮助
```

## 文件结构

```
/etc/sing-box/
├── bin/sing-box          # 核心程序
├── config.json           # 主配置
├── conf/                 # 配置目录
│   └── *.json           # 各协议配置
└── sh/                   # 脚本目录
    ├── sing-box.sh      # 入口脚本
    └── src/             # 模块
        ├── init.sh      # 初始化
        ├── core.sh      # 核心功能
        ├── bbr.sh       # BBR 优化
        ├── dns.sh       # DNS 设置
        ├── log.sh       # 日志管理
        └── download.sh  # 更新卸载
```
