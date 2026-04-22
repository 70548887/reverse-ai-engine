# reverse-ai-engine

> AI 驱动的自动化逆向工程系统 — Web & App 逆向引擎，支持 JS 逆向、APP 逆向、签名算法提取、事件驱动的无人值守任务流水线。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.13](https://img.shields.io/badge/Python-3.13-blue)](LICENSE)
[![mitmproxy 12.2](https://img.shields.io/badge/mitmproxy-12.2-green)](LICENSE)
[![Frida 17.9](https://img.shields.io/badge/Frida-17.9-red)](LICENSE)

---

## 当前状态

> ✅ **P0 基础设施完成** — 2026-04-22

### 记忆层已就绪

| 层次 | 状态 | 详情 |
|------|------|------|
| Qdrant 向量库 | ✅ | 云端 152.136.169.127:32768，collection: openclaw_memory，1306条 |
| SESSION-STATE.md | ✅ | 热记忆在 `/opt/data/home/.openclaw/workspace/` |
| 本地目录结构 | ✅ | memory/ + tasks/ 已建立 |
| 持久化记忆 | ✅ | 关键配置已写入 memory tool |

### 工具链已就绪

| 工具 | 版本 | 状态 |
|------|------|------|
| mitmproxy | 12.2.2 | ✅ |
| frida-tools | 17.9.1 | ✅ |
| jadx | 1.4.7 | ✅ |
| apktool | 2.7.0 | ✅ |
| Java (Temurin) | 17.0.18 | ✅ |
| Python | 3.13.5 | ✅ |
| Node.js | 22.14.0 | /opt/data/home/nodejs/bin/ |

> 大型二进制文件（frida-server ARM64、JDK）存放于 `reverse-tools/` 目录，不在 Git 仓库中。

---

## 快速开始

### 1. 安装依赖

```bash
# 设置环境变量
source tools/env.sh

# 检查工具链状态
python3 tools/check-tools.py
```

### 2. Web 逆向（mitmproxy 抓包）

```bash
# 启动抓包
bash tools/mitm-capture.sh

# 配置浏览器代理到 127.0.0.1:8080
# 访问目标网站，完成操作
# 按 Ctrl+C 停止，HAR 文件自动保存到 reverse-tools/capture/
```

### 3. APP 逆向（APKTool + JADX）

```bash
# 反编译 APK
bash tools/apk-decompile.sh /path/to/target.apk ./decompiled/

# 查看 Java 源码
./reverse-tools/bin/jadx ./decompiled/target/

# 或用命令行导出
./reverse-tools/bin/jadx -d ./output-dir ./target.apk
```

### 4. Frida Hook

```bash
# USB 连接 Android 设备
adb forward tcp:27042 tcp:27042
adb forward tcp:27043 tcp:27043

# 在设备上启动 frida-server（需要 root）
adb shell /data/local/tmp/frida-server &

# 用自定义脚本 Hook
bash tools/frida-task.sh com.example.app tools/frida/scripts/ssl-unpinning.js
```

---

## 项目结构

```
reverse-ai-engine/
├── README.md
├── LICENSE
├── .gitignore
├── docs/                          # 开发文档（9篇）
│   ├── 01-系统架构.md
│   ├── 02-任务类型定义.md
│   ├── 03-控制器设计.md
│   ├── 04-执行器分工.md
│   ├── 05-记忆层设计.md
│   ├── 06-触发机制.md
│   ├── 07-逆向工具链.md
│   ├── 08-交付标准.md
│   └── 09-开发规范.md
└── tools/                         # 逆向工具链（本地安装）
    ├── env.sh                     # 环境变量配置
    ├── check-tools.py             # 工具链健康检查
    ├── mitm-script.py             # mitmproxy 抓包脚本
    ├── mitm-capture.sh            # 抓包启动器
    ├── apk-decompile.sh           # APK 反编译启动器
    ├── frida-task.sh              # Frida Hook 执行器
    ├── jadx/                      # JADX (Java APK 反编译器)
    ├── apktool/                   # APKTool (smali 反编译器)
    ├── frida/                     # Frida (frida-server + frida-inject)
    │   ├── frida-server           # Android ARM64 (设备用)
    │   └── frida-inject           # Android ARM64 (设备用)
    ├── jdk-17.0.18+8/             # Java 17 (JADX/APKTool 运行环境)
    └── android-sdk/               # Android SDK (可选)
```

---

## 开发文档

| 文档 | 内容 |
|------|------|
| [01-系统架构](docs/01-系统架构.md) | 控制器/执行器/工单系统设计 |
| [02-任务类型定义](docs/02-任务类型定义.md) | Web/APP/签名算法三大任务类型 |
| [03-控制器设计](docs/03-控制器设计.md) | reverse-controller.py 核心逻辑 |
| [04-执行器分工](docs/04-执行器分工.md) | Codex 主线 / M2.7 二线分流 |
| [05-记忆层设计](docs/05-记忆层设计.md) | 5层记忆体系（热→冷） |
| [06-触发机制](docs/06-触发机制.md) | 事件驱动 + systemd path |
| [07-逆向工具链](docs/07-逆向工具链.md) | 工具安装/使用/验证 |
| [08-交付标准](docs/08-交付标准.md) | 签名脚本规范 + 验证标准 |
| [09-开发规范](docs/09-开发规范.md) | PEP 8 / Git 规范 / 测试标准 |

---

## License

MIT © 70548887
