# reverse-ai-engine

> AI 驱动的自动化逆向工程系统 — Web & App 逆向引擎，支持 JS 逆向、APP 逆向、签名算法提取、事件驱动的无人值守任务流水线。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 系统定位

本项目旨在实现**无人值守、全自动、可持续**的逆向工程任务执行。

> 核心目标：将逆向工程师从重复性逆向任务中解放出来，由 AI 自动完成目标分析、算法提取、脚本生成、结果验证的全流程。

---

## 核心能力

| 能力 | 说明 |
|------|------|
| 🌐 **Web 逆向** | JS 逆向、签名算法提取、混淆还原、API 协议分析、登录态模拟 |
| 📱 **APP 逆向** | APK/IPA 反编译、SO 层分析、Frida 动态 Hook、SSL Pinning 绕过 |
| 🔐 **加密算法** | RSA/AES/DES/HMAC 等常见加密算法的识别与 Python 重写 |
| 🤖 **AI 控制器** | 任务自动拆解、智能决策、步骤编排、双执行器分流 |
| 🧠 **记忆系统** | 热记忆 + 每日记忆 + 专题记忆 + 向量召回 + Git 审计 |
| ⚡ **事件驱动** | systemd path 触发 + timer 保底巡检，替代高频轮询 |

---

## 架构概览

```
用户 / 外部系统
       ↓
   任务入口 (自然语言 / API / 定时发现)
       ↓
┌──────────────────────────────────────────┐
│         AI 控制器层 (Brain)               │
│  • 理解任务意图                           │
│  • 拆解执行步骤                           │
│  • 判断完成 / blocked / retry            │
│  • 分配执行器                             │
└──────┬─────────────────┬────────────────┘
       │                 │
┌──────▼──────┐  ┌───────▼───────┐  ┌────────▼────────┐
│ Codex 执行器 │  │ M2.7 执行器   │  │ 专用工具执行器    │
│ (主推进)     │  │ (second-opinion│  │ mitmproxy/Frida │
└─────────────┘  └───────────────┘  └─────────────────┘
       │
       ↓
┌──────────────────────────────────────────┐
│  逆向工具生态: 浏览器 / Frida / APKTool   │
│              Jadx / mitmproxy / Python    │
└──────────────────────────────────────────┘
       ↓
┌──────────────────────────────────────────┐
│  交付层: 结果脚本 / 数据 / 凭证 / 文档    │
└──────────────────────────────────────────┘
```

---

## 目录结构

```
reverse-ai-engine/
├── README.md
├── docs/
│   ├── 01-系统架构.md
│   ├── 02-任务类型定义.md
│   ├── 03-控制器设计.md
│   ├── 04-执行器分工.md
│   ├── 05-记忆层设计.md
│   ├── 06-触发机制.md
│   ├── 07-逆向工具链.md
│   ├── 08-交付标准.md
│   └── 09-开发规范.md
├── scripts/
│   ├── reverse-controller.py       # 逆向主控制器 ⭐
│   ├── web-reverse-engine.py       # Web 逆向执行器
│   ├── app-reverse-engine.py       # APP 逆向执行器
│   ├── frida-task-executor.sh      # Frida 任务执行器
│   ├── browser-control.py          # 浏览器控制
│   ├── auto-task-runner.py         # 自动任务主控
│   └── memory-backup.sh            # 记忆备份
├── tools/
│   ├── browsers/                   # 浏览器环境
│   │   └── stealth/                # 反检测脚本
│   ├── frida/
│   │   ├── scripts/                # Frida 脚本库
│   │   │   ├── ssl-unpinning.js
│   │   │   ├── baidu-signature.js
│   │   │   └── generic-hook.js
│   │   └── server/
│   ├── apktool/
│   ├── jadx/
│   ├── mitmproxy/
│   └── python-utils/
│       ├── js-deobfuscator/
│       ├── crypto-utils/
│       └── signature-detector/
├── tasks/                          # 任务队列
│   ├── intake/                     # 入口
│   ├── queue/                      # 工单队列
│   └── status/                     # 执行状态
├── memory/                         # 记忆层
│   ├── YYYY-MM-DD.md               # 每日记忆
│   └── projects/                   # 项目专题
│       ├── web-reverse/
│       └── app-reverse/
└── .github/
    └── workflows/
        └── ci.yml
```

---

## 任务类型定义

### Web 逆向

| 类型 | 子类型 | 示例目标 |
|------|--------|---------|
| JS 逆向 | 签名算法提取 | 某网站 `/api/*` 的 sig 参数 |
| | 混淆还原 | JSfuck / AAEncode / Obfuscator |
| | 通讯协议 | WebSocket / GraphQL / SSE |
| | 验证码识别 | 佟硕 / GT / 陀螺 |
| API 逆向 | 鉴权参数生成 | token / sig / nonce / timestamp |
| | 加密 BODY | 请求体加密解析 |
| | 请求指纹 | X-Request-ID / ETag |
| 登录态 | SSO 单点登录 | OAuth / SAML |
| | 加密登录 | 密码 RSA 加密 |
| | 模拟登录 | 验证码 / 短信 |

### APP 逆向

| 平台 | 子类型 | 说明 |
|------|--------|------|
| Android | Java 层逆向 | jadx 反编译 |
| | SO 层逆向 | Frida / native hook |
| | 签名算法 | 自行算法 / 第三方 SDK |
| | SSL Pinning | 绕过证书绑定 |
| iOS | 结构分析 | class-dump |
| | 运行时 Hook | Frida / Cycript |
| 跨平台 | Flutter / React Native | 特殊处理 |

---

## 开发文档索引

| 文档 | 内容 |
|------|------|
| [01-系统架构](./docs/01-系统架构.md) | 整体架构、模块关系、核心设计原则 |
| [02-任务类型定义](./docs/02-任务类型定义.md) | 任务分类体系、工单格式、判重规则 |
| [03-控制器设计](./docs/03-控制器设计.md) | 决策流程、状态机、执行 DAG |
| [04-执行器分工](./docs/04-执行器分工.md) | Codex / M2.7 / 专用工具的分流规则 |
| [05-记忆层设计](./docs/05-记忆层设计.md) | 5层记忆体系、向量化、召回健康检查 |
| [06-触发机制](./docs/06-触发机制.md) | 事件驱动、定时发现、systemd 单元设计 |
| [07-逆向工具链](./docs/07-逆向工具链.md) | 工具安装、配置、使用方法 |
| [08-交付标准](./docs/08-交付标准.md) | 结果归档、追溯、验收条件 |
| [09-开发规范](./docs/09-开发规范.md) | 代码风格、提交规范、PR 流程 |

---

## 快速开始

### 环境要求

- Python 3.10+
- Node.js 18+
- Git
- Chrome Headless / Firefox DevTools
- Frida
- mitmproxy

### 克隆

```bash
git clone https://github.com/70548887/reverse-ai-engine.git
cd reverse-ai-engine
```

### 初始化

```bash
# 安装 Python 依赖
pip install -r requirements.txt

# 安装 Node 工具
npm install

# 初始化子模块
git submodule update --init
```

### 下发第一个任务

```bash
# 通过 CLI 下发 Web 逆向任务
python3 scripts/reverse-controller.py web \
    --target https://example.com/api/search \
    --method POST \
    --output ./results/example-signature
```

---

## License

MIT © 70548887
