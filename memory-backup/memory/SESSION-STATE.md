# SESSION-STATE.md — 热记忆层

> 最后更新：2026-04-22 14:50
> 版本：v2.1

---

## 当前主线

**项目：** reverse-ai-engine
**仓库：** https://github.com/70548887/reverse-ai-engine
**目标：** 逆向工程自动化系统（网页逆向 + APP逆向）
**当前阶段：** P1 控制器完成，开始 daily/project memory 建设

---

## 项目进度

| 步骤 | 状态 | 说明 |
|------|------|------|
| 1. GitHub 仓库建立 | ✅ 完成 | reverse-ai-engine，9篇开发文档 |
| 2. 逆向工具链安装 | ✅ 完成 | mitmproxy/frida/jadx/apktool/Java |
| 3. 记忆能力修复 | ✅ 完成 | Qdrant MCP 已配置（但服务端不稳定） |
| 4. 热记忆层建立 | ✅ 完成 | SESSION-STATE.md 已建立 |
| 5. 本地目录结构 | ✅ 完成 | memory/projects/scripts/tools + tasks/intake/queue/status |
| 6. 记忆持久化 | ✅ 完成 | 关键信息写入 memory tool |
| 7. P1 控制器开发 | ✅ 完成 | reverse-controller.py，双Pipeline，demo通过 |
| 8. L0-L6 记忆层完善 | ✅ 完成 | 2026-04-24 全面归档，memory-sync.py 就绪 |
| 9. 同步脚本 | ✅ 完成 | scripts/memory-sync.py，L0-L5 全自动 |

---

## 系统能力现状

### 记忆层
| 层次 | 状态 | 详情 |
|------|------|------|
| Qdrant 向量库 | ✅ 可用 | 152.136.169.127:6333，collection: reverse_engineering (76条)，mem0_memories (2条) |
| memory 持久化 | ✅ | 7条关键记忆，含路径/配置/凭证 |
| session_search | ✅ | 跨会话历史搜索 |
| SESSION-STATE.md | ✅ | 热记忆在 /opt/data/home/.openclaw/workspace/ |

### 工具链
| 工具 | 版本 | 路径 |
|------|------|------|
| Node.js | v22.14.0 | /opt/data/home/nodejs/bin/ |
| Python | 3.13.5 | 系统自带 |
| mitmproxy | 12.2.2 | /opt/data/home/reverse-tools/ |
| frida-tools | 17.9.1 | /opt/data/home/reverse-tools/ |
| jadx | 1.4.7 | /opt/data/home/reverse-tools/ |
| apktool | 2.7.0 | /opt/data/home/reverse-tools/ |
| Java (Temurin) | 17 | /opt/data/home/reverse-tools/java/ |

---

## 关键路径速查

```
/opt/data/home/.openclaw/workspace/
├── SESSION-STATE.md          ← 热记忆（当前主线/blocker/下一步）
├── scripts/
│   └── reverse-controller.py ← P1 核心控制器（✅已完成）
├── memory/
│   ├── projects/             ← 项目专题长期记忆
│   ├── scripts/              ← 自动化脚本
│   └── tools/                ← 工具配置
└── tasks/
    ├── intake/pending/       ← 待处理任务入口
    ├── queue/                ← 工单队列（判重）
    └── status/               ← 执行状态追踪

/opt/data/home/reverse-tools/  ← 逆向工具链
/tmp/reverse-ai-engine/       ← GitHub 克隆副本
```

---

## Blocker

- **Qdrant 服务端已稳定**：152.136.169.127:6333，reverse_engineering collection 正常
- **真实 embedding 召回待实现**：recall_memories 降级为 scroll 返回最新记录，需重建后用 BGE 模型恢复

---

## 下一步动作

- [x] 重建 openclaw_memory collection（Qdrant MCP / 端口 32768）→ 已确认用 6333 端口，collection 正常
- [ ] 导入 reverse-ai-engine 文档向量（BGE bge-small-zh-v1.5）
- [ ] 建立 memory/2026-04-24.md 每日记忆
- [ ] 建立 memory/projects/reverse-ai-engine.md 项目专题
- [ ] 配置 systemd 事件驱动触发

---

<!-- AUTO LOG -->
<!-- 2026-04-22T13:09:23 -->
<!-- current_main: ✅ 已完成: demo-web-sig-20260422 | status: done -->

<!-- AUTO: 2026-04-24T12:26:06.994089 -->
- current_main: ✅ 已完成: p2b-pipeline-verify-20260424
- status: done

<!-- AUTO: 2026-04-24T12:34:36.225347 -->
- current_main: ✅ 已完成: p2a-xhs-note-20260424
- status: done
