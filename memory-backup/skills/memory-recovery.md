---
name: memory-recovery
description: 对话断层后，从 Qdrant+文件层恢复项目上下文 — 快速还原项目状态、工具配置和未完成任务
---

# Memory Recovery — 断层上下文恢复

## 触发条件

每次遇到以下情况，**必须**先执行本 skill：
- 用户说"你断层记忆了吗"、"还记得吗"
- 新会话开始，提到之前做过的项目/任务
- 任务中断后继续
- session_search 无结果时

## 恢复流程（按顺序执行）

### Step 1 — 搜 Qdrant（语义搜索）
```bash
python3 /opt/data/home/.openclaw/workspace/memory/scripts/memory-sync.py search "<项目关键词>"
```

### Step 2 — 读取最相关的 .md 文件
根据搜索结果的 `📁 full_path`，用 `read_file` 读取内容。

### Step 3 — 还原上下文
把 .md 文件的 `summary` + 关键结论 整理成一段文字，直接告诉用户：
- 项目当前状态
- 最后做到哪
- 下一步是什么

---

## 常用搜索词

| 场景 | 搜索词 |
|------|--------|
| reverse-ai-engine 项目 | `reverse-ai-engine 项目架构 控制器` |
| 逆向进展 | `知乎签名逆向 小红书 webpack 抖音` |
| 工具配置 | `jadx frida mitmproxy 安装 配置` |
| APP 逆向计划 | `APP 逆向 手机 frida 抓包` |
| 记忆系统搭建 | `memory sync qdrant 记忆持久化` |

---

## 快速验证

```bash
# 验证检索是否正常
python3 /opt/data/home/.openclaw/workspace/memory/scripts/memory-sync.py search "reverse-ai-engine"

# 查看 memory 目录当前文件
ls /opt/data/home/.openclaw/workspace/memory/projects/
```

---

## 关键约定

- 每次项目有重大进展 → 必须用 `memory-write.py` 写记忆文件
- 写完自动触发 sync（`--no-sync` 除外）
- 文件命名：`YYYY-MM-DD_<category>_<slug>.md`
- Frontmatter 必须有 `title` + `category` + `summary`

---

## 记忆写入触发条件

**立即写入：**
- 完成一个逆向目标（知乎/小红书/抖音等）
- 发现关键配置或 bug 解决方案
- 创建新的 skill
- 方案选型结论（选 A 不选 B 的原因）

**建议写入：**
- 对话结束前
- 每次主要任务切换时
- 发现工具链问题及解决过程

