---
name: memory-habit
description: 养成在对话中主动归档上下文的习惯 — 触发条件 + 写入命令 + 自动同步
---

# Memory Habit — 主动归档工作流

每次对话中或结束时，**主动**将关键上下文写入记忆层。

## Session 启动恢复流程（重要！）

新 session 开始时，按顺序执行以下命令，恢复上下文：

```bash
# 1. 读取当前主线状态
cat /opt/data/home/.openclaw/workspace/SESSION-STATE.md

# 2. 读取最近2天的每日记忆
ls -t /opt/data/home/.openclaw/workspace/memory/2026-*.md | head -2 | xargs cat

# 3. 读取项目记忆
cat /opt/data/home/.openclaw/workspace/memory/projects/reverse-ai-engine.md

# 4. 检查积压任务
cat /opt/data/home/.openclaw/workspace/tasks/queue/*.jsonl 2>/dev/null || echo "无积压"
```

或者用一行脚本：
```bash
python3 /opt/data/home/.openclaw/workspace/memory/scripts/memory-sync.py restore
```

> ⚠️ 由于 Hermes 无 session-start-hook，每次新 session 都需要先跑以上命令恢复上下文。  
> 这是当前架构限制，记忆已写入本地文件，但读取需要手动触发。

## 触发条件（符合任一即写）

| 条件 | 行动 |
|------|------|
| 完成了逆向目标（✅/❌） | 写 `projects/` 归档 |
| 发现工具 bug / 解决方案 | 写 `tools/` 记录 |
| 方案选型完成 | 写 `projects/` 归档 |
| 调研结论 | 写对应分类 |
| 对话结束前 | 写 `session/` 总结 |
| 发现了新 APP 的突破口 | 写 `projects/` |

## 写入命令模板

```bash
# 项目进展
python3 memory-write.py \
  --title "知乎 x-zse-96 逆向完成" \
  --category project \
  --tags "知乎,签名,jsvmp,sm4,完成" \
  --summary "知乎 x-zse-96 VM 签名纯算实现完成，SM4 CBC + 位混洗，产出 zhihu_sign_pure.js" \
  --body "## 关键结论\n- ✅ JSVMP 识别完成\n- ✅ SM4 CBC 算法提取\n- ✅ 位混洗逻辑还原\n\n## 关键文件\n- zhihu_sign_pure.js" \
  --related-projects reverse-ai-engine

# 会话总结
python3 memory-write.py \
  --title "与 Cade 的对话总结 — 2026-04-25" \
  --category session \
  --tags "summary,cade,对话" \
  --summary "讨论了记忆系统优化，确定方案C（Qdrant+文件层），落地了 memory-sync.py 和 memory-write.py" \
  --body "## 主要话题\n..." \
  --related-projects reverse-ai-engine
```

## 快捷别名（可加到 shell profile）

```bash
alias mw='python3 /opt/data/home/.openclaw/workspace/memory/scripts/memory-write.py'
alias ms='python3 /opt/data/home/.openclaw/workspace/memory/scripts/memory-sync.py'
alias msr='python3 /opt/data/home/.openclaw/workspace/memory/scripts/memory-sync.py search'
```

## 自动同步

- `memory-write.py` 默认自动 sync
- 每小时 cronjob 自动全量 sync
- `ms sync` 可手动触发

## 验证当前状态

```bash
ls /opt/data/home/.openclaw/workspace/memory/projects/
python3 memory-sync.py search "reverse-ai-engine"
```

## 逆向阶段归档完成检查清单

当用户要求“归档 status/memory/SESSION 并同步”或上下文压缩后只剩归档任务时，按以下顺序一次性闭环，不要只口头总结：

1. 校验核心产物都存在且非空：`analysis/*.json`、`analysis/*.md`、`analysis/*conclusion*.md`、静态脚本、`tasks/status/*.json`、`memory/projects/*.md`、当日 daily memory、`SESSION-STATE.md`。
2. 对 status JSON 做字段抽查，至少确认 `candidate_count`、hook/probe count、`algorithm_status`；若分析 JSON 不含这些汇总字段，以 status JSON 为准。
3. 对 conclusion / project memory / daily / SESSION 做文本标记抽查，确认包含阶段号、`algorithm_status` 或关键结论。
4. 执行 `cd /opt/data/home/.openclaw/workspace && python3 memory/scripts/memory-sync.py sync`。
5. 立刻执行 `memory-sync.py search "<阶段号> <核心关键词> algorithm_status"`，确认新项目记忆 Top 命中。
6. 检查无遗留阶段分析进程，例如 `ps -ef | grep -E 'static_vXX|run_vXX|vXX_' | grep -v grep || true`。
7. 若有会话 todo，把归档项标记 completed，再向用户报告：文件、同步结果、搜索命中、算法状态、遗留进程状态。


