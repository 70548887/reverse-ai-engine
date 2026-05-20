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
2. 对 status JSON 做字段抽查，至少确认 `candidate_count` 或 `trace_record_count`、hook/probe count、`algorithm_status`；若分析 JSON 不含这些汇总字段，以 status JSON 为准。注意部分阶段不会有通用 `hook_set_count` 字段，而是版本前缀字段（如 `v123_focused_first_seen_downstream_fanin_source_backtrace_hook_set_count`），抽查时应搜索 `*hook_set_count` / `*hook*count`，不要因通用字段为 null 误判缺失。
3. 对 conclusion / project memory / daily / SESSION 做文本标记抽查，确认包含阶段号、`algorithm_status` 或关键结论。
4. 执行 `cd /opt/data/home/.openclaw/workspace && python3 memory/scripts/memory-sync.py sync`。
5. 立刻执行 `python3 memory/scripts/memory-sync.py search "<阶段号> <核心关键词> algorithm_status" --category project`，确认新项目记忆命中；若 Top1 不是本轮文件，只要本轮 project memory 在 Top5 命中也可作为语义层可检索证据。注意当前 `memory/scripts/memory-sync.py` 的 CLI 会先把 `sys.argv[2:]` 拼成 query、再解析 `--category`，所以输出标题里的 query 可能包含 `--category project`；这是显示/embedding 噪声，不代表 category filter 未生效。若要避免该噪声，可不带 `--category`，改用结果路径中 `/memory/projects/` 与 `[project]` 标记人工确认。若 broad query（如 `<阶段号> <关键词> algorithm_status`）没有命中新项目记忆，立即追加一次精确 slug 搜索（例如 `python3 memory/scripts/memory-sync.py search "douyin-xcylons-v127-origin-firstseen-closure-value-flow"`）；精确 slug 命中 Top1 可作为同步验证通过，不要因 broad semantic search 被旧阶段相似文本稀释而误判归档失败。
6. 注意 workspace 里存在两个同名脚本：`memory/scripts/memory-sync.py` 才支持 `sync/search`；`scripts/memory-sync.py` 是按任务 status id 镜像归档的脚本，误用 `scripts/memory-sync.py sync` 会报 `任务目录不存在: .../tasks/status/sync`。
7. 检查无遗留阶段分析进程，例如 `ps -ef | grep -E 'static_vXX|run_vXX|vXX_' | grep -v grep || true`。
8. 若有会话 todo，把归档项标记 completed，再向用户报告：文件、同步结果、搜索命中、算法状态、遗留进程状态。

## 已知坑：长 Markdown 块写入方式

- 不要在 `execute_code` 里手写一大段嵌套 shell heredoc + Python 三引号 + 反引号 Markdown；在多层转义下容易出现 `SyntaxError: unexpected character after line continuation character`，导致 daily/SESSION 追加失败。
- 更稳的做法：优先用 `read_file` + `write_file` 或 `patch` 做文本追加/替换；若必须用 Python 脚本批量写入，先把 Markdown 块放进 Python 原生三引号字符串（不要再包一层 shell heredoc），或用 `json.dumps()`/`repr()` 注入字符串字面量。
- 对归档写入失败的恢复流程：先确认目标文件未被部分写入，再用最小化的单步写入重试；不要把写入、`memory-sync.py sync/search`、mem0 写入塞在同一个复杂脚本里。
- 如果 `execute_code` 返回 Python 解析期错误（例如 `IndentationError` / `SyntaxError`）且显示 `tool_calls_made=0`，通常代表脚本在执行前已失败、不会产生部分写入；可直接修正缩进/字符串后重跑完整的幂等归档脚本。为降低此类错误，批量归档脚本中避免长文件末尾残留单个缩进空格，先定义路径/文本，再统一写入和验证。


