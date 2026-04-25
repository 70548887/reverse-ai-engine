---
name: memory-habit
description: 养成在对话中主动归档上下文的习惯 — 触发条件 + 写入命令 + 自动同步
---

# Memory Habit — 主动归档工作流

每次对话中或结束时，**主动**将关键上下文写入记忆层。

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

