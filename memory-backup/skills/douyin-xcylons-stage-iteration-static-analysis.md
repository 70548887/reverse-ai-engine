---
name: douyin-xcylons-stage-iteration-static-analysis
description: 抖音 X-Cylons 多阶段静态挖掘脚本迭代与归档验证流程，避免复制上一轮脚本时输入源/版本/key 错配
tags: ["douyin", "x-cylons", "static-analysis", "reverse-engineering", "workflow"]
---

# Douyin X-Cylons 阶段迭代静态分析流程

## 适用场景

当用户说“继续”“基于 vXX focused set 继续做下一轮”“实现并运行 vYY 静态挖掘并归档”时使用。尤其适合从上一轮 JSON/脚本派生下一轮分析脚本，例如 v126 → v127 origin-firstseen closure/value-flow。

## 核心流程

1. **确定上一轮输入与本轮输出**
   - 上一轮 JSON：`V<prev>=...v<prev>_*.json`
   - 上一轮脚本：`V<prev>_SCRIPT=...static_v<prev>_*.py`
   - 本轮输出：`JOUT/MOUT/COUT=...v<curr>_*.{json,md}`
   - Status：`tasks/status/douyin_xcylons_v<curr>_*.json`
   - Project memory：`memory/projects/...v<curr>...md`

2. **复制脚本后先做版本一致性修正**
   - `importlib.util.spec_from_file_location()` 的模块名和变量名应跟输入版本一致，例如 `v126mod`，不要保留复制来的 `v127mod`。
   - `collect_seeds()` 参数名应是上一轮对象，例如 `collect_seeds(v126)`。
   - seed group key 必须匹配上一轮 JSON 的真实字段，例如 `priority_origin_firstseen_*`，不要误用不存在的 `priority_closure_*`。
   - `input_sources` 应包含上一轮 JSON、SO、上一轮脚本，便于事后审计。

3. **快速验证脚本没有自引用/空输入**
   ```bash
   python3 -m py_compile /path/to/static_v<curr>_*.py && \
   python3 /path/to/static_v<curr>_*.py
   ```
   若出现 `NameError`、文件不存在、`trace_record_count=0` 或 hook/probe count 异常，优先检查版本常量、import module 变量、seed key，而不是扩大静态搜索。

4. **产物与字段抽查**
   - 校验 JSON/MD/conclusion/status/project memory/daily/SESSION 均存在且非空。
   - 对 status JSON 至少抽查：`trace_record_count`、`high_priority_trace_count`、`*hook_set_count` 或 `hook_set_count`、核心 probe count、`algorithm_status`。
   - 明确区分“接口/边界/hook set 继续收敛”和“算法本体还原”：只要没有真实 ACK/X-Cylons/SSL first-seen 同值动态证据，`algorithm_status` 仍为 `not_recovered`。

5. **归档同步验证**
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   python3 memory/scripts/memory-sync.py search "douyin-xcylons-v<curr>-<slug>"
   ps -ef | grep -E 'static_v<curr>|run_v<curr>|v<curr>_' | grep -v grep || true
   ```
   broad semantic query 可能被旧阶段相似文本稀释；若 `<阶段号> <关键词> algorithm_status` 未命中新项目，追加精确 slug 搜索。精确 slug Top1 命中即可视为同步验证通过。

## v127 经验教训

v127 派生时曾出现脚本仍引用错误的 `V127/V127_SCRIPT/v127mod` 和 `priority_closure_*` 输入字段。修正为 `V126/V126_SCRIPT/v126mod` 与 `priority_origin_firstseen_*` 后，脚本成功产出：

```text
trace_record_count = 11200
high_priority_trace_count = 11200
closure_value_flow_bitmix_return_boundary_probe_count = 10350
closure_value_flow_return_arg_slot_pair_probe_count = 850
hook_set_count = 144
algorithm_status = not_recovered
```

## v128 经验教训

v128 从 v127 compact closure/value-flow 记录继续派生时，复用同一阶段迭代框架，但本轮目标改为 `origin/fanin` 收敛：把 origin-side producer fanin、first-use/consumer fanin、return-to-arg/return-to-slot 桥、slot materialization、absent-before origin lane、nearby bitmix/crypto-like lane、runtime-chain/pre-post boundary calls 聚合到候选节点，并输出 focused hook set。

建议命名与产物 slug 明确包含本轮意图，例如：

```text
static_v128_focused_closure_value_flow_origin_fanin_0515.py
v128_focused_closure_value_flow_origin_fanin_static_0515.json
v128_focused_closure_value_flow_origin_fanin_conclusion_0515.md
douyin_xcylons_v128_0515.json
2026-05-15_project_douyin-xcylons-v128-closure-value-flow-origin-fanin.md
```

v128 成功产出后关键抽查字段：

```text
seed_record_count = 2
trace_node_count = 28
high_priority_trace_count = 21
origin_fanin_event_total_count = 789
v128_focused_closure_value_flow_origin_fanin_hook_set_count = 659
algorithm_status = not_recovered
new_value_source_evidence = false
proven_algorithm_evidence = false
first_seen_evidence = false
```

本轮经验：当上一轮记录已经较“窄”（例如只有 2 条 seed record、28 个 trace node）时，不要用总量下降误判失败；应同时检查 hook_set_count、event_total_count、probe 分类是否符合本轮 focused 目标。只要没有 clean X-Cylons value source、first-seen 同值窗口或 proven algorithm 证据，报告仍必须明确“静态 hook placement 扩展，不是算法本体恢复”。

## v129 → v130 经验教训

v129 已经把 v128 origin/fanin 收敛转换为动态 probe manifest；当 active task 进入 v130“hook manifest 压缩/动态执行包生成”时，不要再盲目扩大静态候选。先读取：

```text
/opt/data/home/reverse-tools/douyin_analysis/v129_focused_origin_fanin_dynamic_probe_manifest_static_0515.json
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v129_0515.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-15_project_douyin-xcylons-v129-origin-fanin-dynamic-probe-manifest.md
```

v129 关键基线字段：

```text
v129_probe_node_count = 28
v129_high_priority_probe_count = 13
v129_same_value_first_seen_candidate_count = 3
v129_slot_lifecycle_same_value_candidate_count = 6
v129_producer_consumer_boundary_candidate_count = 4
v129_return_slot_bridge_candidate_count = 13
v129_hook_manifest_addr_count = 724
v129_focused_dynamic_hook_set_count = 740
v129_hook_spec_total_count = 2214
algorithm_status = not_recovered
```

v130 的正确方向是“压缩可执行动态包”，而不是“继续扩 hook”：按 `dynamic_probe_class` / `dynamic_score` / `spec_count` / control anchors 分层，生成 Frida 可运行配置、prioritized address groups、capture policy、runbook/checklist。建议分组：same-value first-seen、slot lifecycle、producer-consumer boundary、return-slot bridge、absent-before/context guard、carry/package + SSL/WS-send controls。静态压缩包本身不能升级算法状态；除非真实 ACK/X-Cylons/SSL 同值 first-seen 动态证据出现，`algorithm_status` 仍为 `not_recovered`。

v130 脚本产物通常会包含 `set()` 去重后的地址、role、node_refs 等中间结构；写 JSON 前必须统一转换为 sorted list / list，否则 `json.dumps` 会报 `TypeError: Object of type set is not JSON serializable`。修复后重新执行 `python3 -m py_compile` 与脚本本体，并验证 JSON/MD/config/runbook/status 均非空。

## v130 → v131 经验教训

v130 已经完成 focused hook manifest compression / execution package；v131 的正确方向不是再扩展 hook set，而是把 v130 的 6 个压缩执行包转为真正可运行、可分析的动态 harness：per-pack JSON configs、Frida runner、JS hook template、strict log analyzer。

v131 生成与验证时应重点检查这些产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/v131_dynamic_pack_harness_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v131_dynamic_pack_harness_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v131_dynamic_pack_harness_conclusion_0515.md
/opt/data/home/reverse-tools/douyin_analysis/run_v131_focused_pack_runner_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v131_focused_pack_hook_template_0515.js
/opt/data/home/reverse-tools/douyin_analysis/analyze_v131_dynamic_pack_log_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v131_pack_configs_0515/
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v131_0515.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-15_project_douyin-xcylons-v131-dynamic-pack-harness.md
```

v131 成功产出后关键抽查字段：

```text
v130_execution_pack_count = 6
v130_unique_compressed_addr_count = 371
v131_pack_config_count = 6
v131_runner_script_count = 3
v131_unique_runtime_addr_count = 371
v131_strict_evidence_event_count = 0
dynamic_harness_ready = true
algorithm_status = not_recovered
new_value_source_evidence = false
proven_algorithm_evidence = false
first_seen_evidence = false
```

本轮经验：`v131_strict_evidence_event_count=0` 在静态 packaging pass 中是预期边界，不是失败；它表示还没有真实直播间 ACK/X-Cylons/SSL first-seen 动态日志。报告时必须说明 v131 是“动态执行 enablement / harness ready”，不是算法恢复。下一步应在真实直播间窗口 force-stop/early attach 后优先运行 `pack_00_guards_then_controls` 与 `pack_01_same_value_first_seen`，再用 `analyze_v131_dynamic_pack_log_0515.py` 分析严格事件。只有出现 absent-before / first-after same-value downstream alignment 或明确 opaque/sign callback output，才能升级 `algorithm_status`。

归档验证时，broad query 如 `v131 dynamic pack harness algorithm_status not_recovered` 应能命中 project memory；同时追加精确 slug `douyin-xcylons-v131-dynamic-pack-harness` 搜索，Top1 命中即可确认同步层可检索。最后检查 `ps -ef | grep -E 'static_v131|run_v131|v131_' | grep -v grep || true` 无残留进程。

## v131 → v132 经验教训

v132 的正确方向是对 v131 动态 harness 做“pack-run readiness 静态审计 + 真实直播间运行矩阵 + 多日志证据汇总器”，而不是继续扩大 hook set，也不是在没有 live log 时声称算法恢复。

v132 生成与验证时应检查/产出这些文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v132_pack_run_readiness_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v132_pack_run_readiness_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v132_pack_run_readiness_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v132_pack_run_readiness_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v132_pack_run_matrix_0516.json
/opt/data/home/reverse-tools/douyin_analysis/run_v132_pack_sequence_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v132_dynamic_evidence_0516.py
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v132_0516.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-16_project_douyin-xcylons-v132-pack-run-readiness.md
```

实现要点：

1. 输入源必须来自 v131：`v131_dynamic_pack_harness_static_0515.json`、`run_v131_focused_pack_runner_0515.py`、`v131_focused_pack_hook_template_0515.js`、`analyze_v131_dynamic_pack_log_0515.py`、`v131_pack_configs_0515/`。
2. 对 v131 runner/analyzer 先 `python3 -m py_compile`，再枚举 6 个 pack config，统计 hook_count、unique_addr_count、duplicate_addr_count、runtime_role、control anchors、dynamic_probe_class_counts。
3. 生成 `v132_pack_run_matrix_0516.json`，优先级建议：
   - `pack_00_guards_then_controls`：180s，baseline absent-before/control context。
   - `pack_01_same_value_first_seen`：240s，主 same-value first-seen probe。
   - `pack_03_producer_consumer_boundary`、`pack_04_return_slot_bridge`、`pack_02_slot_lifecycle`：补充边界。
   - `pack_05_all_high_priority`：300s，仅在窄包后做 stress merged pass。
4. `run_v132_pack_sequence_0516.py` 应只负责编排调用 v131 runner、设置默认 `ADB_SERVER_SOCKET=tcp:10.0.2.2:5037`、把每个 pack 的 stdout 落到 `v132_live_logs_0516/*.jsonl`；必须支持 `--dry-run`，便于无设备/无直播间时验证命令展开。
5. `analyze_v132_dynamic_evidence_0516.py` 可以汇总多个日志、计数 strict value/control 事件并给 preview，但不要自动升级证据；输出默认仍应为 `algorithm_status=not_recovered`，`first_seen_evidence=false`，除非人工确认 strict same-value downstream alignment。

v132 成功产出后关键抽查字段：

```text
v131_pack_config_count = 6
v132_pack_summary_count = 6
v132_unique_runtime_addr_count = 371
v132_run_entry_count = 6
v132_generated_runner_count = 1
v132_generated_analyzer_count = 1
v132_dynamic_execution_performed = false
v132_strict_evidence_event_count = 0
dynamic_harness_ready = true
v132_run_readiness_ready = true
strict_log_analyzer_ready = true
algorithm_status = not_recovered
new_value_source_evidence = false
proven_algorithm_evidence = false
first_seen_evidence = false
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v132_pack_run_readiness_0516.py run_v132_pack_sequence_0516.py analyze_v132_dynamic_evidence_0516.py
python3 run_v132_pack_sequence_0516.py --dry-run --packs pack_00_guards_then_controls,pack_01_same_value_first_seen
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v132-pack-run-readiness"
ps -ef | grep -E 'static_v132|run_v132|v132_' | grep -v grep || true
```

报告口径：v132 是“动态执行准备增强 / run-readiness ready”，不是算法恢复；没有真实 live-room ACK/X-Cylons/SSL first-seen 日志时，`v132_strict_evidence_event_count=0` 是预期边界，不是失败。

## Context compaction / stale active-task handling

当上下文压缩后用户只说“继续”，且 active task 指向较早阶段（例如 `基于 v76 focused set 生成 v77`），不要直接重跑或覆盖产物。先做恢复性核验：

1. 读取对应 `tasks/status/douyin_xcylons_v<curr>_*.json`、`v<curr>_*_conclusion_*.md`、`v<curr>_*_static_*.md/json`，确认产物是否已存在且状态是否 completed。
2. 若产物已存在，优先进入验证/归档步骤：`memory-sync.py sync` + 精确 slug 搜索 + `ps -ef | grep -E 'static_v<curr>|run_v<curr>|v<curr>_'` 检查残留进程。
3. 只有在 status 缺失、产物为空、计数字段异常或明确需要重新生成时，才复制/修改脚本并重跑。
4. 报告时说明“已验证既有 v<curr> 产物”而不是暗示刚刚重新完成生成，避免混淆实际工作与恢复性核验。

v77 恢复性核验经验：context compaction 后 active task 仍显示 v77 in_progress，但文件系统中已存在 `/opt/data/home/reverse-tools/douyin_analysis/v77_focused_set_source_neighborhood_*_0514.{json,md}` 与 status `douyin_xcylons_v77_0514.json`，且 memory-sync 精确搜索 Top1 命中 project memory；此时正确动作是验证并标记 t2/t3 completed，不应盲目重跑 v77。

## Max tool iteration / interrupted continuation handling

当用户要求继续某个阶段（例如 v131 → v132），但工具调用轮次在恢复性核验后耗尽，必须把状态明确标成“部分完成”，不要暗示新阶段产物已经生成。

推荐口径：

1. 明确列出已真实完成的动作：例如已读取上一轮 project memory/status、确认上一轮 key counts、确认下一轮入口方向。
2. 明确列出未完成动作：例如尚未检查 pack config 实体、尚未生成 `v<curr>` JSON/MD/conclusion/status、尚未 memory-sync。
3. Todo 状态应保持对应任务 `in_progress`，不要标 completed。
4. 对 v131 → v132 这种阶段，若只恢复到 v131 baseline，应说明 v132 正确入口是基于 v131 pack harness 的真实直播间 pack-run/readiness/analyzer 汇总，优先 `pack_00_guards_then_controls` 与 `pack_01_same_value_first_seen`，而不是继续扩大静态层级。
5. 算法边界必须保持保守：没有 strict first-seen、absent-before/first-after same-value downstream alignment 或明确 opaque/sign callback output，就继续报告：
   ```json
   {
     "algorithm_status": "not_recovered",
     "new_value_source_evidence": false,
     "proven_algorithm_evidence": false,
     "first_seen_evidence": false
   }
   ```

### v132 interrupted preflight 经验

当上下文压缩后 active task 已进入 `v132 后续挖掘/动态准备脚本`，但只能做少量恢复性工具调用时，优先做最小 preflight，而不是马上写新阶段产物：

1. 读取并确认 v131 基线：
   ```text
   /opt/data/home/reverse-tools/douyin_analysis/v131_dynamic_pack_harness_static_0515.json
   ```
   关键字段应仍为：`dynamic_harness_ready=true`、`dynamic_execution_performed=false`、`strict_log_analyzer_ready=true`、`algorithm_status=not_recovered`。
2. 确认 v131 pack config 实体齐全：
   ```text
   /opt/data/home/reverse-tools/douyin_analysis/v131_pack_configs_0515/pack_00_guards_then_controls.json
   /opt/data/home/reverse-tools/douyin_analysis/v131_pack_configs_0515/pack_01_same_value_first_seen.json
   /opt/data/home/reverse-tools/douyin_analysis/v131_pack_configs_0515/pack_02_slot_lifecycle.json
   /opt/data/home/reverse-tools/douyin_analysis/v131_pack_configs_0515/pack_03_producer_consumer_boundary.json
   /opt/data/home/reverse-tools/douyin_analysis/v131_pack_configs_0515/pack_04_return_slot_bridge.json
   /opt/data/home/reverse-tools/douyin_analysis/v131_pack_configs_0515/pack_05_all_high_priority.json
   ```
3. 确认上一轮 project memory 存在：
   ```text
   /opt/data/home/.openclaw/workspace/memory/projects/2026-05-15_project_douyin-xcylons-v131-dynamic-pack-harness.md
   ```
4. 如果工具轮次耗尽于上述 preflight，最终回复必须明确：`v132 产物尚未生成/未归档`，未完成项包括 runner/template/analyzer 内容检查、v132 脚本创建与运行、JSON/MD/conclusion/status/memory/SESSION 写入、memory-sync 与 closure check。
5. 下次继续 v132 时，从 v131 runner、JS template、strict analyzer 与 pack configs 入手，生成“pack-run/readiness/analyzer 汇总或真实日志分析”产物；没有真实动态日志时仍只能归类为动态准备增强，不能升级算法。

## v132 → v133 经验教训

v133 的正确方向是把 v132/v131 的 pack-run readiness 进一步包装成“可直接 early-attach 执行”的 operational package：preflight、force-stop/launch sequence wrapper、live execution matrix、strict first-seen alignment analyzer、runbook。它仍不是算法恢复阶段；没有真实直播间 live log 时，必须保持 `algorithm_status=not_recovered`。

v133 生成与验证时应检查/产出这些文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v133_early_attach_execution_package_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v133_early_attach_execution_package_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v133_early_attach_execution_package_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v133_early_attach_execution_package_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v133_live_execution_matrix_0516.json
/opt/data/home/reverse-tools/douyin_analysis/run_v133_early_attach_pack_sequence_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v133_firstseen_alignment_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v133_live_execution_runbook_0516.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v133_0516.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-16_project_douyin-xcylons-v133-early-attach-execution-package.md
```

v133 成功产出后关键抽查字段：

```text
v131_pack_config_count = 6
v132_run_entry_count = 6
v133_pack_summary_count = 6
v133_run_entry_count = 6
v133_unique_runtime_addr_count = 371
v133_generated_runner_count = 1
v133_generated_analyzer_count = 1
v133_generated_runbook_count = 1
v133_dynamic_execution_performed = false
v133_strict_evidence_event_count = 0
dynamic_harness_ready = true
v132_run_readiness_ready = true
v133_early_attach_execution_package_ready = true
algorithm_status = not_recovered
new_value_source_evidence = false
proven_algorithm_evidence = false
first_seen_evidence = false
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v133_early_attach_execution_package_0516.py
python3 static_v133_early_attach_execution_package_0516.py
python3 -m py_compile run_v133_early_attach_pack_sequence_0516.py analyze_v133_firstseen_alignment_0516.py
python3 run_v133_early_attach_pack_sequence_0516.py --dry-run --packs minimal
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "v133 early attach execution package algorithm_status not_recovered"
ps -ef | grep -E 'static_v133|run_v133|analyze_v133|v133_' | grep -v grep || true
```

v133 dry-run 的最小 pack 应展开为 `pack_00_guards_then_controls` 与 `pack_01_same_value_first_seen`；preflight 可接受当前 ADB 可见设备不同于旧记忆中的设备，只要 `adb devices` 返回可用 `device` 即可。报告口径：v133 是“early-attach operational execution package ready”，但 `v133_strict_evidence_event_count=0` 在未跑真实直播间日志时是预期边界，不是失败。

## v135 → v136 经验教训

v136 的正确方向是基于 v135 capture contract 生成“evidence bundle validator”，把真实直播间日志、schema、runner stdout、analyzer summary、命令环境快照与人工复核说明打包为可审计证据单元。它不是继续扩 hook，也不是算法恢复层。

v136 生成器/产物建议路径：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v136_capture_contract_evidence_bundle_validator_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v136_capture_contract_evidence_bundle_validator_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v136_capture_contract_evidence_bundle_validator_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v136_capture_contract_evidence_bundle_validator_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v136_evidence_bundle_manifest_0516.json
/opt/data/home/reverse-tools/douyin_analysis/run_v136_capture_contract_live_bundle_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v136_evidence_bundle_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v136_evidence_bundle_runbook_0516.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v136_0516.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-16_project_douyin-xcylons-v136-evidence-bundle-validator.md
```

v136 的严格升级门槛：只有同一请求窗口同时满足 `absent_before_ok=true`、`first_after_ok=true`、`downstream_carry_ok=true`、`same_request_window_ok=true`，并且同一个干净 X-Cylons/ACK 值或稳定 hash 在 candidate 与下游 SSL/WS/webcast 控制点之间一致，才能人工升级到 `candidate_dynamic_alignment_needs_algorithm_recovery`。即使满足也不能标记为 proven algorithm；真正算法恢复仍要求闭合的 opaque/sign callback 或 transform-to-X-Cylons 算法体。

如果工具轮次只够把 `static_v136_capture_contract_evidence_bundle_validator_0516.py` 写入磁盘，但尚未运行生成器，最终报告必须标注“部分完成”：生成器已落盘，但 JSON/MD/conclusion/status/memory 尚未生成，`py_compile`、`memory-sync` 和残留进程检查均未执行。下次继续时优先运行：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 static_v136_capture_contract_evidence_bundle_validator_0516.py
python3 -m py_compile run_v136_capture_contract_live_bundle_0516.py analyze_v136_evidence_bundle_0516.py
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v136-evidence-bundle-validator"
ps -ef | grep -E 'static_v136|run_v136|analyze_v136|v136_' | grep -v grep || true
```

报告口径仍保持保守：`algorithm_status=not_recovered`，不要把证据 bundle 准备或 validator 通过误报为算法本体还原。

## 报告口径

最终报告应包含：文件路径、核心计数、`algorithm_status`、是否已 sync、检索命中证据、遗留进程检查结果。若算法未恢复，要直接说明：本轮只收敛 hook/first-seen/value-flow 边界，仍需真实窗口动态同值验证。