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

## v136 → v137 interrupted preflight 经验

当上下文压缩后 active task 已进入 `基于 v136 evidence bundle/contract 生成下一轮 v137 静态/动态增强产物`，但工具轮次只够做恢复性核验时，优先确认 v136 evidence bundle 输入层是否完整，再决定是否生成 v137。已知 v136 产物应包括：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v136_capture_contract_evidence_bundle_validator_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v136_capture_contract_evidence_bundle_validator_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v136_capture_contract_evidence_bundle_validator_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v136_capture_contract_evidence_bundle_validator_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v136_evidence_bundle_manifest_0516.json
/opt/data/home/reverse-tools/douyin_analysis/run_v136_capture_contract_live_bundle_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v136_evidence_bundle_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v136_evidence_bundle_runbook_0516.md
```

若 `v137*` 在 `/opt/data/home/reverse-tools/douyin_analysis` 下不存在，且 status 也未确认存在，则不要暗示 v137 已生成；应报告“v136 输入完整，v137 尚未生成/归档”。注意 `search_files(target="files")` 的 `pattern` 是 glob，不是正则；不要用 `douyin_xcylons_v136*|douyin_xcylons_v137*` 这种管道表达式判断 status 不存在，应分别搜索 `douyin_xcylons_v136*` 与 `douyin_xcylons_v137*` 或用 shell/脚本做正则。

v137 推荐方向不是继续扩 hook，而是基于 v136 evidence bundle validator 生成“strict evidence promotion gate / replayable audit package / live evidence triage enhancer”：增强 evidence bundle schema 校验、多日志 replay/triage、strict first-seen alignment 判定、人工升级门槛报告、可审计 evidence package manifest、runbook 与 status/memory 归档。

v137 仍应保持保守算法口径：只有真实直播间日志在同一请求窗口同时满足 `absent_before_ok=true`、`first_after_ok=true`、`downstream_carry_ok=true`、`same_request_window_ok=true`，并且同一个干净 X-Cylons/ACK 值或稳定 hash 在 candidate 与下游 SSL/WS/webcast 控制点之间一致，才能进入 `candidate_dynamic_alignment_needs_algorithm_recovery`。即使满足也不能标记 proven algorithm；真正算法恢复仍要求闭合 opaque/sign callback 或 transform-to-X-Cylons 算法体。默认仍为：

```json
{
  "algorithm_status": "not_recovered",
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false
}
```

## v137 完整生成/归档经验

v137 的正确方向是基于 v136 evidence bundle validator 生成 “strict evidence promotion gate / replayable audit package”，把 evidence bundle schema、replay inputs、hard-negative rules、strict promotion criteria、audit manifest、dry-run runner、promotion-gate analyzer 与 runbook 打包为可复核门控层。它不是继续扩 hook，也不是算法恢复层。

v137 生成与验证时应检查/产出这些文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v137_strict_evidence_promotion_gate_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v137_strict_evidence_promotion_gate_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v137_strict_evidence_promotion_gate_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v137_strict_evidence_promotion_gate_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v137_replayable_audit_manifest_0516.json
/opt/data/home/reverse-tools/douyin_analysis/run_v137_replayable_audit_package_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v137_strict_promotion_gate_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v137_strict_evidence_promotion_gate_runbook_0516.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v137_0516.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-16_project_douyin-xcylons-v137-strict-evidence-promotion-gate.md
```

v137 成功产出后关键抽查字段：

```text
status_completed = true
v137_pack_contract_count = 6
v137_required_replay_artifact_count = 6
v137_hard_negative_rule_count = 14
v137_strict_evidence_event_count = 0
session_state_has_v137_entry = true
algorithm_status = not_recovered
new_value_source_evidence = false
proven_algorithm_evidence = false
first_seen_evidence = false
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v137_strict_evidence_promotion_gate_0516.py
python3 static_v137_strict_evidence_promotion_gate_0516.py
python3 -m py_compile run_v137_replayable_audit_package_0516.py analyze_v137_strict_promotion_gate_0516.py
python3 run_v137_replayable_audit_package_0516.py --dry-run --bundle-name dryrun_minimal
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v137-strict-evidence-promotion-gate"
python3 memory/scripts/memory-sync.py search "v137 strict evidence promotion gate algorithm_status not_recovered"
ps -ef | grep -E 'static_v137|run_v137|analyze_v137|v137_' | grep -v grep || true
```

报告口径：v137 是“replayable audit package + strict evidence promotion gate”，用于把 v136 evidence bundle 升级为可复核、可重放、可人工审计的证据门控层；没有真实直播间动态执行日志时，`v137_strict_evidence_event_count=0` 是预期边界，不代表算法已恢复。只有真实直播间日志在同一请求窗口同时满足 `absent_before_ok=true`、`first_after_ok=true`、`downstream_carry_ok=true`、`same_request_window_ok=true`，且同一个干净 X-Cylons/ACK 值或稳定 hash 在 candidate 与下游 SSL/WS/webcast 控制点之间一致，才能进入人工升级候选；即使满足也不能标记 proven algorithm，真正算法恢复仍要求闭合 opaque/sign callback 或 transform-to-X-Cylons 算法体。

## v137 → v138 经验教训

v138 的正确方向是基于 v137 strict evidence promotion gate 生成“live-evidence triage / dynamic execution decision”层：读取既有 live log，按 v137 严格门槛做证据分级，生成 dynamic execution decision matrix、triage analyzer、decision runner 与 runbook。它不是继续扩 hook，也不是算法恢复层；hook-only/context-only 日志只能归为 context/partial signal。

v138 生成与验证时应检查/产出这些文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v138_live_evidence_triage_dynamic_decision_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v138_live_evidence_triage_dynamic_decision_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v138_live_evidence_triage_dynamic_decision_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v138_live_evidence_triage_dynamic_decision_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v138_dynamic_execution_decision_matrix_0516.json
/opt/data/home/reverse-tools/douyin_analysis/run_v138_live_evidence_triage_decision_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v138_live_evidence_triage_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v138_live_evidence_triage_runbook_0516.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v138_0516.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-16_project_douyin-xcylons-v138-live-evidence-triage-dynamic-decision.md
```

v138 成功产出后关键抽查字段：

```text
status = completed
v137_pack_contract_count = 6
v137_required_replay_artifact_count = 6
v137_hard_negative_rule_count = 14
v137_strict_evidence_event_count = 0
v138_existing_live_log_count = 1
v138_triaged_log_count = 1
v138_existing_event_total = 98
v138_existing_hook_ok_count = 89
v138_existing_hook_err_count = 7
v138_existing_target_related_event_count = 98
v138_existing_all_gate_true_event_count = 0
v138_dynamic_decision_level = context_or_partial_signal_only
v138_generated_analyzer_count = 1
v138_generated_runner_count = 1
v138_generated_matrix_count = 1
v138_dynamic_execution_performed = false
v138_strict_evidence_event_count = 0
v137_strict_promotion_gate_ready = true
v138_live_evidence_triage_ready = true
v138_dynamic_execution_decision_ready = true
algorithm_status = not_recovered
new_value_source_evidence = false
proven_algorithm_evidence = false
first_seen_evidence = false
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v138_live_evidence_triage_dynamic_decision_0516.py run_v138_live_evidence_triage_decision_0516.py analyze_v138_live_evidence_triage_0516.py
python3 static_v138_live_evidence_triage_dynamic_decision_0516.py
python3 run_v138_live_evidence_triage_decision_0516.py --dry-run --decision-name verify_v138 v132_live_logs_0516/*.jsonl
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v138-live-evidence-triage-dynamic-decision"
python3 memory/scripts/memory-sync.py search "v138 live evidence triage dynamic decision algorithm_status not_recovered"
ps -ef | grep -E 'static_v138|run_v138|analyze_v138|v138_' | grep -v grep || true
```

报告口径：v138 是“live evidence triage + dynamic execution decision”层；当既有日志仅有 hook_ok/hook_err/context events 且 `v138_existing_all_gate_true_event_count=0` 时，结论必须保持 `context_or_partial_signal_only` 与 `algorithm_status=not_recovered`。下一步真实直播间执行仍应优先 `pack_00_guards_then_controls`，再跑 `pack_01_same_value_first_seen`，只有同一请求窗口满足 absent-before / first-after / downstream-carry / same-window 全门槛并出现同值 X-Cylons/ACK/SSL 对齐，才可进入人工候选升级；proven algorithm 仍要求闭合 opaque/sign callback 或 transform-to-X-Cylons 算法体。

## v138 → v139 经验教训

v139 的正确方向是基于 v138 live-evidence triage 生成 “live-log gap closure / targeted rerun package”：读取 v138 静态产物、status 与现有 live logs，识别具体缺口（例如既有日志只覆盖 `pack_00_guards_then_controls`，缺少 `pack_01_same_value_first_seen`），然后生成 targeted rerun matrix、runner wrapper、gap-closure analyzer、runbook、JSON/MD/conclusion/status/project memory。它不是继续扩 hook，也不是算法恢复层。

v139 生成与验证时应检查/产出这些文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v139_live_log_gap_closure_targeted_rerun_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v139_live_log_gap_closure_targeted_rerun_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v139_live_log_gap_closure_targeted_rerun_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v139_live_log_gap_closure_targeted_rerun_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v139_targeted_rerun_matrix_0516.json
/opt/data/home/reverse-tools/douyin_analysis/run_v139_targeted_live_rerun_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v139_gap_closure_evidence_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v139_live_log_gap_closure_targeted_rerun_runbook_0516.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v139_0516.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-16_project_douyin-xcylons-v139-live-log-gap-closure-targeted-rerun.md
```

v139 成功产出后关键抽查字段：

```text
status = completed
v138_dynamic_decision_level = context_or_partial_signal_only
v138_existing_live_log_count = 1
v138_existing_event_total = 98
v138_existing_hook_ok_count = 89
v138_existing_hook_err_count = 7
v138_existing_all_gate_true_event_count = 0
v139_existing_log_count = 1
v139_pack_config_count = 6
v139_observed_pack_names = ['pack_00_guards_then_controls']
v139_unexecuted_priority_pack_count = 5
v139_primary_gap = missing_pack_01_same_value_first_seen
v139_targeted_rerun_pack_count = 6
v139_minimal_rerun_pack_count = 2
v139_generated_runner_count = 1
v139_generated_analyzer_count = 1
v139_generated_matrix_count = 1
v139_dynamic_execution_performed = false
v139_strict_evidence_event_count = 0
algorithm_status = not_recovered
new_value_source_evidence = false
proven_algorithm_evidence = false
first_seen_evidence = false
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v139_live_log_gap_closure_targeted_rerun_0516.py
python3 static_v139_live_log_gap_closure_targeted_rerun_0516.py
python3 -m py_compile run_v139_targeted_live_rerun_0516.py analyze_v139_gap_closure_evidence_0516.py
python3 run_v139_targeted_live_rerun_0516.py --dry-run --packs minimal
python3 run_v139_targeted_live_rerun_0516.py --dry-run --packs narrow
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v139-live-log-gap-closure-targeted-rerun"
python3 memory/scripts/memory-sync.py search "v139 live log gap closure targeted rerun algorithm_status not_recovered"
ps -ef | grep -E 'static_v139|run_v139|analyze_v139|v139_' | grep -v grep || true
```

v139 minimal dry-run 应展开为 `pack_00_guards_then_controls` 与 `pack_01_same_value_first_seen`；narrow 应继续包含 `pack_03_producer_consumer_boundary` 与 `pack_04_return_slot_bridge`。若生成器写入嵌套 Python 脚本时使用外层三引号，注意 `PROJECT.write_text(md+'\n\n'+conclusion)`、`SESSION.write_text(... '\n' ...)` 必须保留转义换行，避免生成脚本出现 `SyntaxError: unterminated string literal`。

报告口径：v139 是“live-log gap closure + targeted rerun package”。当 v138/v139 既有日志只证明 hook health/context 且缺少 `pack_01_same_value_first_seen` 时，必须明确 `v139_primary_gap=missing_pack_01_same_value_first_seen`，并保持 `algorithm_status=not_recovered`。下一步真实直播间执行优先 `pack_00`→`pack_01`；只有同一 `request_context_id` 同时满足 absent-before / first-after / downstream-carry / same-window 且同一个干净 X-Cylons/ACK/hash 在 candidate 与 downstream/SSL/WS/webcast 控制点一致，才可进入人工候选升级；proven algorithm 仍要求闭合 opaque/sign callback 或 transform-to-X-Cylons 算法体。

## v140 → v141 经验教训

v141 的正确方向是基于 v140 targeted execution hardening / first-seen closure 生成“live-room gate + same-value preflight”层：在调用 v140 hardened runner 前增加真实直播间前台 gate，避免在 Splash/login/search/NotificationShade/launcher 等非直播间状态误跑 pack_00/pack_01，导致只得到 hook health/context 而没有 ACK/X-Cylons/SSL first-seen 窗口。

v141 生成与验证时应检查/产出这些文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v141_live_room_gate_same_value_preflight_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v141_live_room_gate_same_value_preflight_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v141_live_room_gate_same_value_preflight_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v141_live_room_gate_same_value_preflight_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v141_live_room_gate_same_value_preflight_matrix_0516.json
/opt/data/home/reverse-tools/douyin_analysis/run_v141_live_room_gate_same_value_preflight_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v141_same_value_preflight_logs_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v141_live_room_gate_same_value_preflight_runbook_0516.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v141_0516.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-16_project_douyin-xcylons-v141-live-room-gate-same-value-preflight.md
```

v141 成功产出后关键抽查字段：

```text
v141_pack_config_count = 6
v141_existing_log_count = 1
v141_existing_observed_pack_names = ['pack_00_guards_then_controls']
v141_existing_strict_gate_shape_count = 0
v141_generated_runner_count = 1
v141_generated_analyzer_count = 1
v141_generated_matrix_count = 1
v141_dry_run_checked = true
v141_live_room_gate_ready = true
v141_same_value_preflight_ready = true
v141_dynamic_execution_performed = false
v141_strict_evidence_event_count = 0
algorithm_status = not_recovered
new_value_source_evidence = false
proven_algorithm_evidence = false
first_seen_evidence = false
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v141_live_room_gate_same_value_preflight_0516.py run_v141_live_room_gate_same_value_preflight_0516.py analyze_v141_same_value_preflight_logs_0516.py
python3 static_v141_live_room_gate_same_value_preflight_0516.py
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v141-live-room-gate-same-value-preflight"
python3 memory/scripts/memory-sync.py search "v141 live room gate same value preflight algorithm_status not_recovered"
ps -ef | grep -E 'static_v141|run_v141|analyze_v141|v141_' | grep -v grep || true
```

注意：精确 slug 语义检索可能被 v134 live-room-gate readiness 等相似项目抢占 Top1；若 slug 搜索 v141 不是 Top1，但补充 `v141 live room gate same value preflight algorithm_status not_recovered` 后 v141 Top1，即可认为同步验证通过。

v141 报告口径：这是“真实直播间 gate + same-value preflight”增强层，不是算法恢复。dry-run 中 `adb devices` 可见但 `focus` 为空/非 live activity 时，`live_room_gate_passed=false`、`dynamic_executable=false` 是正确阻断。只有用户已手动进入真实直播间且 gate 通过，才去掉 `--dry-run` 运行 minimal_closure；后续仅当 `pack_01_same_value_first_seen` 出现 candidate same-value hash 时再进入 `narrow_with_downstream`。算法升级门槛仍是同一请求窗口同时满足 absent-before / first-after / downstream-carry / same-window 且同一个干净 X-Cylons/ACK/hash 在 candidate 与下游控制点一致；proven algorithm 仍要求闭合 opaque/sign callback 或 transform-to-X-Cylons 算法体。

## v146 operator-handoff verification 经验

当 context compaction 后 active task 只剩“验证 v146 产物、同步记忆并检查残留进程”时，不要重新执行真实动态捕获；v146 的定位是 operator-handoff live proof capture 包，除非真实直播间 gate 已明确通过且用户要求运行，否则只做产物完整性和归档验证。

v146 验证清单：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v146_operator_handoff_live_proof_capture_0516.py
/opt/data/home/reverse-tools/douyin_analysis/run_v146_operator_handoff_live_proof_capture_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v146_live_proof_capture_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v146_operator_handoff_live_proof_capture_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v146_operator_handoff_live_proof_capture_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v146_operator_handoff_live_proof_capture_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v146_operator_handoff_live_proof_capture_matrix_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v146_operator_handoff_live_proof_capture_runbook_0516.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v146_0516.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-16_project_douyin-xcylons-v146-operator-handoff-live-proof-capture.md
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v146_operator_handoff_live_proof_capture_0516.py run_v146_operator_handoff_live_proof_capture_0516.py analyze_v146_live_proof_capture_0516.py
python3 run_v146_operator_handoff_live_proof_capture_0516.py --help
python3 analyze_v146_live_proof_capture_0516.py --help
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v146-operator-handoff-live-proof-capture"
python3 memory/scripts/memory-sync.py search "v146 operator handoff live proof capture algorithm_status not_recovered"
ps -ef | grep -E 'static_v146|run_v146|analyze_v146|v146_' | grep -v grep || true
```

v146 status 关键抽查字段应保持：

```json
{
  "status": "completed",
  "algorithm_status": "not_recovered",
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "v146_dynamic_execution_allowed": false,
  "v146_dynamic_execution_performed": false,
  "v146_strict_evidence_event_count": 0,
  "v146_generated_runner_count": 1,
  "v146_generated_analyzer_count": 1
}
```

注意：`v146_operator_handoff_ready` 可能只存在于 md/memory 口径或为空，不应因此误判失败；以 status completed、runner/analyzer 生成数、dynamic_execution_performed=false、strict_evidence_event_count=0、memory 精确 slug 可检索、无残留进程为 closure 条件。报告时明确：v146 产物验证通过，但没有真实动态执行，算法本体仍 `not_recovered`。

## v159 attach-resilient minimal dynamic sampling 经验

当上一轮动态执行出现 Frida attach timeout 或 aweme 进程卡死时，不要直接扩大 hook set；先区分 Frida 链路问题与目标进程 stale/stuck 状态。v159 的可复用处理方式：

1. 先用轻量目标（如 `adbd` / `surfaceflinger`）验证 Frida USB 链路是否健康；若这些可 attach，而 `com.ss.android.ugc.aweme` timeout，则优先怀疑 aweme stale/stuck process。
2. 对抖音目标使用 `force-stop` + spawn/resume 方式重新获得干净进程，再安装轻量探针；不要附着旧 PID 反复等待。
3. 最小动态采样只安装少量已观察 call-hit seed/neighbor hook，用于验证 reachability/callctx，不要在这个阶段声明算法恢复。
4. 归档时必须同时保留 runtime jsonl、analysis JSON、status JSON、conclusion MD、project memory，并重新运行 analyzer 做一致性复核。
5. v159 成功执行后的健康计数可作为参考：`event_count=49`、`hook_ok_count=12`、`hook_err_count=0`、`callctx_count=30`、`bad_line_count=0`、`strict_evidence_event_count=0`。这些计数只证明 attach/run 稳定性与候选上下文可达。
6. 如果 `term_counts={}` 且没有 `X-Cylons/ackB/client_start_pack_time`、SSL/request downstream alignment 或 same-request first-seen 证据，必须保持：
   ```json
   {
     "algorithm_status": "not_recovered",
     "first_seen_evidence": false,
     "new_value_source_evidence": false,
     "proven_algorithm_evidence": false
   }
   ```
7. memory-sync 后精确 slug 检索应命中 project memory；如果 broad query 被旧阶段稀释，使用精确 slug（例如 `douyin-xcylons-v159-attach-resilient-light-probe`）作为归档验证。

v159 后续正确方向不是继续盲目扩 hook，而是生成 representation/correlation probe：围绕运行时观察到的即时 ASCII/上下文（例如 `domains/`）扩展表示层扫描，并加入 SSL/request correlation。只有出现同一请求窗口内的 X-Cylons/ACK/hash 与 candidate/downstream 对齐，才能升级到人工候选；proven algorithm 仍要求闭合 opaque/sign callback 或 transform-to-X-Cylons 算法体。

## v160 → v161 表示层候选收敛经验

当 v160 representation/correlation probe 已从 v159 runtime log 中定位到 `domains/` / `omains/.` immediate 表示层候选，但真实直播间 `live_room_gate` 仍未通过时，不要强行绕过 gate 或把 representation hit 当成算法证据。正确方向是生成 v161 “representation candidate convergence” 包：把 v160 观察到的地址压缩成 minimal/observed-all/narrow-with-neighbors 三组动态候选，并生成 runner/analyzer/runbook/status/memory，等待真实直播间窗口再执行。

v161 生成与验证时应检查/产出这些文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v161_representation_candidate_convergence_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v161_representation_candidate_convergence_static_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v161_representation_candidate_convergence_static_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v161_representation_candidate_convergence_conclusion_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v161_representation_candidate_convergence_matrix_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/run_v161_representation_candidate_convergence_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v161_candidate_convergence_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v161_representation_candidate_convergence_runbook_20260519.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v161_20260519.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-19_project_douyin-xcylons-v161-representation-candidate-convergence.md
```

v161 run matrix 推荐三组：

```text
minimal_representation_window      # 只含最小 observed domains immediate first-window 地址，降低 attach/hook 压力
observed_domains_immediate_all     # v159/v160 观察到的全部 domains/ immediate 地址
narrow_with_downstream_neighbors   # observed 表示层地址 + v160 高分 same-value/downstream/return-slot neighbor
```

v161 成功产出后关键抽查字段：

```text
v160_live_gate_blocked = true
v160_domain_like_imm_event_count = 7
v160_domain_like_addr_count = 7
v161_primary_observed_addr_count = 7
v161_supplemental_neighbor_addr_count = 3
v161_converged_probe_addr_count = 10
v161_run_entry_count = 3
v161_generated_runner_count = 1
v161_generated_analyzer_count = 1
v161_generated_matrix_count = 1
v161_dynamic_execution_performed = false
v161_strict_evidence_event_count = 0
v161_representation_candidate_convergence_ready = true
algorithm_status = not_recovered
first_seen_evidence = false
new_value_source_evidence = false
proven_algorithm_evidence = false
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v161_representation_candidate_convergence_20260519.py
python3 static_v161_representation_candidate_convergence_20260519.py
python3 -m py_compile run_v161_representation_candidate_convergence_20260519.py analyze_v161_candidate_convergence_20260519.py
python3 run_v161_representation_candidate_convergence_20260519.py --dry-run --group minimal_representation_window
python3 run_v161_representation_candidate_convergence_20260519.py --dry-run --group narrow_with_downstream_neighbors
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v161-representation-candidate-convergence"
python3 memory/scripts/memory-sync.py search "v161 representation candidate convergence algorithm_status not_recovered"
ps -ef | grep -E 'static_v161|run_v161|analyze_v161|v161_' | grep -v grep || true
```

注意：精确 slug 搜索有时会被旧阶段相似项目稀释；补充 `v161 representation candidate convergence algorithm_status not_recovered` 并命中 v161 project memory，即可确认归档可检索。报告口径必须明确：v161 是“表示层候选收敛 + 动态执行矩阵准备”，没有真实直播间动态采样时 `v161_strict_evidence_event_count=0` 是预期边界，不是失败；算法本体仍未恢复。

## v162 → v163 foreground-proof live-gate recovery 经验

当 v162 已确认当前前台仍是 `com.ss.android.ugc.aweme/.splash.SplashActivity`，且 `live_gate_passed=false`、`dynamic_execution_allowed=false` 时，下一轮不要扩大候选地址，也不要强行执行 Frida hook。正确方向是生成 v163 “foreground-proof live-gate recovery” 层：用连续 foreground proof 样本把真实直播间前台作为 hard gate，再委托上一轮最小候选执行。

v163 生成与验证时应检查/产出这些文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v163_foreground_proof_live_gate_recovery_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v163_foreground_proof_live_gate_recovery_static_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v163_foreground_proof_live_gate_recovery_static_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v163_foreground_proof_live_gate_recovery_conclusion_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v163_foreground_proof_live_gate_recovery_matrix_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/run_v163_foreground_proof_live_gate_recovery_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v163_foreground_proof_candidate_logs_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v163_foreground_proof_live_gate_recovery_runbook_20260519.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v163_20260519.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-19_project_douyin-xcylons-v163-foreground-proof-live-gate-recovery.md
```

v163 runner 的关键行为：

1. `--preflight --samples 2` 连续采样 `adb devices`、`pidof com.ss.android.ugc.aweme`、`dumpsys activity/window` foreground proof。
2. hard negative 命中 `SplashActivity`、`Launcher`、`NotificationShade`、`PermissionController`、`Login`、`Search` 等时，必须输出 `stable_real_live_room_ready=false` 并拒绝 hooks。
3. 只有连续样本均显示真实直播间 Activity，且没有 hard negative，才允许 `--execute-minimal` 委托 v162 minimal candidate execution。
4. v163 analyzer 只包装上一轮候选日志分析并保持保守算法状态；不能把 foreground proof 或 hook health 升级为算法证据。

v163 成功产出后关键抽查字段：

```text
status = completed
v162_live_gate_passed = false
v163_live_gate_passed = false
v163_dynamic_execution_allowed = false
v163_dynamic_execution_performed = false
v163_recovery_step_count = 4
v163_hard_negative_rule_count = 7
v163_strict_evidence_event_count = 0
v163_foreground_proof_gate_ready = true
algorithm_status = not_recovered
first_seen_evidence = false
new_value_source_evidence = false
proven_algorithm_evidence = false
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v163_foreground_proof_live_gate_recovery_20260519.py
python3 static_v163_foreground_proof_live_gate_recovery_20260519.py
python3 -m py_compile run_v163_foreground_proof_live_gate_recovery_20260519.py analyze_v163_foreground_proof_candidate_logs_20260519.py
python3 run_v163_foreground_proof_live_gate_recovery_20260519.py --preflight --samples 2 --delay 0.2
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v163-foreground-proof-live-gate-recovery"
python3 memory/scripts/memory-sync.py search "v163 foreground proof live gate recovery algorithm_status not_recovered"
ps -ef | grep -E 'static_v163|run_v163|analyze_v163|v163_' | grep -v grep || true
```

注意：精确 slug 搜索可能被旧的 foreground/live-gate 项目（如 v150）抢占 Top1；补充 `v163 foreground proof live gate recovery algorithm_status not_recovered` 并命中 v163 project memory，即可认为同步验证通过。报告口径必须明确：v163 是“foreground proof + live gate recovery”防误跑层，当前若仍在 SplashActivity，则动态执行被正确阻断；算法本体仍 `not_recovered`。

## v166 → v167 manual unlock/live-room operator prompt + proof retry 经验

当 v166 lock/wake/shade recovery watcher 已能执行 wake/dismiss_shade/launch_aweme，但连续 gate 样本仍显示 `SplashActivity`、`NotificationShade`、`lockscreen/keyguard` 等 hard blockers 时，下一轮不要强行委派动态 hook，也不要扩大 X-Cylons 候选地址。正确方向是生成 v167 “manual unlock/live-room operator prompt + proof retry” 包：明确提示操作者手动解锁、收起通知栏、进入真实直播间，然后用可重复 proof-retry gate 等待连续真实直播间 foreground proof，只有 gate 连续通过才委派 v166 watcher/runner。

v167 产物建议路径：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v167_manual_unlock_live_room_operator_prompt_proof_retry_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/run_v167_manual_unlock_live_room_operator_prompt_proof_retry_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v167_proof_retry_logs_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v167_manual_unlock_live_room_operator_prompt_proof_retry_static_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v167_manual_unlock_live_room_operator_prompt_proof_retry_static_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v167_manual_unlock_live_room_operator_prompt_proof_retry_conclusion_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v167_manual_unlock_live_room_operator_prompt_proof_retry_matrix_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v167_manual_unlock_live_room_operator_prompt_proof_retry_runbook_20260519.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v167_20260519.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-19_project_douyin-xcylons-v167-manual-unlock-live-room-operator-prompt-proof-retry.md
```

v167 runner 关键行为：

1. 输出清晰 operator prompt：手动解锁设备、完全收起 NotificationShade/StatusBar、打开抖音进入真实直播间、保持直播间前台与屏幕常亮。
2. `--proof-retry --dry-run` 只采样 gate，不委派动态执行；若仍是 Splash/lock/shade，应输出 `operator-handoff-required`。
3. `--proof-retry --execute` 只有连续样本满足真实直播间 proof 且无 hard blockers 时，才委派上一轮 v166 runner；否则禁止 Frida hooks。
4. analyzer 统计 `gate_sample_count`、`stable_live_room_proof_count`、`operator_handoff_required_count`、`delegated_execution_event_count`、`dynamic_execution_performed`、`last_hard_blockers` 与 strict evidence 计数，并默认保持算法状态保守。

v167 成功验证后的关键字段示例：

```text
status = completed
v167_live_entry_ready = false
v167_dynamic_execution_allowed = false
v167_dynamic_execution_performed = false
v167_operator_handoff_required = true
v167_last_hard_blockers = ['lockscreen', 'notification_shade', 'splash']
v167_strict_evidence_event_count = 0
algorithm_status = not_recovered
first_seen_evidence = false
new_value_source_evidence = false
proven_algorithm_evidence = false
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v167_manual_unlock_live_room_operator_prompt_proof_retry_20260519.py run_v167_manual_unlock_live_room_operator_prompt_proof_retry_20260519.py analyze_v167_proof_retry_logs_20260519.py
python3 run_v167_manual_unlock_live_room_operator_prompt_proof_retry_20260519.py --proof-retry --dry-run --interval 0.2 --max-samples 3 --stable-count 2
python3 analyze_v167_proof_retry_logs_20260519.py v167_proof_retry_logs_20260519/*.jsonl --out v167_proof_retry_logs_20260519/analysis_verify.json
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v167-manual-unlock-live-room-operator-prompt-proof-retry"
python3 memory/scripts/memory-sync.py search "v167 manual unlock live room operator prompt proof retry algorithm_status not_recovered"
ps -ef | grep -E 'static_v167|run_v167|analyze_v167|v167_' | grep -v grep || true
```

报告口径：v167 是 operator handoff/proof retry 层，不是算法恢复。若当前仍是 `SplashActivity` + `NotificationShade` + `lockscreen`，必须明确真实动态采样未执行，算法状态保持 `not_recovered`；下一步需要人工进入真实直播间后再运行 `--proof-retry --execute`。

## v167 live-existing minimal representation sampling 归档经验

当 gate 已通过并对现有真实直播间进程运行了 v161 `minimal_representation_window` 等最小动态采样后，下一步应优先做“结果分析 + status/memory 归档 + 残留进程检查”，而不是继续扩大 hook set。

可复用归档路径示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/v161_live_logs_20260519/<timestamp>_v161_minimal_representation_window.jsonl
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v167_live_existing_sampling_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v167_live_existing_minimal_representation_sampling_conclusion_20260519.md
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-19_project_douyin-xcylons-v167-live-existing-minimal-representation-sampling.md
```

v167 live-existing minimal sampling 成功归档后的关键字段示例：

```text
status = completed
dynamic_execution_performed = true
v167_live_existing_minimal_sampling_archived = true
event_count = 135
bad_line_count = 0
hook_ok_count = 10
hook_err_count = 0
reprctx_count = 120
representation_candidate_count = 0
downstream_or_value_candidate_count = 0
all_gate_true_event_count = 0
v161_strict_evidence_event_count = 0
algorithm_status = not_recovered
first_seen_evidence = false
new_value_source_evidence = false
proven_algorithm_evidence = false
```

解释口径：这类结果证明 patched live-room gate 与 minimal representation hook window 能在真实 `LivePlayActivity` 前台进程 attach 并采集 runtime context；但如果没有 representation/downstream/value term correlation、没有 strict same-value first-seen、没有 X-Cylons/ACK/SSL alignment，算法本体仍必须保持 `not_recovered`。

归档验证命令模板：

```bash
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v167-live-existing-minimal-representation-sampling"
python3 memory/scripts/memory-sync.py search "v167 live existing minimal representation sampling algorithm_status not_recovered"
ps -ef | grep -E 'run_v16[0-9]|analyze_v16[0-9]|static_v16[0-9]|v167_|v161_' | grep -v grep || true
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
adb shell pidof com.ss.android.ugc.aweme || true
PID=$(adb shell pidof com.ss.android.ugc.aweme | tr -d '\r' | awk '{print $1}')
if [ -n "$PID" ]; then adb shell cat /proc/$PID/status 2>/dev/null | grep -E 'Name|State|TracerPid|Uid|Gid' || true; fi
```

注意：用 Python 生成 Markdown 时，如果脚本嵌套在 shell heredoc 或 `execute_code` 的 Python 字符串中，避免在外层字符串里直接嵌套未转义三引号 f-string；更稳妥做法是用 `"\n".join([...])` 拼接 Markdown，避免 `SyntaxError: invalid syntax` / `unterminated string literal`。

下一步建议：不要再盲目扩 hook set；优先在同一真实直播间前台窗口运行 `observed_domains_immediate_all` 和 `narrow_with_downstream_neighbors`，或加入低开销 downstream SSL/request correlation。只有同一请求窗口内 candidate 与 X-Cylons/ACK/SSL/downstream 同值对齐，才能进入人工候选升级；proven algorithm 仍要求闭合 opaque/sign callback 或 transform-to-X-Cylons 算法体。

## v170 enhanced gate anti-misrun 经验

当上一轮已经具备 v169 gate watcher / v161 observed+narrow 委派入口，但重新探测发现前台状态同时包含 `SplashActivity`、`NotificationShade`、`Keyguard/lockscreen`、`Launcher`、`PermissionController` 等 hard blockers 时，正确动作不是强行执行 v169 `--execute`，而是生成“非误跑增强 gate + 静态下一步执行包”，确保只有连续真实直播间 proof 后才委派动态 hook。

v170 生成与验证时建议产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v170_enhanced_gate_anti_misrun_static_next_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v170_enhanced_gate_logs_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v170_enhanced_gate_anti_misrun_static_next_matrix_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v170_enhanced_gate_anti_misrun_static_next_static_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v170_enhanced_gate_anti_misrun_static_next_static_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v170_enhanced_gate_anti_misrun_static_next_conclusion_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v170_enhanced_gate_anti_misrun_static_next_runbook_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v170_gate_logs_20260519/analysis_verify_final.json
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v170_20260519.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-19_project_douyin-xcylons-v170-enhanced-gate-anti-misrun-static-next.md
```

v170 runner 关键行为：

1. 连续采样 `adb devices`、`pidof com.ss.android.ugc.aweme`、`dumpsys power/activity/window`。
2. 如果命中 `SplashActivity`、`NotificationShade`、`Keyguard/lockscreen`、`Launcher`、`PermissionController`，必须输出 `operator-handoff-required` / `refuse_dynamic_hooks_gate_blocked`，禁止委派 v169/v161。
3. 只有连续样本满足真实直播间前台（例如 `LivePlayActivity` / `webcast`）且 hard blockers 为空，才委派上一轮 v169 observed+narrow runner。
4. analyzer 统计 `gate-sample`、`operator-handoff-required`、`blocker_counts`、`dynamic_execution_performed`、`strict_evidence_event_count`，默认保持算法状态保守。

v170 验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile run_v170_enhanced_gate_anti_misrun_static_next_20260519.py analyze_v170_enhanced_gate_logs_20260519.py
python3 run_v170_enhanced_gate_anti_misrun_static_next_20260519.py --watch --dry-run --interval 0.2 --max-samples 3 --stable-count 2
python3 analyze_v170_enhanced_gate_logs_20260519.py 'v170_gate_logs_20260519/*.jsonl' --out v170_gate_logs_20260519/analysis_verify_final.json
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v170-enhanced-gate-anti-misrun-static-next"
python3 memory/scripts/memory-sync.py search "v170 enhanced gate anti misrun algorithm_status not_recovered"
ps -ef | grep -E 'static_v170|run_v170|analyze_v170|v170_|run_v169|run_v161' | grep -v grep || true
```

生成脚本经验：在 `execute_code` 中嵌套外层 Python、内部 runner/analyzer 和多层三引号时，容易出现 `SyntaxError: unterminated triple-quoted string literal`。更稳的做法是：外层用普通 Python 变量分别构造 runner/analyzer 字符串，避免再嵌套同类型三引号；或直接用 `write_file` 分别写文件，然后 `py_compile` 验证。

报告口径：v170 是 anti-misrun gate / operator handoff 静态增强层，不是算法恢复。若 dry-run 分析显示 `gate-sample=3`、`operator-handoff-required=1`、blocker 包含 splash/notification_shade/lockscreen 等，必须明确 `dynamic_execution_performed=false`、`strict_evidence_event_count=0`、`algorithm_status=not_recovered`。只有用户手动进入真实直播间、v170 连续 gate 通过并委派 v169/v161 后，才进入同请求窗口 X-Cylons/ACK/SSL/downstream 同值证据判断。

## v184 → v185 stripped Cronet/BoringSSL static callsite/vtable scan 经验

当 v184 non-export dynamic sweep 已确认 focused live-room gate passed 且动态执行成功，但 `nonexport_event_count=0`、`same_window_candidate_count=0`、`strict_evidence=0` 时，下一轮不要继续只扫 v183 neighbor PC；正确方向是转向 stripped Cronet/BoringSSL 静态 callsite/vtable/rodata ref 扫描，尝试从 `Cronet_UrlRequestParams_request_headers_add`、HTTP header name/value set、vtable dispatch group、SSL/WS/webcast downstream correlation 的角度重新定位边界。

v185 产物建议路径：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v185_stripped_cronet_boringssl_callsite_vtable_scan_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v185_stripped_cronet_boringssl_callsite_vtable_scan_static_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v185_stripped_cronet_boringssl_callsite_vtable_scan_static_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v185_stripped_cronet_boringssl_callsite_vtable_scan_conclusion_20260519.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v185_20260519.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-19_project_douyin-xcylons-v185-stripped-cronet-boringssl-callsite-vtable-scan.md
```

v185 成功产出后关键字段可能位于 status JSON 的 `summary` 下，而不是顶层；抽查时不要只读顶层 key。示例关键字段：

```text
summary.status = completed
summary.v184_dynamic_execution_performed = true
summary.v184_strict_evidence_event_count = 0
summary.v185_key_export_count = 449
summary.v185_high_export_count = 16
summary.v185_key_callsite_count = 24
summary.v185_header_builder_window_count = 0
summary.v185_vtable_group_count = 160
summary.v185_rodata_ref_count = 240
summary.v185_static_scan_completed = true
summary.dynamic_execution_performed = false
summary.strict_evidence_event_count = 0
summary.algorithm_status = not_recovered
summary.first_seen_evidence = false
summary.new_value_source_evidence = false
summary.proven_algorithm_evidence = false
```

验证命令模板：

```bash
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v185-stripped-cronet-boringssl-callsite-vtable-scan"
python3 memory/scripts/memory-sync.py search "v185 stripped Cronet BoringSSL callsite vtable algorithm_status not_recovered"
ps -ef | grep -E 'static_v185|run_v185|analyze_v185|v185_' | grep -v grep || true
```

精确 slug 检索 Top1 命中 project memory 即可确认归档可检索；broad query 可能被早期相似静态阶段稀释，不应误判同步失败。报告口径：v185 是 stripped Cronet/BoringSSL 静态边界定位，不是算法恢复；如果没有 clean X-Cylons/ACK/SSL first-seen/downstream 同值证据，继续保持 `algorithm_status=not_recovered`。下一步应基于 v185 top vtable groups/key callsites 生成更聚焦动态 hook 包，而不是回到 v183 neighbor PC 扫描。

## v185 → v186 focused Cronet header/vtable dynamic hook package 经验

当 v185 stripped Cronet/BoringSSL static scan 已定位到 key exports/callsites/vtable groups/rodata refs，但没有 header-builder body 或 strict dynamic evidence 时，下一轮的正确方向是生成 focused Cronet header/vtable dynamic hook package，而不是继续泛扫 non-export PC。v186 应把 v185 的 call targets、rodata header/request refs、top vtable dispatch groups 压缩成可执行 pack，并附带 runner/template/analyzer/matrix/runbook。

v186 产物建议路径：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v186_focused_cronet_header_vtable_dynamic_hook_package_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v186_focused_cronet_header_vtable_hook_template_20260519.js
/opt/data/home/reverse-tools/douyin_analysis/analyze_v186_focused_cronet_header_vtable_logs_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v186_focused_cronet_header_vtable_dynamic_hook_matrix_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v186_focused_cronet_header_vtable_dynamic_hook_runbook_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v186_focused_cronet_header_vtable_dynamic_hook_package_static_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v186_focused_cronet_header_vtable_dynamic_hook_package_static_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v186_focused_cronet_header_vtable_dynamic_hook_package_conclusion_20260519.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v186_20260519.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-19_project_douyin-xcylons-v186-focused-cronet-header-vtable-dynamic-hook-package.md
```

推荐 pack 分层：

```text
exports_and_call_targets_minimal   # key exports + direct/near call targets，最小可达性验证
rodata_header_request_refs         # rodata 中 header/request/webcast/cronet 相关 ref 窗口
top_vtable_dispatch_groups         # v185 top vtable dispatch groups
combined_narrow_header_vtable      # 综合窄包，作为前三包后 stress pass
```

v186 成功产出后关键字段示例：

```text
summary.status = completed
summary.v186_pack_count = 4
summary.v186_hook_target_counts.exports_and_call_targets_minimal = 13
summary.v186_hook_target_counts.rodata_header_request_refs = 36
summary.v186_hook_target_counts.top_vtable_dispatch_groups = 96
summary.v186_hook_target_counts.combined_narrow_header_vtable = 103
summary.v186_unique_target_count = 108
summary.dynamic_execution_performed = false
summary.strict_evidence_event_count = 0
summary.algorithm_status = not_recovered
summary.first_seen_evidence = false
summary.new_value_source_evidence = false
summary.proven_algorithm_evidence = false
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile run_v186_focused_cronet_header_vtable_dynamic_hook_package_20260519.py analyze_v186_focused_cronet_header_vtable_logs_20260519.py
python3 run_v186_focused_cronet_header_vtable_dynamic_hook_package_20260519.py --list-packs
python3 run_v186_focused_cronet_header_vtable_dynamic_hook_package_20260519.py --pack exports_and_call_targets_minimal --dry-run --duration 1
python3 analyze_v186_focused_cronet_header_vtable_logs_20260519.py v186_focused_cronet_header_vtable_logs_20260519/*.jsonl --out v186_focused_cronet_header_vtable_logs_20260519/analysis_verify.json
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v186-focused-cronet-header-vtable-dynamic-hook-package"
python3 memory/scripts/memory-sync.py search "v186 focused Cronet header vtable dynamic hook package algorithm_status not_recovered"
ps -ef | grep -E 'static_v186|run_v186|analyze_v186|v186_' | grep -v grep || true
```

v186 runner 必须保留 live gate hard-blocker：若当前前台为 Splash/NotificationShade/非真实直播间，应输出 `refuse_dynamic_hooks_gate_blocked`、`dynamic_execution_performed=false`，不要安装 Frida hooks。dry-run 中被 splash/非真实直播间阻断是正确行为，只能证明 package 编译/枚举/分析链路可用，不能作为算法证据。真实直播间前台后建议按 `minimal → rodata → vtable → combined` 顺序执行。若 mem0 写入超时，不应阻塞本地 closure；以 status/project memory/SESSION/memory-sync 精确 slug 命中和无残留进程作为本地归档闭环。

报告口径：v186 是“focused Cronet header/vtable dynamic hook package / evidence collection package”，不是算法本体还原。没有真实 live-room ACK/X-Cylons/SSL first-seen/downstream 同值日志时，必须保持 `algorithm_status=not_recovered`。

## v187 → v188 precise callsite/register-backtrack static scan 经验

当 v187 high-level Cronet/TTNet/header/request-builder scan 已经把候选压到高层 Java/smali 文件，但仍缺少 header-builder body、动态 first-seen 或 X-Cylons/ACK/SSL 对齐证据时，下一轮 v188 的正确方向是“精确调用点 + 局部寄存器回溯”静态扫描，而不是继续泛扫 native non-export 或盲目扩大 hook set。

v188 应从 v187 candidate 文件出发，在 decompiled smali 中按类别提取：Retrofit annotation method window、`Map.put`/builder、security/sign adjacent、Cronet/TTNet request glue、live/webcast adjacent、dynamic URL/QueryMap 参数窗口，并输出 focused pack。推荐产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v188_precise_callsite_register_backtrack_static_scan_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v188_precise_callsite_register_backtrack_static_scan_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v188_precise_callsite_register_backtrack_static_scan_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v188_precise_callsite_register_backtrack_static_scan_conclusion_20260519.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v188_20260519.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-19_project_douyin-xcylons-v188-precise-callsite-register-backtrack-static-scan.md
```

v188 成功产出后的关键字段示例：

```text
summary.status = completed
summary.v187_candidate_input_file_count = 117
summary.v188_precise_callsite_record_count = 17897
summary.v188_precise_candidate_file_count = 117
summary.v188_category_counts.retrofit_annotation_method_window = 211
summary.v188_category_counts.map_put_builder = 9405
summary.v188_category_counts.security_sign_adjacent = 5600
summary.v188_category_counts.cronet_ttnet_request_glue = 6531
summary.v188_category_counts.live_webcast_adjacent = 9394
summary.v188_category_counts.dynamic_url_querymap_param = 17
summary.v188_pack_counts.exact_retrofit_url_header_query_callsites = 0
summary.v188_pack_counts.security_map_put_register_backtrack = 120
summary.v188_pack_counts.live_webcast_request_builder_callsites = 120
summary.v188_pack_counts.cronet_ttnet_request_glue_callsites = 120
summary.v188_pack_counts.secapi_sign_adjacent_callsites = 120
summary.v188_pack_counts.high_score_precise_backtrack = 160
summary.dynamic_execution_performed = false
summary.strict_evidence_event_count = 0
summary.algorithm_status = not_recovered
summary.first_seen_evidence = false
summary.new_value_source_evidence = false
summary.proven_algorithm_evidence = false
summary.v188_static_scan_completed = true
```

验证/归档命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m json.tool v188_precise_callsite_register_backtrack_static_scan_20260519.json >/tmp/v188_main.pretty.json
python3 -m json.tool /opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v188_20260519.json >/tmp/v188_status.pretty.json
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v188-precise-callsite-register-backtrack-static-scan"
python3 memory/scripts/memory-sync.py search "v188 precise callsite register backtrack algorithm_status not_recovered"
ps -ef | grep -E 'static_v188|run_v188|analyze_v188|v188_' | grep -v grep || true
```

注意：v188 project memory 文件名包含完整 slug `precise-callsite-register-backtrack-static-scan`；如果误按较短路径 `...register-backtrack.md` 检查会显示不存在，应以 status JSON 的 `artifacts.project_memory` 为准。报告口径：v188 是“精确调用点/局部寄存器回溯静态收敛”，不是算法恢复。没有真实直播间动态同请求窗口 ACK/X-Cylons/SSL first-seen/downstream 同值证据时，继续保持 `algorithm_status=not_recovered`。下一步应基于 `security_map_put_register_backtrack`、`cronet_ttnet_request_glue_callsites`、`secapi_sign_adjacent_callsites` 和 `high_score_precise_backtrack` 生成 v189 focused 动态执行包/Frida hook template。

## v188 → v189 focused precise callsite dynamic hook package 经验

当 v188 precise callsite/register-backtrack static scan 已输出 security/map-put、Cronet/TTNet request glue、secapi/sign adjacent、live/webcast request builder 与 high-score precise backtrack pack 时，v189 的正确方向是生成 focused Java dynamic hook package，而不是继续泛扫 native non-export。v189 应把 v188 pack 转成可执行 Java Frida hook template、runner、analyzer、matrix、runbook、static JSON/MD/conclusion/status/project memory。

v189 产物建议路径：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v189_focused_precise_callsite_dynamic_hook_package_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v189_focused_precise_callsite_hook_template_20260519.js
/opt/data/home/reverse-tools/douyin_analysis/analyze_v189_focused_precise_callsite_logs_20260519.py
/opt/data/home/reverse-tools/douyin_analysis/v189_focused_precise_callsite_dynamic_hook_matrix_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v189_focused_precise_callsite_dynamic_hook_runbook_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v189_focused_precise_callsite_dynamic_hook_package_static_20260519.json
/opt/data/home/reverse-tools/douyin_analysis/v189_focused_precise_callsite_dynamic_hook_package_static_20260519.md
/opt/data/home/reverse-tools/douyin_analysis/v189_focused_precise_callsite_dynamic_hook_package_conclusion_20260519.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v189_20260519.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-19_project_douyin-xcylons-v189-focused-precise-callsite-dynamic-hook-package.md
```

推荐 pack 分层：

```text
minimal_security_cronet_sign_window
security_map_put_register_backtrack
cronet_ttnet_request_glue_callsites
secapi_sign_adjacent_callsites
live_webcast_request_builder_callsites
high_score_precise_backtrack
combined_precise_callsite_narrow
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile run_v189_focused_precise_callsite_dynamic_hook_package_20260519.py analyze_v189_focused_precise_callsite_logs_20260519.py
python3 -m json.tool v189_focused_precise_callsite_dynamic_hook_matrix_20260519.json >/tmp/v189_matrix.pretty.json
python3 -m json.tool v189_focused_precise_callsite_dynamic_hook_package_static_20260519.json >/tmp/v189_static.pretty.json
python3 -m json.tool /opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v189_20260519.json >/tmp/v189_status.pretty.json
python3 run_v189_focused_precise_callsite_dynamic_hook_package_20260519.py --list-packs
python3 run_v189_focused_precise_callsite_dynamic_hook_package_20260519.py --pack security_map_put_register_backtrack --dry-run --duration 1
python3 analyze_v189_focused_precise_callsite_logs_20260519.py 'v189_focused_precise_callsite_logs_20260519/*.jsonl' --out v189_focused_precise_callsite_logs_20260519/analysis_verify.json
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "v189 focused precise callsite dynamic hook package algorithm_status not_recovered"
ps -ef | grep -E 'static_v189|run_v189|analyze_v189|v189_' | grep -v grep || true
```

v189 成功验证后的关键字段示例：

```text
summary.status = completed
summary.v189_pack_count = 7
summary.dynamic_execution_performed = false
summary.strict_evidence_event_count = 0
summary.algorithm_status = not_recovered
summary.first_seen_evidence = false
summary.new_value_source_evidence = false
summary.proven_algorithm_evidence = false
```

v189 runner 必须保留真实直播间 gate：如果当前前台不是 `com.ss.android.ugc.aweme` 真实直播间，或 hard blocker 包含 launcher/splash/notification/keyguard 等，应输出 `refuse_dynamic_hooks_gate_blocked` / `operator-handoff-required`，并保持 `dynamic_execution_performed=false`，不要安装 hooks。dry-run 被非直播间前台阻断是正确行为，只证明 package 编译/枚举/分析链路可用，不是算法证据。

生成 analyzer 时注意嵌套字符串换行：写出 `pathlib.Path(ns.out).write_text(txt+'\\n', encoding='utf-8')`，不要让外层生成器把 `\n` 展开成真实换行，否则 `py_compile` 会报 `SyntaxError: unterminated string literal`。遇到这种错误应先修 analyzer，再重新跑 py_compile/list/dry-run/analyzer 全链路。

归档检索时，精确 slug 搜索可能被 v188/v187 等相似阶段稀释；补充 broad query `v189 focused precise callsite dynamic hook package algorithm_status not_recovered` 并命中 v189 Top1 即可确认同步层可检索。

报告口径：v189 是“focused precise callsite Java dynamic hook package / evidence collection package”，不是算法本体还原。没有真实 live-room ACK/X-Cylons/SSL/downstream 同请求窗口同值日志时，必须保持 `algorithm_status=not_recovered`。

## v203 → v204 focused Java+native bridge dynamic hook package 经验

当 v203 已完成 Java/smali precise callsite 与 native Cronet/TTNet bridge static backtrack，并生成 Java+native bridge pack 输入时，v204 的正确方向是生成 focused Java+native bridge 动态 hook 证据采集包：runner、Frida JS template、analyzer、matrix、runbook、static JSON/MD/conclusion、status/project memory，而不是继续扩大静态候选。

v204 产物建议路径：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v204_focused_java_native_bridge_dynamic_hook_package_20260520.py
/opt/data/home/reverse-tools/douyin_analysis/v204_focused_java_native_bridge_hook_template_20260520.js
/opt/data/home/reverse-tools/douyin_analysis/analyze_v204_focused_java_native_bridge_logs_20260520.py
/opt/data/home/reverse-tools/douyin_analysis/v204_focused_java_native_bridge_dynamic_hook_matrix_20260520.json
/opt/data/home/reverse-tools/douyin_analysis/v204_focused_java_native_bridge_dynamic_hook_runbook_20260520.md
/opt/data/home/reverse-tools/douyin_analysis/v204_focused_java_native_bridge_dynamic_hook_package_static_20260520.json
/opt/data/home/reverse-tools/douyin_analysis/v204_focused_java_native_bridge_dynamic_hook_package_static_20260520.md
/opt/data/home/reverse-tools/douyin_analysis/v204_focused_java_native_bridge_dynamic_hook_package_conclusion_20260520.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v204_20260520.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-20_project_douyin-xcylons-v204-focused-java-native-bridge-dynamic-hook-package.md
```

推荐 pack 分层与已验证计数：

```text
minimal_java_native_bridge: 52
java_security_header_map_bridge: 80
java_cronet_ttnet_request_bridge: 80
live_webcast_request_security_bridge: 80
native_cronet_header_builder_bridge: 96
combined_java_native_bridge: 120
```

验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile run_v204_focused_java_native_bridge_dynamic_hook_package_20260520.py analyze_v204_focused_java_native_bridge_logs_20260520.py
python3 -m json.tool v204_focused_java_native_bridge_dynamic_hook_matrix_20260520.json >/tmp/v204_matrix.pretty.json
python3 -m json.tool v204_focused_java_native_bridge_dynamic_hook_package_static_20260520.json >/tmp/v204_static.pretty.json
python3 -m json.tool /opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v204_20260520.json >/tmp/v204_status.pretty.json
python3 run_v204_focused_java_native_bridge_dynamic_hook_package_20260520.py --list-packs
python3 run_v204_focused_java_native_bridge_dynamic_hook_package_20260520.py --pack java_security_header_map_bridge --dry-run --duration 1
python3 analyze_v204_focused_java_native_bridge_logs_20260520.py 'v204_focused_java_native_bridge_logs_20260520/*.jsonl' --out v204_focused_java_native_bridge_logs_20260520/analysis_verify.json
python3 -m json.tool v204_focused_java_native_bridge_logs_20260520/analysis_verify.json >/tmp/v204_analysis_verify.pretty.json
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "v204 focused Java native bridge dynamic hook package algorithm_status not_recovered"
ps -ef | grep -E 'static_v204|run_v204|analyze_v204|v204_' | grep -v grep || true
```

注意事项：

- dry-run pack 名必须使用实际 `--list-packs` 输出，例如 `java_security_header_map_bridge`，不要误写成 `security_header_map_bridge`；否则 runner 会提示 unknown pack。
- v204 runner 必须保留 live-room gate。若当前前台仍为 `.splash.SplashActivity` 或 hard blocker 包含 `splash`，应输出 `refuse_dynamic_hooks_gate_blocked`，保持 `dynamic_execution_performed=false`，不要安装 Frida hooks。
- dry-run gate blocked 只证明包/枚举/analyzer 链路可用，不是动态算法证据。若 `hook_ok_count=0`、`java_event_count=0`、`native_event_count=0`、`strict_evidence_event_count=0`，必须保持：
  ```json
  {
    "dynamic_execution_performed": false,
    "algorithm_status": "not_recovered",
    "first_seen_evidence": false,
    "new_value_source_evidence": false,
    "proven_algorithm_evidence": false
  }
  ```
- 归档时把 `validation.py_compile_ok/json_tool_ok/list_packs_ok/dry_run_ok/analyzer_json_ok`、`dryrun_gate_blocked=true`、`dryrun_last_hard_blockers=["splash"]` 写入 status，并同步 project memory 与 SESSION-STATE。
- memory-sync 精确 slug 搜索可能被 v133/v202 等 execution package 相似项目稀释；补充 `v204 focused Java native bridge dynamic hook package algorithm_status not_recovered`，Top1 命中 v204 project memory 即可视为同步验证通过。

报告口径：v204 是“focused Java+native bridge dynamic hook package / evidence collection package”，不是算法本体还原。下一步应先让真实直播间前台稳定，然后按 `minimal_java_native_bridge → java_security_header_map_bridge → java_cronet_ttnet_request_bridge → live_webcast_request_security_bridge → native_cronet_header_builder_bridge → combined_java_native_bridge` 执行；只有同一 request/window 内出现 X-Cylons/ACK/SSL/downstream 同值 first-seen/carry 严格证据，才能进入人工候选升级。proven algorithm 仍要求闭合 opaque/sign callback 或 transform-to-X-Cylons 算法体。

## v204 → v205 Java bridge method-body/register value-flow convergence 经验

当 v204 focused Java+native bridge dynamic hook package 已经完成并验证，但受 live-room gate 阻断或尚无真实动态同值证据时，v205 的正确方向可以转为 Java bridge 方法体/寄存器值流静态收敛：从 v204 的 Java bridge packs 入手，扫描相关 smali 方法体，提取 security/header/map-put、Cronet/TTNet request glue、live/webcast context、secapi/sign adjacent 的局部 register backtrack 与 value-flow pack。它仍是静态收敛层，不是算法恢复。

v205 产物建议路径：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v205_java_bridge_method_body_register_valueflow_convergence_20260520.py
/opt/data/home/reverse-tools/douyin_analysis/v205_java_bridge_method_body_register_valueflow_convergence_static_20260520.json
/opt/data/home/reverse-tools/douyin_analysis/v205_java_bridge_method_body_register_valueflow_convergence_static_20260520.md
/opt/data/home/reverse-tools/douyin_analysis/v205_java_bridge_method_body_register_valueflow_convergence_conclusion_20260520.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v205_20260520.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-20_project_douyin-xcylons-v205-java-bridge-method-body-register-valueflow-convergence.md
```

v205 验证命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v205_java_bridge_method_body_register_valueflow_convergence_20260520.py
python3 -m json.tool v205_java_bridge_method_body_register_valueflow_convergence_static_20260520.json >/tmp/v205_static.pretty.json
python3 -m json.tool /opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v205_20260520.json >/tmp/v205_status.pretty.json
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v205-java-bridge-method-body-register-valueflow-convergence"
python3 memory/scripts/memory-sync.py search "v205 java bridge method body register valueflow algorithm_status not_recovered"
ps -ef | grep -E 'static_v205|run_v205|analyze_v205|v205_' | grep -v grep || true
```

v205 成功验证后的关键字段示例：

```text
summary.status = completed
summary.v204_dynamic_execution_performed = false
summary.v204_strict_evidence_event_count = 0
summary.v205_input_bridge_pack_count = 6
summary.v205_scanned_smali_file_count = 11
summary.v205_scanned_method_count = 11
summary.v205_valueflow_record_count = 450
summary.v205_scan_error_count = 180
summary.v205_category_counts.explicit_security_header_valueflow = 341
summary.v205_category_counts.map_put_header_builder_valueflow = 372
summary.v205_category_counts.cronet_ttnet_header_request_glue_valueflow = 223
summary.v205_category_counts.security_sign_adjacent_valueflow = 341
summary.v205_category_counts.live_webcast_request_context_valueflow = 268
summary.v205_pack_counts.explicit_security_header_valueflow = 120
summary.v205_pack_counts.map_put_header_builder_valueflow = 120
summary.v205_pack_counts.live_webcast_request_context_valueflow = 120
summary.v205_pack_counts.cronet_ttnet_header_request_glue_valueflow = 120
summary.v205_pack_counts.security_sign_adjacent_valueflow = 120
summary.v205_pack_counts.high_score_java_bridge_valueflow = 180
summary.v205_static_valueflow_convergence_completed = true
summary.dynamic_execution_performed = false
summary.strict_evidence_event_count = 0
summary.algorithm_status = not_recovered
summary.first_seen_evidence = false
summary.new_value_source_evidence = false
summary.proven_algorithm_evidence = false
```

Top records may converge on Java bridge methods such as:

```text
.method public final interceptHeader(Landroid/net/Uri;Ljava/util/Map;)Ljava/util/Map;
v205_score = 536
body_const_count = 5
body_invoke_count = 10
map_put_count = 3
register_backtrack keys = v1, v0
```

注意：v205 status/static JSON 的核心字段位于 `summary` 下；抽查时不要只看顶层。`v205_scan_error_count` 非零不必立即判失败，应结合 `v205_scanned_method_count`、`v205_valueflow_record_count`、pack/category counts 与 `v205_static_valueflow_convergence_completed=true` 判断。memory-sync 精确 slug 与补充 query 都应 Top1 命中 v205 project memory；最后必须做残留进程检查。

报告口径：v205 是“Java bridge method-body/register value-flow 静态收敛”，不是算法本体还原。没有真实 live-room 同请求窗口 ACK/X-Cylons/SSL/downstream 同值 first-seen/carry 证据时，继续保持 `algorithm_status=not_recovered`。

## v206 → v207 Java bridge method callchain / algorithm candidate 静态挖掘经验

当 v205 Java bridge method-body/register value-flow convergence 与 v206 focused Java bridge valueflow dynamic hook package 已完成，但 v206 仍受 live-room gate 阻断或没有真实动态同值证据时，v207 的正确方向可以转为 Java bridge 方法体/调用链/算法候选静态收敛：从 v205/v206 的 Java bridge valueflow targets 入手，提取唯一方法体、one-hop invokes、resolved callees、crypto/encode/encrypt adjacent bodies、map/header mutation、security/metasec/sign adjacent 与 high-score callchain algorithm candidates。它仍是静态候选层，不是算法恢复。

v207 产物建议路径：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v207_java_bridge_method_callchain_algorithm_candidate_20260520.py
/opt/data/home/reverse-tools/douyin_analysis/v207_java_bridge_method_callchain_algorithm_candidate_static_20260520.json
/opt/data/home/reverse-tools/douyin_analysis/v207_java_bridge_method_callchain_algorithm_candidate_static_20260520.md
/opt/data/home/reverse-tools/douyin_analysis/v207_java_bridge_method_callchain_algorithm_candidate_conclusion_20260520.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v207_20260520.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-20_project_douyin-xcylons-v207-java-bridge-method-callchain-algorithm-candidate.md
```

v207 验证/归档命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v207_java_bridge_method_callchain_algorithm_candidate_20260520.py
python3 static_v207_java_bridge_method_callchain_algorithm_candidate_20260520.py
python3 -m json.tool v207_java_bridge_method_callchain_algorithm_candidate_static_20260520.json >/tmp/v207_static.pretty.json
python3 -m json.tool /opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v207_20260520.json >/tmp/v207_status.pretty.json
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v207-java-bridge-method-callchain-algorithm-candidate"
python3 memory/scripts/memory-sync.py search "v207 java bridge method callchain algorithm candidate algorithm_status not_recovered"
ps -ef | grep -E 'static_v207|run_v207|analyze_v207|v207_' | grep -v grep || true
```

v207 成功验证后的关键字段示例：

```text
summary.status = completed
summary.v206_focused_java_bridge_valueflow_dynamic_hook_package_ready = true
summary.v206_dynamic_execution_performed = false
summary.v206_strict_evidence_event_count = 0
summary.v207_input_target_count = 35
summary.v207_unique_method_target_count = 7
summary.v207_method_body_record_count = 7
summary.v207_onehop_invoke_record_count = 45
summary.v207_onehop_resolved_count = 14
summary.v207_extra_algorithm_body_count = 17
summary.v207_scan_error_count = 0
summary.v207_pack_counts.direct_x_cylons_or_ss_queries_methods = 2
summary.v207_pack_counts.crypto_encode_encrypt_adjacent_callchain = 14
summary.v207_pack_counts.map_header_mutation_valueflow_body = 6
summary.v207_pack_counts.security_metasec_sign_adjacent_body = 13
summary.v207_pack_counts.onehop_algorithm_adjacent_resolved_calls = 45
summary.v207_pack_counts.high_score_callchain_algorithm_candidates = 24
summary.v207_static_callchain_algorithm_candidate_completed = true
summary.dynamic_execution_performed = false
summary.strict_evidence_event_count = 0
summary.algorithm_status = not_recovered
summary.first_seen_evidence = false
summary.new_value_source_evidence = false
summary.proven_algorithm_evidence = false
```

注意：v207 status/static JSON 的核心字段位于 `summary` 下；抽查时不要只看顶层。memory-sync 精确 slug 与补充 query 都应 Top1 命中 v207 project memory；最后必须做残留进程检查。报告口径：v207 是“Java bridge 方法体/调用链/算法候选静态收敛”，不是算法本体还原。没有真实 live-room 同请求窗口 ACK/X-Cylons/SSL/downstream 同值 first-seen/carry 证据时，继续保持 `algorithm_status=not_recovered`。下一步可基于 `high_score_callchain_algorithm_candidates`、`crypto_encode_encrypt_adjacent_callchain`、`direct_x_cylons_or_ss_queries_methods` 做 v208 更精确方法体切片/多跳调用链/transform-to-header candidate 收敛，或转 focused Java hook 包等待真实直播间动态同值验证。

## v207 → v208 多跳调用链 / transform-to-header candidate 静态收敛经验

当 v207 Java bridge method callchain / algorithm candidate 已完成，但仍没有真实直播间动态同值证据时，v208 的正确方向可以继续做多跳调用链与 transform-to-header candidate 静态收敛：从 v207 的 `high_score_callchain_algorithm_candidates`、`crypto_encode_encrypt_adjacent_callchain`、`direct_x_cylons_or_ss_queries_methods`、`security_metasec_sign_adjacent_body`、`onehop_algorithm_adjacent_resolved_calls` 取 seed，解析 depth<=3 的 interesting invokes，聚合 header/ss_queries、crypto/security、Map/Header mutation、String/JSON/sort transform 混合路径，并输出 focused dynamic hook candidate methods。它仍是静态候选层，不是算法恢复。

v208 产物建议路径：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v208_multihop_callchain_transform_candidate_convergence_20260520.py
/opt/data/home/reverse-tools/douyin_analysis/v208_multihop_callchain_transform_candidate_convergence_static_20260520.json
/opt/data/home/reverse-tools/douyin_analysis/v208_multihop_callchain_transform_candidate_convergence_static_20260520.md
/opt/data/home/reverse-tools/douyin_analysis/v208_multihop_callchain_transform_candidate_convergence_conclusion_20260520.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v208_20260520.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-20_project_douyin-xcylons-v208-multihop-callchain-transform-candidate-convergence.md
```

v208 验证/归档命令模板：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v208_multihop_callchain_transform_candidate_convergence_20260520.py
python3 static_v208_multihop_callchain_transform_candidate_convergence_20260520.py
python3 -m json.tool v208_multihop_callchain_transform_candidate_convergence_static_20260520.json >/tmp/v208_static.pretty.json
python3 -m json.tool /opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v208_20260520.json >/tmp/v208_status.pretty.json
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-v208-multihop-callchain-transform-candidate-convergence"
python3 memory/scripts/memory-sync.py search "v208 multihop callchain transform candidate algorithm_status not_recovered"
ps -ef | grep -E 'static_v208|run_v208|analyze_v208|v208_' | grep -v grep || true
```

v208 成功验证后的关键字段示例：

```text
summary.status = completed
summary.v207_static_callchain_algorithm_candidate_completed = true
summary.v207_dynamic_execution_performed = false
summary.v207_strict_evidence_event_count = 0
summary.v208_seed_count = 74
summary.v208_unique_seed_node_count = 26
summary.v208_multihop_node_count = 40
summary.v208_resolved_edge_count = 49
summary.v208_unresolved_edge_count = 134
summary.v208_depth_counts = {'0': 26, '1': 6, '2': 6, '3': 2}
summary.v208_path_candidate_count = 40
summary.v208_mixed_transform_signal_path_count = 13
summary.v208_pack_counts.direct_header_or_ss_queries_transform_paths = 1
summary.v208_pack_counts.crypto_security_transform_multihop_paths = 15
summary.v208_pack_counts.map_header_to_encrypt_candidate_nodes = 16
summary.v208_pack_counts.resolved_second_third_hop_algorithm_nodes = 6
summary.v208_pack_counts.high_score_transform_to_header_candidates = 40
summary.v208_pack_counts.focused_v208_dynamic_hook_candidate_methods = 40
summary.v208_static_multihop_callchain_transform_candidate_completed = true
summary.dynamic_execution_performed = false
summary.strict_evidence_event_count = 0
summary.algorithm_status = not_recovered
summary.first_seen_evidence = false
summary.new_value_source_evidence = false
summary.proven_algorithm_evidence = false
```

注意事项：

- v208 status/static JSON 的核心字段位于 `summary` 下；抽查时不要只看顶层。
- `direct_header_or_ss_queries_transform_paths` 数量可能很少（例如 1），不应因此判失败；本轮目标是多跳 transform/security/crypto/header 混合路径收敛，应综合 `v208_multihop_node_count`、`v208_resolved_edge_count`、`v208_mixed_transform_signal_path_count` 与各 pack count 判断。
- 在 `execute_code` 外层 Python 中写入包含中文 Markdown 的内层脚本时，避免外层三引号与内层三引号冲突；更稳妥做法是直接用 `write_file` 写完整脚本，或用 `"\n".join([...])` 拼接长 Markdown/结论，先 `py_compile` 再运行。
- memory-sync 精确 slug 搜索应命中新建 project memory；补充 broad query `v208 multihop callchain transform candidate algorithm_status not_recovered` 可验证语义检索。最后必须检查残留进程。

报告口径：v208 是“Java bridge 多跳调用链 / transform-to-header candidate 静态收敛”，不是算法本体还原。没有真实 live-room 同请求窗口 ACK/X-Cylons/SSL/downstream 同值 first-seen/carry 证据时，继续保持 `algorithm_status=not_recovered`。下一步可基于 `focused_v208_dynamic_hook_candidate_methods` 与 `direct_header_or_ss_queries_transform_paths` 生成 v209 focused Java multihop dynamic hook package，或在真实直播间窗口优先验证 `RequestEncryptUtils/tryEncryptRequest -> tryAddQuery/parseQueries/EncryptorUtil` 链路。

## 报告口径

最终报告应包含：文件路径、核心计数、`algorithm_status`、是否已 sync、检索命中证据、遗留进程检查结果。若算法未恢复，要直接说明：本轮只收敛 hook/first-seen/value-flow 边界，仍需真实窗口动态同值验证。