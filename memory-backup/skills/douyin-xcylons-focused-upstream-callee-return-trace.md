---
name: douyin-xcylons-focused-upstream-callee-return-trace
description: 抖音直播 X-Cylons 在 v99 之后做 focused upstream/callee-return source tracing，把静态 caller/value-source 候选收敛成动态 first-seen hook set
triggers:
  - 抖音 X-Cylons v100
  - callee-return source trace
  - upstream value lane
  - return_to_value_arg_bridge
  - X-Cylons first-seen
---

# Douyin X-Cylons focused upstream / callee-return source tracing

## 适用场景

当 X-Cylons 已经确认 ACK/uplink/SSL/WS-send 传播链，但 v99 之类的静态 caller/return/value-source 挖掘仍没有证明算法本体时，使用本流程继续收敛候选。

目标不是直接宣称算法还原，而是从 v99 priority caller/value-source records 中回溯 value 参数来源，生成更小、更靠近实参来源的动态 hook set。

## 核心方法

1. 输入上一轮 priority caller/value-source records。
2. 对每个 v99 target call site，在 caller 函数内向前扫描 value 参数寄存器/slot 的准备过程。
3. 重点记录三类 source lane：
   - prior callee return lanes：目标 call 前的 callee 返回值进入后续 value 参数寄存器或 spill slot；
   - slot/materializer lanes：从对象/栈/record slot 读取后 materialize 为 value 参数；
   - bitmix/crypto-like lanes：出现 rotate/xor/table/crypto-like 操作但未做同值验证时，只标记为 probe。
4. 对“callee return -> later value argument”的桥接单独分类为 `return_to_value_arg_bridge_candidate_unproven`；不要把桥接点直接升级为 value 生成点。
5. 输出 ranked hook set：upstream source calls、callee returns、slot writes/reads、下游 carry/package/SSL/WS-send controls 一起保留，供真实动态窗口同值验证。

## 必备产物字段

JSON/status 至少包含：

```json
{
  "trace_record_count": 0,
  "high_priority_trace_count": 0,
  "callee_return_value_source_candidate_count": 0,
  "return_to_value_arg_bridge_candidate_count": 0,
  "slot_materialized_value_lane_candidate_count": 0,
  "callee_return_upstream_candidate_count": 0,
  "vNN_focused_upstream_callee_return_source_hook_set_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

Markdown/conclusion 必须明确区分：

- 已确认的是 protocol / SSL / ACK / carry/package / propagation / WS-send 链；
- 本轮新增的是静态 source-lane/hook priority；
- 算法 body / clean value source 尚未 recovered。

## 动态升级规则

只有同时满足以下条件，才能把某个 v100 upstream/callee-return lane 升级为生成点或算法证据：

1. 真实直播间复现 ACK / X-Cylons / SSL first-seen 窗口；
2. clean `X-Cylons` 在该 upstream/callee-return lane 之前不存在；
3. clean `X-Cylons` 首次出现在该 callee return / slot write / callback output；
4. 同一值继续流经 v99 target，并到达 carry/package 或 SSL/WS-send control；
5. 捕获日志能证明同值，而不是仅证明 hook installed 或函数被调用。

若缺任一条件，保持：

```text
new_value_source_evidence=false
proven_algorithm_evidence=false
first_seen_evidence=false
algorithm_status=not_recovered
```

## v100 经验值参考

2026-05-15 v100 从 v99 priority records 做 upstream/callee-return source trace，结果：

```json
{
  "trace_record_count": 116,
  "high_priority_trace_count": 92,
  "callee_return_value_source_candidate_count": 1,
  "return_to_value_arg_bridge_candidate_count": 85,
  "slot_materialized_value_lane_candidate_count": 4,
  "callee_return_upstream_candidate_count": 23,
  "v100_focused_upstream_callee_return_source_hook_set_count": 128,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

代表性高优先级模式：同一 caller 函数内，多个 prior source return calls / slots / callee-return lanes 汇入后续 value argument，例如 `0x1fc724` 附近多处 `return_to_value_arg_bridge_candidate_unproven`。

## v101 经验值参考

2026-05-15 v101 在 v100 之后继续做 focused callee-return source / caller-xref deep mining，目标是把 return producer body、callback/virtual return bridge、direct caller xref 三类候选补齐为下一轮动态 first-seen probe，而不是宣称算法恢复。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/v101_focused_callee_return_source_caller_xref_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v101_focused_callee_return_source_caller_xref_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v101_focused_callee_return_source_caller_xref_conclusion_0515.md
/opt/data/home/reverse-tools/douyin_analysis/static_v101_focused_callee_return_source_caller_xref_0515.py
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v101_0515.json
```

关键计数：

```json
{
  "seed_target_count": 46,
  "trace_record_count": 46,
  "high_priority_trace_count": 46,
  "return_producer_body_candidate_count": 14,
  "callback_or_virtual_return_bridge_candidate_count": 26,
  "return_consumer_caller_xref_candidate_count": 6,
  "direct_caller_xref_total_count": 2081,
  "hook_set_count": 160,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v101 的可复用判断规则：

- `return_producer_body_candidate`：只表示值得动态 hook 的返回值生产函数体；静态看到 return/callee/value lane 不等于 clean X-Cylons 生成点。
- `callback_or_virtual_return_bridge_candidate`：只表示 callback/virtual dispatch 可能承载返回值；需要 first-seen 同值日志才能升级。
- `return_consumer_caller_xref_candidate` / `direct_caller_xref_total_count`：用于扩展 caller 上下文和 hook priority，不是算法本体证据。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态窗口，保持 `algorithm_status=not_recovered`，向用户明确说明“接口/调用链候选推进”和“算法本体还原”仍是两件事。

## v102 经验值参考

2026-05-15 v102 在 v101 的 return-producer / callback / caller-xref probe 基础上，继续展开 focused caller-xref / value-lane deep mining。目标是把候选进一步拆成 caller 参数 lane、return-to-slot/downstream lane、callback/virtual bridge lane 和 return-consumer lane，为下一轮真实动态 first-seen 同值验证准备更集中的 hook set；仍不能把静态 value-lane probe 误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v102_focused_caller_xref_value_lane_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v102_focused_caller_xref_value_lane_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v102_focused_caller_xref_value_lane_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v102_focused_caller_xref_value_lane_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v102_0515.json
```

关键计数：

```json
{
  "trace_record_count": 46,
  "high_priority_trace_count": 46,
  "value_lane_context_count": 1079,
  "high_priority_value_lane_context_count": 1065,
  "return_to_slot_downstream_value_lane_probe_count": 41,
  "slot_to_arg_value_lane_probe_count": 4,
  "callback_virtual_value_lane_bridge_probe_count": 1,
  "return_consumer_value_lane_probe_count": 0,
  "v102_focused_caller_xref_value_lane_hook_set_count": 192,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v102 的可复用判断规则：

- `return_to_slot_downstream_value_lane_probe`：只说明 return producer 的输出可能经 slot/downstream lane 传播；未做 clean X-Cylons first-seen 同值验证时，不能升级为 value source。
- `slot_to_arg_value_lane_probe`：只说明 slot/materialized value 进入后续实参；它是动态 hook priority，不是算法证据。
- `callback_virtual_value_lane_bridge_probe`：只说明 callback/virtual dispatch 可能桥接值；需要真实 ACK/X-Cylons/SSL first-seen 窗口证明 absent-before / first-after / downstream equality。
- `return_consumer_value_lane_probe_count=0` 是重要负结果：不要为了“有结论”强行扩大为算法恢复，只记录静态未发现 return consumer 同值 lane。
- 即使 value-lane contexts 数量很高，只要 `new_value_source_evidence=false`、`first_seen_evidence=false`，就保持 `algorithm_status=not_recovered`，并向用户明确说明“静态 probe/hook set 推进”和“算法本体还原”仍未等价。

## v105 经验值参考

2026-05-15 v105 基于 v104 的 consumer-body nested calls 和 second-hop downstream calls 继续做 focused nested-callee / second-hop value-flow 静态挖掘。目标是把 consumer body 内的 nested callee、callback/virtual bridge、slot/return lane、next-hop runtime chain 拆成可执行的动态 hook set；仍然不能把静态 bitmix/callee/callback probe 误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v105_focused_nested_callee_value_flow_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v105_focused_nested_callee_value_flow_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v105_focused_nested_callee_value_flow_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v105_focused_nested_callee_value_flow_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v105_0515.json
```

关键计数：

```json
{
  "trace_record_count": 720,
  "high_priority_trace_count": 720,
  "nested_bitmix_callee_probe_count": 299,
  "nested_callback_virtual_bridge_probe_count": 390,
  "nested_slot_return_value_lane_probe_count": 25,
  "known_control_anchor_alignment_probe_count": 6,
  "nested_downstream_callee_probe_count": 0,
  "callee_bitmix_or_crypto_total_count": 1249,
  "callee_indirect_branch_total_count": 875,
  "next_hop_runtime_chain_call_count": 7602,
  "callsite_return_lane_total_count": 9932,
  "callsite_slot_lane_total_count": 7476,
  "hook_set_count": 320,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v105 的可复用判断规则：

- `nested_bitmix_callee_probe` / `callee_bitmix_or_crypto_total_count`：只说明 nested callee 内存在 bitmix/crypto-like 静态特征；没有 clean X-Cylons input-output 同值日志时，不是算法恢复证据。
- `nested_callback_virtual_bridge_probe`：只说明 callback/virtual dispatch 可能承载值；需要真实 ACK/X-Cylons/SSL first-seen 窗口证明 absent-before / first-after / downstream equality。
- `nested_slot_return_value_lane_probe`、`callsite_return_lane_total_count`、`callsite_slot_lane_total_count`：用于排序 return/slot/value lane hook priority，不可直接升级为生成点。
- `next_hop_runtime_chain_call_count` 很高时，优先缩成 focused hook set，并保留 known control anchors；不要扩大为无边界全量 hook。
- `nested_downstream_callee_probe_count=0` 是负结果：记录静态没有直接 downstream callee 证据，不要为推进感伪造算法结论。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态窗口，保持 `algorithm_status=not_recovered`，并明确区分“nested-callee/value-flow hook 排序推进”和“算法本体仍未还原”。

## v106 经验值参考

2026-05-15 v106 在 v105 nested-callee / second-hop value-flow 之后，继续展开 focused third-hop fanout / callee-signature clustering。目标是消费 v105 的 next-hop runtime-chain calls 和 callee-body inner calls，把第三跳 callee body、callsite context、repeated target/body-signature clusters 收敛为下一轮动态 hook set；仍不能把静态 fanout/signature/bitmix/callback/slot probe 误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v106_focused_third_hop_fanout_signature_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v106_focused_third_hop_fanout_signature_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v106_focused_third_hop_fanout_signature_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v106_focused_third_hop_fanout_signature_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v106_0515.json
```

关键计数：

```json
{
  "trace_record_count": 960,
  "high_priority_trace_count": 960,
  "third_hop_bitmix_callee_probe_count": 291,
  "third_hop_callback_virtual_bridge_probe_count": 263,
  "third_hop_slot_return_lane_probe_count": 64,
  "repeated_fanout_signature_cluster_probe_count": 328,
  "known_control_anchor_third_hop_alignment_probe_count": 14,
  "third_hop_plain_downstream_probe_count": 0,
  "repeated_target_cluster_count": 47,
  "repeated_body_signature_cluster_count": 50,
  "callee_bitmix_or_crypto_total_count": 2057,
  "callee_indirect_branch_total_count": 1819,
  "next_hop_runtime_chain_call_count": 9230,
  "callsite_return_lane_total_count": 11478,
  "callsite_slot_lane_total_count": 16943,
  "v106_focused_third_hop_fanout_signature_hook_set_count": 384,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v106 的可复用判断规则：

- `third_hop_bitmix_callee_probe` / `callee_bitmix_or_crypto_total_count`：只说明第三跳 callee 具有 bitmix/crypto-like 静态特征；没有 clean X-Cylons input-output 同值日志时，不是算法恢复证据。
- `third_hop_callback_virtual_bridge_probe`：只说明第三跳或 callsite 附近可能经过 callback/virtual dispatch；需要真实 ACK/X-Cylons/SSL first-seen 窗口证明 absent-before / first-after / downstream equality。
- `third_hop_slot_return_lane_probe`、`callsite_return_lane_total_count`、`callsite_slot_lane_total_count`：只用于排序 return/slot/value lane hook priority，不可直接升级为 value source。
- `repeated_fanout_signature_cluster_probe`、`repeated_target_cluster_count`、`repeated_body_signature_cluster_count`：重复 target/body signature 是收敛动态 hook 的强信号，但仍是 probe；不要因为重复次数高就声明算法本体已还原。
- `third_hop_plain_downstream_probe_count=0` 是负结果：记录静态没有发现 plain downstream 证据，不要为推进感伪造算法结论。
- v106 hook set 应保留 v106 repeated clusters / third-hop callsites / callee bodies / further next-hop calls，并合并 v105-v99 controls；但升级规则仍必须依赖真实动态同值验证。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态窗口，保持 `algorithm_status=not_recovered`，并明确区分“第三跳 fanout/signature hook 排序推进”和“算法本体仍未还原”。

## v107 经验值参考

2026-05-15 v107 在 v106 third-hop fanout/signature clustering 之后，继续做 focused repeated-cluster upstream / value-origin 静态挖掘。目标是消费 v106 repeated/focused clusters，在 seed callsite 的 caller 上下文中回溯 prior call returns、return-to-arg、return-to-slot、slot-to-arg、argument-origin、callback/virtual、bitmix lanes，把 repeated clusters 收敛成更靠近 first-seen 的动态 hook set；仍不能把静态 upstream/value-origin lane 误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v107_focused_repeated_cluster_upstream_value_origin_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v107_focused_repeated_cluster_upstream_value_origin_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v107_focused_repeated_cluster_upstream_value_origin_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v107_focused_repeated_cluster_upstream_value_origin_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v107_0515.json
```

关键计数：

```json
{
  "trace_record_count": 302,
  "high_priority_trace_count": 289,
  "prior_return_to_arg_and_slot_value_origin_probe_count": 206,
  "prior_callee_return_to_argument_origin_probe_count": 62,
  "prior_callee_return_to_slot_origin_probe_count": 0,
  "slot_materialized_argument_origin_probe_count": 17,
  "callback_virtual_upstream_origin_bridge_probe_count": 3,
  "repeated_cluster_bitmix_origin_probe_count": 12,
  "plain_repeated_cluster_upstream_context_probe_count": 2,
  "prior_call_total_count": 2694,
  "ret_to_arg_lane_total_count": 3221,
  "ret_to_slot_lane_total_count": 376,
  "slot_to_arg_lane_total_count": 662,
  "arg_origin_lane_total_count": 6613,
  "callback_virtual_lane_total_count": 276,
  "near_bitmix_lane_total_count": 716,
  "downstream_after_seed_call_total_count": 2195,
  "next_hop_runtime_chain_call_count": 4354,
  "v107_focused_repeated_cluster_upstream_value_origin_hook_set_count": 448,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v107 的可复用判断规则：

- `prior_return_to_arg_and_slot_value_origin_probe`：prior callee return 同时出现进入 argument lane 与 slot lane，是高优先级 first-seen hook 信号；但静态桥接不等于 clean X-Cylons 生成点。
- `prior_callee_return_to_argument_origin_probe`：只说明前序 callee 返回值可能喂给后续实参；必须动态证明 absent-before / first-after / downstream equality 才能升级。
- `prior_callee_return_to_slot_origin_probe_count=0` 是负结果：单独 return-to-slot origin 未形成分类，但 ret+arg+slot 组合仍可作为 hook priority。
- `slot_materialized_argument_origin_probe` / `arg_origin_lane_total_count`：说明 slot/materialized/object-field 值进入实参准备过程；它是排序依据，不是算法证据。
- `callback_virtual_upstream_origin_bridge_probe`：只说明 upstream caller 可能通过 callback/virtual dispatch 承载值；需要真实 ACK/X-Cylons/SSL first-seen 同值日志。
- `repeated_cluster_bitmix_origin_probe`：repeated cluster 附近存在 bitmix/crypto-like lane；没有 clean X-Cylons input-output 对齐时不可声明算法恢复。
- v107 hook set 应覆盖 prior-call returns、ret-to-arg/slot、slot-to-arg、callback/virtual bridges、repeated v106 clusters，并合并 v106-v99 controls；不要扩大为无边界全量 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态窗口，保持 `algorithm_status=not_recovered`，并明确区分“upstream/value-origin hook 排序推进”和“算法本体仍未还原”。

## v108 经验值参考

2026-05-15 v108 在 v107 upstream/value-origin lanes 之后，继续展开 focused upstream producer-body / transitive-origin 静态挖掘。目标是消费 v107 的 explicit producer return calls，在 producer callee body 与 producer caller context 中同时排序 bitmix+return、callback/virtual、return-chain consumer、slot read/write、nested callee 与 downstream/next-hop runtime chain，形成更靠近 first-seen 的 focused hook set；仍不能把静态 producer body 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v108_focused_upstream_producer_body_transitive_origin_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v108_focused_upstream_producer_body_transitive_origin_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v108_focused_upstream_producer_body_transitive_origin_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v108_focused_upstream_producer_body_transitive_origin_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v108_0515.json
```

关键计数：

```json
{
  "trace_record_count": 900,
  "high_priority_trace_count": 900,
  "producer_body_bitmix_return_origin_probe_count": 760,
  "producer_callback_virtual_transitive_origin_probe_count": 130,
  "producer_return_chain_transitive_origin_probe_count": 10,
  "producer_slot_materialized_transitive_origin_probe_count": 0,
  "producer_nested_callee_transitive_origin_probe_count": 0,
  "producer_plain_transitive_origin_probe_count": 0,
  "repeated_producer_target_count": 79,
  "repeated_producer_body_signature_count": 45,
  "producer_body_bitmix_total_count": 1160,
  "producer_body_indirect_total_count": 620,
  "producer_body_call_total_count": 8554,
  "producer_return_touch_total_count": 15244,
  "producer_arg_setup_lane_total_count": 17540,
  "producer_return_consumption_lane_total_count": 22818,
  "producer_slot_read_lane_total_count": 6972,
  "producer_slot_write_lane_total_count": 12692,
  "producer_callback_virtual_lane_total_count": 1240,
  "producer_near_bitmix_lane_total_count": 1896,
  "next_hop_runtime_chain_call_count": 18288,
  "v108_focused_upstream_producer_body_transitive_origin_hook_set_count": 512,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v108 的可复用判断规则：

- `producer_body_bitmix_return_origin_probe`：producer callee body 同时具备 bitmix/crypto-like 和 return/value-register touch，是最高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `producer_callback_virtual_transitive_origin_probe`：producer body 或 caller context 经过 `blr/br` callback/virtual 边界，说明值可能跨虚调/回调传播；需要真实 ACK/X-Cylons/SSL first-seen 窗口证明 absent-before / first-after / downstream equality。
- `producer_return_chain_transitive_origin_probe`：只说明前序 producer return 被 caller context 消费并继续进入后续 lane；静态 return-chain 不是 clean value source。
- `producer_slot_materialized_transitive_origin_probe_count=0`、`producer_nested_callee_transitive_origin_probe_count=0`、`producer_plain_transitive_origin_probe_count=0` 是负结果：记录没有形成独立 slot/nested/plain 分类，不要为了推进感扩大为算法结论。
- 重复 producer target/body signature 是动态 hook 收敛信号；重复次数高只提升 hook priority，不可升级为 value source。
- v108 hook set 应合并 producer targets、producer callsites、producer caller function starts、producer body inner calls、return-consumption prior calls、downstream-after-producer calls、v107 seed downstream calls，以及 v107-v99 control anchors。hook set 上限可控制到 512，避免全量无边界 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态窗口，保持 `algorithm_status=not_recovered`，并明确区分“producer-body/transitive-origin hook 排序推进”和“算法本体仍未还原”。

## v109 经验值参考

2026-05-15 v109 在 v108 upstream producer-body / transitive-origin 之后，继续做 focused producer-body inner-callee / return-fanin 静态挖掘。目标是消费 v108 producer body 的 inner calls 与 next-hop runtime-chain calls，把 inner callee body、inner callsite fan-in context、prior return-to-arg/slot、callback/virtual、repeated target/body signature 收敛成更靠近 first-seen 的动态 hook set；仍不能把静态 inner-callee bitmix/return/fanin 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v109_focused_producer_body_inner_callee_return_fanin_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v109_focused_producer_body_inner_callee_return_fanin_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v109_focused_producer_body_inner_callee_return_fanin_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v109_focused_producer_body_inner_callee_return_fanin_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v109_0515.json
```

关键计数：

```json
{
  "trace_record_count": 1082,
  "high_priority_trace_count": 1082,
  "inner_callee_bitmix_return_fanin_probe_count": 680,
  "inner_callback_virtual_return_bridge_probe_count": 277,
  "inner_prior_return_to_arg_slot_fanin_probe_count": 28,
  "inner_return_fanin_lane_probe_count": 97,
  "inner_repeated_target_signature_probe_count": 0,
  "inner_nested_callee_fanout_probe_count": 0,
  "inner_plain_fanin_probe_count": 0,
  "repeated_inner_callee_target_count": 35,
  "repeated_inner_callee_body_signature_count": 37,
  "inner_body_bitmix_total_count": 1455,
  "inner_body_indirect_total_count": 1778,
  "inner_body_call_total_count": 8563,
  "inner_return_touch_total_count": 15861,
  "inner_arg_setup_lane_total_count": 16789,
  "inner_ret_to_arg_fanin_lane_total_count": 6955,
  "inner_ret_to_slot_fanin_lane_total_count": 1116,
  "inner_slot_read_lane_total_count": 6783,
  "inner_slot_write_lane_total_count": 12367,
  "inner_callback_virtual_lane_total_count": 1222,
  "inner_near_bitmix_lane_total_count": 1077,
  "next_hop_runtime_chain_call_count": 20814,
  "v109_focused_producer_body_inner_callee_return_fanin_hook_set_count": 640,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v109 的可复用判断规则：

- `inner_callee_bitmix_return_fanin_probe`：inner callee body 具备 bitmix/crypto-like 与 return/value-register touch，并在 callsite fan-in 附近出现 return/slot/callback lane，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `inner_callback_virtual_return_bridge_probe`：inner callee 或 callsite context 出现 `blr/br`/indirect branch，说明值可能跨 callback/virtual 边界传播；必须动态证明 absent-before / first-after / downstream equality 才能升级。
- `inner_prior_return_to_arg_slot_fanin_probe`：prior callee return 同时汇入 argument lane 与 slot lane，是强 fan-in 排序信号；静态桥接不等于 clean value source。
- `inner_return_fanin_lane_probe`：只说明 inner callsite 附近存在 return-to-arg 或 return-to-slot fan-in；它用于缩小 hook priority，不是算法证据。
- `repeated_inner_callee_target_count` / `repeated_inner_callee_body_signature_count` 是动态 hook 收敛信号；重复 target/body signature 不能单独升级为 value source。
- `inner_repeated_target_signature_probe_count=0`、`inner_nested_callee_fanout_probe_count=0`、`inner_plain_fanin_probe_count=0` 是分类负结果：记录没有形成独立 repeated/nested/plain 分类，不要为了推进感扩大为算法结论。
- v109 hook set 应合并 inner callee targets、inner callsites、inner caller function starts、ret-to-arg/slot prior producer calls、downstream-after-inner-call、inner callee body nested calls、v108 next-hops 与 v108-v99 controls。hook set 上限可控制到 640，避免全量无边界 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态窗口，保持 `algorithm_status=not_recovered`，并明确区分“inner-callee/return-fanin hook 排序推进”和“算法本体仍未还原”。

## v110 经验值参考

2026-05-15 v110 在 v109 producer-body inner-callee / return-fanin 之后，继续做 focused inner-callee nested return/value-lane fanout 静态挖掘。目标是消费 v109 inner callee body 内部 nested calls、callsite prior/downstream fan-in calls、ret-to-arg/slot producer calls，把 nested callee body 与 nested callsite value-lane context 收敛成下一轮 first-seen 动态 hook set；仍不能把静态 nested bitmix/return/value/callback/repeated 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v110_focused_inner_callee_nested_return_value_fanout_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v110_focused_inner_callee_nested_return_value_fanout_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v110_focused_inner_callee_nested_return_value_fanout_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v110_focused_inner_callee_nested_return_value_fanout_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v110_0515.json
```

关键计数：

```json
{
  "trace_record_count": 1600,
  "high_priority_trace_count": 1600,
  "nested_bitmix_return_value_lane_probe_count": 1203,
  "nested_callback_virtual_value_bridge_probe_count": 310,
  "nested_prior_return_to_arg_slot_value_probe_count": 34,
  "nested_slot_to_arg_value_lane_probe_count": 32,
  "nested_return_value_consumer_probe_count": 21,
  "repeated_nested_callee_target_count": 66,
  "repeated_nested_callee_body_signature_count": 64,
  "nested_body_bitmix_total_count": 2284,
  "nested_body_call_total_count": 11965,
  "nested_return_touch_total_count": 22130,
  "nested_arg_setup_lane_total_count": 28010,
  "nested_ret_to_arg_value_lane_total_count": 12720,
  "nested_ret_to_slot_value_lane_total_count": 2166,
  "nested_slot_to_arg_value_lane_total_count": 2750,
  "nested_return_consumer_lane_total_count": 22711,
  "nested_slot_read_lane_total_count": 27744,
  "nested_slot_write_lane_total_count": 19581,
  "nested_callback_virtual_lane_total_count": 2174,
  "nested_near_bitmix_lane_total_count": 2347,
  "next_hop_runtime_chain_call_count": 32726,
  "v110_focused_inner_callee_nested_return_value_fanout_hook_set_count": 768,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v110 的可复用判断规则：

- `nested_bitmix_return_value_lane_probe`：nested callee body 或 callsite context 同时具备 bitmix/crypto-like、return/value-register touch、ret-to-arg/slot 或 return-consumer lane，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `nested_callback_virtual_value_bridge_probe`：nested callee 或 nested callsite context 出现 `blr/br`/indirect branch，说明值可能跨 callback/virtual 边界传播；必须动态证明 absent-before / first-after / downstream equality 才能升级。
- `nested_prior_return_to_arg_slot_value_probe`：prior callee return 同时汇入 argument lane 与 slot lane，是强 fanout/fan-in 排序信号；静态桥接不等于 clean value source。
- `nested_slot_to_arg_value_lane_probe`：slot/materialized value 进入后续实参准备过程；它是 hook priority，不是算法证据。
- `nested_return_value_consumer_probe`：post-call 或 context 中存在 return consumer lane；只能说明返回值可能被消费传播，不可直接升级为生成点。
- `repeated_nested_callee_target_count` / `repeated_nested_callee_body_signature_count` 是动态 hook 收敛信号；重复 target/body signature 不能单独升级为 value source。
- v110 hook set 应合并 nested callee targets、nested callsites、nested caller context starts、ret-to-arg/slot producer calls、downstream-after-nested-call、nested callee deeper body calls、v109 next-hops 与 v108-v99 controls。hook set 上限可控制到 768，避免全量无边界 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态窗口，保持 `algorithm_status=not_recovered`，并明确区分“nested return/value-lane fanout hook 排序推进”和“算法本体仍未还原”。

## v112 经验值参考

2026-05-15 v112 在 v111 deeper nested convergence / return-consumer dominance 之后，继续做 focused return-consumer upstream dominance / fan-in 静态挖掘。目标是把 return-consumer dominance lane、upstream producer、fan-in callsite/callee、prior ret-to-arg/slot、slot-to-arg materialized lane、callback/virtual bridge 与 runtime-chain next-hop 收敛成下一轮 first-seen 动态 hook set；仍不能把静态 dominance/fan-in/bitmix/return-consumer 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v112_focused_return_consumer_upstream_dominance_fanin_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v112_focused_return_consumer_upstream_dominance_fanin_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v112_focused_return_consumer_upstream_dominance_fanin_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v112_focused_return_consumer_upstream_dominance_fanin_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v112_0515.json
```

关键计数：

```json
{
  "trace_record_count": 2800,
  "high_priority_trace_count": 2800,
  "fanin_bitmix_return_consumer_dominance_probe_count": 2448,
  "fanin_repeated_return_lane_convergence_probe_count": 322,
  "fanin_callback_virtual_consumer_bridge_probe_count": 12,
  "fanin_prior_return_to_arg_slot_probe_count": 12,
  "fanin_slot_to_arg_materialized_probe_count": 2,
  "fanin_return_consumer_probe_count": 4,
  "fanin_body_fanout_probe_count": 0,
  "fanin_plain_context_probe_count": 0,
  "fanin_body_bitmix_total_count": 3770,
  "fanin_body_call_total_count": 25628,
  "fanin_return_touch_total_count": 44882,
  "fanin_ret_to_arg_lane_total_count": 39152,
  "fanin_ret_to_slot_lane_total_count": 8156,
  "fanin_return_consumer_lane_total_count": 62984,
  "fanin_dominant_return_consumer_lane_total_count": 49950,
  "next_hop_runtime_chain_call_count": 80354,
  "hook_set_count": 737,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v112 的可复用判断规则：

- `fanin_bitmix_return_consumer_dominance_probe`：fan-in callee/body 同时具备 bitmix/crypto-like、return/value-register touch 与 dominant return-consumer lane，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `fanin_repeated_return_lane_convergence_probe`：重复 return-lane convergence 只提高 hook priority；重复/收敛不能单独升级为 value source。
- `fanin_callback_virtual_consumer_bridge_probe`：return consumer 侧出现 callback/virtual bridge，说明值可能跨虚调/回调传播；必须动态证明 absent-before / first-after / downstream equality 才能升级。
- `fanin_prior_return_to_arg_slot_probe` 与 `fanin_slot_to_arg_materialized_probe`：prior return 汇入实参/slot 或 materialized slot 进入实参，是 fan-in 排序信号；静态桥接不等于 clean value source。
- `fanin_return_consumer_probe`：只说明返回值在 consumer lane 中被继续消费，不可直接等价为生成点。
- `fanin_body_fanout_probe_count=0`、`fanin_plain_context_probe_count=0` 是分类负结果：记录没有形成独立 fanout/plain 分类，不要为了推进感扩大为算法结论。
- v112 hook set 应覆盖 fan-in callsite/callee、upstream producer、dominant return-consumer lane、prior ret-to-arg/slot、slot-to-arg materialized lane、callback/virtual bridge、runtime-chain next-hop，并合并 v111-v99 controls；hook set 可控制在约 737，避免无边界全量 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态窗口，保持 `algorithm_status=not_recovered`，并明确区分“return-consumer upstream dominance / fan-in hook 排序推进”和“算法本体仍未还原”。

## v113 经验值参考

2026-05-15 v113 在 v112 return-consumer upstream dominance / fan-in 之后，继续做 focused fan-in body / source-lane 静态挖掘。目标是把 v112 fan-in / return-consumer dominance 记录扩展到 source callee body、source-lane context、ret-to-arg/slot、slot-to-arg、callback/virtual、runtime-chain 等候选点，形成下一轮真实 ACK / X-Cylons / SSL first-seen 同值验证的 focused hook set；仍不能把静态 source-lane / fan-in body 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v113_focused_fanin_body_source_lane_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v113_focused_fanin_body_source_lane_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v113_focused_fanin_body_source_lane_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v113_focused_fanin_body_source_lane_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v113_0515.json
```

关键计数：

```json
{
  "trace_record_count": 1600,
  "high_priority_trace_count": 1600,
  "source_body_bitmix_return_lane_probe_count": 1500,
  "source_repeated_return_lane_convergence_probe_count": 84,
  "source_callback_virtual_bridge_probe_count": 8,
  "source_slot_to_arg_materialized_probe_count": 8,
  "v113_focused_fanin_body_source_lane_hook_set_count": 739,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v113 的可复用判断规则：

- `source_body_bitmix_return_lane_probe`：source callee body 同时具备 bitmix/crypto-like、return/value-register touch 与 fan-in/source-lane context，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `source_repeated_return_lane_convergence_probe`：重复 return-lane convergence 只提升动态 hook priority；重复/收敛本身不能升级为 value source。
- `source_callback_virtual_bridge_probe`：source lane 经过 callback/virtual dispatch，说明值可能跨虚调/回调传播；必须动态证明 absent-before / first-after / downstream equality 才能升级。
- `source_slot_to_arg_materialized_probe`：slot/materialized value 进入后续实参准备过程，是排序信号，不是算法证据。
- v113 hook set 应覆盖 source callee bodies、fan-in callsites、ret-to-arg/slot、slot-to-arg、callback/virtual bridge、runtime-chain next-hop，并合并 v112-v99 controls；hook set 可控制在约 739，避免无边界全量 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态同值窗口，保持 `algorithm_status=not_recovered`，并明确区分“fan-in body/source-lane hook 排序推进”和“算法本体仍未还原”。

v113 closure check 参考：

1. 校验脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且非空。
2. 抽查 status JSON 中上述 count 与 judgement 字段。
3. conclusion / project memory / daily / SESSION 必须包含 `v113` 与 `algorithm_status=not_recovered`，避免把 source-lane 静态扩展误读为算法已还原。
4. 归档后运行 `memory/scripts/memory-sync.py sync`，再搜索 `v113 focused fanin body source lane algorithm_status not_recovered`，确认 project memory 可检索。
5. 检查无遗留 `static_v113|run_v113|v113_focused|frida.*v113` 进程。
6. mem0 若返回 `200 {"results":[]}` 但 search 暂不命中，按既有 mem0 踩坑处理：以本地 Markdown/JSON/SESSION + memory-sync 搜索命中作为可审计事实源。

## v115 经验值参考

2026-05-15 v115 在 v114 source-body nested dominance follow-up 之后，继续做 focused nested-dominance fanout / value-lane 静态挖掘。目标是消费 v114 的 nested dominance 记录，把 dominant return-consumer、ret-to-arg/slot、slot-materialized、downstream fanout 与 nested-body fanout lanes 扩展成更靠近真实 ACK/X-Cylons/SSL first-seen 的 value-lane/fanout hook set；仍不能把静态 dominance/value-lane/bitmix/return-consumer 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v115_focused_nested_dominance_fanout_value_lane_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v115_focused_nested_dominance_fanout_value_lane_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v115_focused_nested_dominance_fanout_value_lane_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v115_focused_nested_dominance_fanout_value_lane_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v115_0515.json
```

关键计数：

```json
{
  "trace_record_count": 2800,
  "high_priority_trace_count": 2800,
  "value_lane_bitmix_return_dominance_probe_count": 2682,
  "value_lane_prior_return_to_arg_slot_probe_count": 78,
  "value_lane_dominant_return_consumer_probe_count": 40,
  "value_lane_slot_materialized_argument_probe_count": 0,
  "value_lane_callback_virtual_bridge_probe_count": 0,
  "value_lane_repeated_fanout_convergence_probe_count": 0,
  "value_lane_deeper_fanout_probe_count": 0,
  "value_lane_plain_context_probe_count": 0,
  "value_lane_body_bitmix_total_count": 8132,
  "value_lane_body_indirect_total_count": 3108,
  "value_lane_body_call_total_count": 44774,
  "value_lane_return_touch_total_count": 70360,
  "value_lane_arg_lane_total_count": 89588,
  "value_lane_ret_to_arg_total_count": 50540,
  "value_lane_ret_to_slot_total_count": 9766,
  "value_lane_slot_to_arg_total_count": 22994,
  "value_lane_return_consumer_total_count": 93006,
  "value_lane_dominant_return_consumer_total_count": 85792,
  "value_lane_slot_read_total_count": 95204,
  "value_lane_slot_write_total_count": 62918,
  "value_lane_callback_virtual_total_count": 5100,
  "value_lane_near_bitmix_total_count": 9106,
  "value_lane_downstream_fanout_total_count": 62076,
  "next_hop_runtime_chain_call_count": 125750,
  "v115_focused_nested_dominance_fanout_value_lane_hook_set_count": 808,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v115 的可复用判断规则：

- `value_lane_bitmix_return_dominance_probe`：value-lane callee body 或 caller context 同时具备 bitmix/crypto-like、return/value-register touch 与 dominant return-consumer/ret-to-arg lane，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `value_lane_prior_return_to_arg_slot_probe`：prior callee return 同时进入 argument lane 与 slot lane，是强 value propagation 排序信号；静态桥接不能直接升级为 value source。
- `value_lane_dominant_return_consumer_probe`：dominant return-consumer 表示返回值被后续 lane 稳定消费传播；它是 hook priority，不是生成点证明。
- `value_lane_slot_materialized_argument_probe_count=0`、`value_lane_callback_virtual_bridge_probe_count=0`、`value_lane_repeated_fanout_convergence_probe_count=0`、`value_lane_deeper_fanout_probe_count=0`、`value_lane_plain_context_probe_count=0` 是分类负结果：记录没有形成独立 slot/callback/repeated/deeper/plain 分类，不要为了推进感扩大为算法结论。
- v115 hook set 应合并 value-lane callsites/callees、caller function starts、prior producer calls、downstream-after-value-lane、value-lane callee body inner calls、v114 nested dominance points、v113 source lanes、v112 fan-in dominance points、v111-v110 lanes，以及 v106-v99 controls；hook set 可控制到约 808，避免无边界全量 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态同值窗口，保持 `algorithm_status=not_recovered`，并明确区分“nested-dominance fanout/value-lane hook 排序推进”和“算法本体仍未还原”。

v115 closure check 参考：

1. 校验脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且非空。
2. 抽查 status JSON 中 count 与 judgement 字段，尤其 `v115_focused_nested_dominance_fanout_value_lane_hook_set_count`、`new_value_source_evidence=false`、`first_seen_evidence=false`、`algorithm_status=not_recovered`。
3. conclusion / project memory / daily / SESSION 必须包含 `v115` 与 `not_recovered`，避免把 value-lane 静态扩展误读为算法已还原。
4. 归档后运行 `memory/scripts/memory-sync.py sync`，再搜索 `v115 focused nested dominance fanout value lane algorithm_status not_recovered`，确认 project memory 可检索。
5. 检查无遗留 `static_v115|run_v115|v115_focused|frida.*v115` 进程。

## v117 经验值参考

2026-05-15 v117 在 v116 focused value-lane upstream / source-owner 之后，继续做 focused source-owner closure / fanout 静态挖掘。目标是消费 v116 source-owner records，并把 body closure calls、prior return producers、slot/materialized owner lanes、return-consumer lanes、downstream fanout 与 carried next-hop calls 展开到 source-owner closure/fanout contexts，形成下一轮真实 ACK/X-Cylons/SSL first-seen 同值验证的 focused hook set；仍不能把静态 closure/fanout/bitmix/return-consumer 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v117_focused_source_owner_closure_fanout_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v117_focused_source_owner_closure_fanout_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v117_focused_source_owner_closure_fanout_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v117_focused_source_owner_closure_fanout_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v117_0515.json
```

关键计数：

```json
{
  "trace_record_count": 1800,
  "high_priority_trace_count": 1800,
  "closure_bitmix_return_fanout_probe_count": 1787,
  "closure_prior_return_arg_slot_probe_count": 0,
  "closure_callback_virtual_bridge_probe_count": 0,
  "closure_slot_materialized_probe_count": 13,
  "repeated_closure_callee_target_count": 22,
  "repeated_closure_callee_body_signature_count": 24,
  "closure_body_bitmix_total_count": 4811,
  "closure_body_indirect_total_count": 3259,
  "closure_body_call_total_count": 37998,
  "closure_return_touch_total_count": 58381,
  "closure_arg_lane_total_count": 54525,
  "closure_ret_to_arg_total_count": 81796,
  "closure_ret_to_slot_total_count": 18023,
  "closure_return_consumer_total_count": 4650,
  "closure_dominant_return_consumer_total_count": 48904,
  "next_hop_runtime_chain_call_count": 113968,
  "v117_focused_source_owner_closure_fanout_hook_set_count": 852,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v117 的可复用判断规则：

- `closure_bitmix_return_fanout_probe`：closure/source-owner body 同时具备 bitmix/crypto-like、return/value-register touch 与 fanout/return-consumer context，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `closure_slot_materialized_probe`：slot/materialized owner lane 进入 closure fanout，是排序信号，不是 value source 证据。
- `closure_prior_return_arg_slot_probe_count=0`、`closure_callback_virtual_bridge_probe_count=0`、`closure_return_consumer_probe_count=0`、`closure_repeated_fanout_convergence_probe_count=0`、`closure_deeper_fanout_probe_count=0`、`closure_plain_context_probe_count=0` 是分类负结果：记录未形成独立 prior-return/callback/consumer/repeated/deeper/plain 分类，不要为了推进感扩大为算法结论。
- `repeated_closure_callee_target_count` / `repeated_closure_callee_body_signature_count` 是动态 hook 收敛信号；重复 target/body signature 不能单独升级为 value source。
- v117 hook set 应覆盖 closure callee targets、closure callsites、caller function starts、body nested calls、slot/materialized lanes、dominant return-consumer lanes、downstream fanout、v116 source-owner records 与 v115-v99 controls；hook set 可控制到约 852，避免无边界全量 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态同值窗口，保持 `algorithm_status=not_recovered`，并明确区分“source-owner closure/fanout hook 排序推进”和“算法本体仍未还原”。

v117 closure check 参考：

1. 校验脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且非空。
2. 抽查 status JSON 中 count 与 judgement 字段，尤其 `closure_bitmix_return_fanout_probe_count`、`closure_slot_materialized_probe_count`、`v117_focused_source_owner_closure_fanout_hook_set_count`、`new_value_source_evidence=false`、`first_seen_evidence=false`、`algorithm_status=not_recovered`。
3. conclusion / project memory / daily / SESSION 必须包含 `v117` 与 `not_recovered`，避免把 source-owner closure/fanout 静态扩展误读为算法已还原。
4. 归档后运行 `memory/scripts/memory-sync.py sync`，再搜索 `v117 focused source-owner closure fanout algorithm_status not_recovered`，确认 project memory 可检索；本轮验证 Top1 命中 `2026-05-15_project_douyin-xcylons-v117-source-owner-closure-fanout`。
5. 检查无遗留 `static_v117|run_v117|v117_focused|frida.*v117` 进程。

## v118 经验值参考

2026-05-15 v118 在 v117 source-owner closure / fanout 之后，继续做 focused value-use closure / first-seen probe 静态挖掘。目标是消费 v117 closure/fanout records，把 value-use body、prior producer return、arg/slot write/read、return-consumer、post-fanout call、callback/virtual 与 near-bitmix lanes 收敛成下一轮真实 ACK/X-Cylons/SSL first-seen 同值验证的 focused hook set；仍不能把静态 value-use / first-seen probe 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v118_focused_value_use_closure_first_seen_probe_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v118_focused_value_use_closure_first_seen_probe_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v118_focused_value_use_closure_first_seen_probe_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v118_focused_value_use_closure_first_seen_probe_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v118_0515.json
```

关键计数：

```json
{
  "trace_record_count": 1242,
  "high_priority_trace_count": 1242,
  "value_use_bitmix_return_first_seen_probe_count": 1124,
  "value_use_prior_return_arg_slot_first_seen_probe_count": 106,
  "value_use_callback_virtual_first_seen_bridge_probe_count": 4,
  "value_use_return_consumer_first_seen_probe_count": 8,
  "value_use_slot_materialized_first_seen_probe_count": 0,
  "value_use_repeated_fanout_first_seen_probe_count": 0,
  "value_use_deeper_fanout_first_seen_probe_count": 0,
  "value_use_plain_first_seen_context_probe_count": 0,
  "value_use_body_bitmix_total_count": 3171,
  "value_use_body_indirect_total_count": 3479,
  "value_use_body_call_total_count": 27529,
  "value_use_return_touch_total_count": 36784,
  "first_seen_prior_producer_call_total_count": 14859,
  "first_seen_value_arg_write_total_count": 75706,
  "first_seen_value_slot_write_total_count": 12036,
  "first_seen_value_slot_read_total_count": 13833,
  "first_seen_return_consumer_total_count": 95631,
  "first_seen_post_fanout_call_total_count": 51110,
  "first_seen_callback_virtual_total_count": 3588,
  "first_seen_near_bitmix_total_count": 3399,
  "next_hop_runtime_chain_call_count": 68690,
  "v118_focused_value_use_closure_first_seen_probe_hook_set_count": 862,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v118 的可复用判断规则：

- `value_use_bitmix_return_first_seen_probe`：value-use callee/body 或 closure context 同时具备 bitmix/crypto-like、return/value-register touch 与 first-seen-value-use context，是高优先级动态 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `value_use_prior_return_arg_slot_first_seen_probe`：prior producer return 同时汇入 argument lane 与 slot lane，是强 first-seen 排序信号；静态桥接不能直接升级为 value source。
- `value_use_callback_virtual_first_seen_bridge_probe`：value-use closure 经过 callback/virtual dispatch，说明值可能跨虚调/回调传播；必须动态证明 absent-before / first-after / downstream equality 才能升级。
- `value_use_return_consumer_first_seen_probe`：return-consumer lane 表示返回值被后续 use/consumer 继续传播；它是 hook priority，不是生成点证明。
- `value_use_slot_materialized_first_seen_probe_count=0`、`value_use_repeated_fanout_first_seen_probe_count=0`、`value_use_deeper_fanout_first_seen_probe_count=0`、`value_use_plain_first_seen_context_probe_count=0` 是分类负结果：记录未形成独立 slot/repeated/deeper/plain 分类，不要为了推进感扩大为算法结论。
- v118 hook set 应覆盖 value-use callsites/callees、prior producer calls、arg/slot write/read lanes、return-consumer lanes、post-fanout calls、callback/virtual bridge、near-bitmix lanes，并合并 v117-v99 controls；hook set 可控制到约 862，避免无边界全量 hook。
- 实现脚本中要兼容 v117 context lane 既可能是 dict 也可能是 string 的情况；遍历 lane 时先归一化为 `lane_obj = lane if isinstance(lane, dict) else {'line': str(lane)}`，否则会在 `.get('line')` 处崩溃。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态同值窗口，保持 `algorithm_status=not_recovered`，并明确区分“value-use closure / first-seen probe hook 排序推进”和“算法本体仍未还原”。

v118 closure check 参考：

1. 校验脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且非空。
2. 抽查 status JSON 中 count 与 judgement 字段，尤其 `value_use_bitmix_return_first_seen_probe_count`、`value_use_prior_return_arg_slot_first_seen_probe_count`、`v118_focused_value_use_closure_first_seen_probe_hook_set_count`、`new_value_source_evidence=false`、`first_seen_evidence=false`、`algorithm_status=not_recovered`。
3. conclusion / project memory / daily / SESSION 必须包含 `v118` 与 `not_recovered`，避免把 value-use closure/first-seen 静态扩展误读为算法已还原。
4. 归档后运行 `memory/scripts/memory-sync.py sync`，再搜索 `v118 focused value-use closure first-seen probe algorithm_status not_recovered`，确认项目记忆可检索；本轮验证 Top1 命中 `2026-05-15_project_douyin-xcylons-v118-value-use-closure-first-seen-probe`。
5. 检查无遗留 `static_v118|run_v118|v118_focused|frida.*v118` 进程。

## v119 经验值参考

2026-05-15 v119 在 v118 value-use closure / first-seen probe 之后，继续做 focused first-seen producer / consumer closure 静态挖掘。目标是消费 v118 value-use / first-seen 记录，把 prior producer calls、return-to-arg/slot pair、slot read/write、return-consumer、post-consumer fanout、callback/virtual bridge、callee body fanout 与 carried runtime-chain calls 收敛成下一轮真实 ACK/X-Cylons/SSL first-seen 同值验证的 focused hook set；仍不能把静态 first-seen producer-consumer closure 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v119_focused_first_seen_producer_consumer_closure_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v119_focused_first_seen_producer_consumer_closure_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v119_focused_first_seen_producer_consumer_closure_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v119_focused_first_seen_producer_consumer_closure_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v119_0515.json
```

关键计数：

```json
{
  "trace_record_count": 2600,
  "high_priority_trace_count": 2600,
  "pc_bitmix_return_producer_consumer_closure_probe_count": 2504,
  "pc_return_arg_slot_pair_closure_probe_count": 96,
  "pc_producer_to_consumer_bridge_probe_count": 0,
  "pc_callback_virtual_closure_bridge_probe_count": 0,
  "pc_slot_materialized_closure_probe_count": 0,
  "pc_repeated_closure_convergence_probe_count": 0,
  "pc_deeper_consumer_fanout_probe_count": 0,
  "pc_plain_closure_context_probe_count": 0,
  "repeated_pc_callee_target_count": 32,
  "repeated_pc_callee_body_signature_count": 28,
  "pc_body_bitmix_total_count": 8142,
  "pc_body_indirect_total_count": 9684,
  "pc_body_call_total_count": 72458,
  "pc_return_touch_total_count": 88984,
  "pc_pre_producer_call_total_count": 37330,
  "pc_post_consumer_call_total_count": 147176,
  "pc_return_to_arg_lane_total_count": 201201,
  "pc_return_to_slot_lane_total_count": 28805,
  "pc_slot_read_lane_total_count": 36810,
  "pc_slot_write_lane_total_count": 5556,
  "pc_arg_chain_lane_total_count": 372150,
  "pc_callback_virtual_total_count": 8744,
  "pc_near_bitmix_total_count": 9719,
  "next_hop_runtime_chain_call_count": 141532,
  "v119_focused_first_seen_producer_consumer_closure_hook_set_count": 927,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v119 的可复用判断规则：

- `pc_bitmix_return_producer_consumer_closure_probe`：producer-consumer closure 中同时出现 bitmix/crypto-like、return/value-register touch、pre-producer 与 post-consumer/use context，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `pc_return_arg_slot_pair_closure_probe`：return-to-arg 与 return-to-slot pair 同时存在，说明值可能在 producer/consumer closure 内被复制和落槽；它是排序信号，不是 clean value source 证据。
- `pc_producer_to_consumer_bridge_probe_count=0`、`pc_callback_virtual_closure_bridge_probe_count=0`、`pc_slot_materialized_closure_probe_count=0`、`pc_repeated_closure_convergence_probe_count=0`、`pc_deeper_consumer_fanout_probe_count=0`、`pc_plain_closure_context_probe_count=0` 是分类负结果：本轮高优先级几乎都被 bitmix-return closure 与 return-arg-slot pair 覆盖，不要为推进感扩大为算法结论。
- `repeated_pc_callee_target_count` / `repeated_pc_callee_body_signature_count` 是动态 hook 收敛信号；重复 target/body signature 不能单独升级为 value source。
- v119 hook set 应覆盖 producer-consumer callsites/callees、closure function starts、producer/consumer calls、v118 value-use points、v117 closure points、v116 source-owner points、v115 value-lane points、v114 nested dominance points、v113 source lanes、v112 fan-in dominance points 与 v106-v99 controls；hook set 可控制到约 927，避免无边界全量 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态同值窗口，保持 `algorithm_status=not_recovered`，并明确区分“first-seen producer-consumer closure hook 排序推进”和“算法本体仍未还原”。

v119 closure check 参考：

1. 校验脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且非空。
2. 抽查 status JSON 中 count 与 judgement 字段，尤其 `pc_bitmix_return_producer_consumer_closure_probe_count`、`pc_return_arg_slot_pair_closure_probe_count`、`v119_focused_first_seen_producer_consumer_closure_hook_set_count`、`new_value_source_evidence=false`、`first_seen_evidence=false`、`algorithm_status=not_recovered`。
3. conclusion / project memory / daily / SESSION 必须包含 `v119` 与 `not_recovered`，避免把 first-seen producer-consumer closure 静态扩展误读为算法已还原。
4. 归档后运行 `memory/scripts/memory-sync.py sync`，再搜索 `v119 focused first-seen producer consumer closure algorithm_status not_recovered`，确认项目记忆可检索；本轮验证 Top1 命中 `2026-05-15_project_douyin-xcylons-v119-first-seen-producer-consumer-closure`。
5. 检查无遗留 `static_v119|run_v119|v119_focused|frida.*v119` 进程。

## v120 经验值参考

2026-05-15 v120 在 v119 first-seen producer / consumer closure 之后，继续做 focused first-seen deeper producer/consumer value-origin 静态挖掘。目标是消费 v119 producer-consumer closure records，把 producer calls、return-to-arg/slot pair、slot materialization、callback/virtual lanes、callee body fanout 与 carried runtime-chain calls 继续向 deeper value-origin probe 扩展，生成更靠近动态 first-seen 同值验证的 hook set；仍不能把静态 deeper value-origin probe 误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v120_focused_first_seen_deeper_producer_consumer_value_origin_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v120_focused_first_seen_deeper_producer_consumer_value_origin_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v120_focused_first_seen_deeper_producer_consumer_value_origin_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v120_focused_first_seen_deeper_producer_consumer_value_origin_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v120_0515.json
```

关键计数：

```json
{
  "trace_record_count": 3400,
  "high_priority_trace_count": 3400,
  "deeper_pc_value_origin_bitmix_return_probe_count": 3213,
  "deeper_pc_return_arg_slot_origin_probe_count": 187,
  "deeper_pc_callback_virtual_origin_bridge_probe_count": 0,
  "deeper_pc_slot_materialized_origin_probe_count": 0,
  "deeper_pc_repeated_origin_convergence_probe_count": 0,
  "deeper_pc_consumer_fanout_origin_probe_count": 0,
  "deeper_pc_plain_origin_context_probe_count": 0,
  "repeated_deeper_origin_callee_target_count": 30,
  "repeated_deeper_origin_callee_body_signature_count": 26,
  "deeper_origin_body_bitmix_total_count": 10314,
  "deeper_origin_body_indirect_total_count": 16661,
  "deeper_origin_body_call_total_count": 83372,
  "deeper_origin_return_touch_total_count": 102750,
  "origin_prior_producer_call_total_count": 44118,
  "origin_downstream_consumer_call_total_count": 178294,
  "origin_return_to_arg_lane_total_count": 239744,
  "origin_return_to_slot_lane_total_count": 34332,
  "origin_slot_to_arg_lane_total_count": 46688,
  "origin_slot_read_lane_total_count": 46688,
  "origin_slot_write_lane_total_count": 6800,
  "origin_callback_virtual_total_count": 9288,
  "origin_near_bitmix_total_count": 12522,
  "next_hop_runtime_chain_call_count": 199362,
  "v120_focused_first_seen_deeper_producer_consumer_value_origin_hook_set_count": 929,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v120 的可复用判断规则：

- `deeper_pc_value_origin_bitmix_return_probe`：deeper producer/consumer value-origin context 中同时出现 bitmix/crypto-like、return/value-register touch、producer/consumer/use lane，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `deeper_pc_return_arg_slot_origin_probe`：return-to-arg 与 return-to-slot/slot lane 形成 deeper origin pair，说明值可能在 producer/consumer value-origin 路径中被复制、落槽或再消费；它是排序信号，不是 clean value source 证据。
- `deeper_pc_callback_virtual_origin_bridge_probe_count=0`、`deeper_pc_slot_materialized_origin_probe_count=0`、`deeper_pc_repeated_origin_convergence_probe_count=0`、`deeper_pc_consumer_fanout_origin_probe_count=0`、`deeper_pc_plain_origin_context_probe_count=0` 是分类负结果：本轮新增主要集中在 bitmix-return deeper probe 与 return-arg-slot origin pair，不要为推进感扩大为算法结论。
- `repeated_deeper_origin_callee_target_count` / `repeated_deeper_origin_callee_body_signature_count` 是动态 hook 收敛信号；重复 target/body signature 不能单独升级为 value source。
- v120 hook set 应覆盖 deeper origin callee/callsite、producer calls、return-to-arg/slot lanes、slot read/write/materialized lanes、callback/virtual lanes、body fanout、v119 producer-consumer closure points、v118 value-use points 与 v106-v99 controls；hook set 可控制到约 929，避免无边界全量 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态同值窗口，保持 `algorithm_status=not_recovered`，并明确区分“deeper producer/consumer value-origin hook 排序推进”和“算法本体仍未还原”。

v120 closure check 参考：

1. 校验脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且非空。
2. 抽查 status JSON 中 count 与 judgement 字段，尤其 `deeper_pc_value_origin_bitmix_return_probe_count`、`deeper_pc_return_arg_slot_origin_probe_count`、`v120_focused_first_seen_deeper_producer_consumer_value_origin_hook_set_count`、`new_value_source_evidence=false`、`first_seen_evidence=false`、`algorithm_status=not_recovered`。
3. 注意 v120 JSON 中 `algorithm_status` / evidence 字段可能位于 `judgement` 子对象内，且完整 records 可能只以 sample 字段 `v120_trace_records` / `priority_records` 输出；验证脚本不要误按顶层 `records` 或顶层 `algorithm_status` 判失败。
4. conclusion / project memory / daily / SESSION 必须包含 `v120` 与 `not_recovered`，避免把 deeper value-origin 静态扩展误读为算法已还原。
5. 归档后运行 `memory/scripts/memory-sync.py sync`，再搜索 `v120 focused first-seen deeper producer consumer value origin algorithm_status not_recovered`，确认项目记忆可检索；本轮验证 Top1 命中 `2026-05-15_project_douyin-xcylons-v120-first-seen-deeper-producer-consumer-value-origin`。
6. 检查无遗留 `static_v120|run_v120|v120_focused|frida.*v120` 进程。

## v121 经验值参考

2026-05-15 v121 在 v120 first-seen deeper producer/consumer value-origin 之后，继续做 focused first-seen origin-chain / dominance 静态挖掘。目标是消费 v120 deeper value-origin records，把 origin-chain body、return-to-arg/slot dominance、slot/materialized lanes、return-consumer dominance、downstream consumer calls 与 carried runtime-chain calls 收敛成下一轮真实 ACK/X-Cylons/SSL first-seen 同值验证的 focused hook set；仍不能把静态 origin-chain/dominance 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v121_focused_first_seen_origin_chain_dominance_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v121_focused_first_seen_origin_chain_dominance_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v121_focused_first_seen_origin_chain_dominance_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v121_focused_first_seen_origin_chain_dominance_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v121_0515.json
```

关键计数：

```json
{
  "trace_record_count": 4200,
  "high_priority_trace_count": 4200,
  "origin_chain_bitmix_return_dominance_probe_count": 2881,
  "origin_chain_return_arg_slot_dominance_probe_count": 1319,
  "v121_focused_first_seen_origin_chain_dominance_hook_set_count": 976,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v121 的可复用判断规则：

- `origin_chain_bitmix_return_dominance_probe`：origin-chain context 中同时出现 bitmix/crypto-like、return/value-register touch 与 dominance/return-consumer/use lane，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `origin_chain_return_arg_slot_dominance_probe`：return-to-arg 与 return-to-slot/slot lane 在 origin-chain dominance 路径中同时出现，说明值可能被复制、落槽或继续消费；它是排序信号，不是 clean value source 证据。
- v121 hook set 应覆盖 origin-chain callsites/callees、prior producer calls、return-to-arg/slot lanes、slot read/write/materialized lanes、return-consumer dominance lanes、downstream consumer calls、v120 deeper origin points 与 v119-v99 controls；hook set 可控制到约 976，避免无边界全量 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态同值窗口，保持 `algorithm_status=not_recovered`，并明确区分“origin-chain/dominance hook 排序推进”和“算法本体仍未还原”。

v121 closure check 参考：

1. 校验脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且非空。
2. 抽查 status JSON 中 count 与 judgement 字段，尤其 `origin_chain_bitmix_return_dominance_probe_count`、`origin_chain_return_arg_slot_dominance_probe_count`、`v121_focused_first_seen_origin_chain_dominance_hook_set_count`、`new_value_source_evidence=false`、`first_seen_evidence=false`、`algorithm_status=not_recovered`。
3. conclusion / project memory / daily / SESSION 必须包含 `v121` 与 `not_recovered`，避免把 origin-chain/dominance 静态扩展误读为算法已还原。
4. 归档后运行 `memory/scripts/memory-sync.py sync`，再搜索 `v121 focused first-seen origin-chain dominance algorithm_status not_recovered`，确认项目记忆可检索；本轮验证 Top1 命中 `2026-05-15_project_douyin-xcylons-v121-first-seen-origin-chain-dominance`。
5. 检查无遗留 `static_v121|run_v121|v121_focused|frida.*v121` 进程。

## v122 经验值参考

2026-05-15 v122 在 v121 first-seen origin-chain / dominance 之后，继续做 focused first-seen origin-chain downstream / fanin 静态挖掘。目标是消费 v121 origin-chain/dominance records，把 downstream fan-in body、bitmix-return dominance、return-to-arg/slot dominance、repeated callee target/body signature 与 carried runtime-chain calls 收敛成下一轮真实 ACK/X-Cylons/SSL first-seen 同值验证的 focused hook set；仍不能把静态 downstream/fanin/dominance 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v122_focused_first_seen_origin_chain_downstream_fanin_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v122_focused_first_seen_origin_chain_downstream_fanin_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v122_focused_first_seen_origin_chain_downstream_fanin_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v122_focused_first_seen_origin_chain_downstream_fanin_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v122_0515.json
```

关键计数：

```json
{
  "trace_record_count": 5200,
  "high_priority_trace_count": 5200,
  "downstream_fanin_bitmix_return_dominance_probe_count": 4625,
  "downstream_fanin_return_arg_slot_dominance_probe_count": 575,
  "repeated_downstream_fanin_callee_target_count": 7,
  "repeated_downstream_fanin_callee_body_signature_count": 8,
  "v122_focused_first_seen_origin_chain_downstream_fanin_hook_set_count": 983,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v122 的可复用判断规则：

- `downstream_fanin_bitmix_return_dominance_probe`：downstream/fan-in context 中同时出现 bitmix/crypto-like、return/value-register touch 与 dominance/use lane，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `downstream_fanin_return_arg_slot_dominance_probe`：return-to-arg 与 return-to-slot/slot lane 在 downstream fan-in dominance 路径中同时出现，说明值可能被复制、落槽或继续消费；它是排序信号，不是 clean value source 证据。
- `repeated_downstream_fanin_callee_target_count` / `repeated_downstream_fanin_callee_body_signature_count` 是动态 hook 收敛信号；重复 target/body signature 不能单独升级为 value source。
- v122 hook set 应覆盖 downstream fan-in callsites/callees、prior producer calls、return-to-arg/slot lanes、slot read/write/materialized lanes、return-consumer dominance lanes、v121 origin-chain points、v120 deeper origin points 与 v119-v99 controls；hook set 可控制到约 983，避免无边界全量 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态同值窗口，保持 `algorithm_status=not_recovered`，并明确区分“origin-chain downstream/fanin hook 排序推进”和“算法本体仍未还原”。

v122 closure check 参考：

1. 校验脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且非空。
2. 抽查 status JSON 中 count 与 judgement 字段，尤其 `downstream_fanin_bitmix_return_dominance_probe_count`、`downstream_fanin_return_arg_slot_dominance_probe_count`、`v122_focused_first_seen_origin_chain_downstream_fanin_hook_set_count`、`new_value_source_evidence=false`、`first_seen_evidence=false`、`algorithm_status=not_recovered`。
3. conclusion / project memory / daily / SESSION 必须包含 `v122` 与 `not_recovered`，避免把 downstream/fanin 静态扩展误读为算法已还原。
4. 归档后运行 `memory/scripts/memory-sync.py sync`，再搜索 `v122 focused first-seen origin-chain downstream fanin algorithm_status not_recovered`，确认项目记忆可检索；本轮验证 Top1 命中 `2026-05-15_project_douyin-xcylons-v122-first-seen-origin-chain-downstream-fanin`。
5. 检查无遗留 `static_v122|run_v122|v122_focused|frida.*v122` 进程。
6. mem0 若返回 `200 {"results":[]}` 但 search 暂不命中，按既有 mem0 踩坑处理：以本地 Markdown/JSON/SESSION + memory-sync 搜索命中作为可审计事实源。

## v124 经验值参考

2026-05-15 v124 在 v123 downstream-fanin source-backtrace 之后，继续做 focused first-seen source-backtrace origin / producer-closure 静态挖掘。目标是消费 v123 downstream/fanin source-backtrace records，把 prior producer calls、return-to-arg/slot pairs、slot write/read materialization、dominant return-consumer lanes、callback/virtual lanes、body fanout 与 carried runtime-chain calls 进一步回溯到 origin/producer-closure 候选，生成下一轮真实 ACK/X-Cylons/SSL first-seen 同值验证的 focused hook set；仍不能把静态 origin/producer-closure 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v124_focused_first_seen_source_backtrace_origin_producer_closure_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v124_focused_first_seen_source_backtrace_origin_producer_closure_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v124_focused_first_seen_source_backtrace_origin_producer_closure_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v124_focused_first_seen_source_backtrace_origin_producer_closure_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v124_0515.json
```

关键计数：

```json
{
  "trace_record_count": 7600,
  "high_priority_trace_count": 7600,
  "origin_producer_closure_bitmix_return_dominance_probe_count": 7600,
  "origin_producer_closure_return_arg_slot_pair_probe_count": 0,
  "origin_producer_closure_slot_materialized_pair_probe_count": 0,
  "origin_producer_closure_callback_virtual_bridge_probe_count": 0,
  "origin_producer_closure_repeated_origin_convergence_probe_count": 0,
  "origin_producer_closure_plain_upstream_downstream_probe_count": 0,
  "origin_producer_closure_plain_context_probe_count": 0,
  "repeated_origin_producer_closure_callee_target_count": 4,
  "repeated_origin_producer_closure_callee_body_signature_count": 3,
  "origin_producer_closure_body_bitmix_total_count": 4970,
  "origin_producer_closure_body_indirect_total_count": 0,
  "origin_producer_closure_body_call_total_count": 103450,
  "origin_producer_closure_return_touch_total_count": 144210,
  "v124_focused_first_seen_downstream_fanin_origin_producer_closure_hook_set_count": 1046,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v124 的可复用判断规则：

- `origin_producer_closure_bitmix_return_dominance_probe`：origin/producer-closure context 中同时出现 bitmix/crypto-like、return/value-register touch 与 dominance/use lane，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `origin_producer_closure_return_arg_slot_pair_probe_count=0`、`origin_producer_closure_slot_materialized_pair_probe_count=0`、`origin_producer_closure_callback_virtual_bridge_probe_count=0`、`origin_producer_closure_repeated_origin_convergence_probe_count=0`、`origin_producer_closure_plain_*_probe_count=0` 是分类负结果：v124 高优先级全部归入 bitmix-return-dominance，不要为了推进感扩大为算法结论。
- `repeated_origin_producer_closure_callee_target_count` / `repeated_origin_producer_closure_callee_body_signature_count` 是动态 hook 收敛信号；重复 target/body signature 不能单独升级为 value source。
- v124 hook set 应覆盖 origin/producer-closure callsites/callees、function starts、upstream/downstream calls、v123 downstream/fanin points、v121 origin-chain points、v120 deeper value-origin points、v119 producer-consumer closure points 与 v106-v99 controls；hook set 可控制到约 1046，避免无边界全量 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态同值窗口，保持 `algorithm_status=not_recovered`，并明确区分“source-backtrace origin/producer-closure hook 排序推进”和“算法本体仍未还原”。

v124 closure check 参考：

1. 校验脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且非空。
2. 抽查 status JSON 中 count 与 judgement 字段，尤其 `trace_record_count=7600`、`origin_producer_closure_bitmix_return_dominance_probe_count=7600`、`v124_focused_first_seen_downstream_fanin_origin_producer_closure_hook_set_count=1046`、`new_value_source_evidence=false`、`first_seen_evidence=false`、`algorithm_status=not_recovered`。
3. conclusion / project memory / daily / SESSION 必须包含 `v124` 与 `not_recovered`，避免把 origin/producer-closure 静态扩展误读为算法已还原。
4. 归档后运行 `memory/scripts/memory-sync.py sync`，再搜索 `v124 focused first-seen source-backtrace origin producer closure algorithm_status not_recovered`，确认项目记忆可检索；本轮验证 Top5 命中 `2026-05-15_project_douyin-xcylons-v124-source-backtrace-origin-producer-closure`。
5. 注意标题/路径中包含斜杠（如 `origin/producer-closure`）会导致 memory-write 生成异常子目录，例如 `projects/2026-05-15_project_douyin-xcylons-v124-origin/producer-closure-origin-producer-closure.md`；归档 title/slug 应把 `/` 替换成 `-`，并优先使用正确文件 `projects/2026-05-15_project_douyin-xcylons-v124-source-backtrace-origin-producer-closure.md`。
6. 检查无遗留 `static_v124|run_v124|v124_focused|frida.*v124` 进程。

## v125 经验值参考

2026-05-15 v125 在 v124 source-backtrace origin / producer-closure 之后，继续做 focused origin/producer-closure value-boundary 静态挖掘。目标是把 v124 的 origin/producer-closure 候选进一步拆到 return-to-arg / return-to-slot、pre-slot-write / post-slot-read materialization、return-consumer dominance、downstream fanout、repeated closure convergence 与 carried runtime-chain call 等 value-boundary 层，为真实 ACK/X-Cylons/SSL first-seen 同值验证准备更细粒度 hook set；仍不能把静态 value-boundary 特征误判为算法本体。

产物命名参考：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v125_focused_origin_producer_closure_value_boundary_0515.py
/opt/data/home/reverse-tools/douyin_analysis/v125_focused_origin_producer_closure_value_boundary_static_0515.json
/opt/data/home/reverse-tools/douyin_analysis/v125_focused_origin_producer_closure_value_boundary_static_0515.md
/opt/data/home/reverse-tools/douyin_analysis/v125_focused_origin_producer_closure_value_boundary_conclusion_0515.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v125_0515.json
```

关键计数：

```json
{
  "trace_record_count": 9200,
  "high_priority_trace_count": 9200,
  "value_boundary_slot_materialized_return_consumer_probe_count": 710,
  "value_boundary_bitmix_return_consumer_dominance_probe_count": 7070,
  "value_boundary_return_consumer_fanout_probe_count": 710,
  "value_boundary_repeated_closure_convergence_probe_count": 710,
  "repeated_value_boundary_callee_target_count": 11,
  "repeated_value_boundary_callee_body_signature_count": 11,
  "value_boundary_body_bitmix_total_count": 4970,
  "value_boundary_body_indirect_total_count": 4260,
  "value_boundary_body_call_total_count": 52390,
  "value_boundary_return_touch_total_count": 109690,
  "boundary_prior_call_total_count": 53010,
  "boundary_downstream_call_total_count": 61530,
  "boundary_return_to_arg_lane_total_count": 152020,
  "boundary_return_to_slot_lane_total_count": 4260,
  "boundary_return_consumer_lane_total_count": 63690,
  "boundary_dominant_return_consumer_lane_total_count": 63690,
  "next_hop_runtime_chain_call_count": 165510,
  "hook_set_count": 1095,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v125 的可复用判断规则：

- `value_boundary_bitmix_return_consumer_dominance_probe`：value-boundary callee/body 或 caller context 同时具备 bitmix/crypto-like、return/value-register touch 与 dominant return-consumer lane，是高优先级 first-seen hook 信号；没有 clean X-Cylons input-output 同值日志时仍不是算法恢复。
- `value_boundary_slot_materialized_return_consumer_probe`：slot materialized 后被 return-consumer 消费，说明值可能经过落槽/取槽边界传播；它是排序信号，不是 clean value source 证据。
- `value_boundary_return_consumer_fanout_probe`：return-consumer 后有 downstream fanout，可作为同值传播验证的下游锚点；不可直接升级为生成点。
- `value_boundary_repeated_closure_convergence_probe` 与 repeated target/body signature 是动态 hook 收敛信号；重复/收敛不能单独升级为 value source。
- v125 hook set 应覆盖 value-boundary callee/callsite、return-to-arg/slot lanes、slot write/read materialization、dominant return-consumer lanes、downstream fanout、repeated closure convergence、v124 origin/producer-closure points 与 v106-v99 controls；hook set 可控制到约 1095，避免无边界全量 hook。
- 如果未捕获真实 ACK/X-Cylons/SSL first-seen 动态同值窗口，保持 `algorithm_status=not_recovered`，并明确区分“origin/producer-closure value-boundary hook 排序推进”和“算法本体仍未还原”。

v125 closure check 参考：

1. 校验脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且非空。
2. 抽查 status JSON 中 count 与 judgement 字段，尤其 `trace_record_count=9200`、`value_boundary_bitmix_return_consumer_dominance_probe_count=7070`、`hook_set_count=1095`、`new_value_source_evidence=false`、`first_seen_evidence=false`、`algorithm_status=not_recovered`。
3. conclusion / project memory / daily / SESSION 必须包含 `v125` 与 `not_recovered`，避免把 value-boundary 静态扩展误读为算法已还原。
4. 归档后运行 `memory/scripts/memory-sync.py sync`，再搜索 `v125 focused origin producer closure value boundary algorithm_status not_recovered`，确认项目记忆可检索。
5. 检查无遗留 `static_v125|run_v125|v125_focused|frida.*v125` 进程。

## 收尾检查

1. 校验 `.json/.md/conclusion/status` 和脚本都存在且非空。
2. 抽查 status JSON 中 count、hook set count、`algorithm_status`。
3. 抽查 conclusion/project memory/daily/SESSION 是否包含阶段号和边界结论。
4. 运行 `memory/scripts/memory-sync.py sync`。
5. 搜索 `vNN` + 核心字段 + `algorithm_status`，确认项目记忆可检索。
6. 检查无遗留 `static_vNN|run_vNN|vNN_` 分析进程。
7. 若写入 mem0 返回 `200 {"results":[]}`，按接受处理；若立即搜索不命中，仍以本地 Markdown/JSON/SESSION + memory-sync 命中为事实源。
