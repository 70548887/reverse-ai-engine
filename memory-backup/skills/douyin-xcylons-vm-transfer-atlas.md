---
name: douyin-xcylons-vm-transfer-atlas
description: 抖音 X-Cylons native VM 静态深化：从 operand equations 生成 register-transfer / slot-effect atlas 并归档验证
tags: ["douyin", "x-cylons", "native-vm", "static-analysis", "reverse-engineering"]
---

# Douyin X-Cylons VM transfer / slot-effect atlas workflow

## 适用场景

用户要求“继续挖掘”且当前阶段已到 v220+ native VM/dispatcher/handler 静态深挖，已有上一轮 operand equations、opcode family/value-flow atlas、handler microsemantic records，需要继续静态推进但尚无真实直播间动态 trace。

## 关键边界

这类阶段只能产出 `static_register_transfer_slot_effects_ready_for_dynamic_validation`。除非已经有真实 `LivePlayActivity/webcast` 前台动态证据、runtime VM sequence、`0x2bd8` ttEncrypt input/output 绑定、key/mode/IV/padding 和 pure reproduction，否则必须保持：

```json
{
  "algorithm_status": "not_recovered",
  "dynamic_execution_performed": false,
  "opcode_semantics_recovered": false,
  "tt_encrypt_input_output_bound": false,
  "pure_reproduction_ready": false
}
```

## 实现步骤

1. 读取上一轮产物，例如：
   - `v220_vm_opcode_handler_microsemantics_static_*.json`
   - `v222_vm_opcode_family_valueflow_atlas_static_*.json`
   - `v223_vm_operand_lifter_trace_plan_static_*.json`
   - `v224_vm_operand_equation_synthesizer_static_*.json`
2. 从上一轮 dynamic packs 和 high-priority handler equations 选择 targets，去重并确认都存在于 microsemantic records。
3. 对 selected handlers 做小型 AArch64 符号解释，至少覆盖：
   - arithmetic/logic: `and/orr/eor/add/sub`
   - shifts/extracts: `lsl/lsr/asr/ror/ubfx/ubfiz/sbfiz/bfxil`
   - moves/extensions: `mov/movk/sxtw/sxth/uxtw/sxtw/...`
   - memory: `ldr/ldur/ldrb/ldrh/ldrsw/str/stur/strb/strh`
   - predicates/branches: `cmp/tst/cset/csel/b.* / cbz/cbnz/br/blr/ret`
4. 每个 handler 输出：
   - `final_register_expressions`
   - `facts`，如 `opcode_low6`、`operand_bits_6_11`、`operand_high_nibble_12_15`、`state_carry_insert_bits_20_31`
   - `mem_reads` / `mem_writes`
   - `flags` / `branches` / `terminator`
   - `effect_classes`，如 `bytecode-word-field-lift`、`vm-slot-or-output-write`、`computed-dispatch-transfer`、`guarded-path`
5. 将 bytecode prefix words 投影到 handler/effect classes，生成 runtime assertions：`word`、`low6`、`bits6_11`、`high_nibble`、expected effects。
6. 生成下一轮动态验证 packs，常用：
   - `register_transfer_core`
   - `slot_write_validation`
   - `computed_dispatch_tail_validation`
   - `guard_branch_gap_validation`
7. 写入主 JSON、结论 MD、status JSON、project memory，并同步 `SESSION-STATE.md` 与 daily memory。

## 工具使用注意

生成较大的 Python 静态分析脚本时，优先用 `write_file` 写完整文件，再用 `terminal` 执行：

```bash
python3 -m py_compile static_vXXX_*.py
python3 static_vXXX_*.py
python3 -m json.tool vXXX_*.json >/tmp/vXXX_json.ok
```

不要在 `execute_code` 里嵌套超长 triple-quoted Python 源码；外层字符串容易被内层 docstring 提前闭合，出现 `from __future__ imports must occur at the beginning` 或日期文本 `SyntaxError`。

## 归档验证清单

完成前必须验证：

- 分析脚本 `py_compile` 通过
- 主 JSON `json.tool` 通过
- status JSON `json.tool` 通过
- project memory 中明确包含 `algorithm_status=not_recovered`
- `SESSION-STATE.md` 包含本轮 archived 行
- daily memory 包含本轮小节
- `ps -ef` 检查无本轮 `static_vXXX` / `archive_vXXX` 脚本残留；既有 Hermes、MCP、ADB/Frida server 进程单独说明，不误判为本轮残留

## v227 opcode trace oracle 延伸步骤

当 v226 已经把 prefix words 具体化到 slot-effect assertions 后，可以继续生成 v227 `vm-concrete-opcode-trace-oracle-static`，把 concrete prefix projection 聚合为 per-low6 runtime oracle：

1. 读取：
   - `v220_vm_opcode_handler_microsemantics_static_*.json`
   - `v225_vm_register_transfer_slot_effect_atlas_static_*.json`
   - `v226_vm_prefix_slot_effect_concretizer_static_*.json`
2. 以 `concrete_prefix_projection[*].fields.low6` 分组，输出每个 low6 的：
   - `family_label`：例如 `slot_or_output_write_opcode`、`dispatch_tail_or_control_transfer_opcode`、`operand_decode_state_carry_opcode`、`guard_or_predicate_opcode`。
   - `confidence`：单 handler 且多样本、slot-write 一致性好的可标 high；单样本或多 handler 标 low。
   - dominant handler、effect counts、slot_write_word_count、dispatch_tail_word_count。
   - `bits6_11/high_nibble/signed_imm16` 分布。
   - `mem_write_oracle`、`mem_read_oracle`、`branch_oracle` 模板；模板只做安全归一化，不做过度代数化。
3. 同时生成 handler-level oracle，按 target 汇总 low6、prefix words、mem read/write/dispatch 形态。
4. 动态 packs 建议固定为：
   - `opcode_oracle_high_confidence`
   - `slot_write_opcode_oracle`
   - `dispatch_tail_opcode_oracle`
   - `low_confidence_guard_gap_oracle`
   - `handler_oracle_focus`
5. v227 仍必须保持静态边界：`algorithm_status=not_recovered`、`dynamic_execution_performed=false`、`opcode_semantics_recovered=false`、`tt_encrypt_input_output_bound=false`、`pure_reproduction_ready=false`。

v227 归档验证除原清单外，还应确认 conclusion/project memory 明确列出 opcode family counts、高/低置信 opcode 计数，以及下一步是“真实直播间逐 low6 校验 runtime mem_read/mem_write/branch delta”。

## v251 terminal crypto lane candidate mining 延伸步骤

当阶段已从 VM handler/slot-effect 静态挖掘推进到 `libEncryptor.so` terminal crypto lane，但仍无真实直播间动态 trace 时，可做 v251 类 native block-transform 候选收敛：

1. 用 `pyelftools` 读取 `native_so/libEncryptor.so` 的 `.text`、`.mytext`、`.rodata`、`.data`、`.dynsym`、`.rela.*`，记录 SHA256 与 section VA/size。
2. 枚举 `.data` 8-byte words，标记指向 section 的 slot。重点关注 `.data -> .mytext` 的隐藏入口槽；例如本轮发现 `0x18018 -> 0x7d8c (.mytext)`，应纳入下一轮 runtime slot resolution。
3. 用 Capstone ARM64 反汇编 `.text + .mytext`，保守识别函数起点：dynsym FUNC、`bl/b` immediate target、`stp x29,x30,[sp,...]` prologue。按下一个起点切片，避免声称精确函数边界。
4. 对每个 slice 计算候选分数：
   - bit/round ops: `eor/and/orr/lsl/lsr/ror/rev/ubfx/bfxil/add/sub/mul/madd`
   - memory/byte ops: `ldr/str/ldrb/strb/ldrh/strh`
   - branch/loop/call density，loop 加分、calls 适度扣分。
5. 加语义标签而非直接命名算法：
   - `rev + eor + ubfx + 16-byte strb` → `high_priority_terminal_block_transform_helper`
   - 大量重复 round-like 结构 → `duplicated_large_round_family_entry` 或 `large_key_schedule_or_generated_dispatch_candidate`
   - 指向 `.mytext` / `.data slot` 的入口 → `data_slot_pointed_hidden_entry_candidate`
6. 输出 high-priority hook offsets。v251 经验中优先级最高：`0x26e0`, `0x7144`, `0x780c`（rev/eor/ubfx/16-byte strb），然后 `0x4678`, `0x6844`, `0x74c0`, 大型 wrapper/round family `0xdac`, `0x2d44`, `0x4c9c`，以及 `.mytext` entry `0x7d8c`。
7. 归档主 JSON、matrix、conclusion、status、project memory；conclusion 必须明确：这是 stronger native boundary evidence，不是算法恢复。

v251 类归档 invariant：

```json
{
  "algorithm_status": "not_recovered",
  "dynamic_execution_performed": false,
  "tt_encrypt_input_output_bound": false,
  "pure_reproduction_ready": false,
  "algorithm_boundary_status": "static_terminal_crypto_lane_candidates_ready_for_live_v250_oracle_join"
}
```

下一轮动态 pack 应是 observe-only：`terminal_native_candidate_core`、`data_slot_entry_resolution`、`v250_oracle_packet_join`。只有真实 `LivePlayActivity/webcast` 前台、非 synthetic canonical evidence packet、distinct-window quorum、heldout replay、key/mode/IV/padding 绑定和 negative-control rejection ledger 都通过后，才允许把候选提升为已恢复算法。

## 动态下一步模板

真实直播间前台后，优先执行 `register_transfer_core` + `slot_write_validation`；若已有 v227，则优先跑 `opcode_oracle_high_confidence` + `slot_write_opcode_oracle`；若已有 v251 terminal候选，则优先跑 `terminal_native_candidate_core` + `data_slot_entry_resolution` 并 join 到 `v250_oracle_packet_join`。逐 handler/low6/native-offset 记录 pre/post `x0-x18/x21/x22/x25/x27`、predicate/branch、memory read/write address/value、next_pc、terminal input/output digest、header carry evidence，并与静态 transfer equations / opcode_trace_oracles / terminal native candidate ledger 对齐。只有 runtime delta 匹配且绑定 `0x2bd8`/terminal ttEncrypt IO 后，才推进 opcode semantic closure、key/mode/IV/padding 和 pure reproduction。
