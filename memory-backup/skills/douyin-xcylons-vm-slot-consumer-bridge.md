---
name: douyin-xcylons-vm-slot-consumer-bridge
description: 抖音 X-Cylons native VM slot write → consumer mem-read 静态桥接与动态验证包生成流程
tags: ["douyin", "x-cylons", "native-vm", "slot-analysis", "frida", "reverse-engineering"]
---

# Douyin X-Cylons VM slot write → consumer mem-read bridge

## 适用场景

当上一轮已经完成 VM slot write def-use / writer-side static slicing（例如 v230），用户要求“继续挖掘”但仍缺少真实直播间 runtime proof 时使用。

目标是构建 `slot write → consumer mem-read` 的静态桥接优先级，并生成下一轮动态 hook packs；不要把静态 bridge 误判为算法本体恢复。

## 核心流程

1. **读取并校验上一轮输入**
   - 读取上一轮 JSON 中的 slot write records、handler targets、state-carry registers、next-dispatch context。
   - 核对版本号、输入路径、JSON key，避免复制上一轮脚本时沿用旧版本输入。

2. **构建 bridge 评分维度**
   - 共享 VM slot base，常见寄存器：`x21`。
   - 共享 scaled slot index，常见寄存器：`x9`。
   - state-carry register overlap。
   - next-dispatch 邻接关系。
   - consumer handler role / target priority。

3. **扫描 consumer mem-read**
   - 对候选 consumer handler 做 bounded disassembly / operand scan。
   - 优先找同一 slot base/index 下的 memory read。
   - 输出 bridge records：writer target、consumer target、slot base/index、state-carry overlap、dispatch adjacency、confidence、relation type。

4. **聚合与动态包生成**
   - 按 relation 聚合，例如 `direct_slot_index_bridge`。
   - 统计 top consumer targets，例如某些版本中 `0x2f74`、`0x3048`、`0x2e54` 一类高频 consumer。
   - 生成 dynamic packs：
     - `direct_slot_index_bridge_candidates`
     - 特定 consumer target bridge pack
     - `runtime_bridge_probe_schema`

5. **归档算法边界**
   - status/project memory 必须保留：`algorithm_status=not_recovered`。
   - 静态 bridge 只代表 slot 语义候选优先级，不代表算法完整挖出。
   - 升级为真实 VM slot 语义前，必须在真实直播间前台动态 attach 捕获并闭合：
     - `slot_mem_write_runtime_addr/value`
     - `consumer_mem_read_runtime_addr/value`
     - `x21`
     - `x9`
     - state-carry regs
     - `next_pc`
     - runtime addr/value 或数据影响链证明

## 验证清单

- `python -m py_compile <script>.py`
- 主 JSON 可通过 `python -m json.tool`
- status JSON 可通过 `python -m json.tool`
- project memory/status 含 `algorithm_status=not_recovered`
- `SESSION-STATE.md` 与 daily memory 追加归档记录
- `ps -ef` 确认无 archive/static 脚本残留

## 常见坑

- 不要只报告接口/调用链进展，要明确算法本体是否恢复。
- 没有真实直播间 runtime addr/value proof 时，不要把 high-confidence static bridge 写成 recovered。
- 复制上一轮脚本时最容易错的是输入 JSON、版本号、输出 key 和动态 pack 名称。
