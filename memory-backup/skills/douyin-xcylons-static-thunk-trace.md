---
name: douyin-xcylons-static-thunk-trace
description: 抖音直播 X-Cylons 上游静态追踪时，识别 thunk/wrapper 参数转发链并避免把转发 stub 误判为算法本体
tags: ["douyin", "x-cylons", "arm64", "static-analysis", "reverse-engineering"]
---

# 抖音 X-Cylons 静态 thunk/wrapper 追踪

## 适用场景

当 ACK/uplink 包内 `X-Cylons` 已经通过动态 hook 或静态回溯定位到携带/打包点，但继续上追进入大量 ARM64 thunk、wrapper、stub 时，使用本技能判断当前地址是否只是参数转发链，而不是 value 生成算法本体。

典型已知链路：

```text
0x346b90 -> 0x4cff50 -> 0x4cf8a4 -> 0x4cf894/0x4d0128 -> wrapper/stub
```

已知强携带/打包点：

```text
0x346bcc / 0x4cff5c / 0x4cff50
```

已知上游传播/ACK 上下文点：

```text
0x21e17c / 0x2107dc
```

## 判定方法

1. 对候选 thunk/wrapper 地址做局部反汇编，重点看跳转前是否写入 value 参数寄存器（常见为 `x1`，或被 thunk 转存到 `x2`）。
2. 若 thunk 类似 `0x4cf894/0x4d0128`，其特征通常是：
   - 把调用方传入的 `x1` 转存为后续 value 参数，例如 `x2 = x1`；
   - 设置类型/上下文寄存器（例如 `w1 = type`）；
   - 跳到下游 copy/package/consume 逻辑。
3. 若 wrapper/stub 只改写 `x0`，例如：

```asm
0x00210c74: ldr x0, [x0,#0x10]
0x00210c80: b   #0x4cf894
0x00210c88: ldr x0, [x0,#0x10]
0x00210c94: b   #0x4d0128

0x0028a348: ldr x0, [x0,#0xa0]
0x0028a354: b   #0x4d0128
0x0028a454: ldr x0, [x0,#0xa0]
0x0028a460: b   #0x4cf894
```

则这些 wrapper 只是把对象字段 `[x0+offset]` 作为第一个参数传给 thunk，跳转前没有本地写入 `x1`。

## 关键结论

如果 wrapper/stub 只改写 `x0`，而 `x1` 在进入 thunk 前保持 unchanged：

```text
indirect/callback caller supplies x1
  -> wrapper: x1 unchanged, x0 = object field
  -> thunk: x2 = x1, w1 = type
  -> downstream copy/package/consume
```

该 wrapper/stub 不是 `X-Cylons` value 生成点。下一步应追：

- 谁把这些 wrapper 地址放入函数表、vtable、回调槽或跳转表；
- 谁通过函数指针/回调调用它；
- 调用时传入的 `x1` 来源。

不要继续在这类 wrapper 内找算法本体。

## 继续追 wrapper 注册/间接调用（v34 经验）

当确认 wrapper entry 没有常规 `b/bl` 直接调用时，不要停在“无 caller”。下一步应做静态 function-pointer 注册追踪：

1. 对 wrapper entry 地址做全库引用搜索，除了 `b/bl` 外重点找 `adr/adrp+add/ldr literal` 等地址物化指令。
2. 对命中的地址物化点做近邻窗口反汇编，观察 wrapper 地址被装入哪个寄存器（v34 常见为 `x8`）。
3. 在同一 basic block / 函数邻域内找 helper/registration/dispatch 候选调用，尤其是紧随地址物化后的 `bl` 或结构写入。
4. 报告中把“wrapper 地址被物化为 callback/function-pointer 候选”和“真正间接 dispatcher/caller 仍未知”分开写，避免把注册点误判为算法本体。

v34 已知结果：

```text
wrapper entries with no direct b/bl callers:
0x210c74 / 0x210c88 / 0x28a348 / 0x28a454

address materialization:
0x210c74 <- adr at 0x2106f8 into x8
0x210c88 <- adr at 0x210800 into x8
0x28a348 <- adr at 0x28a2d8 into x8
0x28a454 <- adr at 0x28a3e4 into x8

nearby helper/registration/dispatch candidates:
0x1f9ff8 / 0x1fe07c / 0x223b74 / 0x289184 / 0x2dccac / 0x20df1c
```

该证据只能说明 wrapper 很可能作为 callback/function-pointer 被注册或放入函数表；仍需继续追谁间接调用它，以及调用时 `x1` 的来源。

## 继续追 callback record 与 slot-indirect dispatcher（v35 经验）

当 v34 已定位 wrapper ADR 物化点后，下一步不是只列 helper 名称，而是追 wrapper 地址在局部数据结构中的写入槽，并全局扫描从相同槽偏移读取后 `br/blr` 的间接调用点。

1. 对 ADR 物化点所在函数做局部 data-flow：记录 wrapper 地址寄存器是否被 `str/stp` 写入 record/stack/object 槽。
2. 若出现类似 `stp x8, xzr, [record,#0x20]`，可把 `+0x20` 标记为 callback entry slot；同时记录 owner/context 槽，v35 常见为 `+0x30`。
3. 对相关 helper（v35: `0x1f9ff8 / 0x1fe07c / 0x223b74 / 0x289184`）保持谨慎：若静态证据显示它们消费 record/node、保存/链接 callback，默认归类为 registration/container helper，不要提前宣称其生成 X-Cylons value。
4. 全库扫描以下模式，找潜在 dispatcher/caller：
   - 从 `+0x20/+0x28/+0x30/+0x38` 等 callback/record 槽 `ldr` 函数指针；
   - 随后短窗口内出现 `br` / `blr` 到该寄存器；
   - 同窗口内 dump `x0-x3` 传参来源，尤其是 caller-supplied `x1`。
5. 动态验证时优先 hook：
   - wrapper entry: `0x210c74 / 0x210c88 / 0x28a348 / 0x28a454`，dump `x1`；
   - slot-indirect dispatcher 候选，dump target reg、`x0-x3` 与 backtrace；
   - helper exit，确认是否只是注册/链接 record。

v35 已知结果：

```text
callback record layout:
wrapper entry -> +0x20
owner/context -> +0x30

helper candidates that look like registration/container consumers:
0x1f9ff8 / 0x1fe07c / 0x223b74 / 0x289184

global slot-indirect candidates found: 292
priority dispatcher examples:
0x1fb70c -> 0x1fb728
0x20df58 -> 0x20df74
0x2111d0 -> 0x2111ec
```

判定标准：只有动态观察到“enter 前无 X-Cylons value、leave 后出现 value”，或明确 callback 输出 opaque/sign value，才可称为算法生成点。仅发现 callback record、helper 注册或 slot-indirect caller 仍属于调用链进展。

## 继续按 dispatcher 特征收敛动态 hook 范围（v36 经验）

当 v35 全局扫描得到数百个 slot-indirect 候选后，不要直接全量动态 hook。先做静态二次评分，把“像 callback dispatcher 且准备了 caller-supplied value/context 参数”的候选排到前面。

1. 复扫 v35 的 slot-indirect 模式，保持候选总数一致作为 sanity check（v36: 292）。
2. 对每个 `ldr function_reg, [record,#slot]` -> `br/blr function_reg` 候选评分：
   - `slot == +0x20`（callback_fn_slot）高优先级；
   - dispatch 前是否设置 `x1 = record/context + 0x38` 或 `x1 = [context+0x38]`；
   - 是否同时准备 `x2 = record + 0x50` 等 callback 参数；
   - 函数边界是否清晰，是否邻近 v34/v35 helper/registration 区域；
   - 是否只是 payload clear / container housekeeping，需降权但保留。
3. 输出 top/mid 两层候选，用于动态 hook first batch。v36 结果：

```text
slot-indirect candidates: 292
slot distribution: +0x20=177, +0x28=60, +0x30=35, +0x38=20
top dispatcher candidates: 98
mid dispatcher candidates: 58

first dynamic hook batch:
0x28c0f0 -> 0x28c110
0x21197c -> 0x21199c
0x2237ac -> 0x2237c8
0x2a7474 -> 0x2a749c
0x25d8c4 -> 0x25d8e8
0x2111d0 -> 0x2111ec
0x2237d4 -> 0x2237f8
0x2239d4 -> 0x223a04
0x1fb70c -> 0x1fb728
0x223750 -> 0x223770
0x224998 -> 0x2249b8
0x224c1c -> 0x224c3c
```

4. 文档/记忆归档时必须写清：v36 只是把动态验证范围从 292 收敛到优先 dispatcher 集合；它仍不是 X-Cylons value 生成算法本体还原。
5. 动态验证坚持 first-seen 标准：hook dispatcher + wrapper entry，dump target、`x0-x3`、`x1` 指向内容、backtrace；只有 enter 前无 value、leave 后出现 value，或明确 callback 输出 opaque/sign value，才可称为生成点。

v36 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v36_slot_dispatcher_prune_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v36_slot_dispatcher_prune_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v36_slot_dispatcher_prune_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v36_slot_dispatcher_prune_conclusion_0513.md
```

## 继续分析 dispatcher `x1` 来源（v37 经验）

当 v36 已把 292 个 slot-indirect 候选收敛到 first dynamic hook batch 后，下一步应静态确认这些 dispatcher 给 wrapper/thunk 链传入的 `x1` 到底来自哪里。v37 经验：

1. 对 v36 推荐第一批 `16` 个 dispatcher 候选做局部 data-flow；共同模式通常是从 record `+0x20` 读取 callback target（常见寄存器 `x16`），准备 `x1/x2/...`，然后 `br x16`。
2. 主要 `x1` 来源多为 `record+0x38` 地址或 `[record+0x38]` 载入值；这与 v35 的 callback record layout 兼容：
   ```text
   +0x20 callback entry
   +0x38 payload/context
   +0x50 additional callback argument / record field
   ```
3. 如果运行时 `x16` 解析到已知 wrapper：
   ```text
   0x210c74 / 0x210c88 / 0x28a348 / 0x28a454
   ```
   则 dispatcher 传入的 `x1` 会继续成为 wrapper/thunk 链中的上游 value/source 参数，并进入：
   ```text
   wrapper/thunk -> 0x4cf8a4 -> 0x1ff5fc -> 0x346b90/0x4cff50
   ```
4. 静态证据只能说明 dispatcher 如何传递 `x1`，不能证明这些 dispatcher 或 wrapper 本身生成 `X-Cylons` value。
5. `0x1fb70c` 这类会 `ldr x1, [record,#0x38]` 后清空 payload 的候选更像消费/destructor/回调触发路径，动态优先级低于直接 `x1=record+0x38` 的候选。

v37 动态验证优先 hook：

```text
0x28c0f0 -> 0x28c110
0x21197c -> 0x21199c
0x2237ac -> 0x2237c8
0x2a7474 -> 0x2a749c
0x25d8c4 -> 0x25d8e8
0x2111d0 -> 0x2111ec
0x2237d4 -> 0x2237f8
0x2239d4 -> 0x223a04
0x223750 -> 0x223770
0x224998 -> 0x2249b8
0x224c1c -> 0x224c3c
0x20df58 -> 0x20df74
```

同时 hook wrapper entries：

```text
0x210c74
0x210c88
0x28a348
0x28a454
```

动态日志必须记录 resolved callback target（如 `x16`）、`x0-x3`、record `+0x20/+0x38/+0x50` 与 `x1` 指向内容。只有观察到 enter 前无 `X-Cylons` value、leave/回调返回后出现 value，才能升级为生成点；否则继续归类为 dispatcher/copy/package/consume 链路。

v37 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v37_dispatcher_x1_source_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v37_dispatcher_x1_source_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v37_dispatcher_x1_source_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v37_dispatcher_x1_source_conclusion_0513.md
```

截至 v37：协议/接口链路、ACK/uplink 强携带/打包链、上游传播/上下文点都已收窄；但 `X-Cylons` value 生成算法本体仍未完整还原。

## direct caller 全 0 后改追 `+0x38` payload-slot writer（v38 经验）

当 v37/v36 的 priority dispatcher 或 wrapper 做直接 caller 扫描结果全为 0 时，不要继续把“无 direct caller”当作死路，也不要把 dispatcher 本身升级为算法本体。v38 的有效改道是：从 callback record 的 `+0x38` payload/context 槽反向找全局 writer，定位谁在 dispatcher 触发前写入/刷新 payload。

1. 先对 priority dispatcher direct caller 做 sanity check；v38 结果显示所有重点 dispatcher direct caller 均为 `0`，说明路径很可能经由 callback table / indirect dispatch / record slot 触发。
2. 改为全库扫描 `str/stp` 等写入指令，统计结构槽 writer：
   - v38 全局 slot writer：`8286`；
   - 其中 `+0x38` writer：`531`；
   - `score>=70` writer：`80`。
3. 对 `+0x38` writer 按以下特征评分：
   - 写入目标是否为 record/context 的 `+0x38`；
   - 写入值是否来自非平凡函数返回、opaque buffer、上下文读取或上游参数；
   - 是否邻近已知 dispatcher/wrapper/helper 区域；
   - 是否同时操作 `+0x20 callback entry`、`+0x50 extra arg` 等同一 callback record 字段；
   - 过滤明显 clear/destructor/housekeeping writer，但不要完全丢弃。
4. v38 top payload writer 函数包括：
   ```text
   0x32e8e0 / 0x325e38 / 0x33019c / 0x32e9f8 / 0x3328b0
   0x32eb10 / 0x33029c / 0x32ec28 / 0x325f24 / 0x2b9efc
   ```
5. 报告中必须把这些 writer 表述为“payload/context 写入邻域候选”，不能称为已证明的 `X-Cylons` value 生成点。

动态验证优先级：hook `candidate_payload_writer_funcs` + v37 dispatcher/wrapper，用 first-seen 标准判定：

```text
enter writer 前 record+0x38 / x1 指向内容无 X-Cylons/opaque value
writer leave 或后续 callback 返回后 record+0x38 首次出现 value
随后 dispatcher/wrapper/thunk/copy-package 链消费同一 value
```

只有满足以上链路，才能把 writer 升级为生成点或生成点近邻；否则仍归类为 payload/context writer 或调用链收窄。

v38 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/v38_dispatcher_upstream_conclusion_0513.md
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-13_project_douyin-xcylons-v38-dispatcher-upstream.md
```

截至 v38：已从 dispatcher/wrapper/callback record 进一步收窄到 `+0x38` payload-slot writer 邻域；但 `X-Cylons` value 生成算法本体仍未完整还原。

## 对 `+0x38` payload-slot writer 继续分层，排除 init/refcount 噪声（v39 经验）

当 v38 已把方向转到 `+0x38` payload/context writer 后，下一步不要直接把所有高分 writer 动态 hook。先对 top writer 做局部 source slicing，把明显的初始化、清零、常量、引用计数、existing-slot 传播过滤掉，只保留非平凡来源做 first-seen 动态验证。

1. 对 v38 top writer 函数逐个分析 `str/stp` 到 `+0x38` 的源寄存器来源。
2. 按 source class 分层：
   - `zero_clear`：清零/析构/初始化；
   - `constant_or_flag`：写入固定常量或状态 flag；
   - `existing_slot_refcount_or_counter`：引用计数、counter 或已有 slot 传播；
   - `stack_local_derived`：来自栈临时对象，需动态验证；
   - `argument_derived`：来自函数入参，优先动态验证；
   - `call_return_derived/unknown`：如果出现，也应优先动态验证。
3. v39 静态统计示例：
   ```text
   analysed_funcs=18
   store_class_distribution={
     constant_or_flag: 4,
     zero_clear: 7,
     existing_slot_refcount_or_counter: 4,
     stack_local_derived: 2,
     argument_derived: 3
   }
   ```
4. v39 收敛出的优先动态 hook 点：
   ```text
   0x2c4478  # argument_derived +0x38 store
   0x2b3754  # argument_derived +0x38 store
   0x2aeb98  # argument_derived +0x38 store
   0x2ba1e0  # stack_local_derived +0x38 store
   ```
5. 同轮动态必须保留 v37 dispatcher/wrapper，确保 payload first-seen 能与下游消费链对齐：
   ```text
   0x28c0f0 / 0x21197c / 0x2237ac / 0x2a7474 / 0x25d8c4 / 0x2111d0
   0x2237d4 / 0x2239d4 / 0x223750 / 0x224998 / 0x224c1c / 0x20df58
   0x210c74 / 0x210c88 / 0x28a348 / 0x28a454
   ```
6. 动态判定仍使用 strict first-seen：只有 writer enter 前 `record+0x38` / 源参数无 `X-Cylons`/opaque value，leave 后首次出现 value，并被后续 dispatcher/wrapper/`0x4cf8a4` 链消费，才可升级为生成点或生成点近邻。
7. 报告措辞：v39 只是把 v38 payload writer 继续筛分并收敛动态验证集合；没有静态 hash/crypto/base64/复杂算法体或 first-seen 证据时，必须继续写“`X-Cylons` value 生成算法本体仍未完整还原”。

v39 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v39_payload_writer_source_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v39_payload_writer_source_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v39_payload_writer_source_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v39_payload_writer_source_conclusion_0513.md
```

## 对 priority payload writer 继续追入参来源与 callback-record 邻域（v40-v42 经验）

当 v39 已把 `+0x38` payload/context writer 收敛到少数 priority writer 后，不要直接把这些 writer 认定为算法生成点。v40-v42 的有效方法是继续做“引用恢复 + 入参 taint + 邻域调用链”三件事，判断它们是否只是 callback-record / adapter 传播邻域。

1. 对 v39 priority writer 做入口引用复查：
   - direct branch refs；
   - raw pointer refs；
   - `adr/adrp/add/ldr literal` code materialization refs。
2. 如果 priority writer 入口引用全部为 0，说明普通 caller 链仍被 indirect callback/table/record/dispatcher 隐藏；这不是死路，但不能据此升级为算法点。
3. 对每个 writer 做局部入参 taint，跟踪 `x0-x7` 到以下位置：
   - callback record slots：`+0x20/+0x28/+0x30/+0x38/+0x40/+0x48/+0x50/+0x58`；
   - `str/stp` 到 `+0x38` payload/context；
   - `ldr` 从 caller object field；
   - direct `bl` 与 indirect `blr/br` 的参数。
4. v42 结果显示 v41 priority writer 入口引用仍全部为 0：
   ```text
   0x2c4478 direct/raw/code refs = 0/0/0
   0x2b3754 direct/raw/code refs = 0/0/0
   0x2aeb98 direct/raw/code refs = 0/0/0
   0x2ba1e0 direct/raw/code refs = 0/0/0
   ```
5. v42 入参流证据：
   ```text
   0x2c4478: x2/x1 -> record+0x38/+0x40; also has indirect blr, so dump callback target dynamically
   0x2b3754: x2 -> stack+0x38, x3 -> callback_fn_slot; best callback-record layout probe
   0x2aeb98: x1+0x18 -> record+0x38; compact object-field copy adapter
   0x2ba1e0: caller x3-derived scalar -> +0x38; likely metadata/flag/context propagation
   ```
6. 邻域调用链若以 factory/container/parser/builder/helper 为主，且函数局部 bitop/loop 密度低、无 hash/crypto/base64/opaque 算法特征，应归类为 `caller-argument/object-field -> callback payload record` 传播邻域，而不是算法本体。
7. v42 后续动态优先级：
   - hook priority writer entry/leave，dump source arg object and record `+0x20/+0x38/+0x40/+0x50`；
   - hook writer 内 `blr/br`，dump target reg、resolved target、`x0-x3`、backtrace；
   - 与 v37 dispatcher/wrapper/`0x4cf8a4` 下游消费链对齐，按 strict first-seen 判断。
8. 报告措辞必须保持边界：v40-v42 进一步证明 priority writer 更像 callback-record/adapter 传播邻域；如果没有 enter-before/leave-after first-seen 或明确算法输出，仍写“`X-Cylons` value 生成算法本体仍未完整还原”。

v42 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v42_priority_writer_arg_callchain_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v42_priority_writer_arg_callchain_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v42_priority_writer_arg_callchain_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v42_priority_writer_arg_callchain_conclusion_0513.md
```

## priority writer 内 indirect `blr` 来源定位（v43 经验）

当 v42 已证明 priority writer 更像 callback-record/adapter 邻域后，下一步可以继续在 writer body 内找 indirect `blr/br`，但目标是定位“内部回调/adapter 调用点与 record slot 来源”，不是直接宣称找到算法本体。

1. 对 priority writer 函数体做完整 basic-block 反汇编，枚举 writer-internal `blr/br`，并记录：
   - 调用点地址；
   - target register；
   - target register 在本函数内的最近定义；
   - `x0-x5` 在调用前的来源；
   - callback record `+0x20/+0x38/+0x40/+0x50` 是否被读写。
2. v43 结果中，仅有两个 writer 出现 writer-internal `blr` 候选：
   ```text
   0x2c4478: blr at 0x2c4518 / 0x2c46f4
   0x2b3754: blr at 0x2b391c / 0x2b3ad4
   ```
3. `0x2aeb98` 与 `0x2ba1e0` 未见 writer-internal `blr/br`，更像直接 helper/builder adapter；不要把它们当作 callback 算法体入口。
4. v43 静态 trace 显示：
   - `+0x38/+0x40` payload slot 仍主要来自 caller `x1/x2/x3` 或对象字段；
   - `+0x20` callback_fn_slot 更像 callback record / container setup；
   - writer entry / wrapper entry 仍无 direct/raw/code refs，调用继续表现为 indirect/table/record 驱动；
   - writer 内 `blr` 的 target 多来自 vtable/object load 或 live-in `x8`，静态上未解析到已知 wrapper 或 `0x4cf8a4` 消费链。
5. 因此 v43 后最有价值的动态验证不是继续在 writer body 里静态找算法，而是 hook 这些 writer-internal `blr` 调用点，dump resolved target 与 record slots：
   ```text
   blr points: 0x2c4518 / 0x2c46f4 / 0x2b391c / 0x2b3ad4
   dump: x8 resolved target, x0/x1/x2/x3/x5, record +0x20/+0x38/+0x40/+0x50, backtrace
   ```
6. 报告措辞：v43 只是把 priority writer 内的 indirect callback/adapter 调用点继续收窄；没有 first-seen 证据或明确 opaque/sign 输出时，仍必须写“`X-Cylons` value 生成算法本体仍未完整还原”。

v43 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v43_priority_writer_indirect_source_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v43_priority_writer_indirect_source_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v43_priority_writer_indirect_source_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v43_priority_writer_indirect_source_conclusion_0513.md
```

## writer-internal `blr` resolved target/source 分层（v44 经验）

当 v43 已把 priority writer 内的 indirect `blr` 收敛到四个调用点后，下一步应对每个 `blr` 做 resolved target/source 静态追踪与候选分层，决定动态 hook 优先级；目标仍是找 callback/adapter 边界与参数来源，不是静态宣称算法已还原。

1. 对四个 writer-internal `blr` 分别解析 target register 的最近定义来源：
   - object/vtable load，例如 `[obj] -> [vtable+slot]`；
   - factory return object vtable slot；
   - live-in register，例如 `x8` 在函数入口前已携带；
   - secondary cleanup/adapter callback。
2. 同时追踪 `x0-x7` 在 `blr` 前的来源，尤其记录 `x1/x2/x3` 是否仍来自 caller 参数、record slot 或 object field。
3. 分层排序时优先：
   - target 来自 factory return / object vtable 且 payload 参数仍 caller-supplied；
   - 与 callback record `+0x20/+0x38/+0x40/+0x50` 有明确读写关系；
   - 低优先级给 secondary cleanup、析构、adapter 尾调用。
4. v44 静态分层结果：
   ```text
   0x2b391c: high_callback_probe, score=7
     target = factory return object vtable+0x10
     x1 = caller x2 payload
     最像 payload callback/interface 调用点

   0x2b3ad4: high_callback_probe, score=5
     target = arg_x0+0x90 object vtable+0x18
     更像 object adapter callback

   0x2c4518: medium_callback_probe, score=4
     target = live-in/object x8 -> [x8+0x10]
     x1/x2/x3 仍是 caller 参数
     适合作为 resolved-target scout

   0x2c46f4: low_adapter_or_cleanup, score=1
     后段 secondary callback/cleanup/adapter
     x3 来自 caller x5
   ```
5. 动态 v45 优先 hook 顺序：
   ```text
   0x2b391c / 0x2b3ad4 / 0x2c4518 / 0x2c46f4
   ```
   dump resolved target、`x0-x7`、object/vtable 前 `0x40`、record `+0x20/+0x38/+0x40/+0x50` 与 backtrace，并继续用 strict first-seen 判断。
6. 报告措辞：v44 只说明四个 writer-internal `blr` 的 callback/adapter 优先级；静态未解析到固定 wrapper / `0x4cf8a4` 消费链，且无 hash/crypto/base64/opaque 算法体或 first-seen 证据时，必须继续写“`X-Cylons` value 生成算法本体仍未完整还原”。

v44 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/v44_writer_blr_target_source_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v44_writer_blr_target_source_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v44_writer_blr_target_source_conclusion_0513.md
```

## writer-internal BLR 动态未命中时的 v45 归档边界

当 v44 已确定四个 writer-internal `blr` scout 点后，v45 动态验证可能出现“hook 全部安装成功，但目标 BLR 没有命中，只命中下游 consumer”的情况。此时要把“触发条件不足 / 当前场景未走到 writer BLR”与“算法不存在/已排除”区分开。

v45 经验：

```text
目标 BLR:
0x2b391c / 0x2b3ad4 / 0x2c4518 / 0x2c46f4

动态结果示例:
ready = 1
hook-ok = 16
v45-func-enter = 1
hit = consumer_4cf8a4 only
writer-internal BLR hits = 0
SSL live events = 0
clean/first-seen events = 0
```

处理原则：

1. 如果 `ready` 与所有 `hook-ok` 都出现，说明 hook 安装路径有效；BLR 未命中更可能是直播 ACK/uplink 场景没有稳定触发，不能据此排除这些 BLR。
2. 唯一命中 `consumer_4cf8a4` 时，只能说明下游消费链仍可到达；若 `hits=[]`、`cleanValue=false`，不能把它写成 `X-Cylons` first-seen。
3. 静态复核仍保留 v44 分层：
   ```text
   0x2b391c / 0x2b3ad4: high-priority callback/interface scout
   0x2c4518: live-in/object x8 scout
   0x2c46f4: secondary adapter/cleanup
   ```
4. 报告必须明确写：v45 是调用链/adapter/callback-record 邻域收窄；`X-Cylons` value generation algorithm 仍未完整还原。
5. 下一步不是继续静态穷举同一 BLR，而是先稳定触发直播 ACK/uplink 后重跑，优先观察 `0x2b391c` resolved target、`x1/x2` payload、record `+0x20/+0x38/+0x40/+0x50`。若仍只命中 `0x4cf8a4`，则从当前 ACK 消费上下文反向回填 dispatcher/writer 激活条件。

归档经验：使用 `memory-write.py` 写入完整 Markdown 报告时，优先使用 `--body-from <report.md>` 或 Python `subprocess.run([...])` 参数数组；不要把含反引号、地址、JSON 的 Markdown 直接拼成 shell 命令，否则反引号会触发 shell command substitution，导致归档文件内容被清空或破坏。

v45 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v45_writer_blr_resolved_target_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v45_writer_blr_resolved_target_0513.log
/opt/data/home/reverse-tools/douyin_analysis/v45_writer_blr_resolved_target_summary_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v45_writer_blr_static_dynamic_synthesis_0513.md
```

## v46 动态脚本挂住/无 stdout 时的收尾边界

当围绕 `0x4d0808 caller -> 0x4cf8a4` 上游寄存器/record slot 关系运行动态 hook 时，可能出现脚本传入 duration（如 180s）后仍不自然退出，且 stdout preview 长时间为空的情况。此时不要直接判定 hook 失败或目标未命中，应先做进程收尾与文件侧日志核查。

典型命令形态：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
adb shell monkey -p com.ss.android.ugc.aweme -c android.intent.category.LAUNCHER 1
sleep 6
python3 run_v46_4d0808_4cf8a4_context_0513.py 180 2>&1 | tee v46_run_active_$(date +%H%M%S)_0513.out
```

若后台进程 uptime 明显超过 duration 且无输出：

1. 先检查/必要时终止挂住的 v46 进程：
   ```bash
   ps -ef | grep run_v46_4d0808_4cf8a4_context_0513.py
   pkill -f run_v46_4d0808_4cf8a4_context_0513.py
   ```
2. 再看文件侧产物，不要只依赖 process stdout：
   ```bash
   cd /opt/data/home/reverse-tools/douyin_analysis
   ls -lt v46* *4d0808* *4cf8a4* | head -50
   grep -R "v46\|X-Cylons\|ackB\|client_start_pack_time\|0x4d0808\|0x4cf8a4\|Traceback\|TransportError" -n v46* *4d0808* *4cf8a4* | head -200
   ```
3. 如果有 summary JSON，优先统计：
   ```text
   hook-ok / hook-err / v46-* / xEnter / xLeaveNew / ackEnter / sslX / sslLive / consumer_4cf8a4 / caller_4d0808
   ```
4. 判定口径：
   - `ready/hook-ok` 存在但无目标 tag，只能说明 hook 链路可安装、目标事件未复现或 stdout 未吐出；
   - 未读取日志文件前，不能声称 v46 命中或未命中 `0x4d0808/0x4cf8a4`；
   - 即使命中 `0x4cf8a4` consumer，也要检查 `hits/cleanValue/first-seen`，否则仍只是下游消费链可达；
   - 算法本体仍需 strict first-seen：enter 前无 value、leave 后首次出现 value，并被后续 dispatcher/wrapper/`0x4cf8a4` 链消费。

归档时建议生成：

```text
v46_4d0808_4cf8a4_context_conclusion_0513.md
v46_4d0808_4cf8a4_context_summary_0513.json
```

并明确区分：v46 是动态验证 `0x4d0808 caller` 与 `0x4cf8a4` 上游 record/payload 关系；若没有 first-seen 或明确 opaque/sign 输出，仍必须写“`X-Cylons` value 生成算法本体仍未完整还原”。

## `0x4d0808 / 0x4d0834 / 0x4cf8a4` 静态上游降级判定（v47 经验）

当 v46 动态命中 `LR=0x4d0808`、`callsite=0x4d0804 -> 0x4cf8a4`，并看到 nearby callback/adapter candidate `0x4d0834` 后，下一步应做调用前参数来源与 stack local 初始化检查，而不是直接把 `0x4d0808` 或 `0x4d0834` 升级为生成点。

v47 关键局部片段：

```asm
0x004d07b0: adr      x8, #0x4d0834
0x004d07c4: str      x19, [sp, #8]
0x004d07c8: stp      x8, xzr, [sp, #0x10]
0x004d07cc: bl       #0x283c0c
...
0x004d07f0: add      x2, sp, #0x20
0x004d07f4: mov      x0, x19
0x004d07f8: mov      w1, #9
0x004d07fc: stp      xzr, xzr, [sp, #0x20]
0x004d0800: str      xzr, [sp, #0x30]
0x004d0804: bl       #0x4cf8a4
0x004d0808: tbz      w0, #0, #0x4d0814
```

判定规则：

1. `0x4d0808` 是 `0x4d0804 -> 0x4cf8a4` 后的 LR/返回地址；只命中该 LR 不能说明它生成 `X-Cylons` value。
2. 若调用 `0x4cf8a4` 前出现 `x2 = sp + local_offset`，且该 local slot（如 `sp+0x20/sp+0x30`）在调用前被立即清零，则该路径更像本地空/临时对象消费或状态更新，应降级为 non-source path。
3. `0x4d0834` 若只是通过 `adr x8,#0x4d0834` 物化并被写入 stack/record（如 `stp x8, xzr, [sp,#0x10]`），后续函数体只读取 owner/context 字段、调用 helper、维护状态，而无 hash/crypto/base64/复杂 opaque 算法特征，应归类为 callback/adapter/state-maintenance。
4. 此类证据下，`0x4cf8a4 / 0x4cff3c / 0x1ff5fc / 0x346b90 / 0x4cff50 / 0x51cd50` 仍归入 copy/package/consume 链，不能升级为算法本体。
5. 报告中必须明确写：没有算法本体新证据，`X-Cylons` value 生成算法仍未完整还原。

动态复核建议：只有在真实 `X-Cylons` / `ackB` / 目标 SSL 窗口稳定复现时，才继续 dump：`0x4d0804` 前 `sp+0x20/sp+0x30`、`0x4d0834` entry `x0-x3`、`0x4cf8a4` entry `x2`；不要盲目扩大 hook。

v47 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v47_4d0808_4d0834_upstream_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v47_4d0808_4d0834_upstream_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v47_4d0808_4d0834_upstream_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v47_4d0808_4d0834_upstream_conclusion_0513.md
```

运行 v47 静态脚本时，当前 Hermes 环境可能需要：

```bash
PYTHONPATH=/opt/data/home/.local/lib/python3.13/site-packages python3 static_v47_4d0808_4d0834_upstream_0513.py
```

## `0x4d0788 / 0x4d0834` registration-source 精确复核（v48 经验）

当 v47 已把 `0x4d0808 -> 0x4cf8a4` 降级为本地空/临时对象消费路径后，如果仍需确认 nearby `0x4d0834` 是否可能是生成点，应做 registration-source 精确复核：确认 `0x4d0834` 是如何被物化、写入 record、被 helper 注册/链接，而不是只看它的函数体。

v48 关键证据：

```asm
0x004d07a0: mov      w0, w21
0x004d07a4: bl       #0x29f49c
0x004d07a8: mov      x21, x0
0x004d07b0: adr      x8, #0x4d0834
0x004d07b4: adrp     x0, #0x28a000
0x004d07b8: add      x0, x0, #0xd50
0x004d07bc: add      x1, sp, #0x10
0x004d07c0: add      x2, sp, #8
0x004d07c4: str      x19, [sp, #8]
0x004d07c8: stp      x8, xzr, [sp, #0x10]
0x004d07cc: bl       #0x283c0c
0x004d07d0: str      x0, [x29, #0x18]
```

判定规则：

1. 若 `0x4d0834` 只通过 `adr x8,#0x4d0834` 在 `0x4d0788` 内物化，并由 `stp x8,xzr,[sp,#0x10]` 写入 stack callback record，则它优先归类为 callback/adapter entry。
2. `0x4d07cc -> 0x283c0c` 消费 callback record，`0x4d07e4 -> 0x328e0c` 链接注册结果，`0x4d07ec -> 0x2dccac` 清理局部对象；这些是 registration/container/helper 形态，不是直接算法体证据。
3. 同函数内 `0x4d0804 -> 0x4cf8a4` 前若仍满足 `x2=sp+0x20` 且 `sp+0x20/sp+0x30` 立即清零，应继续保持 v47 降级：本地临时对象/状态消费路径，不是已有 `X-Cylons` value source。
4. `0x4d0834` 函数体若主要是 owner state/context 字段读写与 helper 调用，无 hash/crypto/base64/opaque loop/first-seen 证据，则不能升级为 value 生成点。
5. 报告中应明确：v48 证明的是 `0x4d0834` 的 registration relation 和 adapter/state-maintenance 边界；没有算法本体新证据，`X-Cylons` value 生成算法仍未完整还原。

v48 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/v48_4d0788_4d0834_registration_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v48_4d0788_4d0834_registration_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v48_4d0788_4d0834_registration_conclusion_0513.md
```


## registration/helper 上游降级判定（v49 经验）

当 v48 已确认 `0x4d0834` 是由 `0x4d0788` 物化并写入 stack callback record 的 adapter/callback entry 后，下一步可沿 registration 路径继续反查 helper，但目标是确认 helper 语义边界，而不是把高频 helper 误判成算法体。

v49 复核路径：

```text
0x4d07a4 -> 0x29f49c  # 返回 x21，用作 registration/link 上下文
0x4d07cc -> 0x283c0c  # 消费 {owner=x19, callback=0x4d0834} stack callback record
0x4d07e4 -> 0x328e0c  # 链接/容器插入 registration result
0x4d07ec -> 0x2dccac  # cleanup/destructor helper
```

静态引用/语义边界：

```text
0x29f49c: branch refs=27, factory/context-getter style
0x283c0c: branch refs=23, callback-record registration/container consumer
0x328e0c: branch refs=164, link/container insert helper
0x2dccac: branch refs=2067, very common cleanup/destructor helper
```

判定规则：

1. `0x283c0c` 消费 stack callback record `{owner=x19, callback=0x4d0834}`，这只能说明 callback/adapter registration 关系成立，不是 value 生成证据。
2. `0x328e0c` 与 `0x2dccac` 这类高频 link/cleanup helper 不能因出现在注册路径上就升级为算法入口。
3. 若 helper body 没有 hash/crypto/base64/opaque loop 特征，且没有动态 first-seen（enter 前无 value、leave 后出现 value），应继续降级为 factory/registration/link/cleanup 语义。
4. 当前 v49 边界：`0x29f49c / 0x283c0c / 0x328e0c / 0x2dccac`、`0x4d0788 / 0x4d0834` 都不能升级为 `X-Cylons` value 生成点；算法本体仍未完整还原。

v49 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v49_helper_upstream_source_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v49_helper_upstream_source_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v49_helper_upstream_source_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v49_helper_upstream_source_conclusion_0513.md
```


```text
/opt/data/home/reverse-tools/douyin_analysis/static_v33_thunk_caller_x1_source_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v33_thunk_caller_x1_source_static_0512.md
/opt/data/home/reverse-tools/douyin_analysis/v33_thunk_caller_x1_source_static_0512.json
/opt/data/home/reverse-tools/douyin_analysis/v33_thunk_caller_x1_source_conclusion_0512.md

/opt/data/home/reverse-tools/douyin_analysis/static_v34_wrapper_registration_trace_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v34_wrapper_registration_trace_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v34_wrapper_registration_trace_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v34_wrapper_registration_trace_conclusion_0513.md
```

## v50 non-registration / alternative upstream census 经验

当 v49 已将 `0x4d0788/0x4d0834` registration/helper 链降级后，下一步不要继续在同一 helper 链里穷举；应做全局 non-registration census，复查进入 `0x4cf8a4` 的 thunk/wrapper 路径、wrapper 地址物化、以及 `0x4d0834` callback 物化是否存在替代上游。

v50 关键结果：

```text
0x4cf8a4 branch refs: 0x4cf8a0 / 0x4d0134 / 0x4d0804
0x4cf894 branch refs: 0x210c80 / 0x28a460
0x4d0128 branch refs: 0x210c94 / 0x28a354 / 0x4fc0c0
wrapper entries 0x210c74/0x210c88/0x28a348/0x28a454: direct branch refs=0, ADR materialization=1 each
0x4d0834: direct branch refs=0, ADR materialization=1
```

分类统计示例：

```text
callback_record_or_payload_slot_context: 7
object_field_supplied_value_source_candidate: 2
registration_callback_materialization_or_use: 2
generic_forwarding_or_context_path: 5
```

动态验证优先只作为候选，不可升级为算法点：

```text
0x4cf8a0 -> 0x4cf8a4  # callback_record_or_payload_slot_context
0x4d0134 -> 0x4cf8a4  # object_field_supplied_value_source_candidate
0x210c80 -> 0x4cf894
0x28a460 -> 0x4cf894
0x210c94 -> 0x4d0128
0x28a354 -> 0x4d0128
0x4fc0c0 -> 0x4d0128
0x210800 -> 0x210c88
0x28a3e4 -> 0x28a454
```

判定边界：

1. `0x4cf8a0` 路径显示 `x19=[x0+0x38]`、`x2=sp+8`、常量 type（如 `0x1386`），更像 callback record/payload slot context 消费。
2. `0x4d0134` 路径显示 `x2=[x20+0x730]->[0]` 等 object-field supplied source candidate，只能说明上游对象字段供值，不能证明本地生成。
3. `0x4d0804 -> 0x4cf8a4` 仍属于 v47/v48 降级过的 registration/local-empty-object 路径。
4. 四个 wrapper 与 `0x4d0834` 仍表现为 ADR materialized callback/adapter entry；没有 direct caller、hash/crypto/base64/opaque loop 或 first-seen 证据时，不能升级。
5. v50 结论必须写：本轮只完成 v49 之后的替代路径复核和动态验证候选整理；`0x4cf894 / 0x4d0128 / 0x4cf8a4`、四个 wrapper、`0x4d0834` 以及 v49 helpers 仍不能升级为 `X-Cylons` value 生成点；算法本体仍未完整还原。

v50 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v50_non_registration_upstream_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v50_non_registration_upstream_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v50_non_registration_upstream_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v50_non_registration_upstream_conclusion_0513.md
```

## v51 object-field / callback-record source slicing 经验

当 v50 已把替代路径收敛到 `0x4cf8a0 -> 0x4cf8a4`、`0x4d0134 -> 0x4cf8a4`、`0x4fc0c0 -> 0x4d0128` 等 non-registration source-neighborhood 后，下一步应做对象字段 / callback-record payload 的局部反向切片，而不是把这些候选直接升级为算法点。

v51 关键分类：

```text
0x4cf8a0 -> 0x4cf8a4: callback_record_payload_local_stack_x2_to_shared_impl
0x4d0134 -> 0x4cf8a4: object_field_0x730_supplied_x2_to_shared_impl
0x4fc0c0 -> 0x4d0128: direct_call_to_4d0128_object_or_arg_supplied_x1
0x210c80 / 0x28a460 / 0x210c94 / 0x28a354: object_field_supplied_source_candidate
0x210800 / 0x28a3e4: wrapper_callback_materialization_or_tail_adapter
```

判定规则：

1. `0x4cf8a0` 仍是 thunk/shared consumer 入口：`x2 = x1`，`w1 = #1`，随后进入 `0x4cf8a4`；它本身不生成 value。
2. `0x4d0134` 仍是另一类 thunk/shared consumer 入口：`x2 = x1`，`w1 = #2`；局部窗口可见对象字段链和 `+0x730` 形态，但证据只支持 object-field supplied source/context，不支持本地算法生成。
3. `0x4fc0c0 -> 0x4d0128` 可作为继续动态/静态 probe 的优先点：dump 传给 `0x4d0128` 的 `x1`、`x2` 对象字段和后续 `0x4cf8a4` 的 `x2`。但没有 first-seen 前不能升级。
4. 四个 wrapper 及其 ADR materialization 仍保持 callback/adapter/table 路径判断；没有 direct caller、hash/crypto/base64/opaque loop 或 first-seen 证据时不能称为算法本体。
5. v51 未发现新的 hash/crypto/base64/opaque loop，也无 enter-before/leave-after first-seen 证据；因此所有 v51 候选仍只能归类为对象字段/record payload 供值与 shared consumer 邻域。

v51 后续建议：

```text
动态优先：0x4cf8a0 / 0x4d0134 / 0x4fc0c0
dump: x0-x3, x1/x2 指向内容, object +0x730 链, callback record +0x20/+0x38/+0x40/+0x50, backtrace
```

判定标准保持 strict first-seen：只有观察到某点 enter 前无 `X-Cylons`/opaque value，leave 后首次出现 value，并被后续 `0x4cf8a4 -> 0x1ff5fc -> 0x346b90/0x4cff50` 链消费，才能升级为生成点或生成点近邻。

v51 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v51_object_callback_source_slice_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v51_object_callback_source_slice_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v51_object_callback_source_slice_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v51_object_callback_source_slice_conclusion_0513.md
```

v51 结论：本轮只把 v50 后的 object-field / callback-record source-neighborhood 进一步分层；`0x4d0134`、`0x4cf8a0`、`0x4fc0c0`、四个 wrapper 与既有 thunk/shared consumer 链仍不能升级为 `X-Cylons` value 生成点。算法本体仍未完整还原。

## v52-v54 priority source-neighborhood / next-candidate 复核经验

当 v51 已把优先点收敛到 `0x4cf8a0 / 0x4d0134 / 0x4fc0c0` 后，v52 应先复核调用前 value-lane 与局部来源；v53 再复核 v52 暴露的 `0x4d0128` 地址物化点和下游 pack/helper caller；v54 继续深挖 highest-value 候选 `0x3a6930 -> 0x346b90` 与 `0x4d0128` callback-table materializers。三轮都只能作为“候选分层/动态 probe 指南”，不能替代 first-seen 动态证据。

v52 关键结论：

```text
0x4cf8a0 / 0x4d0134: live-in x1 -> x2 后进入 0x4cf8a4 的 shared consumer thunk/type path
0x4fc0c0 -> 0x4d0128: x1=sp+8 本地 payload，x2 来自入参对象链
```

判定规则：

1. `0x4cf8a0`、`0x4d0134` 仍是 shared consumer/type thunk，不是本地 value 生成点。
2. `0x4fc0c0` 是 `0x4d0128` 上游 probe：`x1=sp+8` 本地 payload、`x2` 来自对象字段链；没有 enter-before/leave-after first-seen 前不可升级。
3. v52 未发现新的 hash/crypto/base64/opaque loop 或 first-seen 证据；算法本体仍未还原。

v53 关键分类：
```json
{
  "callback_or_table_materialization_of_4d0128": 3,
  "downstream_pack_wrapper_to_346b90": 1,
  "downstream_helper_call_from_pack_neighborhood": 1,
  "alternate_caller_to_346b90_needs_dynamic_context": 1
}
```

v53 地址判定：

```text
0x4d3a20 / 0x4d487c / 0x4d586c:
  ADR materializes 0x4d0128; callback/table/adapter registration 邻域；不是 value 生成点。

0x4cff58 -> 0x346b90:
  下游 pack wrapper / copy-package 续链；不是算法本体。

0x4cffb4 -> 0x51cd50:
  pack-neighborhood helper call；不是算法本体。

0x3a6930 -> 0x346b90:
  alternate caller，可做动态上下文 probe；静态未证明本地生成 value。
```

v54 关键分类：
```json
{
  "alternate_pack_caller_context_probe": 1,
  "callback_table_materialization_probe": 3,
  "new_algorithm_evidence": false,
  "first_seen_evidence": false
}
```

v54 地址判定：

```text
0x3a6930 -> 0x346b90:
  alternate downstream pack/copy caller。x1 before 0x346b90 仍是 caller/object/live-in derived，窗口内无本地生成；0x346b90 是已知 pack/copy helper。

0x4d3a20 / 0x4d487c / 0x4d586c -> 0x4d0128:
  ADR materializes callback address 并写入/传入 stack/object record 或 registration helper；仍是 callback-table/address materialization 邻域。
```

动态后续建议：优先 probe `0x3a6930 / 0x4d3a20 / 0x4d487c / 0x4d586c`，dump `x0-x3`、`x1/x2` pointed buffers、record/payload slots（尤其 `+0x20/+0x38/+0x50`）、resolved callback target 与 backtrace，并与 `0x4cf8a4 -> 0x1ff5fc -> 0x346b90/0x4cff50` 消费链对齐。只有满足 strict first-seen（enter 前无 value、leave/后续 callback 后首次出现 value，并被后续消费链使用）才能升级为生成点或生成点近邻。

v52/v53/v54 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v52_priority_source_neighborhood_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v52_priority_source_neighborhood_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v52_priority_source_neighborhood_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v52_priority_source_neighborhood_conclusion_0513.md

/opt/data/home/reverse-tools/douyin_analysis/static_v53_next_candidate_reverse_slice_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v53_next_candidate_reverse_slice_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v53_next_candidate_reverse_slice_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v53_next_candidate_reverse_slice_conclusion_0513.md

/opt/data/home/reverse-tools/douyin_analysis/static_v54_alt_caller_callback_table_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v54_alt_caller_callback_table_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v54_alt_caller_callback_table_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v54_alt_caller_callback_table_conclusion_0513.md
```

v54 结论：本轮只完成 alternate caller / callback-table materialization 静态深挖和候选分层；`0x3a6930`、`0x4d3a20`、`0x4d487c`、`0x4d586c` 均不能升级为 `X-Cylons` value 生成点。算法本体仍未完整还原。


## v55-v56 algorithm-like probes 静态深挖与降噪经验

当 v54 后开始全局 census 下游 pack/helper caller 与 callback materializer 时，v55 可能标出若干 `algorithm_like_upstream_probe_needs_dynamic_first_seen` 高分候选。v56 的处理原则是：这些候选必须再做 dedicated crypto / loop / helper-call / `0x1ff5fc` source-lane 降噪，不能只因 generic bitops、分支/回边密度、helper-heavy 大函数窗口而升级为 value 生成点。

v55/v56 关键候选：

```text
algorithm-like upstream probes:
0x4d35ac / 0x45839c / 0x22b940 / 0x459c28 / 0x2b4bc4 / 0x2b4ba0

callback/materializer probe:
0x4d3a20
```

v56 过滤结果：

```json
{
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "static_algorithm_like_probe_evidence": true,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

判定规则：

1. 若函数窗口只有 generic bitops（如 `eor/and/orr/lsl/lsr/mul`）和大量 helper calls，但没有 dedicated AES/SHA/CRC、明确 hash/base64/opaque transform 输出链，不能称为算法体。
2. 若候选调用 `0x1ff5fc`，且 `x1` 来源为 `ret_0x329ab4`、`ret_0x1f9fc8`、caller/object/stack lane，只能说明 source object 被 copy/assign；除非动态 first-seen 证明该返回值就是新生成的 X-Cylons value，否则仍是 probe。
3. `0x4d3a20` 虽在 `0x4d0128` callback/table materializer 邻域且函数窗口 algorithm-like，但地址物化/registration 关系不是 value generation。
4. v56 后续动态 hook 应保留：
   ```text
   tier1 probes: 0x4d35ac / 0x45839c / 0x22b940 / 0x459c28 / 0x2b4bc4 / 0x2b4ba0 / 0x4d3a20
   downstream alignment: 0x1ff5fc / 0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
   ```
5. 动态 dump：`x0-x7`、`0x1ff5fc` 的 `x1` 源对象、返回值、pointed buffers、record/payload slots（`+0x20/+0x38/+0x50`）、backtrace。只有满足 strict first-seen（enter 前无 value，leave/后续 callback 后首次出现并被消费链使用）才能升级。

v55/v56 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v55_pack_upstream_materializer_census_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v55_pack_upstream_materializer_census_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v55_pack_upstream_materializer_census_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v55_pack_upstream_materializer_census_conclusion_0513.md

/opt/data/home/reverse-tools/douyin_analysis/static_v56_algorithm_like_probe_deep_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v56_algorithm_like_probe_deep_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v56_algorithm_like_probe_deep_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v56_algorithm_like_probe_deep_conclusion_0513.md
```

v56 结论：本轮只完成 v55 algorithm-like candidates 的静态深挖与降噪；没有任何候选可升级为 `X-Cylons` value 生成点，算法本体仍未完整还原。

## v57 upstream source/caller/materializer 复核经验

当 v56 已把 `0x4d35ac / 0x45839c / 0x22b940 / 0x459c28 / 0x2b4bc4 / 0x2b4ba0 / 0x4d3a20` 降级为 dynamic probe 后，v57 的有效下一步是做 direct caller、地址物化/raw pointer、以及候选函数内 `0x1ff5fc` 的 `x1` call-return source lane 复核。目标是给动态 hook 排优先级，而不是仅凭静态 caller/source 证据升级算法点。

v57 关键结论：

```json
{
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

优先动态顺序：

```text
0x22b940 / 0x2b4ba0 / 0x2b4bc4 / 0x45839c / 0x459c28 / 0x4d35ac / 0x4d3a20
```

ret-producer targets：

```text
0x1f9fc8  # known container/callback/object helper
0x329ab4  # short helper/function, feeds x1 ret-derived lane in multiple probes
```

判定规则：

1. 如果 candidate/function_start 的 direct refs、ADR/materializer、raw refs 全为 0，不能把“无 direct caller”当作死路；这只说明路径更可能经 callback table / indirect dispatch / object lane 触发。
2. `0x1ff5fc` 的 `x1` 若来自 `ret_0x329ab4` 或 `ret_0x1f9fc8`，只能说明 copy/assign helper 的 source object 由上游 helper 返回；没有 dynamic strict first-seen 前，不能证明该返回值就是新生成的 `X-Cylons` value。
3. `0x1f9fc8` 已知是 container/callback/object helper；即使它出现在 ret-derived lane，也不能升级为算法体。
4. `0x329ab4` 值得作为 ret-producer 动态 hook，但静态特征不足以证明 hash/crypto/base64/opaque transform 输出。
5. 动态验证应同时 hook candidate entry/leave、ret-producer targets、`0x1ff5fc`、下游 `0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50`，dump `x0-x7`、`0x1ff5fc x1` source object、producer returns、pointed buffers、record slots `+0x20/+0x38/+0x50`、backtrace。
6. 只有满足 strict first-seen（candidate/ret-producer enter 前无 value，leave 后首次出现，并被下游消费链使用）才能升级；否则 v57 仍只是上游 source/caller/materializer 排名。

v57 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v57_upstream_source_caller_materializer_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v57_upstream_source_caller_materializer_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v57_upstream_source_caller_materializer_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v57_upstream_source_caller_materializer_conclusion_0513.md
```

v57 结论：本轮只完成 v56 tier1 probes 的更上游 source/return/caller/materializer 排名；没有 new value-source、没有 proven algorithm、没有 first-seen。`X-Cylons` value 生成算法本体仍未完整还原。


## v59 priority producer-argument / source-object 复核经验

当 v57/v58 已将 priority probes 收敛到 `0x22b940 / 0x2b4ba0 / 0x2b4bc4 / 0x45839c / 0x459c28 / 0x4d35ac`，下一步应继续沿 ret/source lane 上推 producer 参数与 source object 定义，而不是把 `0x329ab4`、`0x1f9fc8` 等 ret-producer 直接升级为算法点。

v59 关键结论：

```json
{
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

source class 分布示例：

```json
{
  "ret_derived_source": 23,
  "caller_argument_source": 1,
  "caller_object_field_source": 3,
  "unknown_source": 1
}
```

判定规则：

1. `0x329ab4` 在多个 priority callsites 的 return lane 中反复出现时，优先归类为 typed lookup/filter wrapper；其下游进入 `0x1ff5fc x1` copy/assign 只证明 source object 被拷贝/赋值，不证明本地生成 `X-Cylons` value。
2. `0x329930 / 0x32c45c` 若表现为 keyed lookup/search，且输入来自 caller/object/stack/context，应继续归类为 lookup/search helper，不升级为算法体。
3. `0x1f9fc8` 若 input 来自 caller/object fields（例如 `arg_x19+0x144`、`arg_x19+0x730`）并表现为 fixed-size vector/array index helper，应视为 container-index source，不是本地生成算法。
4. priority callsite 若只呈现 `lookup/filter/container-index -> ret -> 0x1ff5fc copy/assign -> pack/carry`，即使静态窗口看起来复杂，也不能升级为 value 生成点。
5. 动态验证优先 hook：
   ```text
   priority callsites: 0x22b940 / 0x2b4ba0 / 0x2b4bc4 / 0x45839c / 0x459c28 / 0x4d35ac
   producer/lookup chain: 0x329ab4 / 0x329930 / 0x32c45c / 0x1f9fc8
   downstream alignment: 0x1ff5fc / 0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
   ```
6. 动态 dump 要包含 producer args `x0-x3`、producer return、`[ret+0x18]`、`0x1ff5fc x0/x1`、destination object fields、下游 carry points 与 backtrace。只有 strict first-seen（producer/candidate enter 前无 value，leave 后首次出现，并被后续消费链使用）才能升级。
7. 报告措辞：v59 是 priority source-object / producer-argument 上推与降级结论；没有 hash/crypto/base64/opaque transform 输出链或 first-seen 证据时，必须继续写“`X-Cylons` value 生成算法本体仍未完整还原”。

v59 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v59_priority_source_object_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v59_priority_source_object_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v59_priority_source_object_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v59_priority_source_object_conclusion_0513.md
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-13_project_douyin-xcylons-v59-priority-source-object.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v59_0513.json
```

## v60 lookup-chain xref / caller classification 复核经验

当 v59 已将 priority source-object / producer-argument 链降级为 `typed lookup/filter -> ret -> 0x1ff5fc copy/assign -> pack/carry` 后，v60 的有效下一步是对 producer/lookup chain 做全局 direct caller、ADR materializer、raw pointer 复核，并对 caller 上下文分类。目标是确认是否存在绕过既有 lookup/copy 解释的非 copy 算法入口，而不是重复追同一 ret lane。

v60 复核目标：

```text
0x329ab4 / 0x329930 / 0x32c45c / 0x1f9fc8 / 0x1ff5fc
```

v60 结论边界：

```json
{
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

判定规则：

1. 对每个 producer/lookup/copy target 同时统计 direct branch callers、ADR/ADRP/LDR literal 地址物化点、raw pointer refs；若无 materializer/raw pointer 命中，不能把这些 target 升级为函数指针算法入口。
2. 对 direct caller 做 caller class 分类，优先区分：
   - `typed_lookup_or_filter_caller`；
   - `lookup_backend_or_keyed_search_caller`；
   - `container_index_or_object_field_source`；
   - `copy_assign_or_downstream_pack_lane`；
   - `algorithm_like_probe_needs_dynamic_first_seen`。
3. 若 caller 分布仍集中在 typed lookup、lookup backend、container-index、copy/assign lane，且没有 hash/crypto/base64/opaque transform 输出链，应继续降级为 lookup-chain / source-object 传播链。
4. 即使出现 algorithm-like caller，也只能作为动态优先级；没有 strict first-seen（enter 前无 value、leave/回调返回后首次出现并被下游消费）或明确 sign/opaque callback 输出，不能称为 `X-Cylons` value 生成点。
5. v60 后动态优先应同时覆盖：
   ```text
   tier1 callers:
   0x22b940 / 0x2b4ba0 / 0x2b4bc4 / 0x22b714 / 0x22b760 / 0x22b930
   0x293d5c / 0x2b4b90 / 0x2b4bb4 / 0x2b4c90 / 0x24ad20 / 0x24add0

   producer/copy chain:
   0x329ab4 / 0x329930 / 0x32c45c / 0x1f9fc8 / 0x1ff5fc

   downstream alignment:
   0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
   ```
6. 动态 dump 要包含 caller `x0-x7`、producer args/return、`0x1ff5fc x0/x1`、destination/source object fields、pointed buffers、record slots、downstream carry points 与 backtrace；只在同一 value 被 first-seen 并被后续消费链使用时升级。
7. 报告措辞：v60 是 lookup-chain xref/caller classification 收敛轮；没有把任何 caller/materializer 升级为 `X-Cylons` value 生成点。算法本体仍未完整还原。

v60 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v60_lookup_chain_xref_caller_classification_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v60_lookup_chain_xref_caller_classification_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v60_lookup_chain_xref_caller_classification_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v60_lookup_chain_xref_caller_classification_conclusion_0513.md
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-13_project_douyin-xcylons-v60-lookup-chain-xref.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v60_0513.json
```

## v61 tier1 second-level source-lane 反切片经验

当 v60 已完成 producer/lookup/copy chain 的 caller classification 后，v61 的有效下一步是对 v60 tier1 callers 做二级上游/source-lane 反切片，目标是确认是否存在绕过 lookup/copy/container-index 的非平凡来源，而不是重复统计 direct caller。

v61 复核对象：

```text
tier1 callers / callsites:
0x22b940 / 0x2b4ba0 / 0x2b4bc4
0x22b714 / 0x22b760 / 0x22b930
0x293d5c / 0x2b4b90 / 0x2b4bb4 / 0x2b4c90
0x24ad20 / 0x24add0 / 0x24b194 / 0x24b244
0x22c9d0 / 0x244f48 / 0x245440
0x3299fc / 0x329a2c / 0x329a7c
```

v61 关键统计示例：

```json
{
  "class_distribution": {
    "copy_assign_source_lane": 3,
    "typed_lookup_filter_lane": 7,
    "container_index_lane": 4,
    "lookup_backend_lane": 6
  },
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

判定规则：

1. 对每个 tier1 caller 追踪 `x0-x3` source-lane，标注其来源是否为 `typed_lookup_return_lane`、`lookup_backend_lane`、`container_index_lane`、`caller_argument_lane`、`caller_object_field_lane`、`stack_local_lane` 或 `copy_assign_source_lane`。
2. 如果 source-lane 仍解析为 typed lookup/filter return、lookup backend return、container index return、caller argument/object field 或 copy/assign lane，即使窗口内仍有 helper call 或局部复杂控制流，也不能升级为 `X-Cylons` value 生成点。
3. 对 `unknown_lane` 只作为动态 probe 保留；除非静态能看到明确 hash/crypto/base64/opaque transform 输出链，或动态 first-seen 证明 enter 前无 value、leave/回调后首次出现 value，否则不能称为算法本体。
4. v61 后动态优先覆盖：
   ```text
   tier1 callsite probes:
   0x3299fc / 0x329a2c / 0x329a7c
   0x22b714 / 0x22b760 / 0x22b930
   0x24ad20 / 0x24add0 / 0x24b194 / 0x24b244
   0x22b940 / 0x22c9d0 / 0x244f48 / 0x245440

   producer/copy chain:
   0x329ab4 / 0x329930 / 0x32c45c / 0x1f9fc8 / 0x1ff5fc

   downstream alignment:
   0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
   ```
5. 动态 dump 应包含 caller `x0-x7`、producer args/return、`0x1ff5fc x0/x1`、destination/source object fields、pointed buffers、record slots、downstream carry points 与 backtrace；只有同一 value 满足 strict first-seen 并被消费链使用时才可升级。
6. 报告措辞：v61 是二级 source-lane 反切片和动态优先级整理；没有 new value-source、proven algorithm 或 first-seen 时，必须继续写“`X-Cylons` value 生成算法本体仍未完整还原”。

v61 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v61_tier1_second_level_source_slice_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v61_tier1_second_level_source_slice_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v61_tier1_second_level_source_slice_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v61_tier1_second_level_source_slice_conclusion_0513.md
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-13_project_douyin-x-cylons-v61-tier1-second-level-source-lane-slicing.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v61_0513.json
```

## v62 unknown/helper-return lanes 三级展开与归档经验

当 v61 已把 tier1 callers/source-lane 降到 lookup/copy/container-index，但仍遗留大量 `unknown_lane` / `other_helper_return_lane` 时，下一步可做 v62 风格的三级 helper 展开：目标是把未解析 lane 再分类为 helper/parser/container/copy/probe 邻域，并整理动态 hook 优先级，而不是静态宣称找到算法本体。

v62 复核对象：

```text
v61 focus lanes:
x2:unknown_lane / x0:other_helper_return_lane / x1:unknown_lane / x1:other_helper_return_lane

third-level helper probes:
0x3299f0 / 0x203a7c / 0x2130e4 / 0x22c7e0 / 0x22c820 / 0x22d2f4
0x22d304 / 0x22d45c / 0x24b3dc / 0x24c824 / 0x28da18 / 0x2eaf10
0x2eb338 / 0x2ecb10
```

v62 关键结论边界：

```json
{
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

判定规则：

1. 对 unresolved/helper-return lane 做 nearby helper call 展开时，记录每个 helper 的 direct calls、indirect calls、generic bitops、conditional back edges、lookup/copy/downstream calls 与 unknown calls。
2. 如果 helper 聚类为 `lookup_parse_container_helper_lane`、`fixed_size_vector_index_helper`、`copy_assign_helper`、`container_or_object_helper`、`iterator_or_range_helper` 等，只能说明 source-object / helper-return lane 被继续解释，不能升级为 value 生成点。
3. 若 helper 有少量 bitop/backedge，但没有明确 hash/crypto/base64/opaque transform 输出链，也只能保留为 `algorithm_like_unproven_probe` 或 `third_level_helper_or_unknown_lane`。
4. 动态 hook 优先覆盖：
   ```text
   third-level helper probes:
   0x3299f0 / 0x203a7c / 0x2130e4 / 0x22c7e0 / 0x22c820 / 0x22d2f4
   0x22d304 / 0x22d45c / 0x24b3dc / 0x24c824 / 0x28da18 / 0x2eaf10
   0x2eb338 / 0x2ecb10

   v61 tier1 alignment:
   0x3299fc / 0x329a2c / 0x329a7c / 0x22b714 / 0x22b760 / 0x22b930
   0x24ad20 / 0x24add0 / 0x24b194 / 0x24b244 / 0x22b940 / 0x22c9d0
   0x244f48 / 0x245440

   producer/copy chain:
   0x329ab4 / 0x329930 / 0x32c45c / 0x1f9fc8 / 0x1ff5fc
   0x329098 / 0x3296a4 / 0x3299f0 / 0x329a20

   downstream alignment:
   0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
   ```
5. 动态 dump 要包含 candidate/helper `x0-x7`、helper args/return、`0x1ff5fc x0/x1`、source/destination object fields、pointed buffers、record slots、downstream carry points 与 backtrace。
6. 归档 v62 时建议同时生成 task status JSON 与 project memory；用 `memory-write.py --body-from <conclusion.md>`，避免 Markdown 反引号/地址/JSON 被 shell 解释。
7. 报告措辞：v62 是 unknown/helper-return lane 的三级展开与动态优先级整理；没有 new value-source、proven algorithm 或 first-seen 时，必须继续写“`X-Cylons` value 生成算法本体仍未完整还原”。

v62 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v62_unknown_helper_third_level_slice_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v62_unknown_helper_third_level_slice_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v62_unknown_helper_third_level_slice_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v62_unknown_helper_third_level_slice_conclusion_0513.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v62_0513.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-13_project_douyin-x-cylons-v62-unknown-helper-third-level-slice.md
```

## v63-v64 fourth/fifth-level boundary expansion 经验

当 v62 已把 unknown/helper-return lane 展开到三级 helper 后，v63/v64 可继续围绕 top unknown/indirect/materializer 边界做四级/五级展开；目标是给动态 hook 排优先级，并复核是否出现真正的 value-source/algorithm evidence。不要把 shared helper、allocator/runtime、parser/container、lookup/copy、callback/table/indirect dispatch probe 升级成算法本体。

v64 复核范围：

```text
从 v63 top unknown/indirect/materializer boundaries 继续展开 fifth-level callees，
并对 direct caller、ADR materializer、raw pointer ref、blr/br target source 做分层。
```

v64 总结边界：

```json
{
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v64 class distribution 示例：

```text
high_fanout_container_dispatch_helper: 1
allocator_or_shared_object_helper_variant: 1
shared_dispatch_or_object_helper: 2
fifth_level_unknown_or_shared_helper_lane: 51
shared_indirect_helper: 2
allocator_or_shared_object_helper: 1
runtime_or_library_helper_lane: 5
parser_container_or_iterator_lane: 2
third_level_helper_lane: 3
shared_helper_lane: 5
```

v64 动态优先级：

```text
fifth_level_priority_probes:
0x2ecb10 / 0x33596c / 0x338890 / 0x339350 / 0x1f7604 / 0x1fae9c
0x20ad94 / 0x22322c / 0x2dbc3c / 0x32bdd8 / 0x33594c / 0x33a7d4
0x1f720c / 0x338ac8 / 0x203a7c / 0x20df1c / 0x2130e4 / 0x338dd0
0x1f77f4 / 0x1f7d00 / 0x1f8200 / 0x1f9f9c

indirect_target_scouts:
0x2ecb10 / 0x33596c / 0x338890 / 0x339350 / 0x1f7604 / 0x1fae9c
0x20ad94 / 0x22322c / 0x2dbc3c / 0x32bdd8 / 0x33594c / 0x33a7d4
0x338ac8 / 0x338dd0

materializer_or_raw_ref_scouts:
0x2ecb10 / 0x33596c / 0x1f720c / 0x20df1c

producer_lookup_copy_chain:
0x329ab4 / 0x329930 / 0x32c45c / 0x1f9fc8 / 0x1ff5fc
0x329098 / 0x3296a4 / 0x3299f0 / 0x329a20 / 0x32964c / 0x329b0c

downstream_alignment:
0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
```

动态 dump 要求：entry/leave `x0-x7`、returns、resolved `blr/br` targets、indirect target object/vtable memory、producer returns、`0x1ff5fc x0/x1`、source/destination object fields、pointed buffers、record slots、downstream carry backtrace。

判定规则：

1. `0x2ecb10 / 0x33596c / 0x338890 / 0x339350` 等高分点优先作为 high-fanout/shared-dispatch/allocator-object helper scout，不可因 indirect count 或 raw ref 升级为算法点。
2. `0x1f720c / 0x20df1c` 有 materializer/raw ref，可作为 callback/table/shared helper 边界 scout；没有 closed transform chain 前不能升级。
3. `0x338ac8 / 0x338dd0` 更像 parser/container/iterator indirect helper；动态只验证 target 与参数来源。
4. 若 reviewed fifth-level targets 仍解析为 shared helper、allocator/runtime、parser/container、lookup/copy 或 callback/table/indirect dispatch probe，且无 hash/crypto/base64/opaque transform 输出链、无 strict first-seen，必须继续写：`X-Cylons` value 生成算法本体仍未完整还原。

v64 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/v64_fifth_level_boundary_expansion_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v64_fifth_level_boundary_expansion_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v64_fifth_level_boundary_expansion_conclusion_0513.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v64_0513.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-13_project_douyin-x-cylons-v64-fifth-level-boundary-expansion.md
```

## v65 sixth-level source/target/caller expansion 经验

当 v64/v62 之后已经把边界扩到 fifth-level high-value indirect/materializer/shared-helper probes，v65 可继续做第六层 source/target/caller 展开；目标是整理动态 hook 优先级与排除 shared/runtime/container 噪声，不是把第六层 helper 直接升级为算法本体。

v65 复核范围：

```text
从 v64 high-value fifth-level probes 继续展开 unknown callees、materializer owners、direct caller owners、ret-derived indirect-target source lanes。
selected cutpoints:
0x2ecb10 / 0x33596c / 0x338890 / 0x339350 / 0x1f7604 / 0x1fae9c
0x20ad94 / 0x22322c / 0x2dbc3c / 0x32bdd8 / 0x33594c / 0x33a7d4
0x1f720c / 0x338ac8 / 0x20df1c / 0x338dd0
```

v65 总结边界：

```json
{
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v65 class distribution 重点：

```text
algorithm_like_unproven_sixth_level_probe: 30
object_vtable_indirect_dispatch_probe: 21
unknown_indirect_dispatch_probe: 19
factory_return_indirect_dispatch_probe: 13
sixth_level_unknown_or_shared_boundary: 50
materializer_or_raw_table_boundary_probe: 19
runtime_library_noise_lane: 12
lookup_copy_or_source_object_lane: 3
```

判定规则：

1. `algorithm_like_unproven_sixth_level_probe` 只代表静态窗口存在复杂控制流/bitop/helper 组合；没有闭合的 hash/crypto/base64/opaque transform 输出链与 strict first-seen 时，不能升级为 value 生成点。
2. object/vtable/factory-return/unknown indirect dispatch 只作为 resolved-target scout；动态需 dump target object/vtable/GOT/global pointer memory 与调用前后 `x0-x7`。
3. materializer/raw table boundary 只证明地址/表/record 物化边界，不能替代生成证据。
4. 若第六层目标仍归类为 shared/container/runtime helper、lookup/copy/source-object lane、callback/table/materializer boundary，则继续保持“调用链收窄，算法未还原”。
5. 升级标准仍是 strict first-seen：candidate/producer enter 前无 value，leave/回调后首次出现，并被 `0x4cf8a4 -> 0x346b90/0x4cff50` 等消费链使用。

v65 动态优先级：

```text
sixth_level_priority_probes:
0x2b8db4 / 0x1f95d0 / 0x1fc2a4 / 0x1fc694 / 0x1ff9c8 / 0x20c978
0x20e1f0 / 0x20e530 / 0x229588 / 0x338ac8 / 0x1fa908 / 0x20b664
0x228cd0 / 0x28d3f4 / 0x2cc8ac / 0x2d4ccc / 0x2dbb1c / 0x2e2350
0x2e23a4 / 0x2e25e8 / 0x1f98e0 / 0x20e8a8 / 0x20eb94 / 0x20ed28

indirect_target_scouts:
0x1fc2a4 / 0x1fc694 / 0x229588 / 0x338ac8 / 0x20b664 / 0x2dbb1c
0x20e8a8 / 0x20ed28 / 0x21aab4 / 0x21b520 / 0x276df8 / 0x2cb9a4
0x2cc548 / 0x338a78 / 0x1f99a0 / 0x1f9adc / 0x1fae9c / 0x21fcec
0x220988 / 0x22320c

materializer_or_raw_ref_scouts:
0x2b8db4 / 0x1f95d0 / 0x1fc2a4 / 0x1fc694 / 0x1ff9c8 / 0x20c978
0x20e1f0 / 0x20e530 / 0x229588 / 0x21aab4 / 0x2cb9a4 / 0x1f99a0
0x1f9adc / 0x21fcec / 0x220988 / 0x22320c

producer_lookup_copy_chain:
0x329ab4 / 0x329930 / 0x32c45c / 0x1f9fc8 / 0x1ff5fc
0x329098 / 0x3296a4 / 0x3299f0 / 0x329a20 / 0x32964c / 0x329b0c

downstream_alignment:
0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
```

v65 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v65_sixth_level_source_target_caller_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v65_sixth_level_source_target_caller_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v65_sixth_level_source_target_caller_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v65_sixth_level_source_target_caller_conclusion_0513.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v65_0513.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-13_project_douyin-x-cylons-v65-sixth-level-source-target-caller.md
```

v65 结论：本轮只完成第六层 source/target/caller 静态展开与动态优先级整理；未发现 new value-source、proven algorithm 或 first-seen。`X-Cylons` value 生成算法本体仍未完整还原。


## v67 eighth-level boundary/source expansion 归档与验证经验

当 v65/v66 已把边界扩到 high-value algorithm-like / indirect-target / materializer/raw-ref / unknown-shared probes 后，v67 可以继续做第八层 source/target/caller/producer 静态展开；目标仍是降噪、动态 hook 排优先级和归档验证，不是凭静态复杂度升级算法点。

v67 复核范围示例：

```text
selected cutpoints:
0x28f6a8 / 0x290b80 / 0x2b8db4 / 0x1f95d0 / 0x1fc2a4 / 0x1fc694
0x1ff9c8 / 0x20c978 / 0x20e1f0 / 0x20e530 / 0x229588 / 0x1fa908
0x1ff650 / 0x207ec8 / 0x20b664 / 0x21a8fc / 0x228b1c / 0x228cd0
0x2776dc / 0x28d3f4 / 0x28d560 / 0x28d628 / 0x2cc5a0 / 0x2cc8ac
0x2d3ee8 / 0x2d442c / 0x2d4c60 / 0x2d4ccc / 0x2d5a80 / 0x2d6c14
0x2dbb1c / 0x2e2350 / 0x2e23a4 / 0x2e25e8 / 0x2f7044 / 0x330848
0x338ac8 / 0x339468 / 0x1f9824 / 0x1f982c / 0x1f98e0 / 0x1fa998
```

v67 总结边界：

```json
{
  "reviewed_target_count": 341,
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v67 class distribution 重点：

```text
algorithm_like_unproven_eighth_level_probe: 118
unknown_indirect_dispatch_probe: 10
factory_return_indirect_dispatch_probe: 14
object_vtable_indirect_dispatch_probe: 21
caller_supplied_indirect_dispatch_probe: 2
materializer_or_raw_table_boundary_probe: 14
runtime_library_noise_lane: 22
shared_helper_lane: 4
eighth_level_unknown_or_shared_boundary: 100
lookup_copy_or_source_object_lane: 19
```

判定规则：

1. `algorithm_like_unproven_eighth_level_probe` 只代表静态窗口存在 bitop/backedge/helper/常量等算法相似特征；没有闭合 transform-to-output lane 与 strict first-seen 时，不能升级为 `X-Cylons` value 生成点。
2. object/vtable/factory-return/caller-supplied indirect dispatch 只作为 resolved-target scout；动态需 dump target object/vtable/GOT/global memory 与调用前后 `x0-x7`。
3. materializer/raw-ref/table boundary 只证明地址、表或 record 物化边界；不能替代 value generation 证据。
4. 若第八层目标仍聚类为 shared helper、runtime/container noise、lookup/copy/source-object lane 或 indirect dispatch probe，报告必须继续写“`X-Cylons` value 生成算法本体仍未完整还原”。

v67 动态优先级：

```text
eighth_level_priority_probes:
0x28f6a8 / 0x290b80 / 0x2b8db4 / 0x1f95d0 / 0x1fc2a4 / 0x1fc694
0x1ff9c8 / 0x20c978 / 0x20e1f0 / 0x20e530 / 0x229588 / 0x292c7c
0x29348c / 0x294198 / 0x2944a0 / 0x2945f4 / 0x294b50 / 0x2959b0
0x1fa908 / 0x1ff650 / 0x207ec8 / 0x20b664 / 0x21a8fc / 0x228b1c
0x228cd0 / 0x2776dc / 0x278980 / 0x28d3f4 / 0x28d560 / 0x28d628
0x2c2794 / 0x2cc5a0

producer_lookup_copy_chain:
0x329ab4 / 0x329930 / 0x32c45c / 0x1f9fc8 / 0x1ff5fc
0x329098 / 0x3296a4 / 0x3299f0 / 0x329a20 / 0x32964c / 0x329b0c

downstream_alignment:
0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
```

动态 dump 要求：entry/leave `x0-x7`、returns、resolved `blr/br` targets、target object/vtable/GOT/global memory、materializer record/table slots、producer returns、`0x1ff5fc x0/x1`、source/destination object fields、pointed buffers、downstream carry backtrace。只有同一 value 满足 strict first-seen 并被后续消费链使用时才可升级。

归档验证经验：v67 结束时应同时检查脚本、JSON、静态 Markdown、conclusion、task status、project memory 六类产物存在且非空；解析 JSON 确认 `algorithm_status=not_recovered`、`first_seen_evidence=false`、`status=completed_static`、有 `recommended_dynamic_hooks.eighth_level_priority_probes`，并确认 project memory 与 conclusion 内容一致。

v67 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v67_eighth_level_boundary_source_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v67_eighth_level_boundary_source_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v67_eighth_level_boundary_source_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v67_eighth_level_boundary_source_conclusion_0513.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v67_0513.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-13_project_douyin-x-cylons-v67-eighth-level-boundary-source.md
```

v67 结论：本轮只完成第八层 boundary/source 静态展开、动态优先级整理和归档验证；未发现 new value-source、proven algorithm 或 first-seen。`X-Cylons` value 生成算法本体仍未完整还原。

## v68 ninth-level boundary/source expansion 归档与验证经验

当 v67 已把 high-value algorithm-like / indirect-target / materializer/raw-ref / unknown-shared probes 推到第八层后，v68 可以继续从 v67 最高价值边界展开第九层。目标仍是降噪、动态 hook 排优先级和归档验证；不能凭静态复杂度或第九层 helper 聚类升级为算法本体。

v68 复核范围示例：

```text
selected v67 cutpoints:
0x28f6a8 / 0x290b80 / 0x2b8db4 / 0x1f95d0 / 0x1fc2a4 / 0x1fc694
0x1ff9c8 / 0x20c978 / 0x20e1f0 / 0x20e530 / 0x229588 / 0x292c7c
0x29348c / 0x294198 / 0x2944a0 / 0x2945f4 / 0x294b50 / 0x2959b0
0x1fa908 / 0x1ff650 / 0x207ec8 / 0x20b664 / 0x21a8fc / 0x228b1c
0x228cd0 / 0x2776dc / 0x278980 / 0x28d3f4 / 0x28d560 / 0x28d628
0x2c2794 / 0x2cc5a0 / 0x2cc8ac / 0x2d3ee8 / 0x2d40cc / 0x2d442c
0x2d45a8 / 0x2d4c60 / 0x2d4ccc / 0x2d5a80 / 0x2d6c14 / 0x2dbb1c
```

v68 总结边界：

```json
{
  "seed_count": 417,
  "reviewed_target_count": 384,
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v68 class distribution 重点：

```text
algorithm_like_unproven_ninth_level_probe: 135
factory_return_indirect_dispatch_probe: 12
unknown_indirect_dispatch_probe: 9
object_vtable_indirect_dispatch_probe: 17
caller_supplied_indirect_dispatch_probe: 3
materializer_or_raw_table_boundary_probe: 12
runtime_library_noise_lane: 24
ninth_level_unknown_or_shared_boundary: 123
lookup_copy_or_source_object_lane: 24
```

判定规则：

1. `algorithm_like_unproven_ninth_level_probe` 只代表静态窗口存在算法相似特征；没有 closed transform-to-output lane 与 strict first-seen 时，不能升级为 `X-Cylons` value 生成点。
2. factory/object-vtable/caller-supplied/unknown indirect dispatch 只作为 resolved-target scout；动态需 dump target object/vtable/GOT/global memory 与 `x0-x7`。
3. materializer/raw-table boundary 只证明地址、表或 record 物化边界；不能替代生成证据。
4. lookup/copy/source-object、runtime/container/shared helper 聚类继续保持降级，不要误写成算法本体。
5. v68 结论必须写：当前仍是接口/调用链、copy/package/consume 边界收窄；`X-Cylons` value 生成算法本体仍未完整还原。

v68 动态优先级：

```text
ninth_level_priority_probes:
0x20f5f0 / 0x20f788 / 0x28f6a8 / 0x290b80 / 0x294a80 / 0x2b8db4
0x1f95d0 / 0x1fc2a4 / 0x1fc694 / 0x1ff9c8 / 0x20c978 / 0x20e1f0
0x20e530 / 0x229588 / 0x292c7c / 0x29348c / 0x294198 / 0x2944a0
0x2945f4 / 0x294b50 / 0x2959b0 / 0x1fa908 / 0x1ff650 / 0x207ec8
0x20b664 / 0x2149a4 / 0x21a8fc / 0x228b1c / 0x228cd0 / 0x2776dc
0x278980 / 0x288dd8

producer_lookup_copy_chain:
0x329ab4 / 0x329930 / 0x32c45c / 0x1f9fc8 / 0x1ff5fc
0x329098 / 0x3296a4 / 0x3299f0 / 0x329a20 / 0x32964c / 0x329b0c

downstream_alignment:
0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
```

动态 dump 要求：entry/leave `x0-x7`、returns、resolved `blr/br` targets、target object/vtable/GOT/global memory、materializer record/table slots、producer returns、`0x1ff5fc x0/x1`、source/destination object fields、pointed buffers、downstream carry backtrace。只有 strict first-seen 证明同一 value 从无到有并被后续消费链使用时才可升级。

归档验证经验：v68 收尾应同时更新 task status JSON、project memory、daily memory、`SESSION-STATE.md` 和 mem0；检查脚本/JSON/静态 Markdown/conclusion/status/project memory 存在且非空；解析 JSON 确认 `algorithm_status=not_recovered`、`new_value_source_evidence=false`、`first_seen_evidence=false`，并确认没有残留 `static_v68` Python 进程。mem0 自部署写入若返回 `200 {"results":[]}` 可视为服务端接受，仍以本地 Markdown/JSON/SESSION 为可审计事实源。

v68 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v68_ninth_level_boundary_source_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v68_ninth_level_boundary_source_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v68_ninth_level_boundary_source_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v68_ninth_level_boundary_source_conclusion_0513.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v68_0513.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-13_project_douyin-xcylons-v68-ninth-level-boundary-source.md
```

v68 结论：本轮只完成第九层 boundary/source 静态展开、动态优先级整理和归档验证；未发现 new value-source、proven algorithm 或 first-seen。`X-Cylons` value 生成算法本体仍未完整还原。

## v69 tenth-level boundary/source expansion 归档与验证经验

当 v68 已从 v67 最高价值边界展开到第九层后，v69 可以继续从 v68 high-value algorithm-like / indirect-target / materializer/raw-ref / unknown-shared boundary 展开第十层。目标仍是静态降噪、动态 hook 排优先级和可审计归档；不能因第十层窗口复杂、bitop/helper 多、或出现 indirect/materializer 边界就升级为算法本体。

v69 总结边界：

```json
{
  "seed_count": 378,
  "reviewed_target_count": 331,
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v69 class distribution 重点：

```text
algorithm_like_unproven_tenth_level_probe: 120
object_vtable_indirect_dispatch_probe: 17
factory_return_indirect_dispatch_probe: 8
caller_supplied_indirect_dispatch_probe: 2
unknown_indirect_dispatch_probe: 4
materializer_or_raw_table_boundary_probe: 8
runtime_library_noise_lane: 20
tenth_level_unknown_or_shared_boundary: 103
lookup_copy_or_source_object_lane: 29
```

判定规则：

1. `algorithm_like_unproven_tenth_level_probe` 只代表静态窗口存在算法相似特征；没有 closed transform-to-output lane 与 strict first-seen 时，不能升级为 `X-Cylons` value 生成点。
2. object/vtable/factory-return/caller-supplied/unknown indirect dispatch 只作为 resolved-target scout；动态需 dump target object/vtable/GOT/global memory 与 `x0-x7`。
3. materializer/raw-table boundary 只证明地址、表或 record 物化边界；不能替代生成证据。
4. lookup/copy/source-object、runtime/container/shared helper 聚类继续保持降级，不要误写成算法本体。
5. v69 结论必须写：当前仍是接口/调用链、copy/package/consume 上游边界收窄；`X-Cylons` value 生成算法本体仍未完整还原。

v69 动态优先级：

```text
tenth_level_priority_probes:
0x20f5f0 / 0x20f788 / 0x288d70 / 0x28f6a8 / 0x290b80 / 0x291ed8
0x294a80 / 0x2b8db4 / 0x1f95d0 / 0x1fc2a4 / 0x1fc694 / 0x1ff9c8
0x20c978 / 0x20e1f0 / 0x20e530 / 0x20f508 / 0x229588 / 0x292c50
0x292c7c / 0x29348c / 0x29418c / 0x294198 / 0x2944a0 / 0x2945f4

producer_lookup_copy_chain:
0x329ab4 / 0x329930 / 0x32c45c / 0x1f9fc8 / 0x1ff5fc
0x329098 / 0x3296a4 / 0x3299f0 / 0x329a20 / 0x32964c / 0x329b0c

downstream_alignment:
0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
```

动态 dump 要求：entry/leave `x0-x7`、returns、resolved `blr/br` targets、target object/vtable/GOT/global memory、materializer record/table slots、producer returns、`0x1ff5fc x0/x1`、source/destination object fields、pointed buffers、downstream carry backtrace。只有 strict first-seen 证明同一 value 从无到有并被后续消费链使用时才可升级。

归档验证经验：v69 收尾应检查脚本、JSON、静态 Markdown、conclusion、task status、project memory 六类产物存在且非空；解析 JSON 确认 `algorithm_status=not_recovered`、`proven_algorithm_evidence=false`、`first_seen_evidence=false`、`reviewed_target_count == len(tenth_level_reviews)`、`len(priority_dynamic_followups)==96`、`status=completed_static`。注意 `priority_dynamic_followups` 条目的地址字段名是 `target`，不是 `addr`；验证脚本若用 `['addr']` 会触发 `KeyError`。

v69 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v69_tenth_level_boundary_source_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v69_tenth_level_boundary_source_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v69_tenth_level_boundary_source_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v69_tenth_level_boundary_source_conclusion_0513.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v69_0513.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-13_project_douyin-xcylons-v69-tenth-level-boundary-source.md
```

v69 结论：本轮只完成第十层 boundary/source 静态展开、动态优先级整理和归档验证；未发现 new value-source、proven algorithm 或 first-seen。`X-Cylons` value 生成算法本体仍未完整还原。

## v70 eleventh-level boundary/source expansion 归档与验证经验

当 v69 已从 v68 high-value 边界展开到第十层后，v70 可以继续从 v69 的 algorithm-like / indirect-target / materializer/raw-ref / unknown-shared boundary probe 展开第十一层。目标仍是静态降噪、动态 hook 排优先级和可审计归档；不能因第十一层窗口复杂、bitop/helper 多、或出现 indirect/materializer 边界就升级为算法本体。

v70 总结边界：

```json
{
  "reviewed_target_count": 309,
  "upgraded_value_source_count": 0,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v70 class distribution 重点：

```text
algorithm_like_unproven_eleventh_level_probe: 121
object_vtable_indirect_dispatch_probe: 18
factory_return_indirect_dispatch_probe: 7
caller_supplied_indirect_dispatch_probe: 2
unknown_indirect_dispatch_probe: 4
materializer_or_raw_table_boundary_probe: 9
runtime_library_noise_lane: 21
shared_helper_lane: 2
eleventh_level_unknown_or_shared_boundary: 84
shared_container_helper: 5
lookup_copy_or_source_object_lane: 25
high_fanout_shared_helper_noise: 7
parser_container_iterator_lane: 3
```

判定规则：

1. `algorithm_like_unproven_eleventh_level_probe` 只代表静态窗口存在算法相似特征；没有 closed transform-to-output lane 与 strict first-seen 时，不能升级为 `X-Cylons` value 生成点。
2. object/vtable/factory-return/caller-supplied/unknown indirect dispatch 只作为 resolved-target scout；动态需 dump target object/vtable/GOT/global memory 与 `x0-x7`。
3. materializer/raw-table boundary 只证明地址、表或 record 物化边界；不能替代生成证据。
4. lookup/copy/source-object、runtime/container/shared/high-fanout helper 聚类继续保持降级，不要误写成算法本体。
5. v70 结论必须写：当前仍是接口/调用链、copy/package/consume 上游边界收窄；`X-Cylons` value 生成算法本体仍未完整还原。

v70 动态优先级：

```text
eleventh_level_priority_probes:
0x20f284 / 0x20f5f0 / 0x20f788 / 0x222b6c / 0x288d70 / 0x28dcac
0x28f6a8 / 0x290b80 / 0x291ed8 / 0x294a80 / 0x2b8db4 / 0x1f95d0

producer_lookup_copy_chain:
0x329ab4 / 0x329930 / 0x32c45c / 0x1f9fc8 / 0x1ff5fc
0x329098 / 0x3296a4 / 0x3299f0 / 0x329a20 / 0x32964c / 0x329b0c

downstream_alignment:
0x4cf8a4 / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
```

动态 dump 要求：entry/leave `x0-x7`、returns、resolved `blr/br` targets、target object/vtable/GOT/global memory、materializer record/table slots、producer returns、`0x1ff5fc x0/x1`、source/destination object fields、pointed buffers、downstream carry backtrace。只有 strict first-seen 证明同一 value 从无到有并被后续消费链使用时才可升级。

归档验证经验：v70 收尾应检查脚本、JSON、静态 Markdown、conclusion、task status、project memory 六类产物存在且非空；解析 JSON 确认 `algorithm_status=not_recovered`、`proven_algorithm_evidence=false`、`first_seen_evidence=false`、`reviewed_target_count == len(eleventh_level_reviews)`、`len(priority_dynamic_followups)==96`、`status=completed_static`，并确认 project memory 与 conclusion 内容一致。归档层应同步更新 `SESSION-STATE.md`、daily memory 与 mem0；mem0 返回 `200 {"results":[]}` 可视为服务端接受，仍以本地 Markdown/JSON/SESSION 为可审计事实源。进程收尾需确认没有残留 `static_v70/run_v70/v70_eleventh` 分析进程；常驻 `frida-mobile-mcp` 与 adb/frida-server 不算 v70 残留。

v70 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v70_eleventh_level_boundary_source_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v70_eleventh_level_boundary_source_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v70_eleventh_level_boundary_source_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v70_eleventh_level_boundary_source_conclusion_0513.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v70_0513.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-13_project_douyin-xcylons-v70-eleventh-level-boundary-source.md
```

v70 结论：本轮只完成第十一层 boundary/source 静态展开、动态优先级整理和归档验证；未发现 new value-source、proven algorithm 或 first-seen。`X-Cylons` value 生成算法本体仍未完整还原。

## v74 fourteenth-level 静态 source/caller expansion 收尾边界

当 v73/v74 继续把 high-value priority followups 扩到第十四层后，收尾重点不是继续盲目扩大静态层级或全量 hook，而是明确归档边界并提醒下一步先提高真实直播间事件复现率。

v74 总结边界：

```json
{
  "task": "douyin_xcylons_v74",
  "analysis_type": "fourteenth_level_static_source_caller_expansion",
  "seed_count": 356,
  "reviewed_target_count": 313,
  "priority_followups": 56,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v74 已确认/保留的边界：

```text
Protocol / SSL / IM ACK/uplink chains: previously confirmed
Strong carry/package points: 0x346bcc / 0x4cff5c / 0x4cff50
Upstream propagation/context: 0x21e17c / 0x2107dc
WebSocket send chain alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
Algorithm body / value source: not_recovered
```

判定规则：

1. v74 reviewed set 仍聚类为 algorithm-like-but-unproven helpers、indirect/materializer scouts、lookup/copy/runtime/container lanes；这些都不能升级为 `X-Cylons` value 生成点。
2. 静态 algorithm-like 特征、raw refs、materializers、indirect dispatch contexts 都不足以证明算法本体；必须有 strict first-seen 或 explicit opaque/sign output evidence。
3. 下一步优先不是继续扩大 hook，而是提高目标事件复现：force-stop + early attach + confirmed live room reconnect/cut-room，确保真实 ACK/uplink、X-Cylons、目标 SSL 窗口出现。
4. 动态 hook 应只使用 v74/v73 priority probes 的小 focused set，并对齐下游 `0x4cf8a4 -> 0x1ff5fc -> 0x346b90/0x4cff50` 消费链。
5. 升级标准仍是：enter 前无 value，leave/后续 callback 后首次出现同一 `X-Cylons` value，并被下游消费链使用；或捕获明确 opaque/sign callback 输出。
6. 报告/记忆中必须写清：v74 是第十四层 source/caller 静态展开和归档验证；没有 new value-source、proven algorithm 或 first-seen，`X-Cylons` value 生成算法本体仍未完整还原。

v74 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/v74_fourteenth_level_source_caller_static_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v74_fourteenth_level_source_caller_static_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v74_fourteenth_level_source_caller_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v74_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v74-fourteenth-level-source-caller.md
```

## v75 fifteenth-level 候选扩展/降噪收尾边界

当 v74 已把 high-value priority followups 推到第十四层后，v75 可以从 v74 priority followups 继续扩一层，但重点应转为“候选扩展 + 保守降噪/降级”，而不是继续把静态层级深度当作进展本身。

v75 扩展来源：

```text
callees
caller owners
indirect target-source hints
materializer owners
body-preview edges
caller-context owners
```

v75 总结边界：

```json
{
  "task": "douyin_xcylons_v75",
  "analysis_type": "fifteenth_level_candidate_demotion_static",
  "seed_count": 503,
  "reviewed_target_count": 454,
  "priority_followups": 64,
  "demoted_helper_or_noise_lanes": 112,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v75 降级/降噪规则：

1. 反复出现的 shared string/copy/container helper、object lifetime helper、allocator/factory helper、runtime/helper lane、downstream consumer helper，应保守归类为 helper/noise/boundary，不要因为它们位于 priority followup 邻域就升级为算法体。
2. `body-preview`、caller-context、materializer owner 只能用于补充候选来源和 hook 排序；没有 closed transform-to-output lane 时，不构成 value-source 证据。
3. 静态 algorithm-like 特征、indirect dispatch、raw/materializer refs、caller owner 聚类仍然只是 probe 信号；不能替代 strict first-seen 或 explicit opaque/sign callback output。
4. 若 v75 继续没有 `enter` 前无值、`leave/downstream` 首次出现同一新 `X-Cylons` 的证据，也没有可绑定到下游消费链的 opaque/sign callback output，则必须保持 `algorithm_status=not_recovered`。
5. v75 后不建议继续盲目扩大静态层级或 hook 面；最高收益下一步是提升真实直播间动态复现质量：force-stop + early attach、确认真实直播间、触发 reconnect/cut-room/WS/ACK、确认真实 `X-Cylons`/ACK/SSL 明文窗口，再用 v75 priority 小集合 focused hook。

v75 已确认/保留边界：

```text
Protocol / SSL / IM ACK/uplink chains: previously confirmed
Strong carry/package points: 0x346bcc / 0x4cff5c / 0x4cff50
Upstream propagation/context: 0x21e17c / 0x2107dc
WebSocket send chain alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
Algorithm body / value source: not_recovered
```

v75 产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v75_fifteenth_level_candidate_demotion_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v75_fifteenth_level_candidate_demotion_static_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v75_fifteenth_level_candidate_demotion_static_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v75_fifteenth_level_candidate_demotion_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v75_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v75-fifteenth-level-candidate-demotion.md
```

v75 结论：本轮只完成第十五层候选扩展、helper/noise 降级和动态优先级整理；未发现 new value-source、proven algorithm 或 first-seen。`X-Cylons` value 生成算法本体仍未完整还原。

## v80 后转向 focused interprocedural value-flow（v81 方向）

当 v79/v80 已经把 focused hook set 固定并完成局部 source/value-lane 静态分类后，不要继续重复“单函数局部 value-lane 打分”或盲目扩大 hook 数量。v80 的有效边界是：

```text
candidate_count=30
priority_value_lane_probe_count=24
focused_value_lane_hook_set_count=36
new_value_source_evidence=false
proven_algorithm_evidence=false
first_seen_evidence=false
algorithm_status=not_recovered
```

v80 推荐 hook set 可作为 v81 输入，分为 24 个 priority probes 与 carry/context/SSL-send alignment controls。v81 应转向 focused interprocedural value-flow backtrace：

1. 从 v80 priority probes 内的 `x1/x2` value-lane store、producer/copy/downstream callsite、indirect `blr/br` 出发。
2. 对每个 value-lane 的最近定义做跨函数回溯：direct call return、indirect callback、table/materializer、buffer/object field load、bitop/transform block。
3. 对 call return 继续追一至两层 direct callee/caller；对 materializer/raw pointer refs 聚合成 table/record cluster。
4. 同时前推到已知下游消费链，检查是否形成：
   ```text
   transform block/callback output -> clean x1/x2 value -> 0x1ff5fc/copy -> 0x346b90/0x4cff50/carry -> SSL/WS send
   ```
5. 产物中必须明确区分：
   - generator/algorithm-body-like candidate；
   - copy/lookup/container/object-field source lane；
   - consumer/carry/package/alignment control；
   - unresolved indirect/materializer scout。
6. 升级标准仍保持 strict first-seen 或 explicit opaque/sign callback output。静态跨函数 value-flow 只能提升动态优先级，不能单独证明算法本体。

建议 v81 产物命名：

```text
static_v81_focused_interprocedural_value_flow_0514.py
v81_focused_interprocedural_value_flow_0514.json
v81_focused_interprocedural_value_flow_0514.md
v81_focused_interprocedural_value_flow_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v81_0514.json
```

v81 报告结论如果仍没有 clean first-seen 或 explicit opaque/sign output，必须写：接口/调用链和 value-flow 边界进一步收窄，但 `X-Cylons` value 生成算法本体仍未完整还原。

## v82 后转向 focused record-slot / producer-source slicing（v83 方向）

当 v81 focused interprocedural value-flow 与 v82 focused value-source static mining 已经把候选收敛到 `record_slot_value_source_probe_unproven` / `focused_value_source_probe_unproven`，但仍没有 strict first-seen 或 explicit opaque/sign callback output 时，不要继续盲目扩大静态层级或全量动态 hook。v83 更适合做 **focused record-slot / producer-source slicing**。

v82 典型分类统计：

```text
record_slot_value_source_probe_unproven: 20
focused_value_source_probe_unproven: 4
known_upstream_context_control_not_source: 2
known_copy_or_downstream_helper_not_source: 1
```

v82 top probe 常见地址示例：

```text
0x1fc694 / 0x224c14 / 0x229588 / 0x2610b4 / 0x21aecc / 0x21b108
0x1f95d0 / 0x2342ec / 0x234260 / 0x3266cc / 0x1fa908 / 0x1faa04
0x328d94 / 0x26cc24 / 0x26ccbc / 0x2b03d8 / 0x2b8db4 / 0x3289a4
0x26ccd8 / 0x26cd10
```

v83 静态拆解重点：

1. 对每个 focused probe 的 record/object slot write 做精细枚举：
   ```text
   +0x20 / +0x28 / +0x30 / +0x38 / +0x40 / +0x50 / +0x730
   ```
2. 对每个 slot write 的源寄存器/源对象分类：
   ```text
   caller_argument
   object_field_load
   helper_return
   stack_local
   constant_or_zero_init
   vtable_or_indirect_callback_result
   lookup_container_copy_helper_return
   ```
3. 对 helper return / indirect `blr/br` source 继续追一至两层：记录 resolved target、target object/vtable/GOT/global memory、`x0-x7` 参数、return、record slots 与 backtrace。
4. 前推同一 value 是否进入已知消费链：
   ```text
   0x1ff5fc / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc / 0x51cd50
   ```
5. 输出小而可执行的 focused hook set，分组为：
   - priority record-slot source probes；
   - indirect callback / producer scouts；
   - lookup/copy/container controls；
   - downstream carry/package alignment controls。
6. 每个候选都必须写明 positive signal 与 negative sample interpretation：
   - positive：同一干净 `X-Cylons` value 在 candidate enter 前不存在，leave/producer return/下游首次出现，并被 carry/package 或 SSL-send 链消费；或捕获明确 opaque/sign callback output。
   - negative：只有 slot store、helper return、algorithm-like static hint、raw/materializer ref、hook-ok、ready/filter 文本时，仍只能归类为 probe，不能升级。

判定边界：v82/v83 只是在 focused set 内继续细分 record-slot / producer-source / callback-source lane。除非出现 strict first-seen 或 explicit opaque/sign callback output，仍必须保持：

```json
{
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

## v84 后转向 focused caller/source-slot（v85 方向）

当 v83 focused record-slot / producer-source slicing 之后，v84 已经把候选内部的 slot-source、indirect `blr/br` producer/callback lane、direct producer-return helper lane 展开后，不要继续盲目扩大静态层级或把 `algorithm-like` 静态特征升级为算法点。v84 的有效边界是：

```text
candidate_count=18
class_distribution:
  producer_algorithm_like_probe_unproven: 13
  slot_source_expanded_probe_unproven: 2
  known_control_or_helper_not_source: 3
slot_source_class_distribution:
  unresolved_live_in: 49
  constant_or_zero_init: 38
  local_register_derived: 8
  object_or_memory_load: 2
  caller_or_local_forward: 8
indirect_target_source_class_distribution:
  object_or_memory_load: 8
  constant_or_zero_init: 35
new_value_source_evidence=false
proven_algorithm_evidence=false
first_seen_evidence=false
algorithm_status=not_recovered
```

v84 典型高优先 probe：

```text
0x229588  # producer_algorithm_like_probe_unproven, slot source lanes expanded, producer/helper callees retained as runtime probes
0x1fc694  # high-priority indirect callback/producer source scout, many stack/record slot stores
0x224c14  # callback/dispatcher/slot-source neighborhood, includes x1=x0+0x38 / x2=[x0+0x50] / br x16 pattern
```

v85 的有效切入点应是 **focused caller/source-slot static mining**，目标是追这些 v84 probes 的调用方如何准备 source slot，而不是继续只看候选函数内部：

1. 从 v84 的 `priority_slot_source_probes`、`priority_indirect_producer_scouts`、`priority_producer_return_scouts` 中取 focused seed，优先覆盖 `0x229588 / 0x1fc694 / 0x224c14` 以及同类高分项。
2. 对每个 seed 查 direct caller；若 caller 为 0，不要判死路，继续查 ADR/ADRP/LDR literal materializer、raw pointer refs、callback/table registration 与 indirect caller。
3. 在 caller 侧追调用前 `x0-x7` 来源，尤其区分：
   - caller argument / caller object field；
   - stack local；
   - helper return / producer return；
   - callback return / indirect `blr/br` target output；
   - constant_or_zero_init / known control lane。
4. 精查 source slot：
   ```text
   +0x20 / +0x28 / +0x30 / +0x38 / +0x40 / +0x48 / +0x50 / +0x730
   sp+0x20 / sp+0x38 / sp+0x40 / sp+0x48 / sp+0x50
   ```
5. 前推同一 source 是否进入已知消费链：
   ```text
   0x1ff5fc / 0x4cf8a4 / 0x346b90 / 0x346bcc / 0x4cff50 / 0x4cff5c / 0x51cd50
   ```
   但这些仍是 copy/package/consume/alignment controls，不能单独作为生成点证据。
6. 输出候选时必须分组：
   - focused caller-side source-slot probes；
   - indirect caller/materializer scouts；
   - producer-return/callback-output scouts；
   - lookup/copy/container controls；
   - downstream carry/package alignment controls。
7. 升级标准仍是 strict first-seen 或 explicit opaque/sign callback output：candidate/caller/producer enter 前无 value，leave/return/slot/callback 后首次出现同一 clean `X-Cylons` value，并被下游 carry/package/SSL/WS send 链消费。静态 caller/source-slot 证据只能提升动态优先级。

建议 v85 产物命名：

```text
static_v85_focused_caller_source_slot_0514.py
v85_focused_caller_source_slot_0514.json
v85_focused_caller_source_slot_0514.md
v85_focused_caller_source_slot_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v85_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v85-focused-caller-source-slot.md
```

v85 报告如果仍无 strict first-seen 或 explicit opaque/sign output，必须写：接口/调用链、slot-source/caller-source 边界进一步收窄，但 `X-Cylons` value 生成算法本体仍未完整还原。

## v86 focused caller/value-source 静态挖掘归档校验经验

当 v85 caller/source-slot probes 之后继续推进到 caller-owner value-source preparation 层时，v86 的目标是整理 focused caller/value-source probes 与动态 first-seen 候选，不是直接宣称算法本体已还原。

v86 典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v86_focused_caller_value_source_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v86_focused_caller_value_source_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v86_focused_caller_value_source_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v86_focused_caller_value_source_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v86_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v86-focused-caller-value-source.md
/opt/data/home/.openclaw/workspace/memory/2026-05-14.md
/opt/data/home/.openclaw/workspace/SESSION-STATE.md
```

v86 closure check：

1. 校验脚本、JSON、MD、conclusion、status、project memory、daily memory、`SESSION-STATE.md` 都存在且非空。
2. 解析主 JSON 与 status JSON，确认类似字段：
   ```json
   {
     "candidate_owner_count": 31,
     "priority_caller_value_source_probe_count": 4,
     "status": "completed_static"
   }
   ```
3. judgement/status 必须保持：
   ```json
   {
     "algorithm_status":"not_recovered",
     "new_value_source_evidence":false,
     "proven_algorithm_evidence":false,
     "first_seen_evidence":false
   }
   ```
4. conclusion、project memory、daily memory、`SESSION-STATE.md` 中必须能搜到 `v86` 与 `not_recovered` / `algorithm_status`。
5. 归档后运行：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   python3 memory/scripts/memory-sync.py search "v86 focused caller value source algorithm_status not_recovered"
   ps -ef | grep -E 'static_v86|run_v86|v86_' | grep -v grep || true
   ```
   搜索结果应命中 `2026-05-14_project_douyin-xcylons-v86-focused-caller-value-source`；进程检查应无残留 v86 分析进程。

v86 汇报边界：

- 新增价值：从 v85 caller/source-slot probes 推进到 caller-owner value-source preparation layer，识别 focused source-slot value lanes、producer-return scouts、indirect callback/vtable scouts、upstream caller argument-preparation probes。
- 不能升级为 value source：这些仍为静态/probe-level 证据；没有 closed transform-to-`X-Cylons` output lane、没有 strict first-seen、没有 explicit opaque/sign callback output。
- 当前强边界仍保持：
  ```text
  carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
  upstream propagation/context: 0x21e17c / 0x2107dc
  WebSocket/SSL send alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
  algorithm/value source: not_recovered
  ```

## v88 focused producer upstream caller-chain 静态挖掘经验

当 v87 focused set 已经把候选推进到 producer / caller / source-slot 邻域后，v88 的有效方法是做 focused producer upstream caller-chain 静态挖掘：从 producer seeds 出发，枚举 direct caller、caller-side source slot、caller argument preparation、nested helper、second-hop caller/source context 与 indirect source scout，整理小 hook set，而不是盲目继续扩大静态层级或把 algorithm-like 静态信号升级为算法本体。

v88 典型运行命令：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
PYTHONPATH=/opt/data/home/.local/lib/python3.13/site-packages \
  python3 -m py_compile static_v88_focused_producer_upstream_caller_chain_0514.py
PYTHONPATH=/opt/data/home/.local/lib/python3.13/site-packages \
  python3 static_v88_focused_producer_upstream_caller_chain_0514.py
```

v88 典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v88_focused_producer_upstream_caller_chain_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v88_focused_producer_upstream_caller_chain_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v88_focused_producer_upstream_caller_chain_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v88_focused_producer_upstream_caller_chain_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v88_0514.json
```

v88 典型摘要：

```json
{
  "seed_producer_count": 20,
  "reviewed_caller_chain_count": 47,
  "priority_producer_caller_chain_probe_count": 24,
  "hook_set_count": 49,
  "algorithm_status": "not_recovered"
}
```

典型 class distribution：

```json
{
  "producer_caller_indirect_source_scout_unproven": 1,
  "producer_caller_source_slot_probe_unproven": 15,
  "producer_caller_argument_source_probe_unproven": 12,
  "producer_caller_nested_helper_probe_unproven": 5,
  "second_hop_caller_source_context_probe_unproven": 2,
  "algorithm_like_producer_caller_probe_unproven": 5,
  "focused_producer_caller_chain_probe_unproven": 7
}
```

判定规则：

1. `producer_caller_source_slot_probe_unproven` 与 `producer_caller_argument_source_probe_unproven` 只能说明 caller 侧 source/value lane 被继续解释；没有 first-seen 时不能升级为 value source。
2. `producer_caller_indirect_source_scout_unproven`、nested helper、second-hop caller/source context 只作为动态 resolved-target / source-context scout。
3. `algorithm_like_producer_caller_probe_unproven` 只代表静态窗口存在算法相似特征；没有 closed transform-to-`X-Cylons` output lane、strict first-seen 或 explicit opaque/sign callback output 时，不能称为算法本体。
4. v88 后续动态 hook 应使用小 focused set：priority producer caller-chain probes + producer/copy chain + downstream carry/package controls。dump caller/prod `x0-x7`、producer returns、source/destination object fields、slot buffers、resolved indirect targets 与 downstream carry backtrace。
5. 归档验证时需检查 JSON/MD/conclusion/status 存在且非空，解析确认 `algorithm_status=not_recovered`、`new_value_source_evidence=false`、`proven_algorithm_evidence=false`、`first_seen_evidence=false`，再同步 memory 并检查无残留 `static_v88|run_v88|v88_` 分析进程。

v88 报告边界：本轮只完成 focused producer upstream caller-chain 静态挖掘和动态优先级整理；接口/调用链、source-slot/caller-chain 边界进一步收窄，但 `X-Cylons` value 生成算法本体仍未完整还原。

## v90 focused helper/callback target provenance 静态挖掘与收尾经验

当 v89/v90 已经把候选推进到 helper/callback target provenance 层时，v90 的有效方法是从 priority source-provenance probes 出发，继续审计非 control helper、callback target、producer-return、source-slot、indirect target 的来源与动态 first-seen 候选。该阶段仍属于 probe 收敛和动态计划整理，不是算法还原完成。

v90 典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v90_focused_helper_callback_target_provenance_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v90_focused_helper_callback_target_provenance_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v90_focused_helper_callback_target_provenance_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v90_focused_helper_callback_target_provenance_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v90_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v90-focused-helper-callback-target-provenance.md
```

v90 典型结论字段：

```json
{
  "priority_helper_callback_target_probe_count": 32,
  "v90_focused_helper_callback_hook_set_count": 57,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

判定规则：

1. helper/callback target provenance 只能说明 source/callback/producer 邻域进一步收敛；没有 strict first-seen 或 explicit opaque/sign callback output 时，不能升级为 `X-Cylons` value source。
2. 静态上看到 callback target、producer return、source-slot、algorithm-like helper、indirect target、materializer/raw ref，都只能作为动态 probe 信号。
3. v90 focused hook set 应只在真实直播间 ACK/X-Cylons/SSL 窗口已复现时运行；否则仍会得到 hook 健康但目标窗口未命中的负样本。
4. 升级标准保持不变：同一个干净 `X-Cylons` value 在 helper/callback target enter 前不存在，return/slot/indirect callback output 后首次出现，并被 `0x346bcc/0x4cff5c/0x4cff50` carry/package 或 `0x3ec4f0/0x3ec44c/0x3a6b50` SSL/WS send 链消费；或捕获明确 opaque/sign callback 输出。
5. 收尾归档必须校验 JSON/MD/conclusion/status/project memory/daily memory/SESSION 存在且非空，解析 status 确认 `algorithm_status=not_recovered`、probe/hook count 与主 JSON 一致，随后执行 memory sync 与 search 验证，并检查无残留 `static_v90|run_v90|v90_` 分析进程。

v90 汇报边界：新增价值是 helper/callback target provenance 与动态 hook set 进一步收敛；不能宣称算法已挖出。当前强边界仍保持：

```text
carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
upstream propagation/context: 0x21e17c / 0x2107dc
WebSocket/SSL send alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
algorithm/value source: not_recovered
```

## v92 规划边界：从 v91 candidate mining 转向 target-output / first-seen readiness refinement

当 v91 已完成 focused static/dynamic candidate mining，但当前目录中尚无 `*v92*` 产物时，不能把“读取/复核 v91 + 规划 v92”误报为 v92 已完成。应先明确状态：

```text
v92 artifacts: not generated yet
algorithm_status: not_recovered
```

v92 的有效方向不是继续盲目扩大静态层级，而是基于 v91 的 32 个 focused candidates 做 **focused target-output / first-seen readiness refinement**：

1. 输入以 v91 为准：
   ```text
   /opt/data/home/reverse-tools/douyin_analysis/v91_focused_static_dynamic_candidate_mining_0514.json
   /opt/data/home/reverse-tools/douyin_analysis/static_v91_focused_static_dynamic_candidate_mining_0514.py
   ```
2. 对 v91 的两类候选分别细化：
   - `resolved_indirect_callback_target_probe`：解析本地 `blr/br`、target reg、nearest defs、source slot，输出 runtime dump requirement：resolved target、callback return/output、slot before/after、backtrace。
   - `first_seen_algorithm_like_helper_probe`：审计 algorithm-like helper 是否有明确 output lane；没有 closed transform-to-`X-Cylons` 输出链时仍降级为 probe。
3. 固定 control/alignment anchors，不能误升级为算法点：
   ```text
   carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
   upstream/context: 0x21e17c / 0x2107dc
   WebSocket/SSL send alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
   ```
4. v92 hook set 应优先保留 v91 phase1 probes，再补必要 carry/package、upstream/context、SSL-send controls；对每个候选写清 `positive_signal`、`negative_sample_interpretation`、`upgrade_rule`、`upgrade_to_value_source=false`。
5. v92 默认 judgement 仍应保持：
   ```json
   {
     "new_value_source_evidence": false,
     "proven_algorithm_evidence": false,
     "first_seen_evidence": false,
     "algorithm_status": "not_recovered"
   }
   ```
   除非静态/动态证据真的出现 closed transform-to-`X-Cylons` output lane、strict first-seen，或 explicit opaque/sign callback output。
6. 若工具调用上限或中断只完成到“v91 复核 + v92 规划”，最终回复必须明确：`v92 artifacts not generated yet`，并保持 todo 为 `t2 in_progress / t3 pending`，不能暗示 v92 已生成或归档。

建议 v92 产物命名：

```text
static_v92_focused_target_output_firstseen_readiness_0514.py
v92_focused_target_output_firstseen_readiness_0514.json
v92_focused_target_output_firstseen_readiness_0514.md
v92_focused_target_output_firstseen_readiness_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v92_0514.json
```

## v95 规划边界：从 v94 upstream source-lane 转向 callback-output owner 静态挖掘

当 v94 已完成 upstream callback-output/source-slot source-lane 静态分类，但当前目录中尚无 `*v95*` 产物时，不能把“读取/复核 v94 + 规划 v95”误报为 v95 已完成。应明确状态：

```text
v95 artifacts: not generated yet
algorithm_status: not_recovered
```

v95 的有效方向是基于 v94 focused hook set / owner probes 做 **upstream source-lane / callback-output owner static mining**，目标是把 callback-output source、source-slot provenance、owner/caller preparation 再上推一层，生成更小、更明确的动态 first-seen 候选集合，而不是扩大静态层级或宣称算法还原。

建议输入：

```text
/opt/data/home/reverse-tools/douyin_analysis/v94_focused_upstream_callback_output_source_static_0514.json
/opt/data/home/reverse-tools/douyin_analysis/static_v94_focused_upstream_callback_output_source_0514.py
```

建议产物命名：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v95_upstream_source_lane_callback_output_owner_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v95_upstream_source_lane_callback_output_owner_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v95_upstream_source_lane_callback_output_owner_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v95_upstream_source_lane_callback_output_owner_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v95_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v95-upstream-source-lane-callback-output-owner.md
```

v95 输出应保留并强调这些 alignment/control anchors，不得升级为算法点：

```text
carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
upstream/context: 0x21e17c / 0x2107dc
WebSocket/SSL send alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
```

默认 judgement 仍应保持：

```json
{
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

除非静态/动态证据真的出现 closed transform-to-`X-Cylons` output lane、strict first-seen，或 explicit opaque/sign callback output。

如果工具调用上限或中断只完成到“v94 复核 + v95 规划”，最终回复必须明确：`v95 artifacts not generated yet`，并保持 todo 为 `t2 in_progress / t3 pending`，不能暗示 v95 已生成、已验证或已归档。

## 输出要求

报告中必须明确区分：

- 接口/调用链、copy/package/consume 进展；
- `X-Cylons` value 生成算法本体是否已还原。

若只证明了 wrapper/thunk/helper/lookup/container-index/copy lane，应写明“算法本体 / value 生成点仍未完整还原”。
