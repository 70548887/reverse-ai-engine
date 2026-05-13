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

## 复用产物

可参考/复用上一轮 v33/v34/v35/v36/v37 产物：

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

## 输出要求

报告中必须明确区分：

- 接口/调用链、copy/package/consume 进展；
- `X-Cylons` value 生成算法本体是否已还原。

若只证明了 wrapper/thunk 是转发链，应写明“算法本体 / value 生成点仍未完整还原”。
