---
name: douyin-xcylons-aes-wrapper-static-deepening
description: 抖音 X-Cylons 在 AES T-table primitive 已绑定后，继续静态深化 key schedule / mode / IV / padding 的流程
tags: ["douyin", "x-cylons", "aes", "static-analysis", "reverse-engineering"]
---

# Douyin X-Cylons AES wrapper static deepening

## 适用场景

当上一轮已经把 terminal leaf 绑定到 AES T-table / Te / Td primitive family，但还缺 key schedule、mode、IV/chaining、padding、terminal carry 时使用。典型阶段：v254 → v255。

## 流程

1. 解析 `libEncryptor.so` ELF section，建立 VA→file offset 映射；用 Capstone 反汇编 `.text` / `.mytext`。不要只依赖符号表或 imports。
2. 围绕 primitive leaf wrapper 建 watch set：
   - forward AES leaf / inverse AES leaf；
   - encrypt/decrypt wrapper；
   - key setup helper；
   - xor helper；
   - memcpy/memset import thunk 候选。
3. key schedule 静态特征：
   - key-size constants：`0x10 / 0x18 / 0x20`；
   - bit-length constants：`0x80 / 0xc0 / 0x100`；
   - round-count-like constants：`10 / 12 / 14`；
   - context metadata offsets，例如 `+0x1e0`、`+0xf0`；
   - S-box/T-table/Rcon-like table windows；
   - `rev` endian transform 与 xor-chain schedule word 写入。
4. mode / padding 静态特征：
   - `input_len & 0xf`；
   - `0x10 - residual`；
   - residual copy + fill final block；
   - last-byte unpad check `(pad - 1) <= 0xf`；
   - always emits final padded block → PKCS#7-style padding candidate。
5. CBC-like chaining 静态特征：
   - 16-byte xor helper 出现在 forward leaf 前；
   - helper 内有 bytewise `ldrb/eor/strb` 或等价模式；
   - 只能称为 CBC-like candidate，IV / previous ciphertext concrete value 必须动态验证。
6. 产物必须包含：
   - static JSON；
   - matrix JSON；
   - conclusion markdown；
   - status JSON；
   - project memory；
   - dynamic validation packs。
7. dynamic validation packs 应覆盖：
   - key bytes/source；
   - round-key context digest before/after；
   - xor helper x0/x1 16-byte buffers；
   - wrapper input/output/len；
   - same-thread carry 到 `0x2bd8` terminal bytes；
   - terminal bytes 到 X-Cylons/security header carry；
   - heldout replay；
   - negative controls。

## 边界措辞

静态阶段只能说：

- AES primitive 已绑定；
- AES key schedule candidates 已静态收窄；
- PKCS#7-style padding / unpad candidates 已静态收窄；
- CBC-like xor-before-encrypt candidate 已静态收窄。

不能说 X-Cylons 算法已恢复，除非已有真实动态 IO、key source、IV/chaining concrete value、terminal carry、header carry、heldout replay 与 negative controls。

推荐 status 字段：

- `algorithm_status=not_recovered`
- `dynamic_execution_performed=false`
- `strict_evidence_event_count=0`
- `pure_reproduction_ready=false`
- `algorithm_boundary_status=static_aes_key_schedule_mode_padding_hypothesized_but_key_source_iv_terminal_carry_unproven`

## 验证 gate

沿用 `douyin-xcylons-archive-validation-boundary`：

1. `python3 -m py_compile <script.py>`
2. `python3 -m json.tool <static.json>` / `<matrix.json>` / `<status.json>`
3. conclusion markdown 非空并包含 promotion boundary
4. 写 daily memory、project memory、SESSION-STATE
5. `memory/scripts/memory-sync.py sync`
6. `memory/scripts/memory-sync.py search '<version> key-schedule mode padding algorithm_status'`
7. 检查无 `static_vXX|run_vXX|vXX_|frida.*aweme` 残留进程
