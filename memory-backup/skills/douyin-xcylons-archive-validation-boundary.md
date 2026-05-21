---
name: douyin-xcylons-archive-validation-boundary
description: 抖音 X-Cylons 每轮静态/动态挖掘后的归档验证收尾 gate：py_compile、JSON、memory-sync、残留进程与算法边界汇报
tags: ["douyin", "x-cylons", "archive", "validation", "reverse-engineering"]
---

# Douyin X-Cylons 归档验证与算法边界汇报

## 适用场景

当用户要求“验证 JSON/py_compile/memory-sync/残留进程，并汇报算法边界”、或每轮 vXXX 静态/动态挖掘产物已生成后使用。该 skill 专注收尾 gate，补充 `douyin-xcylons-stage-iteration-static-analysis`。

## 固定验证 gate

1. 对本轮脚本执行：
   ```bash
   python3 -m py_compile <script.py>
   ```
2. 对本轮 JSON 产物分别执行：
   ```bash
   python3 -m json.tool <static.json> >/tmp/<version>_static.json
   python3 -m json.tool <matrix.json> >/tmp/<version>_matrix.json
   python3 -m json.tool <status.json> >/tmp/<version>_status.json
   ```
3. 检查 conclusion markdown 非空，并确认包含 algorithm boundary / promotion boundary。
4. 将本轮摘要追加到：
   - `/opt/data/home/.openclaw/workspace/memory/daily/YYYY-MM-DD.md`
   - `/opt/data/home/.openclaw/workspace/SESSION-STATE.md`
5. 摘要必须写明：
   - `algorithm_status`
   - `dynamic_execution_performed`
   - `strict_evidence_event_count`
   - 是否有真实动态 IO / header carry
   - 下一步 gate
6. 在 workspace 下运行记忆同步：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   python3 memory/scripts/memory-sync.py search '<version> <phase> <key-addresses> algorithm_status'
   ```
   只有 search 命中本轮 project memory 才设置 `memory_search_<version>_hit=true`。
7. 检查残留进程：
   ```bash
   ps -ef | grep -E '<version>|<script-key>|frida.*aweme' | grep -v grep || true
   ```
   无输出才设置 `no_residual_process=true`。
8. 回写 status `validation` 字段；最后再次 `json.tool` 校验 status。

## 汇报算法边界的标准措辞

必须把“接口/调用链/静态 primitive 收窄”和“算法本体完整还原”分开说。

如果只完成静态 primitive family 绑定，例如 AES/SM4 表族、round family、leaf/wrapper 候选，但缺少以下证据，则必须保持：

- `algorithm_status=not_recovered`
- `pure_reproduction_ready=false`

未满足的证据通常包括：

- 真实 LivePlayActivity/webcast 前台运行；
- same-thread wrapper → leaf → terminal IO；
- terminal bytes 到 X-Cylons/security-header carry；
- key schedule / round-key buffer；
- IV / chaining mode；
- padding 与 encrypt/decrypt direction；
- negative controls；
- heldout replay。

不要因为 AES/SM4 等 primitive family 命中就宣称 X-Cylons 算法已完整恢复。

## v254 示例

v254 收尾时的边界为：

`static_aes_ttable_family_bound_but_mode_key_iv_padding_unproven`

已证明：`0x26e0`、`0x7144`、`0x780c` 分别绑定到 AES Te/Td 表族；`0x2a70`、`0x7bc4`、`0x7c94` 是 mode/wrapper 静态候选。

未证明：真实动态 IO、key schedule、IV/chaining、padding/direction、`0x2bd8` terminal bytes 到 X-Cylons/security-header carry、negative controls、heldout replay。因此仍是 `not_recovered`。
