---
name: douyin-dynamic-sampling-archival
description: 抖音 X-Cylons 动态采样后，保守判定算法边界并归档 status/project memory/SESSION-STATE 的复用流程
triggers: ["抖音动态采样归档", "X-Cylons algorithm_status", "v161/v169/v172/v173", "strict_evidence_event_count", "LivePlayActivity gate passed"]
---

# Douyin Dynamic Sampling Archival

用于抖音直播 X-Cylons 动态采样已经执行后的收尾：分析 raw/analyzer 日志、保守判定算法是否恢复、同步归档状态与记忆。

## 适用场景

- v169/v172 gate watcher 已证明真实 `LivePlayActivity` 前台稳定。
- v161/focused Frida runner 已实际执行，产出 jsonl 与 analyzer JSON。
- 需要回答“算法是否已经完整挖出”，并把结论写入 `tasks/status`、`memory/projects`、`SESSION-STATE.md`。

## 判定原则

1. gate 通过 + hook 安装成功 ≠ 算法恢复。
2. representation/correlation 命中（例如 `x-tt-e-`、`reprctx_count>0`、`hook_ok>0`、`hook_err=0`）只能说明候选收敛。
3. 只有出现严格证据链时才升级算法状态：
   - 同一 request/thread/window 内 `absent-before` / `first-after` / `downstream-carry` 全门控；或
   - 能与 `X-Cylons` / ACK / SSL 明文 / WS carry 对齐的 clean value-source；或
   - 闭合 opaque/sign callback / transform body。
4. 若 `all_gate_true_event_count=0` 或 `strict_evidence_event_count=0`，必须保守写：
   - `algorithm_status=not_recovered`
   - `first_seen_evidence=false`
   - `new_value_source_evidence=false`
   - `proven_algorithm_evidence=false`

## 归档步骤

1. 读取 analyzer JSON 和已有 status JSON。
2. 抽取并写回关键字段：
   - `dynamic_execution_performed`
   - `gate_status`
   - `delegated_groups`
   - `reprctx_count`
   - `hook_ok_count` / `hook_err_count`
   - `representation_event_count` / `downstream_event_count` / `value_event_count`
   - `same_window_candidate_count`
   - `all_gate_true_event_count`
   - `strict_evidence_event_count`
   - `first_seen_evidence` / `new_value_source_evidence` / `proven_algorithm_evidence`
   - `algorithm_status`
3. 写入 `tasks/status/douyin_xcylons_v*_*.json`，并加 `status=completed`、`*_archived=true`。
4. 写入 `memory/projects/YYYY-MM-DD_project_douyin-xcylons-v*-dynamic-sampling-analysis.md`：
   - 结论
   - 关键计数
   - 算法边界
   - 下一步
5. 在 `SESSION-STATE.md` 追加一行 compact 摘要。
6. 执行并验证：
   ```bash
   python3 -m json.tool tasks/status/douyin_xcylons_v*_*.json >/tmp/status.json
   python3 memory/scripts/memory-sync.py sync
   ```

## v173/v174/v175/v176 踩坑

### v184 Cronet/BoringSSL stripped non-export neighbor sweep 归档

当 v183 已确认 `libsscronet.so` / `libttboringssl.so` exports/symbols 基本不可用，下一轮改为围绕 v183 已观测 PC/offset 做 stripped non-export neighbor sweep（例如 v184），应归档为“focused gate + 非导出邻域探测负样本/候选验证”，不要因为 `hook_ok_count>0` 或 active trigger 已执行就写成 plaintext/header/value-source 或算法恢复。

关键经验：

- `focused live-room gate passed` + `dynamic_execution_performed=true` + `hook_ok_count=60/96` 只说明真实直播间条件下非导出邻域 hook 部分安装成功；如果 `nonexport_event_count=0`、`same_window_candidate_count=0`、`strict_evidence_event_count=0`，必须保守写 `algorithm_status=not_recovered`。
- `hook_err_count` 较高（例如 36/96）常见于 stripped/native 邻域盲扫，不应单独视为失败；关键看是否有明文/value/carry 事件与 strict evidence，而不是安装率。
- 若邻域 sweep 捕获不到事件，下一步不要继续只扩大 v183 neighbor PC；应转向静态反汇编 stripped `libsscronet.so` / `libttboringssl.so` 的 callsite/vtable/HTTP2/QUIC 路径，或上移 hook Java/Cronet/TTNet request/header builder，在进入 native transport 前捕获 header/value-source。
- 归档验证时，`memory-sync.py search` 可能因 Douyin 历史阶段太多导致精确 slug 只在 Top5 命中；只要 sync 列表包含本轮 project memory，且本地文件 grep 到 `algorithm_status=not_recovered`，可视为归档可检索。
- mem0 写入如果超时且工具提示 `Do NOT retry this command`，不要阻塞收尾；以本地 status/project memory/SESSION + memory-sync 搜索命中作为可审计事实源，并在最终报告中注明 mem0 超时。

归档字段建议：

- `real_live_room_gate_passed` / `gate_passed`
- `dynamic_execution_performed=true`
- `hook_target_count`
- `hook_ok_count` / `hook_err_count`
- `nonexport_event_count`
- `same_window_candidate_count`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `next_step=static disassemble stripped Cronet/BoringSSL callsites/vtables or hook higher-level Cronet/TTNet request/header builders`

### v183 Cronet/BoringSSL module/symbol enum 归档

当一轮在真实 `LivePlayActivity` focused gate 下，尝试枚举 Cronet/BoringSSL/QUIC 相关模块、exports、symbols，并补充 SSL/BIO/internal plaintext hook（例如 v183），应归档为“focused gate + 模块枚举/候选 hook 验证”，不要因为 attach 成功或模块列表完整就写成 SSL/ACK/X-Cylons carry 或算法恢复。

关键经验：

- `Module.enumerateExports()` / symbol 枚举在 `libsscronet.so`、`libttboringssl.so`、`libttquic.so` 等 stripped/hidden 场景可能全部返回 0；这只能说明 export/symbol 路径不可用，不能说明不存在 plaintext/header/write 逻辑。
- `v*-ssl-ready installed=0` 与 `v*-symbol-ready installed=0` 时，后续应转向静态 offset/callsite 扫描，或 hook libc `send/sendto/write/writev/connect` 与 Java Cronet/TTNet request/header builder，而不是继续扩大同一 export/symbol pattern。
- Java guard 修复后，native-only attach context 下若记录 `v*-java-trigger-skip`，这是预期降级，不是 hook 安装失败；但也不能把它计作 Java trigger 成功。
- 如果 raw log 有 `v*-runner-done`、candidate events、ADB triggers，但 analyzer 因缺少 `v*-finish` 把 `dynamic_execution_performed=false`，归档时要在 `runtime_notes` 中说明“runner finish 缺失导致 analyzer flag 偏保守”，并同时保留 raw evidence counts；不要只看单一 dynamic flag。
- `hook_ok_count>0` + `candidate_event_count>0` + `module_detail_count>0` 仍只是候选执行/枚举证据；若 `ssl_event_count=0`、`same_window_carry_candidate_count=0`、`strict_evidence_event_count=0`，必须保守写 `algorithm_status=not_recovered`。

归档字段建议：

- `real_live_room_gate_passed`
- `stable_live_room_proof_count`
- `java_guard_fixed`
- `java_trigger_skipped_in_native_context`
- `module_enum_performed`
- `module_detail_count`
- `symbol_ready_count`
- `hook_ok_count` / `hook_err_count`
- `candidate_event_count`
- `ssl_event_count`
- `same_window_carry_candidate_count`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`

### v181 focused gate direct-v175 bypass 归档

当一轮复用 v180 focused blocker/live-room proof，但绕过 v178/v177 这类旧版 broad blocker，直接委派 v175 focused SSL/WS/X-Cylons pack 时，应归档为“focused gate 已可放行 + 下游 focused pack 已执行/候选收敛”，但仍不能写成算法恢复。

关键经验：

- 如果最新 runner 自己的 gate 已给出真实直播间 proof（如 `stable_live_room_proof_count>0`、`gate_passed_by_v181=true`），而 delegated 旧脚本日志里仍出现 `hard_blockers=["dozing"]` 等宽匹配结果，要明确标记为 `v178_broad_blocker_bypassed=true` 或同类字段，避免把旧脚本 blocker 反向覆盖最新 gate 结论。
- 直接委派旧 focused pack 后，要分开统计：`delegated_execution_event_count`、`hook_ok_count/hook_err_count`、`candidate_event_count`、`ssl_event_count`、`same_window_carry_candidate_count`、`strict_evidence_event_count`。
- `hook_ok_count>0` 且 `candidate_event_count>0` 只说明 focused pack 安装成功并捕到候选事件；若 `ssl_event_count=0`、`same_window_carry_candidate_count=0`、`strict_evidence_event_count=0`，仍必须保守写 `algorithm_status=not_recovered`。
- 下一步应优先把 v180/v181 focused gate 下沉到 v175 focused pack 的 preflight，而不是继续扩大 gate 规则；同时增强 `libsscronet` / `libttboringssl` hook 点，目标先让 `ssl_event_count>0`，并通过真实直播间主动操作让 `/webcast/*`、`/ws/v2`、`X-Cylons` 与 SSL 明文同窗出现。

建议字段：

- `gate_passed_by_v181`
- `v178_broad_blocker_bypassed`
- `focused_v175_delegated`
- `dynamic_execution_performed`
- `stable_live_room_proof_count`
- `delegated_execution_event_count`
- `hook_ok_count` / `hook_err_count`
- `candidate_event_count`
- `ssl_event_count`
- `same_window_carry_candidate_count`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`

### v180 full XML preview click / focused blocker gate 归档

当一轮解决的是 live-preview UI 入口自动点击与 blocker/rootcause gate 推进（例如 v180：从设备 pull 全量 UIAutomator XML，识别 `点击进入直播间`/`进入直播间` 的 bounds 并点击；将 Keyguard/Permission/Login 从 dumpsys 宽匹配改为聚焦硬阻断），应归档为“UI/gate 自动化推进 + live-room proof/delegation readiness”，不要误写为 X-Cylons 算法恢复。

关键经验：

- `uiautomator dump | head` 会截断 XML，可能漏掉 `点击进入直播间` 节点；应 `adb pull /sdcard/window_*.xml` 后读取完整 XML。
- Permission hard blocker 只能在当前 focus/resumed component 为 `PermissionController`，或可见 XML 明确有 `允许`/`权限申请`/`权限管理` 等弹窗文本时成立；不要因 manifest/metadata/dumpsys 中出现 Permission 字符串就阻断。
- Keyguard/NotificationShade 也必须基于 visible/focus/showing 状态判定，不能把 `KeyguardDisable Token Info`、StatusBar 常驻窗口等元数据当硬阻断。
- Preview click 必须要求明确 `bounds`，并优先选择可点击、屏幕中部、尺寸足够的节点（例如 content-desc=`点击进入直播间按钮`），避免点到底部导航或 tiny TextView。
- `preview_entry_clicked=true`、`stable_live_room_proof_count>0`、`delegated_execution_event_count>0` 只说明 UI/gate 推进成功；若 `strict_evidence_event_count=0`，仍必须保守写 `algorithm_status=not_recovered`。
- 如果 v180 gate 通过后委派旧版 v178/v177，但旧脚本又因 broad blocker 误判拒绝，应把 v180 focused blocker 逻辑下沉到下游脚本，或直接委派 focused SSL/WS/X-Cylons pack。

归档字段建议：

- `preview_entry_sample_count`
- `preview_entry_click_event_count`
- `preview_entry_clicked`
- `live_preview_hint_count`
- `ui_real_room_hint_count`
- `process_live_hint_count`
- `live_ready_sample_count`
- `stable_ready_streak_max`
- `stable_live_room_proof_count`
- `operator_handoff_required_count`
- `delegated_execution_event_count`
- `dynamic_execution_performed`
- `last_hard_blockers`
- `last_rootcause_hypotheses`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`

归档时创建/验证：runner、analyzer、raw log、analysis JSON、static JSON/MD、conclusion MD、`tasks/status/douyin_xcylons_v*_YYYYMMDD.json`、`memory/projects/YYYY-MM-DD_project_douyin-xcylons-v*-full-xml-preview-click.md`，并向 `SESSION-STATE.md` 追加 compact 摘要后执行 `memory-sync.py sync` 与 search 验证。

### v178 UI recovery / static progress 归档

当一轮只推进 UI recovery、screenshot、UIAutomator/gate telemetry、safe delegation readiness，并完成 `py_compile`、static/matrix/analysis JSON 校验、dry-run/analyzer 验证（例如 v178），但仍未拿到稳定真实直播间 `LivePlayActivity/webcast` 前台证据、没有 focused SSL/WS/X-Cylons carry 日志、没有 delegated execution 事件时，应按“UI recovery / blocker readiness 静态推进”归档，而不是按“动态采样已执行”或“算法恢复”归档。

归档要点：

- status JSON 建议命名为 `tasks/status/douyin_xcylons_v*_YYYYMMDD.json`，并记录验证标记（如 `V*_VALIDATION_OK`）与产物路径。
- `validation` 字段至少包含：`py_compile_ok`、static/matrix/analysis JSON 校验结果、`dry_run_ok`、`analyzer_ok`、`stable_live_room_proof_count`、`dynamic_execution_performed`、`delegated_execution_event_count`、`strict_evidence_event_count`、`latest_blockers` / `last_hard_blockers`。
- 若 blocker 仍包含 `keyguard`、`login_or_account`、`notification_shade`、`permission`、`splash`、`statusbar_shade` 等，project memory 和 SESSION-STATE 必须明确写为 operator/UI 阻断，不是算法证据。
- 若 `stable_live_room_proof_count=0`、`dynamic_execution_performed=false` 或 `delegated_execution_event_count=0`，必须保守写：
  - `algorithm_status=not_recovered`
  - `first_seen_evidence=false`
  - `new_value_source_evidence=false`
  - `proven_algorithm_evidence=false`
  - `strict_evidence_event_count=0`
- 汇报时明确区分：UI recovery / screenshot / UIAutomator / gate telemetry 可用，只表示后续真实直播间执行准备度提升；没有 X-Cylons value-source、first-seen、ACK、SSL 或 WS carry 证据。
- 下一步命令应指向真实设备手动解锁、收起通知栏/状态栏、处理权限/登录、进入直播间后运行对应 `run_v*_ui_recovery_static_progress_*.py --watch --execute --try-recover --screenshot ...`，随后用 analyzer 分析真实 jsonl 日志。

### v176 focused gate/blocker telemetry dry-run 归档

当一轮只完成 gate/blocker telemetry + safe delegation 产物生成、`py_compile`、dry-run 和 analyzer 验证（例如 v176），但没有进入稳定真实直播间、也没有 delegated execution 事件时，应按“gate/blocker readiness / blocker proof”归档，而不是按“动态采样已执行”归档。

归档要点：

- 读取 static JSON 与 analyzer JSON，合并写入 `tasks/status/douyin_xcylons_v*_*.json`。
- `validation` 字段至少包含：`py_compile_ok`、`dry_run_ok`、`gate_sample_count`、`live_ready_sample_count`、`stable_live_room_proof_count`、`operator_handoff_required_count`、`dynamic_execution_performed`、`delegated_execution_event_count`、`last_hard_blockers`、`last_live_entry_ready`。
- `counts` 字段保留 `event_count`、`bad_line_count`、`v*_strict_evidence_event_count`、`blocker_counts`。
- 若 analyzer 显示 `stable_live_room_proof_count=0` 或 `delegated_execution_event_count=0`，必须保守写：
  - `dynamic_execution_performed=false`
  - `strict_evidence_event_count=0`
  - `algorithm_status=not_recovered`
  - `first_seen_evidence=false`
  - `new_value_source_evidence=false`
  - `proven_algorithm_evidence=false`
- project memory 中明确区分：runner/analyzer/dry-run 成功只是 safe-delegation 层可用；Splash/notification/keyguard blockers、进程存在、gate sample 或 hook 模板存在都不是 X-Cylons value-source 或算法恢复证据。
- 写入 `SESSION-STATE.md` 一行 compact 摘要后，执行：
  ```bash
  python3 -m json.tool /opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v*_*.json >/tmp/status.json
  python3 /opt/data/home/.openclaw/workspace/memory/scripts/memory-sync.py sync
  ```

### v175 gate watcher dry-run 归档

如果只完成了 runner/analyzer/gate-watcher 包生成与 `py_compile` / dry-run 验证，但 live gate 没过（例如前台仍是 `com.ss.android.ugc.aweme/.splash.SplashActivity`、`hard_blockers=["splash"]`），必须把它归档为“执行链路准备完成 / 动态采样未执行”，而不是动态采样结果。

状态字段应保守写：

- `dynamic_execution_performed=false`
- `gate_live_entry_ready=false`
- `last_hard_blockers=["splash"]`（或实际 blocker）
- `hook_ok_count=0` / `candidate_event_count=0` / `ssl_event_count=0`（如果 analyzer 只读 dry-run gate 日志）
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`

汇报时明确说：这轮是 package/analyzer/gate-watcher readiness 与 blocker proof，不是 focused Frida 真实直播间采样；不能把 Splash 前台、进程存在、dry-run 成功或 hook 模板存在误判为算法本体恢复。下一步必须由操作员解锁/退出 Splash/进入真实 `LivePlayActivity` 后再运行 `run_v*_gate_watcher_autoexec.py --watch --execute ...`。

### v174 narrow_with_downstream_neighbors 判定

v174 这类 `narrow_with_downstream_neighbors` 动态采样可能出现：`reprctx_count>0`、`same_window_candidate_count>0`、局部 downstream/value 共现，甚至候选窗口里有 `downstream_carry_ok=true`。但只要 `absent_before_ok=false` 或 `first_after_ok=false`，且 `all_gate_true_event_count=0` / `strict_evidence_event_count=0`，仍必须保守判定为：

- `algorithm_status=not_recovered`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`

汇报时明确说“same-window / downstream 共现只是候选收敛，不是 first-after/downstream-carry 全门控严格证据”；除非同时拿到 X-Cylons/ACK/SSL/WS carry 对齐的 clean value-source 或闭合 transform body，否则不能升级为算法恢复。

### analyzer logs 字段类型

analyzer JSON 的 `logs` 字段可能不是字符串路径列表，而是 dict 列表。归档脚本中不要直接 `Path(item)`；先按 `path` / `file` / `log` / `name` 字段规范化，否则会触发：

```text
TypeError: argument should be a str or an os.PathLike object ... not 'dict'
```

安全写法：

```python
log_names = []
for item in analysis.get('logs', []):
    if isinstance(item, str):
        log_names.append(Path(item).name)
    elif isinstance(item, dict):
        for key in ('path', 'file', 'log', 'name'):
            if item.get(key):
                log_names.append(Path(str(item[key])).name)
                break
        else:
            log_names.append(json.dumps(item, ensure_ascii=False)[:120])
```

### v192 full-XML live-tab entry / stale SplashActivity gate 验证归档

当一轮通过全量 UIAutomator XML 识别顶部 `直播` tab / preview node 并实际点击，后续 XML 已出现真实直播间文本（如 `说点什么...`、`礼物`、`欢迎来到直播间`、`live_activity_hint=true`），但 dumpsys 仍残留 `.splash.SplashActivity` 导致 gate 记录 `splash_focused` 并拒绝委派下游 hook pack 时，应归档为“UI/gate entry progressed but stale-splash gate bug blocked delegation”，不是算法恢复。

关键经验：

- 不要只看 dumpsys focus/resumed component；Douyin 可能在 XML 已经是直播间 UI 时仍暴露 stale `.splash.SplashActivity`，导致硬阻断误杀。
- 如果 XML 非空且 package 为 `com.ss.android.ugc.aweme`，并满足 `live_room_hint_count>=2` 或 `live_activity_hint=true`，下一版 gate（如 v193）应把 stale `splash_focused` 降级为 soft blocker，允许委派 focused minimal hook pack。
- `v*_tap_count>0`、`live_tab_candidate_count>0`、`preview_candidate_count>0`、XML 中出现直播间文本，只能说明 UI/entry/gate 层推进；若 `delegate_command_count=0`、`dynamic_execution_performed=false`、`strict_evidence_event_count=0`，必须保守写 `algorithm_status=not_recovered`。
- 验证收尾应覆盖：`py_compile`、matrix/static/status/dry-run/execute-analysis JSON `json.tool`、`memory-sync.py sync`、`SESSION-STATE.md` 追加、残留进程检查（`run_v192|run_v191|v189|v190|frida.*aweme`）。
- 归档时把 bug/rootcause 明确写入 status/project memory：`focused_state still treats dumpsys .splash.SplashActivity as hard splash_focused even when XML/live_activity hints show live-room UI; v193 should downgrade stale splash`。

建议字段：

- `v*_gate_sample_count`
- `v*_main_feed_hint_count`
- `v*_live_tab_candidate_count`
- `v*_preview_candidate_count`
- `v*_tap_count`
- `v*_live_ready_sample_count=0`（若被 stale splash 阻断）
- `blocker_counts.splash_focused`
- `soft_blocker_counts.splash_dumpsys_but_main_feed_xml`
- `delegate_command_count=0`
- `dynamic_execution_performed=false`
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `next_step=stale-splash downgrade/live-room proof gate then delegate focused minimal hook pack`

### v193 stale SplashActivity downgrade / live-room proof delegation 归档

当一轮修复 v192 发现的 stale `.splash.SplashActivity` 硬阻断问题：dumpsys 仍残留 SplashActivity，但全量 UIAutomator XML 已证明真实直播间（如 `说点什么...`、`礼物`、`live_activity_hint=true`、`live_room_hint_count>=2`），并把 `splash_focused` 降级为 soft blocker 后成功委派 v190/v189 minimal，应归档为“live-room proof gate/delegation progressed”，不是算法恢复。

关键经验：

- gate 判定不要只看 dumpsys focus/resumed；如果 XML 非空、package 是 `com.ss.android.ugc.aweme`，且满足 `live_room_hint_count>=2` 或 `live_activity_hint=true`，可以把 `splash_focused` 作为 `splash_dumpsys_but_live_room_xml` soft blocker，允许下游 focused minimal hook pack。
- v193 live verify 的成功指标是 `v193_ready_sample_count>0`、`v193_live_xml_proof_count>0`、`v193_stale_splash_downgraded_count>0`、`v193_delegate_command_count>0`、delegate returncode=0；这些只证明 gate/delegation 修复。
- 如果嵌套 v189 已通过真实 `LivePlayActivity` proof 但出现 `v189-init-error: Java unavailable`，应明确归档为 attach/Frida Java availability 问题；不要把 delegate returncode=0 或 gate pass 写成 hook 成功。
- 若 `hook_ok_count=0`、`java_event_count=0`、`ssl_event_count=0`、`header_or_xcylons_event_count=0`、`strict_evidence_event_count=0`，必须保守写 `algorithm_status=not_recovered`。
- 归档验证除 JSON/py_compile/memory-sync 外，还要执行残留进程检查：`ps -ef | grep -E 'run_v193|run_v192|run_v191|run_v190|run_v189|frida.*aweme|frida-server' | grep -v grep || true`。
- 下一步不应继续扩大 gate；应优先修复当前设备 Frida Java availability/attach context。Java 仍不可用时，再转 native Cronet/TTNet/libc send/write hooks 或静态更高层 request/header builder。

建议字段：

- `v193_ready_sample_count`
- `v193_live_xml_proof_count`
- `v193_live_activity_hint_count`
- `v193_live_room_hint_ge2_count`
- `v193_stale_splash_downgraded_count`
- `raw_blocker_counts.splash_focused`
- `soft_blocker_counts.splash_dumpsys_but_live_room_xml`
- `delegate_command_count` / `delegate_result_count`
- `delegated_logs` / `nested_delegated_logs`
- `dynamic_execution_performed=true` only if nested logs show runner actually attempted attach/execution; still separate from strict algorithm evidence
- `v189_init_error=Java unavailable` when present
- `hook_ok_count=0`
- `java_event_count=0`
- `ssl_event_count=0`
- `header_or_xcylons_event_count=0`
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`

### v190 precise-callsite live sequence wrapper 验证/归档

当一轮把上一版 focused Java hook packs 包装成 live-gated sequence runner（例如 v190 包装 v189 precise callsite packs，提供 `minimal` / `narrow` / `all` sequence）但只完成 package 生成、dry-run、analyzer 和 memory-sync 验证时，应归档为“live-gated execution sequence package ready”，不是算法恢复。

关键经验：

- v190 这类 wrapper 的价值是把已有 packs 串成可在真实直播间前台按顺序执行的 minimal→narrow→all 证据采集流程；如果 `--dry-run` 因 launcher / notification / keyguard / splash 等 blocker 拒绝进入 hook，这是正确的安全行为。
- dry-run 验证应覆盖：`python3 -m py_compile`、matrix/static/status JSON `json.tool`、`--list-plan`、`--sequence minimal --dry-run`、analyzer 输出再 `json.tool`、`memory-sync.py sync`、`memory-sync.py search <slug>`、残留 `ps` 检查。
- `py_compile` 只能发现语法错误，不能保证 analyzer 写出的 JSON 有效；如果代码里误写 `write_text(txt+'\\n')`，会把反斜杠字符写进文件导致 `json.JSONDecodeError: Extra data`。正确写法是 `write_text(txt+'\n', encoding='utf-8')`，随后必须用 `python3 -m json.tool analysis.json` 验证。
- analyzer 读 wrapper logs 时要同时展开 delegated logs（例如 v190 日志里的 `delegated_log` 指向 v189 jsonl），否则只会统计 wrapper command/result，漏掉下游 gate/hook/event 证据。
- 如果验证摘要显示 `v189_gate_pass_count=0`、`operator_handoff_required_count>0`、`dynamic_execution_performed=false`、`strict_evidence_event_count=0`，必须保守写：
  - `algorithm_status=not_recovered`
  - `first_seen_evidence=false`
  - `new_value_source_evidence=false`
  - `proven_algorithm_evidence=false`
- 汇报时明确区分：sequence runner/analyzer/memory-sync/残留进程验证通过，只说明执行包可用；没有真实 `LivePlayActivity/webcast` 前台 gate pass 和同请求窗口 X-Cylons/ACK/SSL/downstream 对齐前，算法本体仍未挖出。

建议字段：

- `v*_live_sequence_execution_package_ready=true`
- `v*_sequence_count`
- `delegated_pack_count`
- `v*_delegate_command_count` / `v*_delegate_result_count`
- `gate_pass_count`
- `operator_handoff_required_count`
- `dynamic_execution_performed=false`
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `validation.py_compile_ok/json_tool_ok/list_plan_ok/dry_run_ok/analyzer_json_ok/memory_sync_ok/no_residual_process=true`

### v203 Java/native Cronet/TTNet bridge static backtrack 归档

当一轮把 Java/smali precise callsite、Cronet/TTNet request/header/security builder 与上一轮 native Cronet/header-builder targets 做静态桥接回溯（例如 v203），应归档为“static bridge backtrack / next dynamic hook matrix generation”，不是动态算法恢复。

关键经验：

- v203 这类阶段的价值是把高层 Java header map/request builder/security-adjacent callsites 与 native Cronet/TTNet header-builder targets 桥起来，生成下一轮 focused Java+native Frida hook 输入矩阵；`bridge_record_count`、`bridge_candidate_file_count`、`native_target_count`、pack counts 都是候选规模，不是 X-Cylons value-source 证据。
- 如果本轮没有真实直播间动态执行、没有 hook hit、没有同请求窗口 X-Cylons/ACK/SSL/WS carry 对齐，必须保守写：`dynamic_execution_performed=false`、`strict_evidence_event_count=0`、`algorithm_status=not_recovered`、`first_seen_evidence=false`、`new_value_source_evidence=false`、`proven_algorithm_evidence=false`。
- SESSION-STATE 追加前要从 status/static JSON 抽取真实 pack counts，不要沿用上一轮或草稿中的错误计数；必要时先 patch SESSION 中错误摘要，再 sync。
- `memory-sync.py search` broad query 可能被历史 v187/v188/v185 等相似 Cronet/TTNet 阶段稀释；归档验证时追加精确计数 query（例如 `v203 bridge_candidate_files native_targets 493`）或 slug query，Top1/Top5 命中新 project memory 即可视为语义层可检索。
- mem0 写入若超时且工具返回 `Do NOT retry this command`，不要阻塞归档；以本地 status/project memory/SESSION + memory-sync 搜索命中为审计事实源。

建议字段：

- `v*_static_backtrack_completed=true`
- `v*_input_smali_file_count`
- `v*_bridge_record_count`
- `v*_bridge_candidate_file_count`
- `v*_bridge_category_counts`
- `v*_pack_counts`
- `v*_pack_count`
- `v*_native_target_input_count`
- `v*_unique_native_target_count`
- `v*_scan_error_count`
- `dynamic_execution_performed=false`
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `next_step=generate focused Java+native Frida dynamic hook package and run real-live-room gated packs in order: security/header-map bridge -> Cronet/TTNet request bridge -> live webcast request security bridge -> combined Java+native bridge`

### v202 QUIC/Cronet internal header-builder focused package 归档

当一轮围绕 `libsscronet.so` / QUIC / Cronet internal header-builder 生成 focused native hook package（例如 v202：`transport_export_controls`、`rodata_header_refs_minimal`、`near_rodata_branch_targets`、`vtable_dispatch_targets`、`combined_internal_header_builder`），但只完成静态包生成、`--list-packs`、dry-run gate 验证和 analyzer JSON 验证时，应归档为“candidate generation + execution package readiness”，不是动态算法恢复。

关键经验：

- v201/v202 这种上移到 Cronet/TTNet/native transport 之前的阶段，`v201_dynamic_execution_performed=true` 或上一轮有 call samples，只能作为输入来源；如果本轮 dry-run gate 因 `splash` / ANR / 非真实直播间 proof 缺失拒绝 hook，则本轮必须写 `dynamic_execution_performed=false`。
- pack counts、unique native target count、rodata refs、near-ref branch targets、vtable groups、export/control boundary candidates 是静态候选规模，不是 X-Cylons value-source 证据。
- dry-run 中出现 `operator-handoff-required`、`hard_blockers=["splash"]`、`real_live_room_proof_missing` 时，要把 `dryrun_gate_blocked=true`、`gate_sample_count`、`operator_handoff_required_count`、`last_hard_blockers` 写入 status/project memory。
- 若 `v*_hook_ok_count=0`、`native_hit_count=0`、`transport/value/downstream/header_event_count=0`、`strict_evidence_event_count=0`，必须保守写：
  - `dynamic_execution_performed=false`
  - `algorithm_status=not_recovered`
  - `first_seen_evidence=false`
  - `new_value_source_evidence=false`
  - `proven_algorithm_evidence=false`
- 归档验证要覆盖：generator/runner/analyzer `py_compile`，static/matrix/analysis/status JSON `python3 -m json.tool`，`--list-packs` 输出，至少一个 pack 的 `--dry-run`，`memory-sync.py sync`，以及 `memory-sync.py search <slug>` 能检索到本轮 project memory。
- 在 Hermes `execute_code` 内嵌较长 Python/Markdown 归档脚本时，避免在 shell heredoc 的 Python 中再嵌套复杂 triple-quoted f-string；容易因引号提前闭合把 Markdown 当 Python 代码解析。更稳妥做法：先用 `write_file` 写 `/tmp/archive_v*.py`，再用 terminal/execute_code 调用并验证。

建议字段：

- `v*_archived=true`
- `phase=static-focused-package-and-dry-run-gate-validation`
- `input_sources` / `input_hashes`
- `static_summary.v*_pack_counts`
- `static_summary.v*_unique_native_target_count`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.list_packs_ok=true`
- `validation.dry_run_ok=true`
- `validation.analyzer_json_ok=true`
- `validation.gate_sample_count`
- `validation.operator_handoff_required_count`
- `validation.last_hard_blockers`
- `dynamic_summary.dynamic_execution_performed=false`
- `dynamic_summary.dryrun_gate_blocked=true`
- `dynamic_summary.hook_target_count_dryrun_pack`
- `dynamic_summary.strict_evidence_event_count=0`
- `algorithm_boundary.algorithm_status=not_recovered`
- `next_step=resolve Splash/ANR gate, place real live room in stable foreground, then execute packs in order transport_export_controls -> rodata_header_refs_minimal -> near_rodata_branch_targets -> vtable_dispatch_targets -> combined_internal_header_builder`

### v206 focused Java bridge valueflow dynamic hook package 归档

当一轮基于上一阶段 Java bridge method-body/register value-flow 收敛结果，生成更窄的 focused Java bridge valueflow 动态 hook 包（例如 v206：`minimal_intercept_header_valueflow`、`explicit_security_header_valueflow`、`map_put_header_builder_valueflow`、`live_webcast_request_context_valueflow`、`cronet_ttnet_header_request_glue_valueflow`、`security_sign_adjacent_valueflow`、`high_score_java_bridge_valueflow`、`combined_java_bridge_valueflow_narrow`），但尚未在真实直播间完成动态执行并拿到 strict evidence，应归档为“focused Java bridge valueflow hook package ready”，不是算法恢复。

关键经验：

- v206 这类阶段的核心价值是把 v205 的宽 valueflow 记录压缩成少量 Java method targets，用于下一轮真实直播间精确 hook；`pack_counts`、`unique_java_method_target_count`、`combined_java_bridge_valueflow_narrow` 只是执行包规模，不是 X-Cylons value-source 证据。
- status JSON 中如果同时存在 `v206_unique_java_method_target_count` 与 `v206_unique_target_count`，应确保二者一致；归档收尾可把 `v206_unique_target_count` 补齐为 `v206_unique_java_method_target_count`，避免后续检索/汇报出现 `None`。
- 验证收尾应覆盖：`python3 -m json.tool` 校验 status/static/matrix JSON，`memory/scripts/memory-sync.py sync`，用精确计数 query 检索（例如 `v206_focused_java_bridge_valueflow_dynamic_hook_package_ready unique_java_method_target_count 7 combined_java_bridge_valueflow_narrow`），并检查 `static_v206|run_v206|analyze_v206|v206_|frida.*aweme|frida-server` 残留进程。
- 残留进程检查若只命中设备侧 `/usr/bin/adb-real ... shell su -c /data/local/tmp/frida-server`，可说明 frida-server 仍在而本轮 `run_v206/analyze_v206/static_v206` 无残留；不要误判为 v206 runner 残留。
- 若本轮没有真实直播间动态执行、没有 hook hit、没有同请求窗口 X-Cylons/header/downstream carry/first-seen 严格证据，必须保守写：`algorithm_status=not_recovered`、`strict_evidence_event_count=0`、`first_seen_evidence=false`、`new_value_source_evidence=false`、`proven_algorithm_evidence=false`。

建议字段：

- `v*_focused_java_bridge_valueflow_dynamic_hook_package_ready=true`
- `v*_pack_count`
- `v*_hook_target_counts`
- `v*_unique_java_method_target_count`
- `v*_unique_target_count`
- `v*_generated_runner_count`
- `v*_generated_analyzer_count`
- `v*_generated_matrix_count`
- `v*_pack_counts`
- `dynamic_execution_performed=false`（若仅包生成/静态验证）
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `next_step=real-live-room foreground then execute packs in order: minimal_intercept_header_valueflow -> explicit_security_header_valueflow -> map_put_header_builder_valueflow -> combined_java_bridge_valueflow_narrow`

### v211 focused Java callee-body dynamic hook package 归档

当一轮基于上一阶段 callee-body smali slice / 方法体内字符串、Map/Header mutation、crypto/security transform 线索收敛结果，生成更窄的 focused Java callee-body Frida 动态 hook 包（例如 v211：`minimal_encrypt_header_callee_body`、`crypto_security_callee_body`、`map_header_mutation_callee_body`、`string_json_query_transform_callee_body`、`live_webcast_context_callee_body`、`high_score_callee_body_candidates`、`combined_java_callee_body_narrow`），但只完成静态包生成、dry-run gate 与归档验证，应归档为“focused Java callee-body dynamic hook package ready”，不是算法恢复。

关键经验：

- v211 这类阶段的价值是把 v210 callee-body slice convergence 转成可执行 Java hook matrix/runner/JS/analyzer/runbook；`pack_counts`、`unique_target_count`、callee body 命中规模只是下一轮采样规模，不是 X-Cylons value-source 证据。
- runner 应复用 focused live-room gate；dry-run 若日志出现 `v*-operator-handoff-required`、`reason=real_live_room_proof_missing`、`hard_blockers=["splash"]`，这是正确安全行为，必须保持 `dynamic_execution_performed=false`，不能因 hook package ready 或 dry-run OK 写成动态采样成功。
- 验证收尾应覆盖：`py_compile`、matrix/static/status JSON `json.tool`、`--list-packs`、至少一个最小 pack 的 dry-run、analyzer JSON `json.tool`、`memory-sync.py sync`、精确 slug/count search Top1/Top5 命中、残留进程检查（如 `static_v211|run_v211|analyze_v211|v211_|frida.*aweme`）。
- 如果本轮没有真实直播间动态执行、没有 Java hook hit、没有同请求窗口 X-Cylons/ACK/header/downstream/SSL or WS carry 对齐，必须保守写：`algorithm_status=not_recovered`、`strict_evidence_event_count=0`、`first_seen_evidence=false`、`new_value_source_evidence=false`、`proven_algorithm_evidence=false`。
- `memory-sync.py search` 精确 query（例如 `v211 focused java callee body dynamic hook package unique_target_count 74`）Top1 命中新 project memory，即可作为语义层可检索验证。

建议字段：

- `v*_focused_java_callee_body_dynamic_hook_package_ready=true`
- `v*_pack_count`
- `v*_pack_counts`
- `v*_unique_target_count`
- `v*_generated_runner_count`
- `v*_generated_hook_template_count`
- `v*_generated_analyzer_count`
- `v*_generated_matrix_count`
- `validation.py_compile_ok=true`
- `validation.list_packs_ok=true`
- `validation.dry_run_ok=true`
- `validation.analyzer_json_ok=true`
- `validation.memory_search_top1_v*_slug=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`（若仅包生成/dry-run gate）
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `next_step=real-live-room foreground then execute packs in order: minimal_encrypt_header_callee_body -> crypto_security_callee_body -> map_header_mutation_callee_body -> string/json/query/live context -> high-score/combined`

### v209 focused Java multihop dynamic hook package 归档

当一轮基于上一阶段 Java 多跳调用链 / transform-to-header candidate convergence，把多跳候选节点转换成 focused Java Frida 动态 hook 包（例如 v209：`minimal_direct_tryencrypt_header_path`、`crypto_security_transform_multihop`、`map_header_to_encrypt_candidates`、`resolved_second_third_hop_algorithm_nodes`、`high_score_transform_to_header_candidates`、`focused_v208_dynamic_hook_candidate_methods`、`combined_java_multihop_narrow`），但只完成静态包生成、dry-run gate 与归档验证，应归档为“focused Java multihop dynamic hook package ready”，不是算法恢复。

关键经验：

- v209 这类阶段的价值是把 v208 多跳路径收敛结果转成可执行 Java hook matrix/runner/JS/analyzer/runbook；`pack_counts`、`unique_target_count`、chain preview、hook target count 只是下一轮采样规模，不是 X-Cylons value-source 证据。
- runner 应复用 focused live-room gate；dry-run 若日志出现 `v*-operator-handoff-required`、`reason=real_live_room_proof_missing`，这是正确安全行为，必须保持 `dynamic_execution_performed=false`，不能因 hook package ready 或 dry-run OK 写成动态采样成功。
- 验证收尾应覆盖：`py_compile`、matrix/static/status JSON `json.tool`、`--list-packs`、至少一个 pack 的 dry-run、analyzer JSON `json.tool`、`memory-sync.py sync`、精确 slug search Top1/Top5 命中、残留进程检查（如 `static_v209|run_v209|analyze_v209|v209_|frida.*aweme`）。
- `memory-sync.py search ... | head` 可能在命中后触发 `BrokenPipeError`，只要输出已显示目标 project memory Top1 命中，可视为搜索验证通过；若要避免噪音，用脚本截断输出而不是管道 head。
- 如果本轮没有真实直播间动态执行、没有 Java hook hit、没有同请求窗口 X-Cylons/ACK/header/downstream/SSL or WS carry 对齐，必须保守写：`algorithm_status=not_recovered`、`strict_evidence_event_count=0`、`first_seen_evidence=false`、`new_value_source_evidence=false`、`proven_algorithm_evidence=false`。

建议字段：

- `v*_focused_java_multihop_dynamic_hook_package_ready=true`
- `v*_pack_count`
- `v*_pack_counts`
- `v*_unique_target_count`
- `v*_generated_runner_count`
- `v*_generated_hook_template_count`
- `v*_generated_analyzer_count`
- `v*_generated_matrix_count`
- `validation.py_compile_ok=true`
- `validation.list_packs_ok=true`
- `validation.dry_run_ok=true`
- `validation.analyzer_json_ok=true`
- `validation.memory_search_top1_v*_slug=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`（若仅包生成/dry-run gate）
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `next_step=real-live-room foreground then execute packs in order: minimal_direct_tryencrypt_header_path -> crypto_security_transform_multihop -> map_header_to_encrypt_candidates -> resolved/high-score/combined`

### v219 focused VM PC/word trace package 归档

当一轮基于已识别的 native VM dispatcher/handler slicing，生成 focused Frida VM PC/word trace 包（例如 v219：`0x2d2c` dispatcher/PC-word sequence、`0x3c28` fetch epilogue、`0x34dc/0x34ec/0x3560/0x3570` width stores、`0x328c/0x3398` predicate stores、`0x2ff0/0x3048/0x33d4/0x33e4/0x3458` VM-reg write/conversion helpers），但只完成 py_compile、dry-run、empty-log analyzer、status/project memory/SESSION 归档验证，应归档为“focused VM PC/word trace package ready”，不是算法恢复。

关键经验：

- 这类阶段的价值是把 static VM handler/CFG/def-use 结果转成可在真实直播间执行的窄 native trace package；`target_count`、offset/role matrix、template/runner/analyzer/runbook ready 只是采样包准备度，不是 opcode 语义或纯算复现。
- runner 应显式拒绝真实 attach，除非同时传入 `--i-understand-dynamic-hook` 和非空 `--live-room-proof`；dry-run OK 只能证明包可加载和参数门控正常。
- analyzer 可用 `/dev/null` 或空日志生成 baseline JSON；若 `event_count=0`、`dynamic_execution_performed=false`、`strict_evidence_event_count=0`、`promotion_allowed=false`，这是 readiness 验证结果，应保守写 `algorithm_status=not_recovered`。
- 归档验证应覆盖：generator/runner/analyzer `py_compile`，generator dry-run，runner dry-run，matrix/status/analysis JSON `json.tool`，`memory-sync.py sync`，精确 slug search Top1 命中，残留进程检查（如 `static_v219|run_v219|analyze_v219|v219_|frida.*aweme`）。
- 如果 broad memory search 被历史阶段稀释没有命中新项目记忆，立即追加精确 slug 搜索（例如 `douyin-xcylons-v219-focused-vm-pc-word-trace-package`）；精确 Top1 命中即可视为语义层可检索。
- status/project memory/SESSION 必须明确区分：package ready ≠ dynamic attach；没有真实 ttEncrypt input/output、完整 VM PC/word runtime sequence、AES mode/key schedule/IV/padding 绑定、pure reproduction 前，不能升级算法状态。

建议字段：

- `v*_archived=true`
- `phase=focused-vm-pc-word-trace-package-dryrun-validation`
- `algorithm_boundary_status=vm_pc_word_trace_package_ready_not_executed`
- `counts.target_count`
- `counts.analysis_event_count=0`
- `counts.analysis_hook_error_count=0`
- `validation.py_compile_ok=true`
- `validation.generator_dry_run_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.status_json_tool_ok=true`
- `validation.analyzer_empty_log_ok=true`
- `validation.analyzer_json_ok=true`
- `validation.dynamic_attach_executed=false`
- `validation.real_live_room_proof_present=false`
- `dynamic_execution_performed=false`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `next_step=place real LivePlayActivity/webcast live room in foreground, run guarded VM PC/word trace, then recover opcode/key/mode/IV/padding and pure reproduction`

### v221 handler/opcode dynamic semantic tracer package 归档

当一轮基于 v220 VM opcode handler micro-semantics 与 v219 PC/word trace 输入，生成 handler/opcode dynamic semantic tracer package（例如 v221：Frida JS template、runner、analyzer、matrix、runbook、static conclusion），但只完成 dry-run、empty-log analyzer、status/project memory/SESSION 归档验证，应归档为“handler/opcode dynamic semantic tracer package ready”，不是算法恢复。

关键经验：

- 这类阶段的价值是把静态 handler opcode 线索转成可在真实直播间执行的动态语义 tracer；`target_count`、matrix/template/runner/analyzer ready 只是采样包准备度，不是 opcode 语义恢复。
- runner 应显式要求双重门控：`--i-understand-dynamic-hook` 与非空 `--live-room-proof`；dry-run OK 只能证明门控/参数/包加载正常。
- analyzer 可用空 jsonl 生成 baseline；若 `event_count=0`、`hook_error_count=0`、`dynamic_execution_performed=false`、`strict_evidence_event_count=0`、`promotion_allowed=false`，这是 readiness 验证，应保守写 `algorithm_status=not_recovered`。
- 归档 status 建议补 `analysis_baseline`，记录 empty log path、analysis JSON、event/hook_error/promotion/dynamic/strict counts；`algorithm_boundary.status=handler_opcode_semantic_trace_package_ready_not_executed`，并显式写 `opcode_semantics_recovered=false`、`vm_runtime_sequence_recovered=false`、`tt_encrypt_input_output_bound=false`、`aes_mode_key_iv_padding_bound=false`、`pure_reproduction_ready=false`。
- `execute_code` 内不要把长 Markdown triple-quoted string 嵌进另一个 Python heredoc/字符串；容易因引号提前闭合把 `Date: 2026-05-20` 等 Markdown 当 Python 解析而 SyntaxError。更稳妥：先用 `write_file` 写 `/tmp/archive_v*.py`，再执行脚本。
- `memory-sync.py search` 即使使用精确 slug，也可能因历史 VM 阶段相似度高而不是 Top1；只要本轮 project memory 在 Top5 命中且本地 status/project memory/SESSION 均已写入，可记录 `memory_search_v*_slug_hit=true`，不要强行写 Top1。
- 残留进程检查建议覆盖 `static_v221|run_v221|analyze_v221|v221_|frida.*aweme`；没有本轮脚本/frida aweme 残留后再标 `no_residual_process=true`。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、dispatcher/fetch/store runtime sequence、ttEncrypt concrete input/output、opcode-level semantic closure、AES mode/key/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=handler-opcode-dynamic-semantic-tracer-package-dryrun-validation`
- `target_count`
- `analysis_baseline.event_count=0`
- `analysis_baseline.hook_error_count=0`
- `analysis_baseline.promotion_allowed=false`
- `validation.py_compile_ok=true`
- `validation.generator_dry_run_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.status_json_tool_ok=true`
- `validation.analyzer_empty_log_ok=true`
- `validation.analyzer_json_ok=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_slug_hit=true`
- `validation.no_residual_process=true`
- `algorithm_boundary.status=handler_opcode_semantic_trace_package_ready_not_executed`
- `dynamic_execution_performed=false`
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `next_step=place real LivePlayActivity/webcast live room in foreground, run guarded handler/opcode semantic tracer, then recover opcode semantics, VM state transitions, key/mode/IV/padding and pure reproduction`

### v215 native Encryptor/ttEncrypt VM boundary 归档

当一轮从 Java/Cronet/header 路径切到 `libEncryptor` / `ttEncrypt` native 层，并确认 JNI wrapper 之后的 VM 边界（例如 v215：`0x7d8c` JNI wrapper、`0x2bd8` byte-pointer transform callee、`0x2d2c` VM dispatcher、`0xb2d0` bytecode blob、AES T-table / inverse S-box 常量），应归档为“native VM byte-pointer boundary identified”，不是算法恢复。

关键经验：

- 不要把 JNI wrapper 当算法主体：`0x7d8c` 参数为 `JNIEnv* / class-or-object / jbyteArray / jint`，内部通过 JNIEnv vtable 取 byte[] 元素、分配输出，再调用更底层 callee。
- 动态 hook 应优先抓 `0x2bd8(x0=byte_ptr, x1=int_arg, x2=out_buf, x3=&out_len)` 的入参/出参，而不是在 `0x7d8c` 误读 jobject / jbyteArray 内存。
- `0x2bd8` prologue 若写入 `vm_bytecode_blob=0xb2d0`、context/table（如 `0x17ce0`）并进入 `0x2d2c`，可将边界状态写为 `native_vm_byte_pointer_boundary_identified`。
- `0x2d2c` 出现大量 `ldrsw + br xN`、dispatch tables（如 `0xa970/0xaa70/0xab50/0xad38`）时，只能证明 VM dispatcher/interpreter 存在；还需要 opcode 语义、key/mode/IV/padding 与 input-output 复现才能升级算法状态。
- AES T-table / inverse S-box（如 `0x8970`、`0xdf50`）只能证明 AES-family / whitebox-table 参与，不能单独证明完整 ttEncrypt/X-Cylons 算法。
- 若本轮只生成 static/matrix/Frida runner/analyzer/runbook，且 dry-run/analyzer 验证通过但未执行真实直播间动态采样或未还原 VM opcode，必须保守写：`dynamic_execution_performed=false`、`strict_evidence_event_count=0`、`algorithm_status=not_recovered`、`first_seen_evidence=false`、`new_value_source_evidence=false`、`proven_algorithm_evidence=false`。
- 归档验证要覆盖：`py_compile`、static/matrix/status JSON `json.tool`、`--list-packs`、最小 pack `--dry-run`、analyzer、`memory-sync.py sync`、精确 slug/offset 搜索 Top1 命中、残留进程检查（如 `static_v215|run_v215|analyze_v215|v215_native_encryptor|frida.*aweme`）。
- `SESSION-STATE.md` 摘要必须明确区分：已识别 native VM 边界，但“VM opcode/key/mode/IV/padding/pure reproduction not recovered”。

建议字段：

- `v*_archived=true`
- `phase=native-encryptor-vm-boundary-static-and-dryrun-validation`
- `algorithm_boundary_status=native_vm_byte_pointer_boundary_identified`
- `key_offsets.jni_wrapper_rva=0x7d8c`
- `key_offsets.byte_pointer_transform_callee_rva=0x2bd8`
- `key_offsets.vm_dispatcher_rva=0x2d2c`
- `key_offsets.vm_bytecode_blob_va=0xb2d0`
- `key_offsets.dispatch_tables=[...]`
- `key_offsets.aes_ttable_va` / `key_offsets.aes_inv_sbox_va`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.status_json_tool_ok=true`
- `validation.list_packs_ok=true`
- `validation.dry_run_ok=true`
- `validation.analyzer_ok=true`
- `validation.memory_search_top1_v*_slug=true`
- `validation.no_residual_v*_process=true`
- `dynamic_execution_performed=false`（若仅 static/dry-run 验证）
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `next_step=hook 0x2bd8 input/output and trace 0x2d2c VM dispatcher/opcode semantics, then prove key/mode/IV/padding and pure reproduction`

### v222 VM opcode-family/value-flow atlas 静态深化归档

当一轮基于 v220 micro-semantics 与 v221 handler/opcode dynamic tracer matrix，继续做 VM opcode-family / handler value-flow atlas 静态深化（例如 v222：primary low6 opcode、bytecode prefix 字段分布、四张 dispatch table、handler value-flow hints、dynamic priority target scoring），但未执行真实直播间动态 attach，应归档为“static VM opcode-family/value-flow atlas completed”，不是算法恢复。

关键经验：

- v222 这类阶段的价值是把静态 handler micro-semantics、dispatch table、bytecode prefix observations 与 v221 tracer target set 合并成 table-aware atlas；`handler_valueflow_count`、`primary_opcode_rows`、`dispatch_table_unique_targets`、`dynamic_priority_targets` 都是静态收敛/下一轮动态优先级，不是 runtime opcode 语义闭合。
- 典型计数字段：`handler_valueflow_count=36`、`primary_opcode_rows=64`、`primary_prefix_observed_opcodes=10`、`dispatch_table_count=4`、`dispatch_table_unique_targets=45`、`dynamic_priority_targets=24`。这些可以写入 status/project memory，但不能升级算法状态。
- Top dynamic targets 可作为下一轮 tracer 输入，例如 `0x2e54/0x3c28/0x2f74/0x2ed0/0x3340/0x318c/0x3048`；归档时明确它们是 prioritized runtime trace targets，而不是已验证算法节点。
- 如果只生成 static JSON / conclusion MD / status / project memory，并完成 `py_compile`、`json.tool`、`memory-sync.py sync/search`、SESSION append、残留进程检查，必须保守写：`dynamic_execution_performed=false`、`real_live_room_proof_present=false`、`strict_evidence_event_count=0`、`algorithm_status=not_recovered`。
- `memory-sync.py search` 的 broad/slug query 可能被 v216-v221 相似 VM 阶段稀释；追加包含 v222、handlers/primary opcode 精确计数的 query（例如 `v222 VM opcode family valueflow atlas handlers 36 primary opcodes 64`）可验证 Top1 命中新 project memory。
- 归档脚本建议单独写到 `/tmp/archive_v222_*.py` 后执行，避免长 Markdown/JSON 拼接在 shell heredoc 中引号错乱；归档后再 patch status validation 字段补齐 `memory_sync_ok`、`memory_search_v222_top1_hit`、`no_residual_process`、`session_state_appended`。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、runtime PC/word sequence、`0x2bd8` ttEncrypt input/output binding、opcode-level semantic closure、key/mode/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=vm-opcode-family-valueflow-atlas-static`
- `counts.handler_valueflow_count`
- `counts.primary_opcode_rows`
- `counts.primary_prefix_observed_opcodes`
- `counts.dispatch_table_count`
- `counts.dispatch_table_unique_targets`
- `counts.dynamic_priority_targets`
- `primary_family_counts`
- `top_dynamic_priority_targets`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.status_json_tool_ok=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v222_top1_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `opcode_semantics_recovered=false`
- `vm_runtime_sequence_recovered=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=run guarded v221/v222 VM PC/word/handler tracer in real LivePlayActivity/webcast foreground, then backfill v222 atlas and bind ttEncrypt input/output + key/mode/IV/padding`

### v223 VM operand-lifter trace plan 静态/动态准备归档

当一轮基于 v222 VM opcode-family/value-flow atlas，把 priority targets 转换成 operand-lifter runtime trace matrix、Frida JS template、runner、analyzer、runbook（例如 v223：capture handler before/after regs、word low6、bits[6:11]、high nibble、VM base regs、memory operands），但只完成 static generation、dry-run、empty-log analyzer、status/project memory/SESSION 归档验证，应归档为“VM operand-lifter trace plan ready”，不是算法恢复。

关键经验：

- v223 这类阶段的价值是把 v222 的静态 atlas 转成可执行 runtime operand-lifter 计划；`matrix_target_count`、`operand_lift_field_count`、`pack_counts` 只是 trace plan / package readiness，不是 opcode semantic closure。
- 典型字段可写入 status/project memory：`selected_priority_target_count=24`、`anchor_target_count=6`、`matrix_target_count=30`、`operand_lift_field_count=34`、`handler_family_count=4`、`dynamic_pack_count=4`，以及 pack counts（如 minimal/core、dispatch-tail、state-memory、high-score）。
- runner dry-run 中 pack 声明数量与实际 `targets` 过滤后数量可能不一致（例如 pack list 14，但 target_count 17），因为 anchors/selected 可能存在 target 重复；归档时保留真实输出，不要把它当 strict evidence。
- 在 Hermes `execute_code` 中生成长 Python 脚本时，避免外层 raw triple-quoted string 与内层 Markdown triple-quoted f-string 混用；若出现 `SyntaxError: invalid character '。'` 或 `leading zeros in decimal integer literals`，说明 Markdown 被提前闭合当成 Python 解析。更稳妥做法是分段 `write_file` 生成 static script / JS / runner / analyzer，或直接在 `execute_code` 当前 Python 中完成归档写入。
- empty-log analyzer baseline 若 `event_count=0`、`handler_enter_count=0`、`strict_evidence_event_count=0`、`promotion_allowed=false`，这是准备包验证结果，应保守写 `dynamic_execution_performed=false` 和 `algorithm_status=not_recovered`。
- 归档验证应覆盖：generator/runner/analyzer `py_compile`，generator dry-run，static/matrix/status/analysis JSON `json.tool`，`--list-packs`，最小 pack runner dry-run，empty-log analyzer JSON，`memory-sync.py sync`，本地 project memory 搜索命中，SESSION 追加，残留进程检查（如 `v223_vm_operand_lifter|run_v223|frida.*aweme`）。常驻 `frida-mobile-mcp` 或设备侧 `/data/local/tmp/frida-server` 不应算 v223 runner 残留。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、runtime handler word/state delta、`0x2bd8` ttEncrypt input/output binding、opcode-level semantic closure、key/mode/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=vm-operand-lifter-trace-plan-static-and-dryrun-validation`
- `counts.selected_priority_target_count`
- `counts.anchor_target_count`
- `counts.matrix_target_count`
- `counts.operand_lift_field_count`
- `counts.handler_family_count`
- `counts.dynamic_pack_count`
- `pack_counts`
- `top_operand_lifter_targets`
- `analysis_baseline.event_count=0`
- `analysis_baseline.handler_enter_count=0`
- `analysis_baseline.handler_leave_count=0`
- `analysis_baseline.strict_evidence_event_count=0`
- `analysis_baseline.promotion_allowed=false`
- `validation.py_compile_ok=true`
- `validation.generator_dry_run_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.list_packs_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.analyzer_empty_log_ok=true`
- `validation.analyzer_json_ok=true`
- `validation.status_json_tool_ok=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v223_hit=true`
- `validation.no_residual_process=true`
- `validation.session_state_appended=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=vm_operand_lifter_trace_plan_ready_not_executed`
- `opcode_semantics_recovered=false`
- `vm_runtime_sequence_recovered=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=place real LivePlayActivity/webcast live room in foreground, run guarded minimal_operand_lifter_core, capture handler word/state deltas, then bind 0x2bd8 ttEncrypt IO and key/mode/IV/padding for pure reproduction`

### v224 VM operand equation synthesizer 静态深化归档

当一轮基于 v223 operand-lifter trace plan，继续把 handler micro-semantics / operand-lift fields / bytecode prefix words 合成为可动态校验的 VM operand equations（例如 v224：`and/ubfx/bfxil/orr/shift/load` 到 word-field/state-carry symbolic equations、128 prefix words concrete assertions、dynamic packs `operand_equation_core` / `state_carry_bfxil_chain` 等），但未执行真实直播间动态 attach，应归档为“VM operand equation synthesizer static analysis completed”，不是算法恢复。

关键经验：

- v224 这类阶段的价值是把 v223 runtime trace plan 进一步静态转成可验证方程；`handler_equation_count`、`prefix_word_count`、`symbolic_fact_count`、confidence counts 与 dynamic pack counts 都是静态收敛/下一轮动态验证输入，不是 runtime opcode 语义闭合。
- 典型字段可写入 status/project memory：`handler_equation_count=24`、`prefix_word_count=128`、`high_confidence_handler_count=4`、`medium_confidence_handler_count=7`、`low_confidence_handler_count=13`、`symbolic_fact_count=34`、`dynamic_pack_count=4`。
- Top targets（例如 `0x2e54`、`0x3c28`、`0x2f74`、`0x2ed0`、`0x3048`）应标注为 dynamic validation priority targets，而不是已证明算法节点。
- 如果只生成 static script / static JSON / conclusion MD / status / project memory，并完成 `json.tool`、`memory-sync.py sync/search`、SESSION append、残留进程检查，必须保守写：`dynamic_execution_performed=false`、`real_live_room_proof_present=false`、`strict_evidence_event_count=0`、`algorithm_status=not_recovered`。
- 归档验证建议用精确 query（例如 `v224 VM operand equation synthesizer handlers 24 prefix_words 128 algorithm_status not_recovered`）；Top1 命中新 project memory 可作为语义层可检索证据。
- 在 `execute_code` 中生成归档脚本时，不要把外层 raw triple-quoted string、shell heredoc 和内层 Markdown triple-quoted f-string 混用；实测会把 `Date: 2026-05-20` 当 Python 解析并触发 `SyntaxError: leading zeros in decimal integer literals`。更稳妥做法：先用 `write_file` 写 `/tmp/archive_v224.py`，Markdown 模板用占位符 + `replace()` 注入 JSON/路径，再用 terminal 执行与验证。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、runtime word/state deltas、`0x2bd8` ttEncrypt input/output binding、opcode-level semantic closure、key/mode/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=vm-operand-equation-synthesizer-static`
- `v*_vm_operand_equation_synthesizer_static_completed=true`
- `counts.handler_equation_count`
- `counts.prefix_word_count`
- `counts.high_confidence_handler_count`
- `counts.medium_confidence_handler_count`
- `counts.low_confidence_handler_count`
- `counts.symbolic_fact_count`
- `counts.dynamic_pack_count`
- `family_counts`
- `symbolic_field_counts`
- `confidence_counts`
- `dynamic_pack_counts`
- `top_operand_equation_targets`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.status_json_tool_ok=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.session_state_appended=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_operand_equations_ready_for_dynamic_validation`
- `opcode_semantics_recovered=false`
- `vm_runtime_sequence_recovered=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run operand_equation_core/state_carry_bfxil_chain, validate runtime word/state deltas, then bind 0x2bd8 ttEncrypt IO and key/mode/IV/padding`

### v233 VM slot-lane runtime assertion compiler 静态深化归档

当一轮基于 v232 slot-lane hypotheses，把 lane 合约编译成 concrete runtime assertion contracts / guarded Frida assertion matrix / runner / analyzer（例如 v233：验证 `x21 + 8 + (x9 << 3)` write/read relation、critical/must-pass assertions、dominant `0x3048 -> 0x2f74` lane），但未执行真实直播间动态 attach，应归档为“VM slot-lane runtime assertion compiler static analysis completed”，不是算法恢复。

关键经验：

- v233 这类阶段的核心价值是把静态 lane hypothesis 转成可动态校验的 assertion contract；`runtime_assertion_count`、`critical_assertion_count`、`must_pass_assertion_count`、`unique_hook_target_count`、`dynamic_pack_count` 都是验证包准备度，不是 runtime proof。
- 典型字段可写入 status/project memory：`slot_lane_count=12`、`compiled_lane_contract_count=12`、`runtime_assertion_count=20`、`critical_assertion_count=16`、`must_pass_assertion_count=16`、`unique_hook_target_count=4`、`dynamic_pack_count=5`、`target_pair_count=4`、`capture_field_count=25`。
- 归档时应写入 status / project memory / daily / SESSION，并验证：static/matrix/status JSON `json.tool`、static/runner/analyzer `py_compile`、conclusion MD 非空、`memory-sync.py sync`、精确 memory search 命中、残留进程检查（如 `static_v233|run_v233|analyze_v233|v233_.*frida|frida.*aweme`）。
- 在 `execute_code` 内生成 v233 归档脚本时，不要把外层 raw triple-quoted string、shell heredoc 与内层 Markdown triple-quoted string 混用；实测会把 Markdown 行 `Date: 2026-05-20` 当 Python 解析，触发 `SyntaxError: leading zeros in decimal integer literals`。稳妥做法：先用 `write_file` 写 `/tmp/archive_v233.py`，Markdown 模板用占位符 + `.replace()` 注入 JSON/路径，再用 terminal/execute_code 执行验证。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、runtime `x21/x9` write/read addr+value proof、`0x2bd8` ttEncrypt input/output binding、opcode-level semantic closure、key/mode/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=vm-slot-lane-runtime-assertion-compiler-static`
- `v*_archived=true`
- `counts.slot_lane_count`
- `counts.compiled_lane_contract_count`
- `counts.runtime_assertion_count`
- `counts.critical_assertion_count`
- `counts.must_pass_assertion_count`
- `counts.unique_hook_target_count`
- `counts.dynamic_pack_count`
- `counts.target_pair_count`
- `counts.capture_field_count`
- `priority_counts`
- `target_pair_assertion_counts`
- `hook_target_counts`
- `slot_bits6_11_occurrence_counts`
- `dynamic_assertion_packs`
- `top_runtime_hook_targets`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.conclusion_md_nonempty=true`
- `validation.runner_py_compile_ok=true`
- `validation.analyzer_py_compile_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.status_json_tool_ok=true`
- `validation.daily_memory_appended=true`
- `validation.session_state_appended=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_runtime_assertions_ready_for_live_lane_validation`
- `opcode_semantics_recovered=false`
- `vm_runtime_sequence_recovered=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run critical_lane_must_pass_assertions / dominant_0x3048_to_0x2f74 assertions, capture x21/x9 write/read addr+values, then bind confirmed lanes to 0x2bd8 ttEncrypt IO and X-Cylons output`

### v232 VM slot-lane semantic merger 静态深化归档

当一轮基于 v231 VM slot write → consumer read bridges，把重复 bridge occurrence 合并成 slot lane hypotheses，并生成按 lane priority 分组的动态验证包（例如 v232：`critical_slot_lanes`、`high_repetition_slot_lanes`、`dominant_0x3048_to_0x2f74_lane`、`secondary_0x2ff0_to_0x3340_lane`、schema/combined pack），但未执行真实直播间动态 attach，应归档为“VM slot-lane semantic merger static analysis completed”，不是算法恢复。

关键经验：

- v232 这类阶段的核心价值是把单条 `write -> read` bridge 升级为可重复验证的 slot lane hypothesis：按 `low6/bits6_11/slot_target/consumer_target/x21+x9 8-byte addr formula` 聚类，并为每条 lane 生成 runtime acceptance contract；`slot_lane_count`、`critical_lane_count`、`dedup_bridge_occurrence_count`、`dynamic_pack_count` 都是静态收敛/下一轮动态验证输入，不是 runtime proof。
- 典型字段可写入 status/project memory：`slot_lane_count=12`、`critical_lane_count=8`、`high_lane_count=1`、`medium_lane_count=3`、`dedup_bridge_occurrence_count=20`、`target_pair_count=4`、`dynamic_pack_count=5`。
- Top lanes（尤其 `0x3048 -> 0x2f74` dominant lane、`0x2ff0 -> 0x3340` secondary lane）应标注为 dynamic validation priority targets，而不是已证明算法节点。
- 如果只生成 static script / static JSON / conclusion MD / status / project memory / daily / SESSION，并完成 `py_compile`、`json.tool`、`memory-sync.py sync/search`、残留进程检查，必须保守写：`dynamic_execution_performed=false`、`real_live_room_proof_present=false`、`strict_evidence_event_count=0`、`algorithm_status=not_recovered`。
- `memory-sync.py search` 的精确 slug query 可能被历史 VM 阶段相似文本稀释，甚至 Top5 不命中新文件；如果 sync 日志明确包含本轮 project memory，且 broad query（例如 `v232 VM slot lane semantic merger algorithm_status not_recovered critical 8`）Top5 命中本轮 project memory，可记录 `memory_search_v232_hit=true`，并在 status 的 `memory_search_note` 说明 older VM stages ranked above due semantic similarity。
- 归档时建议同时写 daily memory 和 SESSION-STATE，并在 status `validation` 中记录：`py_compile_ok`、`static_json_tool_ok`、`conclusion_md_nonempty`、`status_json_tool_ok`、`daily_memory_appended`、`session_state_appended`、`memory_sync_ok`、`memory_search_v232_hit`、`no_residual_process`。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、runtime `x21/x9` write/read addr+value proof、`0x2bd8` ttEncrypt input/output binding、opcode-level semantic closure、key/mode/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=vm-slot-lane-semantic-merger-static`
- `v*_archived=true`
- `counts.slot_lane_count`
- `counts.critical_lane_count`
- `counts.high_lane_count`
- `counts.medium_lane_count`
- `counts.dedup_bridge_occurrence_count`
- `counts.target_pair_count`
- `counts.dynamic_pack_count`
- `validation_priority_counts`
- `lane_relation_counts`
- `target_pair_counts`
- `top_slot_lanes`
- `dynamic_trace_packs`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.conclusion_md_nonempty=true`
- `validation.status_json_tool_ok=true`
- `validation.daily_memory_appended=true`
- `validation.session_state_appended=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_slot_lane_hypotheses_ready_for_runtime_validation`
- `opcode_semantics_recovered=false`
- `vm_runtime_sequence_recovered=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run critical_slot_lanes/dominant/high_repetition packs, capture x21/x9 write/read addr+values, then bind confirmed lanes to 0x2bd8 ttEncrypt IO and X-Cylons output`

### v234 VM lane → ttEncrypt terminal binding plan 静态/动态准备归档

当一轮基于 v233 slot-lane runtime assertions，把 VM lane handler addr/value delta 与 `libEncryptor.so` / `ttEncrypt` terminal boundary 绑定到同一动态验证矩阵（例如 v234：lane hook targets `0x2f74/0x2ff0/0x3048`，ttEncrypt boundary `0x2bd8`，JNI wrapper `0x7d8c`，VM dispatcher `0x2d2c`），但只完成 static generation、runner dry-run、empty-log analyzer、status/project memory/daily/SESSION 归档验证，应归档为“VM lane → ttEncrypt terminal binding plan ready”，不是算法恢复。

关键经验：

- v234 这类阶段的核心价值是把 v233 的 lane assertion contract 接到 terminal ttEncrypt boundary：同时准备 lane addr/value delta capture 与同线程/同请求窗口 `0x2bd8` input/output capture；`selected_binding_assertion_count`、`critical_binding_count`、`lane_hook_targets`、`terminal_boundary_count` 都是动态验证计划规模，不是 runtime proof。
- 典型字段可写入 status/project memory：`selected_binding_assertion_count=18`、`critical_binding_count=16`、`unique_lane_hook_target_count=3`、`target_pair_count=2`、`lane_count=10`、`dynamic_pack_count=5`、`terminal_boundary_count=1`。
- Hook/boundary 字段建议保留：`lane_hook_target_rvas=["0x2f74","0x2ff0","0x3048"]`，`tt_encrypt_boundary.target_module=libEncryptor.so`，`tt_encrypt_jni_wrapper_rva=0x7d8c`，`byte_pointer_transform_callee_rva=0x2bd8`，`vm_dispatcher_rva=0x2d2c`，`vm_bytecode_blob_va=0xb2d0`。
- empty-log analyzer baseline 若 `event_count=0`、`lane_event_count=0`、`ttencrypt_event_count=0`、`terminal_binding_candidate=false`、`algorithm_proven=false`，这是准备包验证结果，应保守写 `dynamic_execution_performed=false` 和 `algorithm_status=not_recovered`。
- 归档验证应覆盖：static/matrix/status JSON `json.tool`，static/runner/analyzer `py_compile`，runner dry-run，empty-log analyzer JSON，conclusion MD 非空，`memory-sync.py sync`，精确 memory search 命中，daily memory 与 SESSION 追加，残留进程检查（如 `static_v234|run_v234|analyze_v234|v234_.*frida|frida.*aweme`）。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、runtime lane value delta、同线程/同请求窗口 `0x2bd8` ttEncrypt input/output、X-Cylons/security header carry、key/mode/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=vm-lane-ttencrypt-terminal-binding-plan-static-and-dryrun-validation`
- `v*_vm_lane_ttencrypt_terminal_binding_plan_ready=true`
- `counts.selected_binding_assertion_count`
- `counts.critical_binding_count`
- `counts.unique_lane_hook_target_count`
- `counts.target_pair_count`
- `counts.lane_count`
- `counts.dynamic_pack_count`
- `counts.terminal_boundary_count`
- `lane_hook_target_rvas`
- `lane_hook_target_counts`
- `target_pair_binding_counts`
- `selection_source_counts`
- `tt_encrypt_boundary`
- `analysis_baseline.event_count=0`
- `analysis_baseline.lane_event_count=0`
- `analysis_baseline.ttencrypt_event_count=0`
- `analysis_baseline.terminal_binding_candidate=false`
- `analysis_baseline.algorithm_proven=false`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.analyzer_empty_log_ok=true`
- `validation.conclusion_md_nonempty=true`
- `validation.daily_memory_appended=true`
- `validation.session_state_appended=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_lane_to_ttencrypt_terminal_binding_plan_ready_for_live_validation`
- `ttencrypt_terminal_binding_proven=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run terminal_binding_critical_lanes/dominant_0x3048_to_0x2f74, capture lane addr/value deltas plus same-thread 0x2bd8 ttEncrypt input/output, then prove deterministic influence and key/mode/IV/padding for pure reproduction`

### v235 lane influence → ttEncrypt oracle 静态/动态准备归档

当一轮基于 v234 terminal binding assertions，把 lane delta 与 `0x2bd8` ttEncrypt input/output 关系进一步编译成 observe-only deterministic influence oracle（例如 v235：18 influence probes、3 个 lane hook targets `0x2f74/0x2ff0/0x3048`、`0x2bd8` terminal boundary、4 个 dynamic packs），但未执行真实直播间动态 attach，应归档为“lane influence → ttEncrypt oracle package ready”，不是算法恢复。

关键经验：

- v235 这类阶段的核心价值是把 terminal binding assertion 转成可重复采样的 influence oracle：要求未来在同线程/同请求窗口内观测 lane value delta 与 `0x2bd8` input/output hash 变化相关；`influence_probe_count`、`critical_probe_count`、`lane_hook_target_count`、`dynamic_pack_count` 都是验证包准备度，不是 runtime proof。
- 典型字段可写入 status/project memory：`v234_binding_assertion_count=18`、`influence_probe_count=18`、`critical_probe_count=15`、`dynamic_pack_count=4`、`lane_hook_target_count=3`、`slot_bits6_11_group_count=8`。
- analyzer synthetic positive fixture 可以证明分析器能识别 deterministic influence candidate，但必须保持 `algorithm_proven=false`；这只是 analyzer 自测，不是算法证据。
- 归档验证应覆盖：static/matrix/status JSON `json.tool`，static/runner/analyzer `py_compile`，runner dry-run，analyzer synthetic positive，conclusion MD 非空，`memory-sync.py sync`，精确 memory search 命中，daily memory 与 SESSION 追加，残留进程检查（如 `static_v235|run_v235|analyze_v235|v235_.*frida|frida.*aweme`）。
- 在 Hermes `execute_code` 内做 v235 归档时，避免把长 Markdown triple-quoted f-string 嵌套进 shell heredoc / outer Python string；实测会让 Markdown 行被当成 Python 解析并触发 `SyntaxError: invalid character '→'`。稳妥做法：先用 `write_file` 写 `/tmp/archive_v235.py`，Markdown 模板用占位符 `.replace()` 注入 JSON/路径，再用 `execute_code`/terminal 执行验证。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、runtime lane value delta、同线程/同请求窗口 `0x2bd8` ttEncrypt input/output、X-Cylons/security header carry、key/mode/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=vm-lane-influence-ttencrypt-oracle-static-and-dryrun-validation`
- `v*_archived=true`
- `v*_lane_influence_ttencrypt_oracle_ready=true`
- `counts.v234_binding_assertion_count`
- `counts.influence_probe_count`
- `counts.critical_probe_count`
- `counts.dynamic_pack_count`
- `counts.lane_hook_target_count`
- `counts.slot_bits6_11_group_count`
- `lane_hook_target_rvas`
- `tt_encrypt_boundary`
- `dynamic_packs`
- `analysis_baseline.event_count=0`
- `analysis_baseline.lane_event_count=0`
- `analysis_baseline.ttencrypt_event_count=0`
- `analysis_baseline.deterministic_lane_influence_proven=false`
- `analysis_baseline.algorithm_proven=false`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.analyzer_synthetic_positive_ok=true`
- `validation.conclusion_md_nonempty=true`
- `validation.daily_memory_appended=true`
- `validation.session_state_appended=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_lane_influence_ttencrypt_oracle_ready_for_live_validation`
- `deterministic_lane_influence_proven=false`
- `ttencrypt_terminal_binding_proven=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run observe-only influence packs, capture repeated lane addr/value deltas plus same-thread 0x2bd8 ttEncrypt input/output windows, then prove deterministic influence and key/mode/IV/padding for pure reproduction`

### v236 deterministic influence → opcode/key-lane backfill 静态深化归档

当一轮基于 v235 lane influence → ttEncrypt oracle，把 influence probes 回填到 VM opcode/key-lane class，并生成 observe-only opcode/key-lane backfill checker/runner/analyzer（例如 v236：18 条 backfill records、15 条 critical backfills、lane hook targets `0x2f74/0x2ff0/0x3048`、terminal boundary `0x2bd8`），但未执行真实直播间动态 attach，应归档为“deterministic influence → opcode/key-lane backfill static/dry-run completed”，不是算法恢复。

关键经验：

- v236 这类阶段的核心价值是把 v235 的 deterministic influence oracle 与 VM opcode/key-lane 分类打通：把 lane/probe 关联到 opcode/key-lane class，并生成下一轮 observe-only checker；`backfill_count`、`critical_backfill_count`、`opcode/key-lane class count`、dynamic pack count 都是静态回填/动态准备度，不是 runtime proof。
- 典型字段可写入 status/project memory：`backfill_count=18`、`critical_backfill_count=15`、`lane_hook_target_count=3`、`dynamic_pack_count`、`opcode_key_lane_class_count`，以及 `lane_hook_target_rvas=["0x2f74","0x2ff0","0x3048"]`、`tt_encrypt_boundary=libEncryptor.so:0x2bd8`。
- analyzer synthetic positive fixture 只能证明 analyzer 能识别 `opcode_key_lane_influence_candidate`；必须保持 `algorithm_proven=false`、`algorithm_status=not_recovered`，不能把 synthetic candidate 当真实算法证据。
- 归档验证应覆盖：static/matrix/status JSON `json.tool`，static/runner/analyzer `py_compile`，runner dry-run，analyzer synthetic positive，checker observe-only 标记，`memory-sync.py sync`，精确 memory search 命中，daily memory 与 SESSION 追加，残留进程检查（如 `static_v236|run_v236|analyze_v236|v236_.*frida|frida.*aweme`）。
- 如果在 `execute_code` 中直接写归档文件，写完 status 后要再跑一轮 `python3 -m json.tool`，并 patch `validation.status_json_tool_ok=true`、`memory_sync_ok=true`、`memory_search_v236_hit=true`、`no_residual_process=true`；不要在 sync/search 前提前宣称归档完成。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、runtime lane addr/value deltas、同线程/同请求窗口 `0x2bd8` ttEncrypt input/output、X-Cylons/security header carry、key/mode/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=deterministic-influence-opcode-keylane-backfill-static-and-dryrun-validation`
- `v*_archived=true`
- `v*_deterministic_influence_opcode_keylane_backfill_completed=true`
- `counts.backfill_count`
- `counts.critical_backfill_count`
- `counts.lane_hook_target_count`
- `counts.dynamic_pack_count`
- `counts.opcode_key_lane_class_count`
- `lane_hook_target_rvas`
- `tt_encrypt_boundary`
- `dynamic_backfill_packs`
- `analysis_baseline.synthetic_candidate_count`
- `analysis_baseline.strict_evidence_event_count=0`
- `analysis_baseline.algorithm_proven=false`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.analyzer_synthetic_positive_ok=true`
- `validation.checker_observe_only=true`
- `validation.status_json_tool_ok=true`
- `validation.daily_memory_appended=true`
- `validation.session_state_appended=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_opcode_keylane_backfill_ready_for_live_validation`
- `deterministic_lane_influence_proven=false`
- `opcode_key_lane_backfill_proven=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run observe-only critical_opcode_keylane_backfill, capture repeated lane addr/value deltas plus same-thread 0x2bd8 ttEncrypt input/output windows, then prove deterministic influence and key/mode/IV/padding for pure reproduction`

### v237 cross-window opcode/key-lane promotion checker 归档

当一轮基于 v236 opcode/key-lane backfill，把 repeated lane delta windows 与同线程 `libEncryptor.so:0x2bd8` ttEncrypt terminal input/output hash 观测按 cluster 聚合，并生成 cross-window opcode/key-lane promotion checker / guarded runner / analyzer（例如 v237：4 个 promotion clusters、1 个 critical cluster、lane hook targets `0x2f74/0x2ff0/0x3048`），但未执行真实直播间动态 attach，应归档为“cross-window opcode/key-lane promotion checker ready”，不是算法恢复。

关键经验：

- v237 这类阶段的核心价值是把 v236 的 backfill records 提升成跨窗口重复候选：按 lane hook target、target pair、key-lane class、terminal `0x2bd8` window 聚类，生成 observe-only promotion checker；`promotion_cluster_count`、`critical_cluster_count`、`key_lane_class_count`、dynamic pack count 都是验证准备度，不是 runtime proof。
- 典型字段可写入 status/project memory：`v236_backfill_count=18`、`promotion_cluster_count=4`、`critical_cluster_count=1`、`lane_hook_target_count=3`、`dynamic_pack_count=4`、`backfill_id_count=18`、`key_lane_class_count=2`，以及 `lane_hook_target_rvas=["0x2f74","0x2ff0","0x3048"]`、`tt_encrypt_boundary.byte_pointer_transform_callee_rva=0x2bd8`。
- analyzer fixture-positive 只能证明分析器能把重复窗口提升为 promotion candidate；若 `strict_evidence_event_count=0`、`algorithm_proven=false`，必须保持 `algorithm_status=not_recovered`，不能把 fixture candidate 当真实算法证据。
- runner dry-run 应显示 observe-only 与 live-room proof gate；缺少真实 live-room proof 时只输出 manual Frida command / DRY_RUN_ONLY，不执行 attach。
- 归档验证应覆盖：static/matrix/status JSON `json.tool`，static/runner/analyzer `py_compile`，runner dry-run，analyzer fixture-positive JSON，project memory/daily/SESSION 写入，`memory-sync.py sync`，精确 memory search 命中，残留进程检查（如 `static_v237|run_v237|analyze_v237|v237_.*frida|frida.*aweme`）。
- status final check 应显式验证：`status=completed`、`v237_archived=true`、`algorithm_status=not_recovered`、`dynamic_execution_performed=false`、`strict_evidence_event_count=0`、`proven_algorithm_evidence=false`、`analysis_baseline.algorithm_proven=false`、`validation.status_json_tool_ok=true`、`memory_sync_ok=true`、`memory_search_v237_hit=true`、`no_residual_process=true`。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、repeated lane addr/value delta、same-thread/same-window `0x2bd8` ttEncrypt input/output hash、deterministic influence proof、key/mode/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=cross-window-opcode-keylane-promotion-static-and-dryrun-validation`
- `v*_archived=true`
- `v*_cross_window_opcode_keylane_promotion_checker_ready=true`
- `counts.v236_backfill_count`
- `counts.promotion_cluster_count`
- `counts.critical_cluster_count`
- `counts.lane_hook_target_count`
- `counts.dynamic_pack_count`
- `counts.backfill_id_count`
- `counts.key_lane_class_count`
- `key_lane_class_counts`
- `target_pair_counts`
- `lane_hook_target_rvas`
- `tt_encrypt_boundary`
- `dynamic_promotion_packs`
- `top_promotion_clusters`
- `analysis_baseline.fixture_event_count`
- `analysis_baseline.fixture_lane_leave_count`
- `analysis_baseline.fixture_ttencrypt_event_count`
- `analysis_baseline.fixture_same_thread_terminal_window_count`
- `analysis_baseline.fixture_cross_window_cluster_count`
- `analysis_baseline.fixture_promotion_candidate_count`
- `analysis_baseline.strict_evidence_event_count=0`
- `analysis_baseline.opcode_key_lane_promotion_proven=true`（candidate-only，需在文字中注明不是算法 proof）
- `analysis_baseline.algorithm_proven=false`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.runner_observe_only=true`
- `validation.analyzer_fixture_positive_ok=true`
- `validation.fixture_promotes_candidates_only=true`
- `validation.fixture_algorithm_proven_false=true`
- `validation.fixture_algorithm_status_not_recovered=true`
- `validation.status_json_tool_ok=true`
- `validation.project_memory_written=true`
- `validation.daily_memory_appended=true`
- `validation.session_state_appended=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_cross_window_opcode_keylane_promotion_checker_ready_for_live_validation`
- `deterministic_lane_influence_proven=false`
- `opcode_key_lane_promotion_proven=false`（真实 runtime proof 仍 false；fixture candidate 另记）
- `ttencrypt_terminal_binding_proven=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run observe-only critical_cross_window_promotion_core, collect repeated lane addr/value deltas plus same-thread 0x2bd8 ttEncrypt input/output hashes across windows, then prove deterministic influence and key/mode/IV/padding before pure reproduction`

### v238 cross-cluster key-lane terminal influence atlas 归档

当一轮基于 v235 influence probes、v236 opcode/key-lane backfills、v237 cross-window promotion clusters，合并生成 cross-cluster terminal influence atlas / observe-only checker / guarded runner / analyzer（例如 v238：4 个 terminal influence atlas、1 个 critical atlas、lane hook targets `0x2f74/0x2ff0/0x3048`、terminal boundary `libEncryptor.so:0x2bd8`），但未执行真实直播间动态 attach，应归档为“cross-cluster key-lane terminal influence atlas ready”，不是算法恢复。

关键经验：

- v238 这类阶段的核心价值是把上一轮 promotion/backfill/oracle 候选整合成跨 cluster 的 terminal influence atlas，用于后续真实直播间 observe-only 验证；`terminal_influence_atlas_count`、`critical_atlas_count`、`dynamic_pack_count`、`lane_hook_target_rvas` 都是准备度/候选规模，不是 runtime proof。
- analyzer fixture-positive 可以证明分析器能识别 terminal influence candidate；若 `strict_evidence_event_count=0`、`algorithm_proven=false`，必须保持 `algorithm_status=not_recovered`，不能把 fixture candidate 当真实算法证据。
- 归档验证应覆盖：static/runner/analyzer `py_compile`，static/matrix/status JSON `json.tool`，runner dry-run，fixture-positive analyzer JSON，project memory/daily/SESSION 写入，`memory-sync.py sync`，精确 memory search 命中，残留进程检查（如 `static_v238|run_v238|analyze_v238|v238_.*frida|frida.*aweme`）。
- status final check 应显式验证：`status=completed`、`v238_archived=true`、`algorithm_status=not_recovered`、`dynamic_execution_performed=false`、`strict_evidence_event_count=0`、`proven_algorithm_evidence=false`、`analysis_baseline.algorithm_proven=false`、`validation.status_json_tool_ok=true`、`memory_sync_ok=true`、`memory_search_v238_hit=true`、`no_residual_process=true`。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、repeated lane addr/value delta、same-thread/same-window `0x2bd8` ttEncrypt input/output hash、X-Cylons/security header carry、key/mode/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=cross-cluster-keylane-terminal-influence-atlas-static-and-dryrun-validation`
- `v*_archived=true`
- `v*_cross_cluster_keylane_terminal_influence_atlas_ready=true`
- `counts.terminal_influence_atlas_count`
- `counts.critical_atlas_count`
- `counts.dynamic_pack_count`
- `lane_hook_target_rvas=["0x2f74","0x2ff0","0x3048"]`
- `tt_encrypt_boundary.byte_pointer_transform_callee_rva=0x2bd8`
- `dynamic_influence_atlas_packs`
- `top_terminal_influence_atlas`
- `analysis_baseline.fixture_event_count`
- `analysis_baseline.fixture_lane_leave_count`
- `analysis_baseline.fixture_ttencrypt_event_count`
- `analysis_baseline.fixture_same_thread_terminal_window_count`
- `analysis_baseline.fixture_atlas_window_group_count`
- `analysis_baseline.fixture_terminal_influence_candidate_count`
- `analysis_baseline.strict_evidence_event_count=0`
- `analysis_baseline.algorithm_proven=false`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.runner_observe_only=true`
- `validation.analyzer_fixture_positive_ok=true`
- `validation.fixture_promotes_candidates_only=true`
- `validation.fixture_algorithm_proven_false=true`
- `validation.fixture_algorithm_status_not_recovered=true`
- `validation.status_json_tool_ok=true`
- `validation.project_memory_written=true`
- `validation.daily_memory_appended=true`
- `validation.session_state_appended=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_cross_cluster_terminal_influence_atlas_ready_for_live_validation`
- `deterministic_lane_influence_proven=false`
- `opcode_key_lane_terminal_influence_proven=false`
- `ttencrypt_terminal_binding_proven=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run observe-only critical_terminal_influence_atlas_core, collect repeated lane addr/value deltas plus same-thread 0x2bd8 ttEncrypt input/output hashes and X-Cylons/security header carry, then prove deterministic influence and key/mode/IV/padding before pure reproduction`

### v239 terminal influence consistency oracle 静态/动态准备归档

当一轮基于 v238 cross-cluster terminal influence atlas、v237 promotion clusters、v236 opcode/key-lane backfills，把 terminal influence atlas 进一步编译成 observe-only terminal influence consistency oracle / guarded runner / analyzer（例如 v239：4 个 terminal consistency oracles、1 个 critical oracle、lane hook targets `0x2f74/0x2ff0/0x3048`、terminal boundary `libEncryptor.so:0x2bd8`），但未执行真实直播间动态 attach，应归档为“terminal influence consistency oracle package ready”，不是算法恢复。

关键经验：

- v239 这类阶段的核心价值是把上一轮 terminal influence atlas 提升成可重复窗口一致性检查：要求未来在同线程/同请求窗口内观测 lane addr/value delta 与 `0x2bd8` ttEncrypt input/output hash 的 repeated consistency；`terminal_consistency_oracle_count`、`critical_oracle_count`、`lane_hook_target_count`、`dynamic_pack_count` 都是验证包准备度，不是 runtime proof。
- 典型字段可写入 status/project memory：`v238_terminal_influence_atlas_count=4`、`v237_promotion_cluster_count=4`、`v236_backfill_count=18`、`terminal_consistency_oracle_count=4`、`critical_oracle_count=1`、`high_oracle_count=3`、`lane_hook_target_count=3`、`dynamic_pack_count=4`。
- analyzer fixture-positive 可以证明分析器能识别 `terminal_consistency_candidate`；但若 `strict_evidence_event_count=0`、`algorithm_proven=false`，必须保持 `algorithm_status=not_recovered`，不能把 fixture candidate 当真实算法证据。
- runner dry-run 应显示 observe-only 与双门控：缺少 `--i-understand-dynamic-hook` 或真实 `--live-room-proof` 时，只输出 manual Frida command / dry-run，不执行 attach。
- 归档验证应覆盖：static/matrix/status JSON `json.tool`，static/runner/analyzer `py_compile`，`--list-packs`，runner dry-run，analyzer fixture-positive JSON，project memory/daily/SESSION 写入，`memory-sync.py sync`，精确 memory search 命中，残留进程检查（如 `static_v239|run_v239|analyze_v239|v239_.*frida|frida.*aweme`）。
- `memory-sync.py search "v239 terminal influence consistency oracle algorithm_status not_recovered"` Top1 命中新 project memory，可作为语义层可检索验证；sync 日志应包含 `projects/2026-05-20_project_douyin-xcylons-v239-terminal-influence-consistency-oracle.md`。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、repeated lane addr/value delta、same-thread/same-window `0x2bd8` ttEncrypt input/output hash、X-Cylons/security header carry、key/mode/IV/padding binding、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=terminal-influence-consistency-oracle-static-and-dryrun-validation`
- `v*_archived=true`
- `v*_terminal_influence_consistency_oracle_ready=true`
- `counts.v238_terminal_influence_atlas_count`
- `counts.v237_promotion_cluster_count`
- `counts.v236_backfill_count`
- `counts.terminal_consistency_oracle_count`
- `counts.critical_oracle_count`
- `counts.high_oracle_count`
- `counts.lane_hook_target_count`
- `counts.dynamic_pack_count`
- `lane_hook_target_rvas=["0x2f74","0x2ff0","0x3048"]`
- `tt_encrypt_boundary.byte_pointer_transform_callee_rva=0x2bd8`
- `dynamic_consistency_packs`
- `top_terminal_consistency_oracles`
- `analysis_baseline.fixture_event_count`
- `analysis_baseline.fixture_lane_event_count`
- `analysis_baseline.fixture_ttencrypt_event_count`
- `analysis_baseline.fixture_terminal_consistency_candidate_count`
- `analysis_baseline.strict_evidence_event_count=0`
- `analysis_baseline.algorithm_proven=false`
- `analysis_baseline.algorithm_status=not_recovered`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.runner_observe_only=true`
- `validation.analyzer_fixture_positive_ok=true`
- `validation.fixture_promotes_candidates_only=true`
- `validation.fixture_algorithm_proven_false=true`
- `validation.fixture_algorithm_status_not_recovered=true`
- `validation.status_json_tool_ok=true`
- `validation.project_memory_written=true`
- `validation.daily_memory_appended=true`
- `validation.session_state_appended=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_terminal_influence_consistency_oracle_ready_for_live_validation`
- `deterministic_lane_influence_proven=false`
- `terminal_influence_consistency_proven=false`
- `ttencrypt_terminal_binding_proven=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run observe-only critical_terminal_consistency_core/high_terminal_consistency_repeat, collect repeated lane addr/value deltas plus same-thread 0x2bd8 ttEncrypt input/output hashes and X-Cylons/security header carry, then prove deterministic influence and key/mode/IV/padding before pure reproduction`

### v241 terminal carry proof ledger 归档

当一轮基于 v240 terminal consistency → X-Cylons/security-header carry checker，把 lane delta、`libEncryptor.so:0x2bd8` ttEncrypt terminal IO、X-Cylons/security-header carry 的同线程/同请求窗口候选进一步整理成 proof ledger / observe-only ledger runner / analyzer（例如 v241），但仍未执行真实直播间动态 attach，应归档为“terminal carry proof ledger ready”，不是算法恢复。

关键经验：

- v241 这类阶段的核心价值是把 v240 的 carry checker 转成可审计 proof ledger：为后续真实采样记录每个 terminal/carry/lane relation 的窗口、hash、thread、request/header carry 证明字段；`contract_count`、`ledger_entry_count`、`carry_relation_count`、dynamic pack count 只是验证账本准备度，不是 runtime proof。
- analyzer fixture-positive / synthetic positive 只能证明分析器能识别 proof-ledger candidate；如果 `strict_evidence_event_count=0`、`algorithm_proven=false`，必须保持 `algorithm_status=not_recovered`，不能把 fixture candidate 当真实算法证据。
- 归档验证应覆盖：static/matrix/status JSON `json.tool`，static/runner/analyzer `py_compile`，`--list-packs`，runner dry-run，fixture-positive analyzer JSON，project memory/daily/SESSION 写入，`memory-sync.py sync`，精确 memory search Top1/Top5 命中，残留进程检查。
- 残留进程检查可用：`ps -ef | grep -E 'static_v241|run_v241|analyze_v241|v241_.*frida|frida.*aweme|terminal_carry_proof_ledger' | grep -v grep || true`。常驻 `frida-mobile-mcp`、ADB 启动的设备侧 `frida-server` 属于共享基础设施；只有本轮 `static_v241/run_v241/analyze_v241/v241_.*frida/frida.*aweme/terminal_carry_proof_ledger` 命中才算 v241 残留。
- status final check 应显式验证：`status=completed`、`v241_archived=true`、`algorithm_status=not_recovered`、`dynamic_execution_performed=false`、`strict_evidence_event_count=0`、`proven_algorithm_evidence=false`、`validation.status_json_tool_ok=true`、`memory_sync_ok=true`、`memory_search_v241_hit=true`、`no_residual_process=true`。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、repeated lane addr/value delta、same-thread/same-window `0x2bd8` ttEncrypt input/output hash、`X-Cylons`/security-header carry 对齐、key/mode/IV/padding 绑定、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=terminal-carry-proof-ledger-static-and-dryrun-validation`
- `v*_archived=true`
- `v*_terminal_carry_proof_ledger_ready=true`
- `counts.terminal_consistency_oracle_count`
- `counts.carry_checker_count`
- `counts.proof_ledger_contract_count` / `counts.ledger_contract_count`
- `counts.critical_ledger_contract_count`
- `lane_hook_target_rvas=["0x2f74","0x2ff0","0x3048"]`
- `tt_encrypt_boundary.byte_pointer_transform_callee_rva=0x2bd8`
- `analysis_baseline.fixture_ledger_candidate_count`
- `analysis_baseline.strict_evidence_event_count=0`
- `analysis_baseline.algorithm_proven=false`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.runner_observe_only=true`
- `validation.analyzer_fixture_positive_ok=true`
- `validation.fixture_promotes_candidates_only=true`
- `validation.status_json_tool_ok=true`
- `validation.project_memory_written=true`
- `validation.daily_memory_appended=true`
- `validation.session_state_appended=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_terminal_carry_proof_ledger_ready_for_live_validation`
- `terminal_influence_consistency_proven=false`
- `xcylons_security_header_carry_proven=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run observe-only critical_terminal_carry_proof_core / terminal_consistency_xcylons_header_carry / combined_terminal_carry_ledger, collect repeated lane deltas plus same-thread 0x2bd8 ttEncrypt IO hashes and header carry, then prove deterministic influence and key/mode/IV/padding before pure reproduction`

### v240 terminal consistency → X-Cylons/security-header carry checker 归档

当一轮基于 v239 terminal influence consistency oracle，把 same-thread/same-window `0x2bd8` ttEncrypt terminal consistency 进一步接到 `X-Cylons` / security-header carry 观测链，生成 observe-only carry checker / guarded runner / analyzer（例如 v240），但未执行真实直播间动态 attach，应归档为“terminal consistency → X-Cylons/security-header carry checker ready”，不是算法恢复。

关键经验：

- v240 这类阶段的核心价值是把 terminal consistency oracle 扩展到 header carry 验证：后续需在真实直播间同线程/同请求窗口内同时观测 lane addr/value delta、`libEncryptor.so:0x2bd8` ttEncrypt input/output hash、`X-Cylons` 或 security-header carry；静态 checker/fixture/dry-run 只是准备度，不是 runtime proof。
- analyzer fixture-positive 可以证明分析器能识别 carry candidate；如果 `strict_evidence_event_count=0`、`algorithm_proven=false`，必须保持 `algorithm_status=not_recovered`，不能把 fixture candidate 当真实算法证据。
- 归档验证应覆盖：static/matrix/status JSON `json.tool`，static/runner/analyzer `py_compile`，runner dry-run，fixture-positive analyzer JSON，project memory/daily/SESSION 写入，`memory-sync.py sync`，精确 memory search 命中，残留进程检查。
- 残留进程检查可用：`ps -ef | grep -E 'static_v240|run_v240|analyze_v240|v240_.*frida|frida.*aweme|terminal_consistency_xcylons_carry' | grep -v grep || true`。常驻 `frida-mobile-mcp`、ADB 启动的设备侧 `frida-server` 属于共享基础设施；只有本轮 `static_v240/run_v240/analyze_v240/v240_.*frida/frida.*aweme/terminal_consistency_xcylons_carry` 命中才算 v240 残留。
- status final check 应显式验证：`status=completed`、`v240_archived=true`、`algorithm_status=not_recovered`、`dynamic_execution_performed=false`、`strict_evidence_event_count=0`、`proven_algorithm_evidence=false`、`validation.status_json_tool_ok=true`、`memory_sync_ok=true`、`memory_search_v240_hit=true`、`no_residual_process=true`。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、repeated lane addr/value delta、same-thread/same-window `0x2bd8` ttEncrypt input/output hash、`X-Cylons`/security-header carry 对齐、key/mode/IV/padding 绑定、pure reproduction 前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=terminal-consistency-xcylons-carry-checker-static-and-dryrun-validation`
- `v*_archived=true`
- `v*_terminal_consistency_xcylons_carry_checker_ready=true`
- `counts.terminal_consistency_oracle_count`
- `counts.carry_checker_count`
- `counts.critical_carry_checker_count`
- `lane_hook_target_rvas=["0x2f74","0x2ff0","0x3048"]`
- `tt_encrypt_boundary.byte_pointer_transform_callee_rva=0x2bd8`
- `analysis_baseline.fixture_carry_candidate_count`
- `analysis_baseline.strict_evidence_event_count=0`
- `analysis_baseline.algorithm_proven=false`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.runner_observe_only=true`
- `validation.analyzer_fixture_positive_ok=true`
- `validation.fixture_promotes_candidates_only=true`
- `validation.status_json_tool_ok=true`
- `validation.project_memory_written=true`
- `validation.daily_memory_appended=true`
- `validation.session_state_appended=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `first_seen_evidence=false`
- `new_value_source_evidence=false`
- `proven_algorithm_evidence=false`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_terminal_consistency_xcylons_carry_checker_ready_for_live_validation`
- `terminal_influence_consistency_proven=false`
- `xcylons_security_header_carry_proven=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run observe-only terminal consistency + X-Cylons/security-header carry packs, collect repeated lane deltas plus same-thread 0x2bd8 ttEncrypt IO hashes and header carry, then prove deterministic influence and key/mode/IV/padding before pure reproduction`

### v243 pure reproduction harness 静态/动态准备归档

当一轮基于 v242 terminal crypto parameter binding oracle，把 `libEncryptor.so:0x2bd8` terminal input/output、lane delta、X-Cylons/security-header carry 与候选 `key/mode/IV/padding` 组合成 observe-only pure reproduction harness / guarded runner / analyzer（例如 v243），但仍未执行真实直播间动态 attach，应归档为“pure reproduction harness ready”，不是算法恢复。

关键经验：

- v243 这类阶段的核心价值是把 crypto parameter oracle 转成可复验的纯算复现验证框架：采集 concrete terminal bytes、绑定 lane delta/header carry、枚举候选 key/mode/IV/padding，并用 heldout replay gate 检查纯算复现；这些都是准备度，不是 runtime proof。
- 典型字段可写入 status/project memory：`v242_crypto_parameter_oracle_count=4`、`pure_reproduction_hypothesis_count=4`、`critical_reproduction_hypothesis_count=1`、`high_reproduction_hypothesis_count=3`、`lane_hook_target_count=3`、`candidate_crypto_parameter_field_count=16`、`dynamic_pack_count=5`、`heldout_replay_gate_count=1`。
- Dynamic pack 建议保留：`critical_pure_reproduction_scaffold`、`mode_key_iv_padding_hypothesis_tests`、`dominant_lane_reproduction_projection`、`high_priority_reproduction_candidates`、`all_terminal_reproduction_harness`。
- analyzer fixture-positive 可以证明分析器能识别 reproduction candidate / heldout replay candidate；但如果 `strict_evidence_event_count=0`、`algorithm_proven=false` 或 `fixture_algorithm_proven_false=true`，必须保持 `algorithm_status=not_recovered`，不能把 fixture candidate 当真实算法证据。
- runner 必须保持 observe-only 与双门控：缺少 `--i-understand-dynamic-hook` 或真实 `--live-room-proof` 时只 dry-run / 输出 manual Frida command，不执行 attach。
- 归档验证应覆盖：static/matrix/status JSON `json.tool`，static/runner/analyzer `py_compile`，`--list-packs`，runner dry-run，analyzer fixture-positive JSON，project memory/daily/SESSION 写入，`memory-sync.py sync`，精确 memory search 命中，残留进程检查（如 `static_v243|run_v243|analyze_v243|v243_.*frida|frida.*aweme|pure_reproduction_harness`）。
- status final check 应显式验证：`status=completed`、`v243_archived=true`、`algorithm_status=not_recovered`、`dynamic_execution_performed=false`、`strict_evidence_event_count=0`、`pure_reproduction_ready=false`、`key_mode_iv_padding_bound=false`、`validation.runner_observe_only=true`、`validation.fixture_algorithm_proven_false=true`、`validation.memory_sync_ok=true`、`validation.memory_search_v243_hit=true`、`validation.no_residual_process=true`。
- 没有真实 `LivePlayActivity/webcast` 动态 attach、concrete `0x2bd8` terminal bytes、same-thread/same-window lane/header carry、key/mode/IV/padding 绑定、heldout pure reproduction 通过前，必须保持 `algorithm_status=not_recovered`。

建议字段：

- `phase=pure-reproduction-harness-static-and-dryrun-validation`
- `v*_archived=true`
- `v*_pure_reproduction_harness_ready=true`
- `counts.v242_crypto_parameter_oracle_count`
- `counts.pure_reproduction_hypothesis_count`
- `counts.critical_reproduction_hypothesis_count`
- `counts.high_reproduction_hypothesis_count`
- `counts.lane_hook_target_count`
- `counts.candidate_crypto_parameter_field_count`
- `counts.dynamic_pack_count`
- `counts.heldout_replay_gate_count`
- `dynamic_reproduction_packs`
- `top_pure_reproduction_hypotheses`
- `tt_encrypt_boundary.byte_pointer_transform_callee_rva=0x2bd8`
- `analysis_baseline.fixture_reproduction_candidate_count`
- `analysis_baseline.heldout_replay_candidate_count`
- `analysis_baseline.strict_evidence_event_count=0`
- `analysis_baseline.algorithm_proven=false`
- `validation.py_compile_ok=true`
- `validation.static_json_tool_ok=true`
- `validation.matrix_json_tool_ok=true`
- `validation.runner_dry_run_ok=true`
- `validation.runner_observe_only=true`
- `validation.analyzer_fixture_positive_ok=true`
- `validation.fixture_algorithm_proven_false=true`
- `validation.fixture_algorithm_status_not_recovered=true`
- `validation.status_json_tool_ok=true`
- `validation.project_memory_written=true`
- `validation.daily_memory_appended=true`
- `validation.session_state_appended=true`
- `validation.memory_sync_ok=true`
- `validation.memory_search_v*_hit=true`
- `validation.no_residual_process=true`
- `dynamic_execution_performed=false`
- `real_live_room_proof_present=false`
- `strict_evidence_event_count=0`
- `algorithm_status=not_recovered`
- `algorithm_boundary_status=static_pure_reproduction_harness_ready_for_live_validation`
- `ttencrypt_terminal_binding_proven=false`
- `tt_encrypt_input_output_bound=false`
- `key_mode_iv_padding_bound=false`
- `pure_reproduction_ready=false`
- `next_step=real LivePlayActivity/webcast foreground; run observe-only critical_pure_reproduction_scaffold, collect concrete terminal bytes + lane/header carry + candidate key/mode/IV/padding, then require heldout pure reproduction before upgrading algorithm_status`

## 汇报模板

```text
已完成动态日志分析与归档。

结论：gate 已通过，动态采样已执行，但 strict_evidence_event_count=0，因此 algorithm_status=not_recovered。

这轮是动态候选收敛，不是算法本体恢复。命中了 representation 层上下文，但没有同请求窗口 absent-before / first-after / downstream-carry 全门控，也没有与 X-Cylons/ACK/SSL/WS 对齐的 clean value-source。

已归档：
- analysis JSON: ...
- conclusion MD: ...
- status JSON: ...
- project memory: ...
```
