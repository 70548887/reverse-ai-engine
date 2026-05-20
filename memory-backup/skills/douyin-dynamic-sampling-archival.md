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
