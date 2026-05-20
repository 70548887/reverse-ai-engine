---
name: douyin-live-gate-watcher-autoexec
description: 抖音直播动态采样前的 gate watcher/auto-exec 流程；在锁屏/通知栏/Splash 等阻断时避免误跑 Frida，等真实直播间稳定后自动委派最小采样
triggers:
  - 抖音直播 gate 阻断
  - Douyin LivePlayActivity watcher
  - X-Cylons dynamic sampling gate
  - dynamic_execution_performed=false
---

# Douyin Live Gate Watcher / Auto-Exec

用于抖音直播 X-Cylons 动态验证阶段：当设备未解锁、停在通知栏/锁屏/Splash/Launcher/权限页时，不要直接跑 Frida focused pack。先用 watcher 轮询系统前台状态，等真实直播间稳定后再自动委派最小动态采样。

## 触发条件

- 当前 status 显示 `v*_live_entry_ready=false` 或 `dynamic_execution_allowed=false`。
- `dumpsys power` 含 `Dozing` / asleep。
- `dumpsys window windows` 含 `NotificationShade`、`Keyguard`、`StatusBar`。
- `dumpsys activity activities` 仍是 `com.ss.android.ugc.aweme/.splash.SplashActivity`、Launcher、PermissionController 等。
- 用户要求“继续挖掘”，但当前没有真实直播间前台证明。

## Watcher 判据

每轮采样至少检查：

```bash
adb shell pidof com.ss.android.ugc.aweme
adb shell dumpsys power | grep -E "mWakefulness|Display Power" -A2
adb shell dumpsys activity activities | grep -E "ResumedActivity|topResumedActivity|mResumedActivity" | head -20
adb shell dumpsys window windows | grep -E "mCurrentFocus|mFocusedApp|NotificationShade|Keyguard|StatusBar" | head -30
```

hard blockers：

- `dozing`
- `lockscreen` / `keyguard`
- `notification_shade`
- `splash`
- `launcher`
- `permission`

放行条件：连续 N 次（建议 3 次）满足：

1. 抖音进程存在；
2. 前台文本含 `com.ss.android.ugc.aweme`；
3. 前台/窗口含真实直播间线索，如 `LivePlayActivity`、`webcast`、`live`；
4. hard blockers 为空。

## 推荐 auto-exec 命令模板

生成 runner 后，dry-run：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 run_vXXX_gate_watcher_autoexec_package_YYYYMMDD.py \
  --watch \
  --dry-run \
  --interval 0.2 \
  --max-samples 3 \
  --stable-count 2
```

等操作者手动解锁并进入真实直播间后执行：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 run_vXXX_gate_watcher_autoexec_package_YYYYMMDD.py \
  --watch \
  --execute \
  --interval 1 \
  --max-samples 600 \
  --stable-count 3

python3 analyze_vXXX_autoexec_candidate_logs_YYYYMMDD.py \
  vXXX_autoexec_logs_YYYYMMDD/*.jsonl \
  --out vXXX_autoexec_logs_YYYYMMDD/analysis.json
```

委派目标通常是上一轮已验证的最小采样入口，例如：

```bash
python3 run_v164_unlock_live_entry_sentinel_20260519.py --execute-v163-minimal --samples 3 --delay 0.2
```

## 归档与验证

必须生成/检查：

- `run_vXXX_gate_watcher_autoexec_package_YYYYMMDD.py`
- `analyze_vXXX_autoexec_candidate_logs_YYYYMMDD.py`
- `vXXX_gate_watcher_autoexec_package_matrix_YYYYMMDD.json`
- `vXXX_gate_watcher_autoexec_package_static_YYYYMMDD.{json,md}`
- `vXXX_gate_watcher_autoexec_package_conclusion_YYYYMMDD.md`
- `tasks/status/douyin_xcylons_vXXX_YYYYMMDD.json`
- `memory/projects/YYYY-MM-DD_project_douyin-xcylons-vXXX-*.md`

验证：

```bash
python3 -m py_compile run_vXXX_gate_watcher_autoexec_package_YYYYMMDD.py analyze_vXXX_autoexec_candidate_logs_YYYYMMDD.py
python3 analyze_vXXX_autoexec_candidate_logs_YYYYMMDD.py vXXX_autoexec_logs_YYYYMMDD/*.jsonl --out vXXX_autoexec_logs_YYYYMMDD/analysis_verify.json
cd /opt/data/home/.openclaw/workspace
python3 memory/scripts/memory-sync.py sync
python3 memory/scripts/memory-sync.py search "douyin-xcylons-vXXX gate watcher autoexec"
```

## 算法状态边界

如果 gate 未通过或没有委派执行，必须保持：

```json
{
  "dynamic_execution_performed": false,
  "strict_evidence_event_count": 0,
  "first_seen_evidence": false,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "algorithm_status": "not_recovered"
}
```

不要把 `hook-ok`、Splash/锁屏/通知栏日志、或单纯的进程存在误判为 X-Cylons 算法证据。只有 strict analyzer 中出现同请求窗口的 absent-before / first-after / downstream-carry，并能与 X-Cylons、ACK、SSL/WS/hash 对齐，才允许提升算法状态。

## Live preview entry handling

如果截图/UIAutomator 不是完整直播间，而是抖音首页直播 Tab 的预览态，可增加一层 preview-entry gate（v179 模式）：

- 从 `adb shell uiautomator dump` 的 XML 中查找 `点击进入直播间` / `进入直播间`。
- 只有在明确找到该文本及 `bounds` 时，才允许 `adb shell input tap <center>`；不要盲点固定坐标。
- 点击 preview entry 后仍要连续 N 次验证真实直播间 proof，不能把“已点击入口”视作 X-Cylons 动态证据。
- 如果 dumpsys 仍显示 `SplashActivity`，但 UI XML 明确出现首页底栏/直播预览入口，可将 splash 视为 soft blocker；但只有真实直播间 marker（如 `LivePlayActivity` / `webcast`，或 UI 上 `说点什么`、`礼物`、`粉丝团` 等多项直播间控件）稳定出现后，才允许委派 focused Frida。
- 当前页面若同时存在 permission/login/keyguard/notification_shade，仍要拒绝点击和拒绝 hook，归类为 operator handoff。

## 已知坑

- 在 `execute_code` 中嵌套大段 Python 脚本、三引号、Markdown 反引号和 shell heredoc 容易引入缩进或 `from __future__` 位置错误。生成 runner/analyzer 时更稳的方式是用 `write_file` 分别写独立文件，再 `py_compile` 验证。
- analyzer 需要把 gate samples、stable-ready、delegated execution、strict evidence 分开统计；不要只看日志文件存在。
- `KEYCODE_WAKEUP` / `KEYCODE_BACK` / `cmd statusbar collapse` / `wm dismiss-keyguard` / `monkey -p com.ss.android.ugc.aweme` 这类 best-effort recovery 只能清理锁屏、通知栏或拉起 App，不能保证从 `SplashActivity` 进入真实直播间。若恢复后仍是 `com.ss.android.ugc.aweme/.splash.SplashActivity` 且 `live_hint=false`，必须继续拒绝动态 hook，判定为 operator handoff，而不是强行执行 Frida。
- 汇总多轮日志时，历史文件里可能残留早先的 `stable-live-room-proof` 或 `delegating-v169` 计数；最终结论必须以 `dynamic_execution_performed`、委派返回结果、最新 `last_hard_blockers`、以及 strict evidence 为准。若最新 gate 仍是 `hard_blockers=["splash"]` 且 strict evidence 为 0，算法状态仍保持 `not_recovered`。
- 如果新版 focused gate 已经基于可见/focus 状态放行真实直播间，但旧下游脚本又用 broad blocker 报 `dozing`/`permission`/`keyguard` 等误阻断，可采用 v181 模式：由新版 runner 记录 `gate_passed_by_vXXX=true` 和 `*_broad_blocker_bypassed=true`，直接委派 focused SSL/WS/X-Cylons pack；同时计划把新版 focused gate 下沉到旧 pack 的 preflight，避免后续被旧 gate 反向覆盖。
