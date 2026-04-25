---
name: reverse-ai-engine-pipeline
description: reverse-ai-engine 完整 Pipeline 跑通指南 — 从 task.json 到 memory-sync 归档
triggers:
  - 运行 reverse-controller.py
  - 跑 Web 逆向 Pipeline
  - browser-control.py 实现
  - memory-sync 归档
---

# reverse-ai-engine 跑通指南

## 架构概览

```
reverse-controller.py (主控制器)
  ├── 接受 task.json 文件（不是命令行参数！）
  ├── build_web_pipeline() → 9步骤 DAG
  └── execute_step() → 按 executor 类型分发

工具链（必须存在）:
  /opt/data/home/reverse-tools/
    ├── browser-control.py     ← 必须！Recon/Stealth/HookConsole 三合一
    ├── mitm-capture.sh        ← mitmproxy 抓包
    ├── apk-decompile.sh       ← APK 反编译
    └── frida-task.sh          ← Frida Hook

记忆归档:
  /opt/data/home/.openclaw/workspace/scripts/memory-sync.py
```

## 快速启动

### 1. 创建任务文件
```json
{
  "task_id": "your-task-id",
  "type": "web.js.signature",
  "priority": "high",
  "target": {
    "url": "https://target.example.com/api",
    "method": "POST",
    "known_params": ["appid", "timestamp", "sig"]
  },
  "actions": [],
  "notes": "任务说明"
}
```

### 2. 运行 Pipeline
```bash
cd /opt/data/home/.openclaw/workspace
python3 scripts/reverse-controller.py tasks/intake/your-task.json
```

### 3. 归档
```bash
python3 scripts/memory-sync.py your-task-id
# 或同步所有任务：
python3 scripts/memory-sync.py --all
```

## 工具说明

### browser-control.py（必须先实现）
Controller 的 codex executor 通过它调用 Playwright。
必须支持3个子命令：
```bash
python3 browser-control.py recon <url>         # 信息收集
python3 browser-control.py stealth <url>        # 隐身探测（WebDriver检测）
python3 browser-control.py hook-console <url>   # JS 定位 + console 日志捕获
```

注意：Playwright 私有属性（如 `_browser.contexts`）在版本间不稳定，`js_files` 直接从 `api_calls` 筛选 `.js` URL，不要用私有属性访问。

### mitm-capture.sh
```bash
mitm-capture.sh [--out capture.har] [--url target-url]
# 需要后台运行，按 Ctrl+C 停止
```

## 常见问题与修复

### ERROR: task file not found
Controller 接受 **task JSON 文件路径**，不是 `--flag value` 格式：
```bash
# 错误
python3 reverse-controller.py run --target xxx
# 正确
python3 reverse-controller.py tasks/intake/my-task.json
```

### 步骤找不到脚本
Pipeline 定义里 tool 路径必须用**绝对路径**：
```python
"tool": "/opt/data/home/reverse-tools/browser-control.py"
```

### Codex executor 只写文件不执行
原始实现是 stub，只写 instruction 文件。需要改 `execute_step()` 加真实脚本调用：
```python
if etype == "codex":
    if "browser-control" in script_tool:
        # 按 step_id 映射到子命令
        subcmd_map = {
            "recon": "recon",
            "browser_probe": "stealth",
            "js_locate": "hook-console",
        }
        cmd = ["python3", script_tool, subcmd_map[step_id], target_url]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        result["status"] = "verified" if r.returncode == 0 else "output_ready"
```

### memory-sync.py Qdrant 报错
Qdrant 服务偶发不稳定属正常，L5 Qdrant 同步失败不影响 L1/L3/L4 文件归档。

## 归档产出位置

Pipeline 结果：
```
/opt/data/home/.openclaw/workspace/tasks/status/<task_id>/
  ├── *.result.json          ← 每步骤结果
  └── *.instruction.md       ← Codex 执行指令（codex executor 生成）
```

记忆层归档：
```
/opt/data/home/.openclaw/workspace/memory/
  ├── YYYY-MM-DD.md                  ← L1 每日记忆
  └── projects/
      ├── <task_id>-auto-results.md  ← L3 原始结果归档
      └── <task_id>-auto-history.md  ← L4 状态轨迹镜像
```

Qdrant 向量：`152.136.169.127:6333` collection `reverse_engineering`

## 验证工具链健康
```bash
python3 /opt/data/home/reverse-tools/check-tools.py
```
