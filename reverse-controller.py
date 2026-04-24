#!/usr/bin/env python3
"""
reverse-controller.py — 逆向引擎大脑
Web & App 逆向任务调度器，基于 docs/03-控制器设计.md 的状态机

用法:
    python3 reverse-controller.py web <url> [--task-id NAME]
    python3 reverse-controller.py app <apk_path> [--task-id NAME]
    python3 reverse-controller.py status [--task-id NAME]
    python3 reverse-controller.py list
"""

import argparse
import json
import hashlib
import sys
import os
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# ── Qdrant 向量库配置 ────────────────────────────────────────────
QDRANT_URL = "http://152.136.169.127:6333"
QDRANT_API_KEY = "3e54af769c101f6b6fdc88d642e36d7adda8d8246140b7168c3d5296a0fc2c60"
COLLECTION = "reverse_engineering"
VECTOR_DIM = 512

# ── 本地路径配置 ────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
WORKSPACE = Path("/opt/data/home/.openclaw/workspace")
MEMORY_DIR = WORKSPACE / "memory"
TASKS_DIR = WORKSPACE / "tasks"
SESSION_FILE = WORKSPACE / "SESSION-STATE.md"

# ─────────────────────────────────────────────────────────────────
# 向量嵌入（用本地 FastEmbed 模型，避免 OpenAI API 依赖）
# ─────────────────────────────────────────────────────────────────
def get_embedding(text: str) -> list[float]:
    """生成文本向量用于 Qdrant 存储"""
    try:
        from fastembed import TextEmbedding
        model = TextEmbedding(model_name="BAAI/bge-small-zh-v1.5")
        emb = list(model.embed([text]))[0]
        return emb
    except ImportError:
        # fallback: 纯文本存储，无向量
        return [0.0] * VECTOR_DIM


def get_embedding_bypass(text: str) -> list[float]:
    """跳过 FastEmbed，用 random projection 作为 fallback"""
    import random
    h = hashlib.sha256(text.encode()).digest()
    rng = random.Random(int.from_bytes(h[:4], "big"))
    return [rng.uniform(-1, 1) for _ in range(VECTOR_DIM)]


# ─────────────────────────────────────────────────────────────────
# Qdrant 操作
# ─────────────────────────────────────────────────────────────────
def qdrant_connect():
    from qdrant_client import QdrantClient
    return QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY)


def generate_point_id(task_id: str, stage: str) -> str:
    """生成合法的 Qdrant point ID（UUID 格式）"""
    import uuid
    raw = f"{task_id}_{stage}"
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, raw))


def upsert_to_qdrant(task_id: str, stage: str, content: str, metadata: dict):
    """将逆向结果存入 Qdrant 向量库"""
    try:
        client = qdrant_connect()
        # 生成 512 维向量（FastEmbed 或 fallback）
        try:
            vector = get_embedding(content)
        except Exception:
            vector = get_embedding_bypass(content)
        point_id = generate_point_id(task_id, stage)
        client.upsert(
            collection_name=COLLECTION,
            points=[{
                "id": point_id,
                "vector": {"dense_vector": vector},
                "payload": {
                    "task_id": task_id,
                    "stage": stage,
                    "content": content[:8000],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **metadata
                }
            }]
        )
        print(f"  ✅ Qdrant 写入成功: {point_id}")
        return True
    except Exception as e:
        print(f"  ⚠️ Qdrant 写入失败: {e}")
        return False


# ─────────────────────────────────────────────────────────────────
# 任务状态管理
# ─────────────────────────────────────────────────────────────────
class TaskState:
    """在本地文件系统管理任务状态"""

    def __init__(self, task_id: str):
        self.task_id = task_id
        self.state_dir = TASKS_DIR / task_id
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.meta_file = self.state_dir / "task-meta.json"
        self.state_file = self.state_dir / "state.json"

    def init(self, task_type: str, target: str):
        meta = {
            "task_id": self.task_id,
            "type": task_type,
            "target": target,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "intake",
            "steps": {},
            "pipeline": [],
        }
        self._save_meta(meta)
        self._save_state({"status": "intake", "blocker": None})
        return meta

    def load(self) -> dict:
        return json.loads(self.meta_file.read_text())

    def _save_meta(self, meta: dict):
        self.meta_file.write_text(json.dumps(meta, indent=2, ensure_ascii=False, default=str))

    def _save_state(self, state: dict):
        self.state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False, default=str))

    def update(self, step: str, status: str, result: Optional[dict] = None, error: Optional[str] = None):
        meta = self.load()
        meta["steps"][step] = {
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            **(result or {}),
            **({} if not error else {"error": error}),
        }
        if error:
            meta["status"] = "failed"
            meta["blocker"] = error
        elif status == "done":
            meta["status"] = "reversing"
        elif status == "verified":
            meta["status"] = "verified"
        self._save_meta(meta)
        self._save_state({"status": meta["status"], "blocker": meta.get("blocker")})

    def archive(self):
        """归档到 memory 层 + Qdrant"""
        meta = self.load()
        task_dir = MEMORY_DIR / "projects" / meta["type"] / self.task_id
        task_dir.mkdir(parents=True, exist_ok=True)

        # 镜像所有步骤结果到 memory 层
        for step_name, step_data in meta.get("steps", {}).items():
            step_file = task_dir / f"{step_name}-result.json"
            step_file.write_text(json.dumps(step_data, indent=2, ensure_ascii=False, default=str))

        # Qdrant 归档（整体摘要）
        summary = f"逆向任务 {self.task_id} 类型 {meta['type']} 目标 {meta['target']} 状态 {meta['status']}"
        for step_name, step_data in meta.get("steps", {}).items():
            summary += f" | {step_name}: {step_data.get('status', 'unknown')}"
        upsert_to_qdrant(self.task_id, "archive", summary, {
            "type": meta["type"],
            "target": meta["target"],
            "status": meta["status"],
        })

        # 更新 SESSION-STATE.md
        self._update_session_state(meta)

    def _update_session_state(self, meta: dict):
        """追加记录到 SESSION-STATE.md"""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        marker = f"## [{ts}] {self.task_id}"
        lines = [
            f"{marker} | type={meta['type']} | target={meta['target']} | status={meta['status']}",
        ]
        for step, data in meta.get("steps", {}).items():
            lines.append(f"  - {step}: {data.get('status')}")
        entry = "\n".join(lines) + "\n"

        if SESSION_FILE.exists():
            content = SESSION_FILE.read_text()
        else:
            content = "# SESSION-STATE.md — 热记忆层\n\n"
        SESSION_FILE.write_text(content + entry)


# ─────────────────────────────────────────────────────────────────
# Pipeline 定义
# ─────────────────────────────────────────────────────────────────
WEB_PIPELINE = [
    {"step": "recon",      "label": "信息收集",    "tool": "browser-control.py"},
    {"step": "capture",    "label": "抓包分析",    "tool": "mitmproxy"},
    {"step": "probe",      "label": "浏览器探测",  "tool": "browser-control.py"},
    {"step": "js_locate",  "label": "JS 定位",     "tool": "browser-control.py"},
    {"step": "reverse",    "label": "逆向分析",    "tool": "Codex/M2.7"},
    {"step": "implement",  "label": "脚本生成",    "tool": "Codex/M2.7"},
    {"step": "verify",     "label": "签名验证",    "tool": "verify-signature.py"},
    {"step": "archive",    "label": "归档",        "tool": "controller"},
]

# ── 方案一：Browser Hook Pipeline（xhs-hook-sign.py）─────────────
# 跳过 Step 5 逆向分析，直接通过浏览器 Hook 调用 window.mnsv2
# 详见 docs/03-控制器设计.md §3.2.1
WEB_HOOK_PIPELINE = [
    {"step": "hook_detect",    "label": "Hook 探测",     "tool": "xhs-hook-sign.py"},
    {"step": "hook_sign",      "label": "Hook 获取签名",  "tool": "xhs-hook-sign.py"},
    {"step": "implement_hook", "label": "生成包装脚本",  "tool": "xhs-hook-sign.py"},
    {"step": "verify",         "label": "签名验证",      "tool": "verify-signature.py"},
    {"step": "archive",        "label": "归档",          "tool": "controller"},
]

APP_PIPELINE = [
    {"step": "apk_fetch",  "label": "APK 获取",   "tool": "APKTool/JADX"},
    {"step": "mitm_cap",   "label": "抓包",        "tool": "mitmproxy"},
    {"step": "frida_hook", "label": "Frida Hook", "tool": "frida-task.sh"},
    {"step": "so_analyze", "label": "SO 分析",     "tool": "IDA/Ghidra"},
    {"step": "implement",  "label": "脚本生成",    "tool": "Codex/M2.7"},
    {"step": "verify",     "label": "签名验证",    "tool": "verify-signature.py"},
    {"step": "archive",    "label": "归档",        "tool": "controller"},
]


# ─────────────────────────────────────────────────────────────────
# 任务队列（intake）
# ─────────────────────────────────────────────────────────────────
def queue_task(task_id: str):
    intake_dir = TASKS_DIR / "intake"
    intake_dir.mkdir(parents=True, exist_ok=True)
    marker = intake_dir / f"{task_id}.json"
    if not marker.exists():
        marker.write_text(json.dumps({"task_id": task_id, "queued_at": datetime.now(timezone.utc).isoformat()}))
    print(f"📋 任务已加入队列: {task_id}")


# ─────────────────────────────────────────────────────────────────
# 执行器（根据工具类型分发）
# ─────────────────────────────────────────────────────────────────
def execute_step(step: dict, task_state: TaskState) -> dict:
    """执行单个 Pipeline 步骤"""
    step_name = step["step"]
    tool = step["tool"]

    print(f"\n🔧 [{step_name}] {step['label']} → 工具: {tool}")

    # 目前仅 verify 步骤有工具桩，其他步骤需要人工/子代理介入
    if tool == "verify-signature.py":
        return execute_verify(task_state)
    elif tool == "controller":
        task_state.archive()
        return {"status": "done", "note": "已归档到 memory 层 + Qdrant"}
    elif tool == "mitmproxy":
        return {"status": "pending", "note": "需要手动启动 mitmproxy 抓包，参考: bash tools/mitm-capture.sh"}
    elif tool in ("Codex/M2.7", "Codex"):
        return {"status": "pending", "note": f"需要子代理执行逆向分析: {step_name}"}
    elif tool in ("browser-control.py",):
        return {"status": "pending", "note": f"browser-control.py 工具桩已创建，需在 fix2 完成后使用"}
    elif tool == "xhs-hook-sign.py":
        return execute_hook_step(step_name, task_state)


def execute_hook_step(step_name: str, task_state: TaskState) -> dict:
    """执行 xhs-hook-sign.py 的各个子步骤"""
    hook_script = BASE_DIR / "tools" / "xhs-hook-sign.py"
    if not hook_script.exists():
        return {"status": "failed", "error": f"xhs-hook-sign.py 未找到: {hook_script}"}

    meta = task_state.load()
    target_url = meta.get("target", "")
    task_id = task_state.task_id

    import subprocess

    if step_name == "hook_detect":
        # Step H1: 探测 mnsv2 是否可用
        output_path = task_state.state_dir / "hook-detect.json"
        try:
            result = subprocess.run(
                [
                    sys.executable, str(hook_script), "run",
                    "--url", target_url,
                    "--method", "POST",
                    "--body", "{}",
                    "--output", str(output_path),
                ],
                capture_output=True, text=True, timeout=120
            )
            # 读取探测结果
            if output_path.exists():
                detect_result = json.loads(output_path.read_text())
                mnsv2_available = detect_result.get("mnsv2_status", {}).get("success", False)
                if not mnsv2_available:
                    candidates = detect_result.get("mnsv2_status", {}).get("candidates", [])
                    return {
                        "status": "failed",
                        "error": f"mnsv2 不可用，候选函数: {candidates}",
                        "detect_data": detect_result,
                    }
            return {
                "status": "done",
                "output": str(output_path),
                "stdout": result.stdout[:500],
                "stderr": result.stderr[:300],
            }
        except subprocess.TimeoutExpired:
            return {"status": "failed", "error": "Hook 探测超时（120s）"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    elif step_name == "hook_sign":
        # Step H2: 获取签名（运行 run 命令）
        output_path = task_state.state_dir / "hook-sign-result.json"
        sig_script = task_state.state_dir / "xhs-signature.py"
        try:
            result = subprocess.run(
                [
                    sys.executable, str(hook_script), "run",
                    "--url", target_url,
                    "--method", "POST",
                    "--body", '{"keyword":"test"}',
                    "--output", str(output_path),
                ],
                capture_output=True, text=True, timeout=120
            )
            return {
                "status": "done",
                "output": str(output_path),
                "stdout": result.stdout[:500],
            }
        except subprocess.TimeoutExpired:
            return {"status": "failed", "error": "Hook 签名超时（120s）"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    elif step_name == "implement_hook":
        # Step H3: 生成 Python 包装脚本
        output_script = task_state.state_dir / "xhs-signature.py"
        try:
            result = subprocess.run(
                [
                    sys.executable, str(hook_script), "generate-script",
                    "--url", target_url,
                    "--method", "POST",
                    "--output", str(output_script),
                ],
                capture_output=True, text=True, timeout=30
            )
            return {
                "status": "done",
                "script_path": str(output_script),
                "stdout": result.stdout[:500],
                "usage": "XHSSigner().sign(path, body)  # 同步调用",
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    else:
        return {"status": "failed", "error": f"未知 Hook 步骤: {step_name}"}


def execute_verify(task_state: TaskState) -> dict:
    """运行 verify-signature.py 验证签名"""
    sig_script = BASE_DIR / "tools" / "verify-signature.py"
    sig_script_local = BASE_DIR / "verify-signature.py"
    target_script = sig_script if sig_script.exists() else sig_script_local

    if not target_script.exists():
        return {
            "status": "failed",
            "error": f"verify-signature.py 未找到，请先生成签名脚本",
            "script_path": str(target_script),
        }

    import subprocess
    try:
        result = subprocess.run(
            [sys.executable, str(target_script)],
            capture_output=True, text=True, timeout=60
        )
        return {
            "status": "done",
            "stdout": result.stdout[:1000],
            "stderr": result.stderr[:500],
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "验证超时（60s）"}
    except Exception as e:
        return {"status": "failed", "error": str(e)}


# ─────────────────────────────────────────────────────────────────
# 主运行逻辑
# ─────────────────────────────────────────────────────────────────
def run_web_task(task_id: str, url: str, method: str = "standard"):
    """
    执行 Web 逆向任务

    Args:
        method: "standard" = 标准 Pipeline（逆向 JS 算法）
                "hook"    = 方案一 Pipeline（Browser Hook，直接调 mnsv2）
    """
    pipeline_name = "🌐 标准" if method == "standard" else "🪝 Hook"
    print(f"\n{'='*60}")
    print(f"{pipeline_name} Web 逆向任务启动")
    print(f"   任务ID: {task_id}")
    print(f"   目标:   {url}")
    print(f"   方案:   {'标准逆向' if method == 'standard' else 'Browser Hook'}")
    print(f"{'='*60}")

    ts = TaskState(task_id)
    ts.init("web", url)
    meta = ts.load()
    meta["pipeline_method"] = method
    ts._save_meta(meta)
    queue_task(task_id)

    # 根据方案选择 Pipeline
    pipeline = WEB_HOOK_PIPELINE if method == "hook" else WEB_PIPELINE

    for i, step in enumerate(pipeline):
        result = execute_step(step, ts)
        status = result.get("status", "unknown")

        if step["step"] == "archive":
            ts.update(step["step"], "done", result)
        else:
            ts.update(step["step"], status, result)

        if status == "failed":
            print(f"\n❌ 步骤 {step['step']} 失败: {result.get('error', 'unknown')}")
            break
        elif status == "pending":
            print(f"⏸️  步骤 {step['step']} 等待 (工具待实现或需人工)")
        else:
            print(f"✅ 步骤 {step['step']} 完成")

    meta = ts.load()
    print(f"\n{'='*60}")
    print(f"📊 任务状态: {meta['status']}")
    print(f"   步骤: {list(meta['steps'].keys())}")
    print(f"   状态文件: {ts.state_file}")
    print(f"{'='*60}")
    return meta


def run_app_task(task_id: str, apk_path: str):
    print(f"\n{'='*60}")
    print(f"📱 App 逆向任务启动")
    print(f"   任务ID: {task_id}")
    print(f"   APK:    {apk_path}")
    print(f"{'='*60}")

    ts = TaskState(task_id)
    ts.init("app", apk_path)
    queue_task(task_id)

    pipeline = APP_PIPELINE
    for step in pipeline:
        result = execute_step(step, ts)
        status = result.get("status", "unknown")
        ts.update(step["step"], status, result)
        if status == "failed":
            break

    meta = ts.load()
    print(f"\n📊 任务状态: {meta['status']}")
    return meta


def cmd_status(task_id: str):
    ts = TaskState(task_id)
    if not ts.meta_file.exists():
        print(f"❌ 任务不存在: {task_id}")
        return
    meta = ts.load()
    print(json.dumps(meta, indent=2, ensure_ascii=False, default=str))


def cmd_list():
    """列出所有任务"""
    if not TASKS_DIR.exists():
        print("暂无任务")
        return
    for td in sorted(TASKS_DIR.iterdir()):
        if td.is_dir() and (td / "task-meta.json").exists():
            meta = json.loads((td / "task-meta.json").read_text())
            ts = datetime.now(timezone.utc) - datetime.fromisoformat(meta["created_at"].replace("Z", "+00:00"))
            age = f"{ts.days}d" if ts.days else f"{ts.seconds//3600}h"
            print(f"  [{meta.get('status','?')[:8]:8}] {td.name} | {meta.get('type')} | {meta.get('target','')[:50]} | {age}")


# ─────────────────────────────────────────────────────────────────
# CLI 入口
# ─────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="reverse-controller.py — 逆向引擎调度器")
    sub = parser.add_subparsers(dest="cmd")

    web = sub.add_parser("web", help="Web 逆向任务")
    web.add_argument("url", help="目标 URL")
    web.add_argument("--task-id", default=None, help="任务 ID")
    web.add_argument("--method", default="standard",
                     choices=["standard", "hook"],
                     help="方案: standard（标准逆向）或 hook（Browser Hook）")

    app = sub.add_parser("app", help="App 逆向任务")
    app.add_argument("apk_path", help="APK 文件路径")
    app.add_argument("--task-id", default=None, help="任务 ID")

    sub.add_parser("list", help="列出所有任务")
    status = sub.add_parser("status", help="查看任务状态")
    status.add_argument("--task-id", required=True)

    args = parser.parse_args()

    if args.cmd == "web":
        task_id = args.task_id or f"web-{hashlib.md5(args.url.encode()).hexdigest()[:8]}"
        run_web_task(task_id, args.url, method=args.method)
    elif args.cmd == "app":
        task_id = args.task_id or f"app-{Path(args.apk_path).stem[:8]}"
        run_app_task(task_id, args.apk_path)
    elif args.cmd == "list":
        cmd_list()
    elif args.cmd == "status":
        cmd_status(args.task_id)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
