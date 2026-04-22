#!/usr/bin/env python3
"""工具链健康检查脚本"""
import subprocess
import os
from pathlib import Path
import json

TOOLS = Path("/opt/data/home/reverse-tools")
JAVA = TOOLS / "jdk-17.0.18+8"
PIP = "/opt/data/home/.local/bin/pip"

TOOL_CHECKS = [
    {
        "name": "mitmproxy",
        "cmd": ["mitmproxy", "--version"],
        "success": "mitmproxy"
    },
    {
        "name": "frida-tools",
        "cmd": ["/opt/data/home/.local/bin/frida", "--version"],
        "success": "17."
    },
    {
        "name": "jadx",
        "cmd": [str(TOOLS / "bin/jadx"), "--version"],
        "success": "1."
    },
    {
        "name": "apktool",
        "cmd": ["java", "-jar", str(TOOLS / "apktool/apktool.jar"), "--version"],
        "success": "2.7"
    },
    {
        "name": "java",
        "cmd": [str(JAVA / "bin/java"), "-version"],
        "success": "version"
    },
    {
        "name": "python3",
        "cmd": ["python3", "--version"],
        "success": "Python"
    },
    {
        "name": "node",
        "cmd": ["node", "--version"],
        "success": "v"
    },
]

def check_tool(tool):
    name = tool["name"]
    cmd = tool["cmd"]
    success_hint = tool["success"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15
        )
        output = result.stdout + result.stderr

        # 过滤版本号行
        version_lines = [
            l.strip() for l in output.split("\n")
            if l.strip() and not l.startswith("WARNING")
        ]
        version_str = version_lines[0] if version_lines else output.strip()[:80]

        passed = success_hint.lower() in output.lower()
        return {
            "name": name,
            "ok": passed,
            "version": version_str[:60],
            "cmd": " ".join(cmd)
        }
    except FileNotFoundError:
        return {"name": name, "ok": False, "version": "命令未找到", "cmd": " ".join(cmd)}
    except subprocess.TimeoutExpired:
        return {"name": name, "ok": False, "version": "超时", "cmd": " ".join(cmd)}
    except Exception as e:
        return {"name": name, "ok": False, "version": str(e)[:40], "cmd": " ".join(cmd)}

def check_frida_server():
    """检查 frida-server 二进制（ARM64 Android专用，主机用frida CLI即可）"""
    fs = TOOLS / "frida/frida-server"
    if not fs.exists():
        return {"name": "frida-server (ARM64/Android)", "ok": False, "version": "文件不存在（正常，主机用frida CLI）", "cmd": ""}

    # frida-server 是 ARM64 格式，在 x86_64 主机上会报 Exec format error
    # 这是正常的，frida-server 用于安卓设备，不在主机运行
    try:
        r = subprocess.run([str(fs), "--version"], capture_output=True, text=True, timeout=5)
        return {"name": "frida-server (ARM64/Android)", "ok": True, "version": r.stdout.strip(), "cmd": str(fs)}
    except FileNotFoundError:
        return {"name": "frida-server (ARM64/Android)", "ok": False, "version": "文件不存在（正常）", "cmd": ""}
    except Exception as e:
        # Exec format error = 架构不匹配，这是正常的（frida-server是给Android ARM64用的）
        err_str = str(e)
        if "Exec format error" in err_str or "cannot execute" in err_str:
            return {"name": "frida-server (ARM64/Android)", "ok": True,
                    "version": "ARM64二进制，主机x86_64用frida CLI即可（正常）", "cmd": str(fs)}
        return {"name": "frida-server (ARM64/Android)", "ok": False, "version": f"运行失败: {e}", "cmd": str(fs)}

def check_pip_packages():
    """检查 pip 包"""
    packages = ["mitmproxy", "frida", "httpx", "loguru", "pyyaml", "requests"]
    found = []
    try:
        r = subprocess.run([PIP, "list", "--format=json"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            installed = {p["name"].lower(): p["version"] for p in json.loads(r.stdout)}
            for pkg in packages:
                if pkg.lower() in installed:
                    found.append(f"{pkg}=={installed[pkg.lower()]}")
    except:
        pass
    return found

def main():
    print("=" * 55)
    print("🔧 reverse-ai-engine 工具链检查")
    print("=" * 55)

    results = []

    # 工具检查
    for tool in TOOL_CHECKS:
        r = check_tool(tool)
        results.append(r)

    # frida-server 单独检查
    results.append(check_frida_server())

    # pip 包检查
    pip_pkgs = check_pip_packages()

    # 打印结果
    passed = 0
    for r in results:
        status = "✅" if r["ok"] else "❌"
        print(f"  {status} {r['name']:<18} {r['version']}")
        if r["ok"]:
            passed += 1

    print()
    print(f"  📦 pip 包:")
    if pip_pkgs:
        for p in sorted(pip_pkgs):
            print(f"     ✅ {p}")
    else:
        print(f"     ❌ 无法获取 pip 包列表")

    print()
    print(f"  📂 工具目录: {TOOLS}")
    for item in sorted(TOOLS.iterdir()):
        if item.is_dir():
            print(f"     📁 {item.name}/")
        else:
            size = item.stat().st_size
            print(f"     📄 {item.name} ({size//1024}KB)")

    print()
    print(f"  结果: {passed}/{len(results)} 工具正常")

    if passed == len(results):
        print("  🎉 工具链全部就绪！")
    else:
        print("  ⚠️  部分工具缺失，请检查。")

if __name__ == "__main__":
    main()
