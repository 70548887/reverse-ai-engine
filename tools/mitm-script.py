# tools/mitm-script.py
# mitmproxy 抓包脚本 — 专为逆向设计
# 用法: mitmproxy -s tools/mitm-script.py --listen-port 8080
#
# 在 APK/Web 逆向时启动，然后配置代理:
#   Android: adb forward tcp:8080 tcp:8080 + 系统代理设置
#   PC 浏览器: 代理插件指向 127.0.0.1:8080

from mitmproxy import http, ctx
import json
import time
import os
from pathlib import Path

class ReverseCapture:
    """
    专为逆向设计的 mitmproxy 抓包脚本
    自动识别加密参数、签名、token 等关键字段
    """

    def __init__(self):
        self.target_patterns = []  # 目标域名列表， 空=全捕获
        self.requests = []
        self.responses = []
        self.start_time = time.time()
        self.session_id = time.strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path("/opt/data/home/reverse-tools/capture")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 自动检测的加密相关关键词
        self.crypto_keywords = [
            "sign", "token", "salt", "nonce", "iv", "key",
            "secret", "hash", "md5", "sha", "encrypt",
            "aes", "rsa", "des", "ecb", "cbc", "signature"
        ]

    def request(self, flow: http.HTTPFlow):
        """记录请求，过滤目标域名"""
        url = flow.request.url

        # 如果设置了目标域名，只捕获匹配的
        if self.target_patterns:
            if not any(p in url for p in self.target_patterns):
                return

        req_data = {
            "url": url,
            "method": flow.request.method,
            "headers": dict(flow.request.headers),
            "query": dict(flow.request.query or {}),
            "path": flow.request.path,
            "host": flow.request.pretty_host,
            "timestamp": flow.request.timestamp_start,
            "content_raw": flow.request.content.decode("utf-8", errors="replace") if flow.request.content else "",
        }

        # 尝试解析 JSON body
        if flow.request.content:
            content_type = flow.request.headers.get("content-type", "")
            if "json" in content_type or flow.request.content.startswith(b"{"):
                try:
                    req_data["json"] = json.loads(flow.request.content)
                except:
                    pass

        # 自动标记加密相关参数
        suspicious_params = {}
        for key in list(req_data.get("query", {}).keys()):
            if any(k in key.lower() for k in self.crypto_keywords):
                suspicious_params[key] = req_data["query"][key]

        if suspicious_params:
            req_data["crypto_params"] = suspicious_params
            # 高亮输出
            print(f"[SIGN] {flow.request.method} {url}")
            for k, v in suspicious_params.items():
                print(f"       {k}={v}")

        self.requests.append(req_data)

    def response(self, flow: http.HTTPFlow):
        """记录响应"""
        if self.target_patterns:
            if not any(p in flow.request.url for p in self.target_patterns):
                return

        resp_data = {
            "url": flow.request.url,
            "status": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "timestamp": flow.response.timestamp_start,
            "content_raw": flow.response.content.decode("utf-8", errors="replace")[:2000] if flow.response.content else "",
            "content_type": flow.response.headers.get("content-type", ""),
        }

        # 解析 JSON 响应
        if flow.response.content:
            ct = flow.response.headers.get("content-type", "")
            if "json" in ct or flow.response.content.startswith(b"{"):
                try:
                    resp_data["json"] = json.loads(flow.response.content)
                except:
                    pass

        self.responses.append(resp_data)

    def done(self):
        """mitmproxy 退出时自动保存"""
        elapsed = time.time() - self.start_time
        output = {
            "session_id": self.session_id,
            "elapsed_seconds": elapsed,
            "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_requests": len(self.requests),
            "total_responses": len(self.responses),
            "requests": self.requests,
            "responses": self.responses,
        }

        har_file = self.output_dir / f"capture_{self.session_id}.json"
        with open(har_file, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False, default=str)

        ctx.log.info(f"✅ 抓包数据已保存: {har_file}")
        ctx.log.info(f"   请求: {len(self.requests)}, 响应: {len(self.responses)}")

# 注册 addon
addons = [ReverseCapture()]
