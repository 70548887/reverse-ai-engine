---
name: mem0-reverse-memory
description: 在 APP 逆向任务中自动存取 mem0 记忆（搜索/写入关键发现）
version: "1.0"
framework: mem0
---

# mem0 逆向记忆存取

## 触发条件
在 APP 逆向、SO 分析、Frida 任务开始时，自动存取 mem0 记忆。

## mem0 服务信息
- **Endpoint**: http://152.136.169.127:6002
- **API Key**: `m0sk_0vlZFDI_YMIUzXBtl9UsYLmuX6Kfx3L8tETkE7t5dM4`
- **用户**: admin
- **过滤格式**: `{"user_id":"admin"}`（GET参数需URL编码）

## Python 工具函数

```python
import urllib.request, urllib.parse, json

BASE = "http://152.136.169.127:6002"
KEY = "m0sk_0vlZFDI_YMIUzXBtl9UsYLmuX6Kfx3L8tETkE7t5dM4"

def mem0_write(memory_text, user="admin", timeout=30):
    # 当前自部署 mem0 的可用写入格式是 messages 数组；旧版 {"memory":...} / {"text":...} 会返回 422。
    # 写入可能较慢，短 timeout（如 8s）可能误报 TimeoutError；优先加长 timeout 后再判失败。
    body = {"messages": [{"role": "user", "content": memory_text}], "user_id": user, "infer": True}
    hdrs = {"X-API-Key": KEY, "Content-Type": "application/json"}
    rq = urllib.request.Request(BASE + "/memories", headers=hdrs, data=json.dumps(body, ensure_ascii=False).encode(), method="POST")
    with urllib.request.urlopen(rq, timeout=timeout) as r:
        return json.loads(r.read())

def mem0_search(query, user="admin", top_k=3):
    body = {"query": query, "filters": {"user_id": user}, "top_k": top_k}
    hdrs = {"X-API-Key": KEY, "Content-Type": "application/json"}
    rq = urllib.request.Request(BASE + "/search", headers=hdrs, data=json.dumps(body).encode(), method="POST")
    with urllib.request.urlopen(rq) as r:
        return json.loads(r.read()).get("results", [])

def mem0_list(user="admin"):
    flt = urllib.parse.quote('{"user_id":"' + user + '"}')
    hdrs = {"X-API-Key": KEY}
    rq = urllib.request.Request(BASE + f"/memories?filters={flt}", headers=hdrs)
    with urllib.request.urlopen(rq) as r:
        return json.loads(r.read()).get("results", [])
```

## 使用时机

1. **任务开始时** — 搜索相关上下文，看之前有没有分析过同样的 SO/函数/算法
2. **发现关键信息时** — 写入：函数名、偏移、算法特征、踩坑记录
3. **任务完成后** — 写入总结：成果、残留问题、下一步

## 写入内容规范

- 函数名 + 偏移地址
- 算法类型（AES/SM4/自定义）
- Frida hook 脚本路径
- 踩坑记录（什么失败了、为什么）
- HTTP Header 格式
- APP 版本、SO 版本

## 逆向任务收尾归档检查清单

完成 APP/SO 逆向阶段性任务（尤其是动态负样本）时，除写入 mem0 外，还应同步验证本地归档层，避免“写了但未收尾”：

1. 先用文件搜索确认本轮实际产物名，不要凭上轮命名模板硬猜；同系列静态产物可能是 `vNN_xxx_0514.json/.md`，而不是 `vNN_xxx_static_0514.json/.md`。若预期路径缺失，先 `search_files(target="files", pattern="*vNN*")` 或等价方式枚举目录，再验证真实路径。
2. 读取/确认 Markdown 结论文件与聚合 JSON 摘要存在，结论中明确区分“调用链/打包/传播进展”和“算法本体/value 生成点是否还原”。
3. 检查任务状态 JSON、`SESSION-STATE.md`、本地 `memory/*.md` 是否包含同一边界结论。
4. 运行本地 `memory-sync.py sync` 后再用 `memory-sync.py search "<project keywords>"` 验证语义层可检索到最新项目归档。
5. 用 `ps -ef | grep <run_script_or_tag>` 确认没有遗留采样/Frida 脚本进程。
6. 写入 mem0 阶段总结；若返回 `200 {"results":[]}`，按服务端接受处理，但仍以本地 Markdown/JSON/SESSION + memory-sync 搜索命中作为可审计事实源。
7. 更新当前 todo 状态为 completed，并将长期 memory 中同一项目的旧边界替换成最新边界。
8. 对负样本要写清楚“不升级为生成点”的原因（如 `first_value_events=[]`、`ssl_events=[]`、未复现目标 ACK/SSL 窗口），避免后续把 hook-installed 误读为算法证据。

## 坑

- `filters` GET参数必须URL编码，否则502
- `infer=False` 时不生成向量，语义搜索失效
- 自部署 mem0 写入 `/memories` 有时返回 `200 {"results":[]}`，这表示请求被服务端接受，不等同于搜索已可立即命中新内容；不要仅因随后语义搜索返回旧/无关结果就判定写入失败，需同时依赖本地 Markdown/JSON/SESSION 归档作为可审计事实源。
- 收尾脚本里不要把 mem0 写入和其他较重检查（例如再调用 shell/ps、memory-sync）塞进同一个长 `execute_code` 脚本；一旦网络/服务端响应异常，整段可能超时并丢失后续检查结果。更稳的流程是：先完成本地 `memory-sync.py sync/search` 和进程检查，再用一个独立、短 timeout（20–45s）的 mem0 写入脚本；若超时，重试一次精简内容，成功返回 `200 {"results":[]}` 即可按接受处理。
- 若已经发生“mem0 写入 + 后续验证”混在 `execute_code` 里导致 300s timeout，按失败恢复处理：不要复跑整段重脚本，改用 `terminal(timeout=60)` 单独运行一个最小 Python one-shot 写入 mem0；写入成功后再分别做 todo/memory 状态更新。
- 如果这个最小 mem0 one-shot 仍超时，且工具返回 `BLOCKED: Command timed out. Do NOT retry this command.`，不要继续重试 mem0 写入，也不要阻塞收尾；改以本地 Markdown/JSON/SESSION + `memory-sync.py sync/search` 命中作为可审计事实源，完成 todo，并在最终报告里注明 mem0 写入超时但本地归档已验证。
