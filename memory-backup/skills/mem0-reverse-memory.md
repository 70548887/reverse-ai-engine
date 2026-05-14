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

1. 读取/确认 Markdown 结论文件与聚合 JSON 摘要存在，结论中明确区分“调用链/打包/传播进展”和“算法本体/value 生成点是否还原”。
2. 检查任务状态 JSON、`SESSION-STATE.md`、本地 `memory/*.md` 是否包含同一边界结论。
3. 用 `ps -ef | grep <run_script_or_tag>` 确认没有遗留采样/Frida 脚本进程。
4. 更新当前 todo 状态为 completed，并将长期 memory 中同一项目的旧边界替换成最新边界。
5. 对负样本要写清楚“不升级为生成点”的原因（如 `first_value_events=[]`、`ssl_events=[]`、未复现目标 ACK/SSL 窗口），避免后续把 hook-installed 误读为算法证据。

## 坑

- `filters` GET参数必须URL编码，否则502
- `infer=False` 时不生成向量，语义搜索失效
- 自部署 mem0 写入 `/memories` 有时返回 `200 {"results":[]}`，这表示请求被服务端接受，不等同于搜索已可立即命中新内容；不要仅因随后语义搜索返回旧/无关结果就判定写入失败，需同时依赖本地 Markdown/JSON/SESSION 归档作为可审计事实源。
