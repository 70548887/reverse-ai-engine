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

def mem0_write(memory_text, user="admin"):
    body = {"memory": memory_text, "user_id": user, "infer": True}
    hdrs = {"X-API-Key": KEY, "Content-Type": "application/json"}
    rq = urllib.request.Request(BASE + "/memories", headers=hdrs, data=json.dumps(body).encode(), method="POST")
    with urllib.request.urlopen(rq) as r:
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

## 坑

- `filters` GET参数必须URL编码，否则502
- `infer=False` 时不生成向量，语义搜索失效
