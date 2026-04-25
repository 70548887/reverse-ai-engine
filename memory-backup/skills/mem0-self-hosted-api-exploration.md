---
name: mem0-self-hosted-api-exploration
description: 自部署 mem0 REST API 踩坑记录 — 连接信息、可用端点地图、已知 Bug（502 上游错误）、推荐用法（infer=False 直接存储）
triggers:
  - mem0 API 接入
  - 记忆系统配置
  - 152.136.169.127:6002
---

# mem0 Self-Hosted API Exploration Guide

## Context
自部署 mem0 REST API (`mem0 v1.1`) 的完整踩坑记录。用于未来快速接入记忆系统，避免重复试探。

---

## 连接信息

| 项目 | 值 |
|------|-----|
| **Base URL** | `http://152.136.169.127:6002` |
| **API Key** | `m0sk_0vlZFDI_YMIUzXBtl9UsYLmuX6Kfx3L8tETkE7t5dM4` |
| **Swagger UI** | `http://152.136.169.127:6002/docs` |
| **OpenAPI Spec** | `http://152.136.169.127:6002/openapi.json` |

---

## 当前后端配置

```yaml
version: v1.1
vector_store:
  provider: pgvector
  host: postgres (容器内网络名)
  port: 5432
  dbname: mem0
llm:
  provider: anthropic
  model: claude-opus-4-7
  anthropic_base_url: https://cc-vibe.com/v1/   # ⚠️ 非官方 Anthropic API
embedder:
  provider: gemini
  model: gemini-embedding-001
  embedding_dims: 1536
history_db_path: /app/history/history.db
```

---

## 可用端点地图

```
认证:
  POST   /auth/register
  POST   /auth/login
  POST   /auth/refresh
  GET    /auth/me
  PATCH  /auth/me
  POST   /auth/change-password

API Keys:
  GET    /api-keys
  POST   /api-keys
  DELETE /api-keys/{key_id}

记忆 (核心):
  POST   /memories              ✓ 写入
  GET    /memories              ✗ 502 (pgvector 读取上游错误)
  GET    /memories/{id}         ✓ 按ID读取
  PUT    /memories/{id}         ✓ 更新
  DELETE /memories/{id}         ✓ 删除单条
  DELETE /memories              ✓ 批量删除 (按 user_id/run_id/agent_id)
  GET    /memories/{id}/history  ? (未测)

搜索:
  POST   /search                ✗ 502 (上游 provider error)

其他:
  GET    /entities              ✓ 用户/agent 列表
  DELETE /entities/{type}/{id}  ? (未测)
  GET    /configure             ✓ 查看当前配置
  POST   /configure             ? (可重新配置 provider)
  GET    /configure/providers   ✓ 支持的 provider 列表
  POST   /generate-instructions  ? (未测)
  POST   /reset                  ? (未测)
  GET    /requests               ✓ 请求日志 (查 upstream 错误很有用)
```

---

## ⚠️ 已知 Bug / 限制

### 1. `GET /memories?user_id=xxx` → 502
**原因**: pgvector 上游读取时出错，但写入 (POST) 正常。
**临时方案**: 用 `POST /memories` 写记忆时，响应返回 `{id, memory, ...}`，**自己保存这些 ID** 用于后续按 ID 读取。

### 2. `POST /search` → 502
**原因**: 向量搜索依赖 embedder 上游 (gemini via cc-vibe.com)。
**临时方案**: 目前无法语义搜索，只能按 ID 读取。

### 3. `POST /memories` + `infer=True` → 200 但 `results=[]`
**原因**: `infer=True` 时 LLM 提取 fact 但调用 `cc-vibe.com` 失败。
**临时方案**: 写入时始终使用 `infer=False`，直接存原始内容。

### 4. Embedder 维度不匹配
Gemini `gemini-embedding-001` 输出 **1536 维**，但项目中其他向量系统可能用 **384 维** (bge-small-zh-v1.5)。注意切换时维度要一致。

---

## 推荐用法

### 写入记忆
```python
import urllib.request, json

BASE = "http://152.136.169.127:6002"
HEADERS = {"X-API-Key": "m0sk_0vlZFDI_YMIUzXBtl9UsYLmuX6Kfx3L8tETkE7t5dM4"}

def store_memory(content: str, user_id: str = "admin", metadata: dict = None):
    payload = {
        "messages": [{"role": "user", "content": content}],
        "user_id": user_id,
        "infer": False,      # 关键：绕过 LLM 提取，直接存储
        "metadata": metadata or {}
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(BASE + "/memories", headers=HEADERS,
                                  data=data, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        result = json.loads(r.read())
    return result["results"][0]["id"]  # 保存此 ID 供后续读取
```

### 按 ID 读取
```python
def get_memory(memory_id: str):
    req = urllib.request.Request(BASE + f"/memories/{memory_id}", headers=HEADERS)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())
    # 返回: {id, memory, hash, metadata, created_at, updated_at, user_id, role}
```

### 列出所有用户/实体
```python
def list_entities():
    req = urllib.request.Request(BASE + "/entities", headers=HEADERS)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())
    # [{id, type, total_memories, created_at, updated_at}, ...]
```

---

## 可选配置方向

如果想改善 502 问题（`POST /search` 和 `GET /memories` 的上游错误）：

1. **切换 embedder → OpenAI** (`/configure` POST)
   - 支持 `openai` embedder（OpenAPI spec 显示可用）
   - 可能解决 cc-vibe.com 上游的不稳定问题

2. **切换 vector_db → Qdrant**
   - 已有 `152.136.169.127:6333` 的 Qdrant 实例
   - 用 Qdrant 替换 pgvector，向量搜索应该能正常

3. **排查 cc-vibe.com 上游**
   - `cc-vibe.com/v1/messages` 是否可达？
   - Anthropic API key 是否有效？
   - 如果换成标准 `api.anthropic.com` 可能解决

---

## 上游可观测性

查请求日志定位上游错误：
```bash
curl -H "X-API-Key: m0sk_..." http://152.136.169.127:6002/requests?limit=20
```
返回每个请求的 `method`, `path`, `status_code`, `latency_ms`，502 错误的 upstream 问题会在这里看到具体耗时。
