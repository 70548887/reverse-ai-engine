---
name: webpack-signature-reverse
description: Webpack/Rspack 动态加载站点的签名逆向方法论 — 以小红书 XHS 为例，定位 x-s/x_b3 等请求头生成逻辑
triggers:
  - Web 逆向签名分析
  - x-s/x_b3/traceid 请求头
  - webpack rspack chunk 动态加载
  - 反爬签名 JavaScript 调试
---

# Webpack/Rspack 签名逆向方法论

## 核心挑战

现代 Web 应用（SPA）大量使用 Webpack/Rspack 动态 chunk 加载，签名逻辑被分散在几十甚至上百个 JS 文件中。

## 完整流程（5步）

### Step 1 — 收集端点资产

```bash
# 用 Python 直接拉取，不走代理
python3 -c "
import urllib.request, ssl, re
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('https://target.com/', headers={'User-Agent': 'Mozilla/5.0'})
with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
    html = r.read().decode('utf-8', errors='ignore')

# 找所有 JS URL（script src）
scripts = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)
print('Scripts:', scripts)

# 找 webpack/rspack chunk map（关键！）
chunk_map = re.search(r'(?:webpack|rspack)_chunkmap[^;]+', html)
if chunk_map:
    print('ChunkMap:', chunk_map.group()[:500])
"
```

**关键资产**（以小红书为例）：
- `fe-static.xhscdn.com/formula-static/xhs-pc-web/public/resource/js/vendor.js` — 基础库（700K）
- `vendor-dynamic.*.js` — 动态 chunk，**签名核心所在**（1.3MB）
- `as.xiaohongshu.com/api/sec/v1/ds?appId=xhs-pc-web` — 安全 JS 端点

### Step 2 — 定位签名函数

下载 `vendor-dynamic.*.js`（通常 1-2MB），搜索签名关键词：

```python
python3 -c "
import urllib.request, ssl, re
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

url = 'https://fe-static.xhscdn.com/formula-static/xhs-pc-web/public/resource/js/vendor-dynamic.a40ef251.js'
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0', 'Referer': 'https://www.xiaohongshu.com/'})
with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
    content = r.read().decode('utf-8', errors='ignore')

# 搜索签名相关关键词
for kw in ['x-s', 'x_s', 'X-Sign', 'seccore_signv2', 'encryptToken',
           'x-b3-traceid', 'traceid', 'x_t', 'signLackReload', 'XYS']:
    ms = list(re.finditer(re.escape(kw), content, re.I))
    if ms:
        print(f'\n[{kw}]: {len(ms)} matches')
        for m in ms[:2]:
            print(f'  ...{content[max(0,m.start()-100):m.start()+200]}...')
"
```

**小红书核心发现**（`vendor-dynamic.js` 内）：
```
function seccore_signv2(e, a) {
  var s=window.toString, u=e;
  // e = URL path, a = params
  // m = K.Pu([u].join(""))  ← URL 做一次 hash
  // w = K.Pu(e)              ← URL 再做一次 hash
  // C = window.mnsv2(u, m, w)  ← 关键！WASM 字节码 VM 生成
  // P = {x0: device_id, x1: "xhs-pc-web", x2: "PC", x3: C, x4: a}
  // return "XYS_" + K.xE(K.lz(JSON.stringify(P)))
}
```

### Step 3 — 追踪加密依赖

签名函数依赖多个外部工具函数（在小红书案例中）：

| 依赖 | 作用 | 来源 |
|------|------|------|
| `K.Pu` | Hash 函数（MD5/SHA 类） | vendor-dynamic.js module s(5681) |
| `K.xE` | Base64 编码 | vendor-dynamic.js |
| `K.lz` | LZ 压缩 | vendor-dynamic.js |
| `window.mnsv2` | **核心设备指纹** | 安全 JS 字节码 VM 生成 |
| `R.i8` | 设备 ID | 初始化时注入 |
| `R.mj` | 平台标识（如 "PC"） | 初始化时注入 |

```python
# 找 module 5681 的定义（K 模块 = 加密工具库）
mod5681_match = re.search(r's\(5681\).*?module.*?exports', content)
# 找 R.i8 的值
for m in re.finditer(r'R\.i8\s*=\s*["\']([^"\']+)["\']', content):
    print(f'R.i8 = {m.group(1)}')
```

### Step 4 — 分析安全 JS（字节码 VM）

有些站点将关键加密逻辑放在远程安全 JS 中，以**字节码 VM** 形式执行：

```python
# 拉取安全 JS
python3 -c "
import urllib.request, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request(
    'https://as.xiaohongshu.com/api/sec/v1/ds?appId=xhs-pc-web',
    headers={'User-Agent': 'Mozilla/5.0', 'Referer': 'https://www.xiaohongshu.com/'}
)
with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
    content = r.read().decode('utf-8', errors='ignore')
print(len(content), 'chars')

# 找 VM 入口函数名
import re
vm_func = re.search(r'glb\[_0x\w+\]\s*=\s*function', content)
print('VM entry:', vm_func.group() if vm_func else 'N/A')

# 找字节码
bytecode = re.search(r'var __\s*=\s*["\']([^"\']{500,})["\']', content)
print('Bytecode len:', len(bytecode.group(1)) if bytecode else 0)

# 找 getdss（注入给 VM 的 native 函数）
m = re.search(r'getdss[^}]{0,200}', content)
if m: print('getdss:', m.group()[:200])
"
```

**小红书安全 JS 特征**：
- `_BHjFmfUMEtxhI` = VM 入口函数（混淆名）
- `__$c` = 2466 字符 hex 字节码（VTKBBQFM 头 = 固定魔数）
- `getdss()` = 时间戳，VM 的 native 注入函数
- `window.mns` = VM 执行后暴露的设备指纹对象

### Step 5 — 用 Node 执行安全 JS（可选）

```bash
# 保存安全 JS 到文件
python3 -c "
import urllib.request, ssl
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
req = urllib.request.Request('https://as.xiaohongshu.com/api/sec/v1/ds?appId=xhs-pc-web',
    headers={'User-Agent':'Mozilla/5.0','Referer':'https://www.xiaohongshu.com/'})
with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
    open('/tmp/xhs_sec.js','wb').write(r.read())
print('Saved')
"

# 用 Node 加载并检查暴露的全局函数
node -e "
const fs = require('fs');
const vm = require('vm');
const secJs = fs.readFileSync('/tmp/xhs_sec.js', 'utf-8');
const ctx = {
    console, setTimeout, setInterval, window: {}, document: {},
    global: {}, process: { argv: [] }
};
vm.createContext(ctx);
vm.runInContext(secJs, ctx);
const fnames = Object.keys(ctx).filter(k => typeof ctx[k] === 'function');
console.log('Functions:', fnames);
const gnames = Object.keys(ctx).filter(k => typeof ctx[k] !== 'function');
console.log('Globals:', gnames);
"
```

## 小红书签名架构总结

```
请求拦截 → signAdaptor 拦截器
  ├── /fe_api/ 路径 → encryptToken() 生成 X-Sign
  │     └── X + md5(url + params + "WSUDD")
  │
  ├── 其他路径 → seccore_signv2(url, params) 生成 X-s / X-t / X-b3-traceid
  │     ├── K.Pu(hash) × 2  ← MD5 类
  │     ├── window.mnsv2(u,m,w)  ← WASM 字节码（设备指纹）
  │     ├── x0 = R.i8 (device_id)
  │     ├── x1 = "xhs-pc-web"
  │     ├── x2 = window[R.mj] || "PC"
  │     ├── x3 = mnsv2 输出
  │     ├── x4 = params
  │     └── XYS_ + base64(lz_compress(JSON))
  │
  └── mns 模块 → window.mns.getMnsToken()
        └── X-MNS header
```

## 常见反爬特征速查

| 特征 | 含义 |
|------|------|
| `x-s` / `X-Sign` | 主签名 header |
| `x-t` | 时间戳 |
| `x-b3-traceid` | 分布式追踪 ID |
| `x-s-common` | 通用签名 |
| `X-MNS` | 设备 Token |
| `XYS_` 前缀 | 小红书特有格式 |
| `websectiga` cookie | 安全检测 cookie |
| `seccore_signv2` | 小红书签名核心函数 |
| `VTKBBQFM` 魔数 | 小红书字节码 VM 标志 |

## 避坑指南

1. **vendor.js 里找不到签名** → 签名逻辑在 `vendor-dynamic.*.js` 动态 chunk 中
2. **vendor-dynamic 下载失败 SSL** → 用 Python urllib 直接拉，不走 curl（SSL 配置更简单）
3. **混淆的 chunk ID** → 从 HTML 的 `<script>` 标签提取所有 JS URL，从响应中找 webpack chunk map
4. **安全 JS 返回 403** → 目标站有 IP 风控（服务器 IP 非住宅），改用 mitmproxy + 真实浏览器抓包
5. **混淆函数名** → 用 `find + context` 模式找相邻的关键字（如 `seccore_signv2` 附近就是 `K.Pu`）

## ⭐ 实战解法：Playwright 浏览器提取（推荐）

对于字节码 VM 类签名（如小红书 `mnsv2`），纯静态分析难度极高，**直接用 Playwright 从真实浏览器页面提取签名是最高效方案**。

### 环境准备

```bash
# 查找已安装的 Playwright 和浏览器路径
node -e "const {chromium}=require('/opt/hermes/node_modules/playwright'); console.log(chromium.executablePath());"
# 输出类似: /opt/hermes/.playwright/chromium_headless_shell-1217/chrome-headless-shell-linux64/chrome-headless-shell

# 如 playwright 找不到浏览器，手动创建软链
mkdir -p ~/.cache/ms-playwright/chromium_headless_shell-1217/chrome-headless-shell-linux64
ln -sf /opt/hermes/.playwright/chromium_headless_shell-1217/chrome-headless-shell-linux64/chrome-headless-shell \
       ~/.cache/ms-playwright/chromium_headless_shell-1217/chrome-headless-shell-linux64/chrome-headless-shell
```

### 提取 mnsv2 签名的关键步骤

```javascript
// 第1步：确认 mnsv2 函数存在（用 node -e 快速验证）
node -e "
const {chromium}=require('/opt/hermes/node_modules/playwright');
(async()=>{
  const br=await chromium.launch({headless:true,
    executablePath:'/opt/hermes/.playwright/chromium_headless_shell-1217/chrome-headless-shell-linux64/chrome-headless-shell',
    args:['--no-sandbox','--disable-dev-shm-usage']});
  const page=await br.newPage();
  await page.goto('https://www.xiaohongshu.com/search_result?keyword=python',
    {waitUntil:'networkidle',timeout:20000}).catch(function(){});
  await page.waitForTimeout(5000);
  const keys=await page.evaluate(function(){
    return Object.keys(window).filter(function(k){return k.includes('mns');});
  });
  console.log('mns keys:', keys);
  await br.close();process.exit(0);
})();
"

// 第2步：注入 URL + 调用签名（用 addInitScript 避免 Python 字符串转义冲突）
node -e "
const {chromium}=require('/opt/hermes/node_modules/playwright');
(async()=>{
  const br=await chromium.launch({headless:true,
    executablePath:'/opt/hermes/.playwright/chromium_headless_shell-1217/chrome-headless-shell-linux64/chrome-headless-shell',
    args:['--no-sandbox','--disable-dev-shm-usage']});
  const page=await br.newPage();
  await page.addInitScript(function(){
    window.__URL__='https://edith.xiaohongshu.com/api/sns/web/v1/search/recommend';
  });
  await page.goto('https://www.xiaohongshu.com/search_result?keyword=python',
    {waitUntil:'networkidle',timeout:20000}).catch(function(){});
  await page.waitForTimeout(5000);
  const sig=await page.evaluate(async function(){
    if(typeof window.mnsv2!=='function')return 'NO_MNSV2';
    return window.mnsv2(window.__URL__);
  });
  console.log('SIG:'+sig);
  await br.close();process.exit(0);
})();
"
// 输出: SIG:mns0101_ig1PM6/RKm2d+92Pnz9QjyMOhfPJXf3N27/fjxoTghL...
```

### Python 封装（推荐直接复制使用）

```python
#!/usr/bin/env python3
"""
小红书 mnsv2 签名脚本
pip install playwright && npx playwright install chromium
"""
import subprocess, json, os

PLAYWRIGHT_PATH = '/opt/hermes/node_modules/playwright'
CHROME_PATH = '/opt/hermes/.playwright/chromium_headless_shell-1217/chrome-headless-shell-linux64/chrome-headless-shell'

def make_sign(input_dict):
    url = input_dict.get("url", "")
    body = input_dict.get("body", {})
    body_str = json.dumps(body, ensure_ascii=False)

    # 用字符串拼接避免 Python f-string {} 与 Node.js 箭头函数冲突
    js_code = (
        "const{chromium}=require('" + PLAYWRIGHT_PATH + "');"
        "(async()=>{"
        "const br=await chromium.launch({"
        "headless:true,"
        "executablePath:'" + CHROME_PATH + "',"
        "args:['--no-sandbox','--disable-dev-shm-usage','--disable-blink-features=AutomationControlled']"
        "});"
        "const page=await br.newPage();"
        "await page.addInitScript(function(){"
        "window.__URL__='" + url.replace("'", "\\'") + "';"
        "window.__BODY__=" + body_str + ";"
        "});"
        "await page.goto('https://www.xiaohongshu.com/search_result?keyword=python',"
        "{waitUntil:'networkidle',timeout:20000}).catch(function(){});"
        "await page.waitForTimeout(5000);"
        "const result=await page.evaluate(async function(){"
        "var u=window.__URL__;var b=window.__BODY__;"
        "if(typeof window.mnsv2!=='function')return 'NO_MNSV2';"
        "try{"
        "var sig=window.mnsv2(u);"
        "if(b&&Object.keys(b).length>0)return sig+'|'+JSON.stringify(b);"
        "return sig;"
        "}catch(e){return 'ERR:'+e.message.substring(0,200);}"
        "});"
        "console.log(result);"
        "await br.close();process.exit(0);"
        "})().catch(function(e){console.log('TOP_ERR:'+e.message);process.exit(1);});"
    )

    env = {**os.environ, 'PLAYWRIGHT_BROWSERS_PATH': '/opt/hermes/.playwright'}
    r = subprocess.run(['node', '-e', js_code],
                      capture_output=True, text=True, timeout=40, env=env)
    result = r.stdout.strip()
    if result.startswith('NO_MNSV2'):
        raise RuntimeError('mnsv2 not found in page')
    if result.startswith('ERR:') or result.startswith('TOP_ERR:'):
        raise RuntimeError(result)
    return result

# 使用
sig = make_sign({"url": "https://edith.xiaohongshu.com/api/sns/web/v1/search/recommend",
                 "body": {"keyword": "python", "page": 1}})
```

### 避坑指南（Playwright 方案）

| 问题 | 原因 | 解法 |
|------|------|------|
| `executable doesn't exist` | Playwright 期望的路径与实际不同 | `find / -name "chrome-headless-shell" 2>/dev/null` 找真实路径；实际路径 `PLAYWRIGHT_BROWSERS_PATH=/opt/data/home/.cache/ms-playwright` |
| `Too many arguments` | `page.evaluate((u,b)=>{...}, url, body)` 参数序列化失败 | 改用 `addInitScript` 注入数据 |
| `Unexpected token '-'` / SyntaxError | Python f-string `{...}` 在传给 Playwright 时序列化出错 | 用 `page.evaluate(f"() => {{ ... }}")` 双花括号，或先注入辅助函数 |
| mnsv2 not found | 页面未完全加载 | `wait_until="domcontentloaded"` + `asyncio.sleep(3-5)` 等待模块加载 |
| 签名返回固定 `mns0101_0` | 未登录状态下 mnsv2 是 stub，不是真实签名 | 必须在登录态下抓包；mitmproxy 挂本地浏览器登录后抓最可靠 |
| `Execution context was destroyed` | `networkidle` 触发导航销毁 JS 上下文 | 用 `wait_until="domcontentloaded"` + 手动 sleep |
| `page.goto() takes 2 positional arguments but 3 were given` | 新版 Playwright API 格式变更 | 用关键字参数 `page.goto(url, wait_until="domcontentloaded", timeout=20000)` 而非 dict |

### mnsv2 函数签名（实测）

```javascript
// mnsv2(url: string, body: object, headers: object) => string
// 第三个参数是 headers 对象，函数会写入 x-t 等 header
const h = {};
const sig = window.mnsv2('/api/sns/web/v1/search/notes', {keyword: 'python'}, h);
// sig = 'mns0101_...' (已登录) 或 'mns0101_0' (未登录/Stub)
// h['x-t'] = '1745539200000' (时间戳)
```

**关键发现**：未登录状态下 `mnsv2` 返回固定值 `"mns0101_0"`，不是真实签名。必须先获取登录态 cookie（`web_session`）才能拿到真实签名。

### 为什么不用纯 Node.js vm 模块？

安全 JS（字节码 VM）通常依赖大量浏览器 DOM/BOM API（`document.cookie`、`window.devicePixelRatio` 等），
在 Node.js `vm` 模块的纯净上下文里无法运行。Playwright 提供完整浏览器环境，是**唯一靠谱方案**。

## 工具链推荐

```bash
# Python + urllib → 快速拉 JS（适合静态分析）
# mitmproxy + 浏览器 → 动态抓真实请求
# Playwright（推荐）→ 直接从真实页面提取签名函数结果
# browser_vision → 截图 + 视觉验证
```

## 适用站点特征

- SPA 应用（Vue/React）使用 Webpack/Rspack
- 签名动态变化（每次请求不同）
- 有反 WebDriver / Headless 检测
- 设备指纹逻辑在远程 JS 中（字节码 VM）
- `x-s` / `x-b3` / `traceid` 等自定义 header
