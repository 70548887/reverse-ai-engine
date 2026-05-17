---
name: douyin-live-focused-frida-hook
description: 抖音直播动态验证时用 focused Frida hook 稳定捕获 SSL 明文、webcast 请求与安全 header，避免过度 hook 导致进程断连
triggers: ["抖音直播动态hook", "douyin Frida SSL", "webcast im push", "x-security-argus", "SSL_write", "libsscronet"]
---

# Douyin Live Focused Frida Hook

用于抖音直播逆向的动态采样阶段：捕获 `/webcast/*`、`/webcast/im/push/preview_v2/`、`/ws/v2`、`x-*` 安全 header，并避免全局 hook 造成进程不稳定。

## 适用场景

- 静态分析已经定位到直播接口，需要在真机上动态验证请求。
- 需要采样最终网络明文、webcast 请求、websocket 升级请求、`x-security-argus` 或传统签名四件套。
- 之前脚本出现 `frida.TransportError: the connection is closed` 或目标进程突然消失。

## 稳定流程

1. 先做最小 attach 验证 Frida 链路和进程稳定性。
2. 确认关键 so 已加载：
   - `libsscronet.so`
   - `libttboringssl.so`
   - `libttcrypto.so`
   - `libmetasec_ml.so`
   - `libEncryptor.so`
3. 不要全局 hook libc/system-wide 的 `write/send/read/recv/open/openat`。
4. 只 hook 关键网络出口：
   - `libttboringssl.so!SSL_write`
   - `libttboringssl.so!SSL_read`
   - `libsscronet.so!SSL_write`
   - `libsscronet.so!SSL_read`
   - `libsscronet.so!send/recv/write/read`
5. 对 `libsscronet.so` / `libttcrypto.so` / `libmetasec_ml.so` / `libEncryptor.so` / `libttboringssl.so` 先做导出枚举，只对少量候选函数 hook。
6. 采样日志重点过滤：
   - `/webcast/`
   - `/webcast/im/push/preview_v2/`
   - `/ws/v2`
   - `x-security-argus`
   - `x-tt-e-t` / `x-tt-e-p` / `x-tt-e-h`
   - `X-Cylons`
   - `x-argus` / `x-ladon` / `x-gorgon` / `x-khronos`

## 关键坑

全模块 `findAnyExport + attach` 拦截 libc/system 函数会让抖音进程极不稳定。实测旧脚本对 `write/send/read/recv/open/openat` 做全局 hook 后，会短时间输出大量 `hook-ok`，随后进程断连/退出，典型报错：

```text
frida.TransportError: the connection is closed
ProcessNotFoundError: unable to find process with pid ...
```

这通常不是 Frida server 失效，而是 hook 范围过大。处理方式：重启 app，先用最小 attach 验证，再改用 focused hook。

## 已验证动态命中

focused hook 可在 SSL 明文出口捕获：

```text
GET /webcast/im/push/preview_v2/?...
Host: webcast100-ws-c-lf.amemv.com
```

以及 websocket 长连接：

```text
/ws/v2
Host: frontier-aweme-lf-ipainner.amemv.com
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Protocol: pbbp2
```

实测出现的安全 header：

```text
x-security-argus
x-tt-e-t
x-tt-e-p
x-tt-e-h
X-Cylons
```

如果没有直接看到 `x-argus` / `x-ladon` / `x-gorgon` / `x-khronos`，不要立即判定算法不存在；新版本或特定接口可能使用 `x-security-argus` 或 `x-tt-e-*` 承载。

## 下一步追踪入口

对 `/webcast/im/push/preview_v2/` 的 `SSL_write` backtrace 中 `libsscronet.so` offset 做反查，优先关注：

```text
libsscronet.so!0x3ec4f0
libsscronet.so!0x3ec44c
libsscronet.so!0x3a6b50
libsscronet.so!0x2d469c
libsscronet.so!0x346bcc
```

这些点位说明 SSL 明文已经在发送前被看到，但安全 header 大概率已经在更上层生成并填充完成。下一阶段应增加 Java/Native Request/Header 构造层 hook，反推安全 header 生成入口。

### 2026-05-11 日志经验：优先追 `X-Cylons`

在抖音 v380501 / `/webcast/im/push/preview_v2/` 动态采样中，直播 preview 主链路稳定命中 SSL 明文，但未出现传统四件套明文 header：

```text
x-argus
x-ladon
x-gorgon
x-khronos
x-security-argus
```

该接口最值得追的动态头是：

```text
X-Cylons
```

`/ws/v2` Frontier 建连另有：

```text
x-tt-e-t
x-tt-e-p
x-tt-e-h
```

`x-security-argus` 可能只出现在 Gecko 静态资源下载类请求中，例如 `lf-sourcecdn-tos.bytegecko.com/.../prefetch.json`，不要误判为直播主链路算法入口。

下一阶段 narrow hook 应聚焦 `libsscronet.so` 的 Cronet Header / Opaque 层，而不是扩大 libc hook：

```text
Cronet_HttpHeader_name_set
Cronet_HttpHeader_value_set
Cronet_UrlRequestParams_request_headers_add
Cronet_ClientOpaqueData_do_sign_set
Cronet_ClientOpaqueData_algorithm_prefer_set
Cronet_Engine_AddClientOpaqueData
Cronet_Engine_SetOpaque
Cronet_Engine_SetOecOpaque
Cronet_Engine_SetMD5Header
```

判定逻辑：

1. 如果 `HttpHeader_*_set` 能看到 `X-Cylons`，说明 header 来源在 Cronet API 调用方上游；继续回溯 Java/业务调用栈。
2. 如果 `HttpHeader_*_set` 看不到但 SSL 明文中有 `X-Cylons`，说明它由 TTNet native 内部后置注入；继续追 Opaque/sign callback。
3. 如果 `ClientOpaqueData_do_sign_set` / `Engine_SetOpaque` 命中，上游 backtrace 通常就是签名插件注册入口。

### 2026-05-11 Cronet Header/Opaque 窄化 hook 经验

实测 `libsscronet.so` 中部分 Cronet/protobuf-C 风格导出共享同一 offset，不要把导出名直接等同为语义唯一的 setter：

```text
Cronet_HttpHeader_name_set              == Cronet_UrlRequestParams_http_method_set == Cronet_FrontierMessageHeader_key_set
Cronet_HttpHeader_value_set             == Cronet_FrontierMessageHeader_value_set
```

因此只 hook `Cronet_HttpHeader_name_set/value_set` 可能看不到最终请求头，即使 SSL 明文里确实存在 `X-Cylons`。更稳的下一步是：

1. hook getter/列表遍历函数，而不是只赌 setter 时机：
   ```text
   Cronet_HttpHeader_name_get
   Cronet_HttpHeader_value_get
   Cronet_UrlRequestParams_request_headers_at
   Cronet_UrlRequestParams_request_headers_size
   ```
2. 在 `Cronet_UrlRequest_InitWithParams` / `Cronet_UrlRequest_CreateWith` 命中时主动遍历 `request_headers`，读取最终 header 列表。
3. SSL 明文与 Cronet Header hook 同时跑：若 SSL 有 `X-Cylons` 但 params/header-list 无，则可判定为 TTNet/native 内部后置注入。
4. Opaque/签名注册入口通常在 Engine 初始化早期完成；普通 attach 到前台进程可能只看到 `hook-ok`，看不到实际调用。要抓：
   - `Cronet_ClientOpaqueData_Create`
   - `Cronet_ClientOpaqueData_do_sign_set`
   - `Cronet_ClientOpaqueData_algorithm_prefer_set`
   - `Cronet_Engine_AddClientOpaqueData`
   - `Cronet_Engine_SetOpaque`
   - `Cronet_Engine_SetOecOpaque`
   需要 force-stop/spawn 后尽早 attach。
5. `Cronet_FrontierMessageHandler_Encode*` backtrace 多次出现 `libvcnverify.so!0x1690`、`libvcn.so!0x1b054` 时，优先把它作为 `/ws/v2` Frontier 安全封装入口继续追。

本轮沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/native_net_next_entry_0511.md
/opt/data/home/reverse-tools/douyin_analysis/run_cronet_header_entry_hook_0511.py
```

### 2026-05-11 主进程 PID 选择坑：不要误 attach 到 sandboxed_process

抖音多进程场景下，`frida.enumerate_processes()` 有时只稳定列出或优先命中：

```text
com.ss.android.ugc.aweme:sandboxed_process0
```

这个 renderer/sandbox 进程通常没有加载目标 native 网络/验证库，典型现象：

```text
modules: []
mod-miss libvcnverify.so
mod-miss libvcn.so
mod-miss libsscronet.so
mod-miss libttboringssl.so
```

如果 hook 输出大量 `mod-miss` 或没有 `hook-ok`，先确认是否 attach 到主进程：

```text
com.ss.android.ugc.aweme
```

更稳的 PID 选择顺序：

1. 优先使用 `device.enumerate_applications()` 查找 `identifier == "com.ss.android.ugc.aweme"` 的主 App PID。
2. 再用 `device.get_frontmost_application()` 交叉确认当前前台 PID。
3. 最后才 fallback 到 `device.enumerate_processes()`，且过滤掉 `:sandboxed_process*`、`:push`、`:miniapp` 等子进程。
4. attach 后立即枚举 modules，确认至少看到：
   ```text
   libsscronet.so
   libttboringssl.so
   libvcn.so
   libvcnverify.so
   ```

示例 `find_pid()` 逻辑应先取 app/frontmost PID，而不是按进程名 contains 搜索第一个命中项。否则 focused hook 会“正常运行但完全无效”。

### 2026-05-11 直播 WS 协议链路补充

一次完整动态验证中，BoringSSL/TTNet 明文出口确认直播长连接可能同时出现多条 WS/Frontier 链路：

```text
/bytelink/wss/v1/
/ws/v2
/webcast/im/push/preview_v2/
/webcast/im/push/v3/
```

典型主机与协议特征：

```text
Host: webcast100-ws-c-lf.amemv.com
Sec-WebSocket-Protocol: pbbp2
which_ws=live_ws
identity=audience
compress=zstd_dict
resp_content_type=protobuf
room_id=<room_id>
rid=<room_id>
```

动态采样结论要明确区分：

1. 已捕获 SSL 明文 / WebSocket Upgrade，只说明接口与协议链路已确认。
2. 已看到 `X-Cylons`、`x-tt-e-t`、`x-tt-e-p`、`x-tt-e-h`，只说明最终安全头存在。
3. 签名算法本体仍需通过 header 设置点、Opaque/sign callback 或 `libvcnverify.so` / `libvcn.so` backtrace 继续还原，不能把“抓到请求头”等同于“算法已挖出”。

本轮沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/live_dynamic_0511_summary.md
```

### 2026-05-11 SSL 对齐与 libvcn 下一步经验

一次后续采样中，`run_live_ssl_all_hook` 只完成 hook 安装但没有新增 SSL 明文事件；此时不要继续空跑，应停止后台进程，回到已有有效窄化日志做对齐分析。有效样本来自：

```text
/opt/data/home/reverse-tools/douyin_analysis/live_ssl_narrow_hook_0511.log
/opt/data/home/reverse-tools/douyin_analysis/live_ssl_alignment_0511.md
```

对齐结论：

1. `/webcast/im/push/preview_v2/` 和 `/webcast/im/push/v3/` 主链路均可见 `X-Cylons`，但未见 `x-tt-e-*` 或传统四件套。
2. `/ws/v2` Frontier 链路同时可见 `X-Cylons` 与 `x-tt-e-t` / `x-tt-e-p` / `x-tt-e-h`。
3. `/bytelink/wss/v1/` 可见 `X-Cylons`，未见 `x-tt-e-*`。
4. `x-tt-e-*` 更偏 Frontier `/ws/v2`，不要把它误判为 `/webcast/im/push/*` 主链路必带头。
5. Cronet params/header deep/rawscan 若搜不到 `X-Cylons` 或 `x-tt-e-*`，但 SSL 明文能看到，倾向于 TTNet/native 内部后置注入，或 hook 点早于最终 header 注入。

`SSL_write` 发送侧 backtrace 可作为稳定锚点：

```text
libsscronet.so!0x3ec4f0
libsscronet.so!0x3ec44c
libsscronet.so!0x3a6b50
libsscronet.so!0x2d469c
libsscronet.so!0x346bcc
libsscronet.so!0x3a66b0
libsscronet.so!0x2d45f4
libsscronet.so!0x2d4a38
```

如果 `vcn_offset_argret_hook_0511.log` 能搜到 `/webcast/im/push/preview_v2/` 和 `X-Cylons`，下一步优先沿：

```text
libvcnverify.so
libvcn.so
```

继续追，而不是继续扩大 SSL/all hook。对用户汇报时要明确：接口/协议链路与最终安全头已经确认，但算法本体仍未完整还原。

### 2026-05-11 vcn focused 采样补充经验

如果 Frida Python 能枚举设备/应用，但 `attach()` 或 `create_script()` 卡住、timeout，或出现 `ServerNotRunningError: closed`，不要直接判断 hook 脚本有问题。先重启设备侧 root Frida server，再用最小脚本验证：

```text
attached
{"tag":"hi","pid":<main_pid>}
ok
```

这类状态属于 Frida server 半失效：枚举可用但注入不可用。恢复后再运行 focused hook。

`libsscronet.so!0x2d469c` 在新一轮采样中可稳定命中直播 URL/请求对象进入 native Cronet 层，哪怕未捕获到 push/v3 或 WS 明文，也可能先看到：

```text
https://webcast.amemv.com/webcast/im/fetch/preview/?
rid=<room_id>
room_id=<room_id>
webcast
live_id=1
```

这说明直播链路已触发，但它不是签名算法入口；应把它作为请求构造/URL 锚点，继续往 header 注入点或 `libvcn*` 回溯。

SSL 明文读取不要只用 `readUtf8String(n)` 判定是否命中。HTTP/2、二进制帧、protobuf、zstd 或中间 `\0` 会导致字符串截断。更稳做法：

1. `Memory.readByteArray(buf, Math.min(len, 16000))` 先取原始字节。
2. 同时输出 hex/ascii 预览和尽力 UTF-8 文本。
3. 过滤条件同时覆盖：
   ```text
   GET /
   POST /
   HTTP/
   /webcast/
   /ws/v2
   /bytelink/wss
   X-Cylons
   x-tt-e-
   ```
4. 若只看到 `/webcast/im/fetch/preview/`，继续触发直播间刷新/切房/等待 WS 建连，不要立刻扩大 hook。

`libvcnverify.so`/`libvcn.so` offset hook 要容忍个别地址不可拦截。例如 `libvcnverify.so!0x1840` 可能报：

```text
Error: unable to intercept function at ...; please file a bug
```

这不是整轮失败；保留其他已安装点继续采样，并在报告中说明该 offset 不可拦截。

### 2026-05-11 `0x2d469c` 与 `X-Cylons` 判定经验

如果任务是判断 `X-Cylons` 是否在 `libsscronet.so!0x2d469c` 入参结构中，优先用两类证据交叉，而不是只看某一个 hook：

1. SSL 明文最终请求头：确认 `X-Cylons` 确实已进入发送数据。
2. `0x2d469c` focused/deep 入参 raw scan 与 header-list dump：确认该点位入参/可遍历 header 中是否已有该头。

已验证样本中，SSL 明文多次看到：

```text
/bytelink/wss/v1/                  X-Cylons
/ws/v2                             X-Cylons + x-tt-e-t/x-tt-e-p/x-tt-e-h
/webcast/im/push/preview_v2/       X-Cylons
/webcast/im/push/v3/               X-Cylons
```

这些 SSL `SSL_write` backtrace 都包含稳定锚点：

```text
libsscronet.so!0x3ec4f0
libsscronet.so!0x3ec44c
libsscronet.so!0x3a6b50
libsscronet.so!0x2d469c
libsscronet.so!0x346bcc
libsscronet.so!0x3a66b0
libsscronet.so!0x2d45f4
libsscronet.so!0x2d4a38
```

但同轮 `0x2d469c` focused/deep 日志显示：

```text
vcn_focused_xcylons_0511.log: 0x2d469c events=279, webcast events=83, raw/text X-Cylons=0
sscronet_2d469c_deep_0511.log: 0x2d469c events=40, webcast events=12, raw/text X-Cylons=0
sscronet_2d469c_deep_0511.log: 0x2d469c header dumps=34, nonzero dumps=1, header X-Cylons=0
```

判定规则：

- 如果 SSL 明文有 `X-Cylons`，而 `0x2d469c` enter 参数、raw scan、可遍历 `request_headers` 都没有，则不要继续把 `0x2d469c` 当成算法入口；它更像请求构造/发送链路锚点。
- 当前证据倾向：`X-Cylons` 不在 `0x2d469c` 入参 URL/参数结构中提前携带，而是在 `0x2d469c` 之后由 TTNet/native 发送链路后置注入，或由更下游 native header 合成层加入。
- 下一步应转向 `0x2d469c` 之后的 `0x3a6b50/0x3ec44c/0x3ec4f0` 附近对象扫描、onLeave 扫描，或追 `libvcnverify.so` / `libvcn.so` 的 header 合成/opaque sign callback。
- 对用户汇报时明确区分：接口/协议链路与最终安全头已经确认，但算法本体仍未完整还原。

本轮沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/xcylons_2d469c_judgement_0511.md
```

### 2026-05-11 v11 后置注入对齐采样经验

`run_v11_xcylons_postinject_0511.py` 同时 hook 了：

```text
libsscronet.so!0x2d469c / 0x346bcc / 0x3a66b0 / 0x3a6b50 / 0x3ec44c / 0x3ec4f0 / 0x2d45f4 / 0x2d4a38
libvcnverify.so!0x1500 / 0x1600 / 0x1690 / 0x16f4 / 0x1700
libvcn.so!0x1b000 / 0x1b054 / 0x1af00 / 0x1b100 / 0x1b200
Cronet_ClientOpaqueData_* / Cronet_Engine_*Opaque* / Cronet_FrontierMessageHandler_Encode*
SSL_write / SSL_read
```

v11 日志结论文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/v11_xcylons_postinject_final_0511.md
```

关键经验：

1. v11 本轮 `hook-ok=40`、`offset-enter=12`，说明 hook 安装与局部命中正常；但 `ssl-live=0`、`align-window=0`、`export-call=0`，没有真实 `/webcast/im/push/*`、`/ws/v2`、`/bytelink/wss` SSL 明文，因此不能用该轮直接确认最终注入函数。
2. 日志中唯一 `X-Cylons` 若来自脚本 ready 文本，不可算请求证据；分析时必须区分脚本文本与真实 SSL/内存数据。
3. `libsscronet!0x2d469c` 多次命中仍只看到 frontier/webcast 周边字符串或请求对象痕迹，继续支持：它是请求构造/发送链路锚点，不是 `X-Cylons` 算法入口。
4. 当前最强判断仍是：`X-Cylons` 在 `0x2d469c` 之后、`SSL_write` 之前后置注入；最可疑区间：
   ```text
   libsscronet.so!0x3a6b50 -> libsscronet.so!0x3ec44c -> libsscronet.so!0x3ec4f0
   ```
5. 最可疑签名/安全封装回调链：
   ```text
   Cronet_ClientOpaqueData_do_sign_set / Cronet_Engine_AddClientOpaqueData / Cronet_Engine_SetOpaque
       -> libvcnverify.so!0x1690 / 0x16f4
       -> libvcn.so!0x1b054
       -> TTNet 后置 header 合成
   ```
   但仍缺少“带 X-Cylons SSL 命中窗口内 vcn/libsscronet 下游 offset 同步命中”的直接证据。

下一版脚本不要继续扩大 libc/all hook，应改为：

1. 持续记录 `0x3a6b50/0x3ec44c/0x3ec4f0/0x2d469c/0x346bcc` enter/leave 最近 8 秒 ring-buffer；只有 SSL 明文命中 `X-Cylons` 时一次性吐出窗口。
2. force-stop 后早期 attach/spawn，专抓 Opaque 注册：
   ```text
   Cronet_ClientOpaqueData_Create
   Cronet_ClientOpaqueData_do_sign_set
   Cronet_ClientOpaqueData_algorithm_prefer_set
   Cronet_Engine_AddClientOpaqueData
   Cronet_Engine_SetOpaque
   Cronet_Engine_SetOecOpaque
   libvcnverify.so!0x1690 / 0x16f4
   libvcn.so!0x1b054
   ```
3. 采样时必须人工或 ADB 触发直播间进房、刷新、切房，直到出现 `/webcast/im/push/preview_v2`、`/webcast/im/push/v3` 或 `/ws/v2`；否则只能得到“hook 安装成功但无目标事件”的负样本。
4. 对用户汇报时继续明确区分：接口/协议链路与最终安全头已确认；`X-Cylons` 算法本体和精确回调入口尚未完整确认。

### 2026-05-11 v12 ring-buffer 空窗/非目标 SSL 采样经验

`run_v12_xcylons_ringbuffer_0511.py` 这类 ring-buffer 同步窗口采样，需要把“hook 链路正常”和“目标直播链路命中”分开判定。一次有效的空窗负样本日志：

```text
/opt/data/home/reverse-tools/douyin_analysis/v12_xcylons_ringbuffer_0511.log
```

统计特征：

```text
ready=1
hook-ok=35
offset-enter=7
export-enter=2
frontier=2
align-window=1
ssl-live=0
/webcast/=0
/ws/v2=0
/bytelink/wss=0
x-tt-e-=0
Traceback=0
TransportError=0
```

另一次“有 SSL 但仍非目标窗口”的负样本来自：

```text
/opt/data/home/reverse-tools/douyin_analysis/v12_resample_live_131810_0511.log
/opt/data/home/reverse-tools/douyin_analysis/v12_downstream_vcn_relation_analysis_0511.md
```

统计特征：

```text
hook-ok=35
offset-enter=14
ssl-live=2
align-window=0
libsscronet!0x2d469c=9
libsscronet!0x2d45f4=5
libvcnverify/libvcn offset-enter=0
```

本轮 SSL 明文只有：

```text
POST /live/v1/sp/get HTTP/1.1
Host: vc-brain-http.ndcpp.com
hasCylons=false
hasTt=false
backtrace=libliveio.so!...  # 非目标 sscronet/webcast push 链路
```

判定规则：

1. `hook-ok`、`offset-enter`、`export-enter` 存在且无 `Traceback` / `TransportError`，说明 Frida/server/脚本链路是正常的。
2. 如果 `ssl-live=0` 且没有 `/webcast/`、`/ws/v2`、`/bytelink/wss`，则说明本轮没有触发到目标直播 SSL 发送窗口，不能推进 `X-Cylons` 算法入口判断。
3. 即使 `ssl-live>0`，若只命中 `/live/v1/sp/get`、`vc-brain-http.ndcpp.com`、`libliveio.so` backtrace，且 `hasCylons=false/hasTt=false`，也只能算非目标直播旁路请求，不能用于判断 `X-Cylons` 注入链。
4. 日志统计中的 `X-Cylons=1` 若只来自脚本 ready/filter 文本，不是请求证据，不能算命中。
5. `align-window=1` 但无目标 `ssl-live` 时通常只是 ring-buffer/offset 周边事件，不代表已对齐到真实带头请求。
6. `libvcnverify.so`/`libvcn.so` hook 安装成功但没有 `offset-enter`，只能说明目标窗口未触发或该轮未走 vcn 链路；不能据此排除 vcn 参与。

下游 offset/vcn 判定口径：

- 仅 `0x2d469c` 看到 `webcast100-ws-c-lf.amemv.com`、`/webcast/room/leave/?r_signature=...`、app_log/frontier 周边字符串，仍只说明它是请求构造/发送链路锚点，不是 `X-Cylons` 算法入口。
- 若 `0x3a6b50/0x3ec44c/0x3ec4f0` 和 `libvcnverify!0x1690/0x16f4`、`libvcn!0x1b054` 在带 `X-Cylons` 的 SSL 窗口内没有同步 `offset-enter`，才可继续收窄；没有目标 SSL 窗口时不要下强结论。
- 当前可疑链仍保持：`0x2d469c` 之后、`SSL_write` 之前的 TTNet/native 后置注入，重点看 `0x3a6b50 -> 0x3ec44c -> 0x3ec4f0` 及 vcn/opaque sign callback。

下一步策略：

1. 先用已有有效 SSL 日志对齐 `X-Cylons` 请求窗口，避免反复空跑。
2. 运行 v12/v13 时以 `/webcast/im/push/preview_v2`、`/webcast/im/push/v3`、`/ws/v2`、`/bytelink/wss/v1` 任一出现作为“目标链路触发成功”的硬条件。
3. 只有命中 `ssl-live` 且明文含目标 URL/header 后，才分析 ring-buffer `align-window` 和下游 offset/vcn 同步关系。
4. 若连续空窗或只命中 `/live/v1/sp/get` 这类非目标 SSL，优先修正直播间触发与前台页面状态，而不是继续增加 hook 点。

### 2026-05-11 v12 continue：主进程/模块正确但仍无目标事件时的判定

后续 300 秒 v12 continue 采样示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/v12_continue_150807_0511.console.log
/opt/data/home/reverse-tools/douyin_analysis/v12_continue_150807_summary_0511.md
```

典型统计：

```text
ready=1
hook-ok=35
offset-enter=3
export-enter=0
align-window=1
ssl-live=0
/webcast/=0
/ws/v2=0
/bytelink/wss=0
X-Cylons=1   # 仅脚本 ready/filter 文本，不是真实请求头
x-tt-e-=0
Traceback=0
TransportError=0
duration reached=1
```

若同时确认 attach 到主进程且关键 so 已加载：

```text
com.ss.android.ugc.aweme
libsscronet.so
libttboringssl.so
libttcrypto.so
libvcn.so
libvcnverify.so
```

则不要再把问题归因于 Frida、PID 或模块缺失。本轮只能说明：

1. Frida/server/脚本链路正常。
2. 主进程选择正确，不是 sandboxed_process 问题。
3. 关键 native 网络/验证库已加载。
4. 但前台 UI 没有真正进入或刷新直播间，导致目标直播链路未触发。

判定口径：

- `align-window=1` 在没有目标 `ssl-live` 的情况下不是后置注入证据。
- 统计里的 `X-Cylons=1` 必须回看来源；若来自 ready/filter 文本，不能算命中。
- 只有出现任一目标 SSL 明文，才进入算法入口分析：
  ```text
  /webcast/im/push/preview_v2/
  /webcast/im/push/v3
  /ws/v2
  /bytelink/wss/v1/
  ```
- 在目标 URL/header 未出现前，下一步是解决直播间触发：进房、刷新、切房、等待 WS 建连；不是扩大 hook 范围。

对用户汇报时建议措辞：采样链路恢复/正常，主进程与关键模块也正确，但本轮没有抓到目标直播 SSL 明文，或只抓到非目标直播旁路请求；算法入口没有新增证据。

### 2026-05-11 ADB/视觉触发直播链路与 Frida 半失效经验

当 v12/v13 focused 采样没有目标 SSL 明文时，要把“前台触发失败”和“Frida 注入失败”分开处理。

UI/触发侧负样本：

1. 抖音搜索页如果输入的是 URL 编码文本，例如：
   ```text
   %E7%9B%B4%E6%92%AD
   ```
   搜索结果可能长期卡在加载/骨架屏；这不是直播接口没走，而是入口没有真正触发。
2. 搜索 `live`、切到“直播”tab，或进入“直播榜”后如果只有骨架屏/占位条，点击占位项通常不会进直播间，也不会触发：
   ```text
   /webcast/im/push/preview_v2/
   /webcast/im/push/v3
   /ws/v2
   /bytelink/wss/v1/
   ```
3. 连续看到搜索结果页/直播榜骨架屏时，优先排查设备网络、代理、证书环境或换入口：推荐流 LIVE 标记、已有 deeplink/room URL、首页刷新/切房。不要继续扩大 hook。

Frida 侧半失效负样本：

1. Python Frida 与设备 frida-server 版本一致（例如均为 `17.9.7`）仍可能出现：
   ```text
   frida.TransportError: timeout was reached     # create_script 卡住
   frida.ServerNotRunningError: unable to connect to remote frida-server: closed
   ```
2. 如果枚举/定位主进程可用，但 `attach()` 或 `create_script()` 卡住/closed，通常是 frida-server 半失效：枚举链路还活着，注入链路已坏。
3. 先干净重启 root frida-server，再跑最小脚本验证，成功标志：
   ```text
   attached
   {"tag":"hi","pid":<main_pid>}
   ok
   ```
4. 只有最小 attach/create_script 验证通过后，才继续 v12/v13 ring-buffer 采样。否则不要把超时误判成目标 hook offset 或脚本逻辑错误。

### 2026-05-11 v12 真直播间但无目标 SSL 明文的判定

一次后续 v12 focused 采样中，ADB/视觉已确认处于真实直播间：页面有主播信息、弹幕、输入框、礼物/互动按钮，不是推荐页、搜索结果页或直播 tab 骨架屏。但采样仍出现：

```text
hook-ok=35
Traceback=0
TransportError=0
ssl-live=0
libvcnverify.so!=0
libvcn.so!=0
```

同时 `libsscronet.so!0x2d469c` 多次命中，内存可见：

```text
webcast100-ws-c-lf.amemv.com
compress_type
```

判定规则：

1. 视觉确认“真实直播间”只能证明 UI 入口正确，不保证当前采样窗口一定会触发目标 SSL 明文；直播间可能已复用长连接、处于静默期，或目标请求未在采样窗口内重发。
2. `0x2d469c` 看到 `webcast100-ws-c-lf.amemv.com` / `compress_type`，说明该点仍是直播 WS/Cronet 请求构造或发送链路锚点；但这不是 `X-Cylons` 算法入口证据。
3. 统计里的 `X-Cylons=1` 若来自脚本 ready/filter 文本，仍不能算真实请求头；必须回看原始日志确认来源。
4. `libvcnverify.so` / `libvcn.so` 没有 offset-enter，只能说明本轮没有在目标 SSL 窗口内看到 vcn 同步参与；不能排除 vcn 参与其它窗口或早期注册。
5. 在“真实直播间 + hook 正常 + 无目标 SSL 明文”时，不要继续扩大 hook；优先触发新网络事件：切房、刷新直播间、退出重进、等待 WS 重连，或 force-stop 后早期 attach 重新捕获建连。

对用户汇报时建议明确：本轮确认了 UI 入口与 `0x2d469c` 直播 WS/Cronet 锚点，但没有抓到 `/webcast/im/push/preview_v2/`、`/webcast/im/push/v3`、`/ws/v2` 或 `/bytelink/wss/v1/` 的目标 SSL 明文，因此不能推进 `X-Cylons` 下游 offset/vcn 同步关系判断。当前判断仍保持：`X-Cylons` 大概率在 `0x2d469c` 之后、`SSL_write` 之前的 TTNet/native 后置 header 合成链路中注入，重点区间仍是 `0x3a6b50 -> 0x3ec44c -> 0x3ec4f0` 与 vcn/opaque sign callback。

### 2026-05-12 v12 resample：player/livestrategy 命中不要误判为 X-Cylons 同步窗口

一次 300 秒 v12 ring-buffer 重采样正常跑满并退出：

```text
duration reached; detaching
done /opt/data/home/reverse-tools/douyin_analysis/v12_xcylons_ringbuffer_0511.log
```

过程中 `libsscronet.so!0x2d469c` 可命中直播播放器/策略相关内存片段，典型字段：

```text
compress_type
player_client_biz_domain
super_resolution_enabled
player_client_associate_page
player_client_resolution
is_multi_came...
```

backtrace 仍可见 `libsscronet -> libttboringssl -> libttcrypto -> libsscronet` 的 SSL/TTNet 链路锚点。但这些 player/protobuf/config 字段只说明直播播放链路或请求对象活跃，不等于已命中带 `X-Cylons` 的目标 SSL 明文，也不能直接证明 vcn 同步窗口。

同轮还可能看到：

```text
libsscronet!0x2d45f4  # backtrace 可回到 base.odex/libart，hits 为空
libsscronet!0x2d4a38  # backtrace 进入 liblivestrategy.so!0x5b6f0/0x5b8bc/0x5a988/0x3c854/0x41bc0/0x41a94
```

判定口径：

1. `0x2d469c` 出现 `compress_type`、`player_client_*`、`webcast100-ws-c-lf` 等，是直播 player/WS/Cronet 锚点证据，不是 header 注入或算法入口证据。
2. `0x2d4a38` 进入 `liblivestrategy.so` 更偏直播策略/播放器决策链路；除非同一时间窗口 SSL 明文出现 `X-Cylons`/目标 URL，否则不要把它当作签名入口。
3. 采样脚本正常结束且无 Traceback/TransportError，只说明链路稳定；最终结论必须基于完整日志统计：目标 URL、真实 SSL 明文、`X-Cylons`、`x-tt-e-*`、`vcn/libvcnverify` offset 是否在同一 ring-buffer 窗口内同步出现。
4. 如果只看到 player/livestrategy 字段而未确认 `/webcast/im/push/*`、`/ws/v2`、`/bytelink/wss/v1` 明文和真实安全头，结论应写成“采样点方向有效，但目标 SSL/X-Cylons/vcn 同步窗口尚未确认”。

### 2026-05-12 v12 after-unlock：真实直播间触发动作要保守，避免登录页干扰

一次解锁后重采样中，ADB/视觉确认进入真实直播间，截图示例：

```text
/tmp/douyin_live_room.png
```

页面含主播信息、关注按钮、聊天区、礼物/分享/互动按钮、直播榜单/活动入口，说明 UI 入口真实。但运行：

```text
python3 /opt/data/home/reverse-tools/douyin_analysis/run_v12_xcylons_ringbuffer_0511.py 240
```

仍可能得到负样本：

```text
hook-ok=35
hook-err=3
offset-enter=4
ssl-live=0
align-window=1
Traceback=0
TransportError=0
/webcast/=0
/ws/v2=0
/bytelink/wss=0
x-tt-e-=0
```

报告示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/v12_after_unlock_resample_0512.md
```

关键经验：

1. “真实直播间 UI”不等于采样窗口里一定会重发 `/webcast/im/push/*`、`/ws/v2`、`/bytelink/wss/v1`。长连接可能已复用或静默，仍需主动触发切房、刷新、退出重进或等待 WS 重连。
2. 触发动作要保守：不要点输入框、礼物、关注、活动等容易触发登录态检查的控件；实测可能跳到：
   ```text
   com.ss.android.ugc.aweme.account.business.login.DYLoginActivity
   ```
   之后 Back 可能返回桌面，导致采样窗口失效。
3. 优先使用直播间内上下滑切房/刷新，或从稳定入口重新进入直播间；每轮采样前后都用截图/前台 activity 确认仍在直播间。
4. `X-Cylons=1` 若只来自脚本 ready/filter 文本，仍不能算真实请求头；必须有目标 SSL 明文或 ring-buffer 同步窗口中的真实数据。
5. 只有 `ssl-live` 命中以下任一目标才进入算法入口判断：
   ```text
   /webcast/im/push/preview_v2/
   /webcast/im/push/v3
   /ws/v2
   /bytelink/wss/v1/
   ```
   并且同一窗口里出现真实 `X-Cylons` 或 `x-tt-e-*`。
6. 无目标 SSL 明文时，结论保持：`libsscronet.so!0x2d469c` 是直播/Cronet请求构造或发送路径锚点，不是 `X-Cylons` 算法入口；可疑区间仍是 `0x3a6b50 -> 0x3ec44c -> 0x3ec4f0` 与 opaque/vcn 回调链。

### 2026-05-12 `0x346bcc` X-Cylons 真实 header-list 命中经验

v12 relaunch 日志中，`libsscronet.so!0x346bcc` 首次在入参/周边内存里命中真实 `X-Cylons` header name/value 对，证据文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/v12_from_relaunch_020907_0512.console.log
/opt/data/home/reverse-tools/douyin_analysis/xcylons_346bcc_entry_progress_0512.md
```

关键事件：

```text
tag=offset-enter
label=libsscronet!0x346bcc
args=["0x70d96057c0", "0x6fef8bf180", "0x3e", "0x6fef8bf1bd", ...]
bt=[
  "libsscronet.so!0x346bcc",
  "libsscronet.so!0x4cff5c",
  "libsscronet.so!0x4cff50",
  "libsscronet.so!0x21e17c",
  "libsscronet.so!0x2107dc",
  "libsscronet.so!0x2235d8",
  "libsscronet.so!0x302114",
  "libsscronet.so!0x30ff40",
  "libsscronet.so!0x34059c",
  "libsscronet.so!0x3406e4",
  "libsscronet.so!0x310510",
  "libsscronet.so!0x2f8d50"
]
```

内存片段可解读为 protobuf-like/header-list：

```text
08 08 10 08 18 8f 4e 20 01 2a 24 0a 08 58 2d 43 79 6c 6f 6e 73 12 18 55 4e 42 38 4d 66 67 4f 71 54 79 6c 51 30 4b 74 62 38 48 67 42 78 2b 64 32 04 6e 6f 6e 65 3a 02 68 62 42 02 10 00
```

对应明文：

```text
X-Cylons = UNB8MfgOqTylQ0Ktb8HgBx+d2
none
hbB
```

判定口径：

1. `0x346bcc` 已是当前最强的 `X-Cylons` header 打包/添加入口候选；它比 SSL 明文更靠近 TTNet/Cronet native header 合成链。
2. 仍不能把 `0x346bcc` 直接等同为算法本体入口：当前证据只证明该点能看到 name/value 对，尚未证明 value 是在该函数内生成，还是由上游传入后在此处打包。
3. `0x2d469c` 继续作为请求构造/发送锚点；`0x2d45f4` 可见下游 header/path 字节；二者都不应再被优先当作 X-Cylons 算法入口。
4. `libvcnverify.so` / `libvcn.so` 同轮可有少量 offset 命中，但若没有与真实 `X-Cylons` 命中窗口同步，不能确认 vcn 就是算法本体入口，也不能据此排除。
5. 后续采样应围绕 `0x346bcc` 做 onEnter/onLeave 内存 diff：记录 args[0..7] 指针、返回值、调用前后 1-2KB 内存，判断 `X-Cylons` 是 enter 前已有还是函数内部写入。
6. 上游反推优先 hook/ring-buffer 这些 backtrace offset，只在 `0x346bcc` 命中真实 `X-Cylons` 时吐出窗口：
   ```text
   0x4cff5c
   0x4cff50
   0x21e17c
   0x2107dc
   0x2235d8
   0x302114
   0x30ff40
   0x34059c
   0x3406e4
   0x310510
   0x2f8d50
   ```
7. v13 focus 采样中 `hook-ok=22`、`offset-hit=186`、`/ws/v2=97`、`x-security-argus=6`、`x-tt-e-=2`、`/webcast/feed/live_tab=2`，说明 `0x2d469c/0x2d45f4` 对请求对象仍稳定可见；但若 v13 日志里的 `X-Cylons` 主要来自 hook label/ready 文本，就不能算真实请求证据。真实 X-Cylons 证据仍以 v12 `0x346bcc` 事件为准。

对用户汇报时务必区分：已定位到强候选 header 打包/添加点 `0x346bcc`，但 `X-Cylons` value 生成算法尚未完整还原。

### 2026-05-12 v14 `0x346bcc` enter/leave diff 负样本经验

在已有 v12 真实样本确认 `libsscronet.so!0x346bcc` 入参/header-list 可见真实：

```text
X-Cylons = UNB8MfgOqTylQ0Ktb8HgBx+d2
```

之后准备并运行 v14 enter/leave diff 脚本：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v14_346bcc_enter_leave_diff_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v14_346bcc_enter_leave_diff_conclusion_0512.md
```

本轮统计：

```text
hook-ok=32
ring-enter=12
ring-hit=8
```

但没有再次命中真实 `X-Cylons` 或已知 value 片段 `UNB8`。判定口径：

1. `hook-ok`、`ring-enter`、`ring-hit` 只能证明 `0x346bcc` 及上游 ring-buffer hook 链路正常，不能证明命中了带 `X-Cylons` 的目标窗口。
2. 如果 enter/leave diff 没有真实 `X-Cylons`/value，不能判断 value 是在 `0x346bcc` 函数内部生成，还是 enter 前由上游传入。
3. 不能把“v14 未复现真实 X-Cylons”当作否定 `0x346bcc` 的证据；v12 的真实 header-list 命中仍使 `0x346bcc` 保持当前最强 header 打包/添加点候选。
4. 下一步应继续围绕 `0x346bcc` 做可复现目标窗口采样：只有当 enter 前无 value、leave 后出现 value，才能支持“函数内部写入/生成”；若 enter 前已存在 value，则沿上游 backtrace offset 反推算法入口。
5. 汇报时保持三分法：
   - 接口/协议链路：已确认。
   - header 打包/添加点：`0x346bcc` 当前最强。
   - 算法本体/value 生成：尚未还原。

### 2026-05-12 v15/v16 SSL 对齐与 3a 链路探测经验

v15/v16 进一步验证了两类 `X-Cylons` 动态链路，证据文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/v15_ssl_xcylons_align_0512.log
/opt/data/home/reverse-tools/douyin_analysis/v16_3a_chain_probe_0512.log
/opt/data/home/reverse-tools/douyin_analysis/run_v16_3a_chain_probe_0512.py
```

v15 在 SSL 明文中抓到 `/webcast/im/push/v3/` WebSocket 握手完整请求：

```text
GET /webcast/im/push/v3/?... HTTP/1.1
Host: webcast100-ws-c-lf.amemv.com
X-Cylons: 8HDckViuCZyeDqQ9z2GtxL89
Sec-WebSocket-Key: 8pI6Qy+Kgx1TCPmnYG5idQ==
Sec-WebSocket-Protocol: pbbp2
```

对应稳定发送栈：

```text
libsscronet.so!0x3ec4f0
<- libsscronet.so!0x3ec44c
<- libsscronet.so!0x3a6b50
<- libsscronet.so!0x3a66b0
<- libsscronet.so!0x2d45f4
<- libsscronet.so!0x2d4a38
<- libsscronet.so!0x51997c
<- libsscronet.so!0x388864
```

v16 以 `0x3ec4f0/0x3ec44c/0x3a6b50/0x3a66b0/0x2d45f4/0x2d4a38/0x51997c/0x388864/0x346bcc/0x4cff5c` 做入参扫描，确认：

1. `0x346bcc` 可稳定命中 IM ACK / 上行包内 `X-Cylons`，典型内容：
   ```text
   X-Cylons..qCiEyQD2UcRdu/rTlzk4nOdl2.none:.ackB
   internal_src:pushserver|first_req_ms:...|seq:5|wss_msg_type:wrds|wrds_v:...
   ```
   典型 backtrace：
   ```text
   libsscronet.so!0x346bcc
   <- libsscronet.so!0x4cff5c
   <- libsscronet.so!0x4cff50
   <- libsscronet.so!0x21e17c
   <- libsscronet.so!0x2107dc
   <- libsscronet.so!0x2235d8
   <- libsscronet.so!0x302114
   <- libsscronet.so!0x2107dc
   ```
2. `0x3ec4f0/0x3ec44c` 可在非目标窗口看到 `webcast100-ws-c-lf.amemv.com` 等连接/host 周边内存，但不一定直接持有完整 HTTP 明文；最终握手明文仍以 SSL_write 为准。
3. `0x2d45f4/0x2d4a38` 会频繁出现 webcast/frontier/DNS/日志对象，噪声较大；只有与 SSL 明文目标 URL/header 同窗口对齐时才算链路证据。

判定口径更新：

- 当前应把 `X-Cylons` 分成两条动态证据链：
  1. WebSocket 握手 `X-Cylons`：最终明文在 SSL_write，发送栈重点是 `0x3ec4f0 <- 0x3ec44c <- 0x3a6b50 <- 0x3a66b0 ...`。
  2. IM ACK/uplink 包内 `X-Cylons`：`0x346bcc <- 0x4cff5c <- 0x4cff50 ...` 是当前最强 header-list/包打包候选。
- 抓到 SSL 明文或 `0x346bcc` 包内 value，只能说明接口链路和 header/包打包点已确认；仍不能宣称算法本体已还原。
- 下一步如果要还原算法，应围绕真实 `X-Cylons` 命中窗口做 enter/leave diff 和上游 ring-buffer：
  - WebSocket 握手链：重点 `0x3a6b50/0x3a66b0/0x3ec44c/0x3ec4f0`。
  - IM ACK/uplink 链：重点 `0x346bcc/0x4cff5c/0x4cff50/0x21e17c`。
  - 只有当 enter 前无 value、leave 后出现 value，才可把某函数升级为“生成/写入点”；否则它仍只是“携带/打包点”。
- 对用户汇报继续明确区分：接口/协议链路已确认，动态打包/发送点已强收窄，算法本体/value 生成还未完整挖出。

### 2026-05-12 v18 ACK + X-Cylons 同窗采样负样本经验

v18 围绕 IM ACK/uplink 包内 `X-Cylons` 链路做 ring-buffer/onEnter/onLeave 同窗采样，目标包括：

```text
libsscronet.so!0x346bcc
libsscronet.so!0x4cff5c
libsscronet.so!0x4cff50
libsscronet.so!0x21e17c
libsscronet.so!0x2107dc
```

沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v18_ack_xcylons_window_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v18_ack_xcylons_window_0512.log
/opt/data/home/reverse-tools/douyin_analysis/v18_ack_xcylons_window_conclusion_0512.md
```

一次典型负样本流程：先确认抖音主进程是否存在；若 `pid None`，通过 ADB 启动 App，再确认主进程和关键 so：

```text
libsscronet.so
libttboringssl.so
libttcrypto.so
libvcn.so
libvcnverify.so
```

该轮 hook 安装正常：

```text
hook-ok=13
hook-err=0
Traceback=0
TransportError=0
```

但 300 秒窗口内没有目标 ACK / X-Cylons 事件复现：

```text
enter=0
leave=0
ack-window=0
xc-window=0
```

判定口径：

1. 主进程、模块和 hook 安装都正常，但 `enter/leave/ack-window/xc-window` 全为 0 时，只能记为“目标 IM ACK/uplink 事件未复现”的负样本。
2. 日志中的 `X-Cylons`、`ackB`、`client_start_pack_time` 若只来自脚本 ready/filter 文本，不是真实请求或内存证据，不能算命中。
3. 该类负样本不能推进算法入口判断，也不能否定 v16 的真实证据。
4. 当前最强 IM ACK/uplink 证据仍以 v16 为准：`0x346bcc` / `0x4cff5c` 在 enter 时同一 buffer 内已经携带 `client_finish_pack_time`、`client_send_ack_time`、`client_start_pack_time`、`client_recv_time`、`X-Cylons=<value>`、`ackB` 与 `internal_src:pushserver|...|wss_msg_type:wrds`。
5. 因为 v16 显示 `0x346bcc` 和 `0x4cff5c` enter 时 value 已存在，所以它们更像 IM ACK/uplink 包内 `X-Cylons` 的携带/打包链路，不是最上游生成点。
6. 更上游是否在 `0x4cff50 / 0x21e17c / 0x2107dc / 0x2235d8 / 0x302114` 内写入，需要再次命中真实 ACK/X-Cylons 窗口后才能判断。

对用户汇报时建议明确：v18 是链路正常但目标事件未复现的负样本；目前已确认协议链路、SSL 明文、IM ACK/uplink 打包携带链路，算法本体/value 生成仍未完整还原。

### 2026-05-12 v19 上游 enter/leave/ring-buffer 严格采样经验

v19 在 v16/v18 基础上继续做上游 enter/leave/ring-buffer 严格采样，目标是避免 ready/filter 文本误报，只在真实 ACK 或 `X-Cylons` 数据窗口出现时吐出证据。沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v19_upstream_xcylons_strict_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v19_upstream_xcylons_strict_conclusion_0512.md
```

执行前先做脚本可执行性检查：

```text
python3 -m py_compile run_v19_upstream_xcylons_strict_0512.py
# JS 提取/静态检查应确认 hook JS 可解析，且没有把 ready 文本计入真实命中
```

典型流程与判定：

1. 如果首次运行发现：
   ```text
   pid None
   no pid
   ```
   先用 ADB 启动抖音并确认主进程，而不是直接修改 hook：
   ```text
   frontmost com.ss.android.ugc.aweme <pid> 抖音
   app com.ss.android.ugc.aweme 抖音 <pid>
   ```
2. attach 后必须确认关键 so 已加载：
   ```text
   libsscronet.so
   libttboringssl.so
   libttcrypto.so
   libvcn.so
   libvcnverify.so
   ```
3. 若统计类似：
   ```text
   hook-ok=13
   hook-err=0
   Traceback=0
   TransportError=0
   strict-x-window=0
   strict-ack-window=0
   strict-enter-x=0
   strict-leave-new-x=0
   X-Cylons=0
   ackB=0
   /webcast/=0
   /ws/v2=0
   /bytelink/wss=0
   ```
   应判定为“主进程、模块、Frida、hook 链路全部正常，但采样窗口内目标 ACK/X-Cylons 事件未复现”的负样本。
4. v19 负样本不能否定 v16 真实证据。当前最强证据仍是：`0x346bcc / 0x4cff5c` 在 v16 中真实看到 IM ACK/uplink 包内携带 `X-Cylons`；但它们更像携带/打包点，`X-Cylons` value 最上游生成算法仍未完整还原。
5. 对用户汇报时继续使用三分法：
   - 协议/接口链路：已确认。
   - header/包携带或打包点：`0x346bcc / 0x4cff5c` 为强证据。
   - 算法本体/value 生成：尚未还原；负样本只说明目标事件未复现。

### 2026-05-12 v22 first-seen diff：`0x21e17c` 上游传播层新增证据

v22 围绕 `0x346bcc` 上游链做 strict first-seen enter/leave diff，目标是追踪 `X-Cylons` value 首次出现层，而不是只确认最终携带点。沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v22_first_seen_xcylons_diff_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v22_first_seen_xcylons_diff_0512.log
/opt/data/home/reverse-tools/douyin_analysis/v22_first_seen_xcylons_diff_conclusion_0512.md
```

典型统计：

```text
hook-ok=15
hook-err=0
Traceback=0
TransportError=0
v22-x-enter=20
v22-x-leave-new=0
v22-ack-enter=4
v22-live-context=5
```

主要命中点：

```text
up!0x21e17c  xEnter=17, enter=165
up!0x302114  xEnter=1
ctx!0x30ff40 xEnter=1
up!0x2235d8  xEnter=1
```

关键经验：

1. v22 把 `X-Cylons` / `/webcast/` / `/ws/v2` 周边内存窗口进一步推到 `libsscronet.so!0x21e17c` 这一层；该点 enter 时已经能看到 `X-Cylons` 相关对象。
2. 典型 backtrace：
   ```text
   libsscronet.so!0x21e17c
   <- libsscronet.so!0x3f0348 / 0x38549c / 0x433798
   <- libsscronet.so!0x30fc84
   <- libsscronet.so!0x30fbf8
   <- libsscronet.so!0x3404ac
   <- libsscronet.so!0x533650
   <- libsscronet.so!0x5337d0
   <- libsscronet.so!0x3406e4
   <- libsscronet.so!0x310510
   <- libsscronet.so!0x2f8d50
   ```
3. ACK 侧也可命中真实上下文字段：
   ```text
   ackB
   client_start_pack_time
   client_finish_pack_time
   client_send_ack_time
   client_recv_time
   internal_src:pushserver
   wss_msg_type
   wrds_v
   /webcast/
   ```
4. `v22-x-leave-new=0` 是关键边界：本轮没有观察到“enter 前无 X-Cylons、leave 后新出现 X-Cylons”，因此不能把 `0x21e17c`、`0x346bcc` 或其它已 hook offset 升级为算法生成/写入点。
5. v22 与 v16/v20 结论兼容：`0x346bcc / 0x4cff5c` 仍是 IM ACK/uplink 包内 `X-Cylons` 的强携带/打包点；`0x21e17c` 是新增的更上游传播/携带层证据；算法本体/value 生成入口仍未完整还原。
6. 采样进程可能超过传入 duration 不自然退出；如果已产出 summary 与有效事件，可手动 kill 后分析日志，但后续脚本应修复退出逻辑，避免后台进程长时间挂起。
7. `extractX` 不要从 JSON keys 或脚本文本中误抽 value；日志中多为 protobuf/对象池原始内存，`X-Cylons` 字段和值未必线性相邻，干净 value 仍应以真实 ASCII/SSL/内存字段为准。

下一步如果继续追算法本体，应以 `0x21e17c` 为新锚点，围绕直接调用邻域做更短窗口 enter/leave diff：

```text
0x3f0348
0x38549c
0x433798
0x30fc84
0x30fbf8
0x3404ac
0x533650
0x5337d0
```

判定标准保持不变：只有观察到某点 enter 前无 value、leave 后出现 value，或定位到明确 sign/opaque callback 输出，才能称为 `X-Cylons` value 生成点；否则仍只能称为携带/传播/打包链路。

### 2026-05-12 v23 `0x21e17c` 邻域 first-seen diff 负样本经验

v23 修复了采样脚本退出逻辑，并围绕 v22 中 `0x21e17c` 直接调用邻域继续做 strict enter/leave first-seen diff。沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v23_21e17c_neighbor_first_seen_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v23_21e17c_neighbor_first_seen_0512.log
/opt/data/home/reverse-tools/douyin_analysis/v23_21e17c_neighbor_first_seen_conclusion_0512.md
```

典型统计：

```text
script-start=1
ready=1
hook-ok=14
hook-err=0
v23-live-enter=3
v23-x-enter=0
v23-x-leave-new=0
v23-ack-enter=0
X-Cylons=0
ackB=0
client_start_pack_time=0
/webcast/=0
/ws/v2=18
/bytelink/wss=0
Traceback=0
TransportError=0
```

本轮只在这些邻域点看到 `/ws/v2` Frontier 配置上下文：

```text
mid!0x3404ac
mid!0x30fc84
mid!0x5337d0
```

典型内存字段：

```text
final_host=frontier-aweme-lf-ipainner.amemv.com
heartbeat_interval=30
/ws/v2
```

判定口径：

1. `hook-ok=14`、`hook-err=0`、无 `Traceback/TransportError`，且关键 so 已加载时，应先判定 Frida、主进程、模块与 hook 链路正常。
2. `v23-x-enter=0`、`v23-x-leave-new=0`、日志全文 `X-Cylons=0` 时，本轮不能算 `X-Cylons` 生成/传播窗口；不要从 `/ws/v2` 配置文本推断算法入口。
3. `ackB=0`、`client_start_pack_time=0`、`v23-ack-enter=0` 时，本轮没有复现 IM ACK/uplink 目标事件，不能推进 ACK 包内 `X-Cylons` 生成点判断。
4. `0x3404ac / 0x30fc84 / 0x5337d0` 在 v23 中只能表述为 Frontier `/ws/v2` 配置/传播上下文点；没有真实 `X-Cylons` 或 first-seen diff 前，不应升级为算法入口。
5. v23 负样本不能否定 v16/v20/v22 真实证据。当前总判断仍是：`0x346bcc / 0x4cff5c` 为 IM ACK/uplink 包内 `X-Cylons` 强携带/打包点，`0x21e17c` 是更上游传播层，算法本体/value 生成点仍未完整还原。
6. 后续继续追时，应先复现真实 `X-Cylons` / `ackB` / `client_start_pack_time` 窗口，再分析邻域 enter/leave diff；否则只记录为“链路正常但目标事件未复现”。

### 2026-05-12 v25 `0x21e17c` 上游 first-seen：ACK 上下文活跃但 X-Cylons 未复现

v25 继续围绕 `0x21e17c` 邻域与上游链做 first-seen / enter-leave diff，沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v25_21e17c_upstream_firstseen_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v25_21e17c_upstream_firstseen_0512.log
/opt/data/home/reverse-tools/douyin_analysis/v25_21e17c_upstream_firstseen_conclusion_0512.md
```

一次典型统计：

```text
hook-ok=28
hook-err=0
Traceback=0
TransportError=0
v25-x-enter=0
v25-x-leave-new=0
v25-ssl-x=0
v25-ssl-live=0
v25-ack-enter=3
v25-live-enter=21
X-Cylons=0
ackB=593
client_start_pack_time=115
/webcast/=7639
/ws/v2=552
```

判定口径：

1. `hook-ok`、无 `Traceback/TransportError` 说明 Frida/主进程/hook 链路正常；这类结果不是脚本失效。
2. `v25-ack-enter` 可在 `up!0x2107dc` 看到 ACK/uplink 字段：`ackB`、`client_start_pack_time`、`client_finish_pack_time`、`client_send_ack_time`、`client_recv_time`、`internal_src:pushserver`、`wss_msg_type`、`wrds_v`。因此 `0x2107dc` 是值得保留的 ACK 上下文点。
3. `anchor!0x21e17c` 继续可见 live/frontier/webcast 上下文，支持它是上游传播/携带/上下文层；但没有 `xEnter/xLeaveNew` 时不能升级为生成点。
4. 若全文 `X-Cylons=0` 且 `v25-ssl-x=0`，即便 `/webcast/`、`/ws/v2`、`ackB` 很多，也只能算“ACK/live 上下文活跃但目标 X-Cylons/SSL 窗口未复现”的负样本。
5. v25 进程可能超过传入 duration 不自然退出；若日志已有 summary，可手动 kill 后分析，但后续脚本应修复退出逻辑。


### 2026-05-12 v26 ACK/X-Cylons source-window 负样本经验

v26 继续围绕已验证 ACK / `X-Cylons` 链路做更严格 source-window / first-seen 采样，沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v26_ack_xcylons_source_window_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v26_ack_xcylons_source_window_0512.log
/opt/data/home/reverse-tools/douyin_analysis/v26_ack_xcylons_source_window_conclusion_0512.md
```

本轮 hook 安装与运行链路正常：

```text
script-start=1
hook-ok=21
ready=1
hook-err=0
mod-miss=0
hook-miss=0
Traceback=0
TransportError=0
```

关键 so 已加载：

```text
libsscronet.so
libttboringssl.so
libttcrypto.so
libvcn.so
libvcnverify.so
```

但最终统计显示没有复现真实 ACK / `X-Cylons` 目标窗口：

```text
xEnter=0
xLeaveNew=0
ackEnter=0
ackLeaveNew=0
sslX=0
sslLive=0
liveEnter=5
emitted=0
```

`first` 中 `x/ack/client_start_pack_time/client_finish_pack_time/client_send_ack_time/client_recv_time/internal_src/wss_msg_type/wrds_v` 全为空。日志中唯一 `X-Cylons=1` 来自脚本 ready/note 文本，不是真实请求或内存证据，不能算命中。

有效命中仅限 live/frontier/webcast 上下文：

```text
mid!0x5337d0
anchor!0x21e17c
up!0x2235d8
up!0x302114
ctx!0x30ff40
```

可见关键词包括：

```text
/webcast/
/ws/v2
/bytelink/wss
webcast100-ws
```

判定口径：

1. v26 是“主进程、模块、hook 链路正常，但目标 ACK/X-Cylons 事件未复现”的负样本。
2. 不能用 v26 否定 v16/v20/v22 的真实 `X-Cylons` / ACK 证据。
3. `0x21e17c / 0x2235d8 / 0x302114 / 0x30ff40` 在本轮只能继续表述为 live/frontier/webcast 上下文或传播层，不能升级为算法生成点。
4. `0x346bcc / 0x4cff5c` 仍保持 IM ACK/uplink 包内 `X-Cylons` 强携带/打包点判断；本轮没有命中不等于被否定。
5. 后续不要继续盲目扩大 hook；应先提高目标事件复现率：force-stop 后早期 attach，保守切房/重进/等待 WS 重连。只有出现真实 `X-Cylons`、`ackB`、`client_start_pack_time` 或目标 SSL 明文后，才分析 enter/leave diff。

### 2026-05-12 v27 reconnect-assisted 采样：NotificationShade/锁屏会让自动触发完全失效

v27 在 v26 负样本后加入了早期 attach、保守重连/切房触发与 strict first-seen 统计，沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v27_ack_xcylons_firstseen_reconnect_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v27_ack_xcylons_firstseen_reconnect_0512.console.log
/opt/data/home/reverse-tools/douyin_analysis/v27_ack_xcylons_firstseen_reconnect_0512.console2.log
/opt/data/home/reverse-tools/douyin_analysis/v27_ack_xcylons_firstseen_reconnect_conclusion_0512.md
```

一次典型受阻统计：

```text
script-start=2
ready=2
hook-ok=52
hook-err=0
mod-miss=0
LOCKED_OR_SHADED=2
skip_trigger_locked_or_shaded=12
TransportError=1   # 首轮 attach timeout
v27-summary=2
v27-first-seen=0
v27-ssl-x=0
X-Cylons=0
ackB=0
client_start_pack_time=0
/webcast/=0
/ws/v2=0
/bytelink/wss=0
```

设备状态反复显示：

```text
mCurrentFocus=Window{... NotificationShade}
mFocusedApp=... com.ss.android.ugc.aweme/.live.LivePlayActivity
mShowingDream=false mDreamingLockscreen=true
```

判定口径：

1. 第二轮 v27 能安装大量 `hook-ok`，说明脚本、主进程、模块与 Frida hook 链路基本正常；不要把本轮直接归因为 hook 点错误。
2. `NotificationShade` + `mDreamingLockscreen=true` 时，ADB 输入会被锁屏/通知栏捕获，v27 会输出 `skip_trigger_locked_or_shaded` 并跳过 UI 重连/切房；此时无法提高 ACK / `X-Cylons` 复现率。
3. 如果 `v27-first-seen=0`、`v27-ssl-x=0` 且全文没有真实 `X-Cylons` / `ackB` / `client_start_pack_time` / 目标 URL，本轮只能记为“锁屏/通知栏导致 UI 触发失败”的负样本。
4. 该负样本不能否定 v16/v20/v22 的真实证据；当前仍保持：`0x346bcc / 0x4cff5c` 是 IM ACK/uplink 包内 `X-Cylons` 强携带/打包点，`0x21e17c` 是上游传播层，`0x2107dc` 是 ACK 上下文点；value 生成算法仍未完整还原。
5. 下一轮必须先人工/物理解锁或以可靠方式退出 `NotificationShade`，确认 `mCurrentFocus` 回到抖音 `LivePlayActivity` 后再运行 v27。仅用 `input keyevent WAKEUP`、上下滑、Back 不一定能解除 Huawei/Samsung 设备的 dozing/NotificationShade 状态。

### 2026-05-12 v28 recover strict first-seen：链路正常但仍未复现目标 X-Cylons/ACK/SSL

v28 在 v27 基础上增加前台恢复逻辑：尝试从 `SplashActivity` / `NotificationShade` / 锁屏状态恢复到抖音前台，再运行 strict first-seen / ACK / `X-Cylons` / SSL 采样。沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v28_recover_strict_firstseen_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v28_recover_strict_firstseen_0512.console.log
/opt/data/home/reverse-tools/douyin_analysis/v28_recover_strict_firstseen_0512.log
/opt/data/home/reverse-tools/douyin_analysis/v28_recover_strict_firstseen_conclusion_0512.md
```

一次典型统计：

```text
hook-ok=26
hook-err=0
mod-miss=0
hook-miss=0
Traceback=0
TransportError=0
v28-summary=10
v28-first-seen=0
v28-ssl-x=0
v28-ssl-live=0
xEnter=0
xLeaveNew=0
ackEnter=0
ackLeaveNew=0
sslX=0
sslLive=0
liveEnter=7
```

主要活跃点：

```text
sslchain!0x2d45f4 enter=609 liveEnter=7
ackctx!0x2107dc enter=14 ackEnter=0
sslchain!0x2d4a38 enter=19
mid!0x533650 enter=1
mid!0x5337d0 enter=1
```

判定口径：

1. `hook-ok`、无 `Traceback/TransportError`、多次 summary 说明 Frida/主进程/模块/hook 链路正常。
2. 日志全文中的 `X-Cylons`、`ackB`、`client_start_pack_time` 等计数可能来自脚本字段名、summary JSON key 或 ready/filter 文本；真实命中必须看 `v28-first-seen-*`、`v28-x-enter`、`v28-ack-enter`、`v28-ssl-x`、`v28-ssl-live` 与 summary counters。
3. 若这些严格 tag/counter 全为 0，即使 `/webcast/`、`/ws/v2`、`webcast100-ws` 出现，也只能记为 live/frontier/webcast 上下文活跃，不是 `X-Cylons` 或 ACK 目标窗口。
4. v28 负样本不能否定 v16/v20/v22 的真实证据；当前仍保持：`0x346bcc / 0x4cff5c` 是 IM ACK/uplink 包内 `X-Cylons` 强携带/打包点，`0x21e17c` 是上游传播层，`0x2107dc` 是 ACK 上下文点。
5. v28 进程可能超过传入 duration 未自然退出；若已有 summary 和有效日志，可手动 kill 后分析，后续脚本需修复退出逻辑。
6. 下一轮不要盲目扩大 hook；先确保真实直播间/WS 重连/ACK 事件复现，再分析 enter/leave first-seen。

### 2026-05-12 v29 static sscronet offset analysis：静态巩固，不是算法还原完成

v29 在 v28 连续负样本后转为静态巩固，避免目标事件未复现时继续空跑。沉淀文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_sscronet_offsets_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v29_static_sscronet_offset_analysis_0512.md
/opt/data/home/reverse-tools/douyin_analysis/v29_static_sscronet_offset_analysis_conclusion_0512.md
```

目标 SO：

```text
/opt/data/home/reverse-tools/douyin_analysis/native_libs/libsscronet.so
ELF AArch64, .text addr=0x1f7044, size=0x3fad68
```

分析范围：

```text
ACK/uplink 包链：0x346bcc / 0x4cff5c / 0x4cff50 / 0x21e17c / 0x2107dc / 0x2235d8 / 0x302114 / 0x30ff40
v22/v23 邻域：0x3404ac / 0x533650 / 0x5337d0 / 0x30fc84 / 0x30fbf8
SSL/WebSocket 发送链：0x3ec4f0 / 0x3ec44c / 0x3a6b50 / 0x3a66b0 / 0x2d45f4 / 0x2d4a38 / 0x51997c / 0x388864
```

关键静态观察：

1. `0x346bcc` 附近 prologue 为 `0x346b94`，表现为小型对象/字段搬运函数，不像复杂算法体：
   ```text
   0x346bc8: bl #0x1f9ff8
   0x346bcc: ldrsb w8, [x21, #0x17]
   0x346bd4: ldr x8, [x21, #8]
   0x346bec: str x20, [x19, #0x10]
   ```
   这支持 v12/v16 动态判断：`0x346bcc` 是 header-list/protobuf-like 对象的携带/打包点，不是最上游 value 生成算法。
2. `0x4cff50 / 0x4cff5c` 附近可见分配 `0x30` 大小对象并调用 `0x346b90`，随后引用计数和对象传递：
   ```text
   0x004cff4c: bl #0x33594c
   0x004cff50: add x1, sp, #8
   0x004cff58: bl #0x346b90
   0x004cff5c: stur x21, [x29, #-0x20]
   0x004d0060: blr x8
   ```
   这更像 ACK/uplink 包构建中的创建/包装/传递层。
3. `0x21e17c / 0x2107dc` 静态 call 密集，符合动态上“上游传播/ACK 上下文层”特征；v22/v25 仍无 leave-new / first-seen 证据，不能升级为生成点。
4. SSL 发送链 `0x3ec4f0 <- 0x3ec44c <- 0x3a6b50 <- 0x3a66b0 ...` 仍适合作为 WebSocket 握手最终发送链和 SSL 对齐链；静态窗口没有给出 value 生成算法证据。

v29 结论边界：

- 协议/接口链路：已确认。
- `X-Cylons` 最终安全头/包内字段：已在 SSL 明文与 IM ACK/uplink 包真实出现。
- 强携带/打包点：`0x346bcc / 0x4cff5c / 0x4cff50`。
- 上游传播/ACK 上下文点：`0x21e17c / 0x2107dc`。
- WebSocket 发送链：`0x3ec4f0 / 0x3ec44c / 0x3a6b50 / 0x3a66b0 ...`。
- 算法本体 / value 生成点：仍未完整还原；v29 静态结果没有足够证据把任何已知点升级为生成算法入口。

下一步建议：

1. 不再单纯扩大 hook 面。
2. 动态继续时，优先复现真实 `X-Cylons`/ACK 窗口，再只围绕 `0x4cff50 -> 0x346b90 -> 0x346bcc` 做 enter/leave object diff，确认 value 在调用前是否已存在。
3. 静态继续时，以 `0x4cff50` 附近调用 `0x4d0238 / 0x51cd50 / blr x8` 为切入点，结合交叉引用和对象字段偏移，定位真正填充 `sp+8` / header 对象的上游路径。

### 2026-05-12 v30 `0x346b90 / 0x4cff50` 深挖：确认是对象复制/传递，不是 X-Cylons value 生成

v30 继续静态深挖 `0x346b90`、`0x346bcc`、`0x4cff50`、`0x4cff5c` 与 `sp+8` header/string 对象来源，沉淀文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v30_346b90_4cff50_deep_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v30_346b90_4cff50_deep_static_0512.md
/opt/data/home/reverse-tools/douyin_analysis/v30_346b90_4cff50_conclusion_0512.md
```

关键反汇编证据：

```text
0x004cff3c: add x0, sp, #8
0x004cff40: mov x1, x21
0x004cff44: bl  #0x1ff5fc      # 最近填充/拷贝 sp+8
0x004cff48: mov w0, #0x30
0x004cff4c: bl  #0x33594c      # 分配/取得 0x30 字节目标对象
0x004cff50: add x1, sp, #8
0x004cff54: mov x21, x0
0x004cff58: bl  #0x346b90      # 用 sp+8 源对象构造/复制新对象
0x004cff5c: stur x21, [x29, #-0x20]
0x004cffb0: mov x3, x21
0x004cffb4: bl  #0x51cd50      # 消费/传递对象
```

`0x346b90 .. 0x346c04` 本身只表现为目标对象初始化、短字符串/对象布局标志检查与字段复制：

```text
x0 = 目标对象
x1 = 源对象
0x346bb4: str wzr, [x0,#8]
0x346bbc: str xzr, [x0,#0x10]
0x346bc8: bl #0x1f9ff8
0x346bcc: ldrsb w8, [x21,#0x17]
0x346bd4: ldr x8, [x21,#8]
0x346bec: str x20, [x19,#0x10]
```

v30 判定：

1. `0x346b90 / 0x346bcc` 不是 `X-Cylons` value 生成算法；它更像对象构造/源字符串对象复制函数。动态上 `0x346bcc` enter 已能看到完整 value，也支持“源对象已携带 value”。
2. `0x4cff50 / 0x4cff5c` 不是算法本体；该层负责从 `sp+8` 源 header/string 对象复制到新对象、引用计数、局部保存，然后交给 `0x51cd50` 或 vtable/callback 消费。
3. `sp+8` 的最近显式写入点是 `0x4cff3c -> 0x1ff5fc(x0=sp+8, x1=x21)`；因此来源还要继续向进入 `0x4cff3c` 前的 `x21` 上游追。
4. v30 与 v16/v20/v22 动态证据兼容：ACK/uplink 携带/打包链已强确认，但 `X-Cylons` value 生成算法本体仍未完整还原。

后续优先级：

- 静态继续追 `0x4cf8a4 .. 0x4d0228` 内 `x21` 的 definition-use 链，尤其进入 `0x4cff3c` 前的来源。
- 动态复现 ACK/X-Cylons 后，同时 dump：`0x4cff3c` before/after 的 `x1=x21` 与 `sp+8`、`0x4cff50/0x4cff58` enter/leave 的 `sp+8` 与新对象 `x21`、`0x51cd50` enter 的 `x3=x21`。
- 若 `0x4cff3c` 前 `x21` 已含完整 value，则继续上追；若 `0x1ff5fc` leave 才出现 value，则把 `0x1ff5fc` 升级为写入/转换点继续分析。

### 2026-05-12 v31 `x21` 来源 / `0x1ff5fc` 语义：来源上推到 `0x4cf8a4` 入参 `x2`

v31 承接 v30，静态追 `0x4cff3c` 前 `x21` 来源与 `0x1ff5fc(x0=sp+8, x1=x21)` 语义。沉淀文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v31_x21_source_1ff5fc_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v31_x21_source_1ff5fc_static_0512.md
/opt/data/home/reverse-tools/douyin_analysis/v31_x21_source_1ff5fc_static_0512.json
/opt/data/home/reverse-tools/douyin_analysis/v31_x21_source_1ff5fc_conclusion_0512.md
```

关键证据：

```text
0x004cf8dc: mov x20, x0
0x004cf8e0: add x0, sp, #0x20
0x004cf8e4: mov x21, x2      # x21 来自函数入参 x2
0x004cf8e8: mov w19, w1
...
0x004cff3c: add x0, sp, #8
0x004cff40: mov x1, x21
0x004cff44: bl  #0x1ff5fc    # copy/assign 入参 x2/x21 到 sp+8
```

`0x1ff5fc` 直接调用点约 `263` 个，函数体读取源对象 `x1` 的短字符串/对象布局标志（如 `[x1,#0x17]`），调用复制/析构/引用相关 helper，未见 hash/crypto/base64/查表/复杂循环特征。它更像高复用 string/object assign/copy helper，而不是 `X-Cylons` value 生成算法。

v31 判定：

1. `0x4cf8a4` 层没有本地生成 `X-Cylons`；`x21` 是调用方传入的第三参数 `x2`。
2. `0x4cff3c -> 0x1ff5fc` 只是把上游源对象 `x2/x21` 复制/赋值到 `sp+8` 临时对象。
3. `0x1ff5fc / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc` 都应继续归类为对象复制、包装、携带、消费链，不是算法本体入口。
4. 真正要继续追的是调用 `0x4cf8a4` 时传入的 `x2` 来源；动态复现时应在 `0x4cf8a4` enter dump `x2`，并在 `0x4cff3c/0x1ff5fc/0x346b90/0x51cd50` 做 enter/leave 对比。
5. 只有观察到某点 enter 前无 value、leave 后出现 value，或定位到明确 sign/opaque callback 输出，才能称为 `X-Cylons` value 生成点；当前算法本体仍未完整还原。

### 2026-05-12 v32 `0x4cf8a4` 调用方 / `x2` 来源：上推到 thunk 调用方传入的 `x1`

v32 承接 v31，继续反查 `0x4cf8a4` 入口来源与保存为 `x21` 的 `x2`。沉淀文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v32_4cf8a4_callers_x2_source_0512.py
/opt/data/home/reverse-tools/douyin_analysis/v32_4cf8a4_callers_x2_source_static_0512.md
/opt/data/home/reverse-tools/douyin_analysis/v32_4cf8a4_callers_x2_source_static_0512.json
/opt/data/home/reverse-tools/douyin_analysis/v32_4cf8a4_callers_x2_source_conclusion_0512.md
```

v32 静态发现：`.text` 内没有普通 `bl 0x4cf8a4` 直接调用，主要通过两个 tail-call thunk 进入：

```asm
0x004cf894: bti c
0x004cf898: mov x2, x1
0x004cf89c: mov w1, #1
0x004cf8a0: b   #0x4cf8a4

0x004d0128: bti c
0x004d012c: mov x2, x1
0x004d0130: mov w1, #2
0x004d0134: b   #0x4cf8a4
```

直接跳入 thunk 的位置：

```text
0x210c80 -> 0x4cf894
0x28a460 -> 0x4cf894
0x210c94 -> 0x4d0128
0x28a354 -> 0x4d0128
```

判定口径：

1. `0x4cf8a4` 不是 `X-Cylons` value 生成点；它继续只是保存、复制、包装上游传入对象。
2. `0x4cf894 / 0x4d0128` 也只是 wrapper/thunk：把上层调用方传入的 `x1` 转成共享实现的 `x2`，并设置类型 `w1=#1/#2`。
3. `0x1ff5fc / 0x346b90 / 0x4cff50 / 0x4cff5c / 0x346bcc` 仍归类为对象复制、包装、携带、打包/消费链，不是算法本体入口。
4. 当前来源链更新为：
   ```text
   upstream caller x1
     -> 0x4cf894 / 0x4d0128 thunk: x2 = x1
     -> 0x4cf8a4: x21 = x2
     -> 0x1ff5fc: copy x21 to sp+8
     -> 0x346b90 / 0x51cd50: 包装/消费
   ```
5. 下一步静态继续应沿 `0x210c80 / 0x210c94 / 0x28a354 / 0x28a460` 的调用方/函数入口追 `x1` 来源，重点判断它来自对象字段、回调返回还是 opaque/sign 输出。
6. 动态复现时应在 `0x4cf894 / 0x4d0128` enter dump `x1`：若 enter 已含完整 `X-Cylons` value，就继续上追调用方；若 enter 无、leave/下游有，才把对应点升级为写入/生成候选。
7. 对用户汇报继续保持边界：接口/协议链路已确认，ACK/uplink 强携带/打包点为 `0x346bcc / 0x4cff5c / 0x4cff50`，`0x21e17c / 0x2107dc` 是上游传播/上下文点；算法本体/value 生成点仍未完整还原。

### 2026-05-13 v52 priority source-neighborhood 静态复核：`0x4cf8a0/0x4d0134/0x4fc0c0` 仍不能升级为生成点

v52 对 v51 优先点做调用前 value-lane 与局部对象/record 槽来源复核，产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v52_priority_source_neighborhood_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v52_priority_source_neighborhood_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v52_priority_source_neighborhood_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v52_priority_source_neighborhood_conclusion_0513.md
```

核心分类：

```text
0x4cf8a0 -> 0x4cf8a4 : arg_x1_forwarded_to_shared_consumer_type1
0x4d0134 -> 0x4cf8a4 : arg_x1_forwarded_to_shared_consumer_type2
0x4fc0c0 -> 0x4d0128 : local_stack_payload_to_4d0128_with_arg_object_side_context
```

判定口径：

1. `0x4cf8a0` 与 `0x4d0134` 都是把 live-in `x1` 转为 `x2` 后进入 `0x4cf8a4` 的 shared consumer thunk/type path（type=1/2），不是本地生成 `X-Cylons` value。
2. `0x4fc0c0` 是调用 `0x4d0128` 的上游 probe：`x1=sp+8` 本地 payload，`x2` 来自入参对象链；仍属于 source-neighborhood / payload 传播邻域。
3. v52 静态窗口没有发现新的 hash/crypto/base64/opaque loop，也没有 enter/leave first-seen 证据。
4. 这些点只能作为动态 dump/first-seen probe；不能升级为 `X-Cylons` value 生成点。
5. 当前总判断保持：接口/协议链路、SSL 明文、IM ACK/uplink 强携带/打包链已有进展；`X-Cylons` value 生成算法本体仍未完整还原。

v40 从 v39 `dynamic_hook_plan_v39` 的 priority payload writer 出发，改用静态 backward slice 追 `+0x38` 写入源与 callback/function-pointer 形态，避免在目标事件难复现时继续空跑。沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v40_payload_writer_upstream_0513.py
/opt/data/home/reverse-tools/douyin_analysis/v40_payload_writer_upstream_static_0513.md
/opt/data/home/reverse-tools/douyin_analysis/v40_payload_writer_upstream_static_0513.json
/opt/data/home/reverse-tools/douyin_analysis/v40_payload_writer_upstream_conclusion_0513.md
```

优先 writer：

```text
0x2c4478
0x2b3754
0x2aeb98
0x2ba1e0
```

source 分类：

```text
caller_argument_copy: 2
argument_or_input_copy: 1
local_or_call_return_copy: 1
```

关键静态结论：

1. `0x2c4478 / 0x2c44b0`：`stp x2, x1, [x23,#0x38]`，直接把 caller `x2/x1` 写入 stack-local callback record 的 `+0x38/+0x40`。
2. `0x2b3754 / 0x2b3784`：`str x2, [sp,#0x38]`，保存 caller `x2` 到栈帧 `+0x38`，随后引用计数。
3. `0x2aeb98 / 0x2aebd8`：从 caller argument `x1+0x18` 拷贝 16 字节到新分配 record 的 `+0x38`。
4. `0x2ba1e0 / 0x2ba4f0`：把来自 caller `x3` 保存到 `x20` 后的 32-bit 值写入 allocated record `+0x38`。
5. priority writer 直接 `b/bl` caller 仍基本为空，address materialization 扫描也未找到明确 callback 注册引用；这更像 callback/table/record 间接触发邻域。
6. 这些点目前更应表述为 caller argument / caller-provided object field 的复制、包装、传播邻域，不能升级为 `X-Cylons` value 生成算法入口。没有 hash/crypto/base64/opaque 复杂算法体，也没有 first-seen 动态证据。

后续动态验证建议：

- Hook v40 writers：`0x2c4478 / 0x2b3754 / 0x2aeb98 / 0x2ba1e0`。
- 同时保留 v37 dispatcher：`0x28c0f0 / 0x21197c / 0x2237ac / 0x2a7474 / 0x25d8c4 / 0x2111d0 / 0x2237d4 / 0x2239d4 / 0x223750 / 0x224998 / 0x224c1c / 0x20df58`。
- 保留 wrapper：`0x210c74 / 0x210c88 / 0x28a348 / 0x28a454`。
- 对 writer 记录 enter/leave `x0-x8`、record base、`+0x20/+0x30/+0x38/+0x50`、源参数指向内容；对 dispatcher 记录 target reg 与传给 wrapper 的 `x1`。
- 判定标准继续使用 strict first-seen：只有 writer enter 前无 opaque/`X-Cylons` value，leave 后首次出现 value，并被后续 dispatcher/wrapper/`0x4cf8a4` 链消费，才可升级为生成点或生成点近邻。

汇报边界：v40 只把调用链从 dispatcher/wrapper/callback record 进一步收窄到 priority payload writer 的 caller-argument/object-field copy 邻域；`X-Cylons` value 生成算法本体仍未完整还原。

### 2026-05-14 v71 focused first-seen 后台 watch 通知判定经验

当 Hermes background process 因 `watch_patterns=["hook-ok"]` 触发系统通知时，不要把通知中的 `hook-ok` 片段当成新的目标事件或采样结论。正确流程是先 poll/wait 后台进程，再读取 summary JSON 与完整 log 做严格判定。

典型命令：

```text
cd /opt/data/home/reverse-tools/douyin_analysis && \
ADB_SERVER_SOCKET=tcp:10.0.2.2:5037 PYTHONUNBUFFERED=1 \
python3 run_v71_focused_firstseen_v70_probes_0513.py 240 \
2>&1 | tee v71_run_active_$(date +%H%M%S)_0513.out
```

v71 典型结果：

```text
process exited, exit_code=0
hook-ok=67
hook-err=1
v71-summary=8
Traceback=0
TransportError=0
```

严格目标事件仍可能全为 0：

```text
X-Cylons=0
ackB=0
client_start_pack_time=0
/webcast/=0
/ws/v2=0
/bytelink/wss=0
first_value_events=[]
strong_events=[]
ssl_events=[]
```

判定口径：

1. `hook-ok` watch 通知只说明某些 Frida hook 安装成功，是中间状态信号，不是 `X-Cylons` / ACK / SSL 真实命中。
2. 最终结论必须以脚本输出的 summary JSON 中 `first_value_events`、`strong_events`、`ssl_events` 等严格数组为准。
3. 日志全文 raw counter 或系统通知片段只能做审计辅助；ready/filter/hook-label 文本不得计入真实请求或内存证据。
4. 如果 summary 显示 strict arrays 为空，即使 hook 链健康，也只能归为“目标 first-seen 窗口未复现”的负样本。
5. 对用户汇报时应明确：采样链路健康，但算法本体未还原，`algorithm_status=not_recovered`。

### 2026-05-14 v72：v71 动态负样本后优先做静态 source expansion，而不是盲目扩 hook

当 v71 focused first-seen 采样显示 hook 链健康但严格目标数组为空时，下一步不要继续盲目扩大动态 hook 面。更稳的可复用流程是：基于上一轮静态高价值 probes 做一层 source/caller/callee 静态扩展，重新确认边界与候选小集合。

沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v72_twelfth_level_source_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v72_twelfth_level_source_static_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v72_twelfth_level_source_static_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v72_twelfth_level_source_conclusion_0514.md
```

v72 典型统计：

```json
{
  "seed_count": 367,
  "reviewed_target_count": 332,
  "priority_followups": 40,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "algorithm_status": "not_recovered"
}
```

分类结果可能仍集中在：

```text
algorithm_like_unproven_twelfth_level_probe
object_vtable_indirect_dispatch_probe
factory_return_indirect_dispatch_probe
materializer_or_raw_table_boundary_probe
lookup_copy_or_source_object_lane
runtime_library_noise_lane
twelfth_level_unknown_or_shared_boundary
```

判定口径：

1. v71/v72 这类组合流程要把“采样链健康”与“目标事件复现”分开。hook-ok 很多但 strict first-seen / SSL / ACK 数组为空，只能说明目标窗口未复现。
2. 动态目标窗口未复现时，优先做静态 source/caller/callee expansion 来收敛候选，而不是增加大范围 hooks。
3. 静态 `algorithm_like_*`、indirect、materializer、copy/runtime/container lane 都只能作为 probe 候选；没有闭合 transform-to-`X-Cylons` 输出链或 strict first-seen 证据，不能升级为 value source。
4. 当前边界仍应表述为：协议/SSL/IM ACK/uplink 链与强携带/打包点有进展，`0x346bcc / 0x4cff5c / 0x4cff50` 是强 carry/package 点，`0x21e17c / 0x2107dc` 是 upstream propagation/context，WebSocket send chain 可用 `0x3ec4f0 / 0x3ec44c / 0x3a6b50` 对齐；算法本体仍 `not_recovered`。
5. 归档时同时写入 JSON、Markdown、conclusion、task status、project memory 与 `SESSION-STATE.md`，并在报告中明确“无 value-source upgrade”。

下一步动态策略：只有先提高真实事件复现率（force-stop + early attach + 确认真直播间 + reconnect/cut-room/等待 WS 重连），才用 v72 priority probes 做小范围 focused hook。升级标准保持 strict first-seen：enter 前无 value、leave/downstream 出现同一个新 `X-Cylons`，或捕获明确 opaque/sign callback 输出。

### 2026-05-14 v77 focused-set source-neighborhood + r0capture 评估经验

v77 在 v76 focused dynamic hook set 基础上停止继续扩大静态层级，改为只审计 focused set 及其 immediate source-neighborhood/control chains，并同步评估 r0capture 是否能改善动态验证。沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v77_focused_set_source_neighborhood_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v77_focused_set_source_neighborhood_static_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v77_focused_set_source_neighborhood_static_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v77_focused_set_source_neighborhood_conclusion_0514.md
/opt/data/home/reverse-tools/douyin_analysis/r0capture_eval_for_xcylons_v77_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v77_0514.json
```

v77 典型统计：

```json
{
  "seed_count": 236,
  "reviewed_target_count": 202,
  "focused_review_count": 26,
  "priority_followups": 39,
  "demoted_or_control_lanes": 93,
  "next_focused_dynamic_hook_set": 36,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

v77 判定口径：

1. focused source-neighborhood 只能作为可审计的小范围候选集收敛，不能把 algorithm-like hint、raw ref、materializer、indirect dispatch context 升级为 value source。
2. 当前强边界仍保持：
   ```text
   carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
   upstream propagation/context: 0x21e17c / 0x2107dc
   WebSocket send chain alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
   algorithm/value source: not_recovered
   ```
3. v77 next focused dynamic hook set 应优先保留 priority probes + carry/package/control anchors，而不是继续扩大 hook 面。
4. 升级标准不变：只有 strict first-seen（enter 前无 value、leave/downstream 出现同一个新 `X-Cylons`）或明确 opaque/sign callback 输出，才能称为 value source。
5. 归档时需要同步 JSON/Markdown/conclusion/status，并在 `SESSION-STATE.md` 标注 `algorithm_status=not_recovered`，避免后续误把“候选收敛”当成“算法还原”。

r0capture 评估结论：

1. r0capture 对当前 X-Cylons 任务只能作为 **auxiliary_network_reproduction_probe**，用于旁路确认真实直播间是否发包、是否出现 `/webcast/im/push/*`、`/ws/v2`、WebSocket/SSL 明文窗口。
2. r0capture 不能替代 focused Frida first-seen / enter-leave diff；它主要证明最终网络事件或明文存在，不能定位 `X-Cylons` value 生成函数或上游对象来源。
3. 对 TTNet/Cronet/libsscronet/libttboringssl 这类高度定制链路，不能假设 r0capture 通杀；且其 hook 面可能偏宽，需避免触发抖音进程不稳定。
4. 推荐使用方式：当 focused hook 多次 `hook-ok` 但无目标 SSL/ACK 时，短时 attach r0capture 作为旁路抓包/pcap/log；如果确认目标包存在，再回到 v77 focused hook set 做 strict first-seen。
5. 即使 r0capture 抓到 `X-Cylons`，也只能增强“目标事件复现/最终头存在”证据，不能把 `algorithm_status` 从 `not_recovered` 升级。

### 2026-05-14 v78 focused static/dynamic candidate audit：审计 focused 候选并固化下一轮动态计划

v78 在 v77/v76 focused set 基础上不再继续扩大静态层级，而是做 focused 静态/动态候选审计：把 runnable first-seen probes、indirect/materializer scouts、carry/package controls、upstream context controls、WebSocket SSL send alignment controls、producer/copy controls 与 demoted helper/noise lanes 分开，生成下一轮更小、更可执行的 hook set。沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v78_focused_static_dynamic_candidate_audit_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v78_focused_static_dynamic_candidate_audit_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v78_focused_static_dynamic_candidate_audit_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v78_focused_static_dynamic_candidate_audit_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v78_0514.json
```

v78 可复用模式：

1. 输入应至少包含上一轮 focused dynamic hook set 与 source-neighborhood 静态审计结果，例如 v76 `focused_dynamic_hook_set`、v77 `v77_next_focused_dynamic_hook_set` / `priority_followups`。
2. 强边界继续固定为：
   ```text
   carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
   upstream context: 0x21e17c / 0x2107dc
   WS/SSL send alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
   ```
3. 对每个候选输出 `dynamic_role`、`audit_score`、`seed_reasons`、静态摘要、runtime dump requirements 与 `upgrade_to_value_source=false`。
4. hook set 选择应优先 probes，再补必要 alignment controls，demoted helper/noise lanes 只保留少量 sanity controls。
5. 升级规则必须写进产物：只有同一个干净 `X-Cylons` value 在 enter 前不存在、leave/downstream 首次出现并被 carry/package 或 SSL-send 链消费，或捕获明确 opaque/sign callback 输出，才能升级为 value source。
6. 如果没有 `new_value_source_evidence`、`proven_algorithm_evidence`、`first_seen_evidence`，结论必须保持：
   ```json
   {"algorithm_status":"not_recovered"}
   ```
7. 归档时同步 JSON、Markdown、conclusion、task status、project memory/daily memory/SESSION-STATE，并明确“focused audit / dynamic-plan consolidation，不是算法还原完成”。

汇报边界：v78 只能说明候选审计与下一轮动态计划固化；即使生成了更小 focused hook set，也不能宣称 `X-Cylons` 算法本体已挖出。

### 2026-05-14 v79 规划经验：从 v78 后转向 first-seen readiness，而不是继续扩层

当 v78 已经完成 focused static/dynamic candidate audit，下一轮不要默认继续做更宽的静态 layer expansion，也不要直接全量动态 hook。更可复用的 v79 方向是 **focused first-seen readiness / dynamic-plan consolidation**：

1. 输入以 v78 JSON 的 `v78_focused_dynamic_hook_set` / `candidates` 为主，不再盲目扩大到新一层 call graph。
2. 对每个候选重新标注：
   ```text
   first_seen_probe
   resolved_indirect_target_scout
   materializer_or_raw_table_scout
   carry_package_control
   upstream_context_control
   websocket_ssl_send_alignment_control
   producer_copy_control
   downstream_consumer_control
   demoted_helper_or_noise
   ```
3. 输出 runtime dump requirements：`entry/leave x0-x7`、return、pointed buffer hex/ascii、resolved `blr/br` target、record slots `+0x20/+0x38/+0x40/+0x50`、backtrace、downstream same-value alignment。
4. 为每个 probe 写清 positive signal 与 negative sample interpretation，避免把 hook-ok、ready/filter 文本、algorithm-like 静态提示、raw refs 或 materializer 误当成 value-source 证据。
5. 生成可审计产物建议：
   ```text
   static_v79_focused_firstseen_readiness_0514.py
   v79_focused_firstseen_readiness_0514.json
   v79_focused_firstseen_readiness_0514.md
   v79_focused_firstseen_readiness_conclusion_0514.md
   /opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v79_0514.json
   ```
6. v79 结论默认仍应保持：
   ```json
   {
     "new_value_source_evidence": false,
     "proven_algorithm_evidence": false,
     "first_seen_evidence": false,
     "algorithm_status": "not_recovered"
   }
   ```
   除非捕获到 strict first-seen 或明确 opaque/sign callback output。
7. 升级标准不变：同一个干净 `X-Cylons` value 在 candidate enter 前不存在，leave/downstream 首次出现，并被 `0x346bcc/0x4cff5c/0x4cff50` carry/package 或 `0x3ec4f0/0x3ec44c/0x3a6b50` SSL-send 链消费；或捕获明确 sign/opaque callback 输出。

汇报边界：v79 是动态前置与 first-seen 准备，不是算法还原完成。若没有真实目标窗口，仍只能报告“候选/计划固化，algorithm_status=not_recovered”。

### 2026-05-14 v79 收尾验证与归档经验

v79 产物生成后不要只口头汇报，应做一次机器可验证的 closure check，再归档并同步记忆层。推荐核验文件：

```text
/opt/data/home/reverse-tools/douyin_analysis/v79_focused_firstseen_readiness_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v79_focused_firstseen_readiness_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v79_focused_firstseen_readiness_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v79_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v79-focused-firstseen-readiness.md
/opt/data/home/.openclaw/workspace/memory/2026-05-14.md
/opt/data/home/.openclaw/workspace/SESSION-STATE.md
```

核验要点：

1. 文件存在且 size > 0；主 JSON/status JSON 可解析。
2. `candidate_count`、`focused_firstseen_hook_set_count`、status 中 hook set 计数应一致。本轮为：
   ```json
   {"candidate_count":36,"focused_firstseen_hook_set_count":36}
   ```
3. judgement/status 必须明确保持：
   ```json
   {
     "algorithm_status":"not_recovered",
     "new_value_source_evidence":false,
     "proven_algorithm_evidence":false,
     "first_seen_evidence":false
   }
4. conclusion、project memory、SESSION-STATE 中应包含 `v79` 与 `not_recovered`/`algorithm_status` 标记，避免后续把 readiness 误读为算法还原。
5. 归档后运行：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   ```
   确认 project/daily memory 已同步到 `reverse_engineering` collection。
6. 最终对用户汇报时只说“候选/计划固化 + 动态前置完成”，不能说“算法已挖出”。边界仍是：无 new value source、无 proven algorithm、无 first-seen evidence。

### 2026-05-14 v80 规划经验：从 v79 readiness 转向 focused source/value-lane 静态追踪

当 v79 已经把 v78 focused set 固化为 first-seen readiness plan，但仍没有真实 first-seen / value-source / proven algorithm 证据时，下一轮不要只重复 readiness，也不要直接扩大动态 hook。更可复用的 v80 方向是 **focused source/value-lane static tracing**：以 v79 的 36 个 focused first-seen hook 为核心，回看 v78/v77 的 source-neighborhood 信息，沿参数、返回值、对象槽与 thunk/callback 传递链继续上追。

推荐 v80 输入：

```text
/opt/data/home/reverse-tools/douyin_analysis/v79_focused_firstseen_readiness_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v78_focused_static_dynamic_candidate_audit_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v77_focused_set_source_neighborhood_static_0514.json
```

推荐 v80 产物命名：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v80_focused_source_value_lane_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v80_focused_source_value_lane_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v80_focused_source_value_lane_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v80_focused_source_value_lane_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v80_0514.json
```

v80 分组建议：

1. value-lane 深挖对象：优先 v79 phase1 中 readiness 分高、且 v78 标记为 `algorithm_like_unproven_probe` 的点，例如：
   ```text
   0x1fc694 / 0x229588 / 0x2a2b6c / 0x1f95d0 / 0x222b6c / 0x23b250 /
   0x26ccbc / 0x2b8db4 / 0x3289a4 / 0x2342ec / 0x2610b4 / 0x26cc24 /
   0x2a2c7c / 0x2b03d8 / 0x1fa908 / 0x1faa04 / 0x234260 / 0x26ccd8 / 0x26cd10
   ```
   静态追踪重点：`x0/x1/x2/x3` 参数来源、return value 走向、栈上 buffer / object slot 写入、是否有稳定 opaque/string/binary output、是否存在 hash/crypto/base64/encode 闭环、是否把同值传入 carry/package 或 SSL-send 控制点。
2. indirect dispatch / callback source 深挖对象：
   ```text
   0x21aecc / 0x21b108 / 0x224c14 / 0x3266cc / 0x328d94
   ```
   重点解析 `blr/br` 真实目标、vtable slot、callback 输出和是否接近 sign/opaque callback；若只是对象方法分发或 helper，则继续降级。
3. alignment / consumer 控制点只作为边界和 downstream same-value 对齐，不升级为算法：
   ```text
   carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
   upstream/context: 0x21e17c / 0x2107dc
   websocket/SSL send: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
   producer/copy: 0x1f9fc8 / 0x1ff5fc / 0x329098 / 0x32964c
   ```

v80 静态输出字段建议：

```text
source_lane_score
value_lane_score
x0_x3_def_chain
return_use_chain
object_slot_writes
stack_buffer_writes
copy_or_assign_helpers
indirect_call_targets
candidate_upstream_sources
downstream_alignment_targets
upgrade_to_value_source=false
```

判定口径：

1. v80 可把候选进一步拆成 source/value-lane、callback/indirect、copy/consumer/control，但没有 strict first-seen 或明确 opaque/sign callback 输出时，所有候选仍必须 `upgrade_to_value_source=false`。
2. 静态 algorithm-like hints、raw refs、materializer、indirect dispatch、object copy/value-lane score 都只能作为 probe 信号。
3. `0x346bcc / 0x4cff5c / 0x4cff50`、`0x21e17c / 0x2107dc`、`0x3ec4f0 / 0x3ec44c / 0x3a6b50` 继续是 carry/package、upstream/context、SSL-send alignment 边界，不是 value generation 证明。
4. 结论默认保持：
   ```json
   {
     "new_value_source_evidence": false,
     "proven_algorithm_evidence": false,
     "first_seen_evidence": false,
     "algorithm_status": "not_recovered"
   }
   ```
5. 对用户汇报时明确：v80 是 source/value-lane 静态深挖和下一轮动态候选准备；除非出现闭合 transform-to-`X-Cylons` 输出链或 first-seen 证据，否则不能宣称算法已挖出。


### 2026-05-14 v76 sixteenth-level focused static consolidation：收敛动态集合，但算法仍未还原

v76 是在多轮动态 first-seen 负样本与静态 source expansion 之后做的 focused static consolidation，产物示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/v76_sixteenth_level_focused_consolidation_static_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v76_sixteenth_level_focused_consolidation_static_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v76_sixteenth_level_focused_consolidation_conclusion_0514.md
```

典型统计：

```json
{
  "seed_count": 413,
  "reviewed_target_count": 371,
  "priority_followups": 48,
  "demoted_helper_or_noise_lanes": 90,
  "focused_dynamic_hook_set": 33,
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "algorithm_status": "not_recovered"
}
```

判定口径：

1. v76 只能说明静态候选进一步收敛到小动态集合；不能表述为 `X-Cylons` value 生成算法已还原。
2. 强 carry/package 点仍是：
   ```text
   0x346bcc / 0x4cff5c / 0x4cff50
   ```
3. upstream propagation/context 仍是：
   ```text
   0x21e17c / 0x2107dc
   ```
4. WebSocket send chain alignment 仍是：
   ```text
   0x3ec4f0 / 0x3ec44c / 0x3a6b50
   ```
5. 如果 `new_value_source_evidence=false`、`proven_algorithm_evidence=false`、`first_seen_evidence=false`，任何 algorithm-like hint、raw ref、materializer、indirect dispatch context 都只能保留为 probe，不得升级为 value source。
6. v76 focused dynamic hook set 可作为下一轮“小范围动态验证集合”，但运行前必须先提高真实直播间重连/ACK/X-Cylons/SSL first-seen 复现率；否则会继续得到 hook 健康但目标窗口未复现的负样本。

v76 focused dynamic hook set：

```text
0x222b6c / 0x26ccbc / 0x2b8db4 / 0x1f95d0 / 0x1fc2a4 / 0x1fc694 /
0x229588 / 0x2890d4 / 0x29348c / 0x2945f4 / 0x29e1e0 / 0x29e1ec /
0x29ed14 / 0x2a24d4 / 0x2a2b6c / 0x1fa908 / 0x3266cc / 0x328d94 /
0x21aecc / 0x21b108 / 0x224c14 / 0x1f7940 / 0x2025e4 / 0x21e418 /
0x346bcc / 0x4cff5c / 0x4cff50 / 0x4cf8a4 / 0x21e17c / 0x2107dc /
0x3ec4f0 / 0x3ec44c / 0x3a6b50
```

下一步优先级：不要继续盲目扩大静态层级或 hook 面；先 force-stop + early attach + 确认真直播间前台 + 切房/重连/等待 WS ACK，捕获真实 `X-Cylons` / ACK / SSL 窗口后再运行 v76 focused hook set。汇报时继续明确区分“接口/调用链进展”和“算法本体还原状态”：当前 `algorithm_status=not_recovered`。

### 2026-05-14 v80 执行前/收尾检查经验：脚本就绪不等于产物完成

v80 focused source/value-lane static tracing 的脚本即使已经写好并通过语法检查，也不能在汇报中表述为“v80 已完成”。必须区分三种状态：

1. **script_ready**：脚本存在、输入路径明确、`python3 -m py_compile` 通过。
2. **artifacts_generated**：实际运行脚本并生成 JSON/MD/conclusion/status/memory/SESSION 产物。
3. **closure_verified**：机器校验产物存在、size>0、JSON 可解析、计数一致、结论边界正确，并完成 memory sync。

v80 推荐执行命令：

```bash
cd /opt/data/home/reverse-tools/douyin_analysis
python3 -m py_compile static_v80_focused_source_value_lane_0514.py
python3 static_v80_focused_source_value_lane_0514.py
```

v80 实际产物命名包含 `static` 后缀；不要误查无后缀文件名。已确认存在的 v80 产物为：

```text
/opt/data/home/reverse-tools/douyin_analysis/v80_focused_source_value_lane_static_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v80_focused_source_value_lane_static_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v80_focused_source_value_lane_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v80_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v80-focused-source-value-lane.md
/opt/data/home/.openclaw/workspace/memory/2026-05-14.md
/opt/data/home/.openclaw/workspace/SESSION-STATE.md
```

如果 `/opt/data/home/reverse-tools/douyin_analysis/v80_focused_source_value_lane_0514.json` 不存在，先检查 `v80_focused_source_value_lane_static_0514.json`，不要误判为 v80 未完成。

v80 closure check 要点：

1. 所有预期文件存在且 size > 0。
2. 主 JSON 与 status JSON 可解析。
3. `candidate_count`、`priority_value_lane_probe_count`、`v80_focused_value_lane_hook_set_count` 等核心计数要互相一致或能解释差异。
4. judgement/status 必须保守保持：
   ```json
   {
     "new_value_source_evidence": false,
     "proven_algorithm_evidence": false,
     "first_seen_evidence": false,
     "algorithm_status": "not_recovered"
   }
   ```
5. conclusion、project memory、daily memory、`SESSION-STATE.md` 中必须出现 `v80` 与 `not_recovered`/`algorithm_status`，避免后续误把 source/value-lane 静态深挖当成算法还原完成。
6. 收尾后同步记忆层：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   ```

若工具调用上限或中断只完成到 `script_ready`，最终回复必须明确说“v80 脚本就绪/语法通过，但尚未实际运行和验证产物”，并列出下一步，而不能暗示 v80 已完成。

### 2026-05-14 v85 closure：focused caller/source-slot 归档校验经验

v85 从 v84 focused slot-source / indirect-producer probes 继续外推到 caller/materializer-side source-slot mining。该阶段属于静态 probe 收敛与动态 first-seen 候选准备，不是算法还原完成。

典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v85_focused_caller_source_slot_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v85_focused_caller_source_slot_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v85_focused_caller_source_slot_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v85_focused_caller_source_slot_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v85_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v85-focused-caller-source-slot.md
/opt/data/home/.openclaw/workspace/memory/2026-05-14.md
/opt/data/home/.openclaw/workspace/SESSION-STATE.md
```

v85 closure check 要点：

1. 校验所有产物存在且 size > 0。
2. 解析主 JSON 与 status JSON，确认计数一致：
   ```json
   {"candidate_count":16,"priority_caller_source_slot_probe_count":5,"hook_set_count":27}
   ```
3. judgement/status 必须保持：
   ```json
   {
     "algorithm_status":"not_recovered",
     "new_value_source_evidence":false,
     "proven_algorithm_evidence":false,
     "first_seen_evidence":false
   }
   ```
4. conclusion、project memory、daily memory、`SESSION-STATE.md` 中必须出现 `v85` 与 `not_recovered` / `algorithm_status`，避免把 caller/source-slot 静态收敛误读为算法已还原。
5. 归档后运行：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   python3 memory/scripts/memory-sync.py search "v85 focused caller source slot algorithm_status not_recovered"
   ps -ef | grep -E 'static_v85|run_v85|v85_' | grep -v grep || true
   ```
   搜索 Top 命中应包含 `2026-05-14_project_douyin-xcylons-v85-focused-caller-source-slot`；进程检查应无遗留 v85 分析进程。

v85 汇报边界：

- 新增价值：caller/source-slot、indirect materializer、producer-return scout 进一步收敛下一轮 first-seen hook set。
- 不能升级为 value source：没有 closed transform-to-`X-Cylons` output lane、没有 strict first-seen、没有明确 opaque/sign callback output。
- 当前强边界仍保持：
  ```text
  carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
  upstream propagation/context: 0x21e17c / 0x2107dc
  WebSocket/SSL send alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
  algorithm/value source: not_recovered
  ```

### 2026-05-14 v91 closure：focused static/dynamic candidate mining 收尾校验经验

v91 基于 v90 helper/callback target provenance，把候选整理成 focused static/dynamic candidate mining plan，并固化下一轮动态 hook set。典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v91_focused_static_dynamic_candidate_mining_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v91_focused_static_dynamic_candidate_mining_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v91_focused_static_dynamic_candidate_mining_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v91_focused_static_dynamic_candidate_mining_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v91_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v91-focused-static-dynamic-candidate-mining.md
/opt/data/home/.openclaw/workspace/memory/2026-05-14.md
/opt/data/home/.openclaw/workspace/SESSION-STATE.md
```

v91 closure check 要点：

1. 检查脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且 size > 0。
2. 解析主 JSON 与 status JSON，确认核心计数：
   ```json
   {"candidate_count":32,"priority_candidate_count":32,"v91_focused_static_dynamic_hook_set_count":58}
   ```
3. 确认 dynamic role / phase 分布符合预期：
   ```json
   {
     "resolved_indirect_callback_target_probe": 21,
     "first_seen_algorithm_like_helper_probe": 11,
     "phase1_resolve_indirect_callback_output": 21,
     "phase1_target_first_seen": 11
   }
   ```
4. judgement/status 必须继续保持：
   ```json
   {
     "algorithm_status":"not_recovered",
     "new_value_source_evidence":false,
     "proven_algorithm_evidence":false,
     "first_seen_evidence":false
   }
5. conclusion、project memory、daily memory、SESSION-STATE 中必须出现 `v91` 与 `not_recovered` / `algorithm_status`，避免把 focused static/dynamic candidate mining plan 误读成算法还原完成。
6. 归档后运行：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   python3 memory/scripts/memory-sync.py search "v91 focused static dynamic candidate mining algorithm_status not_recovered"
   ps -ef | grep -E 'static_v91|run_v91|v91_' | grep -v grep || true
   ```
   搜索 Top 命中应包含 `2026-05-14_project_douyin-xcylons-v91-focused-static-dynamic-candidate-mining`；进程检查应无遗留 v91 分析进程。

v91 汇报边界：

- 新增价值：从 v90 helper/callback target provenance 产出更可执行的 focused static/dynamic 候选计划，覆盖 indirect/callback output resolution 与 algorithm-like helper first-seen probes。
- 不能升级为 value source：没有 closed transform-to-`X-Cylons` output lane、没有 strict first-seen、没有明确 opaque/sign callback output。
- 当前强边界仍保持：
  ```text
  carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
  upstream propagation/context: 0x21e17c / 0x2107dc
  WebSocket/SSL send alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
  algorithm/value source: not_recovered
  ```

### 2026-05-14 v81 closure：interprocedural value-flow 仍是候选收敛，不是算法还原

v81 在 v80 focused source/value-lane 之后做 focused interprocedural value-flow 静态深挖与闭环归档。收尾时不要只看当前 todo 或口头 summary，必须验证产物、状态与记忆同步。

典型归档/校验目标：

```text
/opt/data/home/reverse-tools/douyin_analysis/v81_*_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v81_*_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v81_*_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v81_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v81-focused-interprocedural-value-flow.md
/opt/data/home/.openclaw/workspace/memory/2026-05-14.md
/opt/data/home/.openclaw/workspace/SESSION-STATE.md
```

收尾核验流程：

1. 检查 v81 JSON/MD/conclusion/status/project memory/daily memory/SESSION 文件存在且 size > 0。
2. 解析主 JSON 与 status JSON，确认核心 judgement 没有被误升级：
   ```json
   {
     "algorithm_status": "not_recovered",
     "new_value_source_evidence": false,
     "proven_algorithm_evidence": false,
     "first_seen_evidence": false
   }
   ```
3. 确认 conclusion、project memory、daily memory、`SESSION-STATE.md` 中含 `v81` 与 `not_recovered` / `algorithm_status`，避免把 interprocedural value-flow 收敛误读为算法已还原。
4. 归档后运行记忆同步：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   ```
   成功输出中应看到 `projects/2026-05-14_project_douyin-xcylons-v81-focused-interprocedural-value-flow.md` 被同步到 `reverse_engineering` collection。
5. 最终更新 todo 为 completed 后再汇报。

v81 汇报边界：

- v81 的价值是把 focused set 继续按跨过程 value-flow 收敛，区分 carry/package、propagation/context、SSL send alignment、indirect/value-lane probe、copy/helper/control lane。
- 仍不能把静态 value-flow、algorithm-like hint、raw ref、copy/materializer、indirect dispatch 升级为 value source。
- 当前强边界仍保持：
  ```text
  carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
  upstream propagation/context: 0x21e17c / 0x2107dc
  WebSocket/SSL send alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
  algorithm/value source: not_recovered
  ```
- 对用户明确回答：**算法还没有完整挖出**。只有捕获 strict first-seen（同一个干净 `X-Cylons` value 在 candidate enter 前不存在、leave/downstream 首次出现并被 carry/package 或 SSL-send 链消费）或明确 opaque/sign callback 输出，才能升级 `algorithm_status`。

### 2026-05-14 v93 closure：callback-output/source-slot 静态挖掘归档校验经验

v93 在 v92 target-output / first-seen readiness 后，继续下钻到 callback-output 与 source-slot 静态探针层。该阶段属于 focused static mining 与下一轮动态验证准备，不能表述为算法本体还原完成。

典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v93_focused_callback_output_source_slot_mining_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v93_focused_callback_output_source_slot_mining_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v93_focused_callback_output_source_slot_mining_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v93_focused_callback_output_source_slot_mining_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v93_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v93-focused-callback-output-source-slot-mining.md
/opt/data/home/.openclaw/workspace/memory/2026-05-14.md
/opt/data/home/.openclaw/workspace/SESSION-STATE.md
```

v93 closure check 要点：

1. 检查脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且 size > 0。
2. 解析主 JSON 与 status JSON，确认核心计数与边界，例如：
   ```json
   {"candidate_count":32,"v93_focused_hook_set_count":55}
   ```
3. 确认 judgement/status 必须保持：
   ```json
   {
     "algorithm_status":"not_recovered",
     "new_value_source_evidence":false,
     "proven_algorithm_evidence":false,
     "first_seen_evidence":false,
     "callback_output_source_slot_static_mining_evidence":true
   }
   ```
4. conclusion、project memory、daily memory、SESSION-STATE 中必须出现 `v93` 与 `not_recovered` / `algorithm_status` / `new_value_source_evidence=false` / `first_seen_evidence=false`，避免把 callback-output/source-slot 静态探针扩展误读为算法已还原。
5. 归档后运行：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   python3 memory/scripts/memory-sync.py search "v93 focused callback output source slot algorithm_status not_recovered"
   ps -ef | grep -E 'static_v93|run_v93|v93_' | grep -v grep || true
   ```
   搜索 Top 命中应包含 `2026-05-14_project_douyin-xcylons-v93-focused-callback-output-source-slot-mining`；进程检查应无遗留 v93 分析进程。

v93 汇报边界：

- 新增价值：从 v92 readiness 下钻出 callback-output sites 与 source-slot sites，并固化更小 focused hook set。
- 不能升级为 value source：没有 closed transform-to-`X-Cylons` output lane、没有 strict first-seen、没有明确 opaque/sign callback output。
- 当前强边界仍保持：
  ```text
  carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
  upstream propagation/context: 0x21e17c / 0x2107dc
  WebSocket/SSL send alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
  algorithm/value source: not_recovered
  ```

### 2026-05-14 v94 closure：从 callback-output/source-slot 继续做 upstream source-lane 静态挖掘

v94 在 v93 callback-output / source-slot mining 后继续分类 upstream source lanes。该阶段仍是 focused static mining 与下一轮动态 first-seen 准备，不是算法还原完成。

典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v94_focused_upstream_callback_output_source_0514.py
/opt/data/home/reverse-tools/douyin_analysis/v94_focused_upstream_callback_output_source_static_0514.json
/opt/data/home/reverse-tools/douyin_analysis/v94_focused_upstream_callback_output_source_static_0514.md
/opt/data/home/reverse-tools/douyin_analysis/v94_focused_upstream_callback_output_source_conclusion_0514.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v94_0514.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-14_project_douyin-xcylons-v94-focused-upstream-callback-output-source.md
/opt/data/home/.openclaw/workspace/memory/2026-05-14.md
/opt/data/home/.openclaw/workspace/SESSION-STATE.md
```

v94 closure check 要点：

1. 检查脚本、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 均存在且 size > 0。
2. 解析主 JSON 与 status JSON，确认核心计数与边界，例如：
   ```json
   {"owner_candidate_count":32,"high_priority_owner_count":32,"callback_output_source_probe_count":84,"source_slot_source_probe_count":128,"v94_focused_hook_set_count":59}
   ```
3. judgement/status 必须保持：
   ```json
   {
     "algorithm_status":"not_recovered",
     "new_value_source_evidence":false,
     "proven_algorithm_evidence":false,
     "first_seen_evidence":false
   }
   ```
4. conclusion、project memory、daily memory、SESSION-STATE 中必须出现 `v94` 与 `not_recovered` / `algorithm_status` / `new_value_source_evidence=false` / `first_seen_evidence=false`。
5. 归档后运行：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   python3 memory/scripts/memory-sync.py search "v94 focused upstream callback output source algorithm_status not_recovered"
   ps -ef | grep -E 'static_v94|run_v94|v94_' | grep -v grep || true
   ```
   搜索 Top 命中应包含 `2026-05-14_project_douyin-xcylons-v94-focused-upstream-callback-output-source`；进程检查应无遗留 v94 分析进程。

v94 判定口径：

- 新增价值：把 v93 callback-output/source-slot probes 继续拆成 object/vtable target-source scouts、helper-return output-source scouts、caller/local forwarded source scouts 与 constant/init/housekeeping lanes，并转成具体 runtime dump requirements。
- v94 focused hook set 应保留 carry/package、upstream/context、SSL/WS-send controls 作为 downstream same-value alignment，不要把 alignment control 升级为 value source。
- 不能升级为 value source：没有 closed transform-to-`X-Cylons` output lane、没有 strict first-seen、没有明确 opaque/sign callback output。
- 当前强边界仍保持：
  ```text
  carry/package: 0x346bcc / 0x4cff5c / 0x4cff50
  upstream propagation/context: 0x21e17c / 0x2107dc
  WebSocket/SSL send alignment: 0x3ec4f0 / 0x3ec44c / 0x3a6b50
  algorithm/value source: not_recovered
  ```
- 下一轮动态规则：只有复现真实 live-room ACK/X-Cylons/SSL first-seen 窗口后才运行 v94 focused hook set；升级条件是 candidate/callback/caller enter 无干净 value，return/slot/callback output 首次出现同一个干净 `X-Cylons` value，并被 carry/package 或 SSL/WS-send 链消费，或捕获明确 opaque/sign callback 输出。静态 v94 证据仍只能算 probe。

### 2026-05-16 v132 minimal pack 执行前状态判定经验

v132 已生成 `run_v132_pack_sequence_0516.py` 与 `analyze_v132_dynamic_evidence_0516.py` 后，不要只因为设备 `Awake` 且 `mDreamingLockscreen=false` 就直接运行 minimal pack。执行前必须同时确认前台是真实直播间，而不是抖音启动页/闪屏页。

一次现场检查中设备状态为：

```text
mWakefulness=Awake
mDreamingLockscreen=false
mShowingDream=false
mCurrentFocus=Window{... com.ss.android.ugc.aweme/com.ss.android.ugc.aweme.splash.SplashActivity}
mFocusedApp=ActivityRecord{... com.ss.android.ugc.aweme/.splash.SplashActivity}
```

判定口径：

1. `Awake`、非锁屏、非 NotificationShade 只说明 ADB 输入不会被锁屏/通知栏拦截；不代表动态 pack 具备目标事件复现条件。
2. 当前前台若是 `SplashActivity`，不能直接运行：
   ```text
   pack_00_guards_then_controls
   pack_01_same_value_first_seen
   ```
   否则大概率只得到 `hook-ok`/ready 文本，但没有真实 `/webcast/*`、`/ws/v2`、ACK、SSL 或 `X-Cylons` 目标窗口。
3. minimal pack 动态执行前的硬条件应包括：
   - 前台 activity 已进入真实直播间/`LivePlayActivity` 或截图确认直播间 UI；
   - 非 `SplashActivity`、非登录页、非搜索/直播榜骨架屏、非 NotificationShade/锁屏；
   - 主进程与关键 so 已加载；
   - Frida 最小 attach/create_script 验证通过。
4. 若只停留在 `SplashActivity`，应判定 `dynamic_executable=false`，转入静态/执行包增强（例如为下一版 runner 增加 activity gate、live-room gate、strict analyzer），而不是硬跑 minimal pack。
5. 对用户汇报时明确：v132 是 run-readiness，`dynamic_execution_performed=false`；未进入真实直播间时不能把“不跑”或“无目标事件”误读为算法负证据。`algorithm_status` 继续保持 `not_recovered`。

### 2026-05-16 v143 unlock live-entry blocker：screen_off_or_lockscreen 优先于动态 pack

v143 在 v141/v142 live-room gate 基础上进一步把动态执行阻塞点从泛化的 launcher/system foreground 收敛到更明确的：

```text
screen_off_or_lockscreen
```

典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v143_unlock_live_entry_blocker_0516.py
/opt/data/home/reverse-tools/douyin_analysis/run_v143_unlock_probe_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v143_unlock_live_entry_blocker_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v143_unlock_live_entry_blocker_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v143_unlock_live_entry_blocker_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v143_unlock_live_entry_blocker_matrix_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v143_unlock_live_entry_blocker_runbook_0516.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v143_0516.json
```

v143 判定口径：

1. 动态 pack 执行前不能只看 `screen_off=false` 或设备已唤醒；必须同时确认没有 `Keyguard`、`NotificationShade`、`SECURE_SYSTEM_OVERLAY` 等锁屏/系统遮罩捕获输入。
2. 如果状态类似：
   ```json
   {
     "screen_off": false,
     "keyguard_or_shade": true,
     "aweme_foreground": false,
     "live_room_entry_ready_now": false,
     "dynamic_execution_allowed": false
   }
   ```
   则应明确判定当前 blocker 为 `screen_off_or_lockscreen`，不要强行运行 `pack_00_guards_then_controls` 或 `pack_01_same_value_first_seen`。
3. 锁屏/通知栏/系统遮罩状态下硬跑 focused hook 只会得到锁屏、Splash、ready/filter 或 `hook-ok` 污染数据，不能推进 `X-Cylons` same-value / first-seen / ACK / SSL 证据链。
4. 正确下一步是人工物理解锁并进入真实抖音直播间，再重新跑 live-room gate；只有 `live_room_entry_ready=true` 后才能执行 v140/v141/v142/v143 相关 pack。
5. v143 只定位并归档动态执行环境阻塞，不是算法还原。若没有真实 same-value、proven transform、first-seen 或 opaque/sign callback 输出，继续保持：
   ```json
   {
     "algorithm_status": "not_recovered",
     "new_value_source_evidence": false,
     "proven_algorithm_evidence": false,
     "first_seen_evidence": false
   }
6. 收尾需校验 `static_v143...py` 与 `run_v143...py` 均 `py_compile` 通过，确认 status/conclusion/matrix/runbook/project memory 已归档，再向用户说明“当前阻塞是解锁/真实直播间入口”，而不是把未执行动态 pack 解读为算法负证据。

### 2026-05-16 v145 manual-unlock real-live-room proof gate：人工解锁是动态执行硬前置

v145 在 v144/v143 的锁屏与 live-room gate 基础上，把动态执行 gate 进一步固化为“人工解锁 + 真实直播间 ready”证明门。该阶段的价值是防止在 screen-off、Keyguard/NotificationShade、SplashActivity 等状态下误跑 focused pack，产生 hook-ok/ready 文本污染，并把“未执行动态包”错误解释为算法负证据。

典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v145_manual_unlock_real_live_room_proof_gate_0516.py
/opt/data/home/reverse-tools/douyin_analysis/run_v145_manual_unlock_real_live_room_proof_gate_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v145_manual_unlock_live_room_proof_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v145_manual_unlock_real_live_room_proof_gate_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v145_manual_unlock_real_live_room_proof_gate_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v145_manual_unlock_real_live_room_proof_gate_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v145_manual_unlock_real_live_room_proof_gate_matrix_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v145_manual_unlock_real_live_room_proof_gate_runbook_0516.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v145_0516.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-16_project_douyin-xcylons-v145-manual-unlock-real-live-room-proof-gate.md
```

v145 典型 status：

```json
{
  "status": "completed",
  "algorithm_status": "not_recovered",
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false,
  "v145_dynamic_execution_allowed": false,
  "v145_dynamic_execution_performed": false,
  "v145_manual_proof_blocker": "manual_unlock_required_screen_or_keyguard",
  "v145_screen_off": true,
  "v145_keyguard_or_shade": true,
  "v145_splash_activity": true,
  "v145_aweme_foreground": true,
  "v145_real_live_room_ready_now": false,
  "v145_strict_evidence_event_count": 0
}
```

v145 判定口径：

1. `aweme_foreground=true` 不足以允许动态执行；如果同时 `screen_off=true`、`keyguard_or_shade=true`、`splash_activity=true` 或 `real_live_room_ready_now=false`，必须判定 `dynamic_execution_allowed=false`。
2. `manual_unlock_required_screen_or_keyguard` 是硬 blocker：需要用户人工/物理解锁设备，并进入真实直播间 UI 后再 rerun gate；不要用 ADB 盲点/滑动强行跑 pack。
3. 当前状态下不得执行 `pack_00_guards_then_controls`、`pack_01_same_value_first_seen` 或 v140/v141 focused pack；否则大概率只产生锁屏/Splash/ready/hook-ok 噪声。
4. v145 是 proof gate / runbook / analyzer 包，不是算法还原。没有真实 same-value、first-seen、ACK/X-Cylons/SSL strict evidence 时，继续保持 `algorithm_status=not_recovered`。
5. v145 closure check 应包括：产物存在且 size>0、3 个 Python 脚本 `py_compile` 通过、status JSON 可解析且 blocker/algorithm 边界正确、conclusion/project memory/daily/SESSION 含 `v145` 与 `not_recovered`/`algorithm_status` marker。
6. 收尾后运行：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   python3 memory/scripts/memory-sync.py search "v145 manual unlock real live room proof gate algorithm_status not_recovered"
   ps -ef | grep -E 'static_v145|run_v145|analyze_v145|v145_' | grep -v grep || true
   ```
   搜索应能命中 `2026-05-16_project_douyin-xcylons-v145-manual-unlock-real-live-room-proof-gate`，残留进程检查应为空。

汇报边界：v145 完成的是动态执行前置条件证明与阻塞归档；下一步是用户人工解锁并进入真实直播间后再运行 real-live-room proof / focused pack。不能把 `dynamic_execution_performed=false` 说成算法负证据，也不能把 gate 完成说成 `X-Cylons` 算法已挖出。

### 2026-05-16 v150 foreground recovery live gate 收尾校验经验

v150 在前台恢复/NotificationShade/statusbar recovery 与 live-room execution gate 包装后，重点是闭环校验而不是直接动态执行。典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/run_v150_foreground_recovery_live_gate_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v150_foreground_recovery_evidence_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v150_foreground_recovery_live_gate_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v150_foreground_recovery_live_gate_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v150_foreground_recovery_live_gate_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v150_foreground_recovery_live_gate_matrix_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v150_foreground_recovery_live_gate_runbook_0516.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v150_0516.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-16_project_douyin-xcylons-v150-foreground-recovery-live-gate.md
```

v150 closure check 要点：

1. 校验 runner/analyzer/static JSON/MD/conclusion/matrix/runbook/status/project memory/daily memory/SESSION-STATE 均存在且 size > 0。
2. 对 runner/analyzer 执行：
   ```bash
   cd /opt/data/home/reverse-tools/douyin_analysis
   python3 -m py_compile run_v150_foreground_recovery_live_gate_0516.py analyze_v150_foreground_recovery_evidence_0516.py
   ```
3. 解析主 JSON、matrix JSON、status JSON，确认边界保持：
   ```json
   {
     "status":"completed",
     "algorithm_status":"not_recovered",
     "new_value_source_evidence":false,
     "proven_algorithm_evidence":false,
     "first_seen_evidence":false,
     "v150_dynamic_execution_allowed":false,
     "v150_dynamic_execution_performed":false,
     "v150_strict_evidence_event_count":0
   }
   ```
   status 中可能出现：
   ```json
   {"v150_current_blocker":"not_runtime_sampled_in_static_packaging"}
   ```
   这表示本轮是静态包装/门控归档，未做真实 runtime sample；不能当作算法负证据。
4. conclusion、project memory、daily memory、SESSION-STATE 中必须出现 `v150`、`algorithm_status`、`not_recovered` marker。
5. 同步并搜索验证：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   python3 memory/scripts/memory-sync.py search "v150 foreground recovery live gate algorithm_status not_recovered"
   ```
   Top 命中应包含 `2026-05-16_project_douyin-xcylons-v150-foreground-recovery-live-gate`。
6. 检查无残留进程：
   ```bash
   ps -ef | grep -E 'static_v150|run_v150|analyze_v150|v150_' | grep -v grep || true
   ```

v150 汇报边界：完成的是 foreground / NotificationShade / statusbar recovery + live-room execution gate 包装与归档验证；没有真实 same-value、first-seen、ACK/X-Cylons/SSL strict evidence，也没有明确 opaque/sign callback output，因此 `X-Cylons algorithm_status=not_recovered`。


### 2026-05-16 v141 live-room gate + same-value preflight 经验

v141 在 v140 live-log grounded same-value pack 之后增加 **live-room foreground gate** 和同值 preflight 分析，目标是防止在 Splash/login/search/NotificationShade 等非直播间状态下硬跑动态包，反复得到 hook 健康但无 ACK/X-Cylons/SSL 目标窗口的负样本。

典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v141_live_room_gate_same_value_preflight_0516.py
/opt/data/home/reverse-tools/douyin_analysis/run_v141_live_room_gate_same_value_preflight_0516.py
/opt/data/home/reverse-tools/douyin_analysis/analyze_v141_same_value_preflight_logs_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v141_live_room_gate_same_value_preflight_static_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v141_live_room_gate_same_value_preflight_static_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v141_live_room_gate_same_value_preflight_matrix_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v141_live_room_gate_same_value_preflight_runbook_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v141_live_room_gate_same_value_preflight_conclusion_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v141_same_value_preflight_analysis_0516.json
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v141_0516.json
```

v141 判定口径：

1. 动态执行前必须通过 live-room gate：前台应为真实直播间/`LivePlayActivity` 或截图确认直播间 UI；不得是 `SplashActivity`、登录页、搜索/直播榜骨架屏、NotificationShade/锁屏。
2. `hook-ok` 很多只说明 Frida/hook 安装健康；`hook-err` 中个别 `unable to intercept function` 只要不影响核心目标，可记录但不能当成算法负证据。
3. analyzer 必须只统计真实 jsonl tag/counter：`strict_same_value_alignment`、`repeated_value_hash_count`、目标 ACK/X-Cylons/SSL tag；ready/filter/hook-label 文本不得计入真实命中。
4. 若 analyzer 输出类似：
   ```json
   {"repeated_value_hash_count":0,"strict_same_value_alignment":false,"algorithm_status":"not_recovered"}
   ```
   即使 `event_total`、`hook_ok_count` 很高，也只能判定为“未形成同值 first-seen/下游消费闭环”。
5. v141 的价值是把 v140 pack 变成可安全执行/可审计的 preflight 包；它不是算法还原完成。只有同一个干净 `X-Cylons` value 在 candidate enter 前不存在，leave/return/callback/downstream 首次出现，并被 carry/package 或 SSL-send 链消费，或捕获明确 opaque/sign callback 输出，才能升级为 value source。
6. 收尾归档仍需检查 JSON/MD/conclusion/status/memory/SESSION，确认 `algorithm_status=not_recovered`、`new_value_source_evidence=false`、`proven_algorithm_evidence=false`、`first_seen_evidence=false`，并同步记忆层。

### 2026-05-16 v140 live-log grounded same-value pack 归档经验

当连续动态采样受 UI/直播间复现率影响，且已有真实 live 日志中包含 `X-Cylons` / ACK / SSL 证据时，可以先转为 **live-log grounded same-value pack plan**，不要继续盲目扩大 hook 面。v140 的作用是把已有真实日志样本转成可执行的两阶段最小动态验证包，而不是宣称算法已还原。

典型产物：

```text
/opt/data/home/reverse-tools/douyin_analysis/static_v140_live_log_grounded_same_value_pack_0516.py
/opt/data/home/reverse-tools/douyin_analysis/v140_live_log_grounded_same_value_pack_0516.json
/opt/data/home/reverse-tools/douyin_analysis/v140_live_log_grounded_same_value_pack_0516.md
/opt/data/home/reverse-tools/douyin_analysis/v140_live_log_grounded_same_value_pack_conclusion_0516.md
/opt/data/home/.openclaw/workspace/tasks/status/douyin_xcylons_v140_0516.json
/opt/data/home/.openclaw/workspace/memory/projects/2026-05-16_project_douyin-xcylons-v140-live-log-grounded-same-value-pack.md
```

v140 典型计数与判定：

```json
{
  "live_sample_count": 15,
  "same_value_candidate_count": 12,
  "pack_plan_count": 2,
  "pack_00_guards_then_controls_count": 23,
  "pack_01_same_value_first_seen_count": 32,
  "same_value_pack_plan_ready": true,
  "algorithm_status": "not_recovered",
  "new_value_source_evidence": false,
  "proven_algorithm_evidence": false,
  "first_seen_evidence": false
}
```

两阶段 pack 语义：

1. `pack_00_guards_then_controls`：先验证真实直播间、ACK/SSL/WS 目标窗口、carry/package、upstream/context 与 SSL send alignment controls 是否同窗活跃。
2. `pack_01_same_value_first_seen`：只在 pack_00 目标窗口成立后，追同一个干净 `X-Cylons` value 的 candidate enter/leave/return/callback/downstream first-seen。

升级标准保持严格：只有同一个干净 `X-Cylons` value 在 candidate enter 前不存在，leave/return/callback/downstream 首次出现，并被 `0x346bcc / 0x4cff5c / 0x4cff50` carry/package 或 `0x3ec4f0 / 0x3ec44c / 0x3a6b50` SSL-send 链消费，或捕获明确 opaque/sign callback 输出，才能升级为 value source。否则即使 `same_value_pack_plan_ready=true`，也必须保持：

```text
algorithm_status=not_recovered
```

v140 closure check：

1. 检查 static script、JSON、MD、conclusion、status、project memory、daily memory、SESSION-STATE 存在且 size > 0。
2. 解析主 JSON/status JSON，确认 `pack_plan_count=2`、pack_00/pack_01 计数、`same_value_pack_plan_ready=true` 与 `algorithm_status=not_recovered`。
3. conclusion/project memory/daily/SESSION 必须包含 `v140` 与 `not_recovered` / `algorithm_status`，避免把执行包计划误读成算法还原。
4. 运行：
   ```bash
   cd /opt/data/home/.openclaw/workspace
   python3 memory/scripts/memory-sync.py sync
   python3 memory/scripts/memory-sync.py search "v140 live log grounded same value pack algorithm_status not_recovered"
   ps -ef | grep -E 'static_v140|run_v140|v140_' | grep -v grep || true
   ```
5. 最终汇报边界：v140 固化了同值 first-seen 动态执行计划；`X-Cylons` value 生成算法本体仍未完整挖出。