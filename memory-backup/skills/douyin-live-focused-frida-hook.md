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