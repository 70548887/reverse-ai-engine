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

本轮沉淀文件示例：

```text
/opt/data/home/reverse-tools/douyin_analysis/native_net_next_entry_0511.md
/opt/data/home/reverse-tools/douyin_analysis/run_cronet_header_entry_hook_0511.py
```
