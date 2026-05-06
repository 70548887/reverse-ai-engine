---
name: douyin-live-reverse
description: 抖音直播间接口逆向分析流程 — 从 APK 定位到协议层代码
triggers: ["抖音直播", "APP逆向", "直播间协议", "douyin live", "webcast"]
---

# Douyin Live Room Interface Reverse Analysis

抖音直播间接口逆向分析流程。

## 环境就绪

| 工具 | 路径/状态 |
|------|----------|
| jadx 1.4.7 | `/opt/data/home/reverse-tools/bin/jadx` |
| APK | `/tmp/douyin.apk` (337MB, v380501) |
| DEX 提取目录 | `/tmp/douyin_dex/` |
| 已反编译 DEX | classes15, classes21, classes30, classes33 |
| frida-mobile-mcp | 已配入 Hermes (frida_mobile) |

## 分析成果（2026-04-25）

### 18 个直播间 API 接口
详见: `/opt/data/home/.openclaw/workspace/memory/douyin-live-analysis.md`

### 核心发现

**数据格式：JSON + Gson（非 Protobuf）**
- `0kTo` = Gson ConverterFactory（非 ProtoAdapter）
- `0kS6.LIZ` = Gson 实例（`lower_case_with_underscores` 命名策略）
- `Room` / `FeedItem` 通过 TypeAdapter 做 Gson 反序列化

**关键接口：**
```
POST /webcast/feed/live_tab/      ← 直播Feed流（核心刷新接口）
GET  /webcast/room/info/          ← 直播间信息  
POST /webcast/distribution/check_user_live_status/ ← 用户直播状态
```

## 环境连通与调试坑点

### ADB 连接方式
容器内通常通过宿主机 ADB server 转发连接手机。已验证可用的两种 server 地址：

- `10.0.2.2:5037`
- `172.17.0.1:5037`

推荐在容器里显式设置：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037
adb devices -l
adb shell id
```

### Frida 连接方式
当前环境里 `frida-mobile-mcp` 不一定能自动枚举 USB 设备，但 Python Frida 可直接识别：

```python
import frida
d = frida.get_usb_device(timeout=5)
```

如果 `frida-ps` 不在 PATH，可改用：

```bash
python3 -m frida_tools.ps -Uai
```

### 设备侧 Frida server
已验证手机上可启动：

- `/data/local/tmp/frida-server-17.9.1-android-arm64`

监听确认：

- `127.0.0.1:27042`

### 常见坑
- `5555` 端口通常未开启，不要默认假设是 WiFi ADB
- `frida-mobile-mcp` 的设备列表可能只有 `local/socket/barebone`，但 Python Frida 仍可直接连 USB
- 容器环境可能继承错误的 `ADB_SERVER_SOCKET`，导致 `adb` 总是去连不存在的远程 server；必要时用 `env -i` 清空后再试

## 快速分析流程

```bash
# 1. 提取 APK 内所有 DEX（纯 Python，零额外内存）
python3 -c "
import zipfile, os
z = zipfile.ZipFile('/tmp/douyin.apk')
os.makedirs('/tmp/douyin_dex', exist_ok=True)
for n in z.namelist():
    if n.endswith('.dex'):
        z.extract(n, '/tmp/douyin_dex')
"

# 2. 按需反编译目标 DEX（避开 classes0-58 全量）
export JAVA_HOME="/opt/data/home/reverse-tools/jdk-17.0.18+8"
/opt/data/home/reverse-tools/bin/jadx -d /tmp/out --no-res --no-debug-info /tmp/douyin_dex/classes15.dex

# 3. 快速定位关键词
rg -i "live_tab|webcast.*room|check_user_live" /tmp/out/sources/
```

## SO 层逆向（2026-04-25 新发现）

### 核心 SO 文件

| SO | 职责 |
|----|------|
| `libropaencrypt.so` | RopaEncrypt JNI 入口，AES-128-CBC/GCM + Base64 |
| `libttcrypto.so` | RSA/DES/3DES/AES 底层原语 |
| `libEncryptor.so` | ttEncrypt 主加密入口 |
| `libbyterts.so` / `libkryptonlive.so` | 直播流协议 |

### SO 层架构

```
Java: RopaEncrypt.getEncryptSeq(str, true)
  → libropaencrypt.so (AES-128-CBC + OpenSSL EVP)
    → libttcrypto.so (底层加密原语)
```

### 关键 HTTP Headers（SO 层生成）

```
x-tt-encrypt-queries  ← 加密查询参数
x-tt-encrypt-info     ← 请求体加密
x-tt-cipher-version   ← 加密版本
x-tt-logid            ← UUID
```

### RopaEncrypt API（来自 SO 字符串表 + LocationSDKEntry 源码）

```java
package com.bytedance.ropa.encrypt;

public class RopaEncrypt {
    // 加密请求参数（直播签名核心）
    public static native EncryptResult getEncryptSeq(String input, boolean flag);
    public static native EncryptResult getEncryptSeqV2(String input, int mode, String extra);

    // 解密响应
    public static native EncryptResult getDecryptSeq(String encryptedData);

    // 通用加解密（6 参数）
    public static native String encryptData(String... six params);
    public static native String decryptData(String... six params);

    // 密钥 & 哈希
    public static native String generateKey(long seed);
    public static native long getHash(String data);
    public static native long getRandom();
}

// EncryptResult 结构 (JNI: <init>(ILjava/lang/String;)V)
class EncryptResult {
    int status;        // 状态码
    String data;        // Base64(AES(...)) 结果
    String getData();
}
```

### 调用模式（实测）

```java
EncryptResult r = RopaEncrypt.getEncryptSeq("31.2304", true);
String encrypted = r.getData(); // → "A1B2C3D4..." (Base64)
```

## SO 层分析工具链

### 1. SO 字符串分析（零反编译，直接抽符号）

```bash
# 提取所有字符串，找加密相关
strings lib/arm64-v8a/libropaencrypt.so | grep -iE "encrypt|decrypt|AES|RSA|cipher|Java_com"

# 找导出符号（已strip时主要看字符串）
nm -D libropaencrypt.so   # 导出表
readelf -s libropaencrypt.so  # 完整符号表
```

### 2. 大 DEX 精准提取（避免全量反编译超时）

```bash
# 方法：jadx --single-class 精准提取单个类（不需要 --select-class）
export JAVA_HOME="/opt/data/home/reverse-tools/jdk-17.0.18+8"
/opt/data/home/reverse-tools/jadx/bin/jadx \
  -d /tmp/out_pick \
  --no-res --no-debug-info \
  --single-class "com.ss.android.ugc.aweme.xtab.newtab.api.LiveTabFeedChannelHeaderInterceptor" \
  /tmp/douyin_dex/classes12.dex
```

### 3. DEX 字符串池搜索（极速定位类位置）

```python
# 从 APK zip 直接搜 DEX 中的字符串，无需解压
import zipfile
z = zipfile.ZipFile('/tmp/douyin.apk')
for dex in z.namelist():
    if dex.endswith('.dex'):
        data = z.read(dex)
        if b'RopaEncrypt' in data:
            print(f"Found in: {dex}")
```

### 4. SO 文件批量提取

```python
import zipfile, os
z = zipfile.ZipFile('/tmp/douyin.apk')
target_so = [
    'lib/arm64-v8a/libropaencrypt.so',
    'lib/arm64-v8a/libttcrypto.so',
    'lib/arm64-v8a/libEncryptor.so',
]
os.makedirs('/tmp/douyin_so/arm64-v8a', exist_ok=True)
for so in target_so:
    with open(f"/tmp/douyin_so/{so}", 'wb') as f:
        f.write(z.read(so))
```

## 2026-05-02 补充：当前 decompiled smali 路径与定位点

当前可直接检索的 apktool/smali 解包目录：

```bash
ROOT=/opt/data/home/reverse-tools/douyin_decompiled/douyin_base
```

已确认的静态定位点：

- `smali_classes15/com/ss/android/ugc/aweme/xtab/newtab/api/LiveTabFeedChannelApi.smali`
  - `POST /webcast/feed/live_tab/`
- `smali_classes15/com/ss/android/ugc/aweme/profile/api/RoomRetrofitApi.smali`
  - `GET /webcast/room/info/`
- `smali_classes15/com/ss/android/ugc/aweme/live/api/IInsertPreRoomApi.smali`
  - `GET /webcast/room/info/`
  - `GET /webcast/room/info_by_scene/`
- `smali_classes15/com/ss/android/ugc/aweme/feed/area/api/PreviewRoomApi.smali`
  - `GET /webcast/room/info_by_scene/`
- `smali_classes15/com/ss/android/ugc/aweme/live/feedpage/LiveRoomInfoApi.smali`
  - `GET /webcast/room/info_by_user/`
- `smali_classes12/com/ss/android/ugc/aweme/xtab/newtab/api/LiveTabFeedChannelHeaderInterceptor.smali`
  - 只补 `Content-Type: application/json; charset=utf-8`，不是 RopaEncrypt 入口
- `smali_classes12/com/bytedance/frameworks/baselib/network/queryfilter/QueryFilterEngine.smali`
  - around lines 1528 / 1873 可见 `x-tt-encrypt-queries`
  - around lines 1581-1744 处理 body/query encrypt header 与 `addRequestEncryptHeaders(...)`
- `smali_classes17/com/ss/android/ugc/aweme/frontier/ws/task/WebSocketTask.smali`
  - `connectWebSocket(Context)`、`connectWS()`、`runAfterTokenReady(...)` 等 WS 入口
- `smali_classes12/com/ss/android/ugc/aweme/framework/services/StaticServiceImplManager.smali`
  - `com.bytedance.kmp.network.websocket.IRawWsService` service 注册字符串

实用 grep：

```bash
rg -n -i "RopaEncrypt|getEncryptSeq|x-tt-encrypt-queries|webcast/feed/live_tab|webcast/room/info|IRawWsService|WebSocketTask|RealWebSocket|websocket" \
  /opt/data/home/reverse-tools/douyin_decompiled/douyin_base/smali* \
  | head -n 200
```

注意：对当前 smali 目录直接搜 `RopaEncrypt/getEncryptSeq` 可能没有命中；先从 `QueryFilterEngine` 的 `x-tt-encrypt-queries` header 和 native SO 字符串/JNI 入口并行推进，不要只等 Java 层类名。

## 2026-05-02 补充：Frida server 启动坑

在华为 P10 / Android 9 当前环境中，`frida.get_usb_device()` 能枚举 USB 设备，但 attach 可能报：

```text
frida.ServerNotRunningError: unable to connect to remote frida-server: closed
```

已观察到的失败模式：

- 用普通 `adb shell` 启动 `/data/local/tmp/frida-server-17.9.1-android-arm64`：
  - 输出 `Unable to load SELinux policy ... Permission denied`
  - 随后 `Segmentation fault`
- 非交互 `adb shell 'su -c "...frida-server"'` 可能直接 `Permission denied`
- 即使 `su -v` 显示 `MagiskSU`，`adb shell` 上下文仍是 `uid=2000(shell) context=u:r:shell:s0`，`su` 调用本身也可能失败
- `frida-server` 文件存在并可执行，但不代表当前 shell 有权限以 root 上下文拉起它
- Hermes `terminal` 会拦截前台命令里的 shell-level `nohup ... &`；若要后台启动，需用 `terminal(background=true)` 或拆成独立检查命令

排查顺序：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037
adb devices -l
adb shell id
adb shell 'which su || true; su -c id 2>/dev/null || true'
adb shell 'ps -A | grep -i frida || true; ls -l /data/local/tmp/frida* 2>/dev/null || true'
python3 - <<'PY'
import frida
print([(d.id, d.name, d.type) for d in frida.enumerate_devices()])
PY
```

如果 shell 方式无法启动 server，优先尝试：

1. 从手机端/Magisk 模块或 `service.d` 启动 frida-server，而不是普通 shell 直接拉起。
2. 改用与本机 Python frida 版本匹配的 server；旧版 `frida-server-16.2.2-android-arm64` 也已在 `/data/local/tmp/`，可作为兼容性回退候选。
3. 用交互式/PTY ADB shell 进入后执行 `su`，避免非交互 `su -c` 权限被拒。
4. 如果 mobile-mcp 只显示 `local/socket/barebone`，但 USB 设备实际存在，要优先以 Python frida / ADB 实测为准，不要被 MCP 设备列表误导。

## 下一步

当前容器 Python 默认曾为 `frida 17.9.1 / frida-tools 14.8.1`。若设备侧临时启动 `frida-server-16.2.2-android-arm64`，17.x 客户端会报协议不匹配：

```text
ProtocolError unable to communicate with remote frida-server; please ensure that major versions match
```

可用下面命令把容器端 Python Frida 临时降到 16.2.2（注意 Debian/PEP668 需要 `--break-system-packages`）：

```bash
python3 -m pip install --user --break-system-packages -q 'frida==16.2.2' 'frida-tools==12.3.0'
python3 - <<'PY'
import frida
print('client', frida.__version__)
d = frida.get_usb_device(timeout=5)
for target in [2853, 'com.ss.android.ugc.aweme']:
    try:
        s = d.attach(target)
        print('ATTACHED_OK', target)
        s.detach()
    except Exception as e:
        print('ATTACH_ERR', target, type(e).__name__, e)
PY
```

但在本机实测，16.2.2 server 虽能监听：

```text
127.0.0.1:27042 LISTEN
```

仍无法 attach 抖音：

```text
PermissionDeniedError unable to access process with pid 2853
ProcessNotFoundError unable to find process with name 'system_server'
```

### 2026-05-02 二次验证：Frida/MCP/ADB 的实际边界

已验证的稳定现象：

```bash
# 设备与 Magisk
adb devices -l                         # SJE0217B17002079 / VTR_AL00
adb shell '/sbin/magisk -v'             # 23.0:MAGISK
adb shell '/sbin/magisk su -c id'       # Permission denied

# 16.2.2 可用 shell 身份启动，但不是 root server
adb shell 'ps -A | grep frida'
# shell ... frida-server-16.2.2-android-arm64

# Python Frida 16.2.2 能看到 USB 设备
python3 - <<'PY'
import frida
print(frida.__version__)
d = frida.get_usb_device(timeout=10)
print(d.id, d.name, d.type)
PY
```

但是该 server 仍有如下限制：

- `usb.enumerate_processes()` 可能直接失败：`ProcessNotFoundError unable to find process with name 'system_server'`
- `usb.attach('com.ss.android.ugc.aweme')` 可能同样报 `ProcessNotFoundError ... system_server`
- 用 ADB 查到抖音 PID 后 `usb.attach(pid)` 会报 `PermissionDeniedError unable to access process with pid ...`
- `usb.spawn(['com.ss.android.ugc.aweme'])` 也会触发 `ProcessNotFoundError ... system_server`
- `adb forward tcp:27042 tcp:27042` 可能返回成功，但容器内 `127.0.0.1:27042` 仍可能 `Connection refused`；实际可测到 `10.0.2.2:27042` open
- `frida.get_device_manager().add_remote_device('10.0.2.2:27042')` 可创建 remote device，但 `enumerate_processes()` 仍会失败在 `system_server`
- `mcp_frida_mobile` 在连续失败后会变成 `unreachable after 3 consecutive failures`；此时不要继续重试 MCP，改用 ADB/Python Frida 手工验证

结论：16.2.2 回退只能验证“版本不匹配/连通性”问题，不能解决非 root server 的进程访问权限。当前真正方向仍是让 frida-server 以 root/Magisk 上下文稳定启动，例如：

1. 在手机端 Magisk 的“超级用户”页确认 Shell/ADB 没有被拒绝，并手工授权。
2. 用 Magisk 模块或 `/data/adb/service.d/` 在 boot/service 阶段启动 frida-server，而不是普通 `adb shell` 拉起。
3. 若继续使用 17.9.1，先解决普通 shell 启动时 `Unable to load SELinux policy` + `SIGSEGV`，不要把它当成客户端版本问题。
4. MCP 仅作为辅助；当它和 Python/ADB 结果冲突时，以 Python Frida + ADB 的直接观测为准。

### Magisk UI 状态

可通过 ADB 打开 Magisk：

```bash
adb shell am start -n com.topjohnwu.magisk/.core.SplashActivity
adb exec-out screencap -p > /tmp/magisk.png
```

当前截图显示 Magisk 主页（Magisk 23.0），无 root 授权弹窗；底部第二个盾牌图标是超级用户/授权管理入口，第四个拼图图标是模块入口。若 `su -c` 在非交互 adb 中一直 Permission denied，下一步应在手机端 Magisk 的超级用户页检查 Shell/ADB 是否被拒绝或未授权。

## 2026-05-02 三次验证：Magisk root + Frida spawn 注入可行路径

后续实测确认：问题关键不是 Frida 完全不可用，而是 server 权限和 attach 模式。

### 已确认可行状态

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
adb shell 'su -c id'
# uid=0(root) gid=0(root) context=u:r:magisk:s0

adb shell 'su -c "pkill -f frida-server || true; /data/local/tmp/frida-server-16.2.2-android-arm64 >/data/local/tmp/frida.log 2>&1 &"'
adb forward tcp:27042 tcp:27042
python3 - <<'PY'
import socket
for host in ['127.0.0.1', '10.0.2.2']:
    s=socket.socket(); s.settimeout(2)
    try:
        s.connect((host,27042)); print(host, 'open')
    except Exception as e:
        print(host, e)
    finally:
        s.close()
PY
```

设备侧 `frida-server-16.2.2-android-arm64` 以 Magisk root 上下文运行时可稳定监听 `127.0.0.1:27042`；容器侧经 `adb forward` 后优先测 `10.0.2.2:27042`。

### 推荐注入方式：spawn + attach

直接 attach 已运行的 `com.ss.android.ugc.aweme` 仍可能不稳定；更可靠做法是 spawn 后立刻 attach，再 resume：

```python
import frida, time

dm = frida.get_device_manager()
d = dm.add_remote_device('10.0.2.2:27042')
pid = d.spawn(['com.ss.android.ugc.aweme'])
session = d.attach(pid)

script = session.create_script(r'''
Java.perform(function () {
  console.log('[*] Java ready');
  // TODO: hook OkHttp / WebSocket / Cipher / RopaEncrypt
});
''')
script.on('message', lambda m, d: print(m))
script.load()
d.resume(pid)
print('spawned and resumed', pid)
while True:
    time.sleep(1)
```

### 优先 Hook 目标

- HTTP：`okhttp3.OkHttpClient.newCall`、`okhttp3.RealCall.execute/enqueue`
- WebSocket：`okhttp3.WebSocket.send`、`okhttp3.WebSocketListener.onMessage`；若类名混淆，先枚举包含 `WebSocket` 的类
- 加密：`javax.crypto.Cipher.init/doFinal`
- 直播/加密入口：`com.bytedance.ropa.encrypt.RopaEncrypt.*`、`QueryFilterEngine.addRequestEncryptHeaders(...)`
- 直播入口：`WebSocketTask.connectWebSocket/connectWS`、`/webcast/feed/live_tab/`、`/webcast/room/info*`

### 决策规则

- 如果 `su -c id` 已是 `u:r:magisk:s0`，不要继续按“ADB 无 root”方向排查。
- 若 running attach 失败，优先切到 spawn 注入，不要反复 attach 旧 PID。
- server/client 主版本必须匹配；使用 `frida-server-16.2.2` 时，容器 Python 也应使用 `frida==16.2.2`。
- `mcp_frida_mobile` 不可靠时，以 ADB + Python Frida 的直接结果为准。

## 2026-05-02 四次验证：当前 Hermes 环境的最终可行注入姿势

在当前容器/Huawei P10/Android 9 组合里，三次验证里的 `add_remote_device('10.0.2.2:27042')` 不是最稳路径；实测更稳的是 **Frida server 用 adb+su 启动，但 Python 连接用 USB device API**。

### 启动 frida-server

不要在前台命令里写 `nohup ... &`，Hermes terminal 会拦截 shell-level backgrounding。用 `terminal(background=true)` 运行：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037
adb shell su -c '/data/local/tmp/frida-server-16.2.2-android-arm64'
```

若返回：

```text
Unable to start: Error binding to address 127.0.0.1:27042: Address already in use
```

说明设备侧已经有 frida-server 在跑；先检查而不是重复启动：

```bash
adb shell 'ps -A | grep frida || ps | grep frida; ss -ltnp 2>/dev/null | grep 27042 || netstat -ltnp 2>/dev/null | grep 27042 || true'
```

### 连接方式：优先 Python USB device

实测 `adb forward tcp:27042 tcp:27042` 后，`127.0.0.1:27042` / `10.0.2.2:27042` remote 连接可能出现：

- `ServerNotRunningError unable to connect to remote frida-server`
- `TransportError connection closed`

但下面方式可稳定枚举：

```python
import frida
print('frida version', frida.__version__)  # 当前应为 16.2.2
d = frida.get_usb_device(timeout=5)
print(d.name, d.type)
print(len(d.enumerate_applications()))
print(len(d.enumerate_processes()))
```

### 推荐动态注入模板：spawn + attach + resume

```python
import frida, time, json

device = frida.get_usb_device(timeout=5)
pid = device.spawn(['com.ss.android.ugc.aweme'])
print('spawned', pid)
session = device.attach(pid)

script = session.create_script(r'''
setImmediate(function() {
  Java.perform(function() {
    console.log('=== Java ready ===');

    try {
      var OkHttpClient = Java.use('okhttp3.OkHttpClient');
      OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(req) {
        try {
          console.log('[HTTP] ' + req.method() + ' ' + req.url().toString());
          var hs = req.headers();
          for (var i = 0; i < hs.size(); i++) console.log('  H ' + hs.name(i) + ': ' + hs.value(i));
        } catch (e) { console.log('newCall detail err ' + e); }
        return this.newCall(req);
      };
      console.log('hooked OkHttpClient.newCall');
    } catch (e) { console.log('OkHttp hook err ' + e); }

    try {
      var RealWebSocket = Java.use('okhttp3.internal.ws.RealWebSocket');
      RealWebSocket.send.overload('java.lang.String').implementation = function(s) {
        console.log('[WS.send str] ' + s);
        return this.send(s);
      };
      RealWebSocket.send.overload('okio.ByteString').implementation = function(bs) {
        console.log('[WS.send bytes] len=' + bs.size());
        return this.send(bs);
      };
      console.log('hooked RealWebSocket.send');
    } catch (e) { console.log('WS hook err ' + e); }

    try {
      var Cipher = Java.use('javax.crypto.Cipher');
      Cipher.doFinal.overload('[B').implementation = function(b) {
        var out = this.doFinal(b);
        console.log('[Cipher.doFinal] ' + b.length + ' -> ' + out.length);
        return out;
      };
      console.log('hooked Cipher.doFinal');
    } catch (e) { console.log('Cipher hook err ' + e); }

    try {
      var ClassLoader = Java.use('java.lang.ClassLoader');
      ClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = function(name, resolve) {
        var ret = this.loadClass(name, resolve);
        var low = name.toLowerCase();
        if (name.indexOf('Ropa') >= 0 || low.indexOf('encrypt') >= 0 || low.indexOf('live') >= 0) {
          console.log('[loadClass] ' + name);
        }
        return ret;
      };
      console.log('hooked ClassLoader.loadClass');
    } catch (e) { console.log('ClassLoader hook err ' + e); }
  });
});
''')
script.on('message', lambda m, d: print('MSG', json.dumps(m, ensure_ascii=False)))
script.load()
device.resume(pid)
time.sleep(20)
```

### 已验证动态信号

成功输出包括：

```text
spawned <pid>
=== Java ready ===
hooked OkHttpClient.newCall
hooked RealWebSocket.send
hooked Cipher.doFinal
hooked ClassLoader.loadClass
[Cipher.doFinal] 30 -> 256
[Cipher.doFinal] 1698 -> 1682
[Cipher.doFinal] 17696 -> 17687
[Cipher.doFinal] 377712 -> 377696
```

这说明 Java 层注入已生效，后续应继续扩大 hook 到 `Request$Builder`、`RealCall.execute/enqueue`、`WebSocketListener.onMessage`、`QueryFilterEngine.addRequestEncryptHeaders`、`RopaEncrypt.*`。

### 更新后的决策规则

- `adb shell su -c id` 返回 `u:r:magisk:s0` 后，不要再按“无 root”方向排查。
- `frida-server-16.2.2` 已经占用 27042 时，不要重启；先直接用 Python `frida.get_usb_device(timeout=5)` 验证。
- remote device (`127.0.0.1:27042` / `10.0.2.2:27042`) 报错时，优先切到 USB API，不要在 remote 地址上反复试。
- 抖音运行态 attach 不稳时，直接 `spawn -> attach -> load script -> resume`。
- Hermes 中长驻 frida-server 用 `terminal(background=true)` 管，不要用 `nohup ... &`。
- attach 已运行抖音时，`frida.enumerate_processes()` 可能偶发看不到 `com.ss.android.ugc.aweme`，但 `adb shell pidof -s com.ss.android.ugc.aweme` 能拿到真实 PID，且 `device.attach(pid)` 可成功；因此 attach 启动器应优先用 `adb pidof` 找 PID，再用 Frida 枚举兜底。

## 2026-05-02 五次验证：HTTP/WS + Crypto 长采集脚本与日志坑

### 采集脚本落地点

本轮把“先抓 HTTP/WS，再抓加密参数”固化为两个临时脚本：

```text
/tmp/douyin_live_http_ws_crypto.js
/tmp/run_douyin_capture.py
```

启动方式：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037

python3 /tmp/run_douyin_capture.py --spawn --seconds 120 --log /tmp/douyin_live_room.log
# 若用户已手动进入直播间，优先用 attach：
python3 /tmp/run_douyin_capture.py --attach --seconds 180 --log /tmp/douyin_live_room_attach.log
```

### JS 日志必须 send()，不能只 console.log()

Frida Python 的 `script.on('message')` 不会稳定收到纯 `console.log()` 内容；若要完整写入 Python 日志文件，JS log 函数必须同时调用 `send()`：

```js
function log(tag, msg) {
  var line = '[' + now() + '][' + tag + '] ' + msg;
  console.log(line);
  try { send(line); } catch (e) {}
}
```

否则 smoke test 看似 hook 成功，但 `/tmp/*.log` 里可能只有 Python 启动日志，缺少 HTTP/WS/Crypto 明细。

### 已验证 Hook 面

推荐同时 hook：

- HTTP：`okhttp3.Request$Builder.url/addHeader/header`、`OkHttpClient.newCall`、`RealCall.execute/enqueue`
- WS：`okhttp3.internal.ws.RealWebSocket.send(String/ByteString)`
- Crypto：`Cipher.getInstance/init/doFinal`、`SecretKeySpec`、`IvParameterSpec`、`Mac.doFinal`、`MessageDigest.digest`
- 类发现：`ClassLoader.loadClass` 过滤 `ropa/encrypt/webcast/live/ws`

### 已抓到的动态信号

启动页/登录页阶段也能抓到加密初始化：

```text
[CRYPTO.cipher.getInstance] RSA/ECB/PKCS1Padding
[CRYPTO.cipher.init] mode=1 alg=RSA
[CRYPTO.cipher.doFinal] inLen=30 outLen=256
[CRYPTO.key] AES keyLen=16 keyHex=...
```

早期 smoke 中曾抓到设备参数 JSON 片段和 webcast 参数片段：

```text
{"app_version":"38.5.0","iid":"...","os_version":"28","channel":"huawei_1128_64","version_code":"380501",...}
webcast_gps_access=2&card_partition_ex_tag=0&api_list=...
```

### 关键操作经验

- `--spawn` 早期注入最稳，但可能触发抖音进入登录页；未登录状态下不会产生直播间 `webcast/room/ws` 流量。
- 要抓直播间 WS/HTTP，最佳流程是用户先手动打开抖音并进入直播间，然后用 `--attach` 长采集。
- 若必须自动化 UI，先用 `uiautomator dump` 确认页面；出现 `DYLoginActivity`、`请输入手机号`、`登录后即可拍摄视频` 时，应停止直播抓取判断，先处理登录/手动进房。
- 长采集过程中 ADB 宿主转发可能断开，表现为 `10.0.2.2:5037 Connection timed out`、`adb: no devices/emulators found`、`frida.InvalidArgumentError: device not found`。这时不是 hook 脚本问题，先恢复宿主 `adb devices` 能看到 `SJE0217B17002079 device`。

### 本次实测补充（2026-05-02）

- 某些情况下，抖音启动后会先弹出系统级 **USB 连接方式** 对话框；若弹窗挡住操作，优先选 **“仅充电”** 再继续，否则 ADB/手势会被打断。
- 顶部那种 `P:0/1 / dX / dY / Prs / Size / T` 的灰色浮层是系统触摸/指针调试信息，不是抖音弹窗；分析页面时要先区分系统浮层和 App 弹窗。
- `adb shell pidof -s com.ss.android.ugc.aweme` 可能比 Frida 枚举更快拿到主进程 PID，但 attach 仍可能超时；此时不要反复 attach 旧 PID，直接改用 spawn，或先重启 Frida server 再试。
- 直播抓取的稳定路径仍然是：先把 App 拉到直播频道/具体直播间，再挂载 hook；如果误回到推荐流或启动页，先恢复到直播页再继续采集。

### 现场补充：当前最稳的进入路径

- 当前抖音主进程在推荐页时，顶部栏可直接识别到“直播，按钮”这个入口；先手动/ADB 进入直播 Tab，再继续抓取，比在启动页上空等更有效。
- 长采集时，优先对“已运行进程”做 `attach`，而不是反复 `spawn`；`spawn` 在本环境里更容易把 App 带回启动/登录态。
- 采集脚本的 JS 日志必须同时 `console.log()` + `send()`，否则 Python 侧日志文件可能漏掉关键网络/加密事件。
- 仅看到推荐页/启动页流量时，不代表 hook 失败；通常只是还没真正进入直播频道或直播间。

### 日志快速筛选

```bash
grep -Ei 'webcast|room|frontier|ws|signature|x-|REQ.url|HTTP|CALL|CRYPTO|Ropa|encrypt' /tmp/douyin_live_room*.log
```

### 2026-05-02 补充：推荐流直播预览 vs 直播广场登录墙

本轮从推荐页实测采集到：推荐流内出现直播预览/直播相关卡片时，曝光或点击会触发预览态接口，而不一定进入真实直播间：

```text
GET https://webcast.amemv.com/webcast/preview/button_info/
GET https://webcast3-normal-c-lf.amemv.com/webcast/preview/button_info/
```

典型参数：

```text
room_id=7635250119230622498
anchor_id=4090623555010920
scene=preview_button
aid=1128
app_name=aweme
version_name=38.5.0
version_code=380500
manifest_version_code=380501
iid=7635159978718332465
device_id=2833904552653872
```

注意区分首页入口：

- 首页左上角图标点击后打开的是侧边抽屉，不是直播页。
- 抽屉里的「直播广场」在未登录状态会进入 `com.ss.android.ugc.aweme.account.business.login.DYLoginActivity`，被登录页拦截。
- 因此未登录状态下，不要把「直播广场」作为抓 `/webcast/room/info`、`frontier`、`wss://` 的主路径；更可靠的是在推荐流里直接点击可观看的直播卡片，或使用已知 `room_id` 触发 App 内直播 schema。

日志判读规则：

- 抓到 `/webcast/preview/button_info/` + `room_id`：说明推荐流直播预览态已触发，Hook 正常，但还不等于进入直播间。
- 抓到 `/webcast/distribution/check_user_live_status/`、`/webcast/v2/tab/`、`/webcast/strategy/*`：多为直播基础配置/状态接口，也不代表 WS 已建立。
- 没有 `frontier`、`wss://`、`/webcast/room/info` 时，优先判断 UI 是否实际进入直播间，而不是先怀疑 Frida Hook 失败。
- 本轮整理模板可参考 `/tmp/douyin_live_flow_summary.md`，用于沉淀“推荐页 → 直播预览 → 登录墙/直播间”的关键路径和参数。

若计数为：

```text
webcast: 0
REQ.url: 0
WS.send: 0
```

但有 `CRYPTO.*`，通常代表 Frida 注入正常，只是未进入直播间或网络请求尚未触发。

### 2026-05-03 补充：100 次滑动前的 Activity 守卫与误判规则

本轮按“重新开始捕捉 + 推荐流最多滑动 100 次找直播入口”执行时，Frida/Hook 正常，但 App 一直卡在：

```text
com.ss.android.ugc.aweme/com.ss.android.ugc.aweme.splash.SplashActivity
```

即使 `spawn` 后日志中出现大量 `webcast` / `frontier` / `connect`，也只是启动阶段直播基础配置/连接信号，不能证明已进入推荐流或直播间。实测计数示例：

```text
/webcast/distribution/check_user_live_status/: 38
/webcast/strategy/feature/: 20
/webcast/strategy/rule/: 21
/webcast/trace/report/: 19
frontier: 22
preview/button_info: 0
webcast/room/info: 0
webcast/feed/live_tab: 0
wss://: 0
```

关键经验：

- 自动 100 次滑动前必须先用 `dumpsys window` 确认当前不在 `SplashActivity` / `DYLoginActivity`，并且已进入首页推荐流；否则滑动命令可能只是在启动页上无效执行。
- `frontier` 或普通 `webcast/strategy/*` 出现不应作为“找到直播入口/进入直播间”的停止条件；真正关键命中应优先看：`preview/button_info`、`webcast/room/info`、`webcast/feed/live_tab`、`wss://`、`LivePlayActivity`。
- 如果页面卡在 `SplashActivity`，先解决 UI 进入首页问题（手动解锁/点过启动页/恢复网络/重新拉起 App），不要继续盲滑 100 次。
- `spawn` 虽然能早期注入，但在本环境可能把 App 固定在启动态；若用户已在推荐流，优先 attach 已运行进程再滑动。
- ADB `input swipe` 可能偶发超时；发生后先检查 `adb devices` 和当前 Activity，而不是马上判断 hook 失败。

### 2026-05-03 补充：先准备 hook，再滑动进入，避免重启 App

这次实战又确认了一个更稳的流程：

- **先把 hook 准备好，但不要先 force-stop / 重启 App。**
- 若要进房前预热，优先对**已运行进程**做 `attach`，不要反复 `spawn` 或 `am force-stop`。
- 如果 App 因卡 Splash / ANR 出现不稳，不要立刻认为是“防 Hook”或主动重启；先检查当前 Activity、PID 和 Frida 连接状态。
- 本环境里一次错误的 `force-stop + monkey` 会把 App 拉回启动页，破坏“先准备 hook、再下滑、再点击进直播”的流程。
- 网络层不需要一开始就全量深追；可先保留轻量 hook，重点等进入直播页后再耐心观察 20–60 秒的 WS 建连信号。
- 关键判断应优先看：
  - `LivePlayActivity`
  - `preview/button_info`
  - `webcast/room/info`
  - `frontier`
  - `wss://`
  - `WebSocket`

### 2026-05-03 补充：持续抓取与脚本收敛

用户明确要求“不需要限时，持续抓”时，`/tmp/run_douyin_capture.py` 已支持：

```bash
python3 /tmp/run_douyin_capture.py --attach --js /tmp/douyin_live_http_ws_crypto.js --seconds 0 --log /tmp/douyin_live_ws_cont.log
```

`--seconds 0` 表示常驻采集，直到手动 kill / Ctrl-C；不要再用 180/360 秒限时参数。

长驻抓取时的经验：

- 旧的轻量脚本里硬 hook `WsConnectTask` / `WsPingTask` 会刷 `ClassNotFoundException ... ##not found in Plugin##`。这通常不是崩溃，只是当前版本类不存在/插件化未加载，但会污染日志。
- 更稳做法是先停掉旧进程，再用通用 `OkHttp / RealCall / Request$Builder / WebSocketListener / RealWebSocket / Cipher / Mac / MessageDigest / ClassLoader` hook，不依赖易失 frontier 类名。
- `Cronet` / `UrlRequest` 类不存在时也只是可忽略警告；如果持续刷屏，应从脚本中移除或改成发现类加载后再 hook。
- 后台进程状态要用 Hermes `process.poll/log` 验证；看到 `ClassNotFoundException` 不等于采集停止，必须检查进程是否仍为 `running`。
- 重启采集时先 `process.kill` 旧 session，避免多个 Frida script 同时挂载导致日志混乱。

当前推荐的持续抓取日志：

```text
/tmp/douyin_live_ws_cont.log
```

当前推荐脚本文件：

```text
/tmp/douyin_live_http_ws_crypto.js
```

### 2026-05-03 补充：采集启动器 fallback 与日志提取器

`/tmp/run_douyin_capture.py` 已支持 spawn 失败/超时时自动回退到 monkey 启动后 attach：

```bash
python3 /tmp/run_douyin_capture.py --spawn --spawn-fallback monkey-attach --seconds 0 --log /tmp/douyin_live_ws_cont.log
```

也可直接 attach 已运行抖音：

```bash
python3 /tmp/run_douyin_capture.py --attach --seconds 0 --log /tmp/douyin_live_ws_cont.log
```

关键实现坑：只有真正由 Frida `device.spawn()` 拉起的进程才应 `device.resume(pid)`；如果 spawn 失败后 fallback 到 `monkey-attach`，不要再对 monkey 启动的已运行进程调用 `resume`。启动器里应以 `spawned_by_frida` 判断，而不是简单判断 `args.spawn`：

```python
if spawned_by_frida:
    logger.write("resuming app")
    device.resume(pid)
```

日志提取器 `/tmp/extract_douyin_capture.py` 可把 Frida 采集日志收敛成 text / json / csv，避免大日志直接进上下文：

```bash
python3 /tmp/extract_douyin_capture.py --format text --out /tmp/douyin_live_ws_cont.summary.txt /tmp/douyin_live_ws_cont.log
python3 /tmp/extract_douyin_capture.py --format json --out /tmp/douyin_live_ws_cont.events.json /tmp/douyin_live_ws_cont.log
python3 /tmp/extract_douyin_capture.py --format csv --out /tmp/douyin_live_ws_cont.events.csv /tmp/douyin_live_ws_cont.log
```

验证命令：

```bash
python3 -m py_compile /tmp/run_douyin_capture.py /tmp/extract_douyin_capture.py
python3 /tmp/run_douyin_capture.py --help
python3 /tmp/extract_douyin_capture.py --format json --out /tmp/douyin_capture_attach.events.json /tmp/douyin_capture_attach.log
```

已有日志验证样例：`/tmp/douyin_capture_attach.log` 可提取出 `total_events=220`，分类包括 `crypto/http/lifecycle/class/websocket`，并统计 `live_signal_count` 与 `signature_signal_count`。摘要可重点看 top hosts/top paths/crypto/live-signature signals。

### 2026-05-02 补充：推荐流自动滑动找直播卡片的安全姿势

在推荐流里自动滑动找直播卡片时，起滑点很重要。若从右侧互动栏、底部导航、评论按钮附近滑动，容易误触评论/关注/直播广场并进入登录页，例如登录页文案可能是：

```text
登录后即可评论
登录发现更多精彩
com.ss.android.ugc.aweme.account.business.login.DYLoginActivity
```

用户明确要求“不要进入直播广场，而是在推荐页面滑动寻找推荐的直播间入口”时，按推荐流路径执行：先关闭登录页/侧边抽屉并确认顶部「推荐」高亮、底部「首页」选中；不要点击顶部「直播/播」或侧边菜单「直播广场」。推荐流直播预览的可见特征包括左下粉色「直播中」标签、主播昵称（如 `@雾南枝（逆水寒手游）`）、直播分类/标题；命中后点击屏幕中部预览区域（约 `x=540,y=900`）进入。另一类命中是普通推荐视频右侧作者头像出现粉色圆环/上方「直播」标识，UIAutomator 可能只额外出现一次「直播中」；这通常是主播正在直播的进房入口，按 1080x1920 屏幕可优先点右侧头像区域约 `x=920~1060,y=490~650`，实测中心点 `x=990,y=570` 可进入。进入成功可用 Activity 验证：`com.ss.android.ugc.aweme.live.LivePlayActivity`；截图短时间黑屏/加载中并不一定失败。

实测更安全的滑动区域：

```bash
# 推荐流内安全上滑：屏幕中部偏左，避开右侧按钮、底部导航、文案区
adb shell input swipe 520 820 520 300 350

# 更长距离慢滑版本
adb shell input swipe 500 1050 500 260 650
```

自动化流程建议：

1. 先关闭侧边抽屉/登录页，确认当前顶部「推荐」高亮，底部「首页」选中。
2. attach 已运行抖音进程长采集，避免 spawn 把 App 带回启动/登录态：

```bash
python3 /tmp/run_douyin_capture.py --attach --js /tmp/douyin_live_deep_hooks.js --seconds 360 --log /tmp/douyin_live_scroll_scan.log
```

3. 每次安全上滑后截图 + `dumpsys window` 检查是否误入 `DYLoginActivity`。
4. 同步筛选日志：

```bash
grep -Ei 'preview/button_info|room/info|frontier|wss://|WebSocket|live_tab|webcast' /tmp/douyin_live_scroll_scan*.log
```

5. 若刷到直播相关命中，再停下截图确认是否是直播卡片；不要把普通 `webcast/strategy/*`、`api/apps/xconfig_meta`、`check_user_live_status` 当成进房成功。

本轮经验：连续安全滑动 45 条推荐流内容，只出现普通图文/视频内容与直播基础配置请求，未命中 `/webcast/preview/button_info`、`/webcast/room/info`、`frontier`、`wss://`。这说明“推荐流刷直播卡片”概率不稳定；若长时间无命中，应切换策略到：登录后直播 Tab、已知 `room_id` schema/deeplink、或推荐算法预热，而不是继续盲滑。

## 2026-05-02 补充：不走登录页的直播抓取分支

当目标是直播间/直播 Tab 协议层，不要把时间浪费在登录页。更有效的策略是：

1. 先确认 Frida/ADB 通道可用，再直接进入直播 Tab 或具体直播间。
2. 采集脚本优先 hook：
   - `java.net.URL` / `URI` / `Socket` / `InetSocketAddress`
   - `okhttp3.OkHttpClient.newCall`
   - `okhttp3.internal.ws.RealWebSocket.send(String/ByteString)`
   - `org.chromium.net.UrlRequest$Builder` / `UrlRequest.start`
   - `javax.crypto.Cipher` / `Mac` / `SecretKeySpec` / `IvParameterSpec`
   - `ClassLoader.loadClass` 过滤 `webcast|room|live|frontier|cronet|ttnet|ws`
3. 自定义 JS 日志函数必须同时 `console.log()` + `send()`，否则 Python 侧日志文件可能看不到关键流量。
4. 直播间数据常见模式是：
   - Java/OKHttp/Cronet 先出请求
   - `Cipher.doFinal()` 可能解出 gzip payload
   - 再从明文里找 `webcast` / `room_id` / `frontier` / `push`
5. 若 `mcp_frida_mobile` 连续失败并报 unreachable，不要继续重试它，改用本地 ADB + Python Frida 直接验证。

### 本次实测学到的坑

- `frida.get_usb_device(timeout=...)` 在本环境里比 remote device 更稳。
- `adb_SERVER_SOCKET=tcp:10.0.2.2:5037` 这条链路一旦断开，`adb` 会整体超时，表现为 `device not found` 或 `Connection timed out`，这不是脚本问题。
- `spawn -> attach -> load script -> resume` 比 attach 已运行进程更稳。
- 对直播分析来说，`OkHttp/WS/Cipher/ClassLoader` 的组合比只盯登录页更有产出。

## 2026-05-03 补充：直播 Tab 点击进入与进房验证闭环

本轮从推荐流继续执行时，长时间推荐流安全滑动未命中直播卡片，但顶部频道栏里 `uiautomator dump` 可稳定识别到「直播，按钮」。当用户目标是验证直播间 HTTP/WS，而不是坚持推荐流路径时，可切换到顶部直播 Tab：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037

# 先确认页面不是登录页/启动页
adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'
adb shell uiautomator dump /sdcard/window.xml
adb exec-out cat /sdcard/window.xml > /tmp/douyin_window.xml
python3 - <<'PY'
from pathlib import Path
s = Path('/tmp/douyin_window.xml').read_text(errors='ignore')
print('直播按钮位置', s.find('直播，按钮'))
PY

# 顶部「直播」按钮实测中心点约 (190,135)，不同频道布局需以 XML bounds 为准
adb shell input tap 190 135
sleep 4
```

进入直播 Tab 后，界面可能短时间黑屏或只显示「直播发现」，不要立刻判失败。继续等待、下拉刷新或轻触列表区域后，可能自动进入一个直播间。验证闭环优先看 UI Activity + 关键接口，而不是只看视觉截图：

```bash
adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'
# 成功进房应出现：com.ss.android.ugc.aweme.live.LivePlayActivity

grep -Ei 'webcast/feed/live_tab|webcast/preview/button_info|webcast/room/info|webcast/room/enter|webcast/im/fetch/v2/history|WebSocketListener|RealWebSocket' \
  /tmp/douyin_live_ws_cont.log | tail -n 80
```

本轮成功进房后的关键命中包括：

```text
/webcast/feed/live_tab/
/webcast/preview/button_info/?room_id=...&anchor_id=...
/webcast/room/info_by_scene/?room_id=...&scene=into_preview
/webcast/room/enter_preload/?room_id=...
/webcast/room/enter/?...
/webcast/room/enter_backend/?room_id=...
/webcast/im/fetch/v2/history/?rid=...&room_id=...
WebSocketListener.onOpen
WebSocketListener.onMessage
RealWebSocket.send
```

判定规则：

- `LivePlayActivity` + `/webcast/room/enter*` + `/webcast/im/fetch/v2/history` 基本可判定已进入真实直播间。
- `webcast/feed/live_tab` 只表示直播 Tab/广场加载，不等于进房。
- `preview/button_info` + `room_id/anchor_id` 表示直播预览/候选房间已出现；随后若出现 `room/info_by_scene`、`room/enter*` 才是进入路径。
- 视觉上看到聊天室输入框「说点什么…」、主播信息、弹幕区后，可作为 UI 层二次确认；无需再点榜单/成员等控件验证进房。
- 长驻采集进程可继续保持：`python3 /tmp/run_douyin_capture.py --attach --js /tmp/douyin_live_http_ws_crypto.js --seconds 0 --log /tmp/douyin_live_ws_cont.log`。

### 2026-05-03 补充：ADB/Frida USB 断链的快速判定

当复验长采集前出现以下组合时，先判定为宿主机 ADB/USB 链路未恢复，不要继续调 hook 或重试 MCP：

```text
10.0.2.2:5037 closed
172.17.0.1:5037 closed
adb devices -l 无设备
frida.get_usb_device(...) -> InvalidArgumentError device not found
```

推荐一次性检查命令：

```bash
for host in 10.0.2.2 172.17.0.1; do
  printf '%s:5037 ' "$host"
  timeout 2 bash -lc "</dev/tcp/$host/5037" >/dev/null 2>&1 && echo open || echo closed
  ADB_SERVER_SOCKET=tcp:$host:5037 ANDROID_ADB_SERVER_ADDRESS=$host ANDROID_ADB_SERVER_PORT=5037 timeout 8 adb devices -l || true
done
python3 - <<'PY'
import frida
print('frida', frida.__version__)
try:
    d = frida.get_usb_device(timeout=5)
    print('USB_OK', d.id, d.name, d.type)
except Exception as e:
    print('USB_ERR', type(e).__name__, e)
PY
```

只有宿主机侧 `adb devices -l` 恢复看到 `SJE0217B17002079 device` 后，才继续执行长采集：

```bash
python3 /tmp/run_douyin_capture.py --attach --js /tmp/douyin_live_http_ws_crypto.js --seconds 0 --log /tmp/douyin_live_ws_cont.log
```

### 2026-05-03 补充：运行态 attach 可稳定抓 TTNET/Cronet 与 Crypto

本轮实测中，`spawn` 路径在当前环境可能卡住：

```text
frida.TransportError: timeout was reached
```

但先让抖音正常运行，再对主进程 `attach` 是可行路径：

```bash
python3 /tmp/run_douyin_capture.py --attach --seconds 60 --log /tmp/douyin_capture_attach.log
```

成功信号包括：

```text
script loaded
[INIT] http/ws/crypto hooks installed
[INIT] hooked com.ttnet.org.chromium.net.urlconnection.CronetHttpURLConnection.getResponseCode()
[CRYPTO.SecretKeySpec] alg=AES keyLen=32
[CRYPTO.IvParameterSpec] ivLen=12
[CRYPTO.getInstance] AES/GCM/NoPadding
[TTNET.getResponseCode] https://aweme.snssdk.com/service/settings/v3/?klink_egdi=...
[TTNET.getResponseCode] https://aweme.snssdk.com/aweme/homepage/combine/?...
[CRYPTO.getInstance] RSA/ECB/PKCS1Padding
[CRYPTO.getInstance] AES/CBC/PKCS7PADDING
[CRYPTO.SecretKeySpec] alg=HmacSHA256 keyLen=36
[CRYPTO.mac.doFinal] inLen=52
[CRYPTO.SecretKeySpec] alg=HmacSHA256 keyLen=64
```

### 关键判断

- 大量请求走 `TTNET` / `CronetHttpURLConnection`，不要只盯 OkHttp；`com.ttnet.org.chromium.net.urlconnection.CronetHttpURLConnection.getResponseCode()` 是当前版本有效观察点。
- 常见启动/首页接口：
  - `aweme.snssdk.com/service/settings/v3/`
  - `aweme.snssdk.com/aweme/homepage/combine/`
  - `aweme.snssdk.com/aweme/v1/multicast/query/`
  - `mssdk.bytedance.com/*`
  - `gecko.zijieapi.com/*`
  - `polaris.zijieapi.com/*`
- `klink_egdi=...` 会在大量请求参数中出现，是后续可专盯的签名/设备风控参数之一。
- Crypto 层可见 `AES/GCM/NoPadding`、`AES/CBC/PKCS7PADDING`、`RSA/ECB/PKCS1Padding`、`HmacSHA256`，以及 keyLen `16/32/36/64`、IV len `12` 等线索。
- `okhttp3.internal.ws.RealWebSocket.connect` hook 报 overload 不匹配时不是致命问题；改 hook `.connect('okhttp3.OkHttpClient')` 或暂时只保留 `send/onMessage/onOpen`。
- `org.chromium.net.UrlRequest*` 不存在时也不是失败，当前可用的是 `com.ttnet.org.chromium.*` 命名空间。

### 日志收敛脚本

大日志不要直接贴给模型；先抽关键行：

```python
import re
path='/tmp/douyin_capture_attach.log'
patterns=[
  r'\[TTNET\.getResponseCode\] (https?://\S+)',
  r'\[CRYPTO\.SecretKeySpec\] .*',
  r'\[CRYPTO\.getInstance\] .*',
  r'\[CRYPTO\.init\.key(?:\.spec)?\] .*',
  r'\[CRYPTO\.doFinal(?:\.bytes)?\] .*',
  r'\[CRYPTO\.digest\] .*',
  r'\[CRYPTO\.mac\.doFinal\] .*',
  r'\[INIT\] .*',
  r'\[WARN\] .*',
]
seen=set()
with open(path, errors='ignore') as f:
  for line in f:
    for p in patterns:
      m=re.search(p, line)
      if m and m.group(0) not in seen:
        print(m.group(0)); seen.add(m.group(0))
        break
```

### 决策规则更新

- 若 `spawn` 超时，不要陷入重试；改为“用户/ADB 先拉起 App → attach 主进程 → 等 20–60 秒”。
- 如果目标只是确认网络/加密 hook 是否有效，运行态 attach 已足够；只有需要捕获极早初始化时再考虑 spawn。
- 看到 `TTNET.getResponseCode` + `CRYPTO.*` 即可判定 hook 有效；没有直播接口时先判断 UI 是否进入直播页，而不是怀疑注入失败。

## 2026-05-03 补充：enhanced hook 复验 Query/Ropa/TTNET 的成功判定

本轮在 ADB/Frida USB 恢复后，使用 enhanced hook 重新 attach 已运行抖音进程并长驻采集，确认以下闭环可作为“直播协议 hook 有效”的复验标准：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037
python3 /tmp/run_douyin_capture.py \
  --attach \
  --js /tmp/douyin_live_http_ws_crypto.js \
  --seconds 0 \
  --log /tmp/douyin_live_ws_enhanced_live.log
```

复验命令：

```bash
python3 /tmp/extract_douyin_capture.py \
  --format text \
  --out /tmp/douyin_live_ws_enhanced_live.summary.txt \
  /tmp/douyin_live_ws_enhanced_live.log

python3 - <<'PY'
from pathlib import Path
s = Path('/tmp/douyin_live_ws_enhanced_live.log').read_text(errors='ignore')
for k in [
  'webcast/im/fetch/v2', 'webcast/room/enter', 'webcast/room/info',
  'webcast/feed/live_tab', 'preview/button_info', 'TTNET.getResponseCode',
  'QUERY.filterQuery', 'QUERY.tryEncryptRequest', 'RopaEncrypt.', 'ROPA.',
  'WebSocketListener', 'RealWebSocket', 'x-tt-dt', 'r_signature',
  'klink_egdi', 'CRYPTO.SecretKeySpec', 'CRYPTO.digest'
]:
    print(f'{k}: {s.count(k)}')
PY
```

已验证成功信号：

```text
[LAUNCHER] frida-python=16.2.2
[LAUNCHER] device=VTR AL00 type=usb
[LAUNCHER] attaching pid=<pid>
[LAUNCHER] script loaded
[INIT] enhanced http/ws/crypto/ttnet/query hooks installing
[INIT] hooked com.bytedance.ropa.encrypt.RopaEncrypt.getEncryptSeq overload#0
[INIT] hooked com.bytedance.ropa.encrypt.RopaEncrypt.getEncryptSeqV2 overload#0
[QUERY.filterQuery] url=https://webcast.amemv.com/webcast/im/fetch/v2/?...
[QUERY.tryEncryptRequest] extra=null url=https://webcast.amemv.com/webcast/im/fetch/v2/?...
[TTNET.getResponseCode] com.ttnet.org.chromium.net.urlconnection.CronetHttpURLConnection:https://webcast.amemv.com/webcast/im/fetch/v2/?...
[TTNET.getHeaderFields] .../webcast/im/fetch/v2/?...
[TTNET.getInputStream] .../webcast/im/fetch/v2/?...
[CRYPTO.digest] len=513 ...
[CRYPTO.SecretKeySpec] alg=AES len=16 ...
```

关键判定规则：

- `QUERY.filterQuery` + `QUERY.tryEncryptRequest` 出现，说明 `QueryFilterEngine` 链路已可见。
- `RopaEncrypt.*` 的 `[INIT] hooked ...` 只代表 hook 安装成功；若没有 `ROPA.*` 调用输出，不一定失败，可能当前请求未走 RopaEncrypt、调用发生在 attach 前，或在其他进程。
- `TTNET.getResponseCode/getHeaderFields/getInputStream` 命中 `com.ttnet.org.chromium.net.urlconnection.CronetHttpURLConnection`，说明当前网络观察点有效；不要只盯 `org.chromium.net.*`。
- 直播间真实 IM 请求可表现为 `/webcast/im/fetch/v2/`，参数里常见：`room_id/rid`、`klink_egdi`、`r_signature`、`x-tt-dt` header。
- UI 曾在 `com.ss.android.ugc.aweme.live.LivePlayActivity` 时抓到上述信号；若之后焦点切到桌面，长驻 hook 可能仍可继续运行，但必须先验证抖音主进程是否还存在。
- 如果 `process.poll` 显示采集进程仍是 `running`，但 `adb shell pidof -s com.ss.android.ugc.aweme` 为空、`dumpsys window` 前台是 `com.huawei.android.launcher`，且日志计数不再增长，这通常表示目标 App 已退出/被回收，Frida 采集进程只是外壳还活着。此时不要继续等日志，也不要把它误判成 hook 失败；先 `process.kill` 旧采集 session，重新拉起抖音并进入直播页/直播间，再用 `--attach --seconds 0` 新开一轮长驻采集。

快速判定命令：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037
adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'
adb shell pidof -s com.ss.android.ugc.aweme || true
python3 - <<'PY'
from pathlib import Path
p=Path('/tmp/douyin_live_ws_enhanced_live2.log')
s=p.read_text(errors='ignore') if p.exists() else ''
for k in ['webcast/im/fetch/v2','webcast/room/enter','webcast/room/info','webcast/feed/live_tab','preview/button_info','TTNET.getResponseCode','QUERY.filterQuery','QUERY.tryEncryptRequest','RopaEncrypt.','ROPA.','WebSocketListener.onOpen','RealWebSocket.send','klink_egdi','x-tt-dt','CRYPTO.SecretKeySpec']:
    print(f'{k}: {s.count(k)}')
PY
```

恢复流程：

```bash
# 先停旧 Hermes background session，避免旧 script/日志污染
# process.kill <old_session_id>
adb shell monkey -p com.ss.android.ugc.aweme 1
# 手动或 ADB 进入直播 Tab / LivePlayActivity 后：
python3 /tmp/run_douyin_capture.py \
  --attach \
  --js /tmp/douyin_live_http_ws_crypto.js \
  --seconds 0 \
  --log /tmp/douyin_live_ws_enhanced_live3.log
```

本轮样例房间 ID：

```text
room_id=7635641714312514350
```

该 ID 只是样例，不应写死到脚本逻辑。

## 2026-05-03 补充：ANR/异常提醒后的直播验证恢复规则

本轮复验 `verify_live_signals` 时遇到一个容易误判的场景：Frida/ADB 都正常，Hook 也能加载，但 UI 因 ANR、误触系统 App、抖音异常修复页而离开直播路径，导致关键直播接口计数为 0。

已观察到的状态组合：

```text
mCurrentFocus=com.huawei.android.launcher/.unihome.UniHomeLauncher
adb shell pidof -s com.ss.android.ugc.aweme -> 仍有 PID
frida.get_usb_device(timeout=5) -> USB_OK
采集日志中 WebSocket/Crypto 少量命中，但：
webcast/feed/live_tab: 0
preview/button_info: 0
webcast/room/info: 0
webcast/room/enter: 0
webcast/im/fetch/v2: 0
QUERY.filterQuery: 0
QUERY.tryEncryptRequest: 0
```

判定规则：

- 抖音 PID 存在但前台是桌面/通讯录/手机管家/异常提醒页时，不要把直播接口 0 误判为 Hook 失败；先恢复 UI 到正常抖音首页或直播页。
- 出现系统 ANR「抖音 无响应。是否将其关闭？」时，优先点击「等待」；但点击后必须立刻用 `dumpsys window` 和截图确认是否误入其他系统 App。
- 出现「抖音异常提醒：检测到抖音多次闪退... 退出 / 优化程序」时，点击「优化程序」可能直接回到桌面；之后需要重新拉起抖音并等待进入正常首页，再 attach，不要继续盯旧日志等直播信号。
- 顶部触控/指针调试浮层可能影响视觉判断，但不是 App 弹窗；真正阻断流程的是 ANR、异常提醒、登录页、系统 App 前台。
- 旧的 Frida background 进程在目标 App 退到桌面或重启后可能仍显示存在/已退出混杂；复验前先 `process.list`/`process.kill` 清掉旧采集，避免旧日志污染。

推荐恢复闭环：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037

# 1. 先确认链路和前台，不要直接判断 hook
adb devices -l
adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'
adb shell pidof -s com.ss.android.ugc.aweme || true
python3 - <<'PY'
import frida
print('frida', frida.__version__)
d = frida.get_usb_device(timeout=5)
print('USB_OK', d.id, d.name, d.type)
PY

# 2. 若前台不是抖音正常首页/直播页，先重新拉起并截图确认
adb shell monkey -p com.ss.android.ugc.aweme 1
sleep 6
adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'
adb exec-out screencap -p > /tmp/douyin_recover.png

# 3. 只在 UI 正常后重新 attach 新日志
python3 /tmp/run_douyin_capture.py \
  --attach \
  --js /tmp/douyin_live_http_ws_crypto.js \
  --seconds 0 \
  --log /tmp/douyin_live_ws_recover.log
```

验证 `verify_live_signals` 完成时，必须同时满足：

- UI/Activity 已在直播 Tab 或 `LivePlayActivity`，而不是桌面/通讯录/异常提醒页；
- 日志新增出现至少一类直播路径：`webcast/feed/live_tab`、`preview/button_info`、`webcast/room/info*`、`webcast/room/enter*`、`webcast/im/fetch/v2`；
- 若只有 `WebSocketListener` / `CRYPTO.*` 少量命中但直播路径全为 0，只能说明 hook 活着，不能说明已进入直播页。

## 2026-05-04 补充：直播 Tab 可直接进房，但 enhanced 全量 Hook 会诱发 ANR

本轮从首页推荐流恢复后确认：不挂 Hook 时，顶部频道栏「直播/播」入口可稳定进入直播 Tab/直播发现页，并可自动进入直播间。验证路径：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037

adb shell monkey -p com.ss.android.ugc.aweme 1
sleep 12
adb shell input tap 190 135   # 顶部「直播」入口，实际以 XML bounds 为准
sleep 15
adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'
# 成功进房：com.ss.android.ugc.aweme/.live.LivePlayActivity
```

UI 侧成功信号：

- `LivePlayActivity`
- XML/截图中出现「说点什么」「关注」
- 直播 Tab 阶段可能先出现「直播发现」「自动进入直播间」，等待即可自动进房

但使用 `/tmp/douyin_live_http_ws_crypto.js` 的 enhanced 全量 Hook 在直播间内 attach 后，若继续点击输入框/上滑切房，容易出现系统 ANR：

```text
Application Not Responding: com.ss.android.ugc.aweme
抖音 无响应。是否将其关闭？
按钮：关闭应用 / 等待
```

本轮日志现象：Hook 初始化成功、`RopaEncrypt.*`/`WebSocketListener`/`RealWebSocket.send` 有少量命中，但直播 HTTP 关键路径仍全为 0：

```text
webcast/feed/live_tab: 0
preview/button_info: 0
webcast/room/info: 0
webcast/room/enter: 0
webcast/im/fetch/v2: 0
QUERY.filterQuery: 0
QUERY.tryEncryptRequest: 0
```

判定规则：

- `LivePlayActivity` + UI 元素出现，说明进房路径本身没问题；直播接口为 0 时，不要先怀疑 UI 自动化。
- attach 时机太晚时，`room/enter*` 和 `im/fetch/v2/history` 可能已在 attach 前完成；需要在进入直播 Tab 前挂轻量网络 Hook，或进房后等待刷新/切房触发。
- enhanced 脚本包含 `ClassLoader.loadClass`、`Cipher.doFinal`、`MessageDigest.digest`、Header 构造等高频 Hook，直播页交互时性能压力大；若目标只是 URL/接口计数，先用轻量 Hook，不要一开始全量 Crypto/ClassLoader。
- 出现 ANR 后优先点击「等待」，但必须马上用 `dumpsys window`/截图确认是否误入华为商城、手机管家等系统 App；不要继续盯旧日志。
- 若 Hook 后误入系统 App 或抖音 PID 消失，应先 `process.kill` 旧采集，重新拉起抖音并确认首页，再继续。

推荐下一轮轻量化策略：

1. 先无 Hook/轻量 Hook 确认能从首页进入直播 Tab 和 `LivePlayActivity`。
2. 只保留低频 URL 观察点：`OkHttpClient.newCall`、`RealCall.execute/enqueue`、`Request$Builder.url`、`com.ttnet.org.chromium.net.urlconnection.CronetHttpURLConnection.getResponseCode/getInputStream/getHeaderFields`、`WebSocketListener.onOpen/onMessage`、`RealWebSocket.send`。
3. 暂时移除或延后：`ClassLoader.loadClass`、`Cipher.doFinal`、`MessageDigest.digest`、`SecretKeySpec/IvParameterSpec`、`Header.$init`、`Request$Builder.headers` 等高频 Hook。
4. 直播 URL/room_id 抓到后，再针对单一路径恢复 QueryFilter/Ropa/Crypto 定点 Hook。

## 2026-05-04 补充：轻量 TTNET/URL Hook 成功闭环与摘要落地

本轮在 enhanced 全量 Hook 诱发 ANR 后，改用轻量 URL/TTNET/WS Hook，成功恢复到直播 Tab 并抓到真实直播间接口。可复用文件：

```text
/tmp/douyin_live_light_net.js
/tmp/douyin_live_light_0504.log
/tmp/douyin_live_light_0504.final_summary.md
```

推荐执行方式：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037

# 如 Frida USB 临时 device gone，先重启 16.2.2 server
adb shell 'su -c "pkill -f frida-server || true"'
sleep 1
adb shell 'su -c "/data/local/tmp/frida-server-16.2.2-android-arm64 >/data/local/tmp/frida16.log 2>&1 &"'
sleep 2

# 拉起抖音，确认首页有顶部「直播」入口
adb shell am force-stop com.ss.android.ugc.aweme
adb shell monkey -p com.ss.android.ugc.aweme 1
sleep 10
adb shell uiautomator dump /sdcard/window.xml >/dev/null 2>&1
adb exec-out cat /sdcard/window.xml | grep -E '直播|推荐|首页' | head

# 先 attach 轻量 Hook，再点击顶部直播入口并等待进房
python3 /tmp/run_douyin_capture.py \
  --attach \
  --js /tmp/douyin_live_light_net.js \
  --seconds 0 \
  --log /tmp/douyin_live_light_0504.log

adb shell input tap 190 135
sleep 15
adb shell input tap 540 520   # 直播发现页里轻触列表/预览区域，必要时触发进房
sleep 10
```

本轮最终验证状态：

```text
mCurrentFocus=com.ss.android.ugc.aweme/.live.LivePlayActivity
pid=30923
```

关键命中计数样例：

```text
webcast/feed/live_tab: 23
preview/button_info: 22
webcast/room/info: 13
webcast/room/enter: 65
webcast/im/fetch/v2: 11
QUERY.filterQuery: 68
QUERY.tryEncryptRequest: 52
TTNET.getResponseCode: 63
TTNET.getHeaderFields: 189
TTNET.getInputStream: 63
x-tt-dt: 38
r_signature: 103
klink_egdi: 396
room_id=: 250
anchor_id=: 93
```

样例 ID：

```text
room_id/rid:
- 7635818784263047987
- 7635804407568861998
anchor_id:
- 2051051718472889
```

有效端点包括：

```text
/webcast/feed/live_tab/
/webcast/preview/button_info/
/webcast/room/info_by_scene/
/webcast/room/enter/
/webcast/room/enter_preload/
/webcast/room/enter_backend/
/webcast/im/fetch/v2/history/
/webcast/gift/list/
/webcast/gift/effect_game/get/
/webcast/lottery/melon/lottery_info/
```

判定规则更新：

- `LivePlayActivity + room/enter* + im/fetch/v2 + QueryFilterEngine + TTNET` 可判定已进入真实直播间并抓到协议链路。
- 如果 `webcast/feed/live_tab` 有命中但没有 `room/enter*`，通常只到直播 Tab/直播发现页，继续等待或轻触预览区域。
- 轻量脚本应优先保留 `TTNET.getResponseCode/getHeaderFields/getInputStream`、`Request/URL`、`QueryFilterEngine.filterQuery/tryEncryptRequest`、低频 WS hook；不要一开始启用 `ClassLoader.loadClass`、`Cipher.doFinal`、`MessageDigest.digest`、Header 构造等高频 Hook。
- Frida 报 `TransportError: the connection is closed` / `InvalidOperationError: device is gone` 时，先重启设备侧 `frida-server-16.2.2`，再用 Python USB API attach；不要切回 remote `127.0.0.1:27042` 反复试。
- 大日志收敛用脚本生成 markdown 摘要，不要直接把完整日志塞进上下文；本轮摘要落地为 `/tmp/douyin_live_light_0504.final_summary.md`。

### 2026-05-04 续跑补充：从已运行首页恢复采集的最小闭环

如果前一轮采集/上下文中断，但抖音仍在运行，优先不要 force-stop；先确认 ADB + Frida USB + PID，然后直接 attach 轻量脚本续抓：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037

adb devices -l
adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'
adb shell pidof -s com.ss.android.ugc.aweme || true
python3 - <<'PY'
import frida
print('frida', frida.__version__)
d = frida.get_usb_device(timeout=5)
print('USB_OK', d.id, d.name, d.type)
PY

python3 /tmp/run_douyin_capture.py \
  --attach \
  --js /tmp/douyin_live_light_net.js \
  --seconds 0 \
  --log /tmp/douyin_live_continue_0504.log
```

UI 恢复路径：若截图/视觉确认已在首页推荐流，直接点击顶部直播入口，再轻触直播发现页中部区域触发进房：

```bash
adb shell input tap 190 135
sleep 15
adb shell input tap 540 520
sleep 10
adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'
# 成功：com.ss.android.ugc.aweme/.live.LivePlayActivity
```

注意：`uiautomator dump` 偶发会卡住/超时，但这不代表 App 卡死。若 `dumpsys window` 显示仍在抖音，优先用 `adb exec-out screencap -p > /tmp/douyin_screen.png` 加视觉确认页面；确认是正常首页后继续点直播入口，不要因为 XML dump 超时而重启 App。

本轮续跑样例计数：

```text
webcast/feed/live_tab: 22
preview/button_info: 11
webcast/room/info: 12
webcast/room/enter: 91
webcast/im/fetch/v2: 11
QUERY.filterQuery: 90
QUERY.tryEncryptRequest: 65
TTNET.getResponseCode: 86
TTNET.getHeaderFields: 259
TTNET.getInputStream: 86
r_signature: 149
klink_egdi: 445
x-tt-dt: 46
room_id=: 261
anchor_id=: 92
WS.connect/onOpen/onMessage/send: 0
wss:// / frontier: 0
```

判定规则：`LivePlayActivity + room/enter* + im/fetch/v2 + QueryFilterEngine + TTNET` 已足够判定直播链路抓取成功；同轮 `WS.*=0` 继续支持“当前版本不要把 wss/frontier 当唯一成功指标”的规则。

## 2026-05-04 补充：不要把“未抓到 wss”误判为失败，当前版本可能走 TTNET HTTP fetch

在轻量 TTNET/URL Hook 已经成功抓到真实直播间接口后，额外尝试了 WebSocket 专项 probe：

```text
/tmp/douyin_ws_probe.js
/tmp/douyin_ws_probe2.js
/tmp/douyin_ws_probe2_0504c.log
```

probe 覆盖点包括：

- `okhttp3.internal.ws.RealWebSocket.connect(okhttp3.OkHttpClient)`
- `okhttp3.WebSocketListener.onOpen/onMessage(String|ByteString)`
- `okhttp3.internal.ws.RealWebSocket.send(String|ByteString)`
- `java.net.Socket.connect(SocketAddress[, int])`
- `javax.net.ssl.SSLSocket.startHandshake()`

实测结论：

- WS hook 能安装成功，日志里可见 `hooked okhttp3.internal.ws.RealWebSocket.connect(...)`、`hooked okhttp3.WebSocketListener.onOpen/onMessage(...)`。
- 但进入直播间/滑动刷新后，没有实际命中 `WS.connect`、`WS.onOpen`、`WS.onMessage`、`SOCKET.connect`、`SSL.startHandshake`。
- 日志全文没有 `wss://`、`frontier` 字符串。
- 同时 TTNET/QueryFilter 侧稳定命中：`/webcast/room/enter*`、`/webcast/im/fetch/v2/history/`、`r_signature`、`x-tt-dt`、`klink_egdi`。

判定规则更新：

- 在当前抖音 v38.5.0 / Huawei P10 / Android 9 环境里，直播 IM 数据可能优先表现为 TTNET/Cronet 的 HTTP fetch/history 链路，而不是传统 OkHttp `wss://` WebSocket。
- `RealWebSocket/WebSocketListener` 只出现 hook 初始化、不出现运行事件时，不应直接判定抓取失败；若 `LivePlayActivity + /webcast/im/fetch/v2/history + r_signature` 已出现，应转向 HTTP fetch 与签名链路分析。
- 不要用 `frontier` 或 `wss://` 作为唯一成功指标；当前可用的成功指标是 `room/enter*`、`im/fetch/v2/history`、`QueryFilterEngine`、`TTNET.getResponseCode/getInputStream/getHeaderFields`。
- 若确实需要继续追长连接，下一步应 hook Cronet/native/QUIC/HTTP2 层或 Bytedance KMP websocket service，而不是只反复 hook OkHttp WebSocket。
- WebSocket 专项 probe 不要加入默认 enhanced 脚本长期运行；需要时短时加载即可，避免多脚本同时 attach 导致日志混乱或 ANR。

关键样例：

```text
/webcast/im/fetch/v2/history/?rid=<room_id>&room_id=<room_id>&...&r_signature=<sig>
```

这里的 `r_signature` 是下一阶段更值得优先逆向的目标。

## 2026-05-04 补充：r_signature/QueryFilter 调用栈探针结论

本轮在轻量 TTNET/URL Hook 已确认直播链路后，进一步挂载定点 `r_signature` / `QueryFilterEngine` / `Request$Builder.url` 调用栈 probe，成功触发直播刷新与进房请求。

关键日志：

```text
/tmp/douyin_r_signature_stack_probe_0504c.log
```

有效状态验证：

```text
mCurrentFocus=com.ss.android.ugc.aweme/.live.LivePlayActivity
```

样例计数：

```text
webcast/feed/live_tab: 16
preview/button_info: 8
webcast/room/enter: 50
webcast/im/fetch/v2: 8
QUERY.filterQuery: 44
QUERY.tryEncryptRequest: 42
RETRO.Builder.url.BEFORE: 97
r_signature=: 109
klink_egdi: 175
room_id=: 182
rid=: 8
STACK: 183
```

样例房间：

```text
room_id/rid = 7635850760042875684
anchor_id   = 3018621455177194
```

关键观察：

- `r_signature` 已在直播相关请求中出现，并常与 `luckydog_base`、`luckydog_token`、`luckydog_data`、`klink_egdi` 同现。
- 样例接口包括 `/webcast/privilege/subscribe/info/`、`/webcast/room/enter*`、`/webcast/im/fetch/v2/history/`。
- `QueryFilterEngine.filterQuery` / `tryEncryptRequest` 稳定命中，调用链路可见：
  ```text
  QueryFilterEngine.filterQuery/tryEncryptRequest
    -> X.1IK6.newSsCall
    -> X.1IK9.newSsCall
    -> com.bytedance.ttnet.retrofit.SsRetrofitClient.newSsCall
    -> com.bytedance.retrofit2.CallServerInterceptor.intercept
    -> com.bytedance.retrofit2.intercept.RealInterceptorChain.proceed
  ```
- 本轮 `QueryFilterEngine` 输出中可见 `queryEnc=false`、`bodyEnc=false`；因此 `r_signature` 不应先假定为 QueryFilterEngine 直接生成，可能由更上/下游拦截器追加。
- `Request$Builder.url` 的调用栈显示 URL 会被多层 interceptor 改写，重点类包括：
  ```text
  com.bytedance.ug.sdk.luckydog.tokenunion.interceptor.TokenUnionInterceptor.intercept
  com.bytedance.frameworks.baselib.netx.partner.NetworkPartnerGroup$PartnerInterceptor.intercept
  com.bytedance.frameworks.baselib.netx.partner.mutable.MutableRequest.LIZ
  com.bytedance.frameworks.baselib.network.http.retrofit.BaseSsInterceptor.processBeforeSendRequest
  com.bytedance.ttnet.retrofit.SsInterceptor.processBeforeSendRequest
  ```

下一步定位策略：

1. 对上述 Interceptor 做 before/after URL diff，找出哪一层首次插入 `r_signature`。
2. 静态检索 smali：
   ```bash
   ROOT=/opt/data/home/reverse-tools/douyin_decompiled/douyin_base
   rg -n "TokenUnionInterceptor|NetworkPartnerGroup|BaseSsInterceptor|SsInterceptor|r_signature|luckydog_base|tryEncryptRequest|filterQuery" \
     $ROOT/smali*
   ```
3. 优先枚举/Hook `com.bytedance.ug.sdk.luckydog.*`、`*TokenUnion*`、`*LuckyDog*`，观察 `luckydog_*` 与 `r_signature` 是否同阶段新增。
4. 用同一请求时间序列确认：
   ```text
   原始 Retrofit URL
     -> QueryFilterEngine.filterQuery / tryEncryptRequest
     -> TokenUnion/LuckyDog
     -> BaseSsInterceptor/SsInterceptor
     -> TTNET getResponseCode
   ```

### 2026-05-04 补充：r_signature 静态收敛到 RoomParamHandler

在当前 apktool/smali 目录中，直接搜索 `TokenUnionInterceptor`、`NetworkPartnerGroup$PartnerInterceptor`、`BaseSsInterceptor`、`SsInterceptor` 可能因混淆/拆包不稳定而无命中；不要继续只泛搜这些 Interceptor。`r_signature` 静态入口已收敛到：

```text
smali_classes15/com/bytedance/android/live/network/impl/handler/RoomParamHandler.smali
```

关键方法：

```smali
.method public static final handleGetRequest(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
```

该方法逻辑：

1. 读取 `LIVE_ROOM_SIGNATURE_PARAM` 配置。
2. 调用 `RoomSessionConfig->LIZ(Ljava/lang/String;)Z` 判断当前 path/scene 是否需要房间签名。
3. 从 URL 解析 `room_id`。
4. 通过静态字段 `RoomParamHandler->LIZIZ:LX/04eO;` 以 `room_id` 查询签名缓存。
5. 命中后返回追加 `r_signature` 的新 URL，否则返回原 URL。

同类中还存在直接 append 层：

```smali
const-string v0, "r_signature"
invoke-virtual {v1, v0, p1}, Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;
```

以及综合处理逻辑会先调用：

```smali
invoke-static {p2, p3}, Lcom/bytedance/android/live/network/impl/handler/RoomParamHandler;->handleGetRequest(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
```

若返回值变长且包含 `r_signature`，则直接返回该 URL。因此下一轮 Frida 定点 Hook 应优先选择：

```text
com.bytedance.android.live.network.impl.handler.RoomParamHandler.handleGetRequest(String,String)
android.net.Uri$Builder.appendQueryParameter(String,String)  # 仅 key == r_signature 时打印
com.bytedance.retrofit2.client.Request$Builder.url(String)
```

记录字段：before URL、path/scene 参数、after URL、是否新增 `r_signature`、调用栈。这样比继续泛搜 Interceptor 更快定位签名缓存来源和插入时机。

## 2026-05-04 补充：r_signature diff 日志动态确认插入层

本轮分析 `/tmp/douyin_r_signature_diff_0504b.log`，已把 `r_signature` 的 URL 插入层从“静态疑似 RoomParamHandler”推进到动态确认。

### 日志与样例

```text
/tmp/douyin_r_signature_diff_0504b.log
/tmp/douyin_r_signature_diff_0504b.analysis.txt
```

核心计数样例：

```text
ROOM.handleGetRequest: 24
URI.append.r_signature: 14
RETRO.Builder.url.BEFORE: 160
QUERY.filterQuery: 42
QUERY.tryEncryptRequest: 36
addedSig=true: 13
r_signature=: 133
/webcast/room/enter: 54
/webcast/im/fetch/v2: 57
STACK: 276
```

`r_signature` 样例规律：

- 本轮唯一签名值 2 个
- 长度均为 `112`
- 示例：

```text
ME4EELLwpQZgeoyJONWVaHw5GOAEOOLIQkbClBsPGRP-Tm2157KPN0Y90QmsyYeVoYf7d-LZNhidku_02Z0qA2-H0OpkhDFBDbPZVg7QBAABAAAA
```

### 动态确认的插入调用栈

`android.net.Uri$Builder.appendQueryParameter("r_signature", value)` 的调用栈确认：

```text
android.net.Uri$Builder.appendQueryParameter(Native Method)
  -> com.bytedance.android.live.network.impl.handler.RoomParamHandler.LIZ(SourceFile:33816596)
  -> com.bytedance.android.live.network.impl.handler.RoomParamHandler.handleGetRequest(SourceFile:33882178)
  -> com.bytedance.android.live.network.impl.handler.RoomParamHandler.handlePostRequest(SourceFile:84344855)
  -> X.0lX0.interceptForRoom(SourceFile:67371050)
  -> com.bytedance.android.live.network.impl.NetWorkService.post(SourceFile:67371013)
  -> X.0kNW.execute(SourceFile:590610)
  -> com.bytedance.retrofit2.CallServerInterceptor.executeCall(...)
  -> com.bytedance.retrofit2.intercept.RealInterceptorChain.proceed(...)
```

结论：`r_signature` 的 URL append 层已确认是：

```text
RoomParamHandler.handleGetRequest(String,String)
  -> RoomParamHandler.LIZ(...)
  -> Uri.Builder.appendQueryParameter("r_signature", value)
```

`QueryFilterEngine.filterQuery / tryEncryptRequest` 仍在同一网络链路中稳定出现，但不是本轮观察到的首次插入点；不要再把 QueryFilterEngine 当作 `r_signature` 直接生成层。

### 会追加 r_signature 的接口

本轮 `addedSig=true` 的 scene/path 包括：

```text
/webcast/im/fetch/v2/
/webcast/fansclub/homepage/
/webcast/growth/activity/common_banner/
/webcast/im/fetch/v2/history/
/webcast/ranklist/hour_entrance/
/webcast/gift/list/
/webcast/assets/effects/
/webcast/gift/effect_game/get/
/webcast/gift/play/indicator/
```

完整 URL 中 `r_signature` 命中较多的 path：

```text
/webcast/im/fetch/v2/
/webcast/fansclub/homepage/
/webcast/gift/play/indicator/
/webcast/gift/list/
/webcast/gift/effect_game/get/
/webcast/growth/activity/common_banner/
/webcast/room/leave/
/webcast/im/fetch/v2/history/
/webcast/ranklist/hour_entrance/
/webcast/assets/effects/
```

### 下一步定位规则更新

下一阶段不要继续泛搜 `TokenUnionInterceptor` / `NetworkPartnerGroup` / `BaseSsInterceptor` 这类网络 Interceptor；优先顺着 `RoomParamHandler` 内部追签名缓存来源。

重点静态入口：

```text
smali_classes15/com/bytedance/android/live/network/impl/handler/RoomParamHandler.smali
RoomParamHandler->LIZIZ:LX/04eO;
LIVE_ROOM_SIGNATURE_PARAM
RoomSessionConfig->LIZ(String):Z
```

推荐静态 grep：

```bash
ROOT=/opt/data/home/reverse-tools/douyin_decompiled/douyin_base
rg -n "RoomParamHandler|LIZIZ:LX/04eO|LX/04eO|LIVE_ROOM_SIGNATURE_PARAM|RoomSessionConfig|r_signature" \
  $ROOT/smali*
```

推荐下一轮 Frida 定点 Hook：

```text
com.bytedance.android.live.network.impl.handler.RoomParamHandler.handleGetRequest(String,String)
com.bytedance.android.live.network.impl.handler.RoomParamHandler.LIZ(...)
android.net.Uri$Builder.appendQueryParameter(String,String)  # 仅 key == r_signature 时打印
LX/04eO 相关 get/put/update 方法
/webcast/room/enter* 响应解析或 RoomSession 初始化相关方法
```

记录字段：

```text
room_id
path/scene
before URL
after URL
cache key
cache value / signature value
是否 addedSig
调用栈
```

核心判断：`r_signature` 当前更像按 `room_id` 查询缓存后追加；下一步应定位 `RoomParamHandler.LIZIZ` 这个 `room_id -> signature` 缓存的写入/更新来源，重点看进房接口 `/webcast/room/enter*`、`RoomSessionConfig`、直播 session 初始化和 JSON/Gson 反序列化中是否下发或生成签名。


## 2026-05-04 补充：r_signature 缓存写入源动态确认

本轮挂载 `RoomParamHandler.updateRoomSignature` / `RoomParamHandler.LIZIZ` 缓存 get/put / `Uri.Builder.appendQueryParameter("r_signature", ...)` 定点 Hook 后，已动态确认 `r_signature` 不是 `QueryFilterEngine` 直接生成，而是进房后写入房间签名缓存，后续请求按 `room_id` 读取缓存追加。

关键日志与摘要：

```text
/tmp/douyin_room_signature_source_0504.log
/tmp/douyin_room_signature_source_0504.summary.md
```

样例计数：

```text
ROOM.updateRoomSignature: 2
CACHE.put: 10
CACHE.get: 151
URI.append.r_signature: 26
ROOM.appendSig: 26
ROOM.handleGetRequest: 44
ROOM.handlePostRequest: 24
TTNET.getResponseCode: 29
/webcast/room/enter: 19
/webcast/im/fetch/v2: 63
```

样例 room/signature：

```text
room_id = 7635873514557573915
r_signature len = 112
ME4EEA975I8CvoV3nQHjEPQUQE0EOBzjXEUw9-2Khpw0Z4Y_6wV0XfPYAYroU2ezGuCdKBKhT6ARJI36p3uvEVIbFYivwybM5QRI6-tfBAABAAAA
```

动态确认链路：

```text
/webcast/room/enter* response / enter success message
  -> X.0ZBv.handleMsg(...)
  -> RoomParamHandler.updateRoomSignature(long roomId, String signature)
  -> RoomParamHandler.LIZIZ (X.04eO cache) put(roomId, signature)
  -> later live requests RoomParamHandler.handleGetRequest/handlePostRequest
  -> cache get(roomId)
  -> RoomParamHandler.LIZ(...)
  -> Uri.Builder.appendQueryParameter("r_signature", signature)
  -> TTNET/Cronet request
```

关键栈证据：

```text
RoomParamHandler.updateRoomSignature(Native Method)
  -> X.0ZBv.handleMsg(SourceFile:17301904)
  -> WeakHandler.handleMessage(...)
  -> Handler.dispatchMessage(...)
  -> ActivityThread.main(...)

Uri$Builder.appendQueryParameter(Native Method)
  -> RoomParamHandler.LIZ(SourceFile:33816596)
  -> RoomParamHandler.handleGetRequest(SourceFile:33882178)
  -> RoomParamHandler.handlePostRequest(SourceFile:84344855)
  -> X.0lX0.interceptForRoom(...)
  -> NetWorkService.post/get(...)
  -> Retrofit/TTNET
```

下一步应追 `X.0ZBv.handleMsg` 的消息来源：它很可能是 `/webcast/room/enter*` 响应或直播 session 初始化消息中携带的 room signature。优先静态/动态定位 `X/0ZBv.smali`、其构造参数、Handler message `what/obj`，以及 room enter 响应解析字段；不要再泛追 `TokenUnionInterceptor` 或 `QueryFilterEngine` 作为 `r_signature` 生成层。

## 2026-05-04 补充：r_signature 写入源静态追踪新定位点

在继续追 `X.0ZBv.handleMsg` 与 `RoomParamHandler.updateRoomSignature` 上游时，静态 grep 新增确认以下定位点：

```text
ROOT=/opt/data/home/reverse-tools/douyin_decompiled/douyin_base
```

### 关键静态命中

1. `X/0ZBv.smali` 主写入点：

```text
smali_classes15/X/0ZBv.smali:4649
invoke-static {v1, v2, v0}, Lcom/bytedance/android/live/network/impl/handler/RoomParamHandler;->updateRoomSignature(JLjava/lang/String;)V
```

这与动态栈 `X.0ZBv.handleMsg(SourceFile:17301904) -> RoomParamHandler.updateRoomSignature` 对齐，是当前追 room signature 来源的主入口。

2. `RoomModuleService` 创建 `LX/0ZBv`：

```text
smali_classes15/com/bytedance/android/livesdk/impl/RoomModuleService.smali:961
new-instance v0, LX/0ZBv;
```

后续应读取该构造调用周边，确认传入的 `IEnterRoomController$EnterListener`、Handler/Controller 对象和 room enter 生命周期关系。

3. `X/0ZBv.smali` 构造/字段：

```text
smali_classes15/X/0ZBv.smali:127
iput-object p1, p0, LX/0ZBv;->e:Lcom/bytedance/android/livesdk/chatroom/detail/IEnterRoomController$EnterListener;
```

`0ZBv` 持有 `IEnterRoomController$EnterListener` 字段 `e`，并在多个分支中读取该字段（如 around lines 3352 / 3928 / 4783），说明它处于 enter room controller 回调链路中。

4. 另一条 `updateRoomSignature` 调用点：

```text
smali_classes15/Y/AConsumerS28S0100100_21.smali:398
invoke-static {v1, v2, v4}, Lcom/bytedance/android/live/network/impl/handler/RoomParamHandler;->updateRoomSignature(JLjava/lang/String;)V
```

这说明除了 `X.0ZBv.handleMsg`，还有 Rx/Consumer 式链路会写入 room signature。后续要读取该类 `accept(...)` 分支，确认 `v1/v2` 的 room_id 与 `v4` 的 signature 来自哪个响应对象字段。

### 下一轮静态读取优先级

```text
read_file /opt/data/home/reverse-tools/douyin_decompiled/douyin_base/smali_classes15/X/0ZBv.smali offset=4560 limit=140
read_file /opt/data/home/reverse-tools/douyin_decompiled/douyin_base/smali_classes15/com/bytedance/android/livesdk/impl/RoomModuleService.smali offset=930 limit=80
read_file /opt/data/home/reverse-tools/douyin_decompiled/douyin_base/smali_classes15/Y/AConsumerS28S0100100_21.smali offset=330 limit=120
```

重点还原：

- `updateRoomSignature` 调用前 `v1/v2` 和 `v0/v4` 的来源；
- `Message.what` / `Message.obj`；
- room enter 响应对象类型；
- 可能的 `getRoomId()` / `getSignature()` / `room_signature` 字段；
- `0ZBv` 构造参数与 enter controller/listener 的绑定点。

### 下一轮 Frida 定点 probe

优先 Hook：

```text
X.0ZBv.handleMsg(...)
Y.AConsumerS28S0100100_21.accept(...)
RoomParamHandler.updateRoomSignature(long,String)
android.os.Handler.sendMessage(Message)
android.os.Message.obtain(...)
```

记录字段：

```text
Message.what
Message.obj.getClass()
Message.obj.toString()
room_id
signature
signature.length
调用栈
```

判定规则：`RoomParamHandler.updateRoomSignature` 已确认是缓存写入，不是签名生成；下一步的关键不是继续追 QueryFilter/Interceptor，而是定位 enter room response/message 中哪个字段携带了 signature。

## 2026-05-04 补充：0ZBv.handleMsg 与 EnterRoomExtra.rSignature 静态确认

继续读取 `X/0ZBv.smali`、`Y/AConsumerS0S0200200_21.smali`、`Y/AConsumerS28S0100100_21.smali`、`RoomModuleService.smali` 后，已静态确认 `RoomParamHandler.updateRoomSignature(roomId, signature)` 的签名参数来自 enter room response 的 `EnterRoomExtra.rSignature`，而不是本地实时计算。

### 关键文件

```text
ROOT=/opt/data/home/reverse-tools/douyin_decompiled/douyin_base
smali_classes15/X/0ZBv.smali
smali_classes15/Y/AConsumerS0S0200200_21.smali
smali_classes15/Y/AConsumerS28S0100100_21.smali
smali_classes15/com/bytedance/android/livesdk/impl/RoomModuleService.smali
smali_classes15/com/bytedance/android/livesdk/chatroom/room/core/task/EnterRoomTaskV1.smali
```

### `LX/0ZBv.handleMsg(Message)` 分支

`X/0ZBv.smali` 中 `handleMsg` 主要关注三类 `Message.what`：

```text
what == 0x20 -> 若未结束，调用 LX/0ZBv.LIZJ(false, true)
what == 0x27 -> Message.obj 是 EnterRoomInfoResult 时回调 onEnterRoomInfo(obj)
what == 0x4  -> 进入房间成功/失败主分支，Message.obj 可能是异常或 LX/0ZC5
```

`what == 0x4` 且 `Message.obj instanceof LX/0ZC5` 时，成功路径会读取：

```text
LX/0ZC5.LIZ   -> Room
LX/0ZC5.LIZIZ -> EnterRoomExtra
LX/0ZC5.LIZIZ.rSignature -> room signature
LX/0ZBv.f     -> roomId
```

然后在 `LIVE_ROOM_SIGNATURE_PARAM` 配置启用且 `rSignature` 非空时调用：

```text
RoomParamHandler.updateRoomSignature(LX/0ZBv.f, LX/0ZC5.LIZIZ.rSignature)
```

### `LX/0ZC5` 来源

`Y/AConsumerS0S0200200_21.smali` 中，`ResponseNoDataException.getResponse()` 返回的 `BaseResponse` 被处理为成功封装：

```text
new LX/0ZC5()
LX/0ZC5.LIZ   = Room
LX/0ZC5.LIZIZ = (EnterRoomExtra) BaseResponse.extra
Room.nowTime  = EnterRoomExtra.now / 1000
Room.enterLogId = BaseResponse.logId
Message.obj = LX/0ZC5
Handler.sendMessage(Message)
```

这说明正常 enter room 成功结果通过 `Message.obj = LX/0ZC5` 送入 `0ZBv.handleMsg`，其中 `rSignature` 来自服务端响应 `BaseResponse.extra`。

### re-enter 写入路径

`Y/AConsumerS28S0100100_21.smali::accept$1` 是另一条 `updateRoomSignature` 调用路径：

```text
p1 = BaseResponse
roomId = LX/0ZI3.d.getId()        # d 是 Room
signature = ((EnterRoomExtra) p1.extra).rSignature
if LIVE_ROOM_SIGNATURE_PARAM enabled and signature non-empty:
    RoomParamHandler.updateRoomSignature(roomId, signature)
```

因此 re-enter 成功也会用响应 `extra.rSignature` 更新 room signature 缓存。

### `0ZBv` 构造绑定点

`RoomModuleService.smali` 中创建 enter room controller：

```text
new LX/0ZBv(
  IEnterRoomController$EnterListener,
  long roomId,
  String,
  RoomEnterInfo,
  Room
)
```

`0ZBv` 构造中字段映射：

```text
0ZBv.e = EnterListener
0ZBv.f = roomId
0ZBv.h = RoomEnterInfo.getEnterArgs()
0ZBv.v = Room
0ZBv.M = roomId + "_" + RoomEnterInfo.LJJIII
```

`EnterRoomTaskV1.smali` 会复用预进入结果：若 `IEnterRoomController.getResult()` 是 `LX/0ZC5`，则记录 `pre enter room success on enter room, use pre enter room`，并从 `LX/0ZC5.LIZ` 继续取 `Room`。

### 静态结论

当前可把 r_signature 缓存链路写成：

```text
/webcast/room/enter* response
  -> BaseResponse.extra as EnterRoomExtra
  -> EnterRoomExtra.rSignature
  -> LX/0ZC5.LIZIZ.rSignature 或 re-enter BaseResponse.extra.rSignature
  -> RoomParamHandler.updateRoomSignature(roomId, rSignature)
  -> RoomParamHandler.LIZIZ cache[roomId] = rSignature
  -> 后续 RoomParamHandler.handleGetRequest/handlePostRequest 从 roomId 缓存取出并 append r_signature
```

### 后续动态 probe 要点

下一轮 Frida 不需要再泛追 `QueryFilterEngine`/Interceptor 作为生成层；应定点验证 message 和响应字段：

```text
LX.0ZBv.handleMsg(android.os.Message)
Y.AConsumerS0S0200200_21.accept(...)
Y.AConsumerS28S0100100_21.accept(...)
RoomParamHandler.updateRoomSignature(long,String)
android.os.Handler.sendMessage(Message)
```

记录：

```text
Message.what
Message.obj.getClass().getName()
LX/0ZC5.LIZ room id
LX/0ZC5.LIZIZ.rSignature / length
BaseResponse.logId
BaseResponse.extra class
EnterRoomExtra.rSignature / length
RoomParamHandler.updateRoomSignature 调用栈
```

可直接使用已编写的定点 probe：

```text
/tmp/douyin_room_message_signature_probe.js
```

运行示例：

```bash
export ADB_SERVER_SOCKET=tcp:10.0.2.2:5037
export ANDROID_ADB_SERVER_ADDRESS=10.0.2.2
export ANDROID_ADB_SERVER_PORT=5037
adb devices -l
python3 /tmp/run_douyin_capture.py \
  --attach \
  --js /tmp/douyin_room_message_signature_probe.js \
  --seconds 0 \
  --log /tmp/douyin_room_message_signature_probe_$(date +%m%d).log
```

该 probe 已通过 `node --check` 语法检查；会 Hook `X.0ZBv.handleMsg`、`WeakHandler.handleMessage`、`Handler.sendMessage`、`RoomParamHandler.updateRoomSignature`、`Y.AConsumerS0S0200200_21.accept`、`Y.AConsumerS28S0100100_21.accept/accept$1`，并尝试解包 `LX/0ZC5.LIZ/LIZIZ` 与 `BaseResponse.extra as EnterRoomExtra`。

判定规则：

```text
Message.what == 4
Message.obj.getClass() == X.0ZC5 / LX.0ZC5
LX/0ZC5.LIZIZ.rSignature == RoomParamHandler.updateRoomSignature 第二参
或 BaseResponse.extra.rSignature == updateRoomSignature 第二参
```

若 ADB server 可连通但 `adb devices` 为空，说明当前只是设备未恢复/未授权，不要继续改 probe；等设备恢复后直接运行上述命令复验。

### 2026-05-05 补充：EnterRoomExtra.rSignature 字段定义与响应映射已确认

静态阶段已通过 JADX 反编译 `classes58.dex` 确认 `EnterRoomExtra` 字段定义，摘要落地：

```text
/tmp/douyin_enter_room_rsignature_static_0505.md
/tmp/jadx_enter_extra_classes58/sources/com/bytedance/android/livesdk/chatroom/model/EnterRoomExtra.java
```

关键定义：

```java
@ProtoMessage("webcast.api.room.EnterRoomResponse.EnterRoomExtra")
public final class EnterRoomExtra extends Extra implements InterfaceC21920DuG {
    @IgnoreProtoFieldCheck
    @SerializedName("signature")
    public String rSignature;
}
```

Proto/Flex 元信息同时确认：

```java
new FieldMeta("signature", 7, stringType, null);
new Type.Message("webcast.api.room.EnterRoomResponse.EnterRoomExtra");
```

因此服务端响应字段名是 `signature`，Proto field number 是 `7`，Java 字段名是 `rSignature`；客户端后续追加到 URL 时参数名才变成 `r_signature`。

`/webcast/room/enter/` 接口签名：

```text
RoomManagementRetrofitApi.enterRoom(...)
@POST("/webcast/room/enter/")
@FormUrlEncoded
@PbRequest("room")
Observable<BaseResponse<Room, EnterRoomExtra>>
```

两条写入缓存路径已静态确认：

1. `X/0ZBv.smali` 主 enter 成功路径：`Message.what == 4` 且 `Message.obj instanceof LX/0ZC5` 时，读取 `LX/0ZC5.LIZIZ.rSignature` 并调用 `RoomParamHandler.updateRoomSignature(roomId, signature)`。
2. `Y/AConsumerS28S0100100_21.smali` re-enter 路径：`BaseResponse.extra` cast 为 `EnterRoomExtra`，读取 `rSignature`，以当前 `Room.getId()` 调用 `updateRoomSignature`。

最终模型：

```text
/webcast/room/enter/ response
  -> BaseResponse.extra as EnterRoomExtra
  -> response.extra.signature (proto field 7)
  -> Java EnterRoomExtra.rSignature
  -> RoomParamHandler.updateRoomSignature(roomId, rSignature)
  -> RoomParamHandler.LIZIZ cache[roomId] = rSignature
  -> 后续 handleGetRequest/handlePostRequest
  -> Uri.Builder.appendQueryParameter("r_signature", rSignature)
```

动态 probe `/tmp/douyin_room_message_signature_probe.js` 已通过 `node --check`；`/tmp/run_douyin_capture.py` 与 `/tmp/extract_douyin_capture.py` 已通过 `py_compile`。ADB 恢复后直接运行该 probe，验证 `0ZC5.LIZIZ.rSignature` 或 `BaseResponse.extra.rSignature` 等于 `updateRoomSignature` 第二参即可闭环。


### 2026-05-05 补充：无 ADB 时继续追 EnterRoomExtra 字段定义的策略

在无 ADB 的静态阶段，已经可以通过 `RoomManagementRetrofitApi.enterRoom`、`Y/AConsumerS0S0200200_21`、`X/0ZBv.handleMsg` 确认：

```text
POST /webcast/room/enter/
  -> BaseResponse.extra
  -> cast com.bytedance.android.livesdk.chatroom.model.EnterRoomExtra
  -> EnterRoomExtra.rSignature
  -> LX/0ZC5.LIZIZ.rSignature
  -> RoomParamHandler.updateRoomSignature(roomId, rSignature)
```

关键证据：

- `RoomManagementRetrofitApi.smali` 的 `enterRoom(...)` 返回 `Observable<BaseResponse<Room, EnterRoomExtra>>`，接口是 `POST /webcast/room/enter/`。
- `Y/AConsumerS0S0200200_21.smali` 把 `BaseResponse.extra` cast 成 `EnterRoomExtra`，写入 `LX/0ZC5.LIZIZ`，再作为 `Message.obj` 发送给 Handler。
- `X/0ZBv.smali` 在 `Message.what == 4` 且 `Message.obj instanceof LX/0ZC5` 的成功路径中读取 `LX/0ZC5.LIZIZ.rSignature`，非空时调用 `RoomParamHandler.updateRoomSignature(LX/0ZBv.f, rSignature)`。

坑点：当前 apktool/smali 目录里直接搜索 `*EnterRoomExtra*`、`.field .*rSignature`、`value = "r_signature"` / `"room_signature"` 可能找不到类定义，只能找到引用点。这通常说明模型定义可能在未解出的 split/插件/其他 dex，或 apktool 当前目录不完整；不要因此推翻 `extra.rSignature` 链路。

无 ADB 时的下一步静态策略：

```bash
ROOT=/opt/data/home/reverse-tools/douyin_decompiled/douyin_base
rg -n "EnterRoomExtra|rSignature|room_signature|r_signature|BaseResponse;->extra|LX/0ZC5" $ROOT/smali*
```

若 apktool 目录无字段定义，应改搜原始 APK/DEX 字符串池或 jadx 输出：

```python
import zipfile
apk='/tmp/douyin.apk'
needles=[b'EnterRoomExtra', b'rSignature', b'r_signature', b'room_signature']
with zipfile.ZipFile(apk) as z:
    for n in z.namelist():
        if n.endswith('.dex'):
            data=z.read(n)
            hits=[x.decode() for x in needles if x in data]
            if hits:
                print(n, hits)
```

继续静态补全优先读取：

```text
smali_classes15/Y/AConsumerS28S0100100_21.smali around 300-410   # re-enter updateRoomSignature 路径
smali_classes15/X/0ZC5.smali                                    # Room + EnterRoomExtra 封装结构
smali_classes15/com/bytedance/android/livesdk/impl/RoomModuleService.smali around 930-990
jadx --single-class com.bytedance.android.livesdk.chatroom.model.EnterRoomExtra <命中的 dex>
```

判定规则：`EnterRoomExtra` 字段定义未找到时，下一步是扩大到原始 dex/jadx/split，而不是回头泛追 `QueryFilterEngine`、`TokenUnionInterceptor` 或 `RopaEncrypt` 作为 `r_signature` 生成层。当前更可靠的模型是：`r_signature` 由 room enter 响应 extra 下发，App 只做 room_id 缓存和后续 URL append。
