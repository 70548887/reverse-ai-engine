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

### 2026-05-02 补充：推荐流自动滑动找直播卡片的安全姿势

在推荐流里自动滑动找直播卡片时，起滑点很重要。若从右侧互动栏、底部导航、评论按钮附近滑动，容易误触评论/关注/直播广场并进入登录页，例如登录页文案可能是：

```text
登录后即可评论
登录发现更多精彩
com.ss.android.ugc.aweme.account.business.login.DYLoginActivity
```

用户明确要求“不要进入直播广场，而是在推荐页面滑动寻找推荐的直播间入口”时，按推荐流路径执行：先关闭登录页/侧边抽屉并确认顶部「推荐」高亮、底部「首页」选中；不要点击顶部「直播/播」或侧边菜单「直播广场」。推荐流直播预览的可见特征包括左下粉色「直播中」标签、主播昵称（如 `@雾南枝（逆水寒手游）`）、直播分类/标题；命中后点击屏幕中部预览区域（约 `x=540,y=900`）进入。进入成功可用 Activity 验证：`com.ss.android.ugc.aweme.live.LivePlayActivity`；截图短时间黑屏/加载中并不一定失败。

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

## 下一步

1. **spawn 注入 Frida Hook** — 先 Hook OkHttp/WS/Cipher，确认 Java 层可见流量
2. **Hook RopaEncrypt / QueryFilterEngine / WebSocketTask** — 实时抓输入输出（最快验证路径）
3. **抓包验证 SO headers** — 确认 x-tt-encrypt-queries 实际值格式