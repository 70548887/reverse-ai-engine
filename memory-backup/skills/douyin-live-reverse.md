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

## 下一步

1. **Frida Hook RopaEncrypt** — 实时抓 SO 层输入输出（最快验证路径）
2. **classes12 完整反编译** — 找 OkHttp Interceptor → RopaEncrypt 调用链
3. **抓包验证 SO headers** — 确认 x-tt-encrypt-queries 实际值格式