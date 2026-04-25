---
name: zhihu-signature-reverse
description: 知乎 x-zse-96 VM-based 签名纯算逆向完整工作流 — 从 JSVMP 识别到算法提取、验证
triggers:
  - 知乎 x-zse-96 签名逆向
  - 小红书 x-s 签名逆向
  - 任何 VM-based / JSVMP 混淆签名
  - SM4 CBC + 位混洗签名
---

# 知乎 x-zse-96 签名逆向工作流

## 任务信息

| 项目 | 值 |
|------|---|
| 目标 | 知乎 APP / PC H5 的 x-zse-96 签名头 |
| 耗时 | ~4.5 小时（首次逆向） |
| 成本 | ~¥24（Claude Sonnet 4） |
| 难度 | ★★★★★（JSVMP + SM4 + 多层混淆） |

---

## 核心策略

### 通用原则：绕过 VM 黑盒，而非读懂 VM

VM-based 签名（JSVMP / 字节码混淆）的核心问题：**阅读字节码无意义**，但可以把它当黑盒驱动。

**标准工作流：**

```
1. 定位入口（list_network_requests + get_request_initiator）
2. 发现 JSVMP 特征（function l() / l.prototype.O）
3. 决定路线：纯算 or VM 代理
   └─ 优先纯算：如果参数少且可枚举，走纯算（可移植、无运行时依赖）
   └─ 次选 VM 代理：如果纯算代价太高，保留 JSVMP 调用（依赖原始 JS 文件）
4. 插桩捕获 I/O：patch __g.r / __g.x，在 Node.js 模拟调用
5. 逆向编码层：用 bit-delta 方法推导 encode3 / shuffle 公式
6. 提取运行时常量：VM 运行时会修改 h.zk 等值，必须从运行后提取
7. 验证 + 上线
```

---

## 知乎 x-zse-96 签名（已知结果，直接可用）

### 快速使用

```javascript
// zhihu_sign_pure.js — 纯算法实现，无 JSVMP
const { sign } = require('./zhihu_sign_pure.js');

const xZse96 = sign('/api/v4/question/12345', {
  d_c0: '"AfCKjr-Wpxxx"',
  authId: '1618620392001'
});

console.log(xZse96); // "2.0_xxxxxxxxxxxx..."
```

### 签名算法（10步）

> 详见 references/algorithm.md

| 步骤 | 操作 | 关键点 |
|------|------|-------|
| 1 | 构造 source 字符串 | `"101_3_3.0" + "+" + urlPath + ...` |
| 2 | MD5 → 32位 hex | 标准 MD5 |
| 3 | 构造 block[16] | block[0]=randByte, block[1]=0x15, block[2~15]=md5 XOR K |
| 4 | SM4_ENC(block) → IV | ⚠️ ZK 必须从运行后提取，源码中的值是错的！ |
| 5 | 构造 plaintext[32] | md5hex[14~31] + [0x0E]×14 |
| 6 | SM4_CBC(plaintext, IV) → cipher | C1=ENC(P[0~15]⊕IV), C2=ENC(P[16~31]⊕C1) |
| 7 | X = reverse(cipher) ++ reverse(IV) | 48字节，前后32+16 |
| 8 | encode3(X) — 位混洗 | 16组×3字节，每组独立混洗公式 |
| 9 | XOR CONST[12] | 固定常量 `[232,0,0,2,128,192,0,8,14,0,0,0] × 4` |
| 10 | 自定义 Base64（ALPHA） | `"6fpLRqJO8M/c3jnYxFkUVC4ZIG12SiH=5v0mXDazWBTsuw7QetbKdoPyAl+hN9rgE"` |

### ⚠️ 必坑指南

| 坑 | 症状 | 解决方案 |
|----|------|---------|
| ZK 值被 JSVMP 篡改 | 50次测试全部失败 | 从运行后 `__g._h.zk` 提取，非源码初始值 |
| CONST 被误认为动态 | 不同 URL 测试 baseline 不同 | 实为固定常量，多 URL 测试验证 |
| 以为输出是 IV++C1++C2 | base64 解码不符预期 | 实际是 `reverse(cipher) ++ reverse(IV)` + encode3 |
| 插桩后 JSVMP 不运行 | patch 后 sign() 返回 undefined | 确保 `(new l).O(_BYTECODE, 0, _STRINGS)` 先执行 |

---

## JMCP 工具使用（jsr-reverse）

> 工具集：https://github.com/715494637/reverse-skill/

### 定位签名入口

```javascript
// 1. 抓取页面请求，找到 x-zse-96
await list_network_requests({ url: 'https://www.zhihu.com/api/v4/xxx' })

// 2. 追踪调用链，定位到 JSVMP 入口
await get_request_initiator({ request_id: 'xxx' })

// 3. 在 sign 关键词打断点
await set_breakpoint_on_text({ text: 'sign' })

// 4. 在断点处注入脚本捕获 I/O
await evaluate_script({
  script: `
    __sign_r = __g.r;
    __g.r = function(block) {
      const iv = __sign_r(block);
      console.log('IV:', Buffer.from(iv).toString('hex'));
      return iv;
    };
  `
})

// 5. 提取 JS 源码
await get_script_source({ url: 'https://zhstatic.zhihu.com/assets/zhihu_sign.js' })
```

---

## 验证脚本参考

> 详见 references/test-scripts.md

- `test_layout.js` — 确定 cipher/IV 输出位置（置零法）
- `test_layout2.js` — 推导 encode3 逆公式（bit-delta 法）
- `test_randbyte2.js` — rand_byte LOOKUP 表构建
- `test_third.js` — CONST 固定性验证
- `test_ivmap2.js` — IV bit → output 映射验证

---

## 接口校验结论

| 情况 | 响应 |
|------|------|
| 无 x-zse-96 头 | 403 |
| 有头但内容随机 | 200（GET 不校验密码学内容） |
| 有头且内容正确 | 200 |

签名头的存在性和格式是必须的，GET 接口不校验内容，POST 写操作通常更严。

---

## 相似任务迁移

本案例的方法论可迁移到其他 VM-based 签名：

1. **小红书 x-s / x-b3**：RPS 签名，Webpack 模块拼接，插桩法可解
2. **Airbnb cna**：SM4 类签名，同理可套用
3. **任何 JSVMP**：用插桩法提取 SM4 / AES 的 I/O，然后在 Python/Go 重写
