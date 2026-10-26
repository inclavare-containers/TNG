# TNG 隧道协议与远程证明握手

本文面向开发者与希望深入理解 TNG 的读者，描述两个 TNG 端点之间建立互信并交换加密流量的协议细节：握手如何与远程证明结合、双方交换哪些消息、以及外层 HTTP 的线格式。配置字段与部署方法不在本文范围内：配置参考见[参数手册](configuration.md)，远程证明的配置细节见[远程证明配置](remote_attestation.md)，整体概念见[核心概念与工作流程](architecture.md)。

本文覆盖 TNG 的两条隧道协议：**ohttp**（按 HTTP 请求加密）与 **rats-tls**（按 TCP 连接加密，TNG 的默认协议）。两章共用一套形式化记号（见[时间点与消息记号](#时间点与消息记号)）。

术语约定：本文用 **TNG Ingress**（隧道入口，业务流量进入的一端）与 **TNG Egress**（隧道出口，业务流量发出的一端）称呼两个端点。在一次单向证明中，被证明的一端是 RFC 9334 意义上的 Attester，验证的一端是 Verifier（其 Relying Party 角色由 TNG 自己充当）。

## 术语速查

| 术语 | 含义 |
|---|---|
| AA (Attestation Agent) | 运行在 TEE 内的代理，采集硬件度量并生成 Evidence |
| AS (Attestation Service) | 验证 Evidence 的后端服务，签发 Attestation Result；可以是外部进程（Trustee）或 TNG 内置（`as_type: "builtin"`） |
| Attester | 生成 Evidence 的一端（RFC 9334 角色） |
| Verifier | 验证 Evidence 的一端（RFC 9334 角色） |
| Evidence | Attester 产出的、描述其软硬件环境的密码学证明材料 |
| Attestation Result | AS 验证 Evidence 后签发的结果令牌，TNG 中为 JWT |
| 背调模型 (Background-Check) | RFC 9334 模型之一：Attester 把 Evidence 直接交给 Verifier 一侧，由它请 AS 验证 |
| 护照模型 (Passport) | RFC 9334 模型之一：Attester 预先向 AS 换取 Attestation Result，之后把令牌当作「护照」出示 |
| HPKE | RFC 9180 混合公钥加密，ohttp 封装的密码学基础 |
| KeyConfig | RFC 9458 定义的 HPKE 公钥配置，egress 分发给 ingress 用于加密 |
| 元数据帧 (metadata frame) | TNG 在 ohttp 密文前附加的一段自定义元数据（见[加密请求的封装](#加密请求的封装)） |
| DICE 证书 (DiceCert) | 被证明端自签的 X.509 证书，自定义扩展携带 RA 证明材料，随 TLS 握手出示（见[DICE 证书](#dice-证书证明材料的载体)） |
| ALPN | TLS 应用层协议协商，TNG 用它在 `rats-tls`（非多路复用）与 `h2`（多路复用）间选择数据面 |

## OHTTP 隧道协议

### 角色与协议分层

ohttp 隧道把 RFC 9458 的三个角色压缩为两个端点：TNG Ingress 同时充当协议中的 oblivious client（封装请求、解封响应），TNG Egress 同时充当 oblivious gateway 与 resource server（解封请求、转发给真实上游、封装响应）。协议约束落在 ingress 与 egress 之间这一跳：这一跳上的消息是标准 OHTTP 封装，中间的七层负载均衡器或 relay 只能看到固定形状的外层 POST，无法解密或改写业务内容。

外层传输是普通 HTTP（HTTP/1.1 或 HTTP/2，依客户端协商），保持协议外观为 HTTP 以兼容七层网关；ingress 侧可选配置 `ohttp.tls` 将外层 POST 升级为 HTTPS。与 rats-tls 的连接级加密不同，ohttp 以**单个 HTTP 请求**为加密粒度：每个请求独立做一次 HPKE 封装，不依赖此前任何会话状态，因此请求本身是 0-RTT 的，天然适配无状态集群与任意七层负载均衡。

先看一张不含远程证明的总览图，建立整体印象（图中的 `/tng/...` 是 `x-tng-ohttp-api` 请求头的取值，不是 URL 路径，见下一节）：

```mermaid
sequenceDiagram
    autonumber
    participant C as App（明文 HTTP）
    participant I as TNG Ingress（ohttp client）
    participant E as TNG Egress（ohttp server）
    participant S as Server（明文 HTTP）
    Note over I,E: 获取密钥配置（缓存至 time(CX_a)，默认 300s 刷新）
    I->>E: POST 外层路径（x-tng-ohttp-api: /tng/key-config）
    E->>I: HpkeKeyConfig | time(CX_a)
    loop 每个 HTTP 请求（0-RTT）
        C->>I: HTTP 请求（明文）
        Note over I: body = [u32 长度][Metadata{NoAuth, KeyConfigHint}]<br/>+ Enc(HTTP Request)
        Note right of I: time(OP2_r)
        I->>E: POST 外层路径（x-tng-ohttp-api: /tng/tunnel,<br/>Content-Type: message/ohttp-chunked-req）
        Note over E: 按 KeyConfigHint 定位密钥，<br/>解密 Metadata 与请求体，转发明文
        E->>S: HTTP 请求（明文）
        S->>E: HTTP 响应
        E-->>I: Enc(HTTP Response)<br/>（Content-Type: message/ohttp-chunked-res，流式）
        I-->>C: HTTP 响应（明文）
    end
    Note over I,E: 422（密钥不存在或已过期）→ 客户端废弃缓存并重新获取 KeyConfig
```

### 外层请求路由

egress 不按 URL 路径区分 API：它对外层路径不做匹配，而是把所有请求交给同一个处理器，按 **`x-tng-ohttp-api` 请求头**的取值分发。头取值是形如 `/tng/key-config` 的路径样式常量，但它只是 API 选择器，与请求的实际 URL 无关。不带该头的请求被拒绝（403，`RejectNonTngRequest`）。

ingress 把所有外层请求 POST 到**同一个 URL**（`base_url`）：外层路径来自 `path_rewrites` 的正则改写，或 `path_default`（默认 `root` 即 `/`，可设为 `original` 跟随业务请求路径）。key-config 获取、隧道请求、RA 转发全部走这个 URL，仅靠 `x-tng-ohttp-api` 头区分。

| `x-tng-ohttp-api` 头取值 | 客户端实际行为 | 请求体 | 说明 |
|---|---|---|---|
| `/tng/key-config` | POST（JSON） | `KeyConfigRequest` | 获取密钥配置，[见下节](#密钥配置分发) |
| `/tng/tunnel` | POST | 元数据帧 + ohttp 密文 | 加密的业务请求，[见封装一节](#加密请求的封装) |
| `/tng/background-check/challenge` | GET | 无 | 经 egress 向 AS 取挑战值（仅 Server 验 Client + 背调模型） |
| `/tng/background-check/verify` | POST（JSON） | `AttestationVerifyRequest` | 经 egress 向 AS 提交 Evidence 换取 Attestation Result（同上） |

egress 侧不校验 HTTP 方法，上表是 ingress 客户端的实际行为。前两个头之外还有一个运维用的 REST 控制面（`/status/egress/<id>/ohttp/keys` 等），与数据面协议无关，见[控制接口](configuration.md#control-interface)。

### 密钥配置分发

ingress 在加密第一个请求之前，先向 egress 请求 KeyConfig（1-RTT，结果缓存）。请求与响应均为 JSON。

请求体 `KeyConfigRequest`：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `attestation_request` | object | — | 省略则不请求服务端证明（`attestation_info` 返回 null）。取值为按 `model` 标记的枚举之一，见下 |

`attestation_request` 的两个变体：

```json
{ "attestation_request": { "model": "passport" } }
```

```json
{ "attestation_request": { "model": "background_check", "challenge_token": "<从 AS 获取的挑战 JWT>" } }
```

响应体 `KeyConfigResponse`：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `hpke_key_config.expire_timestamp` | integer | — | 配置过期时间（Unix 秒），过期后 egress 不再接受该密钥加密的请求 |
| `hpke_key_config.encoded_key_config_list` | string | — | RFC 9458 §3.1 定义的 KeyConfig 编码列表，整体 base64；当前实现恒为一把密钥 |
| `attestation_info` | object / null | null | 服务端证明信息，按 `model` 标记的二选一，见下 |

`attestation_info` 的两个变体：

```json
{ "model": "passport", "attestation_result": "<egress 自己的 Attestation Result JWT>", "as_provider": "coco" }
```

```json
{ "model": "background_check", "evidence": "<egress 生成的 Evidence JSON>", "aa_provider": "coco" }
```

`as_provider` / `aa_provider` 标明令牌/证据属于哪个提供方（取值同 RA 配置的 provider，当前有 `coco`、`ita`），供对端选择对应的验证栈；对老版本客户端可省略。

两个模型互斥：请求 `passport` 而服务端配置为背调（或反之）会返回错误。服务端未配置 RA 时 `attestation_info` 为 null。

**密钥生命周期与轮换。** egress 的 HPKE 私钥有三种来源（`ohttp.key.source`）：`self_generated`（默认，自动轮换，`rotation_interval` 默认 300 秒）、`file`（外部文件加载，inotify 热更新）、`peer_shared`（集群内经 Serf gossip 协议共享密钥，适配无状态集群）。密钥有 Pending/Active/Stale 三个状态：轮换间隔到达后当前密钥转 Stale（仍可解密）并生成新的 Active 密钥，再过一个间隔后彻底过期。`expire_timestamp` 对应密钥的最终过期时刻。

ingress 侧缓存密钥配置，其有效期取「密钥 `expire_timestamp`、Attestation Result 的 JWT `exp`」二者的最小值，到期自动后台刷新（默认 300 秒周期，配置了 `attest` 时跟随证明刷新策略）。egress 收到用已不存在的密钥加密的请求时返回 422（遵循 RFC 9458 §6.4 的 key-config 不匹配语义），ingress 据此立刻废弃缓存并重新获取。

### 加密请求的封装

`x-tng-ohttp-api: /tng/tunnel` 的请求体不是 JSON，而是三段拼接的二进制：

```text
[4 字节大端长度 N][N 字节 prost 编码的 Metadata][ohttp-chunked 加密后的请求体（可流式）]
```

元数据部分定义在 `tng/src/tunnel/ohttp/protocol/metadata.proto`：

```proto
message Metadata {
  oneof client_auth {
    NoAuth no_auth = 1;
    AttestedPublicKey attested_public_key = 2;
  }
  ServerKeyConfigHint key_config_hint = 3;
}

message NoAuth {}

message AttestedPublicKey {
  string attestation_result = 1;  // 客户端的 Attestation Result（JWT）
  bytes pk_s = 2;                 // 客户端 HPKE 发送方认证公钥
  string as_provider = 3;         // 签发 attestation_result 的 AS 提供方
}

message ServerKeyConfigHint {
  bytes public_key = 1;           // 服务端 HPKE 公钥原文，用于服务端定位密钥
}
```

三个要点：

- `key_config_hint.public_key` 是**服务端** HPKE 公钥的原始字节，在两种客户端认证模式下都携带。RFC 9458 的 KeyConfig 只有 1 字节 key id，在大规模部署下不够唯一，因此 egress 直接按公钥原文查找对应私钥。缺失时请求被拒绝（400）。
- `client_auth` 二选一：`NoAuth`（ingress 不做证明，匿名客户端）或 `AttestedPublicKey`（ingress 要向 egress 证明自己，见 [Server 验 Client](#server-验-client)）。选择不是显式配置项：ingress 配置了 `attest` 即自动携带 `AttestedPublicKey`，egress 配置了 `verify` 即要求之，二者不匹配会被拒绝。wasm 版 ingress 受平台所限始终是 `NoAuth`。
- 元数据帧总长度上限 32 MiB（`Attestation Result` 令牌可能很大，放在 body 里而不是 HTTP 头，就是为了绕开头大小限制）。超限返回 413。

密文体采用分块流式封装（chunked-ohttp 风格，由 TNG 使用的 ohttp fork 定义）：明文按最多 16 KiB 分块，每块独立 AEAD 加密，前缀变长整数编码的长度；流结束时追加一个长度为零的「终止块」并以 `final` 作为附加认证数据。外层 `Content-Type` 为 `message/ohttp-chunked-req`，egress 强制校验，不符返回 400。响应同理：HTTP 200，`Content-Type: message/ohttp-chunked-res`，密文流式返回，ingress 边收边解密（对 SSE 等流式响应同样适用）。未压缩该内容类型。

### RA 模型选择

「Client 验 Server」与「Server 验 Client」两个方向各自独立选择背调或护照模型，由 `attest`/`verify` 配置块的 `model` 字段控制（省略时默认 `background_check`）。

| 维度 | 背调模型（默认） | 护照模型 |
|---|---|---|
| Evidence 在哪验证 | Verifier 一侧收到 Evidence 后请 AS 验证 | Attester 预先请 AS 验证，换取令牌 |
| 谁与 AS 交互 | 验证方（Verifier 侧的 TNG） | 被证明方（Attester 侧的 TNG） |
| 每次取新配置的往返 | 需要（携带挑战值取新鲜 Evidence） | 不需要（令牌随配置分发） |
| 新鲜度来源 | AS 挑战 JWT（短有效期） | 令牌自身的 exp |
| AS 位置约束 | AS 需被验证方访问到（`as_type: "builtin"` 时进程内验证） | AS 需被被证明方访问到 |
| 典型场景 | 验证方与 AS 网络可达、要求强新鲜度 | 被证明方离 AS 近、验证方网络隔离 |

两个补充说明：

- `as_type: "builtin"`（内置 AS）不是第三种模型，而是背调模型 verify 侧的一个 AS 实现选择：验证逻辑直接链接进 TNG 进程内执行，无需部署外部 AS。护照模型的 attest 侧不支持 builtin 转换器。
- Server 验 Client 方向若用背调模型，AS 必须能被 egress 访问；在无状态集群里 ingress 无法预先假设自己会连到哪个 egress，因此该方向提供了「经 egress 转发」的变体（见下）。

### 时间点与消息记号

RA 各节的时序图沿用 RFC 9334 附录 A 事件表对应的形式化记号：

- `time(XX_y)` 表示事件 XX 的发生时间，`y` 为关联方（`a`: Attester、`v`: Verifier、`r`: Relying Party）。
- `JWT{Nonce, time(NS_v), time(NX_v)}` 这类写法描述消息携带的材料与时效字段；`|` 分隔同一条消息中的并列材料；`Enc(x)` 表示 HPKE 加密后的 `x`。
- 图中协议对象统一用 CamelCase 记号，与正文线格式字段名的对应：`Challenge` 即挑战令牌 `JWT{Nonce, time(NS_v), time(NX_v)}`（线格式字段名 `challenge_token`）；`Claims` 是被证明方绑定进 Evidence 的声明集合，AS 验证后将其回写进令牌（线格式字段名 `runtime_data`），「Claims 覆盖 {…}」表示集合包含（期望的每个键值都出现在令牌里）；`Evidence{hash(…)}` 表示 Evidence 经 TEE 报告数据区绑定了括号内 Claims 的哈希（AA 对 Claims 的规范 JSON 整体哈希），Claims 明文随 Evidence 一起传输；`skS`/`pkS` 是 Server 验 Client 方向中客户端的 HPKE 发送方认证密钥对；`HpkeKeyConfig` 即密钥配置对象（线格式字段名 `hpke_key_config`）。

图中事件与实现的对应：

| 事件 | 含义 | 实现对应 |
|---|---|---|
| NS / NR | 挑战值发出 / 被接收 | 挑战 JWT 的签发（`iat`）与到达 |
| NX | 挑战值过期 | 挑战 JWT 的 `exp` |
| EG / ER | Evidence 生成 / 被接收 | AA 采集硬件度量并绑定 claims / 对端收到 Evidence |
| RG / RX | Attestation Result 生成 / 过期 | AS 签发令牌 / 令牌 `exp` |
| RA | Attestation Result 被接受 | 验证方验签与 claims 覆盖检查通过 |
| CX | KeyConfig 过期 | `hpke_key_config.expire_timestamp` |
| OP2 | 基于验证结果的密码学操作 | 验证通过后执行 HPKE 加密/解密的时刻 |

图中消息以形式化记号表示内容，具体线格式（JSON 字段名、proto 结构、Content-Type）见[密钥配置分发](#密钥配置分发)与[加密请求的封装](#加密请求的封装)两节。

### Client 验 Server

#### 背调模型（默认）

ingress（Relying Party）主动向 AS 要挑战值，用它向 egress（Attester）换取新鲜的 Evidence，再请 AS 验证。每一次 key-config 获取都换新 Evidence，新鲜度由挑战 JWT 保证：

```mermaid
sequenceDiagram
    autonumber
    participant V as AS (Verifier)
    participant RP as TNG Ingress (Relying Party)
    participant AT as TNG Egress (Attester)
    Note right of AT: 生成 HPKE 密钥对，<br/>定期轮换（默认 300s）
    alt 1. 获取挑战值（新鲜度来源）
        RP->>V: 请求挑战值
        Note right of V: time(NS_v)
        V-->>RP: JWT{Nonce, time(NS_v), time(NX_v)}
        Note right of RP: time(NR_r)
    end
    alt 2. 请求携带挑战的密钥配置
        RP->>AT: JWT{Nonce, time(NS_v), time(NX_v)}
        Note right of AT: time(EG_a)
        Note right of AT: Claims{Challenge, HpkeKeyConfig}<br/>经 AA 哈希进 TEE 报告
        AT-->>RP: HpkeKeyConfig | time(CX_a) |<br/>Evidence{hash(Challenge, HpkeKeyConfig)}
        Note right of RP: time(ER_r)
    end
    alt 3. 换取并验证 Attestation Result
        RP->>V: Evidence{hash(Challenge, HpkeKeyConfig)} |<br/>Claims{Challenge, HpkeKeyConfig}
        Note right of V: time(RG_v)
        V-->>RP: Attestation Result{time(RG_v), time(RX_v),<br/>Claims 覆盖 {Challenge, HpkeKeyConfig}}
        Note right of RP: time(RA_r)：验签 + exp + Claims 覆盖检查
    end
    alt 4. 加密请求（0-RTT）
        Note right of RP: time(OP2_r)
        RP->>AT: Enc(HTTP Request)
        AT-->>RP: Enc(HTTP Response)
        Note right of RP: 缓存有效期 = min(time(CX_a), time(RX_v))
    end
```

第 3 步中，若 ingress 配置了 `as_type: "builtin"`，AS 的角色在 ingress 进程内完成（图中的 AS 参与者变为进程内组件），消息语义不变。

#### 护照模型

egress 提前为自己换好 Attestation Result 并随 KeyConfig 一起分发，ingress 只验令牌，不再接触 Evidence：

```mermaid
sequenceDiagram
    autonumber
    participant RP as TNG Ingress (Relying Party)
    participant AT as TNG Egress (Attester)
    participant V as AS (Verifier)
    Note right of AT: 生成 HPKE 密钥对
    alt 1. egress 提前换取 Attestation Result（按 refresh_interval 刷新，默认 600s）
        AT->>V: 请求挑战值
        Note right of V: time(NS_v)
        V-->>AT: JWT{Nonce, time(NS_v), time(NX_v)}
        Note right of AT: time(EG_a)
        Note right of AT: Claims{HpkeKeyConfig}（不含挑战）<br/>经 AA 哈希进 TEE 报告
        AT->>V: Evidence{hash(HpkeKeyConfig)} |<br/>Claims{HpkeKeyConfig}
        Note right of V: time(RG_v)
        V-->>AT: Attestation Result{time(RG_v), time(RX_v),<br/>Claims 覆盖 {HpkeKeyConfig}}（按公钥缓存）
    end
    alt 2. 分发携带 Attestation Result 的密钥配置
        RP->>AT: 请求密钥配置
        AT-->>RP: HpkeKeyConfig | time(CX_a) |<br/>Attestation Result{time(RG_v), time(RX_v), HpkeKeyConfig}
        Note right of RP: time(RA_r)：验签 + exp + Claims 覆盖检查
    end
    alt 3. 加密请求（0-RTT）
        Note right of RP: time(OP2_r)
        RP->>AT: Enc(HTTP Request)
        AT-->>RP: Enc(HTTP Response)
    end
```

egress 按密钥代际缓存护照令牌：密钥轮换后旧令牌不再分发，按 `refresh_interval` 定期刷新。

#### 证明材料如何绑定密钥配置

两种模型的绑定机制相同，这是「验过的 KeyConfig」的密码学含义所在：

1. 被证明方把一个 claims 对象放进 Evidence 的 runtime_data。Client 验 Server 方向是 `ServerUserData{challenge_token, hpke_key_config}`（护照模型无 challenge_token）；Server 验 Client 方向是 `ClientUserData{challenge_token, pk_s}`。注意 `hpke_key_config` 是**完整的配置对象**（含 base64 密钥列表），不是它的哈希。
2. AA 把整个 claims 的规范 JSON 序列化后哈希（当前实现为 SHA-384）写入 TEE 报告数据区，硬件保证这份 claims 与 Evidence 不可分割。
3. AS 验证 Evidence 后把同一份 claims 回写进 Attestation Result 的 runtime_data。
4. 验证方检查令牌：签名信任链（AS 证书或 JWK）、有效期（JWT exp）、以及 runtime_data **覆盖**预期的 claims（子集匹配：期望的每个键值都必须出现在令牌里）。

由此，验证方拿到的令牌同时证明了「对方在可信环境里运行」和「对方用于本次握手的密钥材料出自那个环境」，二者由硬件度量绑定，无法拆开伪造。

### Server 验 Client

#### 护照模型

ingress 为自己生成一对 X25519 密钥（`skS`/`pkS`），提前向 AS 换取把 `pk_s` 绑进 claims 的 Attestation Result，之后每个请求都出示：

```mermaid
sequenceDiagram
    autonumber
    participant V as AS (Verifier)
    participant AT as TNG Ingress (Attester)
    participant RP as TNG Egress (Relying Party)
    Note right of AT: 生成 X25519 密钥对 (skS, pkS)，<br/>作为 HPKE 发送方认证密钥
    alt 1. ingress 提前换取 Attestation Result
        AT->>V: 请求挑战值
        Note right of V: time(NS_v)
        V-->>AT: JWT{Nonce, time(NS_v), time(NX_v)}
        Note right of AT: time(EG_a)
        Note right of AT: Claims{Challenge, pkS}<br/>经 AA 哈希进 TEE 报告
        AT->>V: Evidence{hash(Challenge, pkS)} |<br/>Claims{Challenge, pkS}
        Note right of V: time(RG_v)
        V-->>AT: Attestation Result{time(RG_v), time(RX_v),<br/>Claims 覆盖 {pkS}}
    end
    alt 2. 每个加密请求（0-RTT，附带客户端证明）
        Note right of AT: time(OP2_a)
        AT->>RP: Attestation Result{time(RG_v), time(RX_v), pkS} |<br/>pkS | Enc(HTTP Request)（HPKE Auth 模式封装）
        Note right of RP: time(RA_r) + time(OP2_r)：验令牌<br/>（Claims 覆盖 {pkS}）+ Auth 模式解密成功 = 证明持有 skS
        RP-->>AT: Enc(HTTP Response)
    end
```

egress 侧的验证有两层，缺一不可：

- **令牌层**：按元数据帧里的 `attestation_result` 与 `pk_s` 做与上一节相同的子集校验（期望 claims 为 `{pk_s}`；挑战令牌不重复校验，AS 签发时已验）。
- **密码层**：客户端用 HPKE **发送方认证模式**（RFC 9180 的 auth mode，`SetupAuthS` 语义）封装请求，认证私钥就是被证明的 `skS`。egress 用元数据帧里的 `pk_s` 完成 auth 模式解封装，解密成功即密码学证明对方持有 `skS`。令牌绑定了 `pk_s`，解密证明了 `skS`，两者合起来把「可信环境」与「这个连接的发送方」绑死。

不携带客户端证明时（`NoAuth`）使用 HPKE base 模式。wasm 版 ingress 不支持 `attest`，此方向上恒为 `NoAuth`。

#### 背调模型（经 egress 转发的变体）

严格的背调模型应让 egress 收到请求后自己去 AS 换结果，但那会把验证延迟加进业务请求路径。TNG 把换取动作**提前**到握手阶段，并让 egress 只当转发器：AS 的 challenge/attestation 两个接口经 egress 原样转发，ingress 借此完成证明。这样 ingress 无需预先知道会连到哪个 egress（无状态集群友好），egress 保持无状态：

```mermaid
sequenceDiagram
    autonumber
    participant AT as TNG Ingress (Attester)
    participant RP as TNG Egress (Relying Party)
    participant V as AS (Verifier)
    Note right of AT: 生成 X25519 密钥对 (skS, pkS)
    Note over AT,RP: egress 在此仅充当 AS 的转发器（保持无状态）
    alt 1. 经 egress 转发获取挑战值
        AT->>RP: 请求挑战值<br/>（x-tng-ohttp-api: /tng/background-check/challenge）
        RP->>V: 请求挑战值
        Note right of V: time(NS_v)
        V-->>RP: JWT{Nonce, time(NS_v), time(NX_v)}
        RP-->>AT: JWT{Nonce, time(NS_v), time(NX_v)}
    end
    alt 2. 经 egress 转发换取 Attestation Result
        Note right of AT: time(EG_a)：Claims{Challenge, pkS}<br/>经 AA 哈希进 TEE 报告
        AT->>RP: Evidence{hash(Challenge, pkS)} |<br/>Claims{Challenge, pkS}<br/>（x-tng-ohttp-api: /tng/background-check/verify）
        RP->>V: Evidence | Claims
        Note right of V: time(RG_v)
        V-->>RP: Attestation Result{time(RG_v), time(RX_v),<br/>Claims 覆盖 {pkS}}
        RP-->>AT: Attestation Result{time(RG_v), time(RX_v), pkS}
    end
    alt 3. 每个加密请求（0-RTT，附带客户端证明）
        Note right of AT: time(OP2_a)
        AT->>RP: Attestation Result{time(RG_v), time(RX_v), pkS} |<br/>pkS | Enc(HTTP Request)（HPKE Auth 模式）
        Note right of RP: time(RA_r) + time(OP2_r)：验令牌并 Auth 模式解密
        RP-->>AT: Enc(HTTP Response)
    end
```

egress 配置为护照模型时这两个转发接口返回错误。转发请求/响应的字段与 AS 接口一一对应（`AttestationChallengeResponse{challenge_token}`、`AttestationVerifyRequest{evidence, aa_provider}`、`AttestationVerifyResponse{attestation_result, as_provider}`）。

### 双向验证

两个方向的产物互补：Client 验 Server 得到「经过验证的 KeyConfig」，Server 验 Client 得到「绑定 `pk_s` 的 Attestation Result + auth 模式密钥持有证明」。两者叠加互不干扰，ingress 与 egress 各配置 `attest` + `verify` 即可，模型各自独立选择：

```mermaid
sequenceDiagram
    autonumber
    participant I as TNG Ingress
    participant V as AS (Verifier)
    participant E as TNG Egress
    Note over I,E: ingress 与 egress 均配置 attest + verify，模型各自独立选择
    Note over V,I: Server 验 Client：ingress 持有<br/>Attestation Result{..., pkS} | pkS
    Note over V,E: Client 验 Server：egress 分发<br/>HpkeKeyConfig | time(CX_a) | Evidence 或 Attestation Result
    I->>E: 请求密钥配置（携带验证服务端所需的材料）
    E-->>I: HpkeKeyConfig | time(CX_a) | Evidence 或 Attestation Result
    Note over I: time(RA_r)：验证服务端令牌或 Evidence
    Note over I: time(OP2_r)
    I->>E: Attestation Result{time(RG_v), time(RX_v), pkS} |<br/>pkS | Enc(HTTP Request)（HPKE Auth 模式）
    Note over E: time(RA_r)：验证客户端令牌（pkS）+ Auth 模式解密
    E-->>I: Enc(HTTP Response)
```

### 新鲜度与防重放

协议里的每一份短期凭证都有明确的过期语义：

| 凭证 | 产生方 | 有效期 | 过期后果 |
|---|---|---|---|
| 挑战 JWT（nonce 封装） | AS | 签发时设定（Trustee 实现为签发后 5 分钟） | AS 验证 Evidence 时拒收，HTTP 401 |
| 服务端 KeyConfig | egress | `expire_timestamp`（自动轮换下为一个半轮换周期） | 422，客户端重新获取 |
| Attestation Result | AS | JWT `exp` | 验证方拒收；ingress 侧缓存提前失效 |

关于重放，实现采取的策略是：

- 挑战 JWT 只做签名与 exp 校验，**没有**服务端的已用列表。AS 因此完全无状态（可任意横向扩缩），防重放依赖短 exp 窗口加上挑战值被 TEE 度量进 Evidence 的绑定。
- 加密请求是 0-RTT 的，理论存在重放窗口（与 TLS 1.3 0-RTT 同类问题）。当前实现未做请求密文去重，遵循 RFC 9458 对重放的立场：请求应当幂等或由业务层防护。响应密钥从请求密钥派生且含一次性 nonce，响应不受重放影响。

### AS 接口

背调模型中 TNG 与外部 AS（restful 类型）交互的接口如下（护照模型的交互相同，只是发起方是被证明端）。接口与 Trustee 的 restful AS 一致：

| 接口 | 方法 | 请求体 | 响应 |
|---|---|---|---|
| `/challenge` | POST | `{}` | JSON `{nonce, extra-params: {jwt}}` |
| `/attestation` | POST | JSON（Evidence、runtime_data、policy_ids） | **明文 JWT 字符串**（非 JSON 包装） |
| `/certificate` | GET | 无 | AS 令牌签名证书链，供验证方引导信任 |

两点说明：

- `/attestation` 的请求体遵循 Trustee 的 restful AS schema（新版本为 `verification_requests` 数组结构，对老版本 AS 自动回退平铺结构），其定义以 Trustee 的 `attestation.proto` 为准，本文不复述。
- AS 证书也可以不通过 `/certificate` 发现：在 verify 配置里显式给出 `trusted_certs_paths` 指向 PEM 文件。

`as_type: "grpc"` 的 AS 不支持 challenge 接口（客户端使用哑 nonce，新鲜度退化）；`as_type: "builtin"` 时上述接口全部在 TNG 进程内执行，不产生网络调用。

### 错误响应

ohttp 数据面出错时，egress 返回 JSON 体 `{"code": "<机器可读错误码>", "message": "<人类可读描述>"}`。常见状态码：

| HTTP 状态 | 触发条件 |
|---|---|
| 400 | Content-Type 不是 `message/ohttp-chunked-req`；元数据帧解码失败；缺少 key_config_hint |
| 403 | 请求缺少 `x-tng-ohttp-api` 头 |
| 413 | 元数据帧超过 32 MiB |
| 422 | key_config_hint 指向的密钥不存在或已过期（RFC 9458 §6.4） |
| 500 / 502 / 504 | 内部错误 / 上游不可达 / 上游超时 |

客户端证明不通过（`verify` 侧校验令牌失败）同样落入上述 JSON 错误通道返回。

## RATS-TLS 隧道协议

### 角色与协议分层

rats-tls 隧道以**TCP 连接**为加密粒度：非多路复用模式下，每条被捕获的客户端连接对应 ingress 与 egress 之间一条独立的 TLS 1.3 会话（ingress 恒为 TLS client，egress 恒为 TLS server）。与 ohttp 把 RA 材料放进 HTTP 载荷不同，rats-tls 把证明材料装进 TLS 握手中的 **X.509 证书**：被证明端生成 ECDSA P-256 密钥对和一张自签的 DICE 证书，证明材料作为证书自定义扩展随 `Certificate` 消息发出，`CertificateVerify` 的私钥签名把这份材料与握手中的活连接绑定。

线协议本身是**未改动的标准 TLS 1.3**：没有自定义握手消息、没有 supplemental data、没有 RA 专用 TLS 扩展。TNG 对 rustls 的改动只有放宽单条握手消息与证书的大小上限（TEE 证据加事件日志会让证书超过上游 64 KiB 的防 DoS 上限，配合 RFC 8879 证书压缩使用）。RA 校验发生在**握手完成之后、任何业务数据转发之前**：rustls 层的证书校验器在握手期间恒返回通过，真正的评估由 TNG 在握手后执行，失败即直接断开连接。数据面形态由 ALPN 协商决定：`rats-tls`（非多路复用）或 `h2`（多路复用，见[多路复用与非多路复用](#多路复用与非多路复用)）。

先看一张不含远程证明的总览图（记号沿用[时间点与消息记号](#时间点与消息记号)一节）：

```mermaid
sequenceDiagram
    autonumber
    participant C as App（明文）
    participant I as TNG Ingress（TLS client）
    participant E as TNG Egress（TLS server）
    participant S as Server（明文）
    Note over I,E: 每条客户端 TCP 连接对应一条 TLS 1.3 会话<br/>（ALPN: rats-tls）
    I->>E: TCP 连接
    I->>E: ClientHello
    E->>I: ServerHello / Certificate{DummyCert} /<br/>CertificateVerify / Finished
    I->>E: Finished
    loop 连接生命周期内双向转发
        C->>I: 业务数据（明文）
        Note right of I: time(OP2_r)
        I->>E: Enc(业务数据)
        E->>S: 业务数据（明文）
        S->>E: 业务数据（明文）
        E-->>I: Enc(业务数据)
        I-->>C: 业务数据（明文）
    end
    Note over I,E: 有会话票据时：PSK 恢复 + 0-RTT 早期数据（见新鲜度一节）
```

no_ra 模式下两端使用随二进制内置的固定自签 DummyCert（运行时生成于构建期），提供加密与完整性但不提供任何身份或 RA 保证，仅用于调试，不应在生产环境使用。图中 `Enc(x)` 即 TLS 记录层加密后的 `x`。

### 握手消息流与方向组合

握手消息序是完全标准的 TLS 1.3 流程（ClientHello → ServerHello → EncryptedExtensions → [CertificateRequest] → Certificate → CertificateVerify → Finished → [客户端 Certificate → CertificateVerify → Finished]），启用 RFC 8879 证书压缩。RA 相关的差异只体现在**谁出示带证明材料的证书、谁发送 CertificateRequest、谁在握手后校验**：

| 方向组合 | ingress 配置 | egress 配置 | CertificateRequest | egress 出示证书 | ingress 出示证书 | 握手后校验方 |
|---|---|---|---|---|---|---|
| 单向（Client 验 Server） | `verify` | `attest` | 无 | DiceCert | 空证书 | ingress |
| 反向单向（Server 验 Client） | `attest` | `verify` | 有 | DummyCert | DiceCert | egress |
| 双向 | `attest` + `verify` | `attest` + `verify` | 有 | DiceCert | DiceCert | 双方各自 |
| no_ra（调试） | `no_ra` | `no_ra` | 无 | DummyCert | 空证书 | 无 |

配置组合不匹配会在 TLS 握手内部失败：例如 egress 为 `verify`（要求客户端证书）而 ingress 未配置 `attest`（出示空证书），rustls 直接以 `NoCertificatesPresented` 拒绝。反向单向里 egress 不做 RA、出示 DummyCert，同时以 CertificateRequest 强制要求 ingress 的 DiceCert。

### DICE 证书：证明材料的载体

DICE 证书是 rats-tls 中 RA 材料的唯一载体，其生成与绑定机制（记号同 ohttp 各节）：

1. 被证明端生成 P-256 密钥对，计算公钥的 SHA-256 作为 `PubKeyHash` 放入 Claims（报告数据区声明）。护照模型在此步之后先走 AA→AS 管线换取 Attestation Result，Claims 同样被 TEE 度量绑定。
2. AA 以该 Claims 采集 Evidence，`Evidence{hash(PubKeyHash)}`，约定与 ohttp 一节相同：TEE 报告数据区绑定的是整个 Claims 规范 JSON 的哈希，明文随行。
3. 证明材料以带 tag 的 CBOR 序列化（背调装 AA 的 Evidence，护照装 AS 的令牌），作为自签证书的自定义扩展（OID 2.23.133.5.4.9，TCG DICE Tagged Evidence）写入。
4. 证书为自签、CN 固定、有效期 6 小时（护照模型取与令牌 `exp` 的较小者），启用压缩以控制握手体积。私钥不出被证明端。

验证端在握手后的校验流程：

1. 检查证书**自签签名**（无外部 PKI 链，信任锚是 TEE 度量而非证书链）。
2. 解析扩展，取出证明材料与随行 Claims，重算证书公钥哈希得到期望的 `PubKeyHash`。
3. 背调模型：将 Evidence 连同 Claims 同步提交 AS 换取令牌；护照模型：材料本身就是 AS 令牌，无 AS 往返。
4. 验证令牌：签名信任链（AS 证书/JWK）、`exp`、Claims 覆盖 `{PubKeyHash}`（子集校验，同 ohttp）。通过后结论按证书哈希缓存 60 秒。

与 ohttp 的 `pkS`/`skS` 双层结构完全同构，这是「验过的连接」的密码学含义：

- **令牌层**：Attestation Result 的 Claims 覆盖 `{PubKeyHash}`，证明「这个公钥出自可信环境」。
- **密码层**：TLS `CertificateVerify` 由证书私钥签名，握手验证成功即密码学证明对方持有与 `PubKeyHash` 配对的私钥。

令牌绑定公钥哈希、握手证明私钥持有，二者把「可信环境」与「这条 TLS 连接」绑死，无法拆开伪造。

### 多路复用与非多路复用

| 维度 | 非多路复用（默认） | 多路复用 |
|---|---|---|
| ALPN | `rats-tls` | `h2` |
| 连接模型 | 一条客户端连接 = 一条 TLS 会话 | 一条外层 TLS 会话承载全部流量，每条客户端连接是其中一条 HTTP/2 CONNECT 流 |
| RA | 每条会话各自出示证书并校验 | 外层握手一次出示证书并校验，CONNECT 响应携带校验结果 |
| 会话恢复 | PSK 票据 + 0-RTT 早期数据 | 单条长连接，无 0-RTT |
| 吞吐特征 | 每连接独立密码学，天然并行 | 流量共享一条连接的密码学能力（见参数手册的容量说明） |

多路复用需要 ingress 与 egress 的 `multiplex` 开关一致，否则 ALPN 协商失败；RA 全部由外层握手承载，内层 CONNECT 流不再有证明材料。ingress 侧的连接池按目标端点分片（`multiplex_max_connections`），每分片有并发流上限（`multiplex_max_streams_per_connection`），达到上限后开新分片，这些是吞吐调优参数，语义见[参数手册](configuration.md#transport-layer-common-configuration)。

### RA 模型在 rats-tls 中的形态

背调与护照两模型同样适用于 rats-tls，且**在线格式上不可区分**：TLS 消息流、证书结构、扩展 OID 完全相同，区别只在证书扩展里装的是 AA 的 Evidence 还是 AS 的令牌，以及 AS 被调用的时机（验证端在握手后调用，或被证明端在握手前调用）。模型对比沿用[RA 模型选择](#ra-模型选择)一节的表格。两点 rats-tls 特有约束：attest 侧与 verify 侧的 `model` 必须一致；builtin AS 仅可用于背调模型的 verify 侧（护照 attest + builtin 组合被拒绝）。

### Client 验 Server

#### 背调模型（默认）

egress 在握手前备好装着 Evidence 的 DiceCert，ingress 在握手后请 AS 验证：

```mermaid
sequenceDiagram
    autonumber
    participant V as AS (Verifier)
    participant I as TNG Ingress (Relying Party)
    participant E as TNG Egress (Attester)
    participant AA as AA
    Note right of E: 生成 P-256 密钥对，<br/>Claims{PubKeyHash} = hash(证书公钥)
    alt 1. egress 备好证明材料（按 refresh_interval 刷新，默认 600s）
        E->>AA: 采集 Evidence
        Note right of E: time(EG_a)：Evidence{hash(PubKeyHash)}，<br/>装入 DiceCert 扩展（OID 2.23.133.5.4.9）
    end
    alt 2. TLS 1.3 握手（ALPN: rats-tls）
        I->>E: ClientHello
        E->>I: ServerHello / Certificate{DiceCert{Evidence{hash(PubKeyHash)}}} /<br/>CertificateVerify / Finished
        I->>E: Finished
        Note right of I: TLS 层不校验证明结果，<br/>校验在握手后进行
    end
    alt 3. 握手后验证（转发数据前）
        I->>V: Evidence | Claims{PubKeyHash}
        Note right of V: time(RG_v)
        V-->>I: Attestation Result{time(RG_v), time(RX_v),<br/>Claims 覆盖 {PubKeyHash}}
        Note right of I: time(RA_r)：验签 + exp + Claims 覆盖检查，<br/>失败 → 断开连接（无 TLS alert）
    end
    alt 4. 数据转发
        Note right of I: time(OP2_r)
        I->>E: Enc(业务数据)
        E-->>I: Enc(业务数据)
    end
```

若 ingress 配置了 `as_type: "builtin"`，第 3 步的 AS 角色在 ingress 进程内完成，无网络往返。

#### 护照模型

egress 提前换好令牌装入证书，ingress 握手后只验令牌，无 AS 往返：

```mermaid
sequenceDiagram
    autonumber
    participant I as TNG Ingress (Relying Party)
    participant E as TNG Egress (Attester)
    participant V as AS (Verifier)
    participant AA as AA
    Note right of E: 生成 P-256 密钥对，<br/>Claims{PubKeyHash} = hash(证书公钥)
    alt 1. egress 提前换取 Attestation Result（按 refresh_interval 刷新）
        E->>AA: 采集 Evidence
        Note right of E: time(EG_a)：Evidence{hash(PubKeyHash)}
        E->>V: Evidence | Claims{PubKeyHash}
        Note right of V: time(RG_v)
        V-->>E: Attestation Result{time(RG_v), time(RX_v),<br/>Claims 覆盖 {PubKeyHash}}
        Note right of E: 令牌装入 DiceCert 扩展
    end
    alt 2. TLS 1.3 握手（ALPN: rats-tls）
        I->>E: ClientHello
        E->>I: ServerHello /<br/>Certificate{DiceCert{Attestation Result{time(RG_v), time(RX_v), PubKeyHash}}} /<br/>CertificateVerify / Finished
        I->>E: Finished
    end
    alt 3. 握手后验证（无 AS 往返）
        Note right of I: time(RA_r)：验令牌（签名 + exp +<br/>Claims 覆盖 {PubKeyHash}），失败 → 断开连接
    end
    alt 4. 数据转发
        Note right of I: time(OP2_r)
        I->>E: Enc(业务数据)
        E-->>I: Enc(业务数据)
    end
```

### Server 验 Client

#### 护照模型

ingress 提前换好令牌装入自己的 DiceCert，egress 在握手中强制索取客户端证书并在握手后验证：

```mermaid
sequenceDiagram
    autonumber
    participant AA as AA
    participant V as AS (Verifier)
    participant I as TNG Ingress (Attester)
    participant E as TNG Egress (Relying Party)
    Note right of I: 生成 P-256 密钥对，<br/>Claims{PubKeyHash} = hash(证书公钥)
    alt 1. ingress 提前换取 Attestation Result
        I->>AA: 采集 Evidence
        Note right of I: time(EG_a)：Evidence{hash(PubKeyHash)}
        I->>V: Evidence | Claims{PubKeyHash}
        Note right of V: time(RG_v)
        V-->>I: Attestation Result{time(RG_v), time(RX_v),<br/>Claims 覆盖 {PubKeyHash}}
        Note right of I: 令牌装入 DiceCert 扩展
    end
    alt 2. TLS 1.3 握手（egress 出示 DummyCert 并索取客户端证书）
        I->>E: ClientHello
        E->>I: ServerHello / CertificateRequest /<br/>Certificate{DummyCert} / CertificateVerify / Finished
        I->>E: Certificate{DiceCert{Attestation Result{time(RG_v), time(RX_v), PubKeyHash}}} /<br/>CertificateVerify / Finished
        Note right of E: CertificateVerify 由 DiceCert 私钥签名，<br/>证明持有与 PubKeyHash 配对的私钥
    end
    alt 3. 握手后验证（转发数据前）
        Note right of E: time(RA_r)：验令牌（签名 + exp +<br/>Claims 覆盖 {PubKeyHash}），失败 → 断开连接
    end
    alt 4. 数据转发
        Note right of E: time(OP2_r)
        E-->>I: Enc(业务数据)
        I-->>E: Enc(业务数据)
    end
```

#### 背调模型

流程与护照模型同形，区别在两处：ingress 装入证书的是 AA 的 Evidence（非令牌）；egress 在握手后把 Evidence 连同 Claims 提交 AS 换取令牌再验证（AS 必须能被 egress 访问）：

```mermaid
sequenceDiagram
    autonumber
    participant AA as AA
    participant I as TNG Ingress (Attester)
    participant E as TNG Egress (Relying Party)
    participant V as AS (Verifier)
    Note right of I: 生成 P-256 密钥对，<br/>Claims{PubKeyHash} = hash(证书公钥)
    alt 1. ingress 备好证明材料（按 refresh_interval 刷新）
        I->>AA: 采集 Evidence
        Note right of I: time(EG_a)：Evidence{hash(PubKeyHash)}，<br/>装入 DiceCert 扩展
    end
    alt 2. TLS 1.3 握手（egress 出示 DummyCert 并索取客户端证书）
        I->>E: ClientHello
        E->>I: ServerHello / CertificateRequest /<br/>Certificate{DummyCert} / CertificateVerify / Finished
        I->>E: Certificate{DiceCert{Evidence{hash(PubKeyHash)}}} /<br/>CertificateVerify / Finished
        Note right of E: CertificateVerify 由 DiceCert 私钥签名，<br/>证明持有与 PubKeyHash 配对的私钥
    end
    alt 3. 握手后验证（转发数据前）
        E->>V: Evidence | Claims{PubKeyHash}
        Note right of V: time(RG_v)
        V-->>E: Attestation Result{time(RG_v), time(RX_v),<br/>Claims 覆盖 {PubKeyHash}}
        Note right of E: time(RA_r)：验签 + exp + Claims 覆盖检查，<br/>失败 → 断开连接
    end
    alt 4. 数据转发
        Note right of E: time(OP2_r)
        E-->>I: Enc(业务数据)
        I-->>E: Enc(业务数据)
    end
```

与 ohttp 的背调转发变体不同，这里**没有**「经对端转发」的变体：rats-tls 是连接级协议，ingress 与 egress 直接建连，不存在无状态集群下「不知道会连到哪个 egress」的问题。

### 双向验证

两个方向叠加：egress 出示 DiceCert，同时以 CertificateRequest 索取 ingress 的 DiceCert，双方各自在握手后校验对端：

```mermaid
sequenceDiagram
    autonumber
    participant I as TNG Ingress
    participant V as AS (Verifier)
    participant E as TNG Egress
    Note over I,E: 双方均配置 attest + verify，模型一致（背调或护照）
    Note over V,I: Server 验 Client：ingress 的 DiceCert 装有<br/>自己的证明材料
    Note over V,E: Client 验 Server：egress 的 DiceCert 装有<br/>自己的证明材料
    alt 1. 双方各自备好证明材料（护照或背调）
        Note over I: time(EG_a)
        Note over E: time(EG_a)
    end
    alt 2. TLS 1.3 握手（双向证书）
        I->>E: ClientHello
        E->>I: ServerHello / CertificateRequest /<br/>Certificate{DiceCert} / CertificateVerify / Finished
        I->>E: Certificate{DiceCert} / CertificateVerify / Finished
    end
    alt 3. 双方各自在握手后校验（转发数据前）
        Note over I: time(RA_r)：验证 egress 的 DiceCert
        Note over E: time(RA_r)：验证 ingress 的 DiceCert
    end
    alt 4. 数据转发
        Note over I: time(OP2_r)
        I->>E: Enc(业务数据)
        E-->>I: Enc(业务数据)
    end
```

### 新鲜度与会话恢复

rats-tls 路径**没有逐握手的挑战值**（`time(NS_v)` / `time(NX_v)` 不出现：AS 的 challenge 接口只用于 ohttp 背调流程），新鲜度由一组时间窗口叠加保证：

| 机制 | 周期 / 语义 |
|---|---|
| 证明材料刷新 | attest 侧 `refresh_interval`（默认 600 秒，0 = 每次握手重新生成） |
| 验证结论缓存 | verify 侧 60 秒（同一证书一分钟内不重复评估） |
| 令牌有效期 | AS 令牌的 `exp` |
| 证书有效期 | 6 小时（护照模型取与令牌 `exp` 的较小者） |

会话恢复（PSK）与 0-RTT 的信任**继承自原完整握手**：恢复的连接不再重新执行 RA 校验，`AttestationState::Resumed` 直接信任 PSK 所绑定的那次校验。有会话票据的客户端可在握手完成前携带最多 64 KiB 早期数据（egress 接受上限 128 KiB，被拒的 0-RTT 自动按 1-RTT 重放）。与 ohttp 的挑战 JWT 相比，这里没有逐握手的新鲜度源，代价是证明材料存在最长一个刷新周期的陈旧窗口，收益是恢复连接零额外往返。

### 握手失败与错误行为

- **RA 校验失败**：TLS 层不产生 alert；连接在握手完成后、数据转发前被直接断开，对端观察到的是连接关闭或 TCP 复位，而非 TLS 错误。
- **配置组合不匹配**：在 TLS 握手内部失败，例如 egress 为 `verify` 而 ingress 无 `attest`（空客户端证书）时 rustls 以 `NoCertificatesPresented` 拒绝。
- **UDP 隧道路径（QUIC）例外**：该路径的证书校验器在握手内同步执行，失败映射为 TLS 层的证书无效错误。
