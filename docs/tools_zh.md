# TNG 工具

> `tng tools` 是一组面向运维人员的子命令，用于检查和验证 TNG 在线路上使用的远程证明材料：rats-tls 证书、ohttp 密钥配置以及去中心化的 HPKE 密钥环。
>
> 这些命令**不**运行隧道。它们复用与运行中的 TNG 实例相同的 RA 栈（Attestation Agent、Attestation Service、RA-TLS 验证器），因此由 `tng tools` 生成或验证的证书或密钥配置与隧道本身产生或接受的材料逐字节一致。

## 目录

- [概述](#概述)
- [服务依赖](#服务依赖)
- [术语速查](#术语速查)
- [tng tools rats-tls](#tng-tools-rats-tls)
  - [rats-tls gen](#rats-tls-gen)
  - [rats-tls dump](#rats-tls-dump)
  - [rats-tls verify](#rats-tls-verify)
  - [AttestArgs 与 VerifyArgs JSON](#attestargs-与-verifyargs-json)
- [tng tools ohttp](#tng-tools-ohttp)
  - [ohttp dump](#ohttp-dump)
  - [ohttp verify](#ohttp-verify)
- [tng tools key-sync](#tng-tools-key-sync)
  - [key-sync 参数](#key-sync-参数)
  - [key-sync 输出格式](#key-sync-输出格式)
- [平台支持](#平台支持)

---

## 概述

`tng tools` 按证明材料的种类分为三组子命令：

| 分组 | 材料 | 需要 AA | 需要 AS | 典型用途 |
|---|---|---|---|---|
| `tng tools rats-tls` | rats-tls 证书（PEM） | gen / dump（双向） | verify | 签发或校验 RA-TLS 握手中携带的证书 |
| `tng tools ohttp` | ohttp 密钥配置响应（JSON） | dump（双向） | verify | 拉取并验证 ohttp egress 公告的 HPKE 密钥配置 |
| `tng tools key-sync` | 去中心化 HPKE 密钥环（文件） | 是 | 是 | 运行 serf 集群，将 ohttp 密钥环同步并轮转到磁盘 |

`gen` 与 `verify` 是针对扁平 RA JSON 参数的本地操作；`dump` 连接一个在线端点；`key-sync` 是长驻守护进程。该扁平 JSON 被直接解析为 `AttestArgs` / `VerifyArgs`（见 [AttestArgs 与 VerifyArgs JSON](#attestargs-与-verifyargs-json)），因此与完整的 TNG 配置块不同，model 与 provider 标签必须显式写明。

---

## 服务依赖

部分子命令需要联系 Attestation Agent（AA）采集证据，和/或联系 Attestation Service（AS）验证证据。运行命令前请先启动它们：

```bash
make test-dep-aa &   # AA 监听 /run/confidential-containers/attestation-agent/attestation-agent.sock
make test-dep-as &   # AS 监听 http://127.0.0.1:8080
```

如果当前环境无法使用 `make test-dep-as`，可直接启动一个独立 AS：

```bash
restful-as --socket 0.0.0.0:8080
```

各子命令的依赖见 [概述](#概述) 表格，并在对应小节中再次说明。

---

## 术语速查

- **RA（Remote Attestation，远程证明）**：依据 RATS RFC 9334，以密码学手段向远端证明本系统的运行时完整性。
- **AA（Attestation Agent，证明代理）**：运行在 TEE 内的代理，采集硬件可信度量并格式化为证据。
- **AS（Attestation Service，证明服务）**：验证证据的后端服务，可以是 TNG 内置 AS，也可以是外部部署的 Trustee 等。
- **rats-tls**：在 TLS 1.3 握手内携带远程证明证据的协议，TNG 的默认传输。
- **ohttp（Oblivious HTTP）**：TNG 可替代 rats-tls 使用的应用层加密协议，以 HPKE 加密。
- **HPKE**：Hybrid Public-Key Encryption，混合公钥加密；ohttp 用它封装请求/响应体，密钥为轮转的 X25519 密钥对。
- **serf**：一种 gossip 协议（memberlist），`key-sync` 借助它组建一个由已证明节点构成的去中心化集群，通过 RA-TLS QUIC 传输共享 HPKE 密钥环。
- **PKCS#8 PEM**：`key-sync` 写出私钥材料时使用的文本封装格式，可被基于文件的 ohttp 密钥管理器往返加载。

---

## tng tools rats-tls

rats-tls 证书工具。`gen` 在本地签发证书；`dump` 通过完成 TLS 握手从在线端点捕获服务端证书（不执行证明验证）；`verify` 对证书文件执行完整 RA 验证。

### rats-tls gen

从一份 `AttestArgs` 配置在本地生成 rats-tls 证书。证书与密钥以 PEM 输出。需要 AA（证明方在本机采集证据）。

```bash
tng tools rats-tls gen --attest '<json>' [--cert-out cert.pem] [--key-out key.pem]
```

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--attest` | JSON 字符串 | — | 构建证书所用的扁平 `AttestArgs` JSON（必填） |
| `--cert-out` | PEM 路径 | stdout | 将证书 PEM 写入该文件；省略时打印到 stdout |
| `--key-out` | PEM 路径 | stdout | 将私钥 PEM 写入该文件；省略时打印到 stdout |

证书以 ECDSA P-256 密钥、SHA-256 构建，subject 为 `CN=TNG,O=Inclavare Containers`，走的与运行中 RA-TLS 服务端相同的 `CertBuilder` 路径。Background Check 与 Passport 两种模型均支持；Passport 还会通过 converter 联系 AS 生成嵌入证书的证明结果 token。

<details>
<summary>示例：基于本地 AA 的 Background Check 证书</summary>

```bash
tng tools rats-tls gen \
  --attest '{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}' \
  --cert-out server.pem --key-out server.key
```
</details>

<details>
<summary>示例：Passport 证书（需要 AS 生成 token）</summary>

```bash
tng tools rats-tls gen \
  --attest '{"model":"passport","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}' \
  --cert-out server.pem --key-out server.key
```
</details>

### rats-tls dump

通过完成 TLS 1.3 握手从一个在线端点捕获 rats-tls 服务端证书，不执行证明验证。握手使用一个捕获型验证器，它记录终端实体证书而非校验，因此对任何 rats-tls 服务端都能成功。对 `no_ra` 与真实 RA 服务端均可用。

```bash
tng tools rats-tls dump --endpoint <host:port> [--attest '<json>'] [--cert-out cert.pem]
```

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--endpoint` | `host:port` | — | 要连接的 rats-tls 服务端地址（必填） |
| `--attest` | JSON 字符串 | — | 客户端证书所用的扁平 `AttestArgs` JSON；仅在需要客户端证书的双向 RA 服务端下需要。`no_ra` 服务端请省略。 |
| `--cert-out` | PEM 路径 | stdout | 将捕获的证书 PEM 写入该文件；省略时打印到 stdout |

`--attest` 通过与运行中 RA-TLS 客户端相同的 `CertManager` 驱动客户端证书，因此需要 unix 目标（AA 证明方为 unix 限定）。在非 unix 的非 wasm 目标上，显式 `--attest` 会被拒绝，而非静默回退到无客户端证书。握手期间不交换应用数据，握手完成后立即关闭连接。

<details>
<summary>示例：捕获 no_ra 服务端证书</summary>

```bash
tng tools rats-tls dump --endpoint 127.0.0.1:8443 --cert-out captured.pem
```
</details>

<details>
<summary>示例：捕获双向 RA 服务端证书（需要客户端证书）</summary>

```bash
tng tools rats-tls dump --endpoint 127.0.0.1:8443 \
  --attest '{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}' \
  --cert-out captured.pem
```
</details>

### rats-tls verify

依据一份 `VerifyArgs` 配置对证书文件执行完整 RA 验证。证书可为 PEM 或原始 DER。验证复用与运行中 RA-TLS 握手相同的 `LazyCertVerifier`：Passport 解析并验证嵌入证书的 AS token；Background Check 通过 AS 转换嵌入证据并验证结果。需要 AS。

```bash
tng tools rats-tls verify --cert <file> --verify '<json>'
```

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--cert` | 文件路径 | — | 待验证的证书文件，PEM 或 DER（必填） |
| `--verify` | JSON 字符串 | — | 用于验证证书的扁平 `VerifyArgs` JSON（必填） |

成功时打印 `verified OK` 及格式化的 `AttestationResult`（其序列化为原始 JWT token 字符串）。

<details>
<summary>示例：以 Background Check 模式验证证书</summary>

```bash
tng tools rats-tls verify --cert captured.pem \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}'
```
</details>

<details>
<summary>示例：以 Passport 模式验证证书</summary>

Passport 模式下验证方只校验 token 签名；`as_addr` 可选（存在时用于获取 AS 信任根）。

```bash
tng tools rats-tls verify --cert captured.pem \
  --verify '{"model":"passport","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}'
```
</details>

### AttestArgs 与 VerifyArgs JSON

`--attest` 与 `--verify` 接收一个**扁平** JSON 对象，被直接解析为 `AttestArgs` / `VerifyArgs`，而非完整的 TNG 配置块。由于工具直接解析这些结构体（不经过配置层的标签默认注入），`model` 判别标签与 provider/sub-type 标签都必须显式写明。完整字段参考见 [远程证明配置](remote_attestation_zh.md)；下表列出工具接受的扁平键。

`--attest`（`AttestArgs`）扁平键：

| 键 | 适用范围 | 默认值 | 说明 |
|---|---|---|---|
| `model` | 两者 | — | `background_check` 或 `passport`（必填） |
| `aa_provider` | 两者 | — | `coco`（或 `coco_asr` / `ita` / `ita_asr`）；选择 AA 栈（必填） |
| `aa_type` | 两者 | — | CoCo 取 `uds`（`aa_provider` 为 `coco` 时必填） |
| `aa_addr` | 两者 | — | AA 地址，如 `unix:///run/.../attestation-agent.sock`（`uds` 必填） |
| `as_provider` | passport | — | `coco`（或 `ita`）；选择 converter 对接的 AS 栈 |
| `as_type` | passport | — | CoCo 的 `restful` / `grpc` / `builtin` |
| `as_addr` | passport | — | converter 生成 token 所用的 AS 地址 |
| `policy_ids` | passport | — | AS 据以评估证据的策略 ID |
| `as_headers` | passport | — | 发往 AS 的额外 HTTP 头 |
| `refresh_interval` | 两者 | `EVIDENCE_REFRESH_INTERVAL_SECOND` | 证据刷新间隔（秒）；`0` 表示每次刷新 |

`--verify`（`VerifyArgs`）扁平键：

| 键 | 适用范围 | 默认值 | 说明 |
|---|---|---|---|
| `model` | 两者 | — | `background_check` 或 `passport`（必填） |
| `as_provider` | 两者 | — | `coco`（或 `ita`）；选择 AS 栈（必填） |
| `as_type` | 两者 | — | CoCo 的 `restful` / `grpc` / `builtin`（`as_provider` 为 `coco` 时必填） |
| `as_addr` | BC / passport | — | AS 地址。Background Check 必填（验证方联系 AS）；Passport 可选（用于获取 AS 信任根） |
| `policy_ids` | 两者 | — | AS 据以评估证据的策略 ID |
| `as_headers` | 两者 | — | 发往 AS 的额外 HTTP 头；不能在无 `as_addr` 时设置 |

---

## tng tools ohttp

ohttp 密钥配置工具。`dump` 拉取 ohttp egress 公告的密钥配置响应，写出原始 body 及派生产物（HPKE 密钥、TDX quote、event log、attestation result、claims）；`verify` 对已 dump 的 body 离线重验；`decode` 不打服务端、不打 AS，从已 dump 的 body 复现派生产物。

### ohttp dump

向 ohttp 服务端的密钥配置端点 POST 一个 `KeyConfigRequest`，写出返回的 `KeyConfigResponse` 及派生产物。不带 `--verify` 时为裸请求（无 `attestation_info`），dump 仅写 `raw.json`、`hpke.base64`、`hpke.json`。带 `--verify <VerifyArgs json>` 时，dump 构建 AS 转换器，生成 background-check challenge token（passport 模型则发送 `Passport`），拉取带证明的响应，并就地跑 `verify_keyconfig_attestation` 产出 attestation-result JWT 与解码后的 claims；bundle 随之还包含 `quote.bin`、`eventlog.json`（仅 background-check）、`attestation_result.jwt`、`attestation_result.claims.json`。

background-check 的当场性绑定到生成 nonce 的那个 AS 实例，故 `dump --verify` 在一个进程内跑完整条实时链（生成、拉取、验证、解码），与 ingress 隧道一致。Passport 证明不携带裸 quote/event log（服务端已将其蒸馏为签名 token），故 passport 下省略 `quote.bin`/`eventlog.json`。

```bash
tng tools ohttp dump --endpoint <url> [--verify '<VerifyArgs json>'] (--raw <file> | --out-dir <dir>)
```

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--endpoint` | URL | — | ohttp 密钥配置端点 URL（必填） |
| `--verify` | JSON 字符串 | — | 扁平 `VerifyArgs` JSON。带此项时，dump 生成 challenge token，拉取带证明的密钥配置，就地验证并写出 attestation 产物；不带此项为裸密钥配置（无 attestation 产物） |
| `--raw` | 文件路径 | stdout | 仅将原始 `KeyConfigResponse` body 写入该文件（格式化 JSON）；`--raw` 与 `--out-dir` 均不指定时打印到 stdout |
| `--out-dir` | 目录 | — | 将完整产物 bundle 写入该目录（见下表）。与 `--raw` 互斥 |

请求携带 `x-tng-ohttp-api: key_config` 头，与运行中 ingress 使用的一致。拉取使用独立的 reqwest 客户端以保持其为独立运维工具；仅证明这半边复用运行中的 `verify_keyconfig_attestation`，因此 dump 与隧道以逐字节一致的方式验证。

`--out-dir` 下的 bundle 文件：

| 文件 | 格式 | 总是有 | 需 `--verify` | 仅 background-check |
|---|---|---|---|---|
| `raw.json` | JSON（原始 `KeyConfigResponse` body） | 是 | | |
| `hpke.base64` | base64（`encoded_key_config_list`） | 是 | | |
| `hpke.json` | JSON（RFC 9458：key_id/kem/public_key/suites/expire） | 是 | | |
| `quote.bin` | 二进制（TDX quote） | | 是 | 是 |
| `eventlog.json` | JSON（解析后的 UEFI event log） | | 是 | 是 |
| `attestation_result.jwt` | JWT（AS 签名的 attestation result） | | 是 | |
| `attestation_result.claims.json` | JSON（解码后的 JWT payload） | | 是 | |

<details>
<summary>示例：拉取裸密钥配置（无证明）</summary>

```bash
tng tools ohttp dump --endpoint http://127.0.0.1:8080/ohttp/key --out-dir bundle
```
</details>

<details>
<summary>示例：拉取 background-check 密钥配置、验证并写出完整 bundle（builtin AS）</summary>

```bash
tng tools ohttp dump --endpoint http://127.0.0.1:8080/ohttp/key \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"builtin","attestation_policy":{"type":"default"},"reference_values":[]}' \
  --out-dir bundle
```

`bundle/` 目录随后含 `raw.json`、`hpke.base64`、`hpke.json`、`quote.bin`、`eventlog.json`、`attestation_result.jwt`、`attestation_result.claims.json`。`attestation_result.claims.json` 是解码后的 attestation-result JWT payload：EAR 裁决（`submods.cpu0.ear.status`）、解析后的 TDX quote（`...tdx.quote.body.*`）、`tcb_verification.tcb_status`、UEFI event log，以及 `runtime_data_claims`（challenge token 与绑定的 HPKE 密钥配置）。
</details>

### ohttp verify

依据一份 `VerifyArgs` 配置，对已 dump 的密钥配置 body（`raw.json`）重新验证，打印 attestation-result JWT 与解码后的 claims。复用 ingress 客户端的 `verify_keyconfig_attestation`。

```bash
tng tools ohttp verify --raw <file> --verify '<json>'
```

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--raw` | 文件路径 | — | 待验证的已 dump `KeyConfigResponse` JSON 文件（必填） |
| `--verify` | JSON 字符串 | — | 用于验证证明的扁平 `VerifyArgs` JSON（必填） |

`verify` 是对已 dump 文件的离线重验，故传入 `challenge_token = None`，不重校验抗重放/当场性。它适用于 Passport 证据（自包含 token，无 nonce）与 external-AS background-check 证据（外部 AS 跨进程保留状态）。`dump --verify` 产出的 builtin-AS background-check 密钥配置**无法**在此重验：evidence 里的 challenge token 是 `dump --verify` 那个 builtin AS 实例签的，而本进程新建的 builtin AS 用了不同的进程内签名密钥，`convert` 会拒绝。`verify` 检测到此配置（builtin + background-check）会直接报错，明确指引用 `dump --verify`。无证明 dump（无 `attestation_info`）的密钥配置会以 `no attestation_info` 报错。成功时 `verify` 打印 `verified OK`、原始 attestation-result JWT 与格式化的 `claims:` 块。

<details>
<summary>示例：验证已 dump 的密钥配置</summary>

```bash
tng tools ohttp verify --raw bundle/raw.json \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}'
```
</details>

### ohttp decode

对已 dump 的密钥配置 body（`raw.json`）解码出派生产物，不打服务端、不打 AS（纯本地解码，不验签）。写出 `raw.json`、`hpke.base64`、`hpke.json`，以及 background-check body 的 `quote.bin`。带 `--attestation-result <jwt 文件>` 时，还写出从 JWT payload 解出的 `attestation_result.claims.json` 与 `eventlog.json`。

```bash
tng tools ohttp decode --raw <file> [--attestation-result <jwt 文件>] --out-dir <dir>
```

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--raw` | 文件路径 | — | 待解码的已 dump `KeyConfigResponse` JSON 文件（必填） |
| `--attestation-result` | 文件路径 | — | 先前 `dump --verify` 产出的 `attestation_result.jwt`；提供时 decode 还写出 `attestation_result.claims.json` 与 `eventlog.json` |
| `--out-dir` | 目录 | — | 解码产物的输出目录（必填） |

<details>
<summary>示例：离线重新解码已 dump 的 bundle</summary>

```bash
tng tools ohttp decode --raw bundle/raw.json \
  --attestation-result bundle/attestation_result.jwt --out-dir decoded
```
</details>

---

## tng tools key-sync

去中心化 HPKE 密钥同步守护进程。它运行一个无状态 serf 集群，成员之间通过 RA-TLS QUIC 互证，同步 HPKE 密钥环，按计划轮转，并将运行中集群密钥集镜像到磁盘，使外部 ohttp 密钥管理器（或任意消费方）无需加入集群即可消费轮转中的密钥。需要 AA 与 AS（节点间 RA-TLS 双向证明）。`key-sync` 子命令以 `__egress-common` 特性门控；它在 wasm 目标上不可用，且需要 AA+AS 证明栈（serf 传输使用 RA-TLS 双向证明）。

```bash
tng tools key-sync \
  --host 0.0.0.0 --port 8301 \
  --peer 10.0.0.2:8301 --peer 10.0.0.3:8301 \
  --rotation-interval 300 \
  --attest '<json>' --verify '<json>' \
  --out-dir /var/lib/tng/key-sync \
  [--ready-file /run/tng/key-sync.ready]
```

### key-sync 参数

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--host` | 地址 | `0.0.0.0` | serf 监听地址 |
| `--port` | 端口 | `8301` | serf UDP 端口 |
| `--peer` | 地址 | — | 初始对端（`IP:port` 或 `domain:port`）；可重复。无对端的节点会自举为独立集群。 |
| `--peers-file` | 路径 | — | 用于动态更新对端列表的 JSON 文件；此处发现的新对端会在后台重试直到加入 |
| `--rotation-interval` | 秒 | `300` | HPKE 密钥轮转间隔 |
| `--attest` | JSON 字符串 | — | 本节点用于证明的扁平 `AttestArgs` JSON（必填） |
| `--verify` | JSON 字符串 | — | 本节点用于验证对端的扁平 `VerifyArgs` JSON（必填） |
| `--out-dir` | 目录 | — | 密钥环快照输出目录（必填） |
| `--ready-file` | 路径 | — | 集群自举完成、即将导出时被 touch（写入 `ready`），供外部监管进程轮询就绪状态 |

`--attest` 与 `--verify` 为与 `rats-tls` 相同的扁平 `AttestArgs`/`VerifyArgs` JSON（见 [AttestArgs 与 VerifyArgs JSON](#attestargs-与-verifyargs-json)）。

### key-sync 输出格式

守护进程将集群密钥集的分区快照写入 `--out-dir`，在每次密钥变更通知以及四分之一轮转周期的轮询兜底上重新导出。每个角色目录按文件存放一个密钥，文件名以**公钥十六进制**命名（而非 `key_id`，因为 serf 引擎为每个密钥分配 `key_id = 0`；公钥十六进制是集群密钥集自身索引的唯一区分符）。私钥材料为 PKCS#8 PEM，与基于文件的 ohttp 密钥管理器加载的格式相同。

| 路径 | 角色 | 何时存在 |
|---|---|---|
| `current/<pk_hex>.key` + `current/<pk_hex>.meta.json` | Active | 始终（使用中的密钥） |
| `next/<pk_hex>.key` + `next/<pk_hex>.meta.json` | Pending | 当已暂存一次轮转时 |
| `expired/<pk_hex>.key` + `expired/<pk_hex>.meta.json` | Stale | 当退役密钥尚未过期时 |
| `cluster.json` | 拓扑 | 始终 |

空的角色目录会被删除（例如无 pending 或 stale 密钥时 `next/` 与 `expired/` 不存在）。写入为原子操作（先写同目录 `.tmp` 再 rename），且先做 diff，使未变更的密钥不会被重写，从而避免读者看到半写文件并减少无谓的磁盘抖动。Ctrl-C 时守护进程会执行优雅的 serf 离开。

`<pk_hex>.meta.json` 字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `key_id` | 整数 | HPKE key ID（serf 生成的密钥恒为 `0`） |
| `public_key` | 十六进制字符串 | X25519 公钥，与文件名一致 |
| `kem` | 字符串 | KEM 算法 |
| `suites` | 数组 | KDF/AEAD 套件，每项为 `{ "kdf": ..., "aead": ... }` |
| `status` | 字符串 | `Active`、`Pending` 或 `Stale` |
| `actived_at` | RFC 3339 | 密钥激活时间 |
| `stale_at` | RFC 3339 | 密钥退役时间 |
| `expire_at` | RFC 3339 | 密钥从环中移除时间 |

`cluster.json` 字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `local_node_id` | 字符串 | 本节点的 serf 成员 id |
| `members` | 数组 | 在线成员列表，每项为 `{ "node_id": ..., "status": ... }` |

<details>
<summary>示例：双节点 key-sync 集群</summary>

先启动一个自举节点，再启动第二个节点加入它。两者都需要 AA 与 AS 以进行双向 RA-TLS。

```bash
# 节点 A（自举）
tng tools key-sync --host 0.0.0.0 --port 8301 \
  --rotation-interval 300 \
  --attest '{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}' \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}' \
  --out-dir /var/lib/tng/key-sync --ready-file /run/tng/key-sync.ready

# 节点 B（加入 A）
tng tools key-sync --host 0.0.0.0 --port 8301 \
  --peer 10.0.0.1:8301 --rotation-interval 300 \
  --attest '{"model":"background_check","aa_provider":"coco","aa_type":"uds","aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}' \
  --verify '{"model":"background_check","as_provider":"coco","as_type":"restful","as_addr":"http://127.0.0.1:8080","policy_ids":["default"],"as_headers":{}}' \
  --out-dir /var/lib/tng/key-sync --ready-file /run/tng/key-sync.ready
```

收敛后两节点在 `current/` 下导出相同的 active 密钥，一次轮转周期后两节点的 active 密钥同步更换。gossip 协议及加入/轮转细节见 [peer_shared.md](peer_shared_zh.md)。
</details>

---

## 平台支持

工具复用平台相关的 RA 与 TLS 栈，因此可用性因子命令与目标而异：

| 子命令 | 可用性 | 说明 |
|---|---|---|
| `rats-tls gen` | unix | 需要 AA 证明方（unix 限定） |
| `rats-tls dump` | 非 wasm | `--attest` 需要 unix 目标；在其他非 wasm 目标上请省略 |
| `rats-tls verify` | 非 wasm | wasm TLS 栈不构建验证器 |
| `ohttp dump` | 非 wasm | 使用 reqwest 与 tokio fs |
| `ohttp verify` | 非 wasm | 通过 reqwest 联系 AS |
| `key-sync` | 非 wasm（`__egress-common`） | 需要 AA+AS 证明栈以驱动 RA-TLS serf 传输 |

在子命令不可用的目标上，它会以清晰的报错在运行时退出，而非编译失败。
