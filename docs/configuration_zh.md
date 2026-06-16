# 参数手册

> 本文档描述 TNG 的全部 JSON 配置字段。所有字段均为可选，除非标注为"必填"。
>
> **提示**：如需快速上手，建议先阅读 [场景指南](scenarios/) 中的完整配置示例，再回到本文档查阅具体字段。

## 目录

- [顶层配置对象](#顶层配置对象)
- [Ingress（隧道入口）](#ingress隧道入口)
  - [通用字段](#ingress-通用字段)
  - [传输层通用配置](#rats-tls-传输配置)
  - [模式：mapping（端口映射）](#ingress-mapping端口映射)
  - [模式：http_proxy（HTTP 代理）](#ingress-http_proxyhttp-代理)
  - [模式：socks5（Socks5 代理）](#ingress-socks5socks5-代理)
  - [模式：netfilter（透明代理）](#ingress-netfilter透明代理)
- [Egress（隧道出口）](#egress隧道出口)
  - [通用字段](#egress-通用字段)
  - [direct_forward 规则](#direct_forward-规则)
  - [模式：mapping（端口映射）](#egress-mapping端口映射)
  - [模式：netfilter（端口劫持）](#egress-netfilter端口劫持)
- [远程证明（公共配置）](#远程证明公共配置)
  - [Provider 选择](#provider-选择)
  - [Attester 配置](#attester-配置)
    - [Background Check 模式](#attest-background-check-模式)
    - [Passport 模式](#attest-passport-模式)
  - [Verifier 配置](#verifier-配置)
    - [Background Check 模式](#verify-background-check-模式)
    - [Passport 模式](#verify-passport-模式)
  - [角色组合示例](#角色组合示例)
- [OHTTP 协议](#ohttp-协议)
  - [Ingress 侧配置](#ohttp-ingress-侧配置)
  - [Egress 侧配置](#ohttp-egress-侧配置)
  - [密钥管理](#ohttp-密钥管理)
    - [self_generated 模式](#ohttp-key-self_generated)
    - [peer_shared 模式](#ohttp-key-peer_shared)
    - [file 模式](#ohttp-key-file)
- [Control Interface](#control-interface)
  - [RESTful API](#restful-api)
- [废弃配置](#废弃配置)
- [可观测性](#可观测性)
  - [Log](#log)
  - [Metric](#metric)
  - [Trace](#trace)
- [附录：正则表达式语法](#附录正则表达式语法)

---

## 顶层配置对象

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `control_interface` | [ControlInterface](#control-interface) | 否 | 控制面配置 |
| `metrics` | [Metrics](#metric) | 否 | Metrics 配置，未指定时不启用 |
| `add_ingress` | array [[Ingress](#ingress隧道入口)] | 否 | 隧道入口端点列表 |
| `add_egress` | array [[Egress](#egress隧道出口)] | 否 | 隧道出口端点列表 |
| `admin_bind` | AdminBind | 否 | **已废弃** — 见 [废弃配置](#废弃配置) |

---

## Ingress（隧道入口）

`Ingress` 对象配置隧道的入口端点，控制流量如何进入隧道。

> **命名说明：** "Ingress" 表示流量**进入隧道**，而非 Kubernetes Ingress 中的"入站服务器"含义。

<a name="ingress-通用字段"></a>

### 通用字段

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `ingress_mode` | `mapping` \| `http_proxy` \| `netfilter` \| `socks5 | 无 | 流量入站方式。根据使用的模式，在对象中放置对应模式的键值 |
| `ohttp` | [OHttp](#ohttp-ingress-侧配置) | 无 | OHTTP 协议配置（与 `rats_tls` 互斥） |
| `rats_tls` | [RatsTlsArgs](#rats-tls-传输配置) | 无 | RA-TLS 传输配置（与 `ohttp` 互斥） |
| `no_ra` | boolean | `false` | 禁用远程证明（调试用，不可与 `attest`/`verify` 共存） |
| `attest` | [Attest](#attester-配置) | 无 | 在本端点扮演 Attester |
| `verify` | [Verify](#verifier-配置) | 无 | 在本端点扮演 Verifier |

> [!WARNING]
> `ohttp` 和 `rats_tls` 互斥。同一 Ingress/Egress 中同时指定两者将导致错误。

> [!TIP]
> 未指定 `ohttp` 和 `rats_tls` 时，默认使用 RA-TLS 模式。远程证明相关字段见 [远程证明（公共配置）](#远程证明公共配置) 章节。

### 传输层通用配置

以下字段在 Ingress 和 Egress 中共享，描述 RA-TLS 和 OHTTP 的传输层行为。

<a name="rats-tls-传输配置"></a>

#### RatsTlsArgs

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `multiplex` | boolean | `false` | `true` 时使用 HTTP/2 CONNECT 在单条 TLS 连接上复用多个 TCP 流，适合大量短连接；`false` 时每条连接独立 TLS 会话，单流吞吐量更高，推荐高带宽场景 |

---

<a name="ingress-mapping端口映射"></a>

### 模式：mapping（端口映射）

TNG 监听本地 TCP 端口 (`in.host`, `in.port`)，将流量加密后发送到指定目标 (`out.host`, `out.port`)。客户端需将请求目标改为 TNG 监听的地址。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `mapping` | object | 是 | 端口映射配置对象 |
| `mapping.in.host` | string | 否 (`0.0.0.0`) | 监听地址 |
| `mapping.in.port` | integer | 是 | 监听端口 |
| `mapping.out.host` | string | 是 | 目标地址 |
| `mapping.out.port` | integer | 是 | 目标端口 |

<details>
<summary>示例：mapping 模式</summary>

```json
{
    "add_ingress": [
        {
            "mapping": {
                "in": { "host": "0.0.0.0", "port": 10001 },
                "out": { "host": "127.0.0.1", "port": 20001 }
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": ["default"]
            }
        }
    ]
}
```
</details>

---

<a name="ingress-http_proxyhttp-代理"></a>

### 模式：http_proxy（HTTP 代理）

TNG 监听 HTTP 代理端口，客户端通过 `http_proxy` 环境变量将流量走代理到 TNG，TNG 加密后发送到原始目标。客户端无需修改请求目标。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `http_proxy` | object | 是 | HTTP 代理配置对象 |
| `http_proxy.proxy_listen.host` | string | 否 (`0.0.0.0`) | 监听地址 |
| `http_proxy.proxy_listen.port` | integer | 是 | 监听端口 |
| `http_proxy.dst_filters` | array [[EndpointFilter](#endpointfilter)] | 否 (`[]`) | 目标过滤规则，仅匹配的流量进入隧道 |
| `http_proxy.dst_filter` | EndpointFilter | — | **已废弃** — 被 `dst_filters` 替代 |

#### EndpointFilter

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `domain` | string | `*` | 匹配的目标域名（支持 `*` 通配符，不支持正则） |
| `domain_regex` | string | `.*` | 匹配的目标域名正则表达式（与 `domain` 互斥） |
| `port` | integer | `80` | 匹配的目标端口 |

> `domain` 通配符语法见 [Envoy VirtualHost domains](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost)。

<details>
<summary>示例：http_proxy 模式</summary>

```json
{
    "add_ingress": [
        {
            "http_proxy": {
                "proxy_listen": { "host": "0.0.0.0", "port": 41000 },
                "dst_filters": [
                    { "domain": "*.pai-eas.aliyuncs.com", "port": 80 }
                ]
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": ["default"]
            }
        }
    ]
}
```
</details>


---

<a name="ingress-socks5socks5-代理"></a>

### 模式：socks5（Socks5 代理）

TNG 创建本地 Socks5 代理端口，客户端连接到该代理，TNG 加密后发送到原始目标。客户端只需配置 socks5 代理选项，无需修改请求目标。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `socks5` | object | 是 | Socks5 代理配置对象 |
| `socks5.proxy_listen.host` | string | 否 (`0.0.0.0`) | 监听地址 |
| `socks5.proxy_listen.port` | integer | 是 | 监听端口 |
| `socks5.auth` | [Socks5Auth](#socks5auth) | 否 | 访问认证 |
| `socks5.dst_filters` | array [[EndpointFilter](#endpointfilter)] | 否 (`[]`) | 目标过滤规则 |

#### Socks5Auth

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `username` | string | 是 | 认证用户名 |
| `password` | string | 是 | 认证密码 |

> [!NOTE]
> **socks5 vs socks5h：** `socks5` 在客户端解析域名，`socks5h` 在代理服务器端解析。如果客户端使用 `socks5`，TNG 只能获得目标 IP 而非域名，可能导致 `dst_filters` 域名规则失效。大多数现代客户端（如 curl）支持 `socks5h`。

<details>
<summary>示例：socks5 模式（无认证）</summary>

```json
{
    "add_ingress": [
        {
            "socks5": {
                "proxy_listen": { "host": "0.0.0.0", "port": 1080 }
            },
            "verify": {
                "as_addr": "http://192.168.1.254:8080/",
                "policy_ids": ["default"]
            }
        }
    ]
}
```
</details>

<details>
<summary>示例：socks5 模式（带认证）</summary>

```json
{
    "add_ingress": [
        {
            "socks5": {
                "proxy_listen": { "host": "0.0.0.0", "port": 1080 },
                "auth": { "username": "user", "password": "ppppppwd" }
            },
            "verify": {
                "as_addr": "http://192.168.1.254:8080/",
                "policy_ids": ["default"]
            }
        }
    ]
}
```
</details>

<details>
<summary>示例：socks5 模式（带目标过滤）</summary>

```json
{
    "add_ingress": [
        {
            "socks5": {
                "proxy_listen": { "host": "0.0.0.0", "port": 1080 },
                "dst_filters": [
                    { "domain": "*.example.com", "port": 30001 }
                ]
            },
            "verify": {
                "as_addr": "http://192.168.1.254:8080/",
                "policy_ids": ["default"]
            }
        }
    ]
}
```
</details>

---

<a name="ingress-netfilter透明代理"></a>

### 模式：netfilter（透明代理）

TNG 监听本地端口，通过 iptables 规则将用户流量重定向到该端口，加密后发送到原始目标。客户端无需修改请求目标。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `netfilter` | object | 是 | netfilter 配置对象 |
| `netfilter.capture_dst` | array [[CaptureDst](#capturedst)] | 否 (`[]`) | 目标地址和端口捕获规则 |
| `netfilter.capture_cgroup` | array [string] | 否 (`[]`) | 需要捕获的 cgroup 路径列表 |
| `netfilter.nocapture_cgroup` | array [string] | 否 (`[]`) | 需要排除的 cgroup 路径列表 |
| `netfilter.listen_port` | integer | 否（随机分配） | TNG 监听端口，接收捕获后的流量 |
| `netfilter.so_mark` | integer | `565` | 密文流量 socket 的 SO_MARK 值，防止回环 |

#### CaptureDst

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `host` | string | 否 | 目标 IP 或 CIDR 段（与 `ipset` 二选一） |
| `ipset` | string | 否 | ipset 组名称（与 `host` 二选一） |
| `port` | integer | 否 | 目标端口 |
| `port_end` | integer | 否 | 与 `port` 配合，匹配连续端口段 `[port, port_end]` |

> [!NOTE]
> - `capture_cgroup` 和 `nocapture_cgroup` 仅在 cgroup v2 系统上受支持。
> - 由于 [netfilter 内核实现限制](https://github.com/torvalds/linux/blob/ec7714e4947909190ffb3041a03311a975350fe0/net/netfilter/xt_cgroup.c#L105)，cgroup 路径相对于 TNG 进程所在的 cgroup namespace。使用容器运行 TNG 时需配合 `--cgroupns=host`。

**流量捕获逻辑：**

```mermaid
flowchart TD
    A[开始] --> G{capture_cgroup 规则为空?}
    G --是--> D
    G --否--> B{匹配任意 capture_cgroup?}
    B --否--> C[忽略流量]
    B --是--> D{匹配任意 nocapture_cgroup?}
    D --是--> C
    D --否--> E{命中任意 capture_dst?}
    E --是--> F[捕获流量]
    E --否--> C
```

> **注意**：该模式仅捕获 TCP 流量，不捕获发往本机地址的流量。

<details>
<summary>示例：按目标 IP + 端口捕获</summary>

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    { "host": "127.0.0.1", "port": 30001 }
                ],
                "capture_cgroup": ["/tng_capture.slice"],
                "nocapture_cgroup": ["/tng_nocapture.slice"],
                "listen_port": 50000
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": ["default"]
            }
        }
    ]
}
```
</details>

<details>
<summary>示例：按 CIDR 网段捕获</summary>

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    { "host": "192.168.1.0/24", "port": 30001 }
                ],
                "capture_cgroup": ["/tng_capture.slice"],
                "nocapture_cgroup": ["/tng_nocapture.slice"],
                "listen_port": 50000
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": ["default"]
            }
        }
    ]
}
```
</details>

<details>
<summary>示例：按 ipset 捕获</summary>

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    { "ipset": "myset1", "port": 30001 },
                    { "ipset": "myset2", "port": 30001 }
                ],
                "capture_cgroup": ["/tng_capture.slice"],
                "nocapture_cgroup": ["/tng_nocapture.slice"],
                "listen_port": 50000
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": ["default"]
            }
        }
    ]
}
```
</details>

<details>
<summary>示例：使用 port_end 捕获连续端口段</summary>

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    { "host": "192.168.1.1", "port": 30000, "port_end": 30031 }
                ],
                "listen_port": 50000
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": ["default"]
            }
        }
    ]
}
```
</details>


---

## Egress（隧道出口）

`Egress` 对象配置隧道的出口端点，控制流量如何从隧道流出。

<a name="egress-通用字段"></a>

### 通用字段

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `egress_mode` | `mapping` \| `netfilter` | 无 | 流量出站方式。根据使用的模式，在对象中放置对应模式的键值 |
| `direct_forward` | array [[DirectForwardRule](#direct_forward-规则)] | 否 | 直接转发（不解密）规则 |
| `ohttp` | [OHttp](#ohttp-egress-侧配置) | 无 | OHTTP 协议配置（与 `rats_tls` 互斥） |
| `rats_tls` | [RatsTlsArgs](#rats-tls-传输配置) | 无 | RA-TLS 传输配置（与 `ohttp` 互斥） |
| `no_ra` | boolean | `false` | 禁用远程证明（调试用，不可与 `attest`/`verify` 共存） |
| `attest` | [Attest](#attester-配置) | 无 | 在本端点扮演 Attester |
| `verify` | [Verify](#verifier-配置) | 无 | 在本端点扮演 Verifier |

> `rats_tls.multiplex` 等传输层字段与 Ingress 共用同一组定义，见 [RatsTlsArgs](#rats-tls-传输配置)。

<a name="direct_forward-规则"></a>

### direct_forward 规则

某些场景下需要在加密流量旁放行普通流量（如 healthcheck）。`direct_forward` 指定匹配规则，任一规则匹配则流量不解密直接转发。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `http_path` | string | 是 | 正则表达式，匹配 HTTP 请求 URI 的 [Path](https://developer.mozilla.org/zh-CN/docs/Web/API/URL/pathname) |

<details>
<summary>示例：放行 /public/* 路径的明文请求</summary>

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [{ "port": 30001 }]
            },
            "direct_forward": [
                { "http_path": "/public/.*" }
            ],
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```

此 egress 在允许加密流量访问 30001 端口的同时，放行路径匹配 `/public/.*` 的未加密请求。
</details>

---

<a name="egress-mapping端口映射"></a>

### 模式：mapping（端口映射）

TNG 监听本地端口 (`in.host`, `in.port`)，将解密后的流量发送到目标端点 (`out.host`, `out.port`)。服务端程序需监听在 TNG 解密后转发的目标地址上。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `mapping` | object | 是 | 端口映射配置对象 |
| `mapping.in.host` | string | 否 (`0.0.0.0`) | 监听地址 |
| `mapping.in.port` | integer | 是 | 监听端口 |
| `mapping.out.host` | string | 是 | 目标地址 |
| `mapping.out.port` | integer | 是 | 目标端口 |

<details>
<summary>示例：egress mapping 模式</summary>

```json
{
    "add_egress": [
        {
            "mapping": {
                "in": { "host": "127.0.0.1", "port": 20001 },
                "out": { "host": "127.0.0.1", "port": 30001 }
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```
</details>

---

<a name="egress-netfilter端口劫持"></a>

### 模式：netfilter（端口劫持）

TNG 通过内核 netfilter 拦截**来自其他节点发往指定端口**的入站流量，重定向到 TNG 监听的 `listen_port`。TNG 解密后将明文流量发回本机原始服务端口。

适用于服务端已监听某端口且不便变更端口的场景。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `netfilter` | object | 是 | netfilter 配置对象 |
| `netfilter.capture_dst` | array [[CaptureDst](#capturedst)] | 否 (`[]`) | 目标地址和端口捕获规则（为空时捕获所有 TCP） |
| `netfilter.capture_cgroup` | array [string] | 否 (`[]`) | 需要捕获的 cgroup 路径列表 |
| `netfilter.nocapture_cgroup` | array [string] | 否 (`[]`) | 需要排除的 cgroup 路径列表 |
| `netfilter.capture_local_traffic` | boolean | `false` | 是否捕获源 IP 为本机的流量 |
| `netfilter.listen_port` | integer | 否（从 40000 递增） | TNG 监听端口，接收重定向流量 |
| `netfilter.so_mark` | integer | `565` | 解密后明文流量的 socket SO_MARK 值，防止回环 |

> [!NOTE]
> - `capture_cgroup` 和 `nocapture_cgroup` 仅在 cgroup v2 系统上受支持。
> - 由于 [netfilter 内核实现限制](https://github.com/torvalds/linux/blob/ec7714e4947909190ffb3041a03311a975350fe0/net/netfilter/xt_cgroup.c#L105)，cgroup 路径相对于 TNG 进程所在的 cgroup namespace。容器运行 TNG 时需配合 `--cgroupns=host`。

**流量捕获逻辑：**

```mermaid
flowchart TD
    A[开始] --> G{capture_cgroup 规则为空?}
    G --是--> D
    G --否--> B{匹配任意 capture_cgroup?}
    B --否--> C[忽略流量]
    B --是--> D{匹配任意 nocapture_cgroup?}
    D --是--> C
    D --否--> E{命中任意 capture_dst?}
    E --是--> F[捕获流量]
    E --否--> C
```

> **注意**：该模式仅捕获 TCP 流量，不捕获发往本机地址的流量（除非 `capture_local_traffic: true`）。

<details>
<summary>示例：捕获目标端口 30001 的入站流量</summary>

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [{ "port": 30001 }],
                "capture_local_traffic": true,
                "listen_port": 40000,
                "so_mark": 565
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```
</details>

<details>
<summary>示例：按特定 IP 和端口捕获</summary>

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [{ "host": "127.0.0.1", "port": 30001 }],
                "capture_local_traffic": false,
                "listen_port": 40000,
                "so_mark": 565
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```
</details>

<details>
<summary>示例：按 cgroup + 多端口捕获</summary>

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [
                    { "port": 30001 },
                    { "host": "192.168.1.1", "port": 30002 }
                ],
                "capture_cgroup": ["/vllm.slice"],
                "nocapture_cgroup": ["/system.slice"],
                "capture_local_traffic": true,
                "listen_port": 40000,
                "so_mark": 565
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```
</details>

<details>
<summary>示例：使用 port_end 捕获连续端口段</summary>

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [{ "port": 30000, "port_end": 30031 }],
                "listen_port": 40000,
                "so_mark": 565
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```
</details>

<details>
<summary>示例：捕获所有入站 TCP 流量</summary>

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [],
                "capture_local_traffic": false,
                "listen_port": 40000,
                "so_mark": 565
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```
</details>


---

<a name="远程证明公共配置"></a>

## 远程证明（公共配置）

远程证明是可信计算的核心安全机制之一，用于验证远程系统的运行时完整性与可信状态。通过密码学手段，一个系统（**Attester**）可以生成描述其软硬件配置的"证据"（Evidence），另一个系统（**Verifier**）则可对该证据进行验证，确保其来自合法、未被篡改的可信执行环境（TEE）。

<a name="provider-选择"></a>

### Provider 选择

Attestation Agent 栈和 Attestation Service 栈分别通过 **`aa_provider`** 和 **`as_provider`** 进行选择。省略时默认为 **`"coco"`**（Confidential Containers）。

| Provider | 用途 | 说明 |
|---|---|---|
| `"coco"` | `aa_provider` / `as_provider` | 默认。与 CoCo AA 和 CoCo AS 对接 |
| `"ita"` | `aa_provider` / `as_provider` | 与 CoCo AA 对接收集证据，与 Intel Trust Authority 云服务对接验证 |
| `"coco_asr"` | 仅 `aa_provider` | 通过 CoCo [API Server Rest](https://github.com/confidential-containers/guest-components/tree/main/api-server-rest) (ASR) HTTP 代理收集证据，适用于 TNG 运行在容器中无法直接访问 AA Unix socket |
| `"ita_asr"` | 仅 `aa_provider` | 与 `"ita"` 相同，但通过 ASR HTTP 代理收集证据 |

<a name="attester-配置"></a>

### Attester 配置

**Attester** 是被验证的一方，负责收集本地平台的可信状态信息并生成加密证据（Evidence）。

<a name="attest-background-check-模式"></a>

#### Background Check 模式

[Background Check](https://datatracker.ietf.org/doc/html/rfc9334#name-background-check-model) 是 TNG 默认的远程证明模式。证明方通过 Attestation Agent 获取证据，验证方直接验证。

> [!NOTE]
> 未指定 `"model"` 字段时，TNG 自动使用 Background Check 模式。

**CoCo Provider（`aa_provider` = `"coco"` 或省略）：**

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `model` | string | — | 设为 `"background_check"` 显式启用 |
| `aa_type` | string | `"uds"` | Agent 类型：`"uds"` / `"builtin"` |
| `aa_addr` | string | — | `"uds"` 类型必填，AA 的 Unix socket 地址 |
| `refresh_interval` | int | `600` | Evidence 缓存时间（秒），`0` 表示每次获取最新 |

通过 ASR HTTP 代理时，设置 `aa_provider` = `"coco_asr"` 并提供 `asr_addr` 代替 `aa_addr`。

<details>
<summary>示例：Background Check Attest（CoCo）</summary>

```json
"attest": {
    "aa_type": "uds",
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
}
```

```json
"attest": {
    "model": "background_check",
    "aa_type": "uds",
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
    "refresh_interval": 3600
}
```

通过 ASR 代理：
```json
"attest": {
    "aa_provider": "coco_asr",
    "asr_addr": "http://127.0.0.1:8006"
}
```
</details>

**ITA Provider（`aa_provider` = `"ita"`）：**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `aa_provider` | string | 是 | 设为 `"ita"` |
| `aa_addr` | string | 是 | AA Unix socket 地址 |
| `refresh_interval` | int | `600` | 同上 |

通过 ASR 代理时，设置 `aa_provider` = `"ita_asr"` 并提供 `asr_addr`。

<details>
<summary>示例：ITA Provider</summary>

```json
"attest": {
    "aa_provider": "ita",
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
}
```

通过 ASR 代理：
```json
"attest": {
    "aa_provider": "ita_asr",
    "asr_addr": "http://127.0.0.1:8006"
}
```
</details>

<a name="attest-passport-模式"></a>

#### Passport 模式

除了 Background Check 模式外，TNG 还支持符合 [RATS RFC 9334 文档](https://datatracker.ietf.org/doc/html/rfc9334) 中定义的 [Passport 模式](https://datatracker.ietf.org/doc/html/rfc9334#name-passport-model) 的远程证明。在 Passport 模式中，证明方（Attester）通过 Attestation Agent 获取证明，并将其提交给 Attestation Service 获取 Token（即 Passport）。验证方（Verifier）只需验证该 Token 的有效性，而无需直接与 Attestation Service 交互。

Passport 模式适用于网络隔离或性能要求较高的场景，因为它减少了验证方与 Attestation Service 之间的交互。

> [!NOTE]
> 在许多场景中，Passport 模式也称为"护照模型"

##### CoCo Provider

在 Passport 模式下，[Attest](#attester-配置) 配置需要包含以下字段。以下字段适用于默认 CoCo Provider（`aa_provider` = `"coco"` 或省略，`as_provider` = `"coco"` 或省略）：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `model` | string | — | 设为 `"passport"` 以启用 Passport 模式 |
| `aa_type` | string | `"uds"` | Agent 类型：`"uds"` / `"builtin"` |
| `aa_addr` | string | — | `"uds"` 类型必填，AA 的 Unix socket 地址 |
| `refresh_interval` | int | `600` | Evidence 缓存时间（秒），`0` 表示每次获取最新 |
| `as_type` | string | `"restful"` | AS 类型：`"restful"` / `"grpc"` |
| `as_addr` | string | — | Attestation Service 地址 |
| `as_headers` | object | `{}` | 发送到 AS 的自定义头部（如 Authorization） |
| `policy_ids` | array [string] | — | 策略 ID 列表 |

与 Background Check 模式一样，您可以使用 `aa_provider` = `"coco_asr"` 配合 `asr_addr` 代替 `aa_addr`，通过 ASR HTTP 代理收集证据。

<details>
<summary>示例：Passport Attest（CoCo）</summary>

```json
"attest": {
    "model": "passport",
    "aa_type": "uds",
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
    "refresh_interval": 3600,
    "as_type": "restful",
    "as_addr": "http://127.0.0.1:8080/",
    "as_headers": {
        "Authorization": "Bearer your-token-here",
        "X-Custom-Header": "custom-value"
    },
    "policy_ids": [
        "default"
    ]
}
```
</details>

##### ITA Provider

当 `aa_provider` 和 `as_provider` 设置为 `"ita"` 时，Attest 配置使用以下字段：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `model` | string | 是 | 设为 `"passport"` |
| `aa_provider` | string | 是 | 设为 `"ita"` |
| `aa_addr` | string | 是 | AA Unix socket 地址 |
| `as_provider` | string | 是 | 设为 `"ita"` |
| `as_addr` | string | `https://api.trustauthority.intel.com` | ITA API 基础 URL |
| `api_key` | string | 否 | ITA API 密钥（也可通过 `ITA_API_KEY` 环境变量设置） |
| `policy_ids` | array [string] | `[]` | ITA 策略 ID 列表 |

与 Background Check 模式一样，您可以使用 `aa_provider` = `"ita_asr"` 配合 `asr_addr` 代替 `aa_addr`，通过 ASR HTTP 代理收集证据。

<details>
<summary>示例：Passport Attest（ITA）</summary>

```json
"attest": {
    "model": "passport",
    "aa_provider": "ita",
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
- **`ita_jwks_addr`** (string，可选，默认为 `"https://portal.trustauthority.intel.com"`): Intel Trust Authority 门户 URL，用于获取 JWKS 签名密钥以进行 Token 验证
- **`policy_ids`** (array [string]，可选，默认为空)：ITA 策略 ID 列表，attestation 成功必须匹配这些策略

示例：

```json
"verify": {
    "as_provider": "ita",
    "api_key": "your-ita-api-key",
    "policy_ids": ["my-policy"]
}
```
</details>

<a name="verifier-配置"></a>

### Verifier 配置

**Verifier** 负责接收并验证来自 Attester 的 Evidence，只有证据符合预设信任策略时才认定对端可信。

<a name="verify-background-check-模式"></a>

#### Background Check 模式

**CoCo Provider（`as_provider` = `"coco"` 或省略）：**

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `model` | string | — | 设为 `"background_check"` 显式启用 |
| `as_type` | string | `"restful"` | AS 类型：`"restful"` / `"grpc"` / `"builtin"` |
| `as_addr` | string | — | `"restful"` 和 `"grpc"` 类型必填，AS 地址 |
| `as_headers` | object | `{}` | 发送到 AS 的自定义头部（如 Authorization） |
| `attestation_policy` | object | — | `"builtin"` 类型可选，内置 AS 的证明策略配置。省略时默认为 `{"type": "default"}` |
| `reference_values` | array | — | `"builtin"` 类型可选，内置 AS 的参考值配置列表 |
| `policy_ids` | array [string] | 是 | 策略 ID 列表。仅 `"restful"` 和 `"grpc"` 类型使用，`as_type` 为 `"builtin"` 时被忽略 |
| `trusted_certs_paths` | array [string] | `[]` | 验证 Attestation Token 签名的根 CA 证书路径 |
| `verify_signer_transparency` | boolean | `false` | 验证 Trustee AS 签发的 JWT token 中的 `signer_transparency` 声明（仅 COCO 外部 AS，不适用于 builtin AS） |
| `skip_as_token_cert_verify` | boolean | `false` | **危险：** 跳过 AS token 证书验证，不验证 token 签名证书。开启时不能设置 `trusted_certs_paths`，护照模式下也不能设置 `as_addr`。仅在完全信任 token 来源时使用。 |

> **`verify_signer_transparency` 说明**：当 Trustee 运行在不可信服务商托管的 TEE 内时，其 JWT 签名证书缺乏内生可信机制。`signer_transparency` 功能通过将签名证书与 TEE 证据绑定并记录到 Rekor v2 透明度日志中来解决此问题。验证内容包括证书 DER SHA-256 匹配、report_data 绑定、Rekor 检查点签名验证等。完整规范见 [Trustee AS signer transparency 文档](https://github.com/openanolis/trustee/blob/main/attestation-service/docs/as_signer_transparency.md)。

<details>
<summary>示例：Restful AS</summary>

```json
"verify": {
    "as_addr": "http://127.0.0.1:8080/",
    "as_headers": {
        "Authorization": "Bearer your-token-here"
    },
    "policy_ids": ["default"]
}
```
</details>

<details>
<summary>示例：gRPC AS</summary>

```json
"verify": {
    "as_type": "grpc",
    "as_addr": "http://127.0.0.1:5000/",
    "policy_ids": ["default"]
}
```
</details>

<details>
<summary>示例：Builtin AS</summary>

```json
"verify": {
    "as_type": "builtin",
    "attestation_policy": {
        "type": "default"
    },
    "reference_values": []
}
```
</details>

<details>
<summary>示例：指定根证书路径</summary>

```json
"verify": {
    "as_addr": "http://127.0.0.1:8080/",
    "policy_ids": ["default"],
    "trusted_certs_paths": ["/tmp/as-ca.pem"]
}
```
</details>

**ITA Provider（`as_provider` = `"ita"`）：**

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `as_provider` | string | 是 | 设为 `"ita"` |
| `as_addr` | string | `https://api.trustauthority.intel.com` | ITA API 基础 URL |
| `api_key` | string | 否 | ITA API 密钥（也可通过 `ITA_API_KEY` 环境变量设置） |
| `ita_jwks_addr` | string | `https://portal.trustauthority.intel.com` | ITA 门户 URL，用于获取 JWKS |
| `policy_ids` | array [string] | `[]` | ITA 策略 ID 列表 |

> 推荐通过 `ITA_API_KEY` 环境变量设置 API 密钥，而非写入配置文件。

**Builtin AS（`as_type` = `"builtin"`）：**

`as_type` = `"builtin"` 时，TNG 使用内置 AS 在本地直接验证 Evidence，无需连接外部 AS。适用于网络隔离、延迟敏感或简化部署的场景。

> [!NOTE]
> Builtin 模式需在编译时启用对应 TEE 特性（`builtin-as-tdx`、`builtin-as-sgx` 或 `builtin-as-snp`）。GitHub CI 构建的 RPM 包和二进制产物不支持此模式，仅容器镜像支持。
>
> 对于 SGX/TDX 内置 AS 模式，还需为云服务商配置 `/etc/sgx_default_qcnl.conf` 中的 PCCS URL。详见 [Vendor Configuration Setup](setup-vendor-config.md)。

**PolicyConfig（OPA 策略）：**

| type | 说明 |
|---|---|
| `"default"` | 使用 attestation-service 内置的默认策略，对 TEE 硬件和软件进行详尽度量验证 |
| `"inline"` | 内联策略，需提供 `content`（Base64 编码的 OPA 策略内容） |
| `"path"` | 文件路径策略，需提供 `path`（OPA 策略文件路径） |

**ReferenceValueConfig（参考值来源）：**

| type | 说明 |
|---|---|
| `"sample"` | 直接提供参考值 payload（`payload` 为 `SampleProvenancePayloadConfig`） |
| `"slsa"` | 从 Rekor 透明日志获取 SLSA provenance（历史兼容） |
| `"release_manifest"` | **推荐**：从 RV release manifest bundle 获取参考值 |

**Payload 加载方式：** 每种参考值类型均支持 `"inline"`（内联 content）和 `"path"`（从文件加载）两种方式。

`Provenance` 格式（sample inline）：
```json
{
  "measurement.uki.SHA-384": [
    "a46e162a57e072be7f660e65504477c646acf6b3bfea4ffc0e3a8ee4f2c2726c2284c8bf1ec2b3bd95b204fe7f4e899c"
  ]
}
```

`ReferenceValueListPayload` 格式（release_manifest / slsa）：
```json
{
    "rv_list": [
        {
            "id": "cvm_container_proxy",
            "version": "1.0.0",
            "type": "container",
            "provenance_info": {
                "type": "rv-release-manifest",
                "rekor_url": "https://log2025-1.rekor.sigstore.dev",
                "rekor_api_version": 2
            },
            "provenance_source": {
                "protocol": "oci",
                "uri": "oci://registry/repo:tag",
                "artifact": "bundle"
            },
            "operation_type": "refresh"
        }
    ]
}
```

<details>
<summary>示例1：Sample 模式提供参考值</summary>

```json
{
    "verify": {
        "as_type": "builtin",
        "attestation_policy": {
            "type": "inline",
            "content": "cGFja2FnZSBwb2xpY3kKZGVmYXVsdCBhbGxvdyA9IHRydWU="
        },
        "reference_values": [
            {
                "type": "sample",
                "payload": {
                    "type": "path",
                    "path": "/etc/tng/tdx-reference-values.json"
                }
            }
        ]
    }
}
```

`/etc/tng/tdx-reference-values.json`：
```json
{
    "tdx": {
        "quote": {
            "body": {
                "mr_td": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    }
}
```
</details>

<details>
<summary>示例2：SLSA 模式（历史兼容）</summary>

```json
{
    "verify": {
        "as_type": "builtin",
        "attestation_policy": {
            "type": "default"
        },
        "reference_values": [
            {
                "type": "slsa",
                "payload": {
                    "type": "inline",
                    "content": {
                        "rv_list": [
                            {
                                "id": "my-artifact",
                                "version": "1.0.0",
                                "type": "binary",
                                "provenance_info": {
                                    "type": "slsa-intoto-statements",
                                    "rekor_url": "https://log2025-1.rekor.sigstore.dev"
                                },
                                "operation_type": "add"
                            }
                        ]
                    }
                }
            }
        ]
    }
}
```
</details>

<details>
<summary>示例3：Release Manifest 模式（推荐）</summary>

```json
{
    "verify": {
        "as_type": "builtin",
        "attestation_policy": {
            "type": "default"
        },
        "reference_values": [
            {
                "type": "release_manifest",
                "payload": {
                    "type": "inline",
                    "content": {
                        "rv_list": [
                            {
                                "id": "cvm_container_proxy",
                                "version": "1.0.0",
                                "type": "container",
                                "provenance_info": {
                                    "type": "rv-release-manifest",
                                    "rekor_url": "https://log2025-1.rekor.sigstore.dev",
                                    "rekor_api_version": 2
                                },
                                "provenance_source": {
                                    "protocol": "oci",
                                    "uri": "oci://registry/trustee/provenance:cvm_container_proxy-1.0.0",
                                    "artifact": "bundle"
                                },
                                "operation_type": "refresh"
                            }
                        ]
                    }
                }
            }
        ]
    }
}
```
</details>

<a name="verify-passport-模式"></a>

#### Passport 模式

在 Passport 模式下，[Verify](#verifier-配置) 配置需要包含以下字段。以下字段适用于默认 CoCo Provider（`as_provider` = `"coco"` 或省略）：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `model` | string | — | 设为 `"passport"` 以启用 Passport 模式 |
| `as_type` | string | `"restful"` | AS 类型：`"restful"` / `"grpc"` |
| `as_addr` | string | — | Attestation Service 地址（可选，但 `as_addr` 或 `trusted_certs_paths` 至少需指定一个） |
| `as_headers` | object | `{}` | 发送到 AS 的自定义头部（如 Authorization） |
| `policy_ids` | array [string] | — | 策略 ID 列表 |
| `trusted_certs_paths` | array [string] | `[]` | 验证 Attestation Token 签名的根 CA 证书路径 |
| `verify_signer_transparency` | boolean | `false` | 验证 Trustee AS 签发的 JWT token 中的 `signer_transparency` 声明 |
| `skip_as_token_cert_verify` | boolean | `false` | **危险：** 跳过 AS token 证书验证，不验证 token 签名证书。开启时不能设置 `trusted_certs_paths` 和 `as_addr`。仅在完全信任 token 来源时使用。 |

<details>
<summary>示例：Passport Verify（CoCo）</summary>

```json
"verify": {
    "model": "passport",
    "as_addr": "http://127.0.0.1:8080/",
    "policy_ids": [
        "default"
    ],
    "trusted_certs_paths": [
        "/tmp/as-ca.pem"
    ]
}
```
</details>

<details>
<summary>示例：Passport 模式下跳过证书验证</summary>

```json
"verify": {
    "model": "passport",
    "policy_ids": [
        "default"
    ],
    "skip_as_token_cert_verify": true
}
```

> [!WARNING]
> 此示例完全跳过了 token 证书验证。仅在完全信任 token 来源（例如 token 来自受控环境中的可信 trustee）时使用。
</details>

##### ITA Provider

当 `as_provider` 设置为 `"ita"` 时，Verify 配置使用以下字段：

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `model` | string | — | 设为 `"passport"` |
| `as_provider` | string | 是 | 设为 `"ita"` |
| `ita_jwks_addr` | string | `https://portal.trustauthority.intel.com` | ITA 门户 URL，用于获取 JWKS |
| `policy_ids` | array [string] | `[]` | ITA 策略 ID 列表 |

<details>
<summary>示例：Passport Verify（ITA）</summary>

```json
"verify": {
    "model": "passport",
    "as_provider": "ita",
    "policy_ids": ["my-policy"]
}
```
</details>

<a name="角色组合示例"></a>

### 角色组合示例

TNG 在每个 Ingress/Egress 上通过 `no_ra`、`attest`、`verify` 三类字段控制远程证明角色。

| 场景 | 客户端配置 | 服务端配置 | 说明 |
|---|---|---|---|
| 单向 | `verify` | `attest` | 最常见，服务端在 TEE 中 |
| 双向 | `attest` + `verify` | `attest` + `verify` | 两端都在不同 TEE 中 |
| 逆单向 | `attest` | `verify` | 客户端在 TEE 中，服务端用内嵌固定证书 |
| 无 TEE（调试） | `no_ra` | `no_ra` | 非 TEE 环境，建立普通 TLS 会话 |

---

## OHTTP 协议

OHTTP (Oblivious HTTP) 是一种旨在增强隐私保护的网络协议扩展，通过在HTTP请求层面进行加密，提供端到端的隐私保护和匿名性增强。TNG可利用OHTTP提供安全通信，同时保持与现有HTTP基础设施的兼容性。

在默认情况下，TNG使用rats-tls协议提供TCP流级别的加密保护，这适用于大多数情况。如果需要启用该特性，可以通过分别在Ingress中配置`ohttp`和在Egress中配置`ohttp`来实现切换为OHTTP协议。

> [!WARNING]  
> 如果启用OHTTP特性，则要求内层被保护的业务必须是http流量，而不能是普通的tcp流量。



<a name="ohttp-ingress-侧配置"></a>

### Ingress 侧配置

在 `add_ingress` 中指定 `ohttp` 字段开启 OHTTP。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `path_rewrites` | array [[PathRewrite](#pathrewrite)] | `[]` | Path 重写规则列表，按顺序匹配 |

#### PathRewrite

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `match_regex` | string | 是 | 匹配内层 HTTP 请求 path 的正则表达式（整串匹配） |
| `substitution` | string | 是 | 替换后的 path，支持 `$1` / `$name` 引用捕获组 |

> 2.0.0+ 使用 Rust regex 的 `$ref` 语法引用捕获组（向后兼容 `\整数`）。

<details>
<summary>示例：OHTTP path 重写</summary>

```json
{
    "add_ingress": [
        {
            "mapping": {
                "in": { "host": "0.0.0.0", "port": 10001 },
                "out": { "host": "127.0.0.1", "port": 20001 }
            },
            "ohttp": {
                "path_rewrites": [
                    {
                        "match_regex": "^/foo/bar/([^/]+)([/]?.*)$",
                        "substitution": "/foo/bar/$1"
                    }
                ]
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": ["default"]
            }
        }
    ]
}
```
</details>

#### L7 网关兼容性

OHTTP 加密后的 HTTP 请求遵循以下规则，以便与 L7 负载均衡器配合使用：

1. Method 统一为 `POST`
2. Path 默认为 `/`，可通过 `path_rewrites` 重写
3. Host（或 `:authority`）与内层业务请求保持一致
4. `Content-Type` 分别为 `message/ohttp-chunked-req` 和 `message/ohttp-chunked-res`
5. 不包含被加密请求的原始请求头和响应头


<a name="ohttp-egress-侧配置"></a>

### Egress 侧配置

与 Ingress 对应，在 `add_egress` 中指定 `ohttp` 字段开启 OHTTP。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `cors` | [CorsConfig](#corsconfig) | 无 | CORS 配置，用于浏览器端访问 OHTTP 端点 |
| `key` | [KeyConfig](#ohttp-密钥管理) | 无 | 密钥管理配置（见下方 [密钥管理](#ohttp-密钥管理)） |

> [!NOTE]
> `allow_non_tng_traffic_regexes` 在 2.2.4+ 已弃用，请使用 `direct_forward` 替代。

#### CorsConfig

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `allow_origins` | array [string] | `[]` | 允许的来源，`["*"]` 允许所有 |
| `allow_methods` | array [string] | `[]` | 允许的 HTTP 方法，`["*"]` 允许所有 |
| `allow_headers` | array [string] | `[]` | 允许的请求头，`["*"]` 允许所有 |
| `expose_headers` | array [string] | `[]` | 允许浏览器访问的响应头 |
| `allow_credentials` | boolean | `false` | 是否允许携带凭证 |

<details>
<summary>示例：OHTTP + CORS</summary>

```json
{
    "add_egress": [
        {
            "mapping": {
                "in": { "host": "127.0.0.1", "port": 20001 },
                "out": { "host": "127.0.0.1", "port": 30001 }
            },
            "ohttp": {
                "cors": {
                    "allow_origins": ["https://example.com"],
                    "allow_methods": ["GET", "POST"],
                    "allow_headers": ["Content-Type", "Authorization"],
                    "allow_credentials": true
                }
            },
            "direct_forward": [
                { "http_path": "/api/builtin/.*" }
            ],
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```
</details>

<a name="ohttp-密钥管理"></a>

### 密钥管理

TNG 支持三种 OHTTP 密钥管理策略。

<a name="ohttp-key-self_generated"></a>

#### self_generated 模式（默认）

TNG 自主生成 HPKE 密钥对并自动轮换。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `key.source` | string | `"self_generated"` | 密钥来源 |
| `key.rotation_interval` | integer | `300` | 轮换周期（秒） |

<details>
<summary>示例</summary>

```json
{
    "add_egress": [
        {
            "netfilter": { "capture_dst": [{ "port": 8080 }] },
            "ohttp": {
                "key": {
                    "source": "self_generated",
                    "rotation_interval": 300
                }
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```
</details>

<a name="ohttp-key-peer_shared"></a>

#### peer_shared 模式

多个 TNG 实例通过基于 Serf Gossip 协议的 QUIC 加密通道共享密钥，仅经远程证明验证的可信节点可参与密钥交换。有关协议设计、密钥轮换机制和异常处理的详细说明，请参考 [Peer Shared 密钥共享协议](./peer_shared_zh.md)。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `key.source` | string | `"peer_shared"` | 密钥来源 |
| `key.rotation_interval` | integer | `300` | 轮换周期（秒） |
| `key.host` | string | `0.0.0.0` | Serf 监听地址 |
| `key.port` | integer | `8301` | Serf UDP 端口 |
| `key.peers` | array [string] | — | 初始 peer 节点列表（`IP:port` 或 `domain:port`） |
| `key.peers_file` | string | 无 | 动态更新节点列表的 JSON 文件路径 |
| `key.attest` | object | 无 | 节点证明自身身份的配置 |
| `key.verify` | object | 无 | 验证远程对等节点身份的配置 |
| `key.no_ra` | boolean | `false` | 禁用节点间远程证明 |

<details>
<summary>示例</summary>

```json
{
    "add_egress": [
        {
            "netfilter": { "capture_dst": [{ "port": 8080 }] },
            "ohttp": {
                "key": {
                    "source": "peer_shared",
                    "rotation_interval": 300,
                    "host": "0.0.0.0",
                    "port": 8301,
                    "peers": [
                        "192.168.10.1:8301",
                        "tng-service.default.svc.cluster.local:8301"
                    ],
                    "peers_file": "/etc/tng/peers.json",
                    "attest": {
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                    },
                    "verify": {
                        "as_addr": "http://as.example.com:8080/",
                        "policy_ids": ["default"]
                    }
                }
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```
</details>

<a name="ohttp-key-file"></a>

#### file 模式

从外部文件加载 OHTTP HPKE 私钥，适用于与外部密钥管理系统集成。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `key.source` | string | 是 | 设为 `"file"` |
| `key.path` | string | 是 | PEM 格式 PKCS#8 X25519 私钥文件路径 |

文件格式示例：
```pem
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEILi5PepL11X3ptJneUQu40m2kiuNeLD9MRK4CYh94t1d
-----END PRIVATE KEY-----
```

通过 `openssl genpkey -algorithm X25519 -outform PEM` 生成。TNG 使用 inotify 监听文件变化并自动重新加载。

<details>
<summary>示例</summary>

```json
{
    "add_egress": [
        {
            "netfilter": { "capture_dst": [{ "port": 8080 }] },
            "ohttp": {
                "key": {
                    "source": "file",
                    "path": "/etc/tng/ohttp-key.pem"
                }
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```
</details>

## Control Interface

> [!NOTE]
> 该接口与 [废弃配置](#废弃配置) 中的 Envoy Admin Interface 完全不同。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `control_interface.restful.host` | string | `0.0.0.0` | 监听地址 |
| `control_interface.restful.port` | integer | — | 监听端口（必填） |

<details>
<summary>示例</summary>

```json
"control_interface": {
    "restful": {
        "host": "0.0.0.0",
        "port": 50000
    }
}
```
</details>

### RESTful API

| 端点 | 说明 |
|---|---|
| `/livez` | 存活检查，返回 `200 OK` 表示实例正在运行 |
| `/readyz` | 就绪检查，返回 `200 OK` 表示实例可以处理流量 |
| `/status/` | 返回可用组件类型列表（如 `["egress", "ingress"]`） |
| `/status/egress/` | 返回 egress 实例 ID 列表 |
| `/status/egress/{id}/` | 返回指定 egress 的资源列表 |
| `/status/egress/{id}/ohttp/keys` | 返回 egress 的 OHTTP 密钥状态快照 |
| `/status/ingress/` | 返回 ingress 实例 ID 列表 |
| `/status/ingress/{id}/ohttp/keys` | 返回 ingress OHTTP 客户端缓存状态 |

---

<a name="废弃配置"></a>

## 废弃配置

<a name="envoy_admin_interface"></a>

### admin_bind（Envoy Admin Interface）

> [!WARNING]
> 已弃用。TNG 已放弃与 Envoy 的集成，配置此选项无任何效果。

| 字段 | 类型 | 说明 |
|---|---|---|
| `admin_bind.host` | string | 监听地址，默认 `0.0.0.0` |
| `admin_bind.port` | integer | 监听端口（必填） |

> 该端口不使用身份验证，请勿在生产环境中使用。

<details>
<summary>示例（已弃用）</summary>

```json
{
    "admin_bind": {
        "host": "0.0.0.0",
        "port": 9901
    }
}
```
</details>

---

<a name="可观测性"></a>

## 可观测性

包含 Log、Metric、Trace 三个层面。

### Log

TNG 默认将日志输出到标准输出，通过 `RUST_LOG` 环境变量控制日志级别：`error`、`warn`、`info`、`debug`、`trace`、`off`。默认 `info`，禁用所有第三方库日志。

> 支持复杂配置，参考 [tracing-subscriber EnvFilter](https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives)。

### Metric

| 范围 | 名称 | 类型 | 描述 |
|---|---|---|---|
| 实例 | `live` | Gauge | `1` 表示实例存活且健康 |
| ingress/egress | `tx_bytes_total` | Counter | 发送的总字节数 |
| ingress/egress | `rx_bytes_total` | Counter | 接收的总字节数 |
| ingress/egress | `cx_active` | Gauge | 当前活跃连接数 |
| ingress/egress | `cx_total` | Counter | 总连接数 |
| ingress/egress | `cx_failed` | Counter | 失败总连接数 |

**导出标签：**

| 模式 | 标签 |
|---|---|
| ingress mapping | `ingress_type=mapping,ingress_id={id},ingress_in={in.host}:{in.port},ingress_out={out.host}:{out.port}` |
| ingress http_proxy | `ingress_type=http_proxy,ingress_id={id},ingress_proxy_listen={proxy_listen.host}:{proxy_listen.port}` |
| egress mapping | `egress_type=netfilter,egress_id={id},egress_in={in.host}:{in.port},egress_out={out.host}:{out.port}` |
| egress netfilter | `egress_type=netfilter,egress_id={id},egress_listen_port={listen_port}` |

**支持的 Exporter：**

| 类型 | 配置字段 |
|---|---|
| `otlp` | `protocol`（`grpc`/`http/protobuf`/`http/json`）、`endpoint`、`headers`、`step`（默认 60s） |
| `falcon` | `server_url`、`endpoint`、`tags`、`step`（默认 60s） |
| `stdout` | `step`（默认 60s） |

<details>
<summary>示例：OTLP</summary>

```json
{
    "metric": {
        "exporters": [
            {
                "type": "otlp",
                "protocol": "http/protobuf",
                "endpoint": "https://otlp.example.com/url",
                "headers": { "Authorization": "XXXXXXXXX" },
                "step": 2
            }
        ]
    }
}
```
</details>

<details>
<summary>示例：Falcon</summary>

```json
{
    "metric": {
        "exporters": [
            {
                "type": "falcon",
                "server_url": "http://127.0.0.1:1988",
                "endpoint": "master-node",
                "tags": { "namespace": "ns1", "app": "tng" },
                "step": 60
            }
        ]
    }
}
```
</details>

### Trace

支持 OpenTelemetry 标准 tracing 导出。

| 类型 | 说明 |
|---|---|
| `otlp` | `protocol`（`grpc`/`http/protobuf`/`http/json`）、`endpoint`、`headers` |
| `stdout` | 同步输出，高并发时影响性能，仅供调试 |

<details>
<summary>示例</summary>

```json
{
    "trace": {
        "exporters": [
            {
                "type": "otlp",
                "protocol": "http/protobuf",
                "endpoint": "https://otlp.example.com/url"
            }
        ]
    }
}
```
</details>

---

## 附录：正则表达式语法

TNG 配置中有部分字段允许指定正则表达式。

| 版本 | 语法 |
|---|---|
| 2.0.0 之前 | RE2 语法，参考 [Google RE2](https://github.com/google/re2/wiki/Syntax) |
| 2.0.0+ | Rust regex 语法，不支持 look-around 和 backreferences，参考 [regex crate](https://docs.rs/regex/1.11.1/regex/index.html#syntax) |
