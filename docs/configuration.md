# Parameter Manual

> This document describes all JSON configuration fields for TNG. All fields are optional unless marked as "required".
>
> **Tip:** For a quick start, we recommend reviewing the complete configuration examples in the [Scenario Guide](scenarios/) first, then referring back to this document for specific field details.

## Table of Contents

- [Top-Level Configuration Object](#top-level-configuration-object)
- [Ingress (Tunnel Entry)](#ingress-tunnel-entry)
  - [Common Fields](#common-fields)
  - [Transport Layer Common Configuration](#transport-layer-common-configuration)
  - [Mode: mapping (Port Mapping)](#mode-mapping-port-mapping)
  - [Mode: http_proxy (HTTP Proxy)](#mode-http_proxy-http-proxy)
  - [Mode: socks5 (Socks5 Proxy)](#mode-socks5-socks5-proxy)
  - [Mode: netfilter (Transparent Proxy)](#mode-netfilter-transparent-proxy)
  - [Mode: hook (LD_PRELOAD)](#mode-ingress-hook-ld-preload)
- [Egress (Tunnel Exit)](#egress-tunnel-exit)
  - [Common Fields](#common-fields)
  - [direct_forward Rules](#direct_forward-rules)
  - [Mode: mapping (Port Mapping)](#mode-mapping-port-mapping)
  - [Mode: netfilter (Port Hijacking)](#mode-netfilter-port-hijacking)
  - [Mode: hook (LD_PRELOAD)](#egress-hook-ld-preload)
- [Remote Attestation (Common Configuration)](#remote-attestation-common-configuration)
  - [Provider Selection](#provider-selection)
  - [Attester Configuration](#attester-configuration)
    - [Background Check Mode](#background-check-mode)
    - [Passport Model](#passport-model)
  - [Verifier Configuration](#verifier-configuration)
    - [Background Check Mode](#background-check-mode)
    - [Passport Model](#passport-model)
  - [Role Combination Examples](#role-combination-examples)
- [OHTTP Protocol](#ohttp-protocol)
  - [Ingress Side Configuration](#ingress-side-configuration)
  - [Egress Side Configuration](#egress-side-configuration)
  - [Key Management](#key-management)
    - [self_generated Mode](#self_generated-mode-default)
    - [peer_shared Mode](#peer_shared-mode)
    - [file Mode](#file-mode)
- [Control Interface](#control-interface)
  - [RESTful API](#restful-api)
- [Deprecated Configuration](#deprecated-configuration)
- [Observability](#observability)
  - [Log](#log)
  - [Metric](#metric)
  - [Trace](#trace)
- [Appendix: Regular Expression Syntax](#appendix-regular-expression-syntax)

---

## Top-Level Configuration Object

| Field | Type | Required | Description |
|---|---|---|---|
| `control_interface` | [ControlInterface](#control-interface) | No | Control plane configuration |
| `metrics` | [Metrics](#metric) | No | Metrics configuration; disabled if not specified |
| `add_ingress` | array [[Ingress](#ingress-tunnel-entry)] | No | List of tunnel ingress endpoints |
| `add_egress` | array [[Egress](#egress-tunnel-exit)] | No | List of tunnel egress endpoints |
| `admin_bind` | AdminBind | No | **Deprecated** — See [Deprecated Configuration](#deprecated-configuration) |

---

## Ingress (Tunnel Entry)

The `Ingress` object configures the tunnel's entry endpoints, controlling how traffic enters the tunnel.

> **Naming Note:** "Ingress" refers to traffic **entering the tunnel**, not the Kubernetes Ingress meaning of "inbound server traffic".

<a name="ingress-common-fields"></a>

### Common Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `ingress_mode` | `mapping` \| `http_proxy` \| `netfilter` \| `socks5` \| `hook` | None | Traffic inbound mode. Place the corresponding mode's key-value in the object based on the mode used |
| `ohttp` | [OHttp](#ingress-side-configuration) | None | OHTTP protocol configuration (mutually exclusive with `rats_tls`) |
| `rats_tls` | [RatsTlsArgs](#transport-layer-common-configuration) | None | RA-TLS transport configuration (mutually exclusive with `ohttp`) |
| `no_ra` | boolean | `false` | Disable remote attestation (for debugging only; cannot coexist with `attest`/`verify`) |
| `attest` | [Attest](#attester-configuration) | None | Act as Attester at this endpoint |
| `verify` | [Verify](#verifier-configuration) | None | Act as Verifier at this endpoint |

> [!WARNING]
> `ohttp` and `rats_tls` are mutually exclusive. Specifying both in the same Ingress/Egress will result in an error.

> [!TIP]
> When neither `ohttp` nor `rats_tls` is specified, RA-TLS mode is used by default. Remote attestation-related fields are described in the [Remote Attestation (Common Configuration)](#remote-attestation-common-configuration) section.

### Transport Layer Common Configuration

The following fields are shared between Ingress and Egress, describing transport layer behavior for both RA-TLS and OHTTP.

<a name="rats-tls-transport-configuration"></a>

#### RatsTlsArgs

| Field | Type | Default | Description |
|---|---|---|---|
| `multiplex` | boolean | `false` | When `true`, uses HTTP/2 CONNECT to multiplex multiple TCP streams over a single TLS connection, suitable for many short-lived connections; when `false`, each connection has an independent TLS session with higher single-stream throughput, recommended for high-bandwidth scenarios |

---

<a name="ingress-mapping-port-mapping"></a>

### Mode: mapping (Port Mapping)

TNG listens on one or more local TCP ports (`in.host`, `in.port`, optionally `in.port_end`), encrypts traffic, and sends it to the specified target(s) (`out.host`, `out.port`, optionally `out.port_end`). Clients must change their request target to the address TNG is listening on.

| Field | Type | Required | Description |
|---|---|---|---|
| `mapping.rules` | array | Yes | List of forwarding rules (or use legacy `in`/`out` format, see below) |
| `mapping.rules[].in.host` | string | No (`0.0.0.0`) | Listen address |
| `mapping.rules[].in.port` | integer | Yes | Start listen port |
| `mapping.rules[].in.port_end` | integer | No | End listen port (inclusive, closed interval `[port, port_end]`). Must be >= `port` |
| `mapping.rules[].out.host` | string | Yes | Target address |
| `mapping.rules[].out.port` | integer | Yes | Start target port |
| `mapping.rules[].out.port_end` | integer | No | End target port (inclusive). Range size must match `in` range size |

> **Note:** The legacy format with `mapping.in` and `mapping.out` (single object, no `rules` array) is still supported for backward compatibility.

<details>
<summary>Example: mapping mode with multiple rules and port range</summary>

```json
{
    "add_ingress": [
        {
            "mapping": {
                "rules": [
                    {
                        "in": { "host": "0.0.0.0", "port": 10001 },
                        "out": { "host": "127.0.0.1", "port": 20001 }
                    },
                    {
                        "in": { "host": "0.0.0.0", "port": 10010, "port_end": 10020 },
                        "out": { "host": "127.0.0.1", "port": 20010, "port_end": 20020 }
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

<details>
<summary>Example: legacy mapping format (single in/out)</summary>

```json
{
    "add_ingress": [
        {
            "mapping": {
                "in": { "host": "0.0.0.0", "port": 10001 },
                "out": { "host": "127.0.0.1", "port": 20001 }
            }
        }
    ]
}
```

</details>

---

<a name="ingress-http_proxy-http-proxy"></a>

### Mode: http_proxy (HTTP Proxy)

TNG listens on an HTTP proxy port. Clients route traffic through the proxy to TNG via the `http_proxy` environment variable. TNG encrypts and forwards to the original target. Clients do not need to modify their request target.

| Field | Type | Default | Description |
|---|---|---|---|
| `http_proxy` | object | Yes | HTTP proxy configuration object |
| `http_proxy.proxy_listen.host` | string | No (`0.0.0.0`) | Listen address |
| `http_proxy.proxy_listen.port` | integer | Yes | Listen port |
| `http_proxy.dst_filters` | array [[EndpointFilter](#endpointfilter)] | No (`[]`) | Target filtering rules; only matching traffic enters the tunnel |
| `http_proxy.dst_filter` | EndpointFilter | — | **Deprecated** — Replaced by `dst_filters` |

#### EndpointFilter

| Field | Type | Default | Description |
|---|---|---|---|
| `domain` | string | `*` | Target domain to match (supports `*` wildcard; does not support regex) |
| `domain_regex` | string | `.*` | Target domain regex (mutually exclusive with `domain`) |
| `port` | integer | `80` | Target port to match |
| `port_end` | integer | None | Optional end port for range matching. When set with `port`, matches ports in `[port, port_end]` inclusive range. Requires `port` to be set. |

> The `domain` wildcard syntax is described in [Envoy VirtualHost domains](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost).

<details>
<summary>Example: http_proxy mode</summary>

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

<a name="ingress-socks5-socks5-proxy"></a>

### Mode: socks5 (Socks5 Proxy)

TNG creates a local Socks5 proxy port. Clients connect to this proxy, and TNG encrypts and forwards to the original target. Clients only need to configure Socks5 proxy options without modifying their request target.

| Field | Type | Default | Description |
|---|---|---|---|
| `socks5` | object | Yes | Socks5 proxy configuration object |
| `socks5.proxy_listen.host` | string | No (`0.0.0.0`) | Listen address |
| `socks5.proxy_listen.port` | integer | Yes | Listen port |
| `socks5.auth` | [Socks5Auth](#socks5auth) | No | Access authentication |
| `socks5.dst_filters` | array [[EndpointFilter](#endpointfilter)] | No (`[]`) | Target filtering rules |

#### Socks5Auth

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | Yes | Authentication username |
| `password` | string | Yes | Authentication password |

> [!NOTE]
> **socks5 vs socks5h:** `socks5` resolves domain names on the client side, while `socks5h` resolves them on the proxy server side. If the client uses `socks5`, TNG can only obtain the target IP rather than the domain name, which may cause `dst_filters` domain rules to be ineffective. Most modern clients (such as curl) support `socks5h`.

<details>
<summary>Example: socks5 mode (no authentication)</summary>

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
<summary>Example: socks5 mode (with authentication)</summary>

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
<summary>Example: socks5 mode (with target filtering)</summary>

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

<a name="ingress-netfilter-transparent-proxy"></a>

### Mode: netfilter (Transparent Proxy)

TNG listens on a local port, and iptables rules redirect user traffic to that port. TNG encrypts and forwards to the original target. Clients do not need to modify their request target.

| Field | Type | Default | Description |
|---|---|---|---|
| `netfilter` | object | Yes | netfilter configuration object |
| `netfilter.capture_dst` | array [[CaptureDst](#capturedst)] | No (`[]`) | Destination address and port capture rules |
| `netfilter.capture_cgroup` | array [string] | No (`[]`) | List of cgroup paths to capture |
| `netfilter.nocapture_cgroup` | array [string] | No (`[]`) | List of cgroup paths to exclude |
| `netfilter.listen_port` | integer | No (randomly assigned) | TNG listen port for captured traffic |
| `netfilter.so_mark` | integer | `565` | SO_MARK value for encrypted traffic sockets to prevent loops |

#### CaptureDst

| Field | Type | Required | Description |
|---|---|---|---|
| `host` | string | No | Target IP or CIDR (mutually exclusive with `ipset`) |
| `ipset` | string | No | ipset group name (mutually exclusive with `host`) |
| `port` | integer | No | Target port |
| `port_end` | integer | No | Used with `port` to match continuous port range `[port, port_end]` |

> [!NOTE]
> - `capture_cgroup` and `nocapture_cgroup` are only supported on cgroup v2 systems.
> - Due to [netfilter kernel implementation limitations](https://github.com/torvalds/linux/blob/ec7714e4947909190ffb3041a03311a975350fe0/net/netfilter/xt_cgroup.c#L105), cgroup paths are relative to the cgroup namespace where the TNG process resides. When running TNG in a container, use `--cgroupns=host`.

**Traffic capture logic:**

```mermaid
flowchart TD
    A[Start] --> G{capture_cgroup empty?}
    G --Yes--> D
    G --No--> B{Matches any capture_cgroup?}
    B --No--> C[Ignore traffic]
    B --Yes--> D{Matches any nocapture_cgroup?}
    D --Yes--> C
    D --No--> E{Matches any capture_dst?}
    E --Yes--> F[Capture traffic]
    E --No--> C
```

> **Note:** This mode only captures TCP traffic and does not capture traffic destined for local addresses.

> [!NOTE]
> **Running in containers without `CAP_NET_ADMIN`:** The netfilter mode requires `CAP_NET_ADMIN` to create iptables rules. If your container lacks this capability, you can work around it using [pasta](https://passt.top), which bypasses the missing capability by creating a child network namespace and user namespace pair:
>
> 1. Ensure the container environment allows user namespace creation: `clone(CLONE_NEWUSER)` must not be blocked by seccomp. Verify with a simple C program calling `clone()` with `CLONE_NEWUSER`.
> 2. Ensure `/dev/net/tun` is available. If missing and you have `CAP_MKNOD`, create it manually: `mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 666 /dev/net/tun`.
> 3. Run TNG as a non-root user via pasta: `su <non-root-user> -s /bin/bash -c 'pasta -t none -a 10.0.2.100 -4 -- /path/to/tng ...'`. Pasta creates a user namespace + network namespace where the process gains `CAP_NET_ADMIN`, enabling iptables to function. **Both TNG and your business application must run inside the same pasta namespace** for the netfilter rules to take effect.
>
> If `clone(CLONE_NEWUSER)` fails with `Operation not permitted`, your container runtime's seccomp profile blocks user namespace creation, and this workaround will not work.

<details>
<summary>Example: Capture by target IP + port</summary>

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
<summary>Example: Capture by CIDR segment</summary>

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
<summary>Example: Capture by ipset</summary>

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
<summary>Example: Capture continuous port range with port_end</summary>

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

<a name="mode-ingress-hook-ld-preload"></a>

### Ingress Hook Mode (`"hook"`)

> **Requires:** `tng exec` — the child process is loaded with `LD_PRELOAD=libtng_hook.so`.

Intercepts outgoing TCP connections from the child process via LD_PRELOAD and routes them through TNG's encrypted tunnel using HTTP CONNECT protocol.

| Field | Type | Required | Description |
|---|---|---|---|
| `capture_dst` | array | Yes | Destination IP+port rules to intercept. |
| `capture_dst[].host` | CIDR or IP | No | IPv4 address or CIDR prefix. Omit to match any IP (`*`). |
| `capture_dst[].port` | integer | Yes | Destination port to intercept. |
| `capture_dst[].port_end` | integer | No | End of port range (inclusive). Without this, single port match. |
| `proxy_port` | integer | No | Internal HTTP proxy port. Auto-allocated if omitted. |
| `proxy_listen` | string | No | Bind address for internal proxy. Default: `127.0.0.1`. |

**Example:**

```json
{
  "add_ingress": [
    {
      "hook": {
        "capture_dst": [
          { "host": "10.0.0.0/24", "port": 80 },
          { "host": "10.0.0.0/24", "port": 443 },
          { "port": 8080, "port_end": 8090 }
        ],
        "proxy_port": 49001
      },
      "attest": { "no_ra": true }
    }
  ]
}
```

---

## Egress (Tunnel Exit)

The `Egress` object configures the tunnel's exit endpoints, controlling how traffic exits the tunnel.

<a name="egress-common-fields"></a>

### Common Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `egress_mode` | `mapping` \| `netfilter` \| `hook` | None | Traffic outbound mode. Place the corresponding mode's key-value in the object based on the mode used |
| `direct_forward` | array [[DirectForwardRule](#direct_forward-rules)] | No | Direct forwarding (without decryption) rules |
| `ohttp` | [OHttp](#egress-side-configuration) | None | OHTTP protocol configuration (mutually exclusive with `rats_tls`) |
| `rats_tls` | [RatsTlsArgs](#transport-layer-common-configuration) | None | RA-TLS transport configuration (mutually exclusive with `ohttp`) |
| `no_ra` | boolean | `false` | Disable remote attestation (for debugging only; cannot coexist with `attest`/`verify`) |
| `attest` | [Attest](#attester-configuration) | None | Act as Attester at this endpoint |
| `verify` | [Verify](#verifier-configuration) | None | Act as Verifier at this endpoint |

> Transport layer fields like `rats_tls.multiplex` share the same definition as Ingress. See [RatsTlsArgs](#transport-layer-common-configuration).

<a name="direct_forward-rules"></a>

### direct_forward Rules

In some scenarios, it is necessary to allow plain-text traffic alongside encrypted traffic (e.g., health checks). `direct_forward` specifies matching rules; if any rule matches, traffic is forwarded without decryption.

| Field | Type | Required | Description |
|---|---|---|---|
| `http_path` | string | Yes | Regular expression matching the HTTP request URI [Path](https://developer.mozilla.org/en-US/docs/Web/API/URL/pathname) |

<details>
<summary>Example: Allow plaintext requests for /public/* path</summary>

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

This egress allows encrypted traffic to access port 30001 while also permitting unencrypted requests whose path matches `/public/.*`.
</details>

---

<a name="egress-mapping-port-mapping"></a>

### Mode: mapping (Port Mapping)

TNG listens on one or more local ports (`in.host`, `in.port`, optionally `in.port_end`), decrypts traffic, and forwards it to the target endpoint(s) (`out.host`, `out.port`, optionally `out.port_end`). Server programs must listen on the target address where TNG forwards decrypted traffic.

| Field | Type | Required | Description |
|---|---|---|---|
| `mapping.rules` | array | Yes | List of forwarding rules (or use legacy `in`/`out` format, see below) |
| `mapping.rules[].in.host` | string | No (`0.0.0.0`) | Listen address |
| `mapping.rules[].in.port` | integer | Yes | Start listen port |
| `mapping.rules[].in.port_end` | integer | No | End listen port (inclusive, closed interval `[port, port_end]`). Must be >= `port` |
| `mapping.rules[].out.host` | string | Yes | Target address |
| `mapping.rules[].out.port` | integer | Yes | Start target port |
| `mapping.rules[].out.port_end` | integer | No | End target port (inclusive). Range size must match `in` range size |

> **Note:** The legacy format with `mapping.in` and `mapping.out` (single object, no `rules` array) is still supported for backward compatibility.

<details>
<summary>Example: egress mapping mode with multiple rules and port range</summary>

```json
{
    "add_egress": [
        {
            "mapping": {
                "rules": [
                    {
                        "in": { "host": "127.0.0.1", "port": 20001 },
                        "out": { "host": "127.0.0.1", "port": 30001 }
                    },
                    {
                        "in": { "host": "127.0.0.1", "port": 20010, "port_end": 20020 },
                        "out": { "host": "127.0.0.1", "port": 30010, "port_end": 30020 }
                    }
                ]
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
<summary>Example: legacy egress mapping format (single in/out)</summary>

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

<a name="egress-netfilter-port-hijacking"></a>

### Mode: netfilter (Port Hijacking)

TNG intercepts **inbound traffic from other nodes destined for specified ports** via kernel netfilter, redirecting it to the `listen_port` that TNG is listening on. After decryption, TNG sends plaintext traffic back to the original service port on the local machine.

This is suitable for scenarios where the server is already listening on a port and changing the port is inconvenient.

| Field | Type | Default | Description |
|---|---|---|---|
| `netfilter` | object | Yes | netfilter configuration object |
| `netfilter.capture_dst` | array [[CaptureDst](#capturedst)] | No (`[]`) | Destination address and port capture rules (captures all TCP if empty) |
| `netfilter.capture_cgroup` | array [string] | No (`[]`) | List of cgroup paths to capture |
| `netfilter.nocapture_cgroup` | array [string] | No (`[]`) | List of cgroup paths to exclude |
| `netfilter.capture_local_traffic` | boolean | `false` | Whether to capture traffic with source IP being the local machine |
| `netfilter.listen_port` | integer | No (increments from 40000) | TNG listen port for redirected traffic |
| `netfilter.so_mark` | integer | `565` | SO_MARK value for decrypted plaintext traffic sockets to prevent loops |

> [!NOTE]
> - `capture_cgroup` and `nocapture_cgroup` are only supported on cgroup v2 systems.
> - Due to [netfilter kernel implementation limitations](https://github.com/torvalds/linux/blob/ec7714e4947909190ffb3041a03311a975350fe0/net/netfilter/xt_cgroup.c#L105), cgroup paths are relative to the cgroup namespace where the TNG process resides. When running TNG in a container, use `--cgroupns=host`.

**Traffic capture logic:**

```mermaid
flowchart TD
    A[Start] --> G{capture_cgroup empty?}
    G --Yes--> D
    G --No--> B{Matches any capture_cgroup?}
    B --No--> C[Ignore traffic]
    B --Yes--> D{Matches any nocapture_cgroup?}
    D --Yes--> C
    D --No--> E{Matches any capture_dst?}
    E --Yes--> F[Capture traffic]
    E --No--> C
```

> **Note:** This mode only captures TCP traffic and does not capture traffic destined for local addresses (unless `capture_local_traffic: true`).

> [!NOTE]
> **Running in containers without `CAP_NET_ADMIN`:** See the [Ingress netfilter note](#mode-netfilter-transparent-proxy) above for the same workaround using pasta.

<details>
<summary>Example: Capture inbound traffic destined for port 30001</summary>

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
<summary>Example: Capture by specific IP and port</summary>

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
<summary>Example: Capture by cgroup + multiple ports</summary>

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
<summary>Example: Capture continuous port range with port_end</summary>

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
<summary>Example: Capture all inbound TCP traffic</summary>

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

<a name="egress-hook-ld-preload"></a>

### Mode: hook (LD_PRELOAD)

The `hook` mode uses LD_PRELOAD to intercept the server application's `bind()` and `getsockname()` syscalls, transparently redirecting listening sockets through the TNG tunnel.

This mode is only available with `tng exec`, which launches a child process with the hook library preloaded.

**Usage:**

```bash
tng exec --config-file=/etc/tng.json -- vllm serve --host 0.0.0.0 --port 8080
```

**Configuration:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hook` | object | Yes | Hook egress configuration object |
| `hook.capture_listen` | array | Yes | List of ports to intercept |
| `hook.capture_listen[].port` | number | Yes | Port to intercept |
| `hook.capture_listen[].host` | string | No | IPv4 address to match (default: any) |
| `hook.capture_listen[].port_end` | number | No | End port for range matching |
| `hook.capture_listen[].redirect_to_port` | number | No | Real port to redirect to (auto-allocated if not set) |
| `hook.capture_listen[].redirect_to_port_end` | number | No | End port for redirect range |

**Rules:**
- `port_end` and `redirect_to_port_end` must both be present or both absent
- Range lengths must match: `port_end - port == redirect_to_port_end - redirect_to_port`
- When `redirect_to_port` is not specified, TNG auto-allocates available ports

**Example:**

```json
{
    "add_egress": [
        {
            "hook": {
                "capture_listen": [
                    { "port": 8080 },
                    { "port": 8080, "port_end": 8090, "redirect_to_port": 48080, "redirect_to_port_end": 48090 },
                    { "host": "192.168.1.1", "port": 30002, "redirect_to_port": 45002 }
                ]
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```

> [!NOTE]
> The `hook` mode is mutually exclusive with other egress modes. When using `tng exec`, only `hook` mode is allowed.

---

<a name="remote-attestation-common-configuration"></a>

## Remote Attestation (Common Configuration)

Remote attestation is one of the core security mechanisms in trusted computing, used to verify the runtime integrity and trustworthiness of remote systems. Through cryptographic means, a system (**Attester**) generates "evidence" describing its hardware and software configuration, and another system (**Verifier**) verifies this evidence to ensure it comes from a legitimate, untampered Trusted Execution Environment (TEE).

<a name="provider-selection"></a>

### Provider Selection

The Attestation Agent stack and Attestation Service stack are selected via **`aa_provider`** and **`as_provider`** respectively. If omitted, they default to **`"coco"`** (Confidential Containers).

| Provider | Usage | Description |
|---|---|---|
| `"coco"` | `aa_provider` / `as_provider` | Default. Interfaces with CoCo AA and CoCo AS |
| `"ita"` | `aa_provider` / `as_provider` | Interfaces with CoCo AA for evidence collection, and Intel Trust Authority cloud service for verification |
| `"coco_asr"` | `aa_provider` only | Collects evidence via CoCo [API Server Rest](https://github.com/confidential-containers/guest-components/tree/main/api-server-rest) (ASR) HTTP proxy, suitable when TNG runs in a container without direct access to AA Unix socket |
| `"ita_asr"` | `aa_provider` only | Same as `"ita"`, but collects evidence via ASR HTTP proxy |

<a name="attester-configuration"></a>

### Attester Configuration

The **Attester** is the party being verified, responsible for collecting local platform trust state information and generating cryptographic evidence (Evidence).

<a name="attest-background-check-mode"></a>

#### Background Check Mode

[Background Check](https://datatracker.ietf.org/doc/html/rfc9334#name-background-check-model) is TNG's default remote attestation mode. The proving party obtains evidence through the Attestation Agent, and the verifying party verifies it directly.

> [!NOTE]
> When the `"model"` field is not specified, TNG automatically uses Background Check mode.

**CoCo Provider (`aa_provider` = `"coco"` or omitted):**

| Field | Type | Default | Description |
|---|---|---|---|
| `model` | string | — | Set to `"background_check"` to explicitly enable |
| `aa_type` | string | `"uds"` | Agent type: `"uds"` / `"builtin"` |
| `aa_addr` | string | — | Required for `"uds"` type; AA Unix socket address |
| `refresh_interval` | int | `600` | Evidence cache time in seconds; `0` means fetch latest each time |

When using ASR HTTP proxy, set `aa_provider` = `"coco_asr"` and provide `asr_addr` instead of `aa_addr`.

<details>
<summary>Example: Background Check Attest (CoCo)</summary>

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

Via ASR proxy:
```json
"attest": {
    "aa_provider": "coco_asr",
    "asr_addr": "http://127.0.0.1:8006"
}
```
</details>

**ITA Provider (`aa_provider` = `"ita"`):**

| Field | Type | Required | Description |
|---|---|---|---|
| `aa_provider` | string | Yes | Set to `"ita"` |
| `aa_addr` | string | Yes | AA Unix socket address |
| `refresh_interval` | int | `600` | Same as above |

When using ASR proxy, set `aa_provider` = `"ita_asr"` and provide `asr_addr`.

<details>
<summary>Example: ITA Provider</summary>

```json
"attest": {
    "aa_provider": "ita",
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
}
```

Via ASR proxy:
```json
"attest": {
    "aa_provider": "ita_asr",
    "asr_addr": "http://127.0.0.1:8006"
}
```
</details>

<a name="attest-passport-model"></a>

#### Passport Model

In addition to the Background Check mode, TNG also supports remote attestation that conforms to the [Passport model](https://datatracker.ietf.org/doc/html/rfc9334#name-passport-model) defined in the [RATS RFC 9334 document](https://datatracker.ietf.org/doc/html/rfc9334). In the Passport model, the Attester obtains evidence through the Attestation Agent and submits it to the Attestation Service to obtain a Token (i.e., Passport). The Verifier only needs to verify the validity of this Token without directly interacting with the Attestation Service.

The Passport model is suitable for scenarios with network isolation or high performance requirements, as it reduces the interaction between the Verifier and the Attestation Service.

##### CoCo Provider

In the Passport model, the [Attest](#attester-configuration) configuration should include the following fields. The fields below apply to the default CoCo provider (`aa_provider` = `"coco"` or omitted, `as_provider` = `"coco"` or omitted):

| Field | Type | Default | Description |
|---|---|---|---|
| `model` | string | — | Set to `"passport"` to enable the Passport model |
| `aa_type` | string | `"uds"` | Agent type: `"uds"` / `"builtin"` |
| `aa_addr` | string | — | Required for `"uds"` type; AA Unix socket address |
| `refresh_interval` | int | `600` | Evidence cache time in seconds; `0` means fetch latest each time |
| `as_type` | string | `"restful"` | AS type: `"restful"` / `"grpc"` |
| `as_addr` | string | — | Attestation Service address |
| `as_headers` | object | `{}` | Custom headers sent to AS (e.g., Authorization) |
| `policy_ids` | array [string] | — | Policy ID list |

As with Background Check mode, you can use `aa_provider` = `"coco_asr"` with `asr_addr` instead of `aa_addr` to collect evidence via the ASR HTTP proxy.

<details>
<summary>Example: Passport Attest (CoCo)</summary>

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

When `aa_provider` and `as_provider` are set to `"ita"`, the Attest configuration uses the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `model` | string | Yes | Set to `"passport"` |
| `aa_provider` | string | Yes | Set to `"ita"` |
| `aa_addr` | string | Yes | AA Unix socket address |
| `as_provider` | string | Yes | Set to `"ita"` |
| `as_addr` | string | `https://api.trustauthority.intel.com` | ITA API base URL |
| `api_key` | string | No | ITA API key (can also be set via `ITA_API_KEY` environment variable) |
| `policy_ids` | array [string] | `[]` | ITA policy ID list |

As with Background Check mode, you can use `aa_provider` = `"ita_asr"` with `asr_addr` instead of `aa_addr` to collect evidence via the ASR HTTP proxy.

<details>
<summary>Example: Passport Attest (ITA)</summary>

```json
"attest": {
    "model": "passport",
    "aa_provider": "ita",
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
    "as_provider": "ita",
    "api_key": "your-ita-api-key",
    "policy_ids": ["my-policy"]
}
```
</details>

<a name="verifier-configuration"></a>

### Verifier Configuration

The **Verifier** receives and verifies Evidence from the Attester, only recognizing the peer as trusted if the evidence complies with preset trust policies.

<a name="verify-background-check-mode"></a>

#### Background Check Mode

**CoCo Provider (`as_provider` = `"coco"` or omitted):**

| Field | Type | Default | Description |
|---|---|---|---|
| `model` | string | — | Set to `"background_check"` to explicitly enable |
| `as_type` | string | `"restful"` | AS type: `"restful"` / `"grpc"` / `"builtin"` |
| `as_addr` | string | — | Required for `"restful"` and `"grpc"` types; AS address |
| `as_headers` | object | `{}` | Custom headers sent to AS (e.g., Authorization) |
| `attestation_policy` | object | — | Optional for `"builtin"` type; built-in AS attestation policy configuration. Defaults to `{"type": "hardware_only"}` if omitted (the alias `{"type": "default"}` resolves to the same). Accepted `type` values: `hardware_only` (alias `default`) — only verifies hardware TEE recognition, ignores reference values (the default, suited to general-purpose deployments); `hardware_with_reference_values` — trustee comprehensive appraisal against configured reference values; `trust_all` — affirms every dimension unconditionally (debug/test only); `inline` — base64-encoded rego; `path` — path to a rego file |
| `reference_values` | array | — | Optional for `"builtin"` type; built-in AS reference value configuration list |
| `policy_ids` | array [string] | — | Policy ID list. Only for `"restful"` and `"grpc"` types; ignored when `as_type` is `"builtin"` |
| `trusted_certs_paths` | array [string] | `[]` | Root CA certificate paths for verifying Attestation Token signatures |
| `verify_signer_transparency` | boolean | `false` | Verify `signer_transparency` claim in JWT tokens issued by Trustee AS (only for COCO external AS, not applicable to builtin AS) |
| `skip_as_token_cert_verify` | boolean | `false` | **DANGER:** Skip AS token certificate verification. The token signing certificate is not validated. When `true`, `trusted_certs_paths` cannot be set. In Passport mode, `as_addr` also cannot be set. Only use this when you fully trust the token source. |

> **`verify_signer_transparency` description:** When Trustee runs inside a TEE hosted by an untrusted provider, its JWT signing certificate lacks inherent trust mechanisms. The `signer_transparency` feature solves this by binding the signing certificate to TEE evidence and recording it in a Rekor v2 transparency log. Verification includes certificate DER SHA-256 match, report_data binding, Rekor checkpoint signature verification, etc. See the [Trustee AS signer transparency document](https://github.com/openanolis/trustee/blob/main/attestation-service/docs/as_signer_transparency.md) for the full specification.

<details>
<summary>Example: Restful AS</summary>

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
<summary>Example: gRPC AS</summary>

```json
"verify": {
    "as_type": "grpc",
    "as_addr": "http://127.0.0.1:5000/",
    "policy_ids": ["default"]
}
```
</details>

<details>
<summary>Example: Builtin AS</summary>

```json
"verify": {
    "as_type": "builtin",
    "attestation_policy": {
        "type": "hardware_only"
    },
    "reference_values": []
}
```
</details>

<details>
<summary>Example: Specify root certificate paths</summary>

```json
"verify": {
    "as_addr": "http://127.0.0.1:8080/",
    "policy_ids": ["default"],
    "trusted_certs_paths": ["/tmp/as-ca.pem"]
}
```
</details>

**ITA Provider (`as_provider` = `"ita"`):**

| Field | Type | Default | Description |
|---|---|---|---|
| `as_provider` | string | Yes | Set to `"ita"` |
| `as_addr` | string | `https://api.trustauthority.intel.com` | ITA API base URL |
| `api_key` | string | No | ITA API key (can also be set via `ITA_API_KEY` environment variable) |
| `ita_jwks_addr` | string | `https://portal.trustauthority.intel.com` | ITA portal URL for fetching JWKS |
| `policy_ids` | array [string] | `[]` | ITA policy ID list |

> It is recommended to set the API key via the `ITA_API_KEY` environment variable rather than writing it in the configuration file.

<a name="builtin-as-configuration"></a>
**Builtin AS (`as_type` = `"builtin"`):**

When `as_type` = `"builtin"`, TNG uses the built-in AS to verify Evidence locally without connecting to an external AS. This is suitable for network-isolated, latency-sensitive, or simplified deployment scenarios.

> [!NOTE]
> Builtin mode requires compiling with the corresponding TEE feature enabled (`builtin-as-tdx`, `builtin-as-sgx`, or `builtin-as-snp`). GitHub CI-built RPM packages and binary artifacts do not support this mode; only container images support it.
>
> For SGX/TDX builtin AS mode, you also need to configure the PCCS URL in `/etc/sgx_default_qcnl.conf` for your cloud provider. See the [Vendor Configuration Setup](setup-vendor-config.md) guide for details.

**PolicyConfig (OPA Policy):**

| type | Description |
|---|---|
| `"default"` | Uses the default policy built into attestation-service, performing comprehensive measurement verification of TEE hardware and software |
| `"inline"` | Inline policy; requires `content` (Base64-encoded OPA policy content) |
| `"path"` | File path policy; requires `path` (OPA policy file path) |

**ReferenceValueConfig (Reference Value Source):**

| type | Description |
|---|---|
| `"sample"` | Directly provides reference value payload (`payload` is `SampleProvenancePayloadConfig`) |
| `"slsa"` | Fetches SLSA provenance from Rekor transparency log (historical compatibility) |
| `"release_manifest"` | **Recommended**: Fetches reference values from RV release manifest bundle |

**Payload Loading Methods:** Each reference value type supports both `"inline"` (inline content) and `"path"` (load from file) methods.

`Provenance` format (sample inline):
```json
{
  "measurement.uki.SHA-384": [
    "a46e162a57e072be7f660e65504477c646acf6b3bfea4ffc0e3a8ee4f2c2726c2284c8bf1ec2b3bd95b204fe7f4e899c"
  ]
}
```

`ReferenceValueListPayload` format (release_manifest / slsa):
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
<summary>Example 1: Provide reference values in Sample mode</summary>

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

`/etc/tng/tdx-reference-values.json`:
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
<summary>Example 2: SLSA mode (historical compatibility)</summary>

```json
{
    "verify": {
        "as_type": "builtin",
        "attestation_policy": {
            "type": "hardware_with_reference_values"
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
<summary>Example 3: Release Manifest mode (recommended)</summary>

```json
{
    "verify": {
        "as_type": "builtin",
        "attestation_policy": { "type": "hardware_with_reference_values" },
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

<a name="verify-passport-model"></a>

#### Passport Model

In the Passport model, the [Verify](#verifier-configuration) configuration should include the following fields. The fields below apply to the default CoCo provider (`as_provider` = `"coco"` or omitted):

| Field | Type | Default | Description |
|---|---|---|---|
| `model` | string | — | Set to `"passport"` to enable the Passport model |
| `as_type` | string | `"restful"` | AS type: `"restful"` / `"grpc"` |
| `as_addr` | string | — | Attestation Service address (optional, but at least one of `as_addr` or `trusted_certs_paths` must be specified) |
| `as_headers` | object | `{}` | Custom headers sent to AS (e.g., Authorization) |
| `policy_ids` | array [string] | — | Policy ID list |
| `trusted_certs_paths` | array [string] | `[]` | Root CA certificate paths for verifying Attestation Token signatures |
| `verify_signer_transparency` | boolean | `false` | Verify `signer_transparency` claim in JWT tokens issued by Trustee AS |
| `skip_as_token_cert_verify` | boolean | `false` | **DANGER:** Skip AS token certificate verification. The token signing certificate is not validated. When `true`, neither `trusted_certs_paths` nor `as_addr` can be set. Only use this when you fully trust the token source. |

<details>
<summary>Example: Passport Verify (CoCo)</summary>

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
<summary>Example: Passport Verify with skip_as_token_cert_verify</summary>

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
> This example skips token certificate verification entirely. Only use this when you fully trust the token source (e.g., the token comes from a trusted trustee in a controlled environment).
</details>

##### ITA Provider

When `as_provider` is set to `"ita"`, the Verify configuration uses the following fields:

| Field | Type | Default | Description |
|---|---|---|---|
| `model` | string | — | Set to `"passport"` |
| `as_provider` | string | Yes | Set to `"ita"` |
| `ita_jwks_addr` | string | `https://portal.trustauthority.intel.com` | ITA portal URL for fetching JWKS |
| `policy_ids` | array [string] | `[]` | ITA policy ID list |

<details>
<summary>Example: Passport Verify (ITA)</summary>

```json
"verify": {
    "model": "passport",
    "as_provider": "ita",
    "policy_ids": ["my-policy"]
}
```
</details>

<a name="role-combination-examples"></a>

### Role Combination Examples

TNG controls remote attestation roles on each Ingress/Egress via three fields: `no_ra`, `attest`, and `verify`.

| Scenario | Client Configuration | Server Configuration | Description |
|---|---|---|---|
| Unidirectional | `verify` | `attest` | Most common; server is in TEE |
| Bidirectional | `attest` + `verify` | `attest` + `verify` | Both ends are in different TEEs |
| Reverse Unidirectional | `attest` | `verify` | Client is in TEE; server uses embedded fixed certificate |
| No TEE (debugging) | `no_ra` | `no_ra` | Non-TEE environment; establishes normal TLS session |

---

## OHTTP Protocol

OHTTP (Oblivious HTTP) is a network protocol extension designed to enhance privacy protection by encrypting HTTP requests at the application layer, providing end-to-end privacy and anonymity. TNG can utilize OHTTP for secure communication while maintaining compatibility with existing HTTP infrastructure.

By default, TNG uses the rats-tls protocol for TCP stream-level encryption, which is suitable for most scenarios. To enable OHTTP, configure `ohttp` in Ingress and `ohttp` in Egress respectively.

> [!WARNING]  
> If OHTTP is enabled, the inner protected business traffic must be HTTP traffic, not ordinary TCP traffic.



<a name="ohttp-ingress-side-configuration"></a>

### Ingress Side Configuration

Enable OHTTP in `add_ingress` by specifying the `ohttp` field.

| Field | Type | Default | Description |
|---|---|---|---|
| `path_rewrites` | array [[PathRewrite](#pathrewrite)] | `[]` | Path rewrite rule list, matched in order |

#### PathRewrite

| Field | Type | Required | Description |
|---|---|---|---|
| `match_regex` | string | Yes | Regular expression matching the inner HTTP request path (full match) |
| `substitution` | string | Yes | Rewritten path, supports `$1` / `$name` to reference capture groups |

> Version 2.0.0+ uses Rust regex's `$ref` syntax for capture group references (backward compatible with `\integer`).

<details>
<summary>Example: OHTTP path rewrite</summary>

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

#### L7 Gateway Compatibility

OHTTP-encrypted HTTP requests follow these rules for compatibility with L7 load balancers:

1. Method is unified as `POST`
2. Path defaults to `/`, can be rewritten via `path_rewrites`
3. Host (or `:authority`) remains consistent with the inner business request
4. `Content-Type` is `message/ohttp-chunked-req` for requests and `message/ohttp-chunked-res` for responses
5. Does not include the original request and response headers of the encrypted request

#### `header_passthrough` (Ingress)

Controls which HTTP headers are copied from the plaintext downstream request
to the outer OHTTP POST request. This allows intermediaries (ALB, WAF, load
balancers) between Ingress and Egress to read specific headers for routing,
tracing, or rate limiting.

| Field | Type | Description |
|---|---|---|
| `request_headers` | `string[]` | Header names to copy from the downstream request to the outer OHTTP POST request. These headers are NOT forwarded to the upstream server — they remain encrypted in the OHTTP body. |

Example:
```json
"ohttp": {
  "header_passthrough": {
    "request_headers": ["x-trace-id", "x-tenant-id"]
  }
}
```


<a name="ohttp-egress-side-configuration"></a>

### Egress Side Configuration

Corresponding to Ingress, enable OHTTP in `add_egress` by specifying the `ohttp` field.

| Field | Type | Default | Description |
|---|---|---|---|
| `cors` | [CorsConfig](#corsconfig) | None | CORS configuration for browser access to OHTTP endpoints |
| `key` | [KeyConfig](#key-management) | None | Key management configuration (see [Key Management](#key-management) below) |

> [!NOTE]
> `allow_non_tng_traffic_regexes` is deprecated since 2.2.4; use `direct_forward` instead.

#### CorsConfig

| Field | Type | Default | Description |
|---|---|---|---|
| `allow_origins` | array [string] | `[]` | Allowed origins; `["*"]` allows all |
| `allow_methods` | array [string] | `[]` | Allowed HTTP methods; `["*"]` allows all |
| `allow_headers` | array [string] | `[]` | Allowed request headers; `["*"]` allows all |
| `expose_headers` | array [string] | `[]` | Response headers accessible to browsers |
| `allow_credentials` | boolean | `false` | Whether to allow credentials |

<details>
<summary>Example: OHTTP + CORS</summary>

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

#### `header_passthrough` (Egress)

Controls which HTTP headers are copied from the plaintext upstream response
to the outer OHTTP HTTP response. This allows intermediaries between Egress
and Ingress to read specific headers.

| Field | Type | Description |
|---|---|---|
| `response_headers` | `string[]` | Header names to copy from the upstream response to the outer OHTTP HTTP response. These headers are NOT forwarded to the downstream client — they remain encrypted in the OHTTP body. |

Example:
```json
"ohttp": {
  "header_passthrough": {
    "response_headers": ["x-custom-header", "x-rate-limit-remaining"]
  }
}
```

<a name="ohttp-key-management"></a>

### Key Management

TNG supports three OHTTP key management strategies.

<a name="ohttp-key-self_generated"></a>

#### self_generated Mode (Default)

TNG autonomously generates HPKE key pairs and automatically rotates them.

| Field | Type | Default | Description |
|---|---|---|---|
| `key.source` | string | `"self_generated"` | Key source |
| `key.rotation_interval` | integer | `300` | Rotation interval in seconds |

<details>
<summary>Example</summary>

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

#### peer_shared Mode

Multiple TNG instances share keys through a QUIC-encrypted channel based on the Serf Gossip protocol. Only nodes verified through remote attestation can participate in key exchange. For a detailed design document covering the protocol, key rotation mechanism, and failure handling, see [Peer Shared Key Sharing Protocol](./peer_shared.md).

| Field | Type | Default | Description |
|---|---|---|---|
| `key.source` | string | `"peer_shared"` | Key source |
| `key.rotation_interval` | integer | `300` | Rotation interval in seconds |
| `key.host` | string | `0.0.0.0` | Serf listen address |
| `key.port` | integer | `8301` | Serf UDP port |
| `key.peers` | array [string] | — | Initial peer node list (`IP:port` or `domain:port`) |
| `key.peers_file` | string | None | JSON file path for dynamic peer list updates |
| `key.attest` | object | None | Configuration for nodes to prove their identity |
| `key.verify` | object | None | Configuration for verifying remote peer identity |
| `key.no_ra` | boolean | `false` | Disable remote attestation between nodes |

<details>
<summary>Example</summary>

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

> 💡 **Join retry behavior**: When a node configured with `peers` (or `peers_file`) starts, it retries joining
> each configured peer with exponential backoff (base 1s, doubling, full jitter,
> capped at 5 minutes) and **does not become operational until every configured peer
> has joined**. This prevents a node from silently bootstrapping as a standalone
> cluster when a peer is briefly unavailable. A node with no configured peers at
> all (a dedicated bootstrap node, `peers: []`) skips joining and bootstraps
> immediately, as before.
>
> New peers discovered later via `peers_file` are also retried in the background
> (non-blocking) until joined.

<a name="ohttp-key-file"></a>

#### file Mode

Load OHTTP HPKE private key from an external file, suitable for integration with external key management systems.

| Field | Type | Required | Description |
|---|---|---|---|
| `key.source` | string | Yes | Set to `"file"` |
| `key.path` | string | Yes | PEM-format PKCS#8 X25519 private key file path |

File format example:
```pem
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEILi5PepL11X3ptJneUQu40m2kiuNeLD9MRK4CYh94t1d
-----END PRIVATE KEY-----
```

Generate using `openssl genpkey -algorithm X25519 -outform PEM`. TNG uses inotify to monitor file changes and automatically reloads the key.

<details>
<summary>Example</summary>

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
> This interface is completely different from the [Envoy Admin Interface](#deprecated-configuration) described in [Deprecated Configuration](#deprecated-configuration).

| Field | Type | Default | Description |
|---|---|---|---|
| `control_interface.restful.host` | string | `0.0.0.0` | Listen address |
| `control_interface.restful.port` | integer | — | Listen port (required) |

<details>
<summary>Example</summary>

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

| Endpoint | Description |
|---|---|
| `/livez` | Liveness check; returns `200 OK` indicating the instance is running |
| `/readyz` | Readiness check; returns `200 OK` indicating the instance can handle traffic |
| `/status/` | Returns a list of available component types (e.g., `["egress", "ingress"]`) |
| `/status/egress/` | Returns a list of egress instance IDs |
| `/status/egress/{id}/` | Returns a list of resources for the specified egress |
| `/status/egress/{id}/ohttp/keys` | Returns the OHTTP key status snapshot for the specified egress |
| `/status/ingress/` | Returns a list of ingress instance IDs |
| `/status/ingress/{id}/ohttp/keys` | Returns the ingress OHTTP client cache state |

---

<a name="deprecated-configuration"></a>

## Deprecated Configuration

<a name="envoy_admin_interface"></a>

### admin_bind (Envoy Admin Interface)

> [!WARNING]
> Deprecated. TNG has abandoned integration with Envoy; configuring this option has no effect.

| Field | Type | Description |
|---|---|---|
| `admin_bind.host` | string | Listen address, default `0.0.0.0` |
| `admin_bind.port` | integer | Listen port (required) |

> This port does not use authentication; do not use it in production environments.

<details>
<summary>Example (deprecated)</summary>

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

<a name="observability"></a>

## Observability

Includes Log, Metric, and Trace aspects.

### Log

TNG outputs logs to standard output by default. Control the log level via the `RUST_LOG` environment variable: `error`, `warn`, `info`, `debug`, `trace`, `off`. Default is `info`, with all third-party library logs disabled.

> Supports complex configurations; see [tracing-subscriber EnvFilter](https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives).

### Metric

| Scope | Name | Type | Description |
|---|---|---|---|
| Instance | `live` | Gauge | `1` indicates instance is alive and healthy |
| ingress/egress | `tx_bytes_total` | Counter | Total bytes sent |
| ingress/egress | `rx_bytes_total` | Counter | Total bytes received |
| ingress/egress | `cx_active` | Gauge | Currently active connections |
| ingress/egress | `cx_total` | Counter | Total connections |
| ingress/egress | `cx_failed` | Counter | Total failed connections |

**Export labels:**

| Mode | Labels |
|---|---|
| ingress mapping | `ingress_type=mapping,ingress_id={id},ingress_in={in.host}:{in.port},ingress_out={out.host}:{out.port}` |
| ingress http_proxy | `ingress_type=http_proxy,ingress_id={id},ingress_proxy_listen={proxy_listen.host}:{proxy_listen.port}` |
| egress mapping | `egress_type=netfilter,egress_id={id},egress_in={in.host}:{in.port},egress_out={out.host}:{out.port}` |
| egress netfilter | `egress_type=netfilter,egress_id={id},egress_listen_port={listen_port}` |

**Supported Exporters:**

| Type | Configuration Fields |
|---|---|
| `otlp` | `protocol` (`grpc`/`http/protobuf`/`http/json`), `endpoint`, `headers`, `step` (default 60s) |
| `falcon` | `server_url`, `endpoint`, `tags`, `step` (default 60s) |
| `stdout` | `step` (default 60s) |

<details>
<summary>Example: OTLP</summary>

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
<summary>Example: Falcon</summary>

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

Supports OpenTelemetry standard tracing export.

| Type | Description |
|---|---|
| `otlp` | `protocol` (`grpc`/`http/protobuf`/`http/json`), `endpoint`, `headers` |
| `stdout` | Synchronous output; impacts performance under high concurrency; for debugging only |

<details>
<summary>Example</summary>

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

## Appendix: Regular Expression Syntax

Some fields in TNG configuration allow specifying regular expressions.

| Version | Syntax |
|---|---|
| Before 2.0.0 | RE2 syntax; see [Google RE2](https://github.com/google/re2/wiki/Syntax) |
| 2.0.0+ | Rust regex syntax; does not support look-around and backreferences; see [regex crate](https://docs.rs/regex/1.11.1/regex/index.html#syntax) |
