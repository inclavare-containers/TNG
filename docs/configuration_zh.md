# 参数手册

## 顶层配置对象

- **`control_interface`** (ControlInterface)：TNG实例的控制面配置。
- **`metrics`** (Metrics)：指定tng实例的Metrics配置，在未指定该选项时将不启用Metrics功能。
- **`add_ingress`** (array [Ingress])：在`add_ingress`数组中添加tng隧道的入口端点（ingress），根据client侧用户场景，可以选择对应的流量入站方式。
- **`add_egress`** (array [Egress])：在`add_egress`数组中添加tng隧道的出口端点（egress），根据server侧用户场景，可以选择对应的流量出站方式。
- （已废弃）**`admin_bind`** (AdminBind)：Envoy实例的Admin Interface配置，在未指定该选项时将不开启Admin Interface功能

## Ingress

`Ingress`对象用于配置tng隧道的入口端点，控制流量入站到tng隧道的方式，支持多种流量入站方式。

### 字段说明

- **`ingress_mode`** (IngressMode)：指定流量入站的方式，可以是`mapping`、`http_proxy`或`netfilter`。
- （已废弃）**`encap_in_http`** (EncapInHttp, 可选)：HTTP封装配置。该配置已在2.2.5中废弃，请改用`ohttp`字段代替。
- **`ohttp`** (OHttp, 可选)：OHTTP配置。
- **`no_ra`** (boolean, 可选，默认为`false`)：是否禁用远程证明。将该选项设置为`true`表示在该隧道端点上，tng用普通的X.509证书进行通信，而不触发远程证明流程。请注意该证书为tng代码中内嵌的一个固定的P256 X509自签名证书，不具有机密性，因此**该选项仅作调试用途，不应被用于生产环境**。该选项不能与`attest`或`verify`同时存在。
- **`attest`** (Attest, 可选)：若指定该字段，表示在该隧道端点上tng扮演Attester角色。
- **`verify`** (Verify, 可选)：若指定该字段，表示在该隧道端点上tng扮演Verifier角色。

## IngressMode

### mapping：端口映射方式

在该场景中，tng监听一个本地tcp端口（`in.host`, `in.port`），将所有tcp请求加密后发送到指定tcp端点（`out.host`, `out.port`）。因此用户的client程序需要改变其tcp请求的目标到（`in.host`, `in.port`）上。

#### 字段说明

- **`r#in`** (Endpoint)：
    - **`host`** (string, 可选，默认为`0.0.0.0`)：监听的主机地址。
    - **`port`** (integer)：监听的端口号。
- **`out`** (Endpoint)：
    - **`host`** (string)：目标主机地址。
    - **`port`** (integer)：目标端口号。

示例：

```json
{
    "add_ingress": [
        {
            "mapping": {
                "in": {
                    "host": "0.0.0.0",
                    "port": 10001
                },
                "out": {
                    "host": "127.0.0.1",
                    "port": 20001
                }
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": [
                    "default"
                ]
            }
        }
    ]
}
```

### http_proxy：HTTP代理方式

在该场景中，tng监听一个本地http proxy端口，用户容器可通过设置`http_proxy`环境变量（或在业务代码中发送请求时特地设置`http_proxy`代理），将流量走代理到tng client监听的端口，后者负责将所有用户tcp请求加密后发送到原目标地址。因此用户的client程序无需修改其tcp请求的目标。


#### 字段说明

- **`proxy_listen`** (Endpoint)：指定tng暴露的`http_proxy`协议监听端口的监听地址(`host`)和端口(`port`)值
    - **`host`** (string, 可选，默认为`0.0.0.0`)：监听的本地地址。
    - **`port`** (integer)：监听的端口号。
- **`dst_filters`** (array [EndpointFilter], 可选，默认为空数组)：该项指定了一个过滤规则，指示需要被tng隧道保护的目标域名（或ip）和端口的组合。除了被该过滤规则匹配的流量外，其余流量将不会进入tng隧道，而是以明文形式转发出去（这样能够确保不需要保护的普通流量请求正常发出）。当未指定该字段或者指定为空数组时，所有流量都会进入tng隧道。
    - **`domain`** (string, 可选，默认为`*`)：匹配的目标域名。该字段并不支持正则表达式，但是支持部分类型的通配符（*）。具体语法，请参考envoy文档中`config.route.v3.VirtualHost`类型的`domains`字段的[表述文档](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost)
    - **`domain_regex`** (string, 可选，默认为`.*`)：匹配的目标域名的正则表达式，该字段支持完整的正则表达式语法。`domain_regex`字段和`domain`只能同时指定其中之一。
    - **`port`** (integer, 可选，默认为`80`)：匹配的目标端口。如不指定则默认为80端口
- （已废弃）**`dst_filter`** (EndpointFilter)：在1.0.1及以前版本的TNG中使用，为必选参数，现已被`dst_filters`替代，保留此项是为了兼容旧版中的配置


示例：

```json
{
    "add_ingress": [
        {
            "http_proxy": {
                "proxy_listen": {
                    "host": "0.0.0.0",
                    "port": 41000
                },
                "dst_filters": [
                    {
                        "domain": "*.pai-eas.aliyuncs.com",
                        "port": 80
                    }
                ]
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": [
                    "default"
                ]
            }
        }
    ]
}
```


### socks5：Socks5代理方式

在本场景中，tng创建一个本地sock5代理服务器端口，用户程序可以连接到该socks5代理服务器，从而将请求代理到tng中，后者负责将所有用户tcp请求加密后发送到原目标地址。在该过程中，用户的client程序除了需要配置一个socks5代理选项，无需修改其tcp请求的目标。

#### 字段说明

- **`proxy_listen`** (Endpoint)：指定tng暴露的`socks5`协议监听端口的监听地址(`host`)和端口(`port`)值
    - **`host`** (string, 可选，默认为`0.0.0.0`)：监听的本地地址。
    - **`port`** (integer)：监听的端口号。
- **`auth`** (Socks5Auth，可选)：指定本地监听的socks5端口所需要的访问认证方式，您可以使用该选项来限制只有知道密码的程序能够访问该socks5代理端口。
    - **`username`** (string)：socks5代理认证所需的用户名。
    - **`password`** (string)：socks5代理认证所需的密码。
- **`dst_filters`** (array [EndpointFilter], 可选，默认为空数组)：该项指定了一个过滤规则，指示需要被tng隧道保护的目标域名（或ip）和端口的组合。除了被该过滤规则匹配的流量外，其余流量将不会进入tng隧道，而是以明文形式转发出去（这样能够确保不需要保护的普通流量请求正常发出）。当未指定该字段或者指定为空数组时，所有流量都会进入tng隧道。
    - **`domain`** (string, 可选，默认为`*`)：匹配的目标域名。该字段并不支持正则表达式，但是支持部分类型的通配符（*）。具体语法，请参考envoy文档中`config.route.v3.VirtualHost`类型的`domains`字段的[表述文档](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost)
    - **`domain_regex`** (string, 可选，默认为`.*`)：匹配的目标域名的正则表达式，该字段支持完整的正则表达式语法。`domain_regex`字段和`domain`只能同时指定其中之一。
    - **`port`** (integer, 可选，默认为`80`)：匹配的目标端口。如不指定则默认为80端口

> [!NOTE]
> socks5协议有两种版本，分别称为：
> - `socks5`: SOCKS5协议，在客户端侧完成解析域名。
> - `socks5h`: SOCKS5协议，在代理服务器侧完成解析域名。
> 如果您的客户端使用`socks5`而不是`socks5h`，那么tng中SOCKS5代理服务器将无法获得客户端请求的原始域名，而只能获得请求的目标IP地址，这可能导致您的`dst_filters`规则无法生效。幸运的是，大部分现代客户端实现的是`socks5h`版本，或者同时提供两种选择（例如curl）。如果你的客户端不是这样，请增加对IP地址的匹配，或者改用其它类型的ingress比如`http_proxy`。 


示例：

```json
{
    "add_ingress": [
        {
            "socks5": {
                "proxy_listen": {
                    "host": "0.0.0.0",
                    "port": 1080
                }
            },
            "verify": {
                "as_addr": "http://192.168.1.254:8080/",
                "policy_ids": [
                    "default"
                ]
            }
        }
    ]
}
```

```json
{
    "add_ingress": [
        {
            "socks5": {
                "proxy_listen": {
                    "host": "0.0.0.0",
                    "port": 1080
                },
                "auth": {
                    "username": "user",
                    "password": "ppppppwd"
                }
            },
            "verify": {
                "as_addr": "http://192.168.1.254:8080/",
                "policy_ids": [
                    "default"
                ]
            }
        }
    ]
}
```

```json
{
    "add_ingress": [
        {
            "socks5": {
                "proxy_listen": {
                    "host": "0.0.0.0",
                    "port": 1080
                },
                "dst_filters": [
                    {
                        "domain": "*.example.com",
                        "port": 30001
                    }
                ]
            },
            "verify": {
                "as_addr": "http://192.168.1.254:8080/",
                "policy_ids": [
                    "default"
                ]
            }
        }
    ]
}
```

### netfilter：透明代理方式

在该场景中，tng将会监听一个本地tcp端口，并通过配置iptables规则，将用户流量转发到tng client监听的该端口。后者负责将所有用户tcp请求加密后发送到原目标地址。因此用户的client程序无需修改其tcp请求的目标。

在该模式下，可以通过配置目标tcp端口、程序所在的cgroup等选项来实现对需要捕获的流量的精确控制。

#### 字段说明

- **`capture_dst`** (array, 可选，默认为空数组)：指定需要被tng隧道捕获的流量的目标地址和端口。如果未指定该字段或者指定为空数组，则所有流量都将被tng隧道捕获。
    该字段以数组形式包含多个对象，每个对象表示一条匹配规则，用于匹配出站TCP请求的目标地址和端口信息。具体规则字段如下：
    - 目标IP地址：可以通过以下两种方式之一进行指定，如未指定，则表示匹配所有目标IP地址：
        - 指定目标IP地址或者IP地址段：
            - **`host`** (string)：需要匹配的目标IP地址或者IP地址段，支持CIDR格式。例如：`192.168.1.1`，`192.168.1.1/32`，`192.168.1.0/24`。
        - 指定目标IP所在的ipset：
            - **`ipset`** (string)：需要匹配的ipset组名称。
    - 目标端口号：可选，如未指定，则表示匹配所有目标端口号
        - **`port`** (integer)：目标端口号。
- **`capture_cgroup`** (array [string], 可选，默认为空数组)：指定需要被tng隧道捕获的流量的cgroup。如果未指定该字段或者指定为空数组，则将忽略capture_cgroup 规则。
- **`nocapture_cgroup`** (array [string], 可选，默认为空数组)：指定不需要被tng隧道捕获的流量的cgroup。

> [!NOTE]
> - `capture_cgroup`和`nocapture_cgroup`字段仅在您的系统使用cgroup v2时受支持。
> - 与[cgroup namespace](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)的关系：由于netfilter的实现限制[\[1\]](https://github.com/torvalds/linux/blob/ec7714e4947909190ffb3041a03311a975350fe0/net/netfilter/xt_cgroup.c#L105)[\[2\]](https://github.com/torvalds/linux/blob/ec7714e4947909190ffb3041a03311a975350fe0/kernel/cgroup/cgroup.c#L6995-L6996)，此处指定的cgroup路径于tng进程本身所在cgroup namespace的视角而言的。因此当使用容器单独运行tng时，如您需要配置`capture_cgroup`和`nocapture_cgroup`字段，请配合docker的`--cgroupns=host`选项使用。

- **`listen_port`** (integer, 可选)：指定tng监听的端口号，用于接收捕获后的请求，通常不需要手动指定。如果未指定该字段，则tng将随机分配一个端口号。
- **`so_mark`** (integer, 可选，默认值为565)：由tng加密后，承载密文流量的TCP请求对应socket的SO_MARK标记值，用于避免解密后的流量再次被netfilter转发到当前的ingress。


对流量的捕获使用如下规则进行

```mermaid
flowchart TD
    A[开始] --> G{capture_cgroup 规则为空?}
    G --是--> D
    G --否--> B{是否匹配任意一条 capture_cgroup 规则?}
    B --否--> C[忽略流量]
    B --是--> D{是否匹配任意一条 nocapture_cgroup 规则?}
    D --是--> C
    D --否--> E{是否命中任意一个 capture_dst 规则?}
    E --是--> F[捕获流量]
    E --否--> C
```

> **注意**：该模式只能捕获TCP流量，且不会捕获发往本机地址的流量

示例：

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    {
                        "host": "127.0.0.1",
                        "port": 30001
                    }
                ],
                "capture_cgroup": ["/tng_capture.slice"],
                "nocapture_cgroup": ["/tng_nocapture.slice"],
                "listen_port": 50000
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": [
                    "default"
                ]
            }
        }
    ]
}
```

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    {
                        "host": "192.168.1.0/24",
                        "port": 30001
                    }
                ],
                "capture_cgroup": ["/tng_capture.slice"],
                "nocapture_cgroup": ["/tng_nocapture.slice"],
                "listen_port": 50000
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": [
                    "default"
                ]
            }
        }
    ]
}
```

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    {
                        "ipset": "myset1",
                        "port": 30001
                    },
                    {
                        "ipset": "myset2",
                        "port": 30001
                    }
                ],
                "capture_cgroup": ["/tng_capture.slice"],
                "nocapture_cgroup": ["/tng_nocapture.slice"],
                "listen_port": 50000
            },
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": [
                    "default"
                ]
            }
        }
    ]
}
```


## Egress
在`add_egress`数组中添加tng隧道的出口端点（egress），根据server侧用户场景，可以选择对应的流量出站方式。

### 字段说明
- **`egress_mode`** (EgressMode)：指定流量出站的方式，可以是`mapping`或`netfilter`。
- **`direct_forward`** (array [DirectForwardRule], 可选)：指定需要直接转发（而不经过解密）的流量的匹配规则。
- （已废弃）**`decap_from_http`** (DecapFromHttp, 可选)：HTTP解封装配置。该配置已在2.2.5中废弃，请改用`ohttp`字段代替。
- **`ohttp`** (OHttp, 可选)：OHTTP配置。
- **`no_ra`** (boolean, 可选，默认为`false`)：是否禁用远程证明。将该选项设置为`true`表示在该隧道端点上，tng用普通的X.509证书进行通信，而不触发远程证明流程。请注意该证书为tng代码中内嵌的一个固定的P256 X509自签名证书，不具有机密性，因此**该选项仅作调试用途，不应被用于生产环境**。该选项不能与`attest`或`verify`同时存在。
- **`attest`** (Attest, 可选)：若指定该字段，表示在该隧道端点上tng扮演Attester角色。
- **`verify`** (Verify, 可选)：若指定该字段，表示在该隧道端点上tng扮演Verifier角色。

### DirectForwardRule

在某些场景中，您可能希望一个被保护的监听端口上通过加密流量的同时，也允许一些普通流量通过（比如healthcheck流量）。

您可以使用`direct_forward`字段指定一组匹配规则，只要其中任意一个规则匹配成功，则该流量将作为普通流量直接转发，而不经过解密。

目前支持的匹配规则有：
- **`http_path`** (string)：将流量解析为HTTP请求，并通过正则表达式匹配HTTP请求URI中的[Path](https://developer.mozilla.org/zh-CN/docs/Web/API/URL/pathname)。

示例：

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": {
                    "port": 30001
                }
            },
            "direct_forward": [
                {
                    "http_path": "/public/.*"
                }
            ],
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```
上面的示例配置里一个`netfilter`类型的egress，在允许通过加密流量访问30001端口的同时，允许路径与正则表达式`/public/.*`相匹配的未加密HTTP请求流量通过。


## EgressMode

### mapping：端口映射方式
在该场景中，tng监听一个本地tcp端口（`in.host`, `in.port`），将所有tcp请求解密后发送到指定tcp端点（`out.host`, `out.port`）。用户的server程序需要改变其tcp监听端口监听在（`out.host`, `out.port`）上。

#### 字段说明
- **`in`** (Endpoint)：指定tng监听的本地tcp端口。
    - **`host`** (string, 可选，默认为`0.0.0.0`)：监听的本地地址。
    - **`port`** (integer)：监听的端口号。
- **`out`** (Endpoint)：指定解密后的tcp请求发送的目标端点。
    - **`host`** (string)：目标地址。
    - **`port`** (integer)：目标端口号。

示例：
```json
{
    "add_egress": [
        {
            "mapping": {
                "in": {
                    "host": "127.0.0.1",
                    "port": 20001
                },
                "out": {
                    "host": "127.0.0.1",
                    "port": 30001
                }
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```

### netfilter：端口劫持方式
在该场景中，用户的server程序已监听在本机某一端口，且因业务原因不便变更端口号或为tng新增开放端口。为了让tng能够解密发往server程序端口（`capture_dst.host`, `capture_dst.port`）上的TCP流量，需要结合内核netfilter提供的能力，将流量重定向到tng监听的`listen_port`上。tng在解密完流量后，将TCP流量按照原先的目标（`capture_dst.host`, `capture_dst.port`）发出。

#### 字段说明
- **`capture_dst`** (Endpoint)：指定需要被tng捕获的目标端点。
    - **`host`** (string, 可选，默认匹配本机上所有端口的本地ip地址)：目标地址。若不填，则默认匹配本机上所有端口的本地ip地址（见iptables的 `-m addrtype --dst-type LOCAL` 选项：[iptables-extensions.man.html](https://ipset.netfilter.org/iptables-extensions.man.html)）。
    - **`port`** (integer)：目标端口号。
- **`capture_local_traffic`** (boolean, 可选，默认为`false`)：若值为`false`则在捕获时会忽略源ip为本机ip的请求，不会将它们重定向到`listen_port`。若值为`true`，则会连带捕获源ip为本机ip的请求。
- **`listen_port`** (integer, 可选，默认从40000端口开始递增取值)：tng监听的端口号，用于接收由netfilter重定向的流量。
- **`so_mark`** (integer, 可选，默认值为565)：tng解密后，承载明文流量的TCP请求对应socket的SO_MARK标记值，用于避免解密后的流量再次被netfilter转发到这一egress。

示例：

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": {
                    "host": "127.0.0.1",
                    "port": 30001
                },
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

## Attester

将TNG端点配置为远程证明Attester角色所需的相关参数。

> 目前只支持通过[Attestation Agent](https://github.com/confidential-containers/guest-components/tree/main/attestation-agent)获取evidence。

### 字段说明
- **`aa_addr`** (string)：指定Attestation Agent (AA) 的地址。
- **`refresh_interval`** (int，可选，默认值为600)：指定从Attestation Agent获取证明材料（Evidence）并更新自身X.509证书的频率（单位为秒）。如果指定为0，则在每次安全会话建立时都请求获取最新的Evidence。

示例：

```json
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
```

```json
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                "refresh_interval": 600
            }
```

## Verifier

将TNG端点配置为远程证明Verifier角色所需的相关参数。

> 目前只支持通过[Attestation Service](https://github.com/confidential-containers/trustee/tree/main/attestation-service)消费和验证对端发来的evidence。

### 字段说明
- **`as_addr`** (string)：指定要连接到的Attestation Service (AS) 的URL。支持连接到以gRPC协议和Restful HTTP两种协议类型的Attestation Service。默认将其解析为Restful HTTP的URL，可通过`as_is_grpc`选项控制。
- **`as_is_grpc`** (boolean, 可选，默认为false)：若设置为`true`，这将`as_addr`解释为gRPC URL。
- **`policy_ids`** (array [string])：指定要使用的policy ID列表。
- **`trusted_certs_paths`** (array [string], 可选，默认为空)：指定用于验证AS token中的签名和证书链的根CA证书路径。如果指定多个根CA证书，只要其中一个能够验证即通过。如果不指定该字段或指定为空，则跳过证书验证。

示例：连接到Restful HTTP类型的AS服务

```json
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": [
                    "default"
                ]
            }
```

示例：连接到gRPC类型的AS服务

```json
            "verify": {
                "as_addr": "http://127.0.0.1:5000/",
                "as_is_grpc": true,
                "policy_ids": [
                    "default"
                ]
            }
```

示例：指定验证AS token的根证书路径

```json
            "verify": {
                "as_addr": "http://127.0.0.1:8080/",
                "policy_ids": [
                    "default"
                ],
                "trusted_certs_paths": [
                    "/tmp/as-ca.pem"
                ]
            }
```

## Attester和Verifier的组合与双向远程证明

通过在隧道两端（包括ingress和egress）上配置不同的`attest`和`verify`属性组合，可以实现灵活的信任模型

|远程证明场景|tng client配置|tng server配置|说明|
|---|---|---|---|
|单向|`verify`|`attest`|最常见场景，tng server在TEE中，tng client在普通环境|
|双向|`attest`、`verify`|`attest`、`verify`|tng server和tng client在两个不同TEE中|
|（逆）单向|`attest`|`verify`|tng server在普通环境，tng client在TEE中。此时等于只验证client证书，在tls握手中，tng server会用tng代码中内嵌的一个固定的P256 X509自签名证书来作为自己的证书|
|无TEE（仅作调试用途）|`no_ra`|`no_ra`|tng server和tng client都在非TEE环境中，此时tng client和tng server之间通过单向验证建立普通的TLS会话|


### Background Check模式

[Background Check](https://datatracker.ietf.org/doc/html/rfc9334#name-background-check-model)是TNG默认的远程证明模式，符合[RATS RFC 9334文档](https://datatracker.ietf.org/doc/html/rfc9334)中定义的标准模式。在该模式下，证明方（Attester）通过Attestation Agent获取证明材料，验证方（Verifier）直接验证这些证明材料。验证过程需要验证方能够访问Attestation Service来验证证明的有效性。

> [!NOTE]
> 在许多场景中，Background Check模式也称为"背调模型"

> [!NOTE]
> 当配置中未指定`"model"`字段时，TNG会自动使用Background Check模式。

#### Attest（Background Check模式）

在Background Check模式下，[Attest](#attest)配置需要包含以下字段：

- **`model`** (string，可选): 设置为"background_check"以启用Background Check模式
- **`aa_addr`** (string): Attestation Agent的地址
- **`refresh_interval`** (integer, 可选): 证明刷新间隔（秒）

示例：

```json
"attest": {
    "model": "background_check",
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
    "refresh_interval": 3600
}
```

#### Verify（Background Check模式）

在Background Check模式下，[Verify](#verify)配置需要包含以下字段：

- **`model`** (string，可选): 设置为"background_check"以启用Background Check模式
- **`as_addr`** (string): Attestation Service的地址
- **`as_is_grpc`** (boolean, 可选，默认为false): Attestation Service是否使用gRPC协议
- **`policy_ids`** (array [string]): 策略ID列表
- **`trusted_certs_paths`** (array [string], 可选): 受信任的证书路径列表

示例：

```json
"verify": {
    "model": "background_check",
    "as_addr": "http://127.0.0.1:8080/",
    "as_is_grpc": false,
    "policy_ids": [
        "default"
    ]
}
```

### Passport模式

除了Background Check模式外，TNG还支持符合[RATS RFC 9334文档](https://datatracker.ietf.org/doc/html/rfc9334)中定义的[Passport模式](https://datatracker.ietf.org/doc/html/rfc9334#name-passport-model)的远程证明。在Passport模式中，证明方（Attester）通过Attestation Agent获取证明，并将其提交给Attestation Service获取Token（即Passport）。验证方（Verifier）只需验证该Token的有效性，而无需直接与Attestation Service交互。

Passport模式适用于网络隔离或性能要求较高的场景，因为它减少了验证方与Attestation Service之间的交互。

> [!NOTE]
> 在许多场景中，Passport模式也称为"护照模型"

#### Attest（Passport模式）

在Passport模式下，[Attest](#attest)配置需要包含以下字段：

- **`model`** (string): 设置为"passport"以启用Passport模式
- **`aa_addr`** (string): Attestation Agent的地址
- **`refresh_interval`** (integer, 可选): 证明刷新间隔（秒）
- **`as_addr`** (string): Attestation Service的地址
- **`as_is_grpc`** (boolean, 可选，默认为false): Attestation Service是否使用gRPC协议
- **`policy_ids`** (array [string]): 策略ID列表
- **`trusted_certs_paths`** (array [string], 可选): 受信任的证书路径列表

示例：

```json
"attest": {
    "model": "passport",
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
    "refresh_interval": 3600,
    "as_addr": "http://127.0.0.1:8080/",
    "as_is_grpc": false,
    "policy_ids": [
        "default"
    ]
}
```

#### Verify（Passport模式）

在Passport模式下，[Verify](#verify)配置需要包含以下字段：

- **`model`** (string): 设置为"passport"以启用Passport模式
- **`policy_ids`** (array [string]): 策略ID列表
- **`trusted_certs_paths`** (array [string], 可选): 受信任的证书路径列表

示例：

```json
"verify": {
    "model": "passport",
    "policy_ids": [
        "default"
    ]
}
```

## OHTTP

OHTTP (Oblivious HTTP) 是一种旨在增强隐私保护的网络协议扩展，通过在HTTP请求层面进行加密，提供端到端的隐私保护和匿名性增强。TNG可利用OHTTP提供安全通信，同时保持与现有HTTP基础设施的兼容性。

在默认情况下，TNG使用rats-tls协议提供TCP流级别的加密保护，这适用于大多数情况。如果需要启用该特性，可以通过分别在Ingress中配置`ohttp`和在Egress中配置`ohttp`来实现切换为OHTTP协议。

> [!WARNING]  
> 如果启用OHTTP特性，则要求内层被保护的业务必须是http流量，而不能是普通的tcp流量。



### OHttp：入站侧（Ingress）配置

可通过在`add_ingress`对象中指定的`ohttp`字段来开启OHTTP能力。如未指定`ohttp`则不会开启OHTTP能力。

#### 字段说明

- **`path_rewrites`** (array [PathRewrite], 可选，默认为空数组)：该字段指定了以正则表达式的方式进行流量path重写的参数列表。所有重写将按照在path_rewrites列表中的顺序进行，且只会匹配上列表中的一项。如果HTTP 请求未能匹配任何有效的path_rewrites列表成员，这将默认设置OHTTP流量的path为`/`。
    - **`match_regex`** (string)：用于匹配内层被保护的业务http请求的path的正则表达式，该字段的值将被用于针对整个path字符串进行匹配，而不是部分匹配。

    - **`substitution`** (string)：当http请求的原始path与`match_regex`匹配时，OHTTP流量的path将被整个替换为`substitution`的值。

> [!NOTE]
> 关于正则表达式的语法，请参考 <a href="#regex">正则表达式</a> 章节中的说明

> [!NOTE]
> - 在2.0.0之前的版本中，`substitution`字段在该字段中，支持使用`\整数`（整数从1开始）的方式来引用`match_regex`字段中的正则表达式所匹配到的组中的内容。例如该字段中的`\1`将被替换为匹配到的第一个组中的内容。具体规则请参考envoy中对应的`substitution`字段的[描述](https://www.envoyproxy.io/docs/envoy/latest/api-v3/type/matcher/v3/regex.proto#type-matcher-v3-regexmatchandsubstitute)。
> - 在2.0.0版本及之后的版本中，上述引用规则已被淘汰，支持以`$ref`语法来引用匹配到的组，其中`ref`可以是一个整数，对应于捕获组的索引，或者它可以是一个名称，用于引用被命名的组。具体规则请参考[此处](https://docs.rs/regex/1.11.1/regex/struct.Regex.html#method.replace)。此外，`substitution`字段仍然支持上述`\整数`引用规则，以提供后向兼容性。


示例：

在这个示例中，我们添加了一个PathRewrite规则，表示将path能够匹配上`^/foo/bar/([^/]+)([/]?.*)$`的所有用户HTTP Reqesut，其tng隧道的OHTTP流量的path重写为`/foo/bar/$1`（注意其中`$1`是一个正则替换规则）。

```json
{
    "add_ingress": [
        {
            "mapping": {
                "in": {
                    "host": "0.0.0.0",
                    "port": 10001
                },
                "out": {
                    "host": "127.0.0.1",
                    "port": 20001
                }
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
                "policy_ids": [
                    "default"
                ]
            }
        }
    ]
}
```


#### L7网关兼容性

在使用7层网关许多场景中，TNG在使用OHTTP协议保护流量后，通常需要保留原始流量的一些字段，以便路由、负载均衡等功能正常运作。但出于数据机密性的考虑，加密保护后的HTTP请求中的字段不应该包含敏感信息。因此，tng提供了一些规则来配置加密保护后的HTTP请求的字段：
1. 加密后的HTTP请求的请求method统一为`POST`
2. 加密后的HTTP请求的请求路径path默认为`/`，也可以通过指定`path_rewrites`字段，根据内层被保护的业务http请求的path以正则表达式的方式重写出加密后的HTTP请求的path。
3. 加密后的HTTP请求的Host（或者`:authority`）和内层被保护的业务http请求保持一致。
4. 加密后的HTTP请求和响应将分别使用`Content-Type: message/ohttp-chunked-req`和`Content-Type: message/ohttp-chunked-res`作为`Content-Type`。
5. 加密后的HTTP请求及响应中将不包含被加密HTTP请求中的请求头和响应头。


### OHttp：出站侧（Egress）配置
与入站侧的配置对应，出站侧可通过在`add_egress`对象中指定`ohttp`字段来开启OHTTP支持。如不指定`ohttp`字段则不使用OHTTP协议。

> [!NOTE]
> `allow_non_tng_traffic_regexes`在2.2.4版本及之后的版本中已被弃用，请使用`direct_forward`字段来替代。

此外，还可通过配置`allow_non_tng_traffic_regexes`子项，除了允许tng加密流量传入端点，还将允许非加密http请求流量传入，这可以满足一些同时需要两种流量的场景（如healthcheck）。该子项的值为一个json字符串列表，其中的每项是一个正则表达式匹配语句，只有http请求PATH与该正则语句完全匹配的非加密http请求流量，才会被TNG放行。子项的默认值为`[]`，即拒绝任何非加密http请求。

#### 字段说明
- (已废弃) **`allow_non_tng_traffic_regexes`** (array [string], 已弃用，可选，默认为空数组)：该字段指定了允许非加密http请求流量传入的正则表达式列表。每个元素是一个正则表达式字符串，只有当http请求路径与这些正则表达式匹配时，非加密http请求流量才会被放行。
- **`cors`** (CorsConfig, 可选)：OHTTP服务器的CORS配置。该字段允许您配置跨域资源共享（CORS）头部，以启用基于浏览器的访问OHTTP端点。

    - **`allow_origins`** (array [string], 可选，默认为空)：允许访问OHTTP端点的来源列表。使用`["*"]`允许所有来源。
    
    - **`allow_methods`** (array [string], 可选，默认为空)：允许用于跨域请求的HTTP方法列表（例如`["GET", "POST", "OPTIONS"]`）。使用`["*"]`允许所有方法。
    
    - **`allow_headers`** (array [string], 可选，默认为空)：允许在跨域请求中使用的头部列表（例如`["Content-Type", "Authorization"]`）。使用`["*"]`允许所有头。
    
    - **`expose_headers`** (array [string], 可选，默认为空)：浏览器被允许从响应中访问的头部列表。使用`["*"]`允许所有头。
    
    - **`allow_credentials`** (boolean, 可选，默认为false)：是否允许在跨域请求中包含凭证（cookies、authorization headers等）。

> [!NOTE]
> 关于正则表达式的语法，请参考 <a href="#regex">正则表达式</a> 章节中的说明


示例：

```json
{
    "add_egress": [
        {
            "mapping": {
                "in": {
                    "host": "127.0.0.1",
                    "port": 20001
                },
                "out": {
                    "host": "127.0.0.1",
                    "port": 30001
                }
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
                {
                    "http_path": "/api/builtin/.*"
                }
            ],
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```

## Control Interface

> [!NOTE]
> 该接口与下面的 <a href="#envoy_admin_interface">Envoy Admin Interface</a> 是完全不同的功能。后者是Envoy内置的管理接口，在未来的版本中，我们将对其删除。

### 字段说明

- **`control_interface`** (ControlInterface, 可选，默认为空)：该字段指定了控制接口的监听地址和端口。
    - **`restful`** (Endpoint, 可选，默认为空)：该字段指定了RESTful API的配置。包含以下子字段：
        - **`host`** (string, 可选，默认为`0.0.0.0`)：监听的本地地址。
        - **`port`** (integer)：监听的端口号，必填。

实例：

```json
                "control_interface": {
                    "restful": {
                        "host": "0.0.0.0",
                        "port": 50000
                    }
                }
```

在该示例中，tng将开启Control Interface，并且其RESTful API接口监听在`0.0.0.0:50000`端口上。

### RESTful API

暴露RESTful API接口，支持以下操作：
- **`/livez`**：该端口返回tng实例的存活状态。如果返回`200 OK`，则表示实例正在运行中。
- **`/readyz`**：该端口返回tng实例的就绪状态。如果返回`200 OK`，则表示实例正在运行中，且已可以处理流量。


## Envoy Admin Interface
<span id = "envoy_admin_interface"></span>

> [!WARNING]
> 由于我们放弃了与envoy的集成，该选项已被弃用。配置该选项将不会有任何效果。

可使用`admin_bind`选项开启envoy实例的[Admin Interface](https://www.envoyproxy.io/docs/envoy/latest/operations/admin)能力。

> [!WARNING]  
> 由于该端口并不使用身份验证，请不要在生产环境中使用该选项。

#### 字段说明
- **`admin_bind`** (Endpoint, 可选，默认为空)：该字段指定了envoy admin interface的监听地址和端口。包含以下子字段：
    - **`host`** (string, 可选，默认为`0.0.0.0`)：监听的本地地址。
    - **`port`** (integer)：监听的端口号，必填。

示例：

在这个示例中，admin_bind字段指定了envoy admin interface的监听地址为0.0.0.0，端口号为9901。

```json
{
    "admin_bind": {
        "host": "0.0.0.0",
        "port": 9901
    }
}
```

## 可观测性（Observability）

可观测性是指对系统运行状态的监控，以帮助运维人员了解系统的运行情况，并采取适当的措施。可观测性的概念包含Log、Metric、Trace三个层面。

### Log

TNG当前版本默认启用了将日志输出到标准输出的能力，用户可以通过`RUST_LOG`环境变量的值控制tng的输出日志等级，支持的等级包括`error``warn``info``debug``trace`和一个特殊的等级`off`。

默认情况下日志为`info`级别，且禁用了所有第三方库的日志。

> [!NOTE]
> 除了简单日志级别外，也支持复杂配置，请参考[tracing-subscriber](https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives) crate 的文档。


### Metric

在TNG中，我们提供如下Metrics：

<table>
    <tr>
        <th>范围</th>
        <th>名称</th>
        <th>类型</th>
        <th>标签</th>
        <th>描述</th>
    </tr>
    <tr>
        <td>实例</td>
        <td><code>live</code></td>
        <td>Gauge</td>
        <td>无</td>
        <td>值为<code>1</code>表示TNG实例存活且健康</td>
    </tr>
    <tr>
        <td rowspan="6">ingress/egress</td>
        <td><code>tx_bytes_total</code></td>
        <td>Counter</td>
        <td rowspan="6"><a href="#metric_labels">见下表</a></td>
        <td>发送的总字节数</td>
    </tr>
    <tr>
        <td><code>rx_bytes_total</code></td>
        <td>Counter</td>
        <td>接收的总字节数</td>
    </tr>
    <tr>
        <td><code>cx_active</code></td>
        <td>Gauge</td>
        <td>目前活跃连接数</td>
    </tr>
    <tr>
        <td><code>cx_total</code></td>
        <td>Counter</td>
        <td>从实例启动到目前为止处理的总连接数</td>
    </tr>
    <tr>
        <td><code>cx_failed</code></td>
        <td>Counter</td>
        <td>从实例启动到目前为止失败的总连接数</td>
    </tr>
</table>


<span id = "metric_labels">ingress/egress的导出标签</span>如下：

| 范围 | 类型 | 标签 | 
| --- | --- | --- |
| ingress | `mapping` | `ingress_type=mapping,ingress_id={id},ingress_in={in.host}:{in.port},ingress_out={out.host}:{out.port}` |
| ingress | `http_proxy` | `ingress_type=http_proxy,ingress_id={id},ingress_proxy_listen={proxy_listen.host}:{proxy_listen.port}` |
| egress | `mapping` | `egress_type=netfilter,egress_id={id},egress_in={in.host}:{in.port},egress_out={out.host}:{out.port}` |
| egress | `netfilter` | `egress_type=netfilter,egress_id={id},egress_listen_port={listen_port}` |


目前，TNG支持如下类型的exporter：

- **`otlp`**：导出到与OpenTelemetry Protocol（OTLP）兼容的端点，如Prometheus和Jaeger。
- **`falcon`**：导出到open-falcon服务
- **`stdout`**：打印到日志输出

您可以通过指定`metric`字段来开启对Metric的支持。


#### 字段说明

- **`metric`** (Metric, 可选，默认为空)：该字段指定了Metric的配置。包含以下子字段：
    - **`exporters`** (array [MetricExporter], 可选，默认为空数组)：该字段指定了Metric的导出器列表。包含以下子字段：
        - **`type`** (string)：该字段指定了Metric的导出器类型。

- 对于OTLP导出器（`type="otlp"`），包含以下子字段：
    - **`protocol`** (string)：该字段指定了OTLP协议的数据格式类型，有如下可选值：
        - `grpc`：使用gRPC上报
        - `http/protobuf`：使用HTTP上报，内容使用protobuf序列化方式
        - `http/json`：使用HTTP上报，内容使用json序列化方式
    - **`endpoint`** (string)：该字段指定了OTLP端点的url
    - **`headers`** (Map，可选)：发出的导出请求中需附加的HTTP Header列表。例如，可以附加`Authorization`请求头满足OTLP端点的鉴权需求。此外，无论是否填写该字段，都可以通过[环境变量](https://opentelemetry.io/docs/languages/sdk-configuration/otlp-exporter/#header-configuration)的方式添加header
    - **`step`** (integer, 可选，默认为60)：该字段指定了metric采集和上报的间隔时间step值，单位为秒。

- 对于open-falcon导出器（`type="falcon"`），包含以下子字段：
    - **`server_url`** (string)：该字段指定了open-falcon服务端地址。
    - **`endpoint`** (string)：该字段指定了每条metric绑定的endpoint值。
    - **`tags`** (map [string], 可选，默认为空)：该字段指定了每条metric的额外附加标签，这些标签将和TNG产生的metric的标签一起被发送给open-falcon服务端。
    - **`step`** (integer, 可选，默认为60)：该字段指定了metric采集和上报的间隔时间step值，单位为秒。

- 对于stdout导出器（`type="stdout"`），包含以下子字段：
    - **`step`** (integer, 可选，默认为60)：该字段指定了metric采集和打印的间隔时间step值，单位为秒。

示例：

```json
{
    "metric": {
        "exporters": [
            {
                "type": "oltp",
                "protocol": "http/protobuf",
                "endpoint": "https://oltp.example.com/example/url",
                "headers": {
                    "Authorization": "XXXXXXXXX",
                },
                "step": 2
            }
        ]
    }
}
```

```json
{
    "metric": {
        "exporters": [
            {
                "type": "falcon",
                "server_url": "http://127.0.0.1:1988",
                "endpoint": "master-node",
                "tags": {
                    "namespace": "ns1",
                    "app": "tng"
                },
                "step": 60
            }
        ]
    }
}
```

```json
{
    "metric": {
        "exporters": [
            {
                "type": "stdout",
                "step": 60
            }
        ]
    }
}
```

### Trace

TNG支持OpenTelemetry标准语义下的tracing事件导出，包括每个请求中的Trace、Span、Events信息。

支持如下类型的exporter：

- **`otlp`**：导出到与OpenTelemetry Protocol（OTLP）兼容的端点。
- **`stdout`**：打印到标准输出，注意该导出器将以同步方式（而非异步方式）输出Trace信息，在高并发情况下对性能有较大影响，故应仅作调试使用。

您可以通过指定`trace`字段来开启对Trace的支持。


#### 字段说明

- **`trace`** (Trace, 可选，默认为空)：该字段指定了Trace的配置。包含以下子字段：
    - **`exporters`** (array [TraceExporter], 可选，默认为空数组)：该字段指定了Trace的导出器列表。包含以下子字段：
        - **`type`** (string)：该字段指定了Trace的导出器类型。

- 对于OTLP导出器（`type="otlp"`），包含以下子字段：
    - **`protocol`** (string)：该字段指定了OTLP协议的数据格式类型，有如下可选值：
        - `grpc`：使用gRPC上报
        - `http/protobuf`：使用HTTP上报，内容使用protobuf序列化方式
        - `http/json`：使用HTTP上报，内容使用json序列化方式
    - **`endpoint`** (string)：该字段指定了OTLP端点的url
    - **`headers`** (Map，可选)：发出的导出请求中需附加的HTTP Header列表。例如，可以附加`Authorization`请求头满足OTLP端点的鉴权需求。此外，无论是否填写该字段，都可以通过[环境变量](https://opentelemetry.io/docs/languages/sdk-configuration/otlp-exporter/#header-configuration)的方式添加header

- 对于stdout导出器（`type="stdout"`），无需配置额外字段。

示例：

```json
{
    "trace": {
        "exporters": [
            {
                "type": "oltp",
                "protocol": "http/protobuf",
                "endpoint": "https://oltp.example.com/example/url"
            }
        ]
    }
}
```

```json
{
    "trace": {
        "exporters": [
            {
                "type": "stdout"
            }
        ]
    }
}
```

## 正则表达式
<span id = "regex"></span>

TNG配置文件中有部分字段允许指定正则表达式，而在TNG的迭代过程中，正则表达式的语法规则进行了调整，现作说明如下：

- 在2.0.0之前的版本中，仅支持RE2语法。RE2是Google的正则表达式引擎，其语法格式可以参考[此处](https://github.com/google/re2/wiki/Syntax)，如需在线测试语法正确性可以参考[此处的工具](https://re2js.leopard.in.ua/)。
- 在2.0.0版本及之后的版本中，支持的是常见的正则表达式语法，而非RE2语法，因此不支持正向预查（look-around）和 反向引用（backreferences）特性。支持的完整语法规则请参考[此处](https://docs.rs/regex/1.11.1/regex/index.html#syntax)。