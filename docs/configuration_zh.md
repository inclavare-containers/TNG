# 参数手册

## 顶层配置对象

- **`add_ingress`** (array [Ingress])：在`add_ingress`数组中添加tng隧道的入口端点（ingress），根据client侧用户场景，可以选择对应的流量入站方式。
- **`add_egress`** (array [Egress])：在`add_egress`数组中添加tng隧道的出口端点（egress），根据server侧用户场景，可以选择对应的流量出站方式。
- **`admin_bind`** (AdminBind)：(⚠️已废弃) Envoy实例的Admin Interface配置，在未指定该选项时将不开启Admin Interface功能


## Ingress

`Ingress`对象用于配置tng隧道的入口端点，控制流量入站到tng隧道的方式，支持多种流量入站方式。

### 字段说明

- **`ingress_mode`** (IngressMode)：指定流量入站的方式，可以是`mapping`、`http_proxy`或`netfilter`。
- **`encap_in_http`** (EncapInHttp, 可选)：HTTP封装配置。
- **`web_page_inject`** (boolean, 可选，默认为`false`)：开启该选项后，会在网页最上方注入一个标题栏，以显示当前页面的远程证明状态信息，这可以让浏览器用户强感知到远程证明的存在。注意，该功能需要同时指定`encap_in_http`字段
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


### netfilter：透明代理方式

在该场景中，tng监听一个本地tcp端口，并通过配置iptables规则，将用户流量转发到tng client监听的该端口。后者负责将所有用户tcp请求加密后发送到原目标地址。因此用户的client程序无需修改其tcp请求的目标。

> 暂未实现


## Egress
在`add_egress`数组中添加tng隧道的出口端点（egress），根据server侧用户场景，可以选择对应的流量出站方式。

### 字段说明
- **`egress_mode`** (EgressMode)：指定流量出站的方式，可以是`mapping`或`netfilter`。
- **`decap_from_http`** (DecapFromHttp, 可选)：HTTP解封装配置。
- **`no_ra`** (boolean, 可选，默认为`false`)：是否禁用远程证明。将该选项设置为`true`表示在该隧道端点上，tng用普通的X.509证书进行通信，而不触发远程证明流程。请注意该证书为tng代码中内嵌的一个固定的P256 X509自签名证书，不具有机密性，因此**该选项仅作调试用途，不应被用于生产环境**。该选项不能与`attest`或`verify`同时存在。
- **`attest`** (Attest, 可选)：若指定该字段，表示在该隧道端点上tng扮演Attester角色。
- **`verify`** (Verify, 可选)：若指定该字段，表示在该隧道端点上tng扮演Verifier角色。

## EgressMode

### mapping：端口映射方式
在该场景中，tng监听一个本地tcp端口（`in.host`, `in.port`），将所有tcp请求解密后发送到指定tcp端点（`out.host`, `out.port`）。用户的server程序需要改变其tcp监听端口监听在（`in.host`, `in.port`）上。

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
在该场景中，用户的server程序已监听在本机某一端口，且因业务原因不便变更端口号或为tng server新增开放端口。为了让tng server能够解密发往server程序端口（`capture_dst.host`, `capture_dst.port`）上的TCP流量，需要结合内核netfilter提供的能力，将流量重定向到tng server监听的`listen_port`上。tng server在解密完流量后，将TCP流量按照原先的目标（`capture_dst.host`, `capture_dst.port`）发出。

#### 字段说明
- **`capture_dst`** (Endpoint)：指定需要被tng server捕获的目标端点。
    - **`host`** (string, 可选，默认匹配本机上所有端口的本地ip地址)：目标地址。若不填，则默认匹配本机上所有端口的本地ip地址（见iptables的 `-m addrtype --dst-type LOCAL` 选项：[iptables-extensions.man.html](https://ipset.netfilter.org/iptables-extensions.man.html)）。
    - **`port`** (integer)：目标端口号。
- **`capture_local_traffic`** (boolean, 可选，默认为`false`)：若值为`false`则在捕获时会忽略源ip为本机ip的请求，不会将它们重定向到`listen_port`。若值为`true`，则会连带捕获源ip为本机ip的请求。
- **`listen_port`** (integer, 可选，默认从40000端口开始递增取值)：tng server监听的端口号，用于接收由netfilter重定向的流量。
- **`so_mark`** (integer, 可选，默认值为565)：tng server解密后，承载明文流量的TCP请求对应socket的SO_MARK标记值，用于避免解密后的流量再次被netfilter转发到tng server。

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

示例：

```json
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
```

## Verifier

将TNG端点配置为远程证明Verifier角色所需的相关参数。

> 目前只支持通过[Attestation Service](https://github.com/confidential-containers/trustee/tree/main/attestation-service)消费和验证对端发来的evidence。

### 字段说明
- **`as_addr`** (string)：指定要连接到的Attestation Service (AS) 的URL。支持连接到以gRPC协议和Restful HTTP两种协议类型的Attestation Service。默认将其解析为Restful HTTP的URL，可通过`as_is_grpc`选项控制。
- **`as_is_grpc`** (boolean, 可选，默认为false)：若设置为`true`，这将`as_addr`解释为gRPC URL。
- **`policy_ids`** (array of strings)：指定要使用的policy ID列表。
- **`trusted_certs_paths`** (array of strings, 可选，默认为空)：指定用于验证AS token中的签名和证书链的根CA证书路径。如果指定多个根CA证书，只要其中一个能够验证即通过。如果不指定该字段或指定为空，则跳过证书验证。

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


## 伪装成七层流量

在现代的服务端开发中，app client和app server之间通常采用http协议通信，且链路中很可能经过HTTP中间件（如nginx反向代理、仅允许7层的负载均衡服务等）。然而，tng的rats-tls流量可能无法通过这些HTTP中间件，为了在业务中以尽可能少的负担接入tng，我们提供一个特性将tng的rats-tls流量伪装成七层http流量。

这一特性可以通过分别在Ingress中配置EncapInHttp和在Egress中配置DecapFromHttp来实现

鉴于这些中间组件的特性，tng在伪装成http流量后通常需要保留原始流量的一些字段，以便路由、负载均衡等功能正常运作。但出于数据机密性的考虑，伪装后http流量中的字段不应该包含敏感信息。因此，tng提供了一些规则来配置伪装后http流量的字段：
1. 伪装后http流量的请求method统一为`POST`
2. 伪装后http流量的请求路径path默认为`/`，也可以通过指定`path_rewrites`字段，根据内层被保护的业务http请求的path以正则表达式的方式重写出伪装后http流量的path。
3. 伪装后http流量的Host（或者`:authority`）和内层被保护的业务http请求保持一致。
4. 伪装后http流量将带有一个名为`tng`的请求头，可用于区分普通流量和伪装后流量。同时原业务流量中的请求头将被隐去。

> [!WARNING]  
> 如果启用「伪装成七层流量」特性，则要求内层被保护的业务必须是http流量，而不能是普通的tcp流量。

### EncapInHttp：入站侧流量的伪装

可通过在`add_ingress`对象中指定的`encap_in_http`字段来开启伪装能力。如未指定`encap_in_http`则不会开启伪装能力。

#### 字段说明
- **`path_rewrites`** (array [PathRewrite], 可选，默认为空数组)：该字段指定了以正则表达式的方式进行流量path重写的参数列表。所有重写将按照在path_rewrites列表中的顺序进行，且只会匹配上列表中的一项。如果HTTP 请求未能匹配任何有效的path_rewrites列表成员，着将默认设置伪装后http流量的path为`/`。
    - **`match_regex`** (string)：用于匹配内层被保护的业务http请求的path的正则表达式。
    - **`substitution`** (string)：当path匹配上match_regex时，伪装后http流量的path将被重写为substitution。支持使用`\数字`的方式来引用正则匹配到的group。

示例：

在这个示例中，我们添加了一个PathRewrite规则，表示将path能够匹配上`^/foo/bar/([^/]+)([/]?.*)$`的所有用户HTTP Reqesut，其tng隧道的HTTP外壳流量的path重写为`/foo/bar/\1`（注意其中`\1`是一个正则替换规则）。

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
            "encap_in_http": {
                "path_rewrites": [
                    {
                        "match_regex": "^/foo/bar/([^/]+)([/]?.*)$",
                        "substitution": "/foo/bar/\\1"
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

### DecapFromHttp：出站侧流量的伪装
与入站侧的配置对应，出站侧可通过在`add_egress`对象中指定`decap_from_http`字段来开启对已伪装流量的拆解。如不指定`decap_from_http`字段则不开启。

此外，还可通过配置`allow_non_tng_traffic_regexes`子项，除了允许tng加密流量传入端点，还将允许非加密http请求流量传入，这可以满足一些同时需要两种流量的场景（如healthcheck）。该子项的值为一个json字符串列表，其中的每项是一个正则表达式匹配语句，只有http请求PATH与该正则语句完全匹配的非加密http请求流量，才会被TNG放行。子项的默认值为`[]`，即拒绝任何非加密http请求。

#### 字段说明
- **`allow_non_tng_traffic_regexes`** (array [string], 可选，默认为空数组)：该字段指定了允许非加密http请求流量传入的正则表达式列表。每个元素是一个正则表达式字符串，只有当http请求路径与这些正则表达式匹配时，非加密http请求流量才会被放行。


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
            "decap_from_http": {
                "allow_non_tng_traffic_regexes": ["/api/builtin/.*"]
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```

### Envoy Admin Interface

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

### 可观测性（Observability）

可观测性是指对系统运行状态的监控，以帮助运维人员了解系统的运行情况，并采取适当的措施。可观测性的概念包含Log、Metric、Tracing三个层面。TNG目前包含了对Metric的支持。

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
| egress | `netfilter` | `egress_type=netfilter,egress_id={id},egress_port={port}` |

目前，TNG仅支持向open-falcon导出Metrics，其他类型的Metrics导出方式（如Prometheus等）正在开发中。

您可以通过指定`metrics`字段来开启对Metrics的支持。


#### 字段说明

- **`metrics`** (Metrics, 可选，默认为空)：该字段指定了Metrics的配置。包含以下子字段：
    - **`exporters`** (array [Exporter], 可选，默认为空数组)：该字段指定了Metrics的导出器列表。包含以下子字段：
        - **`type`** (string)：该字段指定了Metrics的导出器类型，目前仅支持`falcon`。
        - **`server_url`** (string)：该字段指定了open-falcon服务端地址。
        - **`endpoint`** (string)：该字段指定了每条metric绑定的endpoint值。
        - **`tags`** (map [string], 可选，默认为空)：该字段指定了每条metric的额外附加标签，这些标签将和TNG产生的metric的标签一起被发送给open-falcon服务端。
        - **`step`** (integer, 可选，默认为60)：该字段指定了每条metric的间隔时间step值，单位为秒。


示例：
```json
{
    "metric": {
        "exporters": [{
            "type": "falcon",
            "server_url": "http://127.0.0.1:1988",
            "endpoint": "master-node",
            "tags": {
                "namespace": "ns1",
                "app": "tng"
            },
            "step": 60
        }]
    }
}
```
