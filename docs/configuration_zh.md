# 参数手册

## 顶层配置对象

- **`add_ingress`** (array [Ingress])：在`add_ingress`数组中添加tng隧道的入口端点（ingress），根据client侧用户场景，可以选择对应的流量入站方式。
- **`add_egress`** (array [Egress])：在`add_egress`数组中添加tng隧道的出口端点（egress），根据server侧用户场景，可以选择对应的流量出站方式。
- **`admin_bind`** (AdminBind)：Envoy实例的Admin Interface配置，在未指定该选项时将不开启Admin Interface功能


## Ingress

`Ingress`对象用于配置tng隧道的入口端点，控制流量入站到tng隧道的方式，支持多种流量入站方式。

### 字段说明

- **`ingress_mode`** (IngressMode)：指定流量入站的方式，可以是`mapping`、`http_proxy`或`netfilter`。
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

> TBD

### netfilter：透明代理方式

在该场景中，tng监听一个本地tcp端口，并通过配置iptables规则，将用户流量转发到tng client监听的该端口。后者负责将所有用户tcp请求加密后发送到原目标地址。因此用户的client程序无需修改其tcp请求的目标。

> TBD


## Egress
在`add_egress`数组中添加tng隧道的出口端点（egress），根据server侧用户场景，可以选择对应的流量出站方式。

### 字段说明
- **`egress_mode`** (EgressMode)：指定流量出站的方式，可以是`mapping`或`netfilter`。
- **`no_ra`** (boolean, 可选，默认为`false`)：是否禁用远程证明。将该选项设置为`true`表示在该隧道端点上，tng用普通的X.509证书进行通信，而不触发远程证明流程。请注意该证书为tng代码中内嵌的一个固定的P256 X509自签名证书，不具有机密性，因此**该选项仅作调试用途，不应被用于生产环境**。该选项不能与`attest`或`verify`同时存在。
- **`attest`** (Attest, 可选)：若指定该字段，表示在该隧道端点上tng扮演Attester角色。
- **`verify`** (Verify, 可选)：若指定该字段，表示在该隧道端点上tng扮演Verifier角色。


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
        "aa_addr": "unix:///tmp/attestation.sock"
      }
    }
  ]
}
```
## EgressMode

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
        "aa_addr": "unix:///tmp/attestation.sock"
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
        "aa_addr": "unix:///tmp/attestation.sock"
      }
```

## Verifier

将TNG端点配置为远程证明Verifier角色所需的相关参数。

> 目前只支持通过[Attestation Service](https://github.com/confidential-containers/trustee/tree/main/attestation-service)消费和验证对端发来的evidence。

### 字段说明
- **`as_addr`** (string)：指定要连接到的Attestation Service (AS) 的URL。支持连接到以gRPC协议和Restful HTTP两种协议类型的Attestation Service。默认将其解析为Restful HTTP的URL，可通过`as_is_grpc`选项控制。
- **`as_is_grpc`** (boolean, 可选，默认为false)：若设置为`true`，这将`as_addr`解释为gRPC URL。
- **`policy_ids`** (array of strings)：指定要使用的policy ID列表。

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

## Attester和Verifier的组合与双向远程证明

通过在隧道两端（包括ingress和egress）上配置不同的`attest`和`verify`属性组合，可以实现灵活的信任模型

|远程证明场景|tng client配置|tng server配置|说明|
|---|---|---|---|
|单向|`verify`|`attest`|最常见场景，tng server在TEE中，tng client在普通环境|
|双向|`attest`、`verify`|`attest`、`verify`|tng server和tng client在两个不同TEE中|
|（逆）单向|`attest`|`verify`|tng server在普通环境，tng client在TEE中。此时等于只验证client证书，在tls握手中，tng server会用tng代码中内嵌的一个固定的P256 X509自签名证书来作为自己的证书|
|无TEE（仅作调试用途）|`no_ra`|`no_ra`|tng server和tng client都在非TEE环境中，此时tng client和tng server之间通过单向验证建立普通的TLS会话|


### Envoy Admin Interface

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

