# Parameter Manual

## Top-Level Configuration Object

- **`add_ingress`** (array [Ingress]): Add ingress endpoints of the tng tunnel in the `add_ingress` array. Depending on the client-side user scenario, you can choose the appropriate inbound traffic method.
- **`add_egress`** (array [Egress]): Add egress endpoints of the tng tunnel in the `add_egress` array. Depending on the server-side user scenario, you can choose the appropriate outbound traffic method.
- **`admin_bind`** (AdminBind): (⚠️ deprecated)Configuration for the Admin Interface of the Envoy instance. If this option is not specified, the Admin Interface feature will not be enabled.

## Ingress

The `Ingress` object is used to configure the ingress endpoints of the tng tunnel and control how traffic enters the tng tunnel. It supports multiple inbound traffic methods.

### Field Descriptions

- **`ingress_mode`** (IngressMode): Specifies the method for inbound traffic, which can be `mapping`, `http_proxy`, or `netfilter`.
- **`encap_in_http`** (EncapInHttp, optional): HTTP encapsulation configuration.
- **`web_page_inject`** (boolean, optional, default is `false`): When enabled, this option injects a header bar at the top of the webpage to display the remote attestation status of the current page, providing strong awareness of remote attestation to browser users. Note that this feature requires the `encap_in_http` field to be specified simultaneously.
- **`no_ra`** (boolean, optional, default is `false`): Whether to disable remote attestation. Setting this option to `true` indicates that the tng uses a standard X.509 certificate for communication at this tunnel endpoint without triggering the remote attestation process. Please note that this certificate is a fixed, embedded P256 X509 self-signed certificate within the tng code and does not provide confidentiality, hence **this option is for debugging purposes only and should not be used in production environments**. This option cannot coexist with `attest` or `verify`.
- **`attest`** (Attest, optional): If this field is specified, it indicates that the tng acts as an Attester at this tunnel endpoint.
- **`verify`** (Verify, optional): If this field is specified, it indicates that the tng acts as a Verifier at this tunnel endpoint.

## IngressMode

### mapping: Port Mapping Mode

In this scenario, tng listens on a local TCP port (`in.host`, `in.port`) and encrypts all TCP requests before sending them to a specified TCP endpoint (`out.host`, `out.port`). Therefore, the user's client program needs to change its TCP request target to (`in.host`, `in.port`).

#### Field Descriptions

- **`r#in`** (Endpoint):
  - **`host`** (string, optional, default is `0.0.0.0`): The host address to listen on.
  - **`port`** (integer): The port number to listen on.
- **`out`** (Endpoint):
  - **`host`** (string): The target host address.
  - **`port`** (integer): The target port number.

Example:

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

### http_proxy: HTTP Proxy Mode

In this scenario, tng listens on a local HTTP proxy port. User containers can route traffic through the proxy to the tng client’s listening port by setting the `http_proxy` environment variable (or explicitly setting the `http_proxy` proxy when sending requests in the application code). The tng client then encrypts all user TCP requests and sends them to the original target address. Therefore, the user's client program does not need to modify its TCP request targets.

#### Field Descriptions

- **`proxy_listen`** (Endpoint): Specifies the listening address (`host`) and port (`port`) values for the `http_proxy` protocol exposed by tng.
  - **`host`** (string, optional, default is `0.0.0.0`): The local address to listen on.
  - **`port`** (integer): The port number to listen on.
- **`dst_filters`** (array [EndpointFilter], optional, default is an empty array): This specifies a filtering rule indicating the combination of target domain (or IP) and port that needs to be protected by the tng tunnel. Traffic not matched by this filtering rule will not enter the tng tunnel and will be forwarded in plaintext (ensuring that regular traffic requests that do not need protection are sent out normally). If this field is not specified or is an empty array, all traffic will enter the tng tunnel.
  - **`domain`** (string, optional, default is `*`): The target domain to match. This field does not support regular expressions but does support certain types of wildcards (*). For specific syntax, please refer to the [description document](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost) for the `domains` field of the `config.route.v3.VirtualHost` type in the envoy documentation.
  - **`domain_regex`** (string, optional, default is `.*`): This field specifies a regular expression for matching target domains. It supports full regular expression syntax. The `domain_regex` field and the `domain` field are mutually exclusive; only one of them can be specified simultaneously.
  - **`port`** (integer, optional, default is `80`): The target port to match. If not specified, the default is port 80.
- (Deprecated) **`dst_filter`** (EndpointFilter): Used in TNG version 1.0.1 and earlier as a required parameter, now replaced by `dst_filters`. This is retained for compatibility with older configurations.

Example:

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

### netfilter: Transparent Proxy Mode

In this scenario, tng listens on a local TCP port and forwards user traffic to this port by configuring iptables rules. The tng client then encrypts all user TCP requests and sends them to the original target address. Therefore, the user's client program does not need to modify its TCP request targets.

> Not yet implemented

## Egress

Add egress endpoints of the tng tunnel in the `add_egress` array. Depending on the server-side user scenario, you can choose the appropriate outbound traffic method.

### Field Descriptions

- **`egress_mode`** (EgressMode): Specifies the outbound traffic method, which can be `mapping` or `netfilter`.
- **`decap_from_http`** (DecapFromHttp, optional): HTTP decapsulation configuration.
- **`no_ra`** (boolean, optional, default is `false`): Whether to disable remote attestation. Setting this option to `true` indicates that the tng uses a standard X.509 certificate for communication at this tunnel endpoint without triggering the remote attestation process. Please note that this certificate is a fixed, embedded P256 X509 self-signed certificate within the tng code and does not provide confidentiality, hence **this option is for debugging purposes only and should not be used in production environments**. This option cannot coexist with `attest` or `verify`.
- **`attest`** (Attest, optional): If this field is specified, it indicates that the tng acts as an Attester at this tunnel endpoint.
- **`verify`** (Verify, optional): If this field is specified, it indicates that the tng acts as a Verifier at this tunnel endpoint.

## EgressMode

### mapping: Port Mapping Mode

In this scenario, tng listens on a local TCP port (`in.host`, `in.port`) and decrypts all TCP requests before sending them to a specified TCP endpoint (`out.host`, `out.port`). The user's server program needs to change its TCP listening port to listen on (`in.host`, `in.port`).

#### Field Descriptions

- **`in`** (Endpoint): Specifies the local TCP port that tng listens on.
  - **`host`** (string, optional, default is `0.0.0.0`): The local address to listen on.
  - **`port`** (integer): The port number to listen on.
- **`out`** (Endpoint): Specifies the target endpoint where decrypted TCP requests are sent.
  - **`host`** (string): The target address.
  - **`port`** (integer): The target port number.

Example:

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

### netfilter: Port Hijacking Mode

In this scenario, the user's server program is already listening on a certain port on the local machine, and due to business reasons, it is inconvenient to change the port number or add new open ports for the tng server. To allow the tng server to decrypt TCP traffic sent to the server program's port (`capture_dst.host`, `capture_dst.port`), it is necessary to use the capabilities provided by the kernel's netfilter to redirect the traffic to the `listen_port` on which the tng server is listening. After decrypting the traffic, the tng server sends the TCP traffic to the original target (`capture_dst.host`, `capture_dst.port`).

#### Field Descriptions

- **`capture_dst`** (Endpoint): Specifies the target endpoint that needs to be captured by the tng server.
  - **`host`** (string, optional, defaults to matching all local IP addresses on all ports): The target address. If not specified, it defaults to matching all local IP addresses on all ports on the machine (see the iptables option `-m addrtype --dst-type LOCAL`: [iptables-extensions.man.html](https://ipset.netfilter.org/iptables-extensions.man.html)).
  - **`port`** (integer): The target port number.
- **`capture_local_traffic`** (boolean, optional, default is `false`): If set to `false`, requests with a source IP that is the local machine's IP will be ignored during capture and not redirected to `listen_port`. If set to `true`, requests with a source IP that is the local machine's IP will also be captured.
- **`listen_port`** (integer, optional, default starts incrementing from port 40000): The port number on which the tng server listens to receive traffic redirected by netfilter.
- **`so_mark`** (integer, optional, default value is 565): The SO_MARK value of the socket corresponding to the TCP request carrying the plaintext traffic after decryption by the tng server, used to prevent the decrypted traffic from being redirected to the tng server again by netfilter.

Example:

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

Parameters required to configure the TNG endpoint as a remote attestation Attester role.

> Currently, only supports obtaining evidence through the [Attestation Agent](https://github.com/confidential-containers/guest-components/tree/main/attestation-agent).

### Field Descriptions

- **`aa_addr`** (string): Specifies the address of the Attestation Agent (AA).

Example:

```json
      "attest": {
        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
      }
```

## Verifier

Parameters required to configure the TNG endpoint as a remote attestation Verifier role.

> Currently, only supports consuming and verifying evidence received from the peer through the [Attestation Service](https://github.com/confidential-containers/trustee/tree/main/attestation-service).

### Field Descriptions

- **`as_addr`** (string): Specifies the URL of the Attestation Service (AS) to connect to. Supports connecting to the Attestation Service with both gRPC protocol and Restful HTTP protocol. By default, it is parsed as a Restful HTTP URL, which can be controlled by the `as_is_grpc` option.
- **`as_is_grpc`** (boolean, optional, default is false): If set to `true`, interprets `as_addr` as a gRPC URL.
- **`policy_ids`** (array of strings): Specifies the list of policy IDs to use.
- **`trusted_certs_paths`** (array of strings, optional, default is empty): Specifies the paths to root CA certificates used to verify the signature and certificate chain in the AS token. If multiple root CA certificates are specified, verification succeeds if any one of them verifies successfully. If this field is not specified or is set to an empty array, certificate verification is skipped.


Example: Connecting to a Restful HTTP type AS service

```json
      "verify": {
        "as_addr": "http://127.0.0.1:8080/",
        "policy_ids": [
          "default"
        ]
      }
```

Example: Connecting to a gRPC type AS service

```json
      "verify": {
        "as_addr": "http://127.0.0.1:5000/",
        "as_is_grpc": true,
        "policy_ids": [
          "default"
        ]
      }
```

Example: Specifying Root Certificate Paths for AS Token Verification

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

## Attester and Verifier Combinations and Bidirectional Remote Attestation

By configuring different combinations of `attest` and `verify` properties at both ends of the tunnel (including ingress and egress), a flexible trust model can be achieved.

| Remote Attestation Scenario | TNG Client Configuration | TNG Server Configuration | Description |
|---|---|---|---|
| Unidirectional | `verify` | `attest` | Most common scenario, where the TNG server is in a TEE, and the TNG client is in a normal environment. |
| Bidirectional | `attest`, `verify` | `attest`, `verify` | The TNG server and TNG client are in two different TEEs. |
| (Reverse) Unidirectional | `attest` | `verify` | The TNG server is in a normal environment, and the TNG client is in a TEE. In this case, only the client certificate is verified. During the TLS handshake, the TNG server will use a fixed P256 X509 self-signed certificate embedded in the TNG code as its certificate. |
| No TEE (For Debugging Purposes Only) | `no_ra` | `no_ra` | Both the TNG server and TNG client are in non-TEE environments. In this case, a normal TLS session is established between the TNG client and TNG server through unidirectional verification. |

## Disguising as Layer 7 Traffic

In modern server-side development, communication between app clients and app servers commonly uses the HTTP protocol, and the link may pass through HTTP middleware (such as nginx reverse proxy, or Layer 7-only load balancing services). However, TNG's rats-tls traffic might not pass through these HTTP middlewares. To integrate TNG with minimal burden in the business, we offer a feature to disguise TNG's rats-tls traffic as Layer 7 HTTP traffic.

This feature can be achieved by configuring `EncapInHttp` in Ingress and `DecapFromHttp` in Egress.

Considering the characteristics of these intermediate components, TNG needs to retain some fields of the original traffic after being disguised as HTTP traffic to ensure normal operation of functions like routing and load balancing. However, for data confidentiality, the fields in the disguised HTTP traffic should not contain sensitive information. Therefore, TNG provides some rules to configure the fields of the disguised HTTP traffic:

1. The request method of the disguised HTTP traffic is uniformly `POST`.
2. The request path of the disguised HTTP traffic defaults to `/`, but it can be rewritten to the path of the disguised HTTP traffic using the `path_rewrites` field based on the path of the protected business HTTP request inside, using regular expressions.
3. The Host (or `:authority`) of the disguised HTTP traffic remains consistent with the protected business HTTP request inside.
4. The disguised HTTP traffic carries a request header named `tng`, which can be used to distinguish between normal traffic and disguised traffic. Meanwhile, the request headers in the original business traffic will be concealed.

> [!WARNING]  
> If the "Disguising as Layer 7 Traffic" feature is enabled, the protected business inside must be HTTP traffic, not ordinary TCP traffic.

### EncapInHttp: Disguising Inbound Traffic

The disguising capability can be enabled by specifying the `encap_in_http` field in the `add_ingress` object. If `encap_in_http` is not specified, the disguising capability will not be enabled.

#### Field Descriptions

- **`path_rewrites`** (array [PathRewrite], optional, default is an empty array): This field specifies a list of parameters for traffic path rewriting using regular expressions. All rewrites will be performed in the order they appear in the path_rewrites list, and only one item in the list will be matched. If the HTTP request does not match any valid member of the path_rewrites list, the path of the disguised HTTP traffic will default to `/`.

  - **`match_regex`** (string): A regular expression used to match the path of the protected business HTTP request inside.
  - **`substitution`** (string): When the path matches the match_regex, the path of the disguised HTTP traffic will be rewritten to this substitution. It supports using `\digit` to reference the groups matched by the regular expression.

Example:

In this example, we add a PathRewrite rule indicating that for all user HTTP requests whose paths match `^/foo/bar/([^/]+)([/]?.*)$`, the path of the TNG tunnel's HTTP wrapper traffic will be rewritten to `/foo/bar/\1` (note that `\1` is a regex substitution rule).

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

### DecapFromHttp: Disguising Outbound Traffic

Corresponding to the inbound configuration, the outbound side can enable the dismantling of already disguised traffic by specifying the `decap_from_http` field in the `add_egress` object. If the `decap_from_http` field is not specified, it will not be enabled.

Additionally, by configuring the `allow_non_tng_traffic_regexes` sub-item, you can allow non-encrypted HTTP request traffic to enter the endpoint in addition to the encrypted TNG traffic. This can meet scenarios where both types of traffic are needed (such as health checks). The value of this sub-item is a JSON string list, where each item is a regular expression match statement. Only non-encrypted HTTP request traffic whose HTTP request PATH completely matches these regular expression statements will be allowed by TNG. The default value of the sub-item is `[]`, which means any non-encrypted HTTP requests are denied.

#### Field Descriptions

- **`allow_non_tng_traffic_regexes`** (array [string], optional, default is an empty array): This field specifies a list of regular expressions that allow non-encrypted HTTP request traffic to enter. Each element is a regular expression string, and only when the HTTP request path matches these regular expressions will non-encrypted HTTP request traffic be allowed.

Example:

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
> Due to the removal of Envoy, this option has been deprecated. Configuring this option will have no effect.

The `admin_bind` option can be used to enable the [Admin Interface](https://www.envoyproxy.io/docs/envoy/latest/operations/admin) capability of the Envoy instance.

> [!WARNING]  
> As this port does not use authentication, do not use this option in a production environment.

#### Field Descriptions

- **`admin_bind`** (Endpoint, optional, default is empty): This field specifies the listening address and port for the Envoy admin interface. It includes the following sub-fields:
  - **`host`** (string, optional, default is `0.0.0.0`): The local address to listen on.
  - **`port`** (integer): The port number to listen on, required.

Example:

In this example, the `admin_bind` field specifies that the Envoy admin interface listens on the address `0.0.0.0` and port `9901`.

```json
{
  "admin_bind": {
    "host": "0.0.0.0",
    "port": 9901
  }
}
```

