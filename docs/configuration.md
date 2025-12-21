# Parameter Manual

## Top-Level Configuration Object

- **`control_interface`** (ControlInterface): The configuration of the control plane for the TNG instance.
- **`metrics`** (Metrics): Specifies the configuration for Metrics, which is disabled by default.
- **`add_ingress`** (array [Ingress]): Add ingress endpoints of the tng tunnel in the `add_ingress` array. Depending on the client-side user scenario, you can choose the appropriate inbound traffic method.
- **`add_egress`** (array [Egress]): Add egress endpoints of the tng tunnel in the `add_egress` array. Depending on the server-side user scenario, you can choose the appropriate outbound traffic method.
- (Deprecated) **`admin_bind`** (AdminBind): Configuration for the Admin Interface of the Envoy instance. If this option is not specified, the Admin Interface feature will not be enabled.

## Ingress

The `Ingress` object is used to configure the ingress endpoints of the tng tunnel and control how traffic enters the tng tunnel. It supports multiple inbound traffic methods.

### Field Descriptions

- **`ingress_mode`** (IngressMode): Specifies the method for inbound traffic, which can be `mapping`, `http_proxy`, or `netfilter`.
- (Deprecated) **`encap_in_http`** (EncapInHttp, optional): HTTP encapsulation configuration. This configuration has been deprecated since version 2.2.5, please use the `ohttp` field instead.
- **`ohttp`** (OHttp, optional): OHTTP configuration.
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

In this scenario, tng listens on a local HTTP proxy port. User containers can route traffic through the proxy to the tng client's listening port by setting the `http_proxy` environment variable (or explicitly setting the `http_proxy` proxy when sending requests in the application code). The tng client then encrypts all user TCP requests and sends them to the original target address. Therefore, the user's client program does not need to modify its TCP request targets.

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

### socks5: Socks5 Proxy Mode

In this scenario, TNG creates a local SOCKS5 proxy server port. User applications can connect to this SOCKS5 proxy server, thereby proxying requests to TNG, which is responsible for encrypting all user TCP requests and sending them to the original destination address. In this process, the user's client program only needs to configure a SOCKS5 proxy option and does not need to modify the target of its TCP requests.

#### Field Descriptions

- **`proxy_listen`** (Endpoint): Specifies the listening address (`host`) and port (`port`) values for the `socks5` protocol port exposed by TNG.
  - **`host`** (string, optional, default is `0.0.0.0`): The local address to listen on.
  - **`port`** (integer): The port number to listen on.
- **`auth`** (Socks5Auth, optional): Specifies the authentication method required for accessing the locally listened SOCKS5 port. You can use this option to restrict access to the SOCKS5 proxy port to only those programs that know the password.
  - **`username`** (string): The username required for SOCKS5 proxy authentication.
  - **`password`** (string): The password required for SOCKS5 proxy authentication.
- **`dst_filters`** (array [EndpointFilter], optional, default is an empty array): This specifies a filtering rule indicating the combination of target domain (or IP) and port that needs to be protected by the tng tunnel. Traffic not matched by this filtering rule will not enter the tng tunnel and will be forwarded in plaintext (ensuring that regular traffic requests that do not need protection are sent out normally). If this field is not specified or is an empty array, all traffic will enter the tng tunnel.
    - **`domain`** (string, optional, default is `*`): The target domain to match. This field does not support regular expressions but does support certain types of wildcards (*). For specific syntax, please refer to the [description document](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#config-route-v3-virtualhost) for the `domains` field of the `config.route.v3.VirtualHost` type in the envoy documentation.
    - **`domain_regex`** (string, optional, default is `.*`): This field specifies a regular expression for matching target domains. It supports full regular expression syntax. The `domain_regex` field and the `domain` field are mutually exclusive; only one of them can be specified simultaneously.
    - **`port`** (integer, optional, default is `80`): The target port to match. If not specified, the default is port 80.

> [!NOTE]
> There are two versions of the SOCKS5 protocol, which are referred to as:
> - `socks5`: SOCKS5 protocol where domain name resolution is performed on the client side.
> - `socks5h`: SOCKS5 protocol where domain name resolution is performed on the proxy server side.
> If your client uses `socks5` instead of `socks5h`, the SOCKS5 proxy server in tng will not be able to obtain the original domain name of the client request, but only the destination IP address. This may cause your `dst_filters` rules to be ineffective. Fortunately, most modern clients implement the `socks5h` version, or provide both options (e.g., curl). If your client does not support `socks5h`, please add matching rules based on IP addresses, or switch to another type of ingress such as `http_proxy`.

Examples:

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

### netfilter: Transparent Proxy Mode

In this mode, tng will listen on a local TCP port and forward user traffic to the port listened to by the tng client by configuring iptables rules. The latter is responsible for encrypting all user TCP requests and sending them to the original destination address. Therefore, the user's client program does not need to modify its TCP request target.

Precise control over the traffic to be captured can be achieved by configuring options such as the target TCP port and the cgroup where the program resides.

#### Field Descriptions

- **`capture_dst`** (array, optional, default is an empty array): Specifies the destination address and port of the traffic that needs to be captured by the tng tunnel. If this field is not specified or is set to an empty array, all traffic will be captured by the tng tunnel.

  This field contains multiple objects in the form of an array, each representing a matching rule used to match the destination address and port information of outbound TCP requests. The specific rule fields are as follows:

  - **Destination IP Address**: Can be specified in one of the following two ways. If not specified, it indicates a match for all destination IP addresses:
    - Specify a target IP address or CIDR block:
      - **`host`** (string): The target IP address or CIDR block to match. CIDR notation is supported. Examples include: `192.168.1.1`, `192.168.1.1/32`, `192.168.1.0/24`.
    - Specify an ipset group containing the target IPs:
      - **`ipset`** (string): The name of the ipset group to match.

  - **Destination Port** (optional): If not specified, it indicates a match for all destination port numbers.
    - **`port`** (integer): The target port number.
- **`capture_cgroup`** (array [string], optional, default is an empty array): Specifies the cgroup of the traffic that needs to be captured by the tng tunnel. If this field is not specified or is set to an empty array, the `capture_cgroup` rules will be ignored.
- **`nocapture_cgroup`** (array [string], optional, default is an empty array): Specifies the cgroup of the traffic that does not need to be captured by the tng tunnel.

> [!NOTE]
> - The `capture_cgroup` and `nocapture_cgroup` fields are only supported when your system uses **cgroup v2**.
> - **Relation to cgroup namespace**: Due to netfilter implementation limitations [\[[1\]](https://github.com/torvalds/linux/blob/ec7714e4947909190ffb3041a03311a975350fe0/net/netfilter/xt_cgroup.c#L105) [\[[2\]](https://github.com/torvalds/linux/blob/ec7714e4947909190ffb3041a03311a975350fe0/kernel/cgroup/cgroup.c#L6995-L6996), the cgroup path specified here is interpreted from the perspective of the cgroup namespace in which the TNG process itself resides. Therefore, if you run TNG separately in a container and need to configure the `capture_cgroup` and `nocapture_cgroup` fields, please use Docker's `--cgroupns=host` option accordingly.

- **`listen_port`** (integer, optional): Specifies the port number that tng listens on to receive captured requests, usually no manual specification is required. If this field is not specified, tng will randomly assign a port number.
- **`so_mark`** (integer, optional, default value is 565): The SO_MARK value of the socket corresponding to the TCP request carrying the cyphertext traffic after encryption by the tng, used to prevent the encrypted traffic from being redirected to this ingress again by netfilter.

Traffic capture follows the rules below:

```mermaid
flowchart TD
    A[Start] --> G{capture_cgroup is empty?}
    G --Yes--> D
    G --No--> B{Does it match any capture_cgroup rule?}
    B --No--> C[Ignore traffic]
    B --Yes--> D{Does it match any nocapture_cgroup rule?}
    D --Yes--> C
    D --No--> E{Does it match any capture_dst rule?}
    E --Yes--> F[Capture traffic]
    E --No--> C
```

> **Note**：This mode can only capture TCP traffic and will not capture traffic destined for address owned by any interfaces on the local machine.

Example:

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

Add egress endpoints of the tng tunnel in the `add_egress` array. Depending on the server-side user scenario, you can choose the appropriate outbound traffic method.

### Field Descriptions

- **`egress_mode`** (EgressMode): Specifies the outbound traffic method, which can be `mapping` or `netfilter`.
- **`direct_forward`** (array [DirectForwardRule], optional): Specifies matching rules for traffic that needs to be forwarded directly (without decryption).
- (Deprecated) **`decap_from_http`** (DecapFromHttp, optional): HTTP decapsulation configuration. This configuration has been deprecated since version 2.2.5, please use the `ohttp` field instead.
- **`ohttp`** (OHttp, optional): OHTTP configuration.
- **`no_ra`** (boolean, optional, default is `false`): Whether to disable remote attestation. Setting this option to `true` indicates that the tng uses a standard X.509 certificate for communication at this tunnel endpoint without triggering the remote attestation process. Please note that this certificate is a fixed, embedded P256 X509 self-signed certificate within the tng code and does not provide confidentiality, hence **this option is for debugging purposes only and should not be used in production environments**. This option cannot coexist with `attest` or `verify`.
- **`attest`** (Attest, optional): If this field is specified, it indicates that the tng acts as an Attester at this tunnel endpoint.
- **`verify`** (Verify, optional): If this field is specified, it indicates that the tng acts as a Verifier at this tunnel endpoint.


### DirectForwardRule

In certain scenarios, you may want a protected listening port to allow both encrypted traffic and some regular traffic (e.g., health check traffic).

You can use the `direct_forward` field to specify a set of matching rules. If any rule matches successfully, the traffic will be directly forwarded as regular traffic without decryption.

Currently supported matching rules include:
- **`http_path`** (string): Parses the traffic as an HTTP request and matches the [Path](https://developer.mozilla.org/en-US/docs/Web/API/URL/pathname) in the HTTP request URI using a regular expression.

Example:

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

The example configuration sets up a `netfilter` type egress that allows encrypted traffic to access port 30001 while also permitting unencrypted HTTP requests whose path matches the regular expression `/public/.*`.

## EgressMode

### mapping: Port Mapping Mode

In this scenario, tng listens on a local TCP port (`in.host`, `in.port`) and decrypts all TCP requests before sending them to a specified TCP endpoint (`out.host`, `out.port`). The user's server program needs to change its TCP listening port to listen on (`out.host`, `out.port`).

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

In this scenario, the user's server program is already listening on a certain port on the local machine, and due to business reasons, it is inconvenient to change the port number or add new open ports for the tng. To allow the tng to decrypt TCP traffic sent to the server program's port (`capture_dst.host`, `capture_dst.port`), it is necessary to use the capabilities provided by the kernel's netfilter to redirect the traffic to the `listen_port` on which the tng is listening. After decrypting the traffic, the tng sends the TCP traffic to the original target (`capture_dst.host`, `capture_dst.port`).

#### Field Descriptions

- **`capture_dst`** (Endpoint): Specifies the target endpoint that needs to be captured by the tng.
    - **`host`** (string, optional, defaults to matching all local IP addresses on all ports): The target address. If not specified, it defaults to matching all local IP addresses on all ports on the machine (see the iptables option `-m addrtype --dst-type LOCAL`: [iptables-extensions.man.html](https://ipset.netfilter.org/iptables-extensions.man.html)).
    - **`port`** (integer): The target port number.
- **`capture_local_traffic`** (boolean, optional, default is `false`): If set to `false`, requests with a source IP that is the local machine's IP will be ignored during capture and not redirected to `listen_port`. If set to `true`, requests with a source IP that is the local machine's IP will also be captured.
- **`listen_port`** (integer, optional, default starts incrementing from port 40000): The port number on which the tng listens to receive traffic redirected by netfilter.
- **`so_mark`** (integer, optional, default value is 565): The SO_MARK value of the socket corresponding to the TCP request carrying the plaintext traffic after decryption by the tng, used to prevent the decrypted traffic from being redirected to this egress again by netfilter.

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

## Remote Attestation

Remote attestation is one of the core security mechanisms of trusted computing, used to verify the runtime integrity and trusted state of remote systems (such as virtual machines, containers, or edge devices). Through cryptographic means, a system (**Attester**) can generate "evidence" describing its hardware and software configuration, and another system (**Verifier**) can verify this evidence to ensure it comes from a legitimate, untampered trusted execution environment (TEE, such as Intel TDX, AMD SEV-SNP, HYGON CSV, etc.).

In the TNG architecture, we have integrated a standardized remote attestation process that supports flexibly configuring TNG endpoints as either **Attester** or **Verifier** roles, thus achieving bidirectional trusted authentication and establishing secure communication links.

### Attester: The Initiator Proving Its Trustworthiness

**Attester** refers to the party being verified, responsible for collecting trusted state information of the local platform and generating cryptographic evidence. This evidence contains measurements, signatures, timestamps, and attestation materials from the TEE (such as reports and certificates), which can be used to prove its integrity and security to remote parties.

In TNG, you can configure any endpoint as an Attester role, enabling it to respond to remote verification requests and provide trusted evidence.

> [!NOTE]
> **Current Implementation Notes**:  
> Currently, TNG only supports obtaining Evidence through the [Attestation Agent](https://github.com/confidential-containers/guest-components/tree/main/attestation-agent).  
> The Attestation Agent runs in a protected guest environment, responsible for interacting with the underlying TEE and encapsulating standardized attestation data, ensuring the security and portability of the attestation process.

### Verifier: The Decision Maker Verifying Peer Trustworthiness

**Verifier** is the verifying party, responsible for receiving Evidence from the Attester and performing integrity verification, policy comparison, and trust assessment. Only when the evidence complies with preset trust policies (such as specific PCR values, firmware versions, or signing keys) will the Verifier recognize the Attester as trusted and allow subsequent security operations (such as key release or connection establishment).

In the TNG architecture, the Verifier can be part of the control plane or service gateway, actively or passively verifying the identity and trust level of accessing nodes.

> **Current Implementation Notes**:  
> The current Verifier functionality of TNG relies on the [Attestation Service](https://github.com/confidential-containers/trustee/tree/main/attestation-service) to consume and verify received Evidence.  
> The Attestation Service provides a unified interface for parsing and verifying attestation data of different TEE types, and supports integration with the Trustee Server to achieve centralized policy management and root of trust distribution.


## Attester and Verifier Combinations and Bidirectional Remote Attestation

By configuring different combinations of `attest` and `verify` properties at both ends of the tunnel (including ingress and egress), a flexible trust model can be achieved.

| Remote Attestation Scenario | TNG Client Configuration | TNG Server Configuration | Description |
|---|---|---|---|
| Unidirectional | `verify` | `attest` | Most common scenario, where the TNG server is in a TEE, and the TNG client is in a normal environment. |
| Bidirectional | `attest`, `verify` | `attest`, `verify` | The TNG server and TNG client are in two different TEEs. |
| (Reverse) Unidirectional | `attest` | `verify` | The TNG server is in a normal environment, and the TNG client is in a TEE. In this case, only the client certificate is verified. During the TLS handshake, the TNG server will use a fixed P256 X509 self-signed certificate embedded in the TNG code as its certificate. |
| No TEE (For Debugging Purposes Only) | `no_ra` | `no_ra` | Both the TNG server and TNG client are in non-TEE environments. In this case, a normal TLS session is established between the TNG client and TNG server through unidirectional verification. |

## Remote Attestation Models

### Background Check Model

[Background Check](https://datatracker.ietf.org/doc/html/rfc9334#name-background-check-model) is TNG's default remote attestation model, which conforms to the standard model defined in the [RATS RFC 9334 document](https://datatracker.ietf.org/doc/html/rfc9334). In this model, the Attester obtains evidence through the Attestation Agent, and the Verifier directly verifies this evidence. The verification process requires the Verifier to be able to access the Attestation Service to verify the validity of the evidence.

> [!NOTE]
> When the `"model"` field is not specified in the configuration, TNG automatically uses the Background Check model.

#### Attest (Background Check Model)

In the Background Check model, the [Attest](#attest) configuration should include the following fields:

- **`model`** (string, optional): Set to "background_check" to enable the Background Check model
- **`aa_addr`** (string): Address of the Attestation Agent
- **`refresh_interval`** (int, optional, default value is 600): Specifies the cache time for obtaining evidence from the Attestation Agent (in seconds). If set to 0, it requests the latest evidence each time a secure session is established. In Background Check mode, this option only takes effect when communicating using the rats-tls protocol, affecting the frequency of updating its own X.509 certificate. This option has no effect when communicating using the OHTTP protocol.

Example:

```json
"attest": {
    // When model is not specified, Background Check mode is used by default
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
}
```

```json
"attest": {
    "model": "background_check",
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
}
```

```json
"attest": {
    "model": "background_check",
    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
    "refresh_interval": 3600
}
```

#### Verify (Background Check Model)

In the Background Check model, the [Verify](#verify) configuration should include the following fields:

- **`model`** (string, optional): Set to "background_check" to enable the Background Check model
- **`as_addr`** (string): Address of the Attestation Service
- **`as_is_grpc`** (boolean, optional, defaults to false): Whether the Attestation Service uses the gRPC protocol
- **`policy_ids`** (array [string]): List of policy IDs
- **`trusted_certs_paths`** (array [string], optional, default is empty): Specifies the paths to root CA certificates used to verify the signature and certificate chain in the Attestation Token. If multiple root CA certificates are specified, verification succeeds if any one of them verifies successfully. If this field is not specified or is set to an empty array, certificate verification is skipped.

Example: Connecting to a Restful HTTP type AS service

```json
"verify": {
    // When model is not specified, Background Check mode is used by default
    "as_addr": "http://127.0.0.1:8080/",
    "policy_ids": [
        "default"
    ]
}
```

Example: Connecting to a gRPC type AS service

```json
"verify": {
    "model": "background_check",
    "as_addr": "http://127.0.0.1:5000/",
    "as_is_grpc": true,
    "policy_ids": [
        "default"
    ]
}
```

Example: Specifying Root Certificate Paths for Attestation Token Verification

```json
"verify": {
    "model": "background_check",
    "as_addr": "http://127.0.0.1:8080/",
    "policy_ids": [
        "default"
    ],
    "trusted_certs_paths": [
        "/tmp/as-ca.pem"
    ]
}
```

### Passport Model

In addition to the Background Check model, TNG also supports remote attestation that conforms to the [Passport model](https://datatracker.ietf.org/doc/html/rfc9334#name-passport-model) defined in the [RATS RFC 9334 document](https://datatracker.ietf.org/doc/html/rfc9334). In the Passport model, the Attester obtains evidence through the Attestation Agent and submits it to the Attestation Service to obtain a Token (i.e., Passport). The Verifier only needs to verify the validity of this Token without directly interacting with the Attestation Service.

The Passport model is suitable for scenarios with network isolation or high performance requirements, as it reduces the interaction between the Verifier and the Attestation Service.

#### Attest (Passport Model)

In the Passport model, the [Attest](#attest) configuration should include the following fields:

- **`model`** (string): Set to "passport" to enable the Passport model
- **`aa_addr`** (string): Address of the Attestation Agent
- **`refresh_interval`** (int, optional, default value is 600): Specifies the frequency of obtaining attestation credentials (Attestation Token) from the Attestation Agent and Attestation Service (in seconds). If set to 0, it requests the latest Attestation Token each time a secure session is established. In Passport mode, if communicating using the rats-tls protocol, this option affects the frequency of updating its own X.509 certificate. If communicating using the OHTTP protocol, this option affects the internal Attestation Token cache update frequency, but does not affect the OHTTP key rotation frequency.
- **`as_addr`** (string): Address of the Attestation Service
- **`as_is_grpc`** (boolean, optional, defaults to false): Whether the Attestation Service uses the gRPC protocol
- **`policy_ids`** (array [string]): List of policy IDs

Example:

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

#### Verify (Passport Model)

In the Passport model, the [Verify](#verify) configuration should include the following fields:

- **`model`** (string): Set to "passport" to enable the Passport model
- **`policy_ids`** (array [string]): List of policy IDs
- **`trusted_certs_paths`** (array [string], optional, default is empty): Specifies the paths to root CA certificates used to verify the signature and certificate chain in the Attestation Token. If multiple root CA certificates are specified, verification succeeds if any one of them verifies successfully. If this field is not specified or is set to an empty array, certificate verification is skipped.

Example:

```json
"verify": {
    "model": "passport",
    "policy_ids": [
        "default"
    ]
}
```



## OHTTP

Oblivious HTTP (OHTTP) is a network protocol extension designed to enhance privacy protection by encrypting HTTP requests to provide end-to-end privacy protection and anonymity enhancement. TNG can use OHTTP to provide secure communication while maintaining compatibility with existing HTTP infrastructure.

By default, TNG uses the rats-tls protocol to provide TCP stream-level encryption protection, which is suitable for most situations. If you need to enable this feature, you can switch to the OHTTP protocol by configuring `ohttp` in Ingress and `ohttp` in Egress respectively.

> [!WARNING]  
> If the OHTTP feature is enabled, the inner protected business must be HTTP traffic, not ordinary TCP traffic.

### OHttp: Ingress Configuration

The OHTTP capability can be enabled by specifying the `ohttp` field in the `add_ingress` object. If `ohttp` is not specified, the OHTTP capability will not be enabled.

#### Field Descriptions

- **`path_rewrites`** (array [PathRewrite], optional, default is an empty array): This field specifies a list of parameters for rewriting traffic paths using regular expressions. All rewrites will be applied in the order they appear in the path_rewrites list, and only one match will be performed per request. If an HTTP request does not match any valid member of the `path_rewrites` list, the default path for OHTTP traffic will be set to `/`.

    - **`match_regex`** (string): A regular expression used to match the path of the inner protected HTTP request. The value of this field will be used to match the entire path string, not just a part of it.

    - **`substitution`** (string): When the original path of an HTTP request matches `match_regex`, the path of the OHTTP traffic will be replaced entirely with the value of `substitution`.

> [!NOTE]
> For syntax information about regular expressions, please refer to the <a href="#regex">Regular Expressions</a> section.

> [!NOTE]
> - Prior to version 2.0.0, the `substitution` field supported referencing captured groups using `\integer` (where `integer` starts from 1). For example, `\1` would be replaced by the content of the first captured group. Refer to the corresponding `substitution` field description in Envoy [here](https://www.envoyproxy.io/docs/envoy/latest/api-v3/type/matcher/v3/regex.proto#type-matcher-v3-regexmatchandsubstitute).
> - Starting from version 2.0.0, the above referencing rule has been deprecated. Instead, `$ref` syntax is supported to reference captured groups, where `ref` can be an integer (index of the capturing group) or a name (for named groups). Refer to [this documentation](https://docs.rs/regex/1.11.1/regex/struct.Regex.html#method.replace). Additionally, the `\integer` referencing rule is still supported for backward compatibility.

Example:

In this example, we add a PathRewrite rule that matches all user HTTP requests with paths that can be matched by `^/foo/bar/([^/]+)([/]?.*)$`. The path of the TNG tunnel's OHTTP traffic will be rewritten to `/foo/bar/$1` (note that `$1` is a regular expression replacement rule).

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

#### L7 Gateway Compatibility

In many Layer 7 gateway scenarios, after TNG protects traffic using the OHTTP protocol, it usually needs to retain some fields of the original traffic so that functions such as routing and load balancing can work properly. However, for data confidentiality, the fields in the encrypted HTTP request should not contain sensitive information. Therefore, TNG provides some rules to configure the fields of the encrypted HTTP request:
1. The request method of the encrypted HTTP request is uniformly `POST`
2. The request path of the encrypted HTTP request defaults to `/`, but it can also be rewritten according to the path of the inner protected business HTTP request using regular expressions by specifying the `path_rewrites` field.
3. The Host (or `:authority`) of the encrypted HTTP request is consistent with the inner protected business HTTP request.
4. The encrypted HTTP request and response will use `Content-Type: message/ohttp-chunked-req` and `Content-Type: message/ohttp-chunked-res` as `Content-Type` respectively.
5. The encrypted HTTP request and response will not contain the request headers and response headers in the encrypted HTTP request.

### OHttp: Egress Configuration

Corresponding to the ingress configuration, the egress side can enable OHTTP support by specifying the `ohttp` field in the `add_egress` object. If the `ohttp` field is not specified, the OHTTP protocol will not be used.

> [NOTE]  
> The `allow_non_tng_traffic_regexes` field has been deprecated since version 2.2.4. Please use the `direct_forward` field instead.

Additionally, by configuring the `allow_non_tng_traffic_regexes` sub-item, you can allow non-encrypted HTTP request traffic to enter the endpoint in addition to the encrypted TNG traffic. This can meet scenarios where both types of traffic are needed (such as health checks). The value of this sub-item is a JSON string list, where each item is a regular expression match statement. Only non-encrypted HTTP request traffic whose HTTP request PATH completely matches these regular expression statements will be allowed by TNG. The default value of the sub-item is `[]`, which means any non-encrypted HTTP requests are denied.

#### Field Descriptions

- (Deprecated) **`allow_non_tng_traffic_regexes`** (array [string], optional, default is an empty array): This field specifies a list of regular expressions that allow non-encrypted HTTP request traffic to enter. Each element is a regular expression string, and only when the HTTP request path matches these regular expressions will non-encrypted HTTP request traffic be allowed.
- **`cors`** (CorsConfig, optional): CORS configuration for the OHTTP server. This field allows you to configure Cross-Origin Resource Sharing (CORS) headers to enable browser-based access to the OHTTP endpoints.

    - **`allow_origins`** (array [string], optional, default is empty): A list of origins that are allowed to access the OHTTP endpoints. Use `["*"]` to allow all origins.
    
    - **`allow_methods`** (array [string], optional, default is empty): A list of HTTP methods that are allowed for cross-origin requests (e.g., `["GET", "POST", "OPTIONS"]`). Use `["*"]` to allow all methods.
    
    - **`allow_headers`** (array [string], optional, default is empty): A list of headers that are allowed in cross-origin requests (e.g., `["Content-Type", "Authorization"]`). Use `["*"]` to allow all headers.
    
    - **`expose_headers`** (array [string], optional, default is empty): A list of headers that browsers are allowed to access from the response. Use `["*"]` to allow all headers.
    
    - **`allow_credentials`** (boolean, optional, default is false): Whether to allow credentials (cookies, authorization headers, etc.) to be included in cross-origin requests.

- **`key`** (KeyArgs, optional): Key configuration for the OHTTP server. Refer to the following sections for detailed configuration fields.

> [!NOTE]
> For syntax information about regular expressions, please refer to the <a href="#regex">Regular Expressions</a> section.

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

#### OHTTP Key Configuration: `self_generated` Mode

TNG supports multiple OHTTP key management strategies. When keys are not provided via external mechanisms, TNG defaults to the **`self_generated` mode**, where each TNG instance independently generates its own HPKE key pair and automatically rotates it.

In this mode, TNG will:
- Automatically generate an X25519 key pair at startup
- Periodically generate new keys while retaining old keys for a certain period (to handle delayed requests)
- Ensure that at least one active key is always available to decrypt client requests

If you wish to configure this explicitly, simply set `key.source = "self_generated"` in the `ohttp` configuration:

```json
"ohttp": {
    "key": {
        "source": "self_generated",
        "rotation_interval": 300
    }
}
```

##### Field Descriptions

- **`key`** (KeyConfig): Configuration for OHTTP key management.
    - **`source`** (`string`): The source type of the key. Set to `"self_generated"` to enable automatic key generation.
    - **`rotation_interval`** (`integer`, optional, default `300`): Key rotation interval in seconds.

Example configuration:

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": {
                    "port": 8080
                }
            },
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


#### OHTTP Key Configuration: `file` Mode

TNG supports loading the OHTTP HPKE private key from an external file, suitable for production environments that need to integrate with external key management systems (such as Confidential Data Hub, Hashicorp Vault, Kubernetes Secrets, or custom rotation scripts). This mode is enabled by setting `key.source = "file"`.

In this mode, TNG will:
- Read a PEM-encoded PKCS#8 X25519 private key from the specified path at startup
- Automatically monitor the file for changes, including content modifications and atomic replacements
- Automatically reload the new key when the file is updated and trigger key change events
- Atomically replace the current key, ensuring that subsequent requests use the public key configuration corresponding to the new key

This mode allows operations systems to rotate keys without restarting the TNG instance, improving both security and availability.

To use file-based key loading, simply set `key.source = "file"` in the `ohttp` configuration and provide the file path:

```json
"ohttp": {
    "key": {
        "source": "file",
        "path": "/etc/tng/ohttp-key.pem"
    }
}
```

##### Field Description

- **`key`** (KeyConfig): OHTTP key management configuration.
  - **`source`** (`string`): Type of key source. Set to `"file"` to indicate that the private key should be loaded from a local file.
  - **`path`** (`string`): Absolute path to the PEM file. Must point to a valid, readable PKCS#8 private key file.

##### File Format Requirements

The file must be a PEM-formatted, PKCS#8–encoded key, for example:
```pem
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEILi5PepL11X3ptJneUQu40m2kiuNeLD9MRK4CYh94t1d
-----END PRIVATE KEY-----
```

The key must be generated using the X25519 curve. You can generate a sample key using OpenSSL:
```bash
openssl genpkey -algorithm X25519 -outform PEM
```

TNG uses operating system-level file change notification mechanisms (e.g., inotify on Linux) to detect file modifications and trigger key reloading.

##### Example Configuration

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": {
                    "port": 8080
                }
            },
            "ohttp": {
                "key": {
                    "source": "file",
                    "path": "/etc/tng/ohttp-key.pem"
                }
            },
            "attest": {
                "model": "background_check",
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```

#### OHTTP Key Configuration: `peer_shared` Mode

TNG supports a decentralized key management mode for sharing OHTTP private keys among multiple TNG instances. Building upon the [self_generated](#ohttp-key-configuration-self_generated-mode) mode, this approach adds the capability for multiple TNG instances to share OHTTP private keys. This capability relies on the serf distributed protocol (Gossip), where each TNG instance joins a serf cluster by specifying the IP or domain name of any peer in the cluster. Cluster members broadcast their private keys to each other. Therefore, even in stateless service scenarios with TNG, and even with an HTTP-based LoadBalancer in front, any node in the cluster can decrypt traffic.

In this mode, TNG will:
- Each node independently generates its own key pair
- Exchange keys with other nodes through the secure serf protocol based on remote attestation
- Maintain a local "key ring" containing valid private keys from all nodes
- Allow any node to decrypt requests encrypted with other nodes' public keys

If you wish to enable this mode, simply specify `key.source = "peer_shared"` in the `ohttp` configuration:

```json
"ohttp": {
    "key": {
        "source": "peer_shared",
        "rotation_interval": 300,
        "host": "0.0.0.0",
        "port": 8301,
        "peers": [
            "192.168.10.1:8301",
            "tng-service.default.svc.cluster.local:8301"
        ]
    }
}
```

##### Field Descriptions

- **`key`** (KeyConfig): OHTTP key management configuration.
    - **`source`** (`string`): The source type of the key. Set to `"peer_shared"` to enable the decentralized key sharing mode.
    - **`rotation_interval`** (`integer`, optional, default `300`): Key rotation interval in seconds. Each node independently rotates its own key.
    - **`host`** (`string`, optional, default `0.0.0.0`): Local listening address for inter-node secure communication.
    - **`port`** (`integer`, optional, default `8301`): Local listening port for inter-node secure communication.
    - **`peers`** (`array of strings`): List of initial node addresses (IP or DNS name:port) to connect to. At least one node must be accessible to join the cluster. When a node address is specified as a domain name, TNG will attempt to resolve that domain name and try all returned IP addresses as peer nodes in sequence (rather than just trying the first IP), which improves connection success rate in complex network environments.

Example configuration:

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": {
                    "port": 8080
                }
            },
            "ohttp": {
                "key": {
                    "source": "peer_shared",
                    "rotation_interval": 300,
                    "host": "0.0.0.0",
                    "port": 8301,
                    "peers": [
                        "192.168.10.1:8301",
                        "tng-service.default.svc.cluster.local:8301"
                    ]
                }
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```

## Control Interface

> [!NOTE]
> This interface is distinct from the <a href="#envoy_admin_interface">Envoy Admin Interface</a> below. The latter is Envoy's built-in management interface, which we plan to remove in future versions.

### Field Description
- **`control_interface`** (ControlInterface, optional, default is empty): This field specifies the listening address and port for the control interface.
    - **`restful`** (Endpoint, optional, default is empty): This field specifies the configuration for the RESTful API. It includes the following subfields:
        - **`host`** (string, optional, default is `0.0.0.0`): The local address to listen on.
        - **`port`** (integer): The port number to listen on, required.

Example:

```json
                "control_interface": {
                    "restful": {
                        "host": "0.0.0.0",
                        "port": 50000
                    }
                }
```

In this example, tng will enable the Control Interface, and its RESTful API will listen on port `50000` at `0.0.0.0`.

### RESTful API

Exposes RESTful API endpoints, supporting the following operations:
- **`/livez`**: This endpoint returns the liveness status of the tng instance. If it returns `200 OK`, it indicates that the instance is running.
- **`/readyz`**: This endpoint returns the readiness status of the tng instance. If it returns `200 OK`, it indicates that the instance is running and ready to handle traffic.

## Envoy Admin Interface
<span id = "envoy_admin_interface"></span>

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

## Observability

Observability refers to the monitoring of the system's operational status to help operations personnel understand the system's running conditions and take appropriate measures. The concept of observability includes three aspects: Log, Metric, and Trace.

### Log

The current version of TNG defaults to enabling the capability of outputting logs to standard output. Users can control the log level of tng by setting the value of the `RUST_LOG` environment variable. Supported levels include `error`, `warn`, `info`, `debug`, `trace`, and a special level `off`.

By default, the log level is set to `info`, and logging from all third-party libraries is disabled.

> [!NOTE]
> In addition to simple log levels, complex configurations are also supported. Please refer to the documentation for the [tracing-subscriber](https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives) crate.

### Metric

Observability refers to the monitoring of system runtime status to help operations personnel understand the system's operating conditions and take appropriate measures. The concept of observability includes three levels: Log, Metric, and Tracing. TNG currently includes support for Metrics.

In TNG, we provide the following Metrics:

<table>
    <tr>
        <th>Scope</th>
        <th>Name</th>
        <th>Type</th>
        <th>Labels</th>
        <th>Description</th>
    </tr>
    <tr>
        <td>Instance</td>
        <td><code>live</code></td>
        <td>Gauge</td>
        <td>None</td>
        <td><code>1</code> to indicates the server is alive, or <code>0</code> otherwise</td>
    </tr>
    <tr>
        <td rowspan="6">ingress/egress</td>
        <td><code>tx_bytes_total</code></td>
        <td>Counter</td>
        <td rowspan="6"><a href="#metric_labels">See below table</a></td>
        <td>The total number of bytes sent</td>
    </tr>
    <tr>
        <td><code>rx_bytes_total</code></td>
        <td>Counter</td>
        <td>The total number of bytes received</td>
    </tr>
    <tr>
        <td><code>cx_active</code></td>
        <td>Gauge</td>
        <td>The number of active connections</td>
    </tr>
    <tr>
        <td><code>cx_total</code></td>
        <td>Counter</td>
        <td>Total number of connections handled since the instance started</td>
    </tr>
    <tr>
        <td><code>cx_failed</code></td>
        <td>Counter</td>
        <td>Total number of failed connections since the instance started</td>
    </tr>
</table>

<span id="metric_labels">Export labels for ingress/egress</span> are as follows:

| Scope | Type | Labels | 
| --- | --- | --- |
| ingress | `mapping` | `ingress_type=mapping,ingress_id={id},ingress_in={in.host}:{in.port},ingress_out={out.host}:{out.port}` |
| ingress | `http_proxy` | `ingress_type=http_proxy,ingress_id={id},ingress_proxy_listen={proxy_listen.host}:{proxy_listen.port}` |
| egress | `mapping` | `egress_type=netfilter,egress_id={id},egress_in={in.host}:{in.port},egress_out={out.host}:{out.port}` |
| egress | `netfilter` | `egress_type=netfilter,egress_id={id},egress_listen_port={listen_port}` |

Currently, TNG supports the following types of exporters:

- **`otlp`**: Exports to endpoints compatible with the OpenTelemetry Protocol (OTLP), such as Prometheus and Jaeger.
- **`falcon`**: Exports to the open-falcon service.
- **`stdout`**: Prints to log output.

You can enable Metric support by specifying the `metric` field.

### Field Description

- **`metric`** (Metric, optional, default is empty): This field specifies the configuration of Metric. It includes the following subfields:
    - **`exporters`** (array [MetricExporter], optional, default is an empty array): This field specifies the list of Metric exporters. It includes the following subfields:
        - **`type`** (string): This field specifies the type of the Metric exporter.

- For the OTLP exporter (`type="otlp"`), it includes the following sub-fields:
    - **`protocol`** (string): This field specifies the data format type of the OTLP protocol, with the following optional values:
        - `grpc`: Reports using gRPC.
        - `http/protobuf`: Reports using HTTP, with content serialized in protobuf format.
        - `http/json`: Reports using HTTP, with content serialized in JSON format.
    - **`endpoint`** (string): This field specifies the URL of the OTLP endpoint.
    - **`headers`** (Map, optional): A list of HTTP Headers to be attached in the export request. For example, you can add an `Authorization` header to meet the authentication requirements of the OTLP endpoint. Additionally, regardless of whether this field is filled or not, headers can also be added via [environment variables](https://opentelemetry.io/docs/languages/sdk-configuration/otlp-exporter/#header-configuration).
    - **`step`** (integer, optional, default is 60): This field specifies the interval time step value for metric collection and reporting, in seconds.

- For the open-falcon exporter (`type="falcon"`), it includes the following subfields:
    - **`server_url`** (string): This field specifies the address of the open-falcon server.
    - **`endpoint`** (string): This field specifies the endpoint value bound to each metric.
    - **`tags`** (map [string], optional, default is empty): This field specifies additional tags for each metric. These tags will be sent to the open-falcon server along with the labels generated by TNG.
    - **`step`** (integer, optional, default is 60): This field specifies the interval time step value for metric collection and reporting, in seconds.

- For the `stdout` exporter (`type="stdout"`), it includes the following subfields:
    - **`step`** (integer, optional, default is 60): This field specifies the interval time step value for metric collection and printing, in seconds.

Example:

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

TNG supports the export of tracing events under the OpenTelemetry standard semantics, including Trace, Span, and Events information for each request.

The following types of exporters are supported:

- **`otlp`**: Export to an endpoint compatible with the OpenTelemetry Protocol (OTLP).  
- **`stdout`**: Print to standard output. Note that this exporter outputs Trace information synchronously (not asynchronously), which can significantly impact performance in high-concurrency scenarios, so it should only be used for debugging purposes.

You can enable support for Trace by specifying the `trace` field.


#### Field Description

- **`trace`** (Trace, optional, default is empty): This field specifies the configuration for Trace. It includes the following subfields:
    - **`exporters`** (array [TraceExporter], optional, default is an empty array): This field specifies the list of Trace exporters. It includes the following subfields:
        - **`type`** (string): This field specifies the type of the Trace exporter.

- For the OTLP exporter (`type="otlp"`), it includes the following subfields:
    - **`protocol`** (string): This field specifies the data format type of the OTLP protocol, with the following optional values:
        - `grpc`: Use gRPC for reporting.
        - `http/protobuf`: Use HTTP for reporting, with content serialized using protobuf.
        - `http/json`: Use HTTP for reporting, with content serialized using JSON.
    - **`endpoint`** (string): This field specifies the URL of the OTLP endpoint.
    - **`headers`** (Map, optional): This is a list of HTTP Headers to be attached to the export request. For example, you can add an `Authorization` header to meet the authentication requirements of the OTLP endpoint. Additionally, regardless of whether this field is filled or not, headers can also be added via [environment variables](https://opentelemetry.io/docs/languages/sdk-configuration/otlp-exporter/#header-configuration).

- For the stdout exporter (`type="stdout"`), no additional fields need to be configured.

Examples:

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


## Regular Expressions
<span id="regex"></span>

Some fields in the TNG configuration file allow the specification of regular expressions. During the evolution of TNG, the syntax rules for regular expressions have been updated. The following provides an explanation:

- In versions prior to 2.0.0, only RE2 syntax was supported. RE2 is Google's regular expression engine. Its syntax format can be found [here](https://github.com/google/re2/wiki/Syntax). If you need to test the correctness of your syntax online, you can use tools available [here](https://re2js.leopard.in.ua/).
- Starting from version 2.0.0 and onwards, common regular expression syntax is supported instead of RE2 syntax. As a result, features such as look-around assertions and backreferences are not supported. Complete syntax rules can be found [here](https://docs.rs/regex/1.11.1/regex/index.html#syntax).
