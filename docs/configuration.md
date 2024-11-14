# Parameter Manual

## Top-Level Configuration Object

- **`add_ingress`** (array [Ingress]): Add ingress endpoints of the tng tunnel in the `add_ingress` array. Depending on the client-side user scenario, you can choose the appropriate inbound traffic method.
- **`add_egress`** (array [Egress]): Add egress endpoints of the tng tunnel in the `add_egress` array. Depending on the server-side user scenario, you can choose the appropriate outbound traffic method.
- **`admin_bind`** (AdminBind): Configuration for the Admin Interface of the Envoy instance. If this option is not specified, the Admin Interface feature will not be enabled.

## Ingress

The `Ingress` object is used to configure the ingress endpoints of the tng tunnel and control how traffic enters the tng tunnel. It supports multiple inbound traffic methods.

### Field Descriptions

- **`ingress_mode`** (IngressMode): Specifies the method for inbound traffic, which can be `mapping`, `http_proxy`, or `netfilter`.
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

> TBD

### netfilter: Transparent Proxy Mode

In this scenario, tng listens on a local TCP port and forwards user traffic to this port by configuring iptables rules. The tng client then encrypts all user TCP requests and sends them to the original target address. Therefore, the user's client program does not need to modify its TCP request targets.

> TBD

## Egress

Add egress endpoints of the tng tunnel in the `add_egress` array. Depending on the server-side user scenario, you can choose the appropriate outbound traffic method.

### Field Descriptions

- **`egress_mode`** (EgressMode): Specifies the outbound traffic method, which can be `mapping` or `netfilter`.
- **`no_ra`** (boolean, optional, default is `false`): Whether to disable remote attestation. Setting this option to `true` indicates that the tng uses a standard X.509 certificate for communication at this tunnel endpoint without triggering the remote attestation process. Please note that this certificate is a fixed, embedded P256 X509 self-signed certificate within the tng code and does not provide confidentiality, hence **this option is for debugging purposes only and should not be used in production environments**. This option cannot coexist with `attest` or `verify`.
- **`attest`** (Attest, optional): If this field is specified, it indicates that the tng acts as an Attester at this tunnel endpoint.
- **`verify`** (Verify, optional): If this field is specified, it indicates that the tng acts as a Verifier at this tunnel endpoint.

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
        "aa_addr": "unix:///tmp/attestation.sock"
      }
    }
  ]
}
```

## EgressMode

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
        "aa_addr": "unix:///tmp/attestation.sock"
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
        "aa_addr": "unix:///tmp/attestation.sock"
      }
```

## Verifier

Parameters required to configure the TNG endpoint as a remote attestation Verifier role.

> Currently, only supports consuming and verifying evidence received from the peer through the [Attestation Service](https://github.com/confidential-containers/trustee/tree/main/attestation-service).

### Field Descriptions

- **`as_addr`** (string): Specifies the URL of the Attestation Service (AS) to connect to. Supports connecting to the Attestation Service with both gRPC protocol and Restful HTTP protocol. By default, it is parsed as a Restful HTTP URL, which can be controlled by the `as_is_grpc` option.
- **`as_is_grpc`** (boolean, optional, default is false): If set to `true`, interprets `as_addr` as a gRPC URL.
- **`policy_ids`** (array of strings): Specifies the list of policy IDs to use.

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

## Attester and Verifier Combinations and Bidirectional Remote Attestation

By configuring different combinations of `attest` and `verify` properties at both ends of the tunnel (including ingress and egress), a flexible trust model can be achieved.

| Remote Attestation Scenario | TNG Client Configuration | TNG Server Configuration | Description |
|---|---|---|---|
| Unidirectional | `verify` | `attest` | Most common scenario, where the TNG server is in a TEE, and the TNG client is in a normal environment. |
| Bidirectional | `attest`, `verify` | `attest`, `verify` | The TNG server and TNG client are in two different TEEs. |
| (Reverse) Unidirectional | `attest` | `verify` | The TNG server is in a normal environment, and the TNG client is in a TEE. In this case, only the client certificate is verified. During the TLS handshake, the TNG server will use a fixed P256 X509 self-signed certificate embedded in the TNG code as its certificate. |
| No TEE (For Debugging Purposes Only) | `no_ra` | `no_ra` | Both the TNG server and TNG client are in non-TEE environments. In this case, a normal TLS session is established between the TNG client and TNG server through unidirectional verification. |


### Envoy Admin Interface

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

