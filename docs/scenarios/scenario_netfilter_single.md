## Use Case 2: Client Accessing Single Confidential Computing Node via Transparent Proxy

[中文文档](scenario_netfilter_single_zh.md)

### Scenario Overview

- **Goal**: Existing applications access backend services directly via TCP/HTTP and do not want to change code or configure application-layer proxies. They only want to import traffic into the TNG tunnel "transparently" at the network layer.
- **Approach**:
  - On the client side, use the `netfilter` mode of TNG Ingress and redirect matching traffic to the local TNG via iptables;
  - On the server side, also use the `netfilter` mode of TNG Egress to hijack traffic sent to the backend service port, which is then decrypted by TNG and forwarded to the backend service.
- **Effect**:
  - The destination address and port configuration of the application remain unchanged;
  - Which traffic enters the TNG tunnel is entirely controlled by iptables rules and configurations like `capture_dst` / `capture_cgroup`;
  - The client side can enable remote attestation to ensure that connections are established only with trusted server environments.

### Topology Diagram

![Topology Diagram](../diagrams/scenario_netfilter_single.drawio.svg)

### Client-side TNG (Ingress) Configuration Example

- **Ingress Mode**: `netfilter`
- **Remote Attestation Role**: `verify` (client verifies server)

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": {
                    "port": 8080
                }
            },
            "verify": {
                "as_addr": "<attestation-service-url>",
                "policy_ids": [
                    "default"
                ]
            }
        }
    ]
}
```

- **Key Points**:
  - **`netfilter.capture_dst.port`**: Specifies the target port to be captured (8080 in the example), which is the service port originally accessed directly by the application.
  - If needed, fields like `capture_cgroup` / `nocapture_cgroup` can be combined to capture traffic only from applications within specific cgroups, avoiding impact on other local businesses.
  - The meanings of **`verify.as_addr`** and **`policy_ids`** are the same as in Use Case 1, used for connecting to the Attestation Service and selecting policies.

### Server-side TNG (Egress) Configuration Example

- **Egress Mode**: `netfilter`
- **Remote Attestation Role**: `attest`

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": {
                    "port": 8080
                },
                "capture_local_traffic": true
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```

- **Key Points**:
  - Similar to the Egress configuration in Use Case 1, but here the client side is also `netfilter`, so applications on both ends do not need to be aware of the proxy/tunnel's existence.
  - When `capture_local_traffic` is `true`, requests from the server itself to backend services are also taken over by TNG, facilitating testing in a single-machine environment.

### Typical Usage Steps

- **Client side**:
  - Deploy and start TNG Ingress, loading the above `netfilter + verify` configuration;
  - Generate or manually write iptables rules according to the configuration to redirect traffic sent to the target port (e.g., 8080) to the TNG listening port (`listen_port`).
- **Server side**:
  - Similar to Use Case 1, start Attestation Agent and backend services in a confidential computing environment;
  - Start TNG Egress, loading the `netfilter + attest` configuration;
  - Set iptables rules to forward traffic entering the confidential instance and sent to the backend port to TNG first.

In this mode, the connection targets of the client and server applications remain unchanged. TNG uses the kernel netfilter to access traffic in an "invisible place," achieving true "transparent proxy + remote attestation" capability, which is very suitable for the smooth access of existing online services.
