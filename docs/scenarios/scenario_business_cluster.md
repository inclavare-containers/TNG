## Use Case 4: Client Accessing Business Cluster Scenario (OHTTP Support)

[中文文档](scenario_business_cluster_zh.md)

### Scenario Overview

- **Goal**: The client accesses an existing HTTP business cluster, and the intent is to establish a secure tunnel based on the OHTTP protocol between the client and the cluster without disrupting existing Layer 7 infrastructure such as load balancers and routing rules.
- **Approach**:
  - On the client side, use the `netfilter` mode of TNG Ingress to access traffic, and encrypt business requests via the OHTTP protocol;
  - On the server side, use the `netfilter` mode of TNG Egress to access traffic, and then decrypt the OHTTP traffic to restore the original business request;
  - A Layer 7 gateway (e.g., Nginx, Application Gateway) can be retained in the middle to handle routing and load balancing, but it now carries encrypted OHTTP traffic.
- **Effect**:
  - The link between the client and the business cluster is protected by the TNG tunnel, and due to OHTTP's characteristics, the gateway cannot see the specific content of the requests;
  - Existing Layer 7 gateway configurations and routing rules can continue to work with minimal changes;
  - Combined with Remote Attestation to ensure that TNG nodes accessing the cluster are in a trusted environment.

### Topology Diagram

![Topology Diagram](../diagrams/scenario_business_cluster.drawio.svg)

### Client-side TNG (Ingress) Configuration Example

The client side captures traffic sent to the business gateway port via `netfilter` and rewrites the HTTP request path as needed via the OHTTP protocol before entering the tunnel:

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": {
                    "port": 8080
                }
            },
            "ohttp": {
                "path_rewrites": [
                    {
                        "match_regex": "^/foo/([^/]+)([/]?.*)$",
                        "substitution": "/foo/$1"
                    }
                ]
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
  - **`netfilter.capture_dst.port`**: The port exposed externally by the business entry point (e.g., a certain gateway).
  - **`ohttp.path_rewrites`**: Rewrites the encrypted outer request path via regular expressions to adapt to the backend gateway's routing rules.
  - **`verify`**: Ensures that the client-side TNG verifies the server-side TNG's environment via remote attestation before establishing the tunnel.

### Server-side TNG (Egress) Configuration Example

The server-side TNG is responsible for receiving encrypted OHTTP traffic from the gateway, completing decryption, and then forwarding the original request to the backend service:

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
            "ohttp": {
                "key": {
                    "source": "self_generated"
                }
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```

- **Key Points**:
  - **`ohttp.key`**: Configures the OHTTP key source. `self_generated` means TNG will automatically generate and rotate keys.
  - When **`capture_local_traffic`** is `true`, it can still correctly hijack local traffic when deployed on the same machine as the gateway.
  - **`attest`**: The server acts as the attester, providing remote attestation materials for its local environment to the Attestation Service.

### Typical Usage Steps

- **Client side**:
  - Deploy and start TNG Ingress, configuring `netfilter + ohttp` and `verify`;
  - Import traffic sent to the business gateway port into TNG via iptables;
  - The client application continues to access the business using the original address/path.

- **Server side**:
  - Deploy the business gateway and backend services in a confidential computing environment;
  - Start Attestation Agent and Attestation Service;
  - Start TNG Egress, configuring `netfilter + ohttp` and `attest`, and set netfilter rules to hijack traffic from the tunnel.

Through this mode, the entire HTTP link can be encrypted and remote attestation control can be performed without modifying existing gateway configurations. This is very suitable for reinforcing clustered HTTP businesses.
