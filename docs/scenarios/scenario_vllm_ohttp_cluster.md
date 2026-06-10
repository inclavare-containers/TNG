## Use Case 5: vLLM Inference Service with OHTTP Cluster

[中文文档](scenario_vllm_ohttp_cluster_zh.md)

### Scenario Overview

- **Goal**: The client accesses vLLM inference services deployed in a confidential computing cluster via OpenAI-compatible API, with end-to-end OHTTP encryption and remote attestation, without modifying the vLLM application code.
- **Approach**:
  - On the client side, use the `http_proxy` mode of TNG Ingress as a local HTTP proxy, and encrypt inference prompts via the OHTTP protocol;
  - In the middle, deploy an Nginx Layer 7 gateway with `least_conn` load balancing to distribute OHTTP-encrypted traffic across backend TNG Egress instances;
  - On the server side, each vLLM instance is co-located with a TNG Egress instance, using `netfilter` mode to capture traffic and `peer_shared` OHTTP key distribution to ensure any node can decrypt traffic routed to it by Nginx.
- **Effect**:
  - The client application only needs to configure an HTTP proxy address; vLLM instances run unmodified with the OpenAI-compatible API;
  - OHTTP encryption ensures Nginx (the load balancer) cannot see the inference prompt content;
  - Remote attestation verifies that each vLLM node runs in a trusted confidential computing environment;
  - The `peer_shared` cluster allows seamless horizontal scaling — new nodes share OHTTP keys automatically via Serf Gossip protocol.

### Topology Diagram

![Topology Diagram](../diagrams/scenario_vllm_ohttp_cluster.drawio.svg)

### Client-side TNG (Ingress) Configuration Example

The client side starts TNG Ingress as a local HTTP proxy. Applications send requests through this proxy, and TNG encrypts them via OHTTP before forwarding to the Nginx gateway:

```json
{
    "add_ingress": [
        {
            "http_proxy": {
                "proxy_listen": {
                    "host": "0.0.0.0",
                    "port": 41000
                },
                "dst_filters": {
                    "domain": "*",
                    "port": 8080
                }
            },
            "ohttp": {},
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
  - **`http_proxy.proxy_listen`**: The HTTP proxy address applications connect to, e.g., `http://127.0.0.1:41000`.
  - **`dst_filters`**: Only requests to specified domains/ports (any domain, port 8080 — matching the Nginx gateway) enter the TNG tunnel; other traffic is forwarded as a regular HTTP proxy.
  - **`ohttp`**: Enables OHTTP encryption for the inference prompts. The client automatically fetches the active public key from the server cluster.
  - **`verify.as_addr`**: The address of the Attestation Service, used to verify the server-side TNG environment trustworthiness before establishing the tunnel.

### Server-side TNG (Egress) Configuration Example

Each server node runs a TNG Egress instance with `netfilter` + OHTTP (`peer_shared`) + `attest`. Below is the configuration for a single node (Node 1, IP `192.168.1.11`):

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [
                    { "port": 8080 }
                ]
            },
            "ohttp": {
                "key": {
                    "source": "peer_shared",
                    "rotation_interval": 300,
                    "host": "0.0.0.0",
                    "port": 8301,
                    "peers": [
                        "192.168.1.12:8301",
                        "192.168.1.13:8301"
                    ],
                    "attest": {
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                    },
                    "verify": {
                        "as_addr": "<attestation-service-url>",
                        "policy_ids": [
                            "default"
                        ]
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

- **Key Points**:
  - **`netfilter.capture_dst`**: Port 8080 matches the vLLM listening port. TNG automatically sets up iptables rules to hijack traffic sent to this port.
  - **`ohttp.key.source: "peer_shared"`**: OHTTP keys are shared across the cluster via Serf Gossip protocol, ensuring all nodes share the same key pool. Any node can decrypt traffic encrypted by any other node's public key.
  - **`peers`**: List of other nodes in the cluster. Supports **IP:port** and **domain:port** formats (e.g., `tng-node-1.default.svc.cluster.local:8301`). Only one accessible peer is needed to join the cluster.
  - **`peers_file`** (alternative to `peers`): Path to a JSON file containing peer addresses (e.g., `"/etc/tng/peers.json"`). Useful for large-scale clusters or dynamic peer management via external orchestration tools.
  - **`ohttp.key` within `attest`/`verify`**: Controls inter-node remote attestation within the peer_shared cluster, ensuring only verified trusted nodes participate in key sharing.
  - **Top-level `attest`**: Server acts as the attester, providing remote attestation materials for the client-side verification.
  - **`listen_port`**: Not explicitly configured — TNG uses its default value for the netfilter captured traffic receiving port.

### Nginx Gateway Configuration Example

Nginx acts as the unified entry point, load-balancing OHTTP-encrypted requests across TNG Egress instances:

```nginx
upstream vllm_cluster {
    least_conn;
    server 192.168.1.11:8080;   # TNG Egress + vLLM Node 1
    server 192.168.1.12:8080;   # TNG Egress + vLLM Node 2
    server 192.168.1.13:8080;   # TNG Egress + vLLM Node 3
}

server {
    listen 8080;

    location / {
        proxy_pass http://vllm_cluster;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

- **Key Points**:
  - **`least_conn`**: Distributes requests to the node with the fewest active connections, balancing load across the cluster.
  - Nginx forwards to port 8080 on each backend node, where TNG Egress captures the traffic via netfilter.
  - Nginx cannot see the OHTTP-encrypted request content — it only routes at the transport layer.

### Typical Usage Steps

- **Server side** (repeat for each node):
  1. Start vLLM instance with OpenAI-compatible API, listening on port 8080;
  2. Start Attestation Agent (Unix socket at `/run/confidential-containers/attestation-agent/attestation-agent.sock`);
  3. Write the TNG Egress configuration JSON and start TNG;
  4. Verify the peer_shared cluster has formed (check Serf peers via `serf members` or TNG logs);

- **Nginx gateway**:
  1. Install Nginx on the gateway machine;
  2. Write the upstream + server configuration;
  3. Start Nginx and verify it routes to backend nodes.

- **Client side**:
  1. Start TNG Ingress with the `http_proxy + ohttp + verify` configuration;
  2. Configure your application to use the HTTP proxy at `http://<tng-ingress-ip>:41000`;
  3. Send requests to the Nginx gateway address (e.g., `http://<nginx-gateway-ip>:8080`).

### End-to-End Test

```bash
# Send an OpenAI-compatible chat completion request through TNG HTTP Proxy
curl -x http://<tng-ingress-ip>:41000 \
     http://<nginx-gateway-ip>:8080/v1/chat/completions \
     -H "Content-Type: application/json" \
     -d '{
         "model": "Qwen/Qwen2.5-7B",
         "messages": [{"role": "user", "content": "Hello, what is TNG?"}],
         "max_tokens": 256
     }'
```

- The `-x` flag directs the request through the local TNG HTTP Proxy.
- The target address is the Nginx gateway's 8080 port.
- TNG Ingress encrypts the request with OHTTP, Nginx load-balances to a TNG Egress node, which decrypts and forwards to the local vLLM instance.
- The response follows the reverse path back to the client.
