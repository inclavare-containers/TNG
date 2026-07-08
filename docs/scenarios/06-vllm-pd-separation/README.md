## Use Case 6: vLLM P/D Separation with NIXL/UCX KV Cache Transfer Encryption

[中文文档](scenario_zh.md)

### Scenario Overview

- **Goal**: In a vLLM disaggregated prefill/decode (P/D) architecture, the P node and D node are deployed on separate hosts and communicate via the NIXL Connector and UCX for KV cache transfer. TNG provides end-to-end security across three communication links:
  1. **User → vLLM Proxy**: OHTTP encryption with one-way remote attestation (user verifies the Proxy's TEE identity)
  2. **vLLM Proxy → P/D Nodes**: OHTTP encryption with mutual remote attestation
  3. **P ↔ D KV Cache**: Rats-TLS (`multiplex: false`) encryption with mutual remote attestation
- **Approach**:
  - The vLLM Proxy runs in an independent TEE, receiving user inference requests and routing them to P or D nodes
  - P and D nodes use symmetric TNG configurations — any node can act as both KV cache server and client
  - The KV cache port range (5000-5031) is captured via `netfilter` with `port_end`, encrypted by rats-tls with independent TLS sessions per stream for high-bandwidth throughput
- **Effect**:
  - User requests are encrypted end-to-end; the vLLM Proxy runs in a verifiable TEE
  - Proxy-to-P/D inference traffic uses OHTTP + mutual RA
  - P↔D KV cache transfer uses rats-tls with per-stream independent TLS sessions (`multiplex: false`), avoiding single-connection bandwidth bottlenecks
  - vLLM NIXL/UCX requires no code changes — UCX connects to its original KV cache port, with iptables transparently redirecting traffic to TNG at the netfilter layer

### Topology Diagram

![Topology Diagram](diagram.drawio.svg)

### Node Address Assignment

| Node | Role | IP Address |
| --- | --- | --- |
| vLLM Proxy | Inference request router (no inference computation) | `10.0.0.1` |
| P Node | vLLM Prefill instance (KV cache server) | `10.0.0.10` |
| D Node | vLLM Decode instance (KV cache client) | `10.0.0.20` |

### User-side TNG Client Configuration

The user initiates inference requests through a TNG Client using `mapping` mode with OHTTP and one-way RA (verify):

```json
{
    "add_ingress": [
        {
            "mapping": {
                "in": { "host": "127.0.0.1", "port": 8080 },
                "out": { "host": "10.0.0.1", "port": 8080 }
            },
            "ohttp": {},
            "verify": {
                "as_addr": "<attestation-service-url>",
                "policy_ids": ["default"]
            }
        }
    ]
}
```

- **Key Points**:
  - The user application connects to `127.0.0.1:8080`; TNG encrypts the request via OHTTP and sends it to the vLLM Proxy at `10.0.0.1:8080`
  - **`verify`** ensures the user-side TNG validates the Proxy's TEE identity via remote attestation before establishing the tunnel (one-way RA)
  - **Tip**: If you prefer not to use mapping mode, TNG also supports an HTTP proxy mode (port 41000) — configure your application's HTTP proxy to point to the TNG Client instead.

### vLLM Proxy-side TNG Configuration

The vLLM Proxy runs in an independent TEE and requires two TNG rules: receiving user requests (egress 8080) and forwarding inference requests to P/D nodes (ingress 8080):

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    { "port": 8080 }
                ]
            },
            "ohttp": {},
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            },
            "verify": {
                "as_addr": "<attestation-service-url>",
                "policy_ids": ["default"]
            }
        }
    ],
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [
                    { "port": 8080 }
                ]
            },
            "ohttp": {},
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ]
}
```

- **Key Points**:
  - **egress 8080**: Receives OHTTP-encrypted requests from users (one-way RA — the Proxy acts as Attester, verified by the user), decrypts and forwards to the local vLLM Proxy process listening on port 8080
  - **ingress 8080**: The vLLM Proxy actively connects to P/D nodes' port 8080 to send inference requests, encrypted via OHTTP with mutual RA (both `attest` and `verify`)
  - Both `attest` and `verify` are configured so the Proxy proves its own TEE identity while also verifying the P/D nodes' identities

### P/D Node TNG Configuration (Symmetric)

P and D nodes share the same TNG configuration. Each node handles two types of traffic: receiving inference requests from the Proxy (egress 8080, OHTTP) and bidirectional KV cache transfer between P and D (ingress + egress 5000-5031, rats-tls):

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    { "port": 5000, "port_end": 5031 }
                ]
            },
            "rats_tls": {
                "multiplex": false
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            },
            "verify": {
                "as_addr": "<attestation-service-url>",
                "policy_ids": ["default"]
            }
        }
    ],
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [
                    { "port": 8080 }
                ]
            },
            "ohttp": {},
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            },
            "verify": {
                "as_addr": "<attestation-service-url>",
                "policy_ids": ["default"]
            }
        },
        {
            "netfilter": {
                "capture_dst": [
                    { "port": 5000, "port_end": 5031 }
                ]
            },
            "rats_tls": {
                "multiplex": false
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            },
            "verify": {
                "as_addr": "<attestation-service-url>",
                "policy_ids": ["default"]
            }
        }
    ]
}
```

- **Key Points**:
  - **egress 8080 (OHTTP)**: Receives inference requests from the vLLM Proxy. The Proxy actively connects (ingress), while the P/D node passively accepts the connection (egress) — OHTTP encrypted with mutual RA
  - **ingress 5000-5031 (rats-tls)**: When this node initiates a KV cache transfer to the peer (e.g., D pulling from P), it actively connects to the peer's KV cache port range — rats-tls with `multiplex: false` for independent per-stream TLS sessions, plus mutual RA
  - **egress 5000-5031 (rats-tls)**: When the peer initiates a KV cache transfer to this node, it passively accepts connections on the KV cache port range — same rats-tls and RA configuration
  - **`rats_tls.multiplex: false`**: Each KV cache transfer gets its own independent TLS session without HTTP/2 CONNECT tunneling, achieving higher per-stream throughput — recommended for high-bandwidth KV cache scenarios
  - **Symmetric configuration**: P and D use identical configs; roles can be swapped at any time without reconfiguration

### vLLM and UCX Configuration

#### Prerequisites

- **vLLM version**: v0.8.0 or later (NixlConnector support with V1 engine)
- **NIXL library**: bundled with vLLM requirements (`nixl[cu13] >= 0.7.1, < 0.10.0`)
- **UCX**: >= 1.18.0 recommended for stability
- **Proxy dependencies**: `pip install quart` (required for the disaggregated proxy)

#### Prefill Node (P) — `10.0.0.10`

```bash
# UCX environment variables for TCP transport
export UCX_TLS=tcp
export UCX_NET_DEVICES=all

# NIXL side channel port (unique per instance if co-located)
export VLLM_NIXL_SIDE_CHANNEL_PORT=5600

# Start vLLM in prefill mode (KV producer)
vllm serve <model-name> \
    --host 0.0.0.0 \
    --port 8100 \
    --kv-transfer-config '{"kv_connector":"NixlConnector","kv_role":"kv_producer","kv_rank":0}'
```

#### Decode Node (D) — `10.0.0.20`

```bash
# UCX environment variables for TCP transport
export UCX_TLS=tcp
export UCX_NET_DEVICES=all

# NIXL side channel port
export VLLM_NIXL_SIDE_CHANNEL_PORT=5600

# Start vLLM in decode mode (KV consumer)
vllm serve <model-name> \
    --host 0.0.0.0 \
    --port 8200 \
    --kv-transfer-config '{"kv_connector":"NixlConnector","kv_role":"kv_consumer","kv_rank":1}'
```

#### vLLM Disaggregated Proxy — `10.0.0.1`

The proxy routes user requests between prefill and decode nodes. This is a standalone Quart-based script provided in the vLLM repository examples:

```bash
# Install proxy dependencies
pip install quart

# Start the disaggregated proxy
python3 examples/online_serving/disaggregated_serving/disagg_proxy_demo.py \
    --model <model-name> \
    --prefill http://10.0.0.10:8100 \
    --decode http://10.0.0.20:8200 \
    --port 8080
```

> **Note**: There is no official built-in `python -m vllm` entrypoint for the disaggregated proxy. The `disagg_proxy_demo.py` is an example script. For production deployments, consider [vLLM Production Stack](https://github.com/vllm-project/production-stack) which includes a more robust prefix-aware router.

#### Client Test Command

```bash
# Test the OpenAI-compatible Chat Completions API via TNG Client
curl http://127.0.0.1:8080/v1/chat/completions \
    -H "Content-Type: application/json" \
    -d '{
        "model": "<model-name>",
        "messages": [
            {"role": "user", "content": "Hello, how are you?"}
        ],
        "max_tokens": 100,
        "temperature": 0.7
    }'
```

#### Environment Variables Reference

| Variable | Description | Default | Notes |
|----------|-------------|---------|-------|
| `UCX_TLS` | Transport layers for UCX | — | `tcp` for plain TCP (intercepted by TNG) |
| `UCX_NET_DEVICES` | Network devices for UCX | — | Use `all` or specific device names (e.g., `mlx5_0:1`); `tcp` is NOT a valid device name |
| `VLLM_NIXL_SIDE_CHANNEL_PORT` | NIXL handshake port | `5600` | Must be unique per instance if P and D are co-located |
| `VLLM_NIXL_SIDE_CHANNEL_HOST` | NIXL side channel host | `localhost` | Optional |

#### `--kv-transfer-config` Parameters

| Parameter | Values | Description |
|-----------|--------|-------------|
| `kv_connector` | `"NixlConnector"` | Use NIXL for KV cache transfer |
| `kv_role` | `"kv_producer"`, `"kv_consumer"`, `"kv_both"` | Role in KV transfer topology |
| `kv_rank` | `0`, `1`, etc. | Rank for ordering (producer=0, consumer=1) |
| `kv_buffer_device` | `"cuda"`, `"cpu"` | Device for KV buffer allocation |

### Typical Usage Steps

1. **User side**:
   - Start TNG Client with the mapping + ohttp + verify configuration above
   - Configure the inference client application to connect to `127.0.0.1:8080`

2. **vLLM Proxy side** (`10.0.0.1`):
   - Deploy the vLLM Proxy process in a TEE (e.g., TDX VM)
   - Start the Attestation Agent
   - Start TNG with the ingress + egress configuration above
   - The vLLM Proxy process listens on port 8080

3. **P Node** (`10.0.0.10`) and **D Node** (`10.0.0.20`):
   - Start the Attestation Agent on each node
   - Start TNG with the symmetric configuration above
   - Configure UCX and NIXL environment variables as shown in the vLLM Configuration section
   - Start vLLM with NixlConnector (P node as `kv_producer`, D node as `kv_consumer`)

4. **vLLM Proxy side** (`10.0.0.1`):
   - Deploy the vLLM Proxy process and disaggregated proxy in a TEE (e.g., TDX VM)
   - Start the Attestation Agent
   - Start TNG with the ingress + egress configuration above
   - Start the disaggregated proxy on port 8080 (matching the TNG egress listen port)

5. **Verification**:
   - Send an inference request from the user client to `127.0.0.1:8080`
   - The request flows: Client → (OHTTP) → Proxy → (OHTTP + mutual RA) → P Node (prefill)
   - After prefill, the D node pulls KV cache from the P node via NIXL/UCX — the TCP traffic is intercepted by TNG netfilter and encrypted with rats-tls (`multiplex: false`) + mutual RA
   - The D node receives the KV cache and continues decoding, returning the response through the same chain
