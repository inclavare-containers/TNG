## Use Case 5: vLLM Disaggregated Prefill (PD Separation) with NIXL Connector

[中文文档](scenario_vllm_nixl_pd_zh.md)

### Scenario Overview

- **Goal**: In a confidential computing cluster, deploy vLLM in disaggregated prefill (PD separation) mode and protect all communication paths with TEE remote attestation and TNG encryption. An inference client accesses a proxy service that dispatches prefill requests to the Prefill (P) node and decode requests to the Decode (D) node; P and D transfer KV cache over NIXL/TCP using **dynamically-assigned ports**. All four nodes (client, proxy, P, D) run in independent TEEs.
- **Approach**:
  - Deploy one TNG instance per node, combining Ingress/Egress configurations in a single file where needed;
  - **Client → Proxy**: one-way RA — the client verifies the proxy's TEE environment, but the proxy does not verify the client;
  - **Proxy ↔ P node** and **Proxy ↔ D node**: mutual RA — both parties attest and verify each other;
  - **P ↔ D (NIXL/TCP, dynamic ports)**: mutual RA — on the sending side (P) use a `capture_dst` entry with only D's NIXL IP (no port) to intercept any port P's NIXL client connects to; on the receiving side (D) use a dedicated NIXL network interface and IP-only `capture_dst` matching to intercept all incoming NIXL connections without needing to know the dynamic port number in advance.
- **Effect**:
  - All communication paths in the vLLM PD pipeline are encrypted and attested end-to-end;
  - Neither vLLM nor the NIXL library requires any code changes — TNG captures traffic transparently via netfilter;
  - NIXL's dynamic TCP port allocation is handled at the IP level, requiring no manual port tracking or application reconfiguration.

### Topology Diagram

![Topology Diagram](../diagrams/scenario_vllm_nixl_pd.drawio.svg)

### Network Layout

The following example uses dedicated network interfaces to cleanly separate NIXL traffic from proxy/service traffic:

| Node | Service IP (proxy ↔ P/D) | NIXL IP (P ↔ D only) |
|------|--------------------------|----------------------|
| Proxy | `192.168.1.1` | — |
| P (Prefill) | `192.168.1.2` | `10.0.1.1` |
| D (Decode) | `192.168.1.3` | `10.0.1.2` |

- vLLM HTTP: Proxy listens on port **8000**; P listens on **8100**; D listens on **8200**.
- NIXL KV transfer: P's NIXL client initiates TCP connections to D's dynamically-assigned NIXL receiver port on `10.0.1.2`.

Using a dedicated NIXL network (`10.0.1.0/24`) ensures that IP-only `capture_dst` rules on P and D apply only to NIXL traffic and do not interfere with proxy/service traffic on the main network.

### Client-side TNG Configuration

The client uses TNG Ingress to wrap inference requests in RA-TLS. Only `verify` is configured — the client verifies the proxy's TEE but does not need to attest itself.

- **Ingress Mode**: `netfilter`
- **RA Role**: `verify` only

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    {
                        "host": "192.168.1.1",
                        "port": 8000
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

### Proxy Node TNG Configuration

The proxy node runs a single TNG instance covering three communication paths. `add_egress` (accepting client connections) and `add_ingress` (connecting to P/D) are combined in one config file:

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [
                    {
                        "port": 8000
                    }
                ],
                "capture_local_traffic": true
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
    ],
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    {
                        "host": "192.168.1.2",
                        "port": 8100
                    }
                ]
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            },
            "verify": {
                "as_addr": "<attestation-service-url>",
                "policy_ids": [
                    "default"
                ]
            }
        },
        {
            "netfilter": {
                "capture_dst": [
                    {
                        "host": "192.168.1.3",
                        "port": 8200
                    }
                ]
            },
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
    ]
}
```

- **Key Points**:
  - The `add_egress` entry uses `attest` only (no `verify`), implementing one-way RA toward the client: the proxy attests its TEE environment; the client is not required to be in a TEE.
  - The two `add_ingress` entries each target one backend node (P at port 8100, D at port 8200) with full mutual RA (`attest` + `verify`).

### P Node (Prefill) TNG Configuration

The P node's TNG handles two paths:
- Accepting connections from the proxy (Egress, mutual RA, fixed port 8100);
- Sending NIXL KV data to D (Ingress, mutual RA, **dynamic port — uses IP-only capture**).

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [
                    {
                        "port": 8100
                    }
                ]
            },
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
    ],
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    {
                        "host": "10.0.1.2"
                    }
                ],
                "capture_cgroup": [
                    "/system.slice/vllm-p.service"
                ]
            },
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
    ]
}
```

- **Key Points**:
  - The `add_ingress` entry specifies `"host": "10.0.1.2"` (D's NIXL IP) with **no `port` field**. This matches all outgoing TCP connections from P to that IP on any port, transparently covering NIXL's dynamically-assigned destination port.
  - `capture_cgroup` further restricts interception to P's vLLM process, so only NIXL connections originated by vLLM-P are wrapped in the tunnel. Remove this field if all outgoing traffic to `10.0.1.2` should be captured regardless of the source process.

### D Node (Decode) TNG Configuration

The D node's TNG handles two types of incoming connections via two `add_egress` entries:
- Connections from the proxy (fixed port 8200, mutual RA);
- NIXL connections from P (dynamic port on D's NIXL interface, mutual RA).

```json
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [
                    {
                        "host": "10.0.1.2"
                    }
                ]
            },
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            },
            "verify": {
                "as_addr": "<attestation-service-url>",
                "policy_ids": [
                    "default"
                ]
            }
        },
        {
            "netfilter": {
                "capture_dst": [
                    {
                        "port": 8200
                    }
                ]
            },
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
    ]
}
```

- **Key Points**:
  - The first entry (`"host": "10.0.1.2"`, no port) intercepts all incoming TCP on D's NIXL interface via the PREROUTING chain, handling NIXL's dynamic port without needing to configure it. TNG uses `SO_ORIGINAL_DST` internally to recover the original destination port and forward decrypted traffic to the NIXL receiver.
  - The second entry (`"port": 8200`) handles proxy→D HTTP traffic arriving on D's service IP (`192.168.1.3`).
  - Because the two entries target different network interfaces (NIXL: `10.0.1.x`; service: `192.168.1.x`), the iptables rules for the two entries do not overlap and can coexist safely.
  - TNG generates a separate iptables chain for each `add_egress` entry (`TNG_EGRESS_0`, `TNG_EGRESS_1`, ...). Each chain is inserted at the top of PREROUTING in configuration order; the last-configured entry ends up processed first. Placing the NIXL entry (IP-only, broader) before the proxy entry (port-specific) in the array ensures the proxy chain (`TNG_EGRESS_1`) is evaluated first — though in practice, since the two entries target different IPs, the ordering has no functional impact here.

### Key Points

- **Mutual RA (two-way attestation)**:
  - On the Proxy↔P, Proxy↔D, and P↔D links, both ends configure `attest` (prove their own TEE) and `verify` (verify the peer's TEE);
  - A TNG tunnel is established only when both parties' TEE measurements pass the attestation policies. Any compromised or non-TEE node breaks the handshake.

- **One-way RA for the Client**:
  - The client configures `verify` only; the proxy configures `attest` only;
  - This is appropriate for inference services where the client need not be in a TEE but must be able to trust the serving infrastructure before sending data.

- **Dynamic Port Handling (NIXL/TCP)**:
  - vLLM's NIXL connector allocates TCP listener ports at runtime; the exact port cannot be known at TNG configuration time.
  - By omitting the `port` field from `capture_dst` and specifying only `host`, TNG's netfilter captures all TCP traffic to that IP on any port, transparently routing NIXL connections through the RA-TLS tunnel regardless of which port was dynamically assigned.
  - This approach requires no changes to vLLM, NIXL, or any surrounding infrastructure — the dynamic port resolution remains entirely within the application layer while TNG operates at the network layer.

- **Attestation Policy Differentiation**:
  - This example uses `policy_ids: ["default"]` across all paths for clarity. In production, define separate policy IDs for each node role (e.g., `proxy-policy`, `prefill-node-policy`, `decode-node-policy`) to express fine-grained trust requirements and prevent a compromised proxy from impersonating a P or D node.

### Typical Usage Steps

- **Attestation Service**:
  - Define attestation policies for each node role;
  - Ensure all nodes can reach the Attestation Service endpoint (`<attestation-service-url>`).

- **On each TEE node (proxy, P, D)**:
  - Start the Attestation Agent;
  - Start the application (proxy service / vLLM prefill / vLLM decode) on the configured ports;
  - Start TNG with the per-node configuration above. TNG will automatically configure the required iptables/TPROXY rules — no manual iptables management is needed.

- **On the client**:
  - Start TNG Ingress with the client configuration above;
  - Send inference requests to `192.168.1.1:8000` as usual; TNG transparently handles RA-TLS wrapping.

With this setup, the entire vLLM PD separation pipeline is protected end-to-end: from the client's inference request, through proxy dispatch, to inter-node NIXL KV cache transfer — all without modifying vLLM or the NIXL library, and with transparent handling of NIXL's dynamic TCP port allocation.
