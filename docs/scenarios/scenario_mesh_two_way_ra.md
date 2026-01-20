## Use Case 3: Mutual Remote Attestation between Mesh Cluster Nodes

[中文文档](scenario_mesh_two_way_ra_zh.md)

### Scenario Overview

- **Goal**: In a cluster composed of multiple confidential computing nodes, establish mutual remote attestation and encrypted channels for communication between nodes, allowing mutual access only when "I trust you, and you trust me."
- **Approach**:
  - Run a TNG instance on each node, and simultaneously configure both Ingress and Egress;
  - Enable both `attest` and `verify` on both ends to achieve mutual remote attestation;
  - Control which ports' traffic should enter the TNG tunnel via `netfilter`.
- **Effect**:
  - Communication between cluster nodes is established only when both environments pass verification;
  - Nodes can be incrementally introduced or updated in the Mesh while maintaining overall link trustworthiness.

### Topology Diagram

![Topology Diagram](../diagrams/scenario_mesh_two_way_ra.drawio.svg)

### TNG Configuration Example on a Single Node

The following example shows a node acting as both an "entry point" (Ingress) and an "exit point" (Egress), using `netfilter` on both sides and enabling both `attest` and `verify`:

```json
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": {
                    "port": 9001
                }
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
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": {
                    "port": 9001
                }
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

> Note: In actual configuration, ensure that fields like `capture_dst` on each node match the node's actual listening ports and routing policies; the above example only shows typical usage.

### Key Points

- **Mutual Remote Attestation (Mutual RA)**:
  - Each node is configured with `attest` (proving itself) and `verify` (verifying the peer);
  - When establishing a connection, both sides send the peer's attestation materials to the Attestation Service for verification. The tunnel is established only if both sides pass policy checks.
- **Port Selection (`capture_dst.port`)**:
  - Typically, choose the actual communication ports between microservices, such as the forwarding ports between service mesh sidecars;
  - Can also be combined with cgroup, ipset, etc., to control more precisely which traffic should enter the tunnel.
- **Policy Management (`policy_ids`)**:
  - Different policy IDs can be used to divide the cluster into different trust domains, such as "production cluster," "test cluster," or "specific image versions."

### Typical Usage Steps

- **On each Mesh node**:
  - Deploy backend services or sidecars;
  - Start Attestation Agent and ensure access to a centralized Attestation Service;
  - Start TNG, loading a mutual RA configuration containing both `add_ingress` and `add_egress`;
  - Configure iptables rules (automatically or manually by TNG) to import inbound and outbound traffic that needs protection into TNG.

- **At the cluster level**:
  - Configure policies in the Attestation Service (corresponding to `policy_ids`), specifying which TEE measurements, images, and configurations are considered "trusted";
  - When rolling out upgrades or adding new nodes, as long as the nodes meet the policy requirements, they can automatically join the communicable Mesh.

Through this method, any connection established between any two nodes in the Mesh cluster is built on the basis of "both sides having passed remote attestation verification," which is more secure than the traditional model that only verifies server certificates. This is particularly suitable for multi-tenant or multi-party confidential computing clusters.
