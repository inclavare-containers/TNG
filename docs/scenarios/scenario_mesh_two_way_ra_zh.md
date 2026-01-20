## 用例3：Mesh 集群节点间双向远程证明

### 场景概述

- **目标**：在一个由多个机密计算节点组成的集群中，为节点之间的通信建立双向远程证明和加密通道，只有当“我信你，你也信我”时才允许互相访问。
- **做法**：
  - 每个节点上都运行一个 TNG 实例，并同时配置 Ingress 与 Egress；
  - 在两端都启用 `attest` 和 `verify`，实现双向远程证明；
  - 通过 `netfilter` 控制哪些端口的流量需要进入 TNG 隧道。
- **效果**：
  - 集群节点之间的通信只在双方环境都通过验证时才建立；
  - 可以逐步在 Mesh 中引入或更新节点，同时保持整体链路的可信性。

### 拓扑示意图

![拓扑示意图](../diagrams/scenario_mesh_two_way_ra_zh.drawio.svg)

### 单个节点上的 TNG 配置示例

以下示例展示了一个节点同时作为“接入端”（Ingress）和“出口端”（Egress），两侧都使用 `netfilter`，并同时开启 `attest` 和 `verify`：

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
    ]
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

> 注：实际配置中，应确保各节点上的 `capture_dst` 等字段与本节点的实际监听端口、路由策略相匹配，上例只展示典型写法。

### 关键点说明

- **双向远程证明（Mutual RA）**：
  - 每个节点都配置了 `attest`（证明自己）和 `verify`（验证对端）；
  - 在建立连接时，双方都会向 Attestation Service 发送对方的证明材料进行验证，只有双方都通过策略检查，隧道才会建立。
- **端口选择（`capture_dst.port`）**：
  - 通常选择微服务之间实际通信的端口，例如服务网格 sidecar 间的转发端口；
  - 也可以配合 cgroup、ipset 等更精细地控制哪些流量应进入隧道。
- **策略管理（`policy_ids`）**：
  - 可以通过不同的策略 ID 将集群划分为不同信任域，例如“生产集群”、“测试集群”或“特定镜像版本”等。

### 典型使用步骤

- **每个 Mesh 节点上**：
  - 部署后端服务或 sidecar；
  - 启动 Attestation Agent，并确保能够访问集中式 Attestation Service；
  - 启动 TNG，加载包含 `add_ingress` 和 `add_egress` 的双向 RA 配置；
  - 配置 iptables 规则（由 TNG 自动或手工完成），将需要保护的出入站流量导入 TNG。

- **集群层面**：
  - 在 Attestation Service 中配置策略（`policy_ids` 对应），指定哪些 TEE 度量值、镜像、配置被视为“可信”；
  - 滚动升级或新增节点时，只要节点满足策略要求，就可以自动加入可通信的 Mesh。

通过这种方式，Mesh 集群内任意两节点之间建立的连接，都建立在“双方都经过远程证明验证”的基础上，比传统仅验证服务端证书的模式更安全，特别适合多租户或多方参与的机密计算集群。
