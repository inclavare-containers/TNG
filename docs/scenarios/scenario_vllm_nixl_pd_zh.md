## 用例5：基于 NIXL 连接器的 vLLM PD 分离场景

[English Document](scenario_vllm_nixl_pd.md)

### 场景概述

- **目标**：在机密计算集群中，以 PD 分离（Disaggregated Prefill）模式部署 vLLM，并对全部通信路径施加 TEE 远程证明与 TNG 加密保护。推理客户端访问代理服务，由代理将预填充（Prefill）请求分发给 P 节点、将解码（Decode）请求分发给 D 节点；P 节点与 D 节点通过 NIXL/TCP 传输 KV 缓存，所使用的 TCP 端口**动态分配**。四类节点（客户端、代理、P、D）各自运行在独立的 TEE 中。
- **做法**：
  - 每个节点各运行一个 TNG 实例，在同一配置文件中按需组合 Ingress 与 Egress；
  - **客户端 → 代理**：单向远程证明（RA）——客户端验证代理节点的 TEE 环境，代理不需要验证客户端；
  - **代理 ↔ P 节点** 与 **代理 ↔ D 节点**：双向 RA——双方互相证明并验证；
  - **P ↔ D（NIXL/TCP，动态端口）**：双向 RA——发送侧（P 节点）在 `capture_dst` 中仅指定 D 节点的 NIXL 网络 IP（不限制端口），透明拦截 P 侧 NIXL 客户端连接的任意端口；接收侧（D 节点）使用专属 NIXL 网络接口配合仅匹配 IP 的 `capture_dst`，无需提前知晓动态端口号即可拦截所有入向 NIXL 连接。
- **效果**：
  - vLLM PD 分离流水线中的全部通信路径均获得端到端加密与远程证明保护；
  - vLLM 和 NIXL 库无需任何代码修改——TNG 通过 netfilter 透明拦截流量；
  - NIXL 的动态 TCP 端口分配在网络层由 TNG 透明处理，无需应用层感知或手工跟踪端口号。

### 拓扑示意图

![拓扑示意图](../diagrams/scenario_vllm_nixl_pd_zh.drawio.svg)

### 网络规划

示例使用专用网络接口将 NIXL 流量与代理/服务流量分离：

| 节点 | 服务 IP（代理 ↔ P/D） | NIXL IP（仅 P ↔ D） |
|------|----------------------|---------------------|
| 代理（Proxy） | `192.168.1.1` | — |
| P 节点（Prefill） | `192.168.1.2` | `10.0.1.1` |
| D 节点（Decode） | `192.168.1.3` | `10.0.1.2` |

- vLLM HTTP 端口：代理监听 **8000**；P 节点监听 **8100**；D 节点监听 **8200**。
- NIXL KV 传输：P 侧 NIXL 客户端向 D 节点 `10.0.1.2` 的动态 NIXL 接收端口发起 TCP 连接。

使用独立的 NIXL 专用网络（`10.0.1.0/24`）可确保 P/D 节点上的仅 IP 匹配规则只作用于 NIXL 流量，不干扰服务网络上的代理流量。

### 客户端 TNG 配置

客户端使用 TNG Ingress 将推理请求包裹在 RA-TLS 隧道中。仅配置 `verify`——验证代理节点的 TEE 环境，客户端自身无需提供证明。

- **Ingress 模式**：`netfilter`
- **RA 角色**：仅 `verify`

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

### 代理节点 TNG 配置

代理节点运行单个 TNG 实例，覆盖三条通信路径。`add_egress`（接受客户端连接）与 `add_ingress`（连接 P/D 节点）合并在同一配置文件中：

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

- **关键说明**：
  - `add_egress` 仅配置 `attest`（不配置 `verify`），实现对客户端的单向 RA：代理向客户端证明自身 TEE 环境，客户端无需是 TEE 节点。
  - 两条 `add_ingress` 分别指向 P 节点（端口 8100）和 D 节点（端口 8200），均配置 `attest`+`verify` 实现双向 RA。

### P 节点（Prefill）TNG 配置

P 节点的 TNG 实例处理两条路径：
- 接受来自代理的连接（Egress，双向 RA，固定端口 8100）；
- 向 D 节点发送 NIXL KV 数据（Ingress，双向 RA，**动态端口——使用仅 IP 捕获**）。

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

- **关键说明**：
  - `add_ingress` 中的 `capture_dst` 仅指定 `"host": "10.0.1.2"`（D 节点的 NIXL IP），**不填写 `port` 字段**。这样 TNG netfilter 会在 OUTPUT 链中匹配 P 节点向该 IP 发出的所有 TCP 连接，无论目标端口是多少，从而透明覆盖 NIXL 动态分配的端口。
  - `capture_cgroup` 将拦截范围进一步限定为 P 节点的 vLLM 进程（需要 cgroup v2）。若希望捕获发往 `10.0.1.2` 的所有出向流量而不区分进程，可删除此字段。

### D 节点（Decode）TNG 配置

D 节点的 TNG 实例通过两条 `add_egress` 分别处理两类入向连接：
- 来自代理的连接（固定端口 8200，双向 RA）；
- 来自 P 节点的 NIXL 连接（D 节点 NIXL 接口上的动态端口，双向 RA）。

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

- **关键说明**：
  - 第一条 Egress（`"host": "10.0.1.2"`，无端口）通过 PREROUTING 链拦截 D 节点 NIXL 接口上所有入向 TCP 连接，无需预知动态端口号。TNG 内部通过 `SO_ORIGINAL_DST` 获取原始目标端口，将解密后的流量转发给 D 节点的 NIXL 接收器。
  - 第二条 Egress（`"port": 8200`）处理到达 D 节点服务 IP（`192.168.1.3`）的代理 HTTP 流量。
  - 两条 Egress 分别针对不同的网络接口（NIXL：`10.0.1.x`；服务：`192.168.1.x`），iptables 规则互不重叠，可安全共存。
  - TNG 为每条 `add_egress` 生成独立的 iptables 链（`TNG_EGRESS_0`、`TNG_EGRESS_1`……），各链依次以 `-I PREROUTING 1` 方式插入，后配置的链先被检查。将仅 IP 匹配的 NIXL 条目置于数组首位、端口匹配的代理条目置于第二位，可使端口 8200 的代理规则（`TNG_EGRESS_1`）优先被检查——不过由于两条规则针对不同 IP，实际上无论顺序如何都不会产生冲突。

### 关键点说明

- **双向远程证明（Mutual RA）**：
  - 在代理↔P、代理↔D 以及 P↔D 三条链路上，两端均配置 `attest`（证明自身 TEE）和 `verify`（验证对端 TEE）；
  - 只有双方的 TEE 度量值均通过证明策略校验时，TNG 隧道才会建立，任何一方的 TEE 异常都会导致握手失败。

- **客户端的单向 RA**：
  - 客户端仅配置 `verify`，代理仅配置 `attest`；
  - 适用于推理服务场景：客户端无需运行在 TEE 中，但必须能够信任服务端的基础设施环境后才向其发送数据。

- **动态端口处理（NIXL/TCP）**：
  - vLLM NIXL 连接器在运行时动态分配 TCP 监听端口，TNG 配置阶段无法预知该端口号；
  - 在 `capture_dst` 中仅指定 `host`（不填写 `port`），TNG netfilter 将捕获发往该 IP 任意端口的全部 TCP 流量，透明地将 NIXL 连接纳入 RA-TLS 隧道，无需关心实际分配的端口号；
  - 该方案无需修改 vLLM 或 NIXL 库，也无需额外的端口发现机制——动态端口的协商仍在应用层完成，TNG 在网络层透明接管。

- **证明策略的差异化配置**：
  - 示例中所有路径统一使用 `policy_ids: ["default"]` 以便说明。生产环境应为每类节点角色定义独立的策略 ID（如 `proxy-policy`、`prefill-node-policy`、`decode-node-policy`），以细粒度表达信任要求，防止被攻陷的代理节点冒充 P 或 D 节点。

### 典型使用步骤

- **Attestation Service 侧**：
  - 为各节点角色（代理、P 节点、D 节点）配置证明策略；
  - 确保所有 TEE 节点均能访问 Attestation Service 地址（`<attestation-service-url>`）。

- **各 TEE 节点（代理、P、D）上**：
  - 启动 Attestation Agent；
  - 启动应用程序（代理服务 / vLLM 预填充实例 / vLLM 解码实例）并监听相应端口；
  - 启动 TNG，加载各节点对应的上述配置。TNG 将自动配置所需的 iptables/TPROXY 规则，无需手工管理 iptables。

- **客户端侧**：
  - 启动 TNG Ingress，加载客户端配置；
  - 照常向 `192.168.1.1:8000` 发送推理请求，TNG 透明处理 RA-TLS 封装。

通过上述配置，vLLM PD 分离流水线中的每一段通信——从客户端推理请求、经代理分发，到 P/D 节点间的 NIXL KV 缓存传输——均受到全链路加密与远程证明保护，且无需对 vLLM 或 NIXL 库做任何修改，NIXL 的动态 TCP 端口分配问题也由 TNG 在网络层透明处理。
