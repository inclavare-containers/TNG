## 用例2：客户端通过透明代理访问单机密计算节点

### 场景概述

- **目标**：已有应用直接通过 TCP/HTTP 访问后端服务，不希望改代码、也不希望配置应用层代理，只想在网络层“透明地”把流量导入 TNG 隧道。
- **做法**：
  - 在客户端侧使用 TNG Ingress 的 `netfilter` 模式，通过 iptables 把符合条件的流量重定向到本地 TNG；
  - 在服务端侧同样使用 TNG Egress 的 `netfilter` 模式，劫持发往后端服务端口的流量，由 TNG 解密后再转发给后端服务。
- **效果**：
  - 应用的目标地址、端口配置保持不变；
  - 哪些流量进入 TNG 隧道完全由 iptables 规则和 `capture_dst` / `capture_cgroup` 等配置控制；
  - 客户端侧可以开启远程证明，确保只与可信的服务端环境建立连接。

### 拓扑示意图

![拓扑示意图](../diagrams/scenario_netfilter_single_zh.drawio.svg)

### 客户端侧 TNG（Ingress）配置示例

- **Ingress 模式**：`netfilter`
- **远程证明角色**：`verify`（客户端验证服务端）

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

- **关键点说明**：
  - **`netfilter.capture_dst.port`**：指定需要被捕获的目标端口（例子中为 8080），即应用原本直接访问的服务端口。
  - 如有需要，可以结合 `capture_cgroup` / `nocapture_cgroup` 等字段，只捕获特定 cgroup 内应用的流量，避免影响同机其他业务。
  - **`verify.as_addr`** 和 **`policy_ids`** 的含义与用例 1 相同，用于连接 Attestation Service 并选择策略。

### 服务端侧 TNG（Egress）配置示例

- **Egress 模式**：`netfilter`
- **远程证明角色**：`attest`

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

- **关键点说明**：
  - 与用例 1 中的 Egress 配置类似，只是这里客户端侧也是 `netfilter`，因此两端应用都不需要感知代理/隧道的存在。
  - `capture_local_traffic` 为 `true` 时，服务端本机访问后端服务的请求也会被 TNG 接管，方便在单机环境中测试。

### 典型使用步骤

- **客户端侧**：
  - 部署并启动 TNG Ingress，加载上述 `netfilter + verify` 配置；
  - 根据配置生成或手动编写 iptables 规则，将发往目标端口（例如 8080）的流量重定向到 TNG 监听端口（`listen_port`）。
- **服务端侧**：
  - 与用例 1 类似，在机密计算环境中启动 Attestation Agent 和后端服务；
  - 启动 TNG Egress，加载 `netfilter + attest` 配置；
  - 设置 iptables 规则，将进入机密实例、发往后端端口的流量先转发给 TNG。

在这种模式下，客户端和服务端应用的连接目标保持不变，TNG 借助内核 netfilter 在“看不见的地方”接入流量，实现真正的“透明代理 + 远程证明”能力，非常适合线上已有服务平滑接入。
