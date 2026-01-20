## 用例4：客户访问业务集群场景（OHTTP 协议支持）

### 场景概述

- **目标**：客户端访问的是一个已有的 HTTP 业务集群，希望在客户端与集群之间建立基于 OHTTP 协议的安全隧道，同时不破坏现有 7 层负载均衡、路由规则等基础设施。
- **做法**：
  - 在客户端侧使用 TNG Ingress 的 `netfilter` 模式接入流量，并通过 OHTTP 协议对业务请求进行加密；
  - 在服务端侧使用 TNG Egress 的 `netfilter` 模式接入，并通过 OHTTP 协议进行解密，恢复原始业务请求；
  - 中间可以保留 7 层网关（例如 Nginx、应用网关）来做路由和负载均衡，承载加密后的 OHTTP 流量。
- **效果**：
  - 客户端与业务集群之间的链路被 TNG 隧道保护，且由于 OHTTP 的特性，网关无法看到请求具体内容；
  - 现有的 7 层网关配置、路由规则可以在最小改动下继续工作；
  - 配合远程证明，确保接入集群的 TNG 节点处于可信环境。

### 拓扑示意图

![拓扑示意图](../diagrams/scenario_business_cluster_zh.drawio.svg)

### 客户端侧 TNG（Ingress）配置示例

客户端侧通过 `netfilter` 捕获发往业务网关端口的流量，并在进入隧道前，按需要通过 OHTTP 协议对 HTTP 请求路径做重写：

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

- **关键点说明**：
  - **`netfilter.capture_dst.port`**：业务入口网关对外暴露的端口。
  - **`ohttp.path_rewrites`**：通过正则表达式对加密后的外层请求路径进行重写，以适配后端网关的路由规则。
  - **`verify`**：确保客户端侧 TNG 在建立隧道前，对服务端 TNG 所在环境进行远程证明验证。

### 服务端侧 TNG（Egress）配置示例

服务端侧 TNG 负责从网关接收加密的 OHTTP 流量，完成解密后，将原始请求转发给后端服务：

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

- **关键点说明**：
  - **`ohttp.key`**：配置 OHTTP 密钥来源。`self_generated` 表示 TNG 会自动生成并轮转密钥。
  - **`capture_local_traffic`** 为 `true` 时，可在与网关同机部署时仍能正确劫持本机流量。
  - **`attest`**：服务端作为证明方，向 Attestation Service 提供本机环境的远程证明材料。

### 典型使用步骤

- **客户端侧**：
  - 部署并启动 TNG Ingress，配置 `netfilter + ohttp` 和 `verify`；
  - 通过 iptables 将发往业务网关端口的流量导入 TNG；
  - 客户端应用继续按原地址/路径访问业务。

- **服务端侧**：
  - 在机密计算环境中部署业务网关和后端服务；
  - 启动 Attestation Agent 与 Attestation Service；
  - 启动 TNG Egress，配置 `netfilter + ohttp` 和 `attest`，并设置 netfilter 规则劫持来自隧道的流量。

通过这一模式，可以在不修改现有网关配置的前提下，对整个 HTTP 链路进行加密和远程证明控制，非常适合集群化 HTTP 业务的加固。
