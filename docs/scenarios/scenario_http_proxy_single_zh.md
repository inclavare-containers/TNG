## 用例1：客户端通过 HTTP 代理访问单机密计算节点

### 场景概述

- **目标**：客户端已经支持 HTTP/HTTPS 访问后端服务，希望在不改业务代码的前提下，引入机密计算和远程证明，对端到端链路进行加密和环境校验。
- **做法**：在客户端侧部署一个 TNG Ingress，作为本地 HTTP 代理；在服务端机密计算实例内部署一个 TNG Egress，通过 netfilter 劫持发往后端服务的流量。
- **效果**：
  - 客户端应用只需配置 HTTP 代理（或环境变量），无需改请求地址；
  - 客户端侧 TNG 在建立隧道前会向 Attestation Service 验证服务端 TNG 所在环境的可信性；
  - 服务端 TNG 解密流量后转发给本地后端服务。

### 拓扑示意图

![拓扑示意图](../diagrams/scenario_http_proxy_single_zh.drawio.svg)

### 客户端侧 TNG（Ingress）配置示例

- **Ingress 模式**：`http_proxy`
- **远程证明角色**：`verify`（仅验证服务端）

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
  - **`proxy_listen`**：客户端应用配置的 HTTP 代理地址，例如 `http://127.0.0.1:41000`。
  - **`dst_filters`**：只将发往指定域名/端口（例子中是任意域名、端口 8080）的请求送入 TNG 隧道，其余流量按普通 HTTP 代理转发。
  - **`verify.as_addr`**：Attestation Service 的地址，客户端 TNG 会向该服务发送服务端的证明材料进行验证。
  - **`policy_ids`**：指定使用的远程证明策略集，例如 `default`。

### 服务端侧 TNG（Egress）配置示例

- **Egress 模式**：`netfilter`
- **远程证明角色**：`attest`（作为证明者）

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
  - **`netfilter.capture_dst.port`**：后端应用实际监听的端口（例如 8080）。TNG 将通过 iptables 劫持发往该端口的加密流量。
  - **`capture_local_traffic`**：为 `true` 时也会劫持源 IP 为本机的流量，方便在同一台机密计算实例内部署 TNG 和后端服务。
  - **`attest.aa_addr`**：指向本机 Attestation Agent 的 Unix Socket 地址，TNG 将通过它获取当前环境的远程证明材料，供客户端侧验证。

### 典型使用步骤

- **客户端侧**：
  - 启动 TNG Ingress，加载上述 `http_proxy + verify` 配置；
  - 在浏览器或 HTTP 客户端中配置 HTTP 代理（指向 `proxy_listen`）；
  - 正常访问原本的服务地址（域名/IP 不需要改）。
- **服务端侧**：
  - 在机密计算环境中部署后端服务并监听端口（例如 8080）；
  - 启动 Attestation Agent 与 Attestation Service；
  - 启动 TNG Egress，加载 `netfilter + attest` 配置，并配置系统 iptables 规则（可由 TNG 自动生成）。

当客户端发起请求时，请求会先到本地 TNG，经远程证明验证通过后通过加密隧道发送到服务端 TNG，再解密并转发到后端服务，实现“HTTP 代理 + 机密计算 + 远程证明”的组合场景。
