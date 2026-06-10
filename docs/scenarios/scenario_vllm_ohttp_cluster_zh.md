## 用例5：vLLM 推理服务 OHTTP 集群场景

### 场景概述

- **目标**：客户端通过 OpenAI 兼容 API 访问部署在机密计算集群中的 vLLM 推理服务，在端到端链路上使用 OHTTP 加密和远程证明，且无需修改 vLLM 应用代码。
- **做法**：
  - 在客户端侧使用 TNG Ingress 的 `http_proxy` 模式作为本地 HTTP 代理，并通过 OHTTP 协议对推理提示词进行加密；
  - 中间部署 Nginx 7 层网关，使用 `least_conn` 负载均衡算法将 OHTTP 加密流量分发到后端多个 TNG Egress 实例；
  - 在服务端侧，每个 vLLM 实例与一个 TNG Egress 实例同机部署，TNG 使用 `netfilter` 模式捕获流量，并通过 `peer_shared` OHTTP 密钥分发确保被 Nginx 路由到任意节点的流量都能被正确解密。
- **效果**：
  - 客户端应用只需配置 HTTP 代理地址即可；vLLM 实例以原生的 OpenAI 兼容 API 运行，无需任何改造；
  - OHTTP 加密确保 Nginx（负载均衡器）无法看到推理提示词的内容；
  - 远程证明验证每个 vLLM 节点运行于可信的机密计算环境；
  - `peer_shared` 集群支持无缝水平扩展——新节点通过 Serf Gossip 协议自动共享 OHTTP 密钥。

### 拓扑示意图

![拓扑示意图](../diagrams/scenario_vllm_ohttp_cluster_zh.drawio.svg)

### 客户端侧 TNG（Ingress）配置示例

客户端侧启动 TNG Ingress 作为本地 HTTP 代理。应用通过该代理发送请求，TNG 在进入隧道前通过 OHTTP 协议对请求进行加密，然后转发至 Nginx 网关：

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

- **关键点说明**：
  - **`http_proxy.proxy_listen`**：客户端应用配置的 HTTP 代理地址，例如 `http://127.0.0.1:41000`。
  - **`dst_filters`**：只有发往指定域名/端口（任意域名，端口 8080——匹配 Nginx 网关）的请求才会进入 TNG 隧道；其他流量作为普通 HTTP 代理转发。
  - **`ohttp`**：启用 OHTTP 加密推理提示词。客户端自动从服务端集群获取当前有效的公钥。
  - **`verify.as_addr`**：Attestation Service 的地址，用于在建立隧道前验证服务端 TNG 所在环境的可信性。

### 服务端侧 TNG（Egress）配置示例

每个服务节点运行一个 TNG Egress 实例，使用 `netfilter` + OHTTP（`peer_shared`）+ `attest`。以下是单个节点（节点 1，IP `192.168.1.11`）的配置：

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

- **关键点说明**：
  - **`netfilter.capture_dst`**：端口 8080 与 vLLM 监听端口一致。TNG 会自动设置 iptables 规则，劫持发往该端口的流量。
  - **`ohttp.key.source: "peer_shared"`**：OHTTP 密钥通过 Serf Gossip 协议在集群内共享，确保所有节点共享同一密钥池。被 Nginx 路由到任意节点的流量，都能被该节点解密。
  - **`peers`**：集群中其他节点的地址列表。支持 **IP:port** 和**域名:port**格式（例如 `tng-node-1.default.svc.cluster.local:8301`）。只需提供一个可访问的 peer 即可加入集群。
  - **`peers_file`**（替代 `peers` 的方式）：指向包含 peer 地址的 JSON 文件路径（如 `"/etc/tng/peers.json"`）。适用于大规模集群或通过外部编排工具动态管理 peer 列表的场景。
  - **`ohttp.key` 内的 `attest`/`verify`**：控制 peer_shared 集群内节点间的远程证明，确保只有经过验证的可信节点才能参与密钥共享。
  - **顶层 `attest`**：服务端作为证明方，向客户端提供本机环境的远程证明材料。
  - **`listen_port`**：未显式配置——TNG 使用默认值作为 netfilter 捕获流量的接收端口。

### Nginx 网关配置示例

Nginx 作为统一入口，将 OHTTP 加密请求负载均衡到各 TNG Egress 实例：

```nginx
upstream vllm_cluster {
    least_conn;
    server 192.168.1.11:8080;   # TNG Egress + vLLM 节点 1
    server 192.168.1.12:8080;   # TNG Egress + vLLM 节点 2
    server 192.168.1.13:8080;   # TNG Egress + vLLM 节点 3
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

- **关键点说明**：
  - **`least_conn`**：将请求分发到当前连接数最少的节点，在集群间均衡负载。
  - Nginx 转发到各后端节点的 8080 端口，由 TNG Egress 通过 netfilter 捕获流量。
  - Nginx 无法看到 OHTTP 加密的请求内容——它仅在传输层做路由。

### 典型使用步骤

- **服务端侧**（每个节点重复）：
  1. 启动 vLLM 实例，使用 OpenAI 兼容 API，监听端口 8080；
  2. 启动 Attestation Agent（Unix socket 位于 `/run/confidential-containers/attestation-agent/attestation-agent.sock`）；
  3. 编写 TNG Egress 配置 JSON 并启动 TNG；
  4. 验证 peer_shared 集群已形成（通过 `serf members` 或 TNG 日志检查）。

- **Nginx 网关**：
  1. 在网关机器上安装 Nginx；
  2. 写入 upstream + server 配置；
  3. 启动 Nginx 并验证其能正确路由到后端节点。

- **客户端侧**：
  1. 启动 TNG Ingress，加载 `http_proxy + ohttp + verify` 配置；
  2. 在应用中配置 HTTP 代理（指向 `http://<tng-ingress-ip>:41000`）；
  3. 向 Nginx 网关地址发起请求（如 `http://<nginx-gateway-ip>:8080`）。

### 端到端测试

```bash
# 通过 TNG HTTP Proxy 发送 OpenAI 兼容 API 请求
curl -x http://<tng-ingress-ip>:41000 \
     http://<nginx-gateway-ip>:8080/v1/chat/completions \
     -H "Content-Type: application/json" \
     -d '{
         "model": "Qwen/Qwen2.5-7B",
         "messages": [{"role": "user", "content": "Hello, what is TNG?"}],
         "max_tokens": 256
     }'
```

- `-x` 参数将请求通过本地 TNG HTTP Proxy 发送。
- 目标地址为 Nginx 网关的 8080 端口。
- TNG Ingress 使用 OHTTP 加密请求，Nginx 负载均衡到某个 TNG Egress 节点，该节点解密后转发给本地 vLLM 实例。
- 响应沿反向路径返回客户端。
