# 部署场景

[English](README.md) · [文档首页](../README_zh.md)

首次体验可使用无需 TEE 的[本地入门教程](../getting-started_zh.md)。以下指南说明实际部署拓扑；请替换服务地址，并按环境配置证据收集与验证。

| 目标 | 接入方式与协议 | 部署与证明 | 指南 |
| --- | --- | --- | --- |
| 透明访问单个机密节点 | Netfilter；RATS-TLS | 客户端网关与 TEE 服务端，配置 AA 和验证器 | [单节点透明代理](01-netfilter-single/README_zh.md) |
| 通过应用 HTTP 代理访问 | HTTP 代理 + 服务端 netfilter；RATS-TLS | 客户端代理与 TEE 服务端，配置 AA 和验证器 | [单节点 HTTP 代理](02-http-proxy-single/README_zh.md) |
| 经 HTTP 路由访问多副本机密服务 | OHTTP | 多服务节点，配置共享密钥与远程证明 | [业务集群](03-business-cluster/README_zh.md) |
| 服务间通信验证双方 | 透明拦截；双向 RATS-TLS | TEE 节点同时配置证明和验证 | [节点间双向证明](04-mesh-two-way-ra/README_zh.md) |
| 在 HTTP 网关后加密 vLLM 推理请求 | OHTTP；CLI 与 SDK 接入 | Nginx 与多副本推理服务，配置 AA 和验证 | [vLLM OHTTP 集群](05-vllm-ohttp-cluster/README_zh.md) |
| 保护 vLLM prefill/decode 流量 | 推理请求使用 OHTTP；TCP KV-cache 传输使用 RATS-TLS 非复用 | 分离的 prefill/decode 节点，在受保护链路启用证明 | [vLLM PD 分离](06-vllm-pd-separation/README_zh.md) |
| 分离请求来源与内容的可见性 | OHTTP 与公共 relay | 调用方、relay 与机密服务方；隐私取决于角色分离与信任假设 | [OHTTP relay 隐私](08-ohttp-relay-privacy/README_zh.md) |

各指南提供具体配置与前置条件。RATS-TLS 是否复用需要另行选择，[连接模型与负载均衡](../using-with-slb_zh.md)说明其影响。OHTTP [peer-shared 密钥](../peer_shared_zh.md)让副本能够解密使用集群密钥加密的请求，不提供自动服务编排或无限规模承诺。

## 相关参考

- [远程证明](../remote_attestation_zh.md)：代理、内置或外部验证、策略与参考值。
- [配置](../configuration_zh.md)：端口映射、HTTP/SOCKS5 代理、netfilter 与 UDP 模式。
- [隧道协议](../protocols_zh.md)：握手细节与安全行为。
- [性能](../performance_zh.md)：实测配置与方法。
