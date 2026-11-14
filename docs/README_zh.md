# TNG 文档

[English](README.md) · [项目首页](../README_zh.md)

## 从这里开始

通过[本地快速开始](getting-started_zh.md)发出第一个请求。它使用 RATS-TLS 非复用隧道，关闭远程证明。随后按[远程证明指南](remote_attestation_zh.md)收集和验证真实 TEE 证据。

[架构指南](architecture_zh.md)介绍 Ingress、Egress 与证明角色。[场景目录](scenarios/README_zh.md)帮助你选择部署拓扑。

## 选择接入方式

| 应用 | 入口 | 注意事项 |
| --- | --- | --- |
| 已知服务端口 | [端口映射](configuration_zh.md) · [本地示例](getting-started_zh.md) | 显式配置本地与远端隧道地址 |
| 支持代理的应用 | [HTTP 代理场景](scenarios/02-http-proxy-single/README_zh.md) · [HTTP/SOCKS5 配置](configuration_zh.md) | 在应用中设置代理 |
| 现有进程 | [`tng exec` 与 hook](../tng-hook/README_zh.md) | Linux 进程拦截，平台和动态库要求见指南 |
| 需要透明拦截的工作负载 | [Netfilter 场景](scenarios/01-netfilter-single/README_zh.md) | Linux 网络环境及所需权限 |
| 浏览器 | [JavaScript/WASM SDK](../tng-wasm/README_zh.md) · [在线演示](https://inclavare-containers.github.io/TNG/) | 客户端能力在 WebAssembly 中运行 |
| Python HTTP 或 OpenAI 客户端 | [Python SDK](../tng-python/README_zh.md) · [入门](../tng-python/docs/getting-started_zh.md) | 包装现有受支持客户端 |
| Go HTTP 客户端 | [Go SDK](../tng-go/README_zh.md) · [入门](../tng-go/docs/getting-started_zh.md) | `http.RoundTripper`，需要 TNG 二进制 |

## 部署指南

- [场景目录](scenarios/README_zh.md)：单节点、OHTTP 集群、双向证明、vLLM 与 relay 隐私。
- [L4 负载均衡](using-with-slb_zh.md)：按协议和捕获模式说明连接模型与粘性。
- [浏览器 CORS](../tng-wasm/docs/cors_zh.md)：跨域浏览器请求配置。

## 概念与参考

| 主题 | 文档 |
| --- | --- |
| 隧道端点与信任角色 | [架构](architecture_zh.md) |
| 证据收集、验证模型与策略 | [远程证明](remote_attestation_zh.md) |
| 字段、捕获模式、OHTTP、UDP/QUIC 与可观测性 | [配置参考](configuration_zh.md) |
| 证书、封装消息和密钥同步的运维命令 | [CLI 工具](tools_zh.md) |
| 日志目标、格式与滚动 | [日志](log_zh.md) |
| 需要迁移的变更 | [版本兼容性](version_compatibility_zh.md) |
| 已发布和未发布的变更 | [变更日志](../CHANGELOG.md) |

## 内部设计与贡献

| 任务 | 文档 |
| --- | --- |
| 构建、打包或运行测试 | [开发者指南](developer_zh.md) |
| 理解 RATS-TLS 和 OHTTP 握手 | [隧道协议](protocols_zh.md) |
| 理解 OHTTP 集群密钥分发与轮换 | [Peer-shared 密钥](peer_shared_zh.md) |
| 查看实测性能 | [性能快照](performance_zh.md) |
| 运行压测或生成报告 | [Benchmark 工具](../bench/README_zh.md) · [报告](../bench/reporting_zh.md) |
| 修改或理解产品主图 | [图示说明](assets/README_zh.md) |

集成测试共享网络命名空间与 iptables 规则。请按开发者指南顺序运行 `make run-test`。贡献文档时同步更新英文和中文。
