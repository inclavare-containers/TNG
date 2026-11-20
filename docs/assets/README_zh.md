# TNG 主图说明

[English](README.md) · [文档首页](../README_zh.md)

[英文图](tng-overview.svg) · [中文图](tng-overview_zh.svg)

主图展示调用方与机密服务可信域之间的一种部署形态。副本表示在适当路由与密钥配置下支持的拓扑，不承诺节点数量或自动编排。VM 和 Pod/sidecar 表示部署位置，不表示提供 Operator 或托管 Kubernetes 集成。

## 阅读图示

青色实线表示 TNG 隧道端点之间的加密流量。灰色实线表示本地应用链路，是否保护取决于部署方式。负载均衡器路由加密流量，L4/L7 是否适用取决于协议。紫色虚线表示证明关系，不表示逐包时序。验证可在 TNG 内执行，也可使用外部服务；证明方通过 TEE 内的代理收集证据。

图中主例为应用接入本地 Ingress。浏览器 WASM SDK 自身提供客户端 TNG 能力，无需该本地守护进程。根据选定模型，任一端都可成为证明方或验证方。调用方也可以位于 TEE 中。

OHTTP 密钥共享仅适用于 OHTTP 副本。TCP RATS-TLS、HTTP OHTTP 与 UDP over QUIC 是独立通道，由配置和二进制可用功能决定。图示不表示 UDP 经由 TCP TLS 连接，也不表示所有协议使用共享集群密钥。OHTTP relay 隐私需要独立 relay 和适当的信任模型。

## 能力依据

| 图中元素 | 参考 |
| --- | --- |
| 隧道入口、出口与证明角色 | [架构](../architecture_zh.md) · [远程证明](../remote_attestation_zh.md) |
| 端口映射、代理、透明拦截与 UDP/QUIC | [配置](../configuration_zh.md) |
| RATS-TLS 与 OHTTP | [协议](../protocols_zh.md) |
| `tng exec` | [Hook 指南](../../tng-hook/README_zh.md) |
| 浏览器、Python 和 Go | [WASM](../../tng-wasm/README_zh.md) · [Python](../../tng-python/README_zh.md) · [Go](../../tng-go/README_zh.md) |
| L4/L7 路由与多副本服务 | [负载均衡](../using-with-slb_zh.md) · [场景](../scenarios/README_zh.md) |
| OHTTP 密钥共享与轮换 | [Peer-shared 密钥](../peer_shared_zh.md) |

## 修改方式

直接编辑 SVG 源文件，同步更新两种语言。保留可编辑文本、系统字体和独立浅色图面，保证 GitHub 深浅主题下均可读。不要添加脚本、远程资源、嵌入位图或 `foreignObject`。每张 SVG 保持在 150 KB 以下。

将两张图渲染至约 830 px 宽，检查文字、箭头端点、信任边界和裁切情况。既检查 README 中的缩略效果，也检查完整图片。XML 能解析不代表图示语义或可读性合格。
