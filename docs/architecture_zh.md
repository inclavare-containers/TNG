# 核心概念与工作原理

本页详细介绍了 TNG (Trusted Network Gateway) 的核心工作模型、远程证明机制以及所采用的加密协议。在开始配置和部署 TNG 之前，理解这些概念将有助于您更好地设计网络拓扑并编写配置文件。

## 隧道模型与 Ingress/Egress

### 隧道模型

在经典的TCP编程模型中，网络通信可以简化为如下图所示的Client-Server。Client作为请求（TCP / HTTP）的主动发起方，连接到Server端监听的某个端口。此时Client和Server间使用明文或者TLS等加密协议进行通信。

![Client-Server 模型](diagrams/client_server_model_zh.drawio.svg)

在机密计算环境中，可以在双方可信域中部署一对TNG实例，这对TNG实例间会通过远程证明建立起一个安全信道。Client发起的明文请求会在经过TNG加密后，通过该安全信道发送到另一端的TNG实例，并转发给 Server 端。和 TCP / HTTP 类似，这种安全信道是双工的，当Server处理完请求返回响应时，响应明文同样会被TNG加密，返回给Client侧的TNG，在由其解密后转发给Client程序。

![TNG 隧道模型](diagrams/tng_tunnel_model_zh.drawio.svg)

### Ingress 与 Egress 介绍

在上面的模型中，Client 和 Server 作为连接的主动发起方和被动响应方，其语义分别为 `connect()` 和 `accept()`。对应地，在 TNG 中我们对安全信道也设计了对应的两个概念：入口（Ingress）和出口（Egress）。主动发起方（Client）的流量会通过入口（Ingress）进入安全信道，再从出口（Egress）流出到被动响应方（Server）。

虽然存在有 Ingress 和 Egress 的区分，但两个 TNG 都是对等的实体，所建立的安全信道也是双工的，允许消息在两个方向任意传输。

TNG 实例可以被配置为扮演 Ingress 或者 Egress。主要区别在于对流量的接入方式上。为了更方便实现与已有业务的结合，在 TNG 的 Ingress 和 Egress 侧都提供了多种方法来实现普通业务流量的接入。使得用户可以在无需修改已有应用程序的同时，根据自己的需求灵活地控制流量的加密和解密过程。

> [!TIP]
> 可在 [参数手册](configuration_zh.md) 中查看 [Ingress](configuration_zh.md#ingress) 和 [Egress](configuration_zh.md#egress) 的具体配置参数。

## 远程证明 (Remote Attestation)

在现代云计算环境中，确保通信双方的身份真实性和运行环境的完整性至关重要。TNG 通过引入远程证明机制，为数据通信提供了端到端的强大信任保障。远程证明允许一方（证明者）向另一方（验证者）证明其硬件和软件环境的真实性及未被篡改。

TNG 在远程证明中扮演着核心角色，根据配置可以成为**证明者 (Attester)** 或 **验证者 (Verifier)**。

### 远程证明角色

#### 证明者 (Attester)：证明“我是谁”和“我做了什么”

当 TNG 被配置为证明者角色时，它负责生成并提供其所在计算环境的“可信凭证”或“证据”（Evidence）。这些证据包含了关于计算平台（例如，TEE 环境）的硬件度量值、启动时的软件组件哈希值以及运行时配置等信息。

为了实现这一功能，TNG 会与一个关键组件交互：
*   **Attestation Agent (AA)**：运行在 TEE（可信执行环境）内部的代理程序。AA 负责与底层的安全硬件（如 Intel TDX, AMD SEV-SNP, CSV 等）进行交互，收集原始可信度量数据，并将这些数据格式化为标准的“证据”，供 TNG 获取。

在该场景中，Attester 就是一个“宣誓者”，它拿着由 AA 提供的、经过安全硬件认证的“身份证”，向对方证明自己的清白。

> [!TIP]
> 关于 Attester 的配置字段及示例，请参考参数手册中的 [Attester 部分](configuration_zh.md#attest)。

#### 验证者 (Verifier)：验证“你是否可信”

当 TNG 被配置为验证者角色时，它负责接收并严格审查来自对端 TNG (Attester) 提供的可信证据。验证者会根据预设的安全策略和信任规则，对证据进行多方面验证，以确认对端的身份真实性、运行环境是否符合预期且未被篡改。

为了完成复杂的证据验证过程，TNG 会与另一个关键组件协同工作：
*   **Attestation Service (AS)**：这是一个独立的后端服务，通常运行在一个高度可信的环境中。AS 接收 TNG Verifier 转发来的可信证据，并对其进行深度的验证和解析。这包括：
    *   **证据格式和签名验证**：确保证据的完整性和来源可信。
    *   **平台完整性度量验证**：将证据中包含的硬件和软件度量值与预先定义的“可信基线”（Trusted Baseline）进行比对，确认环境未被非法修改。
    *   **策略符合性检查**：根据定义的策略（Policy），判断远程环境是否满足特定的安全要求。

只有当 Attestation Service 返回验证成功的结果时，TNG Verifier 才会确信对端是可信的，并允许建立安全的通信通道。在该场景中，Verifier 就是一个“审查官”，它将对端提供的“身份证”交给 AS 这个“权威认证机构”去鉴定真伪，并根据验证结果决定是否信任对方。

> [!TIP]
> 关于 Verifier 的配置字段及示例，请参考参数手册中的 [Verifier 部分](configuration_zh.md#verify)。

## 加密协议与安全性

TNG 采用了先进的加密协议来实现通信安全，通过结合远程证明和隐私保护机制，实现传输层或会话层加密。目前主要支持两种核心加密协议，以适应不同的应用场景和安全需求：RATS-TLS 和 OHTTP。

### RATS-TLS

**原理**：在标准的 TLS 1.3 协议握手过程中，融入了远程证明机制传递远程证明证据材料。只有当远程证明验证成功，证明对端的运行环境是真实且可信的时候，TLS 会话才会被正式建立或维持。这意味着攻击者即使能劫持网络，也无法在不可信的环境中伪装成合法的 TNG 实例进行通信。TNG 会将远程证明的验证结果与 TLS 会话生命周期绑定，如果环境被判定为不可信，连接建立过程将立即终止。

**适用场景**：
*   **任意 TCP 流量**：TNG 的设计使其能够透明地处理任意基于 TCP 协议的应用层流量。这意味着无论是 HTTP、数据库连接（如 MySQL、PostgreSQL）、RPC 协议还是任何自定义的 TCP 协议，TNG 都可以通过 RATS-TLS 进行安全保护。
*   **使用 4 层负载均衡器**：由于 RATS-TLS 运行在 TCP 协议之上，它与传统的 TCP/IP 栈兼容性良好。这意味着在部署 TNG 时，你可以继续使用现有的 4 层负载均衡器（例如 LVS、NAT 模式的负载均衡器或云服务提供商的 TCP/UDP 负载均衡器）。

> [!TIP]
> RATS-TLS 是 TNG 的默认通信协议。相关配置见参数手册的 [远程证明](configuration_zh.md#远程证明) 章节。

### OHTTP (Oblivious HTTP)

**原理**：OHTTP 能够将客户的 HTTP 请求和响应进行加密传输。如果与 OHTTP Relay 服务配合使用，使其转发加密的 TNG 请求，可以达到模糊请求来源，从而实现更强的用户隐私保护效果。关于 OHTTP 的介绍请参考 [RFC 9458 文档](https://www.ietf.org/rfc/rfc9458.html)。

**适用场景**：
*   **无状态 HTTP 请求**：OHTTP 的设计天然支持无状态的 HTTP 请求。每次请求都是独立的，不依赖于先前的会话信息。这非常适合 RESTful API 调用、静态资源获取等场景。
*   **使用 7 层负载均衡**：TNG 将在会话层对 HTTP 进行消息级加密，且密文仍然为 HTTP 消息格式，因此加密后的 TNG 流量可以与现有的 7 层负载均衡器（例如 Nginx、HAProxy、应用网关等）无缝集成。此外，TNG 还提供了一组自定义参数配置，能够适配业务现有的 7 层负载均衡器流量分发和路由规则，从而允许 TNG 的安全通道在不改变现有 L7 基础设施的情况下工作。

> [!TIP]
> 关于 OHTTP 的详细配置说明及限制，请参考参数手册中的 [OHTTP 章节](configuration_zh.md#ohttp)。
