# 版本兼容性

尽管我们在研发过程中尽量保持对旧版本行为的兼容，但有些情况下仍不可避免地存在兼容性变更。建议在 client 侧和 server 侧部署相同的最新稳定版本。

不同版本之间的兼容性说明如下：

| 兼容版本范围 | 说明 |
| --- | --- |
| >= 1.0.0, < 2.0.0 | 这些版本使用 Envoy 作为数据面。 |
| >= 2.0.0, <= 2.2.4 | 从 2.0.0 开始，TNG 转向基于 [rustls](https://github.com/rustls/rustls) 和 [hyper](https://github.com/hyperium/hyper) 实现的数据面。 |
| 2.2.5 | 从该版本开始，TNG 使用 OHTTP 替代之前的 rats-tls over HTTP CONNECT 协议组合，并引入护照模型支持。 |
| >= 2.2.6 | 从该版本开始，对 OHTTP 协议做了调整，解决 2.2.5 在 HTTP 路由场景下的设计问题。 |
| > 2.5.0 | 远程证明改用可插拔的 provider 层。携带证据和证明 token 的消息线格式以向后兼容的方式扩展了可选的 provider 字段。配置解析方式变化较大，但依靠默认值保持与既有格式的兼容。`as_is_grpc` 布尔配置项被替换为 `as_type: "grpc"`，使用 `as_is_grpc` 的既有配置必须更新。 |
| > 2.6.0 | **破坏性变更**：`rats_tls.multiplex` 的默认值从 `true` 改为 `false`。此前，当指定 `rats_tls` 但未显式设置 `multiplex` 时，默认使用 HTTP/2 CONNECT 隧道在单条 rats-TLS 连接上复用多个 TCP 流。现在，默认每个下游连接创建独立的 TLS 会话，以获得更高的单流吞吐量。如果你依赖之前的复用行为，必须在配置中显式设置 `"rats_tls": { "multiplex": true }`。这一变更的原因是：H2 复用的带宽受限于单核 CPU 的 TLS 加密能力，在高带宽场景下无法有效扩展，而独立的 TLS 连接可以在多个 CPU 核心上并行加解密。 |
| > 2.6.0 | **破坏性变更**：OHTTP HPKE Auth 模式用于客户端远程度量。当服务端配置了 `verify` 块时，客户端可以在其远程度量 token 中嵌入 X25519 公钥。客户端使用 HPKE Auth 封装（发送者认证），服务端通过 HPKE Auth 解封装验证客户端身份。这与现有的 Base Mode 共存，并根据 attestation token 中是否存在客户端密钥材料自动检测。 |
| > 2.6.0 | **破坏性变更**：`EndpointFilter` 的语义发生变化。（1）`domain: "*"` 现在只匹配域名端点，不再匹配 IP 地址。旧版本中它会匹配任何主机名字符串（包括 IP）。请使用 `ip`/`ip_cidr` 字段匹配 IP，或不指定任何主机字段以匹配所有端点类型。（2）`port` 的默认值从 `80` 改为"任意端口"——当不指定 `port` 时，规则匹配任何端口。之前依赖默认端口 80 的配置需要显式添加 `"port": 80`。 |
| > 2.9.2 | **破坏性变更**：移除 `tng tools ohttp dump --attest-request` 标志。它接收一个裸的 background-check challenge token（`backgroundcheck:<token>`），而该 token 通过工具无法实际获取。改用 `tng tools ohttp dump --verify '<VerifyArgs json>'`，它构建 AS 转换器、通过 `converter.get_nonce()` 生成 challenge token、拉取带 `attestation_info` 的密钥配置并就地验证。 |
| > 2.11.0 | **破坏性变更**：当 `trusted_certs_paths` 非空时，pinned 的证书现在就是 Attestation Token 验证的完整信任根集合，不再向 AS 的 `/certificate` 发现端点获取证书；`as_addr` 仍用于证据评估。此前同时设置 `trusted_certs_paths` 和 `as_addr` 时，从 AS 获取的证书会被静默合并进信任根。token 链仅依赖发现证书才验证通过的配置，现在必须显式 pin 该信任根。这一变更使显式信任根具有权威性，并支持未实现 `/certificate` 的主线 Trustee。 |
| > 2.12.0 | **破坏性变更**：Python SDK 现在要求 Python 3.10 或更高版本。该版本无法安装在 Python 3.8 或 3.9 上；在这些解释器上不加版本号执行 `pip install tng-sdk` 会解析到仍然兼容的最新旧版本，而不是报错。若要看到 `Requires-Python` 错误，请显式固定版本。上游 `urllib3`、`requests`、`anyio`、`pytest` 的修复版本均要求 Python 3.10 或更高版本。 |
| > 2.12.0 | **破坏性变更**：移除 `transparency_log` attestation policy 的 `staticReferenceMeasurements` 字段。设置了该字段的配置不再解析。请改用 `modules` 条目钉住这些度量（`com.alibabacloud.ai.model.<model-id>`、`com.alibabacloud.container.image.<repo>`）。 |
| > 2.12.0 | **破坏性变更**：移除顶层 `transparency_log` 内置证明策略类型，改为 `modules` 策略中的 `transparency_log` 条目。把 `attestation_policy.type` 设为 `"transparency_log"` 的配置不再解析。请把旧取值包进 `{"type": "modules", "modules": [{"type": "transparency_log", "value": <旧取值>}]}`；需要旧平台检查时再加 `tdx` 条目。 |
| > 2.12.0 | **破坏性变更**：`transparency_log` 配置若同时携带非空 `reference_values` 列表，将不再加载。该列表此前仅在同时设置 `staticReferenceMeasurements` 时才会被读取，而该字段已由上一条移除。`modules` 策略（包括带 `transparency_log` 条目的策略）在加载期拒绝非空列表。迁移时请删除该列表。 |
| > 2.12.0 | **破坏性变更**：`modules` 度量条目与 `transparency_log` 条目现在共用一份度量提取规则。三处检查更严。`tdx.kernel` 拒绝 RTMR 索引不是 2 或缺少 SHA-384 摘要的 `td_payload` 事件。`tdx.uki` 拒绝单个启动应用事件携带多个不同的 SHA-384 摘要。`container.image` 不再匹配没有 `EV_EVENT_TAG` 事件类型的 AAEL 事件；真实事件日志都带该类型，所以只影响构造的证据。接受不是 32 MiB 的 `td_payload` blob 属于放宽，不构成兼容性破坏。 |

> **JSON 配置兼容性说明**：一般来说，旧版本的 JSON 配置文件在新版本中仍然能够被识别和解析，但实际行为可能因默认值变更、字段重命名或语义修改而不同。升级前请务必查阅下方的版本兼容性说明，并在测试环境中验证你的配置。
