# 版本兼容性

尽管我们在研发过程中尽量保持对旧版本行为的兼容，但有些情况下仍不可避免地存在兼容性变更。建议在 client 侧和 server 侧部署相同的最新稳定版本。

不同版本之间的兼容性说明如下：

| 兼容版本范围 | 说明 |
| --- | --- |
| >= 1.0.0, < 2.0.0 | 这些版本使用 Envoy 作为数据面。 |
| >= 2.0.0, <= 2.2.4 | 从 2.0.0 开始，TNG 转向基于 [rustls](https://github.com/rustls/rustls) 和 [hyper](https://github.com/hyperium/hyper) 实现的数据面。 |
| 2.2.5 | 从该版本开始，TNG 使用 OHTTP 替代之前的 rats-tls over HTTP CONNECT 协议组合，并引入护照模型支持。 |
| >= 2.2.6 | 从该版本开始，对 OHTTP 协议做了调整，解决 2.2.5 在 HTTP 路由场景下的设计问题。 |
