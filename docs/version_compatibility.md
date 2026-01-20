# Version Compatibility

[中文文档](version_compatibility_zh.md)

Although we try our best to maintain compatibility with the behavior of older versions during development, in some cases, breaking compatibility changes are unavoidable. We recommend deploying the same latest stable version on both the client and server sides.

Compatibility notes between different versions are as follows:

| Compatible Version Range | Description |
| --- | --- |
| >= 1.0.0, < 2.0.0 | These versions use Envoy as the data plane. |
| >= 2.0.0, <= 2.2.4 | Starting from 2.0.0, TNG transitioned to a data plane based on [rustls](https://github.com/rustls/rustls) and [hyper](https://github.com/hyperium/hyper). |
| 2.2.5 | Starting from this version, TNG uses OHTTP instead of the previous rats-tls over HTTP CONNECT protocol combination and introduces Passport model support. |
| >= 2.2.6 | Starting from this version, adjustments have been made to the OHTTP protocol to resolve design issues in HTTP routing scenarios encountered in version 2.2.5. |
