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
| > 2.5.0 | Remote attestation now uses a pluggable provider layer. Wire formats for messages carrying evidence and attestation tokens are extended with optional provider fields in a backward-compatible way. Configuration parsing approach has changed significantly but relies on defaults to preserve compatibility with existing format. The `as_is_grpc` boolean configuration flag has been replaced by `as_type: "grpc"`, existing configs using `as_is_grpc` must be updated. |
| > 2.6.0 | **Breaking change**: The default value of `rats_tls.multiplex` has been changed from `true` to `false`. Previously, when `rats_tls` was specified without explicitly setting `multiplex`, HTTP/2 CONNECT tunneling was used by default to multiplex multiple TCP streams over a single rats-TLS connection. Now, each downstream connection creates an independent TLS session by default, achieving higher per-stream throughput. If you relied on the previous multiplex behavior, you must now explicitly set `"rats_tls": { "multiplex": true }` in your configuration. This change was made because H2 multiplexing is limited by the TLS encryption capacity of a single CPU core and does not scale well for high-bandwidth scenarios, while independent TLS connections can parallelize across multiple cores. |
| > 2.6.0 | **Breaking change**: OHTTP HPKE Auth mode for client attestation. When the server is configured with a `verify` block, the client can embed an X25519 public key in its attestation token. The client uses HPKE Auth encapsulation (sender authenticated), and the server verifies the client identity via HPKE Auth decapsulation. This is in addition to the existing Base Mode — both modes coexist and are auto-detected based on the presence of client key material in the attestation token. |
| > 2.6.0 | **Breaking change**: `EndpointFilter` semantics have changed. (1) `domain: "*"` now only matches domain-name endpoints, not IP addresses. Previously it matched any host string including IPs. Use `ip`/`ip_cidr` fields for IP matching, or omit all host fields to match all endpoint types. (2) The default value of `port` has changed from `80` to "any port" — when `port` is not specified, the rule matches any port. Existing configs that relied on the default port 80 should explicitly add `"port": 80`. |

> **Note on JSON configuration compatibility**: In general, older version JSON configuration files can still be parsed and recognized by newer versions of TNG. However, the actual behavior may differ due to changes in defaults, renamed fields, or modified semantics. Always review the version compatibility notes below before upgrading, and test your configuration in a staging environment.
