# Deployment scenarios

[中文](README_zh.md) · [Documentation](../README.md)

For a first local request without a TEE, use [getting started](../getting-started.md). These guides describe deployment topologies; replace their service addresses and configure evidence collection and verification for your environment.

| Goal | Integration and protocol | Deployment and attestation | Guide |
| --- | --- | --- | --- |
| Connect to one confidential node transparently | Netfilter; RATS-TLS | Client gateway and TEE server; AA and verifier setup | [Single node, transparent proxy](01-netfilter-single/README.md) |
| Connect through an application HTTP proxy | HTTP proxy + server netfilter; RATS-TLS | Client proxy and TEE server; AA and verifier setup | [Single node, HTTP proxy](02-http-proxy-single/README.md) |
| Reach replicated confidential services through HTTP routing | OHTTP | Multiple service nodes; shared-key and attestation configuration | [Business cluster](03-business-cluster/README.md) |
| Verify both ends of service-to-service communication | Transparent interception; mutual RATS-TLS | TEE nodes configured to attest and verify | [Mutual attestation between nodes](04-mesh-two-way-ra/README.md) |
| Encrypt vLLM inference requests behind an HTTP gateway | OHTTP; CLI and SDK access methods | Nginx and replicated inference services; configure AA and verification | [vLLM OHTTP cluster](05-vllm-ohttp-cluster/README.md) |
| Protect vLLM prefill/decode traffic | OHTTP for inference requests; RATS-TLS non-multiplexed for TCP KV-cache transfer | Separate prefill/decode nodes; attestation on the protected paths | [vLLM prefill/decode separation](06-vllm-pd-separation/README.md) |
| Separate request source visibility from content visibility | OHTTP with a public relay | Caller, relay and confidential provider; privacy depends on role separation and trust assumptions | [OHTTP relay privacy](08-ohttp-relay-privacy/README.md) |

Check each guide for exact configuration and prerequisites. RATS-TLS multiplexing is a separate choice; [connection models and load balancing](../using-with-slb.md) explain its consequences. OHTTP [peer-shared keys](../peer_shared.md) allow a replica to decrypt requests encrypted with the cluster's key. They do not provide automatic service orchestration or unlimited scale.

## Related references

- [Remote attestation](../remote_attestation.md): agents, built-in or external verification, policies and reference values.
- [Configuration](../configuration.md): port mapping, HTTP/SOCKS5 proxies, netfilter and UDP modes.
- [Tunnel protocols](../protocols.md): handshake details and security behavior.
- [Performance](../performance.md): measured configurations and methodology.
