# TNG documentation

[中文](README_zh.md) · [Project home](../README.md)

## Start here

Run the [local quick start](getting-started.md) to send your first request. It uses a RATS-TLS non-multiplexed tunnel with attestation disabled. Then follow [remote attestation](remote_attestation.md) to collect and verify real TEE evidence.

The [architecture guide](architecture.md) explains Ingress, Egress and the attestation roles. The [scenario catalog](scenarios/README.md) helps you choose a deployment topology.

## Choose an integration

| Application | Entry point | Considerations |
| --- | --- | --- |
| A service with known ports | [Port mapping](configuration.md) · [Local example](getting-started.md) | Explicit local and remote tunnel addresses |
| An application with proxy support | [HTTP proxy scenario](scenarios/02-http-proxy-single/README.md) · [HTTP/SOCKS5 configuration](configuration.md) | Configure the application to use the proxy |
| An existing process | [`tng exec` and hook](../tng-hook/README.md) | Linux process interception; see platform and library requirements |
| A workload needing transparent interception | [Netfilter scenario](scenarios/01-netfilter-single/README.md) | Linux networking and the required privileges |
| A browser | [JavaScript/WASM SDK](../tng-wasm/README.md) · [Live demo](https://inclavare-containers.github.io/TNG/) | Client functionality runs in WebAssembly |
| Python HTTP or OpenAI clients | [Python SDK](../tng-python/README.md) · [Getting started](../tng-python/docs/getting-started.md) | Wrap an existing supported client |
| Go HTTP clients | [Go SDK](../tng-go/README.md) · [Getting started](../tng-go/docs/getting-started.md) | `http.RoundTripper`; requires a TNG binary |

## Deployment guides

- [Scenario catalog](scenarios/README.md): single nodes, OHTTP clusters, mutual attestation, vLLM and relay privacy.
- [L4 load balancing](using-with-slb.md): connection models and stickiness by protocol and capture mode.
- [Browser CORS](../tng-wasm/docs/cors.md): configuring cross-origin browser requests.

## Concepts and reference

| Topic | Document |
| --- | --- |
| Tunnel endpoints and trust roles | [Architecture](architecture.md) |
| Evidence collection, verification models and policies | [Remote attestation](remote_attestation.md) |
| Fields, capture modes, OHTTP, UDP/QUIC and observability | [Configuration reference](configuration.md) |
| Operator commands for certificates, envelopes and key synchronization | [CLI tools](tools.md) |
| Log destinations, formats and rolling | [Logging](log.md) |
| Changes requiring migration | [Version compatibility](version_compatibility.md) |
| Released and unreleased changes | [Changelog](../CHANGELOG.md) |

## Internals and contributing

| Task | Document |
| --- | --- |
| Build, package or run tests | [Developer guide](developer.md) |
| Understand RATS-TLS and OHTTP handshakes | [Tunnel protocols](protocols.md) |
| Understand OHTTP cluster key distribution and rotation | [Peer-shared keys](peer_shared.md) |
| Inspect measured performance | [Performance snapshot](performance.md) |
| Run or report benchmarks | [Benchmark harness](../bench/README.md) · [Reporting](../bench/reporting.md) |
| Edit or interpret the product figure | [Figure notes](assets/README.md) |

Integration tests share network namespaces and iptables rules. Follow the developer guide and run `make run-test` sequentially. Keep English and Chinese documentation in sync when contributing.
