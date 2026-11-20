# TNG overview figure

[中文](README_zh.md) · [Documentation](../README.md)

[English figure](tng-overview.svg) · [Chinese figure](tng-overview_zh.svg)

The figure shows a deployment pattern across caller and confidential-service trust domains. Replicas indicate a topology supported by suitable routing and key configuration, without promising a node count or automatic orchestration. VM and Pod/sidecar labels describe deployment placement, not an Operator or a managed Kubernetes integration.

## Reading the figure

Solid cyan lines mark encrypted traffic between TNG tunnel endpoints. Gray lines mark local application links; their protection depends on deployment. A load balancer routes the encrypted traffic, with L4/L7 suitability depending on the protocol. Dashed purple lines mark attestation relationships, not a packet-level sequence. Verification may run within TNG or through an external service; the attester collects evidence through an agent inside the TEE.

The drawing uses an application with a local Ingress as its main example. A browser's WASM SDK supplies the client-side TNG capability itself and does not require that local daemon. Either side may be an attester or verifier according to the selected model. Callers can also run inside a TEE.

OHTTP key sharing applies to OHTTP replicas. TCP RATS-TLS, HTTP OHTTP and UDP over QUIC are separate paths, selected by configuration and available binary features. The figure does not imply that UDP is carried through a TCP TLS connection or that every protocol uses shared cluster keys. OHTTP relay privacy requires a suitable separate relay and trust model.

## Capability references

| Figure element | Reference |
| --- | --- |
| Tunnel entry/exit and attestation roles | [Architecture](../architecture.md) · [Remote attestation](../remote_attestation.md) |
| Port mapping, proxies, transparent interception and UDP/QUIC | [Configuration](../configuration.md) |
| RATS-TLS and OHTTP | [Protocols](../protocols.md) |
| `tng exec` | [Hook guide](../../tng-hook/README.md) |
| Browser, Python and Go | [WASM](../../tng-wasm/README.md) · [Python](../../tng-python/README.md) · [Go](../../tng-go/README.md) |
| L4/L7 routing and replicated services | [Load balancing](../using-with-slb.md) · [Scenarios](../scenarios/README.md) |
| OHTTP key sharing and rotation | [Peer-shared keys](../peer_shared.md) |

## Editing

Edit the SVG source directly and update both languages together. Keep labels as text, use system fonts and retain the self-contained light surface for readability in both GitHub themes. Do not add scripts, remote resources, embedded bitmaps or `foreignObject` elements. Keep each SVG below 150 KB.

Render both files at roughly 830 px wide and inspect text, arrow endpoints, trust boundaries and clipping. Check the smaller README view as well as the full image. A successful XML parse alone does not validate the drawing's meaning or readability.
