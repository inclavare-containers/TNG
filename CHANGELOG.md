# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Configuration files accept JSONC: `//` and `/* */` comments, trailing commas in objects and arrays, and a leading UTF-8 BOM. Strict JSON remains valid, and the Go SDK's `Config.FromJSON` accepts the same syntax. Configurations that use the new syntax do not load on older TNG releases.
- `docs/protocols.md` / `docs/protocols_zh.md`: developer-facing reference for the tunnel protocols and their remote-attestation handshake, covering the ohttp tunnel's outer request routing, key-config distribution, request encapsulation, and the background-check and passport attestation flows for both directions, with sequence diagrams in a formal RFC 9334-style notation.
- RATS-TLS chapter in `docs/protocols.md` / `docs/protocols_zh.md`: the standard-TLS-1.3 handshake with RA material carried in the self-signed DICE certificate, the four direction combinations, multiplexed versus non-multiplexed data planes, the freshness and session-resumption model, and handshake failure behavior, in the same notation as the ohttp chapter.
- `trusted-network-gateway-<version>-1.el7.x86_64.rpm` release asset built on a glibc 2.17 (manylinux2014) baseline: it installs on any RPM-based distro with glibc 2.17 or newer, including AnolisOS 7.9, alongside the existing an8 package.
- OHTTP `aead_suites` policy on ingress and egress: a per-endpoint, ordered allowlist of HPKE AEAD suites (`aes128_gcm`, `aes256_gcm`, `chacha20_poly1305`). On the egress it sets both the advertised suites and the decapsulation allowlist, and a disallowed suite is rejected with HTTP 422 so a TNG ingress refetches its key config. On the ingress it also sets the client preference order, which takes precedence over the server's advertised order. Unset keeps the previous behavior; the egress default now advertises AES-256-GCM as well, and an unset ingress still selects the first advertised suite.
- `modules` builtin attestation policy: a modular list of verification rules superseding the fixed policy types. Each entry pins one typed check over a part of the evidence, and the pinned value is embedded as a literal in the generated verification rule: TDX platform posture (`tdx`), standard NVIDIA per-GPU appraisal (`nvidia`), the guest-reported Alibaba AAEL GPU attestation event (`com.alibabacloud.gpu`), guest firmware, kernel and UKI boot measurements (`tdx.td-shim`/`tdx.ovmf`, `tdx.kernel`, `tdx.uki`), container images (`com.alibabacloud.container.image.<repo>`), and models (`com.alibabacloud.ai.model.<model-id>`). The unprefixed `container.image.<repo>` and `ai.model.<model-id>` spellings are permanent aliases. Entries of one AR4SI dimension AND within a group; each dimension is OR-ed over the groups carrying entries of it; hardware depends on the TDX platform every entry's evidence comes from; an empty list asserts nothing (hardware stays non-affirming); a measurement missing from the evidence or differing from the pinned value makes the appraisal non-affirming (fail-closed). Measurement entries gate the `executables` trust dimension and posture entries gate `hardware`, so a failure in one leaves the other dimension at its own result. Unknown types, duplicate types within a group (canonical and alias spellings collide), and malformed values are rejected at load.
- `docs/attestation_modules.md` / `docs/attestation_modules_zh.md`: configuration reference for the `modules` attestation policy type: JSON shapes, group semantics, per-module field tables, dimension attribution, fail-closed conventions, and the migration mapping from the removed policy types.

### Changed

- Egress logs a downstream that resets or closes before the TLS handshake completes at debug instead of error; the access-log `accepted only` line is still emitted for such connections, now at debug, while a session that completes the handshake but dials no backend keeps logging it at error.
- The ohttp tunnel's keep-alive throughput rises at every measured concurrency (RA, 64 KiB body, alternating two-host A/B: +3..+14% RPS at c=1..32, +2..+3% at c=64..128, egress CPU per request down 6..23%), and no-keep-alive rises up to +9% at c<=32 with a small disclosed regression (-3..-4%) at c=64..128; the egress backend leg no longer relays through the per-request duplex pipe and dials the backend directly.
- Policies whose verification rules do not consume reference values now reject a non-empty `reference_values` list at load instead of silently ignoring it: `trust_all`, `hardware_only` (including the `default` alias), `hardware_only_strict`, and `modules`. An empty list remains accepted, and `inline`, `path`, and `transparency_log` continue to accept reference values.
- Linux binary release tarballs are now built against the glibc 2.17 baseline, so they run on distributions from 2014 onward instead of requiring glibc 2.29.
- Pages hosting the TNG JavaScript SDK no longer need cross-origin isolation: the `Cross-Origin-Opener-Policy`/`Cross-Origin-Embedder-Policy` response headers are no longer required, since the SDK does not use `SharedArrayBuffer`.
- The JavaScript SDK is now built with the same 1.89.0 stable toolchain as the rest of the repo; the `nightly-2025-07-07` toolchain is now only needed for `make create-tarball`.
- The Python SDK now requires Python 3.10 or newer. This release cannot be installed on Python 3.8 or 3.9; an unpinned `pip install tng-sdk` on those interpreters resolves to the newest older release, and pinning this version fails the `Requires-Python` check.

### Removed

- `hardware_with_reference_values` and `hardware_strict_with_reference_values` builtin attestation policies: they appraised against trustee's default-policy text with no known adopters. Boot measurement baselines are now pinned inline with `modules` entries (`tdx.td-shim`/`tdx.ovmf`, `tdx.kernel`, `tdx.uki`), plus the `tdx` posture entry for the strict variant. Breaking for configurations that used these types.
- `hardware_strict_with_measurements` builtin attestation policy (added in v2.12.0, no known adopters): replaced by a `modules` policy with `ai.model.<model-id>` and `container.image.<repo>` entries and the `tdx` posture entry, pinning the baselines inline instead of a separate `reference_values` list. Breaking for configurations that used this type.

### Fixed

- Python wheels tagged manylinux_2_17 now bundle a tng binary that actually runs on glibc 2.17; previously it required glibc 2.29, so installs on systems between 2.17 and 2.28 broke at runtime.
- `/status/egress/{id}/` advertises only the configured protocol's subtree (`ohttp` or `rats_tls`); previously a rats_tls egress advertised an `ohttp` node whose every path 404s.

## [2.12.0] - 2026-10-25

### Added

- `hardware_strict_with_measurements` builtin attestation policy: the strict hardware posture (TDX non-debug with an event log) plus an explicit measurement list appraised against registered reference values, for user-owned artifacts that need no transparency service. Supports the `"model"` and `"container.image.<repo>"` measurement types shared with `staticReferenceMeasurements`; malformed lists (empty, unsupported types, duplicates) are rejected at load.
- `staticReferenceMeasurements` transparency_log policy field: measurement types appraised against builtin-AS static reference values instead of the transparency log, for user-owned artifacts the transparency service does not publish. `"model"` checks every `pai/load-model` event against `measurement.model.<model-id>`; `"container.image.<repo>"` checks the pull-image digests of a repo-tail-named image against `measurement.container.image.<repo>`. The static checks AND-gate the measurement verification in both the rekor-v1 and artifact-server policy arms; unsupported types, duplicates, and overlap with published/fallback measurements are rejected at load.
- `multiplex_max_streams_per_connection` ingress option: shards the multiplexed rats-tls tunnel pool across additional egress connections once a connection reaches its stream cap.
- `/status/ingress/{id}/rats_tls/pool` status endpoint exposing the live mux tunnel pool state (shards, cooldowns, overflow).
- `key.join_timeout` option (default 300 s): bounds the startup join of the initial peer list; a peer still unreachable past the deadline fails startup naming that peer and the last join error, instead of retrying forever.
- `key.preboot_timeout` option (default 60 s): bounds the preboot cluster key-set synchronization; if peers are visible but none answers the key-set query within the deadline, startup fails, instead of retrying forever.

### Changed

- The multiplexed rats-tls pool gates new shard handshakes at capacity and cools down failed shards, instead of stacking concurrent handshakes when a single connection saturates.
- ohttp request throughput: HPKE runs on the aws-lc ohttp backend, request and response seals are fused into the body streams, the backend connection is reused per outer ohttp connection, and relay buffers were widened.
- Per-connection memory and CPU: forwarding buffers no longer memset a megabyte per connection, and the periodic attest cert fetch and rats-tls cert resolution no longer block the async runtime.
- When `trusted_certs_paths` is nonempty, the pinned certificates are now the complete set of trust anchors for Attestation Token verification and the AS `/certificate` discovery endpoint is no longer consulted; previously the certificates fetched from the AS were silently merged in. Explicit trust roots now also work against mainline Trustee, which does not implement `/certificate`.

### Fixed

- ohttp tunnels now recover after an upstream send failure: pooled backend connections are evicted instead of being reused against a dead upstream.
- The hook log collector no longer drops queued log datagrams under burst; they are drained with a raw recv.
- The serf key watcher no longer parks forever on a dropped serf handle; it re-checks the handle on every iteration.
- tng no longer signals readiness when a service fails before reporting ready (e.g. an ingress port is already occupied); the ready callback now fires only after every service is actually serving.
- Pinned PEM trust-root files now load every certificate in the bundle (e.g. leaf plus CA) instead of only the first section; empty or malformed bundles are rejected instead of silently producing a partial trust set.
- Attestation tokens whose JWK `x5c` chain uses standard Base64 encoding (per RFC 7517) now verify; previously only URL-safe Base64 was accepted, which rejected tokens from mainline Trustee.
- A measurement revoked by the transparency-log artifact server now denies attestation instead of being rescued by the rekor fallback: the append-only rekor entry of a revoked manifest still authenticates, so the previous behavior let the fallback bypass the revocation.
- Transparency-log resolve successes are cached per artifact-server URL and expire after 5 minutes, so a revocation published after a successful appraisal takes effect without a restart, and a cached success cannot satisfy a policy that points at a different artifact server.

[Unreleased]: https://github.com/inclavare-containers/TNG/compare/v2.12.0...HEAD
[2.12.0]: https://github.com/inclavare-containers/TNG/compare/v2.11.0...v2.12.0
