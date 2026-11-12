# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `modules` policies accept multiple digests for one container image repository: the same `com.alibabacloud.container.image.<repo>` type may appear more than once in one group, and the digests reported by the evidence must equal the configured digest set exactly, so an extra or a missing digest fails the entry. Existing single-digest configurations behave as before.
- A `transparency_log` entry also compares container image digest sets: the logged manifest may contain a `container.image.<repo>` type once per digest, the evidence digest set must equal the manifest's set, and `publishedMeasurements` still lists each type once.

## [2.13.0] - 2026-11-12

### Added

- Configuration files accept JSONC: `//` and `/* */` comments, trailing commas in objects and arrays, and a leading UTF-8 BOM. Strict JSON remains valid, and the Go SDK's `Config.FromJSON` accepts the same syntax. Configurations that use the new syntax do not load on older TNG releases.
- `docs/protocols.md` / `docs/protocols_zh.md`: developer-facing reference for the tunnel protocols and their remote-attestation handshake, covering the ohttp tunnel's outer request routing, key-config distribution, request encapsulation, and the background-check and passport attestation flows for both directions, with sequence diagrams in a formal RFC 9334-style notation.
- RATS-TLS chapter in `docs/protocols.md` / `docs/protocols_zh.md`: the standard-TLS-1.3 handshake with RA material carried in the self-signed DICE certificate, the four direction combinations, multiplexed versus non-multiplexed data planes, the freshness and session-resumption model, and handshake failure behavior, in the same notation as the ohttp chapter.
- `trusted-network-gateway-<version>-1.el7.x86_64.rpm` release asset built on a glibc 2.17 (manylinux2014) baseline: it installs on any RPM-based distro with glibc 2.17 or newer, including AnolisOS 7.9, alongside the existing an8 package.
- OHTTP `aead_suites` policy on ingress and egress: a per-endpoint, ordered allowlist of HPKE AEAD suites (`aes128_gcm`, `aes256_gcm`, `chacha20_poly1305`). On the egress it sets both the advertised suites and the decapsulation allowlist, and a disallowed suite is rejected with HTTP 422 so a TNG ingress refetches its key config. On the ingress it also sets the client preference order, which takes precedence over the server's advertised order. Unset keeps the previous behavior; the egress default now advertises AES-256-GCM as well, and an unset ingress still selects the first advertised suite.
- `modules` builtin attestation policy: a modular list of verification rules that replaces the fixed policy types. Each entry defines one typed check over a part of the evidence, and the expected value is written directly in the generated verification rule: TDX platform posture (`tdx`), standard NVIDIA per-GPU appraisal (`nvidia`), the guest-reported Alibaba AAEL GPU attestation event (`com.alibabacloud.gpu`), guest firmware, kernel and UKI boot measurements (`tdx.td-shim`/`tdx.ovmf`, `tdx.kernel`, `tdx.uki`), container images (`com.alibabacloud.container.image.<repo>`), and models (`com.alibabacloud.ai.model.<model-id>`). The unprefixed `container.image.<repo>` and `ai.model.<model-id>` spellings are permanent aliases. Entries of one AR4SI dimension must all pass within a group; each dimension passes when one of the groups carrying entries of it passes; hardware depends on the TDX platform every entry's evidence comes from; an empty list asserts nothing (hardware stays non-affirming); a measurement missing from the evidence or differing from the expected value makes the appraisal non-affirming (fail-closed). Measurement entries control the `executables` trust dimension, except `rootfs.cc` which controls `file_system`, and posture entries control `hardware`, so a failure in one leaves the other dimensions at their own result. Unknown types, duplicate types within a group (canonical and alias spellings collide), a `container.image.<repo>` whose repo is not a single repository segment, and malformed values are rejected at load.
- `docs/attestation_modules.md` / `docs/attestation_modules_zh.md`: configuration reference for the `modules` attestation policy type: JSON shapes, group semantics, per-module field tables, dimension attribution, fail-closed conventions, and the migration mapping from the removed policy types.
- `tng tools policy export`: renders the Rego a builtin AS loads, either from a full TNG config (one file per builtin `verify`, named by its JSON path) or from a bare `attestation_policy` value. All policy types are supported; a `modules` policy with a `rekor-v1` `transparency_log` entry fetches from the log at export time, while an `artifact-server` entry is rendered offline.
- `rootfs.cc` measurement for the confidential-container root filesystem: `modules` policies accept it as an inline `com.alibabacloud.rootfs.cc` entry, with `rootfs.cc` as a permanent alias, pinning the dm-verity hash tree root hash, and a `transparency_log` entry can publish `rootfs.cc` in `publishedMeasurements` / `fallbackPublishedMeasurements`. TNG extracts the hash from the `td_payload_info` platform config flags event recorded in RTMR1 and fails closed when there is no such event, when one is recorded outside RTMR1, when none carries a `verity-root` table, or when the extracted root hashes differ. The measurement gates the `file_system` trust dimension.

### Changed

- Egress logs a downstream that resets, closes, or never speaks before the protocol exchange completes at debug instead of error, for both rats-tls and OHTTP egress; the access-log `accepted only` line follows the same level. For OHTTP this covers probes and other connections that end without dialing a backend, including key-config API requests, while OHTTP decode failures keep their own error/warn lines. A rats-tls session that completes the handshake but dials no backend still logs the access-log line at error.
- The ohttp tunnel's keep-alive throughput rises at every measured concurrency (RA, 64 KiB body, alternating two-host A/B: +3..+14% RPS at c=1..32, +2..+3% at c=64..128, egress CPU per request down 6..23%), and no-keep-alive rises up to +9% at c<=32 with a small disclosed regression (-3..-4%) at c=64..128; the egress backend leg no longer relays through the per-request duplex pipe and dials the backend directly.
- `modules` policies accept a `transparency_log` entry that keeps the trusted measurement values in a release manifest recorded in a transparency log, instead of writing the digests into the policy. With a `rekor-v1` primary, TNG fetches and checks the log entry when the policy loads; with an `artifact-server` primary, it resolves the entry at appraisal. The optional fallback is used only when the primary returns `fail`. The entry controls the dimensions of its published measurement types (`executables` for the boot, image, and model measurements, `file_system` for `rootfs.cc`); platform posture stays a separate `tdx` entry, so a policy with only `transparency_log` entries makes `hardware` depend on TDX recognition alone. `transparency_log` may repeat within one group: several entries must all match, and separate groups are alternatives. `publishedMeasurements` is required and accepts `tdx.td-shim`, `tdx.kernel`, `rootfs.cc`, and any single-segment `container.image.<repo>`; write the container image and `rootfs.cc` types exactly as the transparency log records them.
- Policies whose verification rules do not consume reference values now reject a non-empty `reference_values` list at load instead of silently ignoring it: `trust_all`, `hardware_only` (including the `default` alias), `hardware_only_strict`, and `modules` (including a policy whose entries include `transparency_log`). An empty list remains accepted, and `inline` and `path` continue to accept reference values.
- The builtin AS features (`builtin-as-*`) now enable `crypto-rustcrypto`. Every builtin AS build includes the RustCrypto verification path, so the non-crypto transparency rejection branch and its error variant are gone.
- Linux binary release tarballs are now built against the glibc 2.17 baseline, so they run on distributions from 2014 onward instead of requiring glibc 2.29.
- Pages hosting the TNG JavaScript SDK no longer need cross-origin isolation: the `Cross-Origin-Opener-Policy`/`Cross-Origin-Embedder-Policy` response headers are no longer required, since the SDK does not use `SharedArrayBuffer`.
- The JavaScript SDK is now built with the same 1.89.0 stable toolchain as the rest of the repo; the `nightly-2025-07-07` toolchain is now only needed for `make create-tarball`.
- The Python SDK now requires Python 3.10 or newer. This release cannot be installed on Python 3.8 or 3.9; an unpinned `pip install tng-sdk` on those interpreters resolves to the newest older release, and pinning this version fails the `Requires-Python` check.
- `tng tools` writes its logs to stderr instead of stdout, so command output (PEM, JSON, Rego) can be redirected or piped cleanly. `--log-file` and `--log-error-file` still take precedence.
- `modules` measurement entries and the `transparency_log` entry now share one measurement extraction rule. `tdx.kernel` requires every matching `td_payload` event to be recorded in RTMR1 (register index 2) and to carry a SHA-384 digest, and all matching events must report the same digest. `tdx.uki` requires the same for every `EV_EFI_BOOT_SERVICES_APPLICATION` event. `container.image` extraction requires the `EV_EVENT_TAG` event type. The `transparency_log` entry no longer requires the `td_payload` blob to be 32 MiB.

### Removed

- `hardware_with_reference_values` and `hardware_strict_with_reference_values` builtin attestation policies: they appraised against trustee's default-policy text with no known adopters. Boot measurement baselines are now pinned inline with `modules` entries (`tdx.td-shim`/`tdx.ovmf`, `tdx.kernel`, `tdx.uki`), plus the `tdx` posture entry for the strict variant. Breaking for configurations that used these types.
- `hardware_strict_with_measurements` builtin attestation policy (added in v2.12.0, no known adopters): replaced by a `modules` policy with `ai.model.<model-id>` and `container.image.<repo>` entries and the `tdx` posture entry, pinning the baselines inline instead of a separate `reference_values` list. Breaking for configurations that used this type.
- The top-level `transparency_log` builtin attestation policy type: it is now a `transparency_log` entry inside a `modules` policy, so a configuration that sets `attestation_policy.type` to `"transparency_log"` no longer parses. Add a `tdx` entry when the old platform checks are wanted; a policy with only the transparency entry makes `hardware` depend on TDX recognition alone. Breaking for configurations that used this type.
- `staticReferenceMeasurements` transparency_log policy field (added in v2.12.0, no known adopters): removed. Configurations that set it no longer parse. Pin those baselines with `modules` measurement entries instead (`com.alibabacloud.ai.model.<model-id>`, `com.alibabacloud.container.image.<repo>`).

### Fixed

- A TNG verifier now accepts both the pre-draft-04 and the draft-04 EAR token claim layouts, so a token issued by an upstream Trustee AS that migrated to draft-04 ([confidential-containers/trustee#1614](https://github.com/confidential-containers/trustee/pull/1614)) no longer fails with a missing `runtime_data_claims` field. The builtin AS's pre-draft-04 tokens keep verifying unchanged.
- Python wheels tagged manylinux_2_17 now bundle a tng binary that actually runs on glibc 2.17; previously it required glibc 2.29, so installs on systems between 2.17 and 2.28 broke at runtime.
- `/status/egress/{id}/` advertises only the configured protocol's subtree (`ohttp` or `rats_tls`); previously a rats_tls egress advertised an `ohttp` node whose every path 404s.
- The `transparency_log` entry no longer silently drops a published measurement that cannot be extracted from the evidence: a manifest is built only when every configured published measurement is extractable, so an incomplete published type set fails the entry instead of comparing a shortened manifest.
- A failing `tng tools` command logs its error once instead of twice; the remaining line still carries the `tools command failed` context and the full cause chain.

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

[Unreleased]: https://github.com/inclavare-containers/TNG/compare/v2.13.0...HEAD
[2.13.0]: https://github.com/inclavare-containers/TNG/compare/v2.12.0...v2.13.0
[2.12.0]: https://github.com/inclavare-containers/TNG/compare/v2.11.0...v2.12.0
