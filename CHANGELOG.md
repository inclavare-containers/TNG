# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Per-phase ohttp request latency histograms on the REST status tree: `/status/ingress/{id}/ohttp/latency` and `/status/egress/{id}/ohttp/latency` report count / mean / p50 / p99 / max in microseconds for every segment of a request (outer POST wait, HPKE open, backend send/reply, seal pumps, write-back scheduling), accumulated since process start. Timing is on by default; set `TNG_OHTTP_LATENCY_TIMING=off` before startup to disable it.
- `docs/protocols.md` / `docs/protocols_zh.md`: developer-facing reference for the tunnel protocols and their remote-attestation handshake, covering the ohttp tunnel's outer request routing, key-config distribution, request encapsulation, and the background-check and passport attestation flows for both directions, with sequence diagrams in a formal RFC 9334-style notation.
- RATS-TLS chapter in `docs/protocols.md` / `docs/protocols_zh.md`: the standard-TLS-1.3 handshake with RA material carried in the self-signed DICE certificate, the four direction combinations, multiplexed versus non-multiplexed data planes, the freshness and session-resumption model, and handshake failure behavior, in the same notation as the ohttp chapter.
- `trusted-network-gateway-<version>-1.el7.x86_64.rpm` release asset built on a glibc 2.17 (manylinux2014) baseline: it installs on any RPM-based distro with glibc 2.17 or newer, including AnolisOS 7.9, alongside the existing an8 package.

### Changed

- ohttp tunnels carry more requests under remote attestation: keep-alive request rates improve 2.8-14.1% at every measured concurrency (1-128); short-connection (no keep-alive) rates improve 2.9-9.3% at concurrency 1-32 with p99 up to 12.3% lower, while saturated short connections (c=64-128) run 2.8-3.6% slower for up to 11.2% lower p99.
- Linux binary release tarballs are now built against the glibc 2.17 baseline, so they run on distributions from 2014 onward instead of requiring glibc 2.29.

### Fixed

- Python wheels tagged manylinux_2_17 now bundle a tng binary that actually runs on glibc 2.17; previously it required glibc 2.29, so installs on systems between 2.17 and 2.28 broke at runtime.

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
