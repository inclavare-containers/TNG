# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `multiplex_max_streams_per_connection` ingress option: shards the multiplexed rats-tls tunnel pool across additional egress connections once a connection reaches its stream cap.
- `/status/ingress/{id}/rats_tls/pool` status endpoint exposing the live mux tunnel pool state (shards, cooldowns, overflow).
- `key.join_timeout` option (default 300 s): bounds the startup join of the initial peer list; a peer still unreachable past the deadline fails startup naming that peer and the last join error, instead of retrying forever.
- `key.preboot_timeout` option (default 60 s): bounds the preboot cluster key-set synchronization; if peers are visible but none answers the key-set query within the deadline, startup fails, instead of retrying forever.

### Changed

- The multiplexed rats-tls pool gates new shard handshakes at capacity and cools down failed shards, instead of stacking concurrent handshakes when a single connection saturates.
- ohttp request throughput: HPKE runs on the aws-lc ohttp backend, request and response seals are fused into the body streams, the backend connection is reused per outer ohttp connection, and relay buffers were widened.
- Per-connection memory and CPU: forwarding buffers no longer memset a megabyte per connection, and the periodic attest cert fetch and rats-tls cert resolution no longer block the async runtime.

### Fixed

- ohttp tunnels now recover after an upstream send failure: pooled backend connections are evicted instead of being reused against a dead upstream.
- The hook log collector no longer drops queued log datagrams under burst; they are drained with a raw recv.
- The serf key watcher no longer parks forever on a dropped serf handle; it re-checks the handle on every iteration.
