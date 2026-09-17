# TNG Performance Optimization Guide

A reference for the iterative methodology to close the gap between TNG rats-tls and HAProxy (or another TLS proxy baseline) in short-connection and long-connection scenarios.

## Overview

TNG rats-tls has two layers of overhead vs a plain TLS proxy like HAProxy:
1. **TLS handshake layer**: rustls vs OpenSSL, tokio async vs HAProxy's event loop, per-connection setup. Affects both no_ra and RA.
2. **RA (remote attestation) layer**: TDX quote collection (AA) + builtin-AS verification. Only affects RA mode.

In short-connection mode (each request = new TCP+TLS), both layers are per-request. In long-connection mode (keep-alive), they are one-time per connection (amortized).

## Baseline gap (pre-optimization, 4-vCPU TDX, short-conn)

| Metric | rats-tls no_ra | rats-tls RA | HAProxy | raw |
|---|---|---|---|---|
| RPS @ c=1 | 277 | 35 | 661 | 3237 |
| RPS @ c=128 | 921 | 75 | 3894 | 30278 |
| p50 @ c=1 | 3.5ms | 28ms | 1.4ms | 0.3ms |
| p50 @ c=128 | 132ms | 1470ms | 32ms | — |

## Phase 0: Deploy + baseline

1. Build the latest tng: `cargo build --release -p tng`.
2. Deploy to both hosts: `scp target/release/tng root@<host>:/root/tng`.
3. Deploy bench scripts: `scp -r bench/ root@<host>:/root/`.
4. Run baseline (4 scenarios: no_ra long, no_ra short, RA long, RA short).
5. Record results as iteration 0 in `bench/.perf-iteration-state.md`.

## Phase 1: Automated measurement

The bench script (`bench/client.sh`) runs all workloads (iperf3 + http, rats-tls + baselines) and writes `bench-results.json`. The report generator (`bench/gen-report.sh`) produces the Markdown report.

For comparison between iterations, extract `http+rats-tls` and `http+haproxy` metrics from `bench-results.json` and compute the gap:

```
gap_pct = (1 - rats_tls_RPS / haproxy_RPS) * 100
```

Track at each concurrency level: RPS, p50, p99, CPU%, Mem, Success%.

## Phase 2: Profiling

### perf flamegraph

```bash
# On the client, while wrk is running (short-conn c=32):
perf record -p <tng_pid> -g --call-graph dwarf -F 99 -- sleep 10
perf script | flamegraph.pl > flamegraph-iter-N.svg
```

### pidstat (if perf unavailable)

```bash
pidstat -p <tng_pid> -urd 1 10
# -u: CPU, -r: memory, -d: I/O. 1s interval, 10 samples.
```

### eBPF/offcpu profiling (if available)

```bash
# off-CPU time (where the process waits):
perf record -p <tng_pid> -e sched:sched_switch -- sleep 10
```

### Hotspot areas (by priority)

1. **RA verification path** (`ra/common.rs:verity_pending_cert` → builtin-AS TDX quote verify): expected ~80% of RA overhead.
2. **TLS handshake** (rustls `connect`/`accept`, cert exchange): expected ~10-15%.
3. **Connection management** (tokio accept, connection setup, buffer alloc): expected ~5%.
4. **Memory allocation** (per-connection cert, TLS context, buffers): expected ~5%.

## Phase 3: Root-cause analysis

For each hotspot, answer:
1. **What is HAProxy doing faster?** (OpenSSL vs rustls? Multi-process vs tokio? No RA? Connection pooling?)
2. **What is the specific bottleneck?** (CPU compute? Lock contention? Memory allocation? System calls? Async scheduling?)
3. **What is the optimization space?** (Algorithm-level? Implementation-level? Architecture-level?)

## Phase 4: Optimization catalog

### Layer 1: RA verification (biggest leverage, targets RA-only gap)

| Optimization | Expected effect | Complexity | Status |
|---|---|---|--- |
| Shared CertVerifyCache (same cert → skip re-verify) | Eliminates repeated builtin-AS calls within TTL | Low | Done (shared cache) |
| 0-RTT session resumption (skip RA on resumed connections) | Resumed connections skip cert verification entirely | Medium | In progress (ticket fix) |
| Pre-generate TDX quote at AA startup | AA caches quote, no per-request quote generation | Low | To evaluate |
| Parallel RA verification (concurrent verifies) | Multiple verifications run in parallel, not serial | Medium | To evaluate |
| Async RA verification (don't block data plane) | Start forward + verify concurrently | High | Rejected (must verify before data) |

### Layer 2: TLS handshake (targets no_ra gap)

| Optimization | Expected effect | Complexity |
|---|---|---|
| Session resumption普及 (0-RTT for returning clients) | 1-RTT → 0-RTT, skip cert exchange | Medium |
| rustls config tuning (reduce cert chain steps) | Fewer verification steps per handshake | Low |
| TLS ticket pre-issuance (server pre-generates tickets) | Faster ticket availability for resumption | Medium |
| Reduce cert size (smaller RA evidence in cert) | Less data to transmit per handshake | Medium |

### Layer 3: Connection management (targets remaining gap)

| Optimization | Expected effect | Complexity |
|---|---|---|
| Connection pool (reuse underlying TLS sessions) | Short-conn requests reuse pooled sessions | High |
| Buffer pool (pre-allocate per-connection buffers) | Eliminate per-connection malloc/free | Medium |
| tokio worker thread tuning | Match thread count to workload | Low |
| Reduce per-connection allocations (Arc, Box, etc.) | Less GC pressure, faster setup | Medium |

## Phase 5: Iteration loop

```
1. Run bench (no_ra + RA short-conn)
2. Generate comparison report
3. Check gap: rats-tls vs HAProxy at each concurrency
4. If gap < 10% at ALL levels → DONE
5. Profile (perf flamegraph)
6. Identify top hotspot
7. Apply ONE optimization
8. Rebuild + redeploy
9. Update bench/.perf-iteration-state.md
10. Go to 1
```

**Iteration discipline**: ONE optimization per iteration. No batch changes. Clean attribution.

## Success criteria

| Metric | Target |
|---|---|
| RA RPS / HAProxy RPS | >= 90% at c=1,8,32,128 |
| RA p50 / HAProxy p50 | <= 110% at c=1,8,32,128 |
| no_ra RPS / HAProxy RPS | >= 90% at c=1,8,32,128 |

## Machine access

- Server (TDX): `ssh` to the server host (4 vCPU, /dev/tdx_guest, AA via systemd)
- Client: `ssh` to the client host (4 vCPU)
- Controller: the repo worktree (cargo, bench scripts)
