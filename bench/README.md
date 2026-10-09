# TNG Two-Host Benchmark

Measure real TNG tunnel performance between two hosts over eth0, with and without remote attestation (RA). Every run measures three scenarios: iperf3 TCP throughput, HTTP keep-alive, and HTTP no-keep-alive.

## Prerequisites

On **both** hosts:
- TNG release binary: `cargo build --release -p tng` (default features include `builtin-as-tdx-rust`).
- podman (or docker): `dnf install -y podman` if absent.
- `python3`, `openssl`.

On the **server (TEE) host** (for RA only):
- Attestation Agent: `dnf install -y attestation-agent libtdx-attest && systemctl start attestation-agent`.
- TDX hardware (`/dev/tdx_guest`).

## What a run measures

- **Scenario A:** iperf3 TCP throughput.
- **Scenario B:** HTTP / wrk, keep-alive. wrk maintains `-c` persistent TCP+TLS connections (HTTP/1.1 keep-alive). Each connection does one TLS handshake at start, then reuses it for all subsequent requests. **RA overhead is amortized** (one handshake per connection, not per request). This is the production case for long-lived connections (microservice-to-microservice, persistent API clients).
- **Scenario C:** HTTP / wrk, no keep-alive. wrk sends `Connection: close`, the server closes after each response, and wrk opens a new TCP+TLS connection for the next request. **Every request pays a full TLS handshake** (plus attestation+verification if RA is on). This isolates the cost of connection establishment: the production case for short-lived connections (API gateway, per-request load balancer, serverless).

Both HTTP scenarios are measured in every client invocation; there is no single-mode pin.

```bash
# Server (P host):
TNG_BIN=/root/tng bash bench/server.sh            # no RA
TNG_BIN=/root/tng RA_MODE=1 bash bench/server.sh  # with RA (builtin AS + hardware_only)

# Client (D host):
TNG_BIN=/root/tng bash bench/client.sh <SERVER_IP>            # no RA
TNG_BIN=/root/tng RA_MODE=1 bash bench/client.sh <SERVER_IP>  # with RA
```

## Report generation

Each run writes three JSON files: `server-info.json` and `client-info.json` (host environment and tool versions) and `bench-results.json` (the measured metrics; keep-alive workloads are keyed `http+...`, no-keep-alive `http-shortconn+...`). After copying `server-info.json` off the server host, generate the Markdown report:

```bash
# Single-run report (Scenarios A/B/C):
bash bench/gen-report.sh <server-info.json> <client-info.json> <bench-results.json> [output.md]

# Comparison report (baseline vs experimental):
bash bench/gen-report.sh --compare \
  <base-server-info.json> <base-client-info.json> <base-results.json> \
  <exp-server-info.json> <exp-client-info.json> <exp-results.json> <output.md>
```

The single report has one table per scenario (iperf3, HTTP keep-alive, HTTP no-keep-alive), with one row per workload and one column per metric. It documents its own sampling methodology in a note under each table, so this README does not repeat it. The comparison report shows only the environment, condition, and tool entries that differ between the two runs; in each scenario table the reference baselines (raw, stunnel, haproxy) appear once with the baseline values, and each TNG workload row appears twice, labeled with its run: `rats-tls(baseline)`, then the bolded `rats-tls(experimental)` row (markdown has no row-level bold); both rows carry the vs-raw annotation, and every experimental value ends with a direction-aware marker (✅ better than or within ±1% of baseline, ⚠️ worse; throughput/RPS/success higher is better, latency/CPU/memory lower is better). To read a row:

- **Throughput (Gbps):** payload bandwidth (iperf3) or HTTP bandwidth (wrk).
- **RPS:** wrk requests per second (HTTP only).
- **Mean / p50 / p90 / p95 / p99:** request latency percentiles in microseconds (HTTP only); p95 and p99 expose tail latency.
- **Success %:** share of requests completed without error (HTTP only).
- **Server CPU % / Mem:** CPU and memory of the server-side tunnel process during the run; `100` equals one logical core. raw baselines have no tunnel, shown as `-`.
- **Δ vs raw:** each non-raw value is followed by its percent change versus the raw baseline at the same concurrency. For throughput/RPS, negative means lower; for latency, positive means slower.

## Key environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `TNG_BIN` | `./target/release/tng` | Path to the tng binary. |
| `SERVER_IP` | — (required, client) | Server host IP. |
| `RA_MODE` | `0` | `1` = enable remote attestation (attest on server, verify via builtin AS + hardware_only on client). |
| `WRK_WARMUP` | `1` | `1` = run a 1-connection warmup before each measured point (primes TLS session ticket for 0-RTT resumption). |
| `IPERF_STREAMS` | `1,8,16,32,64,128` | iperf3 parallel stream counts. |
| `IPERF_DURATION` | `15` | Seconds per iperf3 round. |
| `IPERF_ROUNDS` | `3` | Rounds per point (median recorded). |
| `WRK_CONNS` | `1,8,16,32,64,128` | wrk connection counts, swept in both HTTP scenarios (keep-alive and no keep-alive). |
| `WRK_DURATION` | `15` | Seconds per wrk round. |
| `WRK_ROUNDS` | `3` | Rounds per point (median recorded). |
| `HTTP_BODY_KB` | `64` | HTTP response body size (KiB) served by nginx. |
| `TNG_GIT` | repo HEAD | Identity recorded in the info JSONs; set it when running the scripts from a deployed dir that is not a git checkout. |
| `BENCH_LABEL` | `bench-host` | Prefix for the per-run output directory. |
| `--output-dir DIR` | `bench/artifacts` | Parent directory for the per-run output directory. |

## Output layout

By default the run directory is written under `bench/artifacts/` (gitignored), so outputs from repeated runs stay in one place:

```
${BENCH_LABEL}-YYYYmmdd-HHMMSS/
  server-info.json     # server host env + tools (iperf3/nginx/stunnel/haproxy)
  client-info.json     # client host env + tools (iperf3/wrk/stunnel/haproxy) + params
  bench-results.json   # workload -> {streams|conns} -> metrics, median of N rounds
  configs/             # generated ingress.json / egress.json
  logs/                # tng launch log
  logs/raw/            # full raw output per round: <workload>-{s|c}<n>-r<i>.{json,txt}
```

## Workloads

| Scenario | Workloads | Baselines |
| --- | --- | --- |
| iperf3 (TCP throughput) | rats-tls, rats-tls+mux | raw, stunnel, haproxy |
| HTTP (wrk, 64 KiB body, keep-alive and no keep-alive) | rats-tls, rats-tls+mux, ohttp | raw, stunnel, haproxy |

All TNG paths use `mapping` mode. RA mode adds `attest` (server, via AA) + `verify` (client, builtin AS + hardware_only).

### Port matrix

Each TNG tunneled workload pairs an ingress port `5000X` on the client with an egress port `4000X` on the server; the egress forwards to a local backend on the server host.

| Workload | TNG transport | multiplex | Server port | Client port | Backend |
| --- | --- | --- | --- | --- | --- |
| iperf3+rats-tls | rats-tls | false | 40001 | 50001 | iperf3 :5201 |
| iperf3+rats-tls+mux | rats-tls | true | 40002 | 50002 | iperf3 :5201 |
| http+rats-tls | rats-tls | false | 40003 | 50003 | nginx :8080 |
| http+rats-tls+mux | rats-tls | true | 40004 | 50004 | nginx :8080 |
| http+ohttp | ohttp | n/a | 40005 | 50005 | nginx :8080 |

Baselines (no TNG): `iperf3+raw` / `http+raw` hit the backend directly; `iperf3+stunnel` / `http+stunnel` go through a stunnel TLS tunnel (OpenSSL) to isolate the cost of a generic TLS path; `http+haproxy` / `iperf3+haproxy` go through haproxy (TLS, thread-per-core event loop). The stunnel server ports are `:5210` (iperf3) and `:5211` (http); haproxy server ports are `:5213` (iperf3) and `:5212` (http).

## Container images

Pulled mirror-first (Aliyun mirror), falling back to the primary registry. The resolved source, version, and sha256 digest are recorded in `env.json` for reproducibility.

| Tool | Mirror (Aliyun) | Primary fallback |
| --- | --- | --- |
| iperf3 | `mirrors-ssl.aliyuncs.com/networkstatic/iperf3:latest` | `networkstatic/iperf3:latest` |
| nginx | `mirrors-ssl.aliyuncs.com/library/nginx:stable-alpine` | `lscr.io/linuxserver/nginx:latest` |
| wrk | `mirrors-ssl.aliyuncs.com/ghcr.io/william-yeh/wrk:latest` | `ghcr.io/william-yeh/wrk:latest` |
| stunnel | `mirrors-ssl.aliyuncs.com/dockurr/stunnel:latest` | `dockurr/stunnel:latest` |
| haproxy | `mirrors-ssl.aliyuncs.com/library/haproxy:latest` | `docker.io/library/haproxy:latest` |

The server pulls iperf3, nginx, stunnel, haproxy (backends); the client pulls iperf3, wrk, stunnel, haproxy (load generators + TLS baseline clients). A warning (not a failure) is emitted if iperf3 is older than 3.21.

## Makefile targets

```bash
make bench-host-server         # start server (no_ra)
make bench-host-client SERVER_IP=<P_IP>   # run client (no_ra)
make bench                    # single-host netns dev bench (unchanged)
make bench-multiplex          # same, with multiplex=true
```

For RA mode, use the env vars above with `bash bench/server.sh` / `bash bench/client.sh` directly.
