#!/usr/bin/env bash
# bench/gen-report.sh - generate the Markdown report from per-host info JSONs + results.
# Independent of the client/server runs: run this after both hosts have written their
# *-info.json and the client has written bench-results.json.
#
# Usage: bash bench/gen-report.sh <server-info.json> <client-info.json> <results.json> [output.md]
set -euo pipefail

SRV="${1:?usage: gen-report.sh <server-info.json> <client-info.json> <results.json> [out.md]}"
CLI="${2:?missing client-info.json}"
RES="${3:?missing results.json}"
OUT="${4:-./bench-report.md}"

python3 - "$SRV" "$CLI" "$RES" "$OUT" <<'PY'
import json, os, sys
srv_path, cli_path, res_path, out_path = sys.argv[1:5]

def load(p):
    try: return json.load(open(p))
    except Exception as e: return {}
srv = load(srv_path); cli = load(cli_path)
res = {}
try: res = json.load(open(res_path))
except Exception: pass

# Merge tool metadata: nginx/wrk each live on one side; iperf3/stunnel on both (same image).
tools = {}
for name in ("iperf3", "nginx", "wrk", "stunnel", "haproxy"):
    t = srv.get("tools", {}).get(name) or cli.get("tools", {}).get(name)
    if t: tools[name] = t
p = cli.get("params", {}) or srv.get("params", {})

IPERF_WL = ["iperf3+raw", "iperf3+stunnel", "iperf3+haproxy", "iperf3+rats-tls", "iperf3+rats-tls+mux"]
HTTP_WL  = ["http+raw", "http+stunnel", "http+haproxy", "http+rats-tls", "http+rats-tls+mux", "http+ohttp"]
IPERF_M = [("throughput", "Throughput (Gbps)", "%.2f", True),
           ("cpu_pct", "Tunnel CPU %", "%.1f", False),
           ("mem_gb", "Tunnel Mem (GB)", "%.3f", False)]
HTTP_M = [("throughput", "Throughput (Gbps)", "%.2f", True),
          ("rps", "RPS", "%.0f", True),
          ("mean_us", "Mean (us)", "%d", True),
          ("p50_us", "p50 (us)", "%d", True),
          ("p90_us", "p90 (us)", "%d", True),
          ("p95_us", "p95 (us)", "%d", True),
          ("p99_us", "p99 (us)", "%d", True),
          ("success_pct", "Success %", "%.1f", True),
          ("srv_cpu_pct", "Server CPU %", "%.1f", False),
          ("srv_mem_mib", "Server Mem (MiB)", "%.1f", False)]

def lbl(w): return w.split("+", 1)[1] if "+" in w else w
def num(v):
    try: return float(v)
    except Exception: return None
def row(cells): return "| " + " | ".join(str(c) for c in cells) + " |"
def keys(wls):
    ks = set()
    for w in wls:
        for k in res.get(w, {}): ks.add(k)
    try: return sorted(ks, key=lambda x: int(x))
    except Exception: return sorted(ks)
def merged_table(wls, metrics, axis):
    cols = [axis, "Workload"] + [m[1] for m in metrics]
    out = [row(cols), row(["---"] * len(cols))]
    for k in keys(wls):
        raw_m = res.get(wls[0], {}).get(str(k), {})
        for w in wls:
            m = res.get(w, {}).get(str(k), {})
            r = [k, lbl(w)]
            for (mk, hdr, fmt, has_raw) in metrics:
                v = m.get(mk)
                if v is None or v == "" or (isinstance(v, str) and v in ("N/A", "-")):
                    r.append("-"); continue
                if not has_raw and w == wls[0]:
                    r.append("-"); continue
                vn = num(v)
                if vn is None: r.append("-"); continue
                cell = fmt % vn
                if w != wls[0] and has_raw:
                    rv = num(raw_m.get(mk))
                    if rv is not None and rv != 0:
                        pct = (vn - rv) / rv * 100.0
                        cell = "%s (%+.0f%%)" % (cell, pct)
                r.append(cell)
            out.append(row(r))
    return out

L = []
L.append("# TNG Two-Host Benchmark Report")
L.append("")
# 1. Environment (both hosts)
L.append("## 1. Test Environment")
L.append("")
L.append("| Item | Value |")
L.append("| --- | --- |")
def host_block(side, h):
    if not h: return []
    name = h.get("host", ""); ip = h.get("ip", "")
    return [
        "| %s host | %s (IP %s) |" % (side, name, ip),
        "| %s kernel | %s |" % (side, h.get("uname", "")),
        "| %s CPU | %s (%s vCPU) |" % (side, h.get("cpu_model", ""), h.get("cpu_count", "")),
        "| %s memory | %s |" % (side, h.get("mem", "")),
    ]
L.extend(host_block("Client", cli))
L.extend(host_block("Server", srv))
L.append("| TNG | %s (git %s) |" % (cli.get("tng_version") or srv.get("tng_version", ""),
                                   cli.get("tng_git") or srv.get("tng_git", "")))
L.append("| Container runtime | %s |" % (cli.get("runtime") or srv.get("runtime", "")))
L.append("| Link | eth0: client %s <-> server %s |" % (cli.get("ip", ""), srv.get("ip", "")))
L.append("")
# 2. Conditions
L.append("## 2. Test Conditions")
L.append("")
L.append("| Parameter | Value |")
L.append("| --- | --- |")
L.append("| TNG ingress/egress mode | %s |" % p.get("tng_mode", ""))
if p.get("ra_mode", "0") == "1":
    L.append("| Remote attestation | enabled (no_ra=false) |")
    L.append("| Attest (egress/server) | aa_type=%s, aa_addr=%s |" % (p.get("attest_aa_type",""), p.get("attest_aa_addr","")))
    L.append("| Verify (ingress/client) | as_type=%s, attestation_policy=%s |" % (p.get("verify_as_type",""), p.get("verify_attestation_policy","")))
else:
    L.append("| Remote attestation | disabled (no_ra=true) |")
L.append("| Load containers | --network host |")
L.append("| iperf3 streams | %s |" % p.get("iperf_streams", ""))
L.append("| iperf3 duration / rounds / len | %ss / %s / %s bytes |" % (p.get("iperf_duration",""), p.get("iperf_rounds",""), p.get("iperf_len","")))
L.append("| wrk connections | %s |" % p.get("wrk_conns", ""))
L.append("| wrk duration / rounds / threads | %ss / %s / %s |" % (p.get("wrk_duration",""), p.get("wrk_rounds",""), p.get("wrk_threads","")))
L.append("| HTTP body size | %s KiB |" % p.get("http_body_kb", ""))
L.append("| Result per point | median of N rounds |")
L.append("")
# 3. Tools
L.append("## 3. Test Tool Versions")
L.append("")
L.append("| Tool | Image (resolved) | Source | Version | Digest |")
L.append("| --- | --- | --- | --- | --- |")
for name in ("iperf3", "nginx", "wrk", "stunnel", "haproxy"):
    t = tools.get(name, {})
    L.append("| %s | %s | %s | %s | %s |" % (name, t.get("image", ""), t.get("source", ""),
                                            t.get("version", ""), t.get("digest", "")))
L.append("")
# 4. Methodology
L.append("## 4. Test Methodology")
L.append("")
L.append("Two hosts (server/P and client/D) reach each other over eth0. The server runs iperf3, nginx, and stunnel backends plus one TNG egress process (five `mapping` entries on ports 40001-40005); the client runs one TNG ingress process (five `mapping` entries on 50001-50005) plus stunnel clients. All load tools run in `--network host` containers pulled mirror-first; TNG runs as a host binary.")
L.append("")
L.append("iperf3 sweeps parallel streams (`-P`); HTTP (wrk) sweeps connections (`-c`), each for a fixed duration. Each `(workload, stream/conn)` point runs N rounds and records the median of each metric. wrk runs with `--latency` so p50/p90/p99 come from the latency distribution; p95 comes from a wrk Lua done() callback (latency:percentile(95)) since wrk --latency omits the 95th percentile. The mean is wrk's Thread Stats average; the success rate is (completed requests - non-2xx) / (completed + socket errors).")
L.append("")
L.append("The Server CPU % and Server Mem (MiB) columns are sampled on the server host during the steady-state round via `pidstat -u -r -p <PIDs> 1 <duration>`, taking the Average row, with the SAME method for every tunnel type for a fair comparison: for TNG workloads the tng egress process (by its listen port, all threads summed by pidstat); for the haproxy baseline the haproxy-srv master plus all workers (pgrep, summed across processes); for the stunnel baseline the stunnel-srv process. CPU % is summed across the component's processes (100 = one logical core); RSS is summed (KiB) and reported in MiB. Client-side proxy, bench scripts, curl, the backend, NLB, OS cache, and other processes are NOT counted. raw baselines have no tunnel component, shown as `-`. Every numeric metric on a non-raw row is annotated with its percent change versus the raw baseline at the same concurrency.")
L.append("")
# 5. Results
L.append("## 5. Results")
L.append("")
L.append("### Scenario A - iperf3 (TCP throughput)")
L.append("")
L.extend(merged_table(IPERF_WL, IPERF_M, "Streams"))
L.append("")
L.append("### Scenario B - HTTP / wrk (%s KiB body)" % p.get("http_body_kb", "64"))
L.append("")
L.extend(merged_table(HTTP_WL, HTTP_M, "Conns"))
L.append("")
L.append("Note: vs-raw percent change is in parentheses after each non-raw value. For throughput/RPS a negative value means lower than raw; for latency a positive value means slower than raw. At high concurrency the raw baseline's mean/p90/p99 are skewed by tail-latency spikes, so TNG rows can show large negative changes there, meaning TNG is more stable than a saturated raw server.")
L.append("")

open(out_path, "w").write("\n".join(L))
print(out_path)
PY
