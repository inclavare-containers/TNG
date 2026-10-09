#!/usr/bin/env bash
# bench/gen-report.sh - generate the Markdown report from per-host info JSONs + results.
# Independent of the client/server runs: run this after both hosts have written their
# *-info.json and the client has written bench-results.json.
#
# Single-run mode (one binary, three result scenarios A/B/C):
#   bash bench/gen-report.sh <server-info.json> <client-info.json> <results.json> [output.md]
# Compare mode (baseline vs experimental; see bench/.perf-iteration-state.md conventions):
#   bash bench/gen-report.sh --compare \
#     <base-server-info> <base-client-info> <base-results> \
#     <exp-server-info> <exp-client-info> <exp-results> <output.md>
set -euo pipefail

MODE=single
if [ "${1:-}" = "--compare" ]; then
    MODE=compare; shift
fi
if [ "$MODE" = "compare" ]; then
    if [ $# -ne 7 ]; then
        echo "usage: gen-report.sh --compare <base-server-info> <base-client-info> <base-results> <exp-server-info> <exp-client-info> <exp-results> <out.md>" >&2
        exit 1
    fi
else
    if [ $# -lt 3 ] || [ $# -gt 4 ]; then
        echo "usage: gen-report.sh [--compare] <server-info.json> <client-info.json> <results.json> [out.md]" >&2
        exit 1
    fi
    [ $# -eq 3 ] && set -- "$@" ./bench-report.md
fi

python3 - "$MODE" "$@" <<'PY'
import json, sys

mode = sys.argv[1]
if mode == "compare":
    bsrv_p, bcli_p, bres_p, esrv_p, ecli_p, eres_p, out_path = sys.argv[2:9]
else:
    srv_p, cli_p, res_p, out_path = sys.argv[2:6]

def load(p):
    try: return json.load(open(p))
    except Exception as e: return {}

# Merge tool metadata: nginx/wrk each live on one side; iperf3/stunnel on both (same image).
def merged_tools(srv, cli):
    tools = {}
    for name in ("iperf3", "nginx", "wrk", "stunnel", "haproxy"):
        t = srv.get("tools", {}).get(name) or cli.get("tools", {}).get(name)
        if t: tools[name] = t
    return tools

IPERF_WL = ["iperf3+raw", "iperf3+stunnel", "iperf3+haproxy", "iperf3+rats-tls", "iperf3+rats-tls+mux"]
HTTP_B_WL = ["http+raw", "http+stunnel", "http+haproxy",
             "http+rats-tls", "http+rats-tls+mux", "http+ohttp"]
HTTP_C_WL = ["http-shortconn+" + w.split("+", 1)[1] for w in HTTP_B_WL]
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
# TNG workloads get a labeled (baseline) row + a bolded (experimental) row in
# compare mode; the reference baselines (raw/stunnel/haproxy) appear once with
# baseline values, unlabeled.
TNG_MARKS = ("rats-tls", "rats-tls+mux", "ohttp")

def lbl(w): return w.split("+", 1)[1] if "+" in w else w
def num(v):
    try: return float(v)
    except Exception: return None
def row(cells): return "| " + " | ".join(str(c) for c in cells) + " |"

def keys_of(res, wls):
    ks = set()
    for w in wls:
        for k in res.get(w, {}): ks.add(k)
    try: return sorted(ks, key=lambda x: int(x))
    except Exception: return sorted(ks)

def has_data(res, wls):
    return any(res.get(w) for w in wls)

# Direction-aware "better" sign: throughput/RPS/success are better when higher;
# every latency and resource metric is better when lower.
HIGHER_BETTER = {"throughput", "rps", "success_pct"}
FLAT_BAND_PCT = 1.0  # within this band the experimental value counts as flat (still ✅)

def metric_cells(m, metrics, raw_m, annotate, base_m=None):
    """Format one workload row's metric cells. annotate=True adds the vs-raw
    percent change (the raw row itself passes False). base_m (compare-mode
    experimental rows) appends a direction-aware ✅/⚠️ vs the baseline value."""
    r = []
    for (mk, hdr, fmt, has_raw) in metrics:
        v = m.get(mk)
        if v is None or v == "" or (isinstance(v, str) and v in ("N/A", "-")):
            r.append("-"); continue
        vn = num(v)
        if vn is None: r.append("-"); continue
        cell = fmt % vn
        if annotate and has_raw:
            rv = num(raw_m.get(mk))
            if rv is not None and rv != 0:
                pct = (vn - rv) / rv * 100.0
                cell = "%s (%+.0f%%)" % (cell, pct)
        if base_m is not None:
            bv = num(base_m.get(mk))
            if bv is not None and bv != 0:
                sign = 1 if mk in HIGHER_BETTER else -1
                better_pct = (vn - bv) / abs(bv) * 100.0 * sign
                cell += "✅" if better_pct >= -FLAT_BAND_PCT else "⚠️"
        r.append(cell)
    return r

# --- single-mode result table -------------------------------------------------
def merged_table(res, wls, metrics, axis):
    cols = [axis, "Workload"] + [m[1] for m in metrics]
    out = [row(cols), row(["---"] * len(cols))]
    for k in keys_of(res, wls):
        raw_m = res.get(wls[0], {}).get(str(k), {})
        for w in wls:
            m = res.get(w, {}).get(str(k), {})
            r = [k, lbl(w)] + metric_cells(m, metrics, raw_m, annotate=(w != wls[0]))
            out.append(row(r))
    return out

# --- compare-mode result table ------------------------------------------------
def compare_merged_table(res_b, res_e, wls, metrics, axis):
    cols = [axis, "Workload"] + [m[1] for m in metrics]
    out = [row(cols), row(["---"] * len(cols))]
    ks = set()
    for res in (res_b, res_e):
        for k in keys_of(res, wls): ks.add(k)
    try: ks = sorted(ks, key=lambda x: int(x))
    except Exception: ks = sorted(ks)
    for k in ks:
        raw_b = res_b.get(wls[0], {}).get(str(k), {})
        for w in wls:
            # Reference rows show the baseline only, unlabeled. TNG rows show a
            # "(baseline)" row and, directly below it, a bolded "(experimental)"
            # row; both rows carry the vs-raw annotation against the same
            # displayed raw row so the pair reads against one reference.
            mb = res_b.get(w, {}).get(str(k), {})
            if mb:
                name = lbl(w) + "(baseline)" if lbl(w) in TNG_MARKS else lbl(w)
                out.append(row([k, name] + metric_cells(mb, metrics, raw_b, annotate=(w != wls[0]))))
            if lbl(w) not in TNG_MARKS:
                continue
            me = res_e.get(w, {}).get(str(k), {})
            if me:
                cells = [k, lbl(w) + "(experimental)"] + metric_cells(me, metrics, raw_b, annotate=True, base_m=mb)
                out.append(row(["**%s**" % c for c in cells]))
    return out

# --- info JSON -> (item, value) row lists -------------------------------------
def env_rows(srv, cli):
    rows = []
    def host_block(side, h):
        if not h: return
        rows.append(("%s host" % side, "%s (IP %s)" % (h.get("host", ""), h.get("ip", ""))))
        rows.append(("%s kernel" % side, h.get("uname", "")))
        rows.append(("%s CPU" % side, "%s (%s vCPU)" % (h.get("cpu_model", ""), h.get("cpu_count", ""))))
        rows.append(("%s memory" % side, h.get("mem", "")))
    host_block("Client", cli)
    host_block("Server", srv)
    rows.append(("TNG", "%s (git %s)" % (cli.get("tng_version") or srv.get("tng_version", ""),
                                         cli.get("tng_git") or srv.get("tng_git", ""))))
    rows.append(("Container runtime", cli.get("runtime") or srv.get("runtime", "")))
    rows.append(("Link", "eth0: client %s <-> server %s" % (cli.get("ip", ""), srv.get("ip", ""))))
    return rows

def cond_rows(srv, cli, res):
    p = cli.get("params", {}) or srv.get("params", {})
    rows = [("TNG ingress/egress mode", p.get("tng_mode", ""))]
    if p.get("ra_mode", "0") == "1":
        rows.append(("Remote attestation", "enabled (no_ra=false)"))
        rows.append(("Attest (egress/server)", "aa_type=%s, aa_addr=%s" % (p.get("attest_aa_type", ""), p.get("attest_aa_addr", ""))))
        rows.append(("Verify (ingress/client)", "as_type=%s, attestation_policy=%s" % (p.get("verify_as_type", ""), p.get("verify_attestation_policy", ""))))
    else:
        rows.append(("Remote attestation", "disabled (no_ra=true)"))
    rows.append(("Load containers", "--network host"))
    rows.append(("iperf3 streams", p.get("iperf_streams", "")))
    rows.append(("iperf3 duration / rounds / len", "%ss / %s / %s bytes" % (p.get("iperf_duration", ""), p.get("iperf_rounds", ""), p.get("iperf_len", ""))))
    rows.append(("wrk connections", p.get("wrk_conns", "")))
    rows.append(("wrk duration / rounds / threads", "%ss / %s / %s" % (p.get("wrk_duration", ""), p.get("wrk_rounds", ""), p.get("wrk_threads", ""))))
    rows.append(("HTTP body size", "%s KiB" % p.get("http_body_kb", "")))
    scens = []
    if any(k.startswith("http+") for k in res): scens.append("keep-alive (B)")
    if any(k.startswith("http-shortconn+") for k in res): scens.append("no keep-alive (C)")
    rows.append(("HTTP scenarios measured", " + ".join(scens) if scens else "none"))
    rows.append(("Result per point", "median of N rounds"))
    return rows

def tool_rows(tools):
    rows = []
    for name in ("iperf3", "nginx", "wrk", "stunnel", "haproxy"):
        t = tools.get(name, {})
        fields = [t.get("image", ""), t.get("source", ""), t.get("version", ""), t.get("digest", "")]
        rows.append((name, fields))
    return rows

def tool_cell(fields):
    return "; ".join([f for f in fields if f]) or "-"

def value_table(rows):
    out = ["| Item | Value |", "| --- | --- |"]
    for item, value in rows:
        out.append(row([item, value]))
    return out

def diff_table(brows, erows):
    """Rows whose values differ; identical entries are omitted entirely."""
    emap = dict(erows)
    brows_ = dict(brows)
    order = [item for item, _ in brows] + [item for item, _ in erows if item not in brows_]
    out = []
    for item in order:
        bv = brows_.get(item)
        ev = emap.get(item)
        if isinstance(bv, list) or isinstance(ev, list):
            bs = tool_cell(bv) if bv else "-"
            es = tool_cell(ev) if ev else "-"
        else:
            bs = bv if bv not in (None, "") else "-"
            es = ev if ev not in (None, "") else "-"
        if bs != es:
            out.append(row([item, bs, es]))
    return out

def diff_section(title, brows, erows, bhead, ehead):
    L.append(title)
    L.append("")
    rows = diff_table(brows, erows)
    if not rows:
        L.append("No differences.")
        L.append("")
        return
    L.append("| Item | %s | %s |" % (bhead, ehead))
    L.append("| --- | --- | --- |")
    L.extend(rows)
    L.append("")

METH_BODY = [
    "Two hosts (server/P and client/D) reach each other over eth0. The server runs iperf3, nginx, and stunnel backends plus one TNG egress process (five `mapping` entries on ports 40001-40005); the client runs one TNG ingress process (five `mapping` entries on 50001-50005) plus stunnel clients. All load tools run in `--network host` containers pulled mirror-first; TNG runs as a host binary.",
    "",
    "iperf3 sweeps parallel streams (`-P`); HTTP (wrk) sweeps connections (`-c`), each for a fixed duration. The HTTP matrix is swept twice per run: keep-alive (Scenario B, persistent connections) and no keep-alive (Scenario C, wrk sends `Connection: close`, so every request pays a fresh TCP+TLS handshake). Each `(workload, stream/conn)` point runs N rounds and records the median of each metric. wrk runs with `--latency` so p50/p90/p99 come from the latency distribution; p95 comes from a wrk Lua done() callback (latency:percentile(95)) since wrk --latency omits the 95th percentile. The mean is wrk's Thread Stats average; the success rate is (completed requests - non-2xx) / (completed + socket errors).",
    "",
    "The Server CPU % and Server Mem (MiB) columns are sampled on the server host during the steady-state round via `pidstat -u -r -p <PIDs> 1 <duration>`, taking the Average row, with the SAME method for every tunnel type for a fair comparison: for TNG workloads the tng egress process (by its listen port, all threads summed by pidstat); for the haproxy baseline the haproxy-srv master plus all workers (pgrep, summed across processes); for the stunnel baseline the stunnel-srv process. CPU % is summed across the component's processes (100 = one logical core); RSS is summed (KiB) and reported in MiB. Client-side proxy, bench scripts, curl, the backend, NLB, OS cache, and other processes are NOT counted. raw baselines have no tunnel component, shown as `-`. Every numeric metric on a non-raw row is annotated with its percent change versus the raw baseline at the same concurrency.",
]

HTTP_SCENARIOS = [
    ("### Scenario B - HTTP / wrk ({body} KiB body, keep-alive)", HTTP_B_WL),
    ("### Scenario C - HTTP / wrk ({body} KiB body, no keep-alive)", HTTP_C_WL),
]

L = []
if mode == "compare":
    bsrv = load(bsrv_p); bcli = load(bcli_p)
    esrv = load(esrv_p); ecli = load(ecli_p)
    try: bres = json.load(open(bres_p))
    except Exception: bres = {}
    try: eres = json.load(open(eres_p))
    except Exception: eres = {}

    L.append("# TNG Two-Host Benchmark Comparison Report")
    L.append("")
    diff_section("## 1. Test Environment",
                 env_rows(bsrv, bcli), env_rows(esrv, ecli), "Baseline", "Experimental")
    diff_section("## 2. Test Conditions",
                 cond_rows(bsrv, bcli, bres), cond_rows(esrv, ecli, eres), "Baseline", "Experimental")
    diff_section("## 3. Test Tool Versions",
                 tool_rows(merged_tools(bsrv, bcli)), tool_rows(merged_tools(esrv, ecli)),
                 "Baseline", "Experimental")
    L.append("## 4. Test Methodology")
    L.append("")
    L.extend(METH_BODY)
    L.append("")
    L.append("The two runs are compared row by row, not by delta columns. The reference baselines (raw, stunnel, haproxy) appear once with the baseline values; differences in the reference baselines are not the subject. Each TNG workload (rats-tls, rats-tls+mux, ohttp) appears as two adjacent rows labeled with their run: the upper row `(baseline)` carries the baseline values, the lower row `(experimental)` carries the experimental values with every cell bolded (markdown has no row-level bold). Both rows carry the vs-raw percent-change annotation against the baseline run's raw row at the same concurrency, so the pair reads against one visible reference. Every experimental value ends with a direction-aware marker: ✅ when it is better than, or within ±1% of, the baseline value of the same metric; ⚠️ when worse. Better-direction follows the metric's semantics: throughput, RPS, and success rate are better when higher; latency, CPU, and memory are better when lower.")
    L.append("")
    L.append("## 5. Results")
    L.append("")
    L.append("### Scenario A - iperf3 (TCP throughput)")
    L.append("")
    if not (has_data(bres, IPERF_WL) or has_data(eres, IPERF_WL)):
        L.append("Not measured in this run.")
    else:
        L.extend(compare_merged_table(bres, eres, IPERF_WL, IPERF_M, "Streams"))
    L.append("")
    body_b = (bcli.get("params", {}) or bsrv.get("params", {})).get("http_body_kb", "64")
    body_e = (ecli.get("params", {}) or esrv.get("params", {})).get("http_body_kb", "64")
    body = body_b if body_b else body_e
    for tmpl, wls in HTTP_SCENARIOS:
        L.append(tmpl.format(body=body))
        L.append("")
        if not (has_data(bres, wls) or has_data(eres, wls)):
            L.append("Not measured in this run.")
        else:
            L.extend(compare_merged_table(bres, eres, wls, HTTP_M, "Conns"))
        L.append("")
else:
    srv = load(srv_p); cli = load(cli_p)
    try: res = json.load(open(res_p))
    except Exception: res = {}
    tools = merged_tools(srv, cli)
    p = cli.get("params", {}) or srv.get("params", {})

    L.append("# TNG Two-Host Benchmark Report")
    L.append("")
    L.append("## 1. Test Environment")
    L.append("")
    L.extend(value_table(env_rows(srv, cli)))
    L.append("")
    L.append("## 2. Test Conditions")
    L.append("")
    L.extend(value_table(cond_rows(srv, cli, res)))
    L.append("")
    L.append("## 3. Test Tool Versions")
    L.append("")
    L.append("| Tool | Image (resolved) | Source | Version | Digest |")
    L.append("| --- | --- | --- | --- | --- |")
    for name, fields in tool_rows(tools):
        L.append("| %s | %s | %s | %s | %s |" % (name, fields[0], fields[1], fields[2], fields[3]))
    L.append("")
    L.append("## 4. Test Methodology")
    L.append("")
    L.extend(METH_BODY)
    L.append("")
    L.append("## 5. Results")
    L.append("")
    L.append("### Scenario A - iperf3 (TCP throughput)")
    L.append("")
    if not has_data(res, IPERF_WL):
        L.append("Not measured in this run.")
    else:
        L.extend(merged_table(res, IPERF_WL, IPERF_M, "Streams"))
    L.append("")
    for tmpl, wls in HTTP_SCENARIOS:
        L.append(tmpl.format(body=p.get("http_body_kb", "64")))
        L.append("")
        if not has_data(res, wls):
            L.append("Not measured in this run.")
        else:
            L.extend(merged_table(res, wls, HTTP_M, "Conns"))
        L.append("")
    L.append("Note: vs-raw percent change is in parentheses after each non-raw value, measured against the raw baseline of the same scenario. For throughput/RPS a negative value means lower than raw; for latency a positive value means slower than raw. At high concurrency the raw baseline's mean/p90/p99 are skewed by tail-latency spikes, so TNG rows can show large negative changes there, meaning TNG is more stable than a saturated raw server.")
    L.append("")

open(out_path, "w").write("\n".join(L))
print(out_path)
PY
