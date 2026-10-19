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
# Optional: --title HEADING replaces the default report title and demotes all
# internal headings one level, so several reports nest as sub-reports of one
# PR chapter (see render-pr-reports.sh). Optional: --fold SUMMARY emits the
# whole report inside one default-collapsed <details> block whose summary is
# the given compact line (the PR-comment presentation); the report carries no
# top-level title in that mode. Every report renders the full metric registry;
# metrics a dataset did not collect render '-'.
set -euo pipefail

MODE=single
ALLOW_UNVERIFIED=0
ALLOW_MIXED=0
TITLE=""
FOLD=""
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --compare) MODE=compare; shift ;;
        --allow-unverified) ALLOW_UNVERIFIED=1; shift ;;
        --allow-mixed-versions) ALLOW_MIXED=1; shift ;;
        --title) [ $# -ge 2 ] && [ -n "$2" ] || { echo "usage: --title requires a heading" >&2; exit 2; }; TITLE="$2"; shift 2 ;;
        --fold) [ $# -ge 2 ] && [ -n "$2" ] || { echo "usage: --fold requires a summary line" >&2; exit 2; }; FOLD="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done
if [ "$MODE" = compare ]; then
    [ $# -eq 7 ] || { echo "usage: $0 --compare [--allow-unverified] [--allow-mixed-versions] [--title HEADING] <base-server-info> <base-client-info> <base-results> <exp-server-info> <exp-client-info> <exp-results> <output.md>" >&2; exit 2; }
else
    [ $# -ge 3 ] && [ $# -le 4 ] || { echo "usage: $0 [--allow-unverified] [--allow-mixed-versions] <server-info> <client-info> <results> [output.md]" >&2; exit 2; }
    [ $# -eq 3 ] && set -- "$@" ./bench-report.md
fi

python3 - "$(dirname "$0")" "$ALLOW_UNVERIFIED" "$ALLOW_MIXED" "$TITLE" "$FOLD" "$MODE" "$@" <<'PY_REPORT'
import json, os, sys, tempfile
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv.pop(1))
ALLOW_UNVERIFIED = sys.argv.pop(1) == "1"
ALLOW_MIXED = sys.argv.pop(1) == "1"
TITLE = sys.argv.pop(1)
FOLD = sys.argv.pop(1)
from report_support import CLASSES, check_identity, classify, number

mode = sys.argv[1]
if mode == "compare":
    bsrv_p, bcli_p, bres_p, esrv_p, ecli_p, eres_p, out_path = sys.argv[2:9]
else:
    srv_p, cli_p, res_p, out_path = sys.argv[2:6]

def load(p):
    try:
        with open(p) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return data
    except (OSError, ValueError) as e:
        raise SystemExit(f"Invalid input {p}: {e}")

def validate_results(data, context):
    if not data or not any(data.values()):
        raise SystemExit(f"{context}: empty results; no measured workload")
    allowed = set(IPERF_WL + HTTP_B_WL + HTTP_C_WL)
    for workload, points in data.items():
        if workload not in allowed or not isinstance(points, dict):
            raise SystemExit(f"{context}: unsupported/malformed workload {workload!r}; extend the renderer rather than dropping it")
        for key, metrics in points.items():
            if not str(key).isdigit() or int(key) <= 0 or str(int(key)) != key or not isinstance(metrics, dict):
                raise SystemExit(f"{context}: invalid concurrency/metrics for {workload}: {key!r}")
            for name, value in metrics.items():
                n = number(value)
                if n is not None and (n < 0 or (name == 'success_pct' and n > 100)):
                    raise SystemExit(f"{context}: invalid {name} for {workload}, concurrency={key}: {value!r}")

IDENTITY_ISSUES = []
MIXED_NOTES = []
def validate_hosts(srv, cli, label):
    for side, meta in (("server", srv), ("client", cli)):
        IDENTITY_ISSUES.extend(check_identity(meta, f"{label} {side}"))
    fields = ("tng_git", "tng_version")
    differs = [f for f in fields if srv.get(f) != cli.get(f)]
    # Different architectures can yield different binaries from the same source.
    sb, cb = srv.get("tng_build") or {}, cli.get("tng_build") or {}
    sb = sb if isinstance(sb, dict) else {}
    cb = cb if isinstance(cb, dict) else {}
    differs += [f for f in ("dirty", "source_state_sha256") if sb.get(f) != cb.get(f)]
    if differs:
        note = f"{label}: ingress/egress identities differ ({', '.join(differs)})."
        if not ALLOW_MIXED:
            raise SystemExit(note + " Investigate, or explicitly use --allow-mixed-versions for an intentional compatibility run.")
        MIXED_NOTES.append(note)

def identity_banner():
    if IDENTITY_ISSUES and not ALLOW_UNVERIFIED:
        raise SystemExit("Unverified benchmark identity:\n- " + "\n- ".join(IDENTITY_ISSUES) + "\nUse record-build.py and deploy its manifest with the binary. --allow-unverified is only for explicitly preliminary historical reports.")
    if IDENTITY_ISSUES:
        L.extend(["> **PRELIMINARY / UNVERIFIED: not final reproducible performance evidence.**", ""])
        for issue in IDENTITY_ISSUES:
            L.append("- " + issue)
        L.append("")
        print("Warning: unverified historical/preliminary report", file=sys.stderr)
    for note in MIXED_NOTES:
        L.extend(["> **Intentional mixed-version run:** " + note, ""])

# Merge tool metadata: wrk lives only on the client; nginx and the rest on both
# (server backend + proxies, client-side nginx reference forwarders; same image).
def merged_tools(srv, cli):
    tools = {}
    for name in ("iperf3", "nginx", "wrk", "stunnel", "haproxy"):
        t = srv.get("tools", {}).get(name) or cli.get("tools", {}).get(name)
        if t: tools[name] = t
    return tools

IPERF_WL = ["iperf3+raw", "iperf3+stunnel", "iperf3+haproxy", "iperf3+nginx-stream", "iperf3+rats-tls", "iperf3+rats-tls+mux"]
HTTP_B_WL = ["http+raw", "http+stunnel", "http+haproxy", "http+nginx-stream", "http+nginx-http",
             "http+rats-tls", "http+rats-tls+mux", "http+ohttp"]
HTTP_C_WL = ["http-shortconn+" + w.split("+", 1)[1] for w in HTTP_B_WL]
# Display names for the nginx TLS-proxy references (keys stay the harness labels;
# "(TLS)" marks the listener the load generator reaches through the forwarder).
WORKLOAD_LABELS = {"nginx-stream": "nginx stream (TLS)", "nginx-http": "nginx http (TLS)"}
IPERF_M = [("throughput", "Throughput (Gbps)", "%.2f", True),
           ("cpu_pct", "Ingress CPU %", "%.1f", False),
           ("mem_gb", "Ingress Mem (GB)", "%.3f", False)]
HTTP_M = [("throughput", "Throughput (Gbps)", "%.2f", True),
          ("rps", "RPS", "%.0f", True),
          ("mean_us", "Mean (us)", "%d", True),
          ("p50_us", "p50 (us)", "%d", True),
          ("p90_us", "p90 (us)", "%d", True),
          ("p95_us", "p95 (us)", "%d", True),
          ("p99_us", "p99 (us)", "%d", True),
          ("success_pct", "Success %", "%.1f", True),
          ("cli_cpu_pct", "Ingress CPU %", "%.1f", False),
          ("srv_cpu_pct", "Egress CPU %", "%.1f", False),
          ("srv_mem_mib", "Egress Mem (MiB)", "%.1f", False)]
# TNG workloads get a labeled (baseline) row + a bolded (experimental) row in
# compare mode; the reference baselines (raw/stunnel/haproxy/nginx) appear once
# with baseline values, unlabeled.
TNG_MARKS = ("rats-tls", "rats-tls+mux", "ohttp")


def lbl(w):
    name = w.split("+", 1)[1] if "+" in w else w
    return WORKLOAD_LABELS.get(name, name)
def num(v): return number(v)
def visible_metrics(res_list, wls, metrics):
    """Every report renders the full registry: format identity between the
    PR-level report and ablation sub-reports is a hard requirement, so columns
    never adapt to what a particular dataset happens to carry. Uncollected
    cells render '-' and stay out of the classification counts."""
    return metrics
def row(cells):
    def escape(c):
        return str(c).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|").replace("\n", "<br>").replace("\r", "")
    return "| " + " | ".join(escape(c) for c in cells) + " |"

def fold(title, lines):
    return ["<details>", f"<summary>{title}</summary>", "", *lines, "", "</details>", ""]

def keys_of(res, wls):
    ks = set()
    for w in wls:
        for k in res.get(w, {}): ks.add(k)
    try: return sorted(ks, key=lambda x: int(x))
    except Exception: return sorted(ks)

def has_data(res, wls):
    return any(res.get(w) for w in wls)

def metric_cells(m, metrics, raw_m, annotate, base_m=None, structural_raw=False):
    """Format one workload row's metric cells. annotate=True adds the vs-raw
    percent change (the raw row itself passes False). base_m (compare-mode
    experimental rows) appends a five-class direction-aware marker vs the baseline value."""
    r = []
    for (mk, hdr, fmt, has_raw) in metrics:
        if structural_raw and not has_raw:
            r.append("-"); continue
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
            bv = base_m.get(mk)
            if bv is not None and num(bv) is not None:
                cls, _ = classify(bv, v, mk)
                cell += CLASSES[cls][0]
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
def compare_merged_table(res_b, res_e, wls, metrics, axis, controls=False):
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
                name = lbl(w) + "(baseline)" if controls or lbl(w) in TNG_MARKS else lbl(w)
                out.append(row([k, name] + metric_cells(mb, metrics, raw_b, annotate=(w != wls[0]))))
            if not controls and lbl(w) not in TNG_MARKS:
                continue
            me = res_e.get(w, {}).get(str(k), {})
            if me:
                cells = [k, lbl(w) + "(experimental)"] + metric_cells(me, metrics, raw_b, annotate=(w != wls[0]), base_m=mb, structural_raw=(controls and w == wls[0]))
                out.append(row(["**%s**" % c for c in cells]))
    return out

# --- info JSON -> (item, value) row lists -------------------------------------
def env_rows(srv, cli):
    rows = []
    def host_block(side, h):
        if not h: return
        rows.append(("%s host" % side, "client/load host" if side == "Client" else "server/backend host"))
        rows.append(("%s kernel" % side, " ".join(h.get("uname", "").split()[:1] + h.get("uname", "").split()[2:]) if len(h.get("uname", "").split()) > 2 else h.get("uname", "")))
        rows.append(("%s CPU" % side, "%s (%s vCPU)" % (h.get("cpu_model", ""), h.get("cpu_count", ""))))
        rows.append(("%s memory" % side, h.get("mem", "")))
    host_block("Client", cli)
    host_block("Server", srv)
    for side, h in (("Client", cli), ("Server", srv)):
        # The source revision IS the benchmark identity; manifest-era fields
        # (binary checksum, source-state, dirty, build command/environment,
        # build time, run ID) are not rendered: nobody reads them and the
        # full-SHA columns eat enormous width.
        rows.extend([
            (f"{side} TNG", h.get("tng_version", "[missing]")),
            (f"{side} TNG source revision", h.get("tng_git", "[missing]")),
        ])
    rows.append(("Container runtime", cli.get("runtime") or srv.get("runtime", "")))
    rows.append(("Link", "eth0: client/load host <-> server/backend host"))
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
    rows.append(("Result per point", "strongest of N rounds (highest request rate)"))
    for side, meta in (("Client", cli), ("Server", srv)):
        for key, value in sorted(meta.get("params", {}).items()):
            if key == "server_ip":
                value = "[redacted endpoint]"
            rows.append((f"{side} parameter: {key}", value))
        for name, value in sorted(meta.get("configuration", {}).items()):
            rows.append((f"{side} configuration: {name}", value))
    return rows

def tool_rows(tools):
    rows = []
    for name in ("iperf3", "nginx", "wrk", "stunnel", "haproxy"):
        t = tools.get(name, {})
        fields = [t.get("image", ""), t.get("source", ""), t.get("version", ""), t.get("digest", "")]
        rows.append((name, fields))
    return rows

def host_tool_rows(srv, cli):
    rows = []
    for side, meta in (("Client", cli), ("Server", srv)):
        for name, fields in tool_rows(meta.get("tools", {})):
            rows.append((f"{side} {name}", fields))
    return rows

def tool_cell(fields):
    return "; ".join([f for f in fields if f]) or "-"

def value_table(rows):
    out = ["| Item | Value |", "| --- | --- |"]
    for item, value in rows:
        out.append(row([item, value]))
    return out

def diff_table(brows, erows, only_changes=True):
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
        if not only_changes or bs != es:
            out.append(row([item, bs, es]))
    return out

def diff_section(title, fold_label, brows, erows, bhead, ehead):
    # The five report sections are plain numbered bold lines, not headings:
    # they carry no navigation value and headings eat vertical space.
    L.extend([title, ""])
    header = [row(["Item", bhead, ehead]), row(["---"] * 3)]
    changed = diff_table(brows, erows)
    L.extend(header + changed if changed else ["No differences."])
    L.append("")
    L.extend(fold("Full " + fold_label,
                  header + diff_table(brows, erows, only_changes=False)))

def comparison_summary(rb, re, wls, metrics, controls=False):
    selected = [w for w in wls if (lbl(w) not in TNG_MARKS if controls else lbl(w) in TNG_MARKS)]
    counts = [[0] * len(metrics) for _ in CLASSES]
    findings = []
    scope = []
    missing = []
    expected = {str(k) for k in keys_of(rb, wls)} | {str(k) for k in keys_of(re, wls)}
    for w in selected:
        if not rb.get(w) and not re.get(w):
            # A mode absent from both runs (e.g. an ohttp-only ablation subset) is
            # not measured; modes present in either run still need a complete matrix.
            continue
        bk, ek = set(rb.get(w, {})), set(re.get(w, {}))
        if bk != expected or ek != expected:
            missing.append(f"{w}: incomplete scenario concurrency matrix; expected {sorted(expected)}, before={sorted(bk)}, after={sorted(ek)}")
        if bk != ek:
            missing.append(f"{w}: before/after concurrency keys differ: {sorted(bk)} vs {sorted(ek)}")
        for k in sorted(bk | ek, key=lambda x: int(x)):
            scope.append((w, k))
            mb, me = rb.get(w, {}).get(k, {}), re.get(w, {}).get(k, {})
            for i, (mk, hdr, fmt, has_raw) in enumerate(metrics):
                if controls and w == wls[0] and not has_raw:
                    continue
                if mk not in mb and mk not in me:
                    # Structurally uncollected for this workload pair: render
                    # '-' in the tables, count nothing, flag nothing.
                    continue
                try:
                    cls, delta = classify(mb.get(mk), me.get(mk), mk)
                except ValueError as e:
                    missing.append(f"{w}, concurrency={k}: {e}")
                    continue
                counts[cls][i] += 1
                # Always disclose adverse success-rate changes, even inside stable.
                if cls >= 3 or (mk == 'success_pct' and delta < 0):
                    findings.append(f"{CLASSES[cls][0]} {lbl(w)}, concurrency={k}, {hdr}: {fmt % number(mb[mk])} → {fmt % number(me[mk])} ({delta:+.1f}% vs before)")
    if missing:
        raise SystemExit("Incomplete comparison; no summary/report written:\n- " + "\n- ".join(missing))
    total = sum(sum(c) for c in counts)
    if not total:
        raise SystemExit("No paired metrics available for classification")
    columns = ['Change class', 'Count (%)'] + [m[1] for m in metrics]
    table = [row(columns), row(['---', '---:'] + ['---:'] * len(metrics))]
    for i, (symbol, label) in enumerate(CLASSES):
        n = sum(counts[i])
        table.append(row([f'{symbol} {label}', f'{n} ({n / total * 100:.1f}%)', *counts[i]]))
    table.append(row(['**Total**', f'**{total} (100.0%)**',
                      *[f'**{sum(c[i] for c in counts)}**' for i in range(len(metrics))]]))
    assert sum(sum(c[i] for c in counts) for i in range(len(metrics))) == total
    intro = []
    if findings:
        intro += ['**Notable adverse measurements:**', '', *['- ' + f for f in findings], '']
    return intro + table


def compare_scenario(title, rb, re, wls, metrics, axis):
    L.extend([title, ''])
    if not (has_data(rb, wls) or has_data(re, wls)):
        L.extend(['Not measured in either run.', ''])
        return
    metrics = visible_metrics((rb, re), wls, metrics)
    L.extend(comparison_summary(rb, re, wls, metrics))
    L.extend(fold('Full ' + title[4:] + ' comparison',
                  compare_merged_table(rb, re, wls, metrics, axis)))

METH_BODY = [
    "**Topology and tunnel modes**", "",
    "- Two hosts communicate over eth0: a client/load host runs TNG ingress and load generators; a server/backend host runs TNG egress, iperf3, nginx and TLS-proxy reference backends.",
    "- TNG uses five mapping entries (ingress 50001–50005, egress 40001–40005). Load tools use host-network containers; TNG runs as a host executable. Protocol modes and attestation settings are recorded in Test Conditions.", "",
    "**Workloads and run parameters**", "",
    "- Scenario A measures TCP throughput with iperf3 parallel streams (`-P`). Scenario B measures HTTP/wrk persistent connections; Scenario C sends `Connection: close` for fresh client connections. Actual concurrency, body size, duration, warmup and round counts appear in Test Conditions.",
    "- Each workload/concurrency point runs the recorded number of rounds; the cell takes the strongest round (highest request rate) with all of its metrics, so a round that catches a cold-start race cannot pollute the cell. CPU samples use the final round and memory samples span every measured round, as described below. Keep-alive and no-keep-alive are separate scenarios, not interchangeable workloads.", "",
    "**HTTP latency and success metrics**", "",
    "- wrk runs with `--latency`: p50/p90/p99 come from its reported distribution; p95 is obtained by the Lua `latency:percentile(95)` callback. Mean is wrk's Thread Stats average.",
    "- Success rate is `(completed requests - non-2xx) / (completed requests + socket errors)`. Unchanged success rates are classified as stable, not improved. Any decline must still be investigated even within the display tolerance.", "",
    "**Resource sampling and units**", "",
    "- CPU columns are one-second pidstat windows averaged over the final measured round. Memory columns are the peak RSS under load: `/proc/<pid>/status` VmRSS, summed over the sampled PID set at 1 Hz in parallel with every measured round, reported as the maximum of those samples. Windowed RSS averages mixed the load ramp into the plateau and were bistable run-to-run; the peak answers how much memory serving the workload needs.",
    "- Every workload with a proxy or tunnel process (TNG ingress/egress pair, stunnel, HAProxy, nginx) is measured on a freshly restarted process set: before each cell's warmup and measured rounds the harness stops that workload's processes, verifies the old PIDs and listen ports are released, relaunches the same binary or container with the same config, and waits for the listening ports to be ready. Samplers find processes by listen port, so they always measure the post-restart PIDs. Each cell's memory peak is therefore that cell's own cost, not allocator high-water carried from earlier cells of the pass. Raw reference rows have no proxy process and nothing to restart.",
    "- TCP Ingress CPU/Mem columns sample the ingress instance: the client-side instance of the measured gateway/tunnel (TNG ingress for the TNG workloads). The legacy `Ingress Mem (GB)` label stores the peak VmRSS KiB divided by 1024² (GiB).",
    "- HTTP Egress CPU/Mem columns sample the egress instance: the server-side instance of the measured gateway/proxy (TNG egress, HAProxy, or the stunnel or nginx server container), via `pidstat -u -p <PIDs> 1 <duration>` Average rows for CPU. HAProxy sums master and workers; nginx sums every process holding the proxy's listen port (master + all workers, found via `ss`). CPU sums threads/processes (100% = one logical core); the peak RSS sums the same PID set and is converted from KiB to MiB.",
    "- The HTTP Ingress CPU % column samples the client-side TNG ingress process with the same pidstat method; datasets whose driver did not record it render '-' in the column and exclude it from the counts.",
    "- Raw reference rows have no tunnel process, so their resource fields are structurally uncollected.", "",
    "**Comparison and classification**", "",
    "- Before/after rows compare identical workload and concurrency keys. Parenthesized values compare with the displayed baseline-run raw row; colored markers and classification counts compare with the before row. The exact thresholds and counting scope remain visible beside each result table.",
    "- Classification is based on unrounded recorded metrics. Count (%) measures metric-cell frequency, not statistical confidence or importance. Reference-run drift is reported separately; attribution and acceptance decisions require review.",
]

HTTP_SCENARIOS = [
    ("### Scenario B - HTTP / wrk ({body} KiB body, keep-alive)", HTTP_B_WL),
    ("### Scenario C - HTTP / wrk ({body} KiB body, no keep-alive)", HTTP_C_WL),
]

L = ['---', '']
if mode == "compare":
    bsrv, bcli, bres = load(bsrv_p), load(bcli_p), load(bres_p)
    esrv, ecli, eres = load(esrv_p), load(ecli_p), load(eres_p)
    validate_results(bres, 'baseline')
    validate_results(eres, 'experimental')
    validate_hosts(bsrv, bcli, 'baseline')
    validate_hosts(esrv, ecli, 'experimental')
    L.extend(['# TNG Two-Host Benchmark Comparison Report', ''])
    identity_banner()
    L.extend(['## Benchmark setup', ''])
    diff_section("1. **Test Environment**", "test environment", env_rows(bsrv, bcli), env_rows(esrv, ecli), "Baseline", "Experimental")
    diff_section("2. **Test Conditions**", "test conditions", cond_rows(bsrv, bcli, bres), cond_rows(esrv, ecli, eres), "Baseline", "Experimental")
    diff_section("3. **Test Tool Versions**", "test tool versions", host_tool_rows(bsrv, bcli), host_tool_rows(esrv, ecli), "Baseline", "Experimental")
    L.extend(['4. **Test Methodology**', ''])
    L.extend(fold('Test methodology and metric definitions', METH_BODY))
    L.extend(['## Results', ''])
    compare_scenario('### Scenario A - iperf3 (TCP throughput)', bres, eres, IPERF_WL, IPERF_M, 'Streams')
    body_b = (bcli.get('params', {}) or bsrv.get('params', {})).get('http_body_kb', '64')
    body_e = (ecli.get('params', {}) or esrv.get('params', {})).get('http_body_kb', '64')
    body = body_b if body_b == body_e else f'before={body_b}, after={body_e}'
    for tmpl, wls in HTTP_SCENARIOS:
        compare_scenario(tmpl.format(body=body), bres, eres, wls, HTTP_M, 'Conns')
else:
    srv = load(srv_p); cli = load(cli_p)
    res = load(res_p)
    validate_results(res, "single run")
    validate_hosts(srv, cli, "single run")
    tools = merged_tools(srv, cli)
    p = cli.get("params", {}) or srv.get("params", {})

    L.append("# TNG Two-Host Benchmark Report")
    L.append("")
    identity_banner()
    L.append("## Benchmark setup")
    L.append("")
    L.append("1. **Test Environment**")
    L.append("")
    L.extend(fold("Full test environment", value_table(env_rows(srv, cli))))
    L.append("")
    L.append("2. **Test Conditions**")
    L.append("")
    L.extend(fold("Full test conditions", value_table(cond_rows(srv, cli, res))))
    L.append("")
    L.append("3. **Test Tool Versions**")
    L.append("")
    tool_lines = ["| Tool | Image (resolved) | Source | Version | Digest |", "| --- | --- | --- | --- | --- |"]
    for name, fields in host_tool_rows(srv, cli):
        tool_lines.append(row([name, *fields]))
    L.extend(fold("Full test tool versions", tool_lines))
    L.append("4. **Test Methodology**")
    L.append("")
    L.extend(fold("Test methodology and metric definitions", METH_BODY))
    L.append("")
    L.append("## Results")
    L.append("")
    L.append("### Scenario A - iperf3 (TCP throughput)")
    L.append("")
    if not has_data(res, IPERF_WL):
        L.append("Not measured in this run.")
    else:
        L.extend(fold("Full Scenario A results", merged_table(res, IPERF_WL, IPERF_M, "Streams")))
    L.append("")
    for tmpl, wls in HTTP_SCENARIOS:
        L.append(tmpl.format(body=p.get("http_body_kb", "64")))
        L.append("")
        if not has_data(res, wls):
            L.append("Not measured in this run.")
        else:
            L.extend(fold("Full scenario results",
                          merged_table(res, wls, visible_metrics((res,), wls, HTTP_M), "Conns")))
        L.append("")
    L.append("Note: vs-raw percent change is in parentheses after each non-raw value, measured against the raw baseline of the same scenario. For throughput/RPS a negative value means lower than raw; for latency a positive value means slower than raw. At high concurrency the raw baseline's mean/p90/p99 are skewed by tail-latency spikes, so TNG rows can show large negative changes there, this does not establish the cause of the tail spikes or comparative stability.")
    L.append("")

# Validation completes before replacing any existing report.
if FOLD and TITLE:
    raise SystemExit("--fold and --title are mutually exclusive")
if FOLD:
    # PR-comment presentation: the entire report inside one default-collapsed
    # details block; the summary line is the report's only title.
    body = [l for l in L if not l.startswith('# ')]
    if body and body[0] == '---':   # body-context separator is noise in a comment fold
        body = body[1:]
        while body and body[0] == '':
            body = body[1:]
    L = ['<details>', '<summary>' + FOLD + '</summary>', ''] + body + ['', '</details>']
if TITLE:
    # Sub-report mode: the caller's heading replaces the default H1 and every
    # other heading drops one level so the sub-report nests under the chapter
    # heading the caller assembles.
    shifted = []
    replaced = False
    for line in L:
        if not replaced and line.startswith('# '):
            line = '## ' + TITLE
            replaced = True
        elif line.startswith('#'):
            line = '#' + line
        shifted.append(line)
    L = shifted
with tempfile.NamedTemporaryFile('w', dir=os.path.dirname(os.path.abspath(out_path)), delete=False) as f:
    f.write("\n".join(L) + "\n")
    temp_path = f.name
os.replace(temp_path, out_path)
print(out_path)
PY_REPORT
