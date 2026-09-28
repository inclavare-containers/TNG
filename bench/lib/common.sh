#!/usr/bin/env bash
# Shared helpers for the two-host TNG benchmark (bench/server.sh, bench/client.sh).
# Sourced, not executed. Callers `set -euo pipefail` themselves.

# Colored logging (mirrors scripts/bench-netns.sh style).
log()  { echo -e "\033[1;34m[$(date +%T)]\033[0m $*"; }
ok()   { echo -e "\033[1;32m  ✓\033[0m $*"; }
fail() { echo -e "\033[1;31m  ✗\033[0m $*" >&2; }
die()  { fail "$*"; exit 1; }

# Create the per-run output directory.
# Usage: make_outdir [parent_dir]
# - no arg  -> ${BENCH_LABEL:-bench-host}-YYYYmmdd-HHMMSS under <bench dir>/artifacts
# - one arg -> same-named subdir under the given parent (parent created if absent)
# Sets global OUTDIR (absolute) and OUTLABEL. Defaulting to <bench>/artifacts keeps
# all run outputs in one gitignored place (see .gitignore).
make_outdir() {
    local parent
    if [ $# -ge 1 ] && [ -n "$1" ]; then
        parent="$1"
    else
        parent="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/artifacts"
    fi
    mkdir -p "$parent"
    OUTLABEL="${BENCH_LABEL:-bench-host}"
    OUTDIR="$(cd "$parent" && pwd)/${OUTLABEL}-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$OUTDIR/configs" "$OUTDIR/logs"
    echo "$OUTDIR"
}

# Resolve the container runtime: prefer podman, then docker, else install podman.
ensure_runtime() {
    if command -v podman &>/dev/null; then
        CTR="podman"
    elif command -v docker &>/dev/null; then
        CTR="docker"
    else
        log "No podman/docker found; installing podman..."
        if command -v dnf &>/dev/null; then dnf install -y podman
        elif command -v yum &>/dev/null; then yum install -y podman
        elif command -v apt-get &>/dev/null; then apt-get update && apt-get install -y podman
        else die "Cannot install podman: no dnf/yum/apt-get found"; fi
        command -v podman &>/dev/null || die "podman install failed"
        CTR="podman"
    fi
    ok "Container runtime: $CTR ($("$CTR" --version | head -1))"
}

# Pull mirror-first; record resolved image + source. Sets RESOLVED_IMAGE, RESOLVED_IMAGE_SOURCE.
pull_image() {
    local mirror="$1" primary="$2"
    if "$CTR" pull "$mirror" >/dev/null 2>&1; then
        RESOLVED_IMAGE="$mirror"; RESOLVED_IMAGE_SOURCE="mirror"
        ok "pulled (mirror): $mirror"
    elif "$CTR" pull "$primary" >/dev/null 2>&1; then
        RESOLVED_IMAGE="$primary"; RESOLVED_IMAGE_SOURCE="primary"
        ok "pulled (primary fallback): $primary"
    else
        die "failed to pull $primary (tried mirror $mirror first)"
    fi
}

# Print the sha256 digest of a pulled image (best-effort; "" if unavailable).
image_digest() {
    local image="$1"
    "$CTR" image inspect "$image" --format '{{.Digest}}' 2>/dev/null || true
}

# Run a version command inside an image and echo combined stdout+stderr.
image_version() {
    local image="$1"; shift
    "$CTR" run --rm --network host "$image" "$@" 2>&1 | head -1 || true
}

# Run one iperf3 client round inside a container; echo sender Gbps (float).
run_iperf_one() {
    local host="$1" port="$2" streams="${3:-1}" rawfile="${4:-}"
    local json_out
    json_out=$("$CTR" run --rm --network host "$IPERF3_IMAGE" \
        iperf3 -c "$host" -p "$port" -t "${IPERF_DURATION:-15}" \
        -l 131072 -P "$streams" -J 2>/dev/null) || return 1
    [ -n "$rawfile" ] && printf '%s\n' "$json_out" > "$rawfile"
    echo "$json_out" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    bps = d["end"]["sum_sent"]["bits_per_second"]
    print("%.2f" % (bps / 1e9))
except Exception:
    sys.exit(1)
' 2>/dev/null || return 1
}

# Run N rounds, echo median Gbps. Logs each round to stderr (like bench-netns.sh).
# Sample the client-side tunnel component CPU% and mem(GB) every ~2s for <duration>s.
# target: "tng:<pid>" (host process) | "stunnel:<container>" | "raw:" (N/A).
# Appends "cpu\tmem_gb" lines to <outfile>.
# CPU % of a process (sums ALL threads) over a 1s window via pidstat (sysstat, preinstalled).
# pidstat gives instantaneous windowed CPU% (not cumulative-since-start like ps %cpu),
# sums all threads by default, 0.01% granularity, never negative (reads the kernel's
# thread-group-wide /proc/<pid>/stat accumulator, not per-task files).
proc_cpu_pct() {
    local pid="$1"
    pidstat -p "$pid" -u 1 1 2>/dev/null | awk -v p="$pid" '$3 == p {print $8; exit}'
}

sample_tunnel() {
    local target="$1" duration="$2" outfile="$3"
    local kind="${target%%:*}" id="${target#*:}"
    if [ "$kind" = "raw" ]; then
        printf 'N/A\tN/A\n' >> "$outfile"; return 0
    fi
    local end=$(( $(date +%s) + duration ))
    while [ "$(date +%s)" -lt "$end" ]; do
        local cpu mem
        # $id is the tunnel process's LISTEN port. Find its host PID via ss, then measure
        # CPU with proc_cpu_pct (ticks, all threads, 1% granularity) and mem with ps RSS.
        # Same method for tng and stunnel -> fair comparison. (ps -o times= is 100% steps;
        # podman stats is unreliable for these containers.)
        local port="$id" pid rss
        pid=$(ss -ltnp 2>/dev/null | grep -F ":$port " | grep -o "pid=[0-9]*" | head -1 | cut -d= -f2)
        if [ -n "$pid" ]; then
            cpu=$(proc_cpu_pct "$pid")
            [ -z "$cpu" ] && cpu="N/A"
            rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
            if [ -n "$rss" ]; then mem=$(python3 -c "print('%.3f' % ($rss/1048576))" 2>/dev/null); else mem="N/A"; fi
        else
            cpu="N/A"; mem="N/A"
        fi
        printf '%s\t%s\n' "$cpu" "$mem" >> "$outfile"
        sleep 1
    done
}

# Remote-host counterpart of sample_tunnel: same metrics (1s pidstat CPU window,
# ps RSS in GB) but the tunnel process lives on another host. One ssh call runs the
# whole sampling loop remotely and streams "cpu\tmem" lines to the local outfile,
# avoiding one-ssh-per-second overhead. host:port lookup uses ss just like the local
# path (works for host tng processes and --network host containers). Missing PID -> N/A.
# Sample a SERVER-side tunnel component (tng egress / haproxy master+workers /
# stunnel-srv) on a remote host during the steady-state round. One
# `pidstat -u -r -p <PIDs> 1 <duration>` call covers both CPU% and RSS; we take
# the Average row and sum across PIDs. For haproxy, PIDs = pgrep (master + all
# workers); for tng/stunnel, -p <pid> already sums all threads. CPU% is summed
# (100 = one logical core); RSS is summed (KiB) then /1024 -> MiB. This matches
# the project convention and EXCLUDES the client proxy, bench scripts, backend,
# NLB, and OS cache (only the server-side tunnel component is counted). The
# same method is used for tng and haproxy so they are directly comparable.
# kind: tng | stunnel (PID by listen port) | haproxy (pgrep master+workers).
sample_server() {
    local host="$1" kind="$2" id="$3" duration="$4" outfile="$5"
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "root@$host" \
        bash -s -- "$kind" "$id" "$duration" >> "$outfile" 2>/dev/null <<'REMOTE'
kind="$1"; id="$2"; duration="$3"
pids=""
if [ "$kind" = "haproxy" ]; then
    pids=$(pgrep -d ',' haproxy 2>/dev/null)
else
    pids=$(ss -ltnp 2>/dev/null | grep -F ":$id " | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
fi
if [ -z "$pids" ]; then
    printf 'N/A\tN/A\n'; exit 0
fi
# LC_ALL=C forces the English "Average:" label. Average-data lines have a
# numeric PID ($3). The CPU block has 10 fields (%CPU=$8); the RSS block has
# 9 fields (RSS=$7, KiB). Sum across PIDs; RSS sum -> MiB (/1024).
LC_ALL=C pidstat -u -r -p "$pids" 1 "$duration" 2>/dev/null | awk '
/^Average:/ && $3 ~ /^[0-9]+$/ {
    if (NF == 10) cpu += $8;
    else if (NF == 9) rss += $7;
}
END {
    if (cpu == 0 && rss == 0) print "N/A\tN/A";
    else printf "%.1f\t%.1f\n", cpu, rss/1024;
}'
REMOTE
    [ -s "$outfile" ] || printf 'N/A\tN/A\n' >> "$outfile"
}

# Average a sample_tunnel outfile into "cpu\tmem_gb" (N/A if no numeric samples).
avg_samples() {
    python3 -c "
import sys
vals = [l.split('\t') for l in open(sys.argv[1]) if l.strip()]
c = [float(x[0]) for x in vals if x[0] not in ('N/A','')]
m = [float(x[1]) for x in vals if x[1] not in ('N/A','')]
print('%s\t%s' % ('%.1f' % (sum(c)/len(c)) if c else 'N/A', '%.3f' % (sum(m)/len(m)) if m else 'N/A'))
" "$1" 2>/dev/null || printf 'N/A\tN/A'
}

run_iperf_median() {
    local host="$1" port="$2" streams="${3:-1}" label="$4" tunnel="${5:-raw:}"
    local -a results=()
    local rounds="${IPERF_ROUNDS:-3}"
    local rawdir="${OUTDIR:-.}/logs/raw"
    mkdir -p "$rawdir"
    local cpu="N/A" mem="N/A" spid=""
    local i bw
    for i in $(seq 1 "$rounds"); do
        local sfile=""
        if [ "$i" -eq "$rounds" ] && [ "$tunnel" != "raw:" ]; then
            sfile=$(mktemp)
            sample_tunnel "$tunnel" "${IPERF_DURATION:-15}" "$sfile" &
            spid=$!
        fi
        if bw=$(run_iperf_one "$host" "$port" "$streams" "$rawdir/${label}-s${streams}-r${i}.json"); then
            results+=("$bw")
            ok "$label round $i: ${bw} Gbps" >&2
        else
            fail "iperf3 round $i failed for $label, skipping" >&2
        fi
        if [ -n "$sfile" ]; then
            wait "$spid" 2>/dev/null || true
            read -r cpu mem <<< "$(avg_samples "$sfile")"
            rm -f "$sfile"
        fi
    done
    if [ ${#results[@]} -eq 0 ]; then
        fail "iperf3 all rounds failed for $label" >&2
        printf '0.00\tN/A\tN/A\n'; return 0
    fi
    local med
    med=$(printf '%s\n' "${results[@]}" | sort -g | python3 -c '
import sys
v = sorted(float(x.strip()) for x in sys.stdin if x.strip())
n = len(v)
print("%.2f" % (v[n//2] if n%2 else (v[n//2-1]+v[n//2])/2))
')
    printf '%s\t%s\t%s\n' "$med" "$cpu" "$mem"
}

# Run one wrk round in a container; echo "gbps<TAB>rps<TAB>p50_us<TAB>p99_us".
run_wrk_one() {
    local url="$1" conns="${2:-1}" rawfile="${3:-}"
    local threads="${WRK_THREADS:-$(nproc)}"
    # Default cap at 8 (spec section 7: min(cpu,8)); an explicit WRK_THREADS is used as-is.
    if [ -z "${WRK_THREADS:-}" ] && [ "$threads" -gt 8 ]; then threads=8; fi
    # wrk requires connections >= threads; lower threads to conns, never raise conns.
    [ "$threads" -gt "$conns" ] && threads="$conns"
    local out
    local -a wrk_args=(--latency -d "${WRK_DURATION:-15}s" -t "$threads" -c "$conns")
    if [ "${WRK_SHORT_CONN:-0}" = "1" ]; then
        wrk_args+=(-H "Connection: close")
    fi
    wrk_args+=("$url")
    # wrk's --latency block reports 50/75/90/99 but not 95; a done() callback
    # calls latency:percentile(95) and prints a P95US line we parse below.
    local lua="/tmp/wrk-p95-$$.lua"
    cat > "$lua" <<'LUA'
done = function(summary, latency, requests)
  io.write(string.format("P95US %d\n", latency:percentile(95.0)))
end
LUA
    out=$("$CTR" run --rm --network host -v "$lua:/p95.lua:ro" "$WRK_IMAGE" -s /p95.lua "${wrk_args[@]}" 2>&1) || { rm -f "$lua"; return 1; }
    rm -f "$lua"
    [ -n "$rawfile" ] && printf '%s\n' "$out" > "$rawfile"
    echo "$out" | python3 -c '
import re, sys
s = sys.stdin.read()
def to_us(v, u):
    return int(v * (1 if u == "us" else 1000 if u == "ms" else 1000000))
# Percentiles from the Latency Distribution block (e.g. "  50%  248.00us").
def pct(p):
    m = re.search(r"^\s*%s\s+([\d.]+)(us|ms|s)\s*$" % p, s, re.M)
    return str(to_us(float(m.group(1)), m.group(2))) if m else None
p50 = pct("50%"); p90 = pct("90%"); p99 = pct("99%")
# p95 from the Lua done() callback (wrk --latency omits 95%).
m95 = re.search(r"^P95US\s+(\d+)", s, re.M)
p95 = m95.group(1) if m95 else None
# Thread Stats Latency line "Latency <avg> <stdev> <max> <pct>": avg = mean, max = tail proxy.
ts = re.search(r"^\s*Latency\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)", s, re.M)
mean = avg = mx = None
if ts:
    avg = str(to_us(float(ts.group(1)), ts.group(2)))
    mx = str(to_us(float(ts.group(5)), ts.group(6)))
# Fallback when the distribution block is absent (e.g. very short runs): avg->p50, max->p90/p95/p99.
if p50 is None and avg is not None: p50 = avg
if p90 is None and mx is not None: p90 = mx
if p95 is None and mx is not None: p95 = mx
if p99 is None and mx is not None: p99 = mx
if mean is None: mean = avg if avg is not None else "0"
for v in ("p50", "p90", "p95", "p99"):
    pass
if p50 is None: p50 = "0"
if p90 is None: p90 = "0"
if p95 is None: p95 = "0"
if p99 is None: p99 = "0"
m = re.search(r"Requests/sec:\s+([\d.]+)", s)
rps = m.group(1) if m else "0"
m = re.search(r"Transfer/sec:\s+([\d.]+)(KB|MB|GB)", s)
bps = 0.0
if m:
    v, u = float(m.group(1)), m.group(2)
    bps = v * (1e3 if u == "KB" else 1e6 if u == "MB" else 1e9) * 8
# success rate: completed - non-2xx over (completed + socket errors)
comp_m = re.search(r"(\d+)\s+requests in", s)
comp = int(comp_m.group(1)) if comp_m else 0
se_m = re.search(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", s)
sock = sum(int(x) for x in se_m.groups()) if se_m else 0
n2_m = re.search(r"Non-2xx or 3xx responses:\s+(\d+)", s)
non2xx = int(n2_m.group(1)) if n2_m else 0
total = comp + sock
success = (100.0 * (comp - non2xx) / total) if total else 0.0
print("%.2f\t%s\t%s\t%s\t%s\t%s\t%s\t%.2f" % (bps / 1e9, rps, mean, p50, p90, p95, p99, success))
'
}

# Run N rounds, echo median of each metric, tab-separated.
run_wrk_median() {
    local url="$1" conns="${2:-1}" label="$3" srv="${4:-raw:}"
    local rounds="${WRK_ROUNDS:-3}"
    local rawdir="${OUTDIR:-.}/logs/raw"
    mkdir -p "$rawdir"
    # Warmup: a single 1-connection 1s run primes the TLS session ticket in the TNG
    # ingress's shared ClientSessionMemoryCache. Subsequent connections to the same
    # egress can then resume (0-RTT + skip RA verification on the tls-0rtt build).
    if [ "${WRK_WARMUP:-1}" = "1" ]; then
        local -a warmup_args=(--latency -d 1s -t 1 -c 1)
        if [ "${WRK_SHORT_CONN:-0}" = "1" ]; then
            warmup_args+=(-H "Connection: close")
        fi
        warmup_args+=("$url")
        "$CTR" run --rm --network host "$WRK_IMAGE" "${warmup_args[@]}" >/dev/null 2>&1 || true
    fi
    local tmp; tmp=$(mktemp)
    local srv_cpu="N/A" srv_mem="N/A" rspid=""
    local i line
    for i in $(seq 1 "$rounds"); do
        local rsfile=""
        # Server-side component sampling on the last round, concurrent with wrk.
        # srv = "host:kind:id": tng/stunnel id = listen port; haproxy id = any
        # (pgrep gathers master + workers). raw: -> no sampling.
        if [ "$i" -eq "$rounds" ] && [ "$srv" != "raw:" ] && [ -n "$srv" ]; then
            rsfile=$(mktemp)
            local shost srest skind sid
            shost="${srv%%:*}"; srest="${srv#*:}"; skind="${srest%%:*}"; sid="${srest#*:}"
            sample_server "$shost" "$skind" "$sid" "${WRK_DURATION:-15}" "$rsfile" &
            rspid=$!
        fi
        if line=$(run_wrk_one "$url" "$conns" "$rawdir/${label}-c${conns}-r${i}.txt"); then
            echo "$line" >> "$tmp"
            ok "$label round $i: $line" >&2
        else
            fail "wrk round $i failed for $label, skipping" >&2
        fi
        if [ -n "$rsfile" ]; then
            wait "$rspid" 2>/dev/null || true
            read -r srv_cpu srv_mem <<< "$(avg_samples "$rsfile")"
            rm -f "$rsfile"
        fi
    done
    if [ ! -s "$tmp" ]; then
        fail "wrk all rounds failed for $label" >&2
        rm -f "$tmp"
        printf '0\t0\t0\t0\t0\t0\t0\t0\tN/A\tN/A\n'; return 0
    fi
    # cols: 0=gbps 1=rps 2=mean 3=p50 4=p90 5=p95 6=p99 7=success ; append server cpu, mem
    SC=$srv_cpu SM=$srv_mem python3 -c "
import os
rows = [l.split('\t') for l in open('$tmp') if l.strip()]
def med(col):
    v = sorted(float(r[col]) for r in rows if len(r) > col)
    n = len(v)
    return (v[n//2] if n%2 else (v[n//2-1]+v[n//2])/2) if v else 0.0
print('%.2f\t%.1f\t%d\t%d\t%d\t%d\t%d\t%.2f\t%s\t%s' % (med(0), med(1), med(2), med(3), med(4), med(5), med(6), med(7), os.environ['SC'], os.environ['SM']))
"
    rm -f "$tmp"
}

# Write env.json with machine + tool metadata. Caller must set the *_IMAGE/*_VERSION vars.
collect_info() {
    local json_path="$1" role="$2"
    local tng_ver
    tng_ver="$("${TNG_BIN:-./target/release/tng}" --version 2>/dev/null | head -1 || echo unknown)"
    local git_ref
    git_ref="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    local my_ip
    my_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    python3 - "$json_path" "$role" "$tng_ver" "$git_ref" "$CTR" "$my_ip" \
        "${IPERF3_IMAGE:-}" "${IPERF3_SOURCE:-}" "${IPERF3_VERSION:-}" "${IPERF3_DIGEST:-}" \
        "${NGINX_IMAGE:-}" "${NGINX_SOURCE:-}" "${NGINX_VERSION:-}" "${NGINX_DIGEST:-}" \
        "${WRK_IMAGE:-}" "${WRK_SOURCE:-}" "${WRK_VERSION:-}" "${WRK_DIGEST:-}" \
        "${STUNNEL_IMAGE:-}" "${STUNNEL_SOURCE:-}" "${STUNNEL_VERSION:-}" "${STUNNEL_DIGEST:-}" \
        "${HAPROXY_IMAGE:-}" "${HAPROXY_SOURCE:-}" "${HAPROXY_VERSION:-}" "${HAPROXY_DIGEST:-}" <<'PY'
import json, os, platform, subprocess, sys
json_path, role, tng_ver, git_ref, ctr, my_ip = sys.argv[1:7]
groups = {
    "iperf3": sys.argv[7:11], "nginx": sys.argv[11:15],
    "wrk": sys.argv[15:19], "stunnel": sys.argv[19:23],
    "haproxy": sys.argv[23:27],
}
def sh(cmd):
    try: return subprocess.check_output(cmd, shell=True, universal_newlines=True, stderr=subprocess.DEVNULL).strip()
    except Exception: return ""
tools = {}
for name, g in groups.items():
    image, source, version, digest = g
    if image and image != "(server side)":
        tools[name] = {"image": image, "source": source, "version": version, "digest": digest}
ver_cmd = "%s --version | head -1" % ctr
meta = {
  "role": role,
  "host": platform.node(),
  "ip": my_ip,
  "uname": sh("uname -a"),
  "cpu_model": sh("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs"),
  "cpu_count": os.cpu_count(),
  "mem": sh("grep MemTotal /proc/meminfo | awk '{print $2\" kB\"}'"),
  "tng_version": tng_ver, "tng_git": git_ref,
  "runtime": sh(ver_cmd),
  "params": {
    "iperf_duration": os.environ.get("IPERF_DURATION","15"),
    "iperf_streams": os.environ.get("IPERF_STREAMS","1,8,16,32,64,128"),
    "iperf_rounds": os.environ.get("IPERF_ROUNDS","3"),
    "iperf_len": "131072",
    "wrk_duration": os.environ.get("WRK_DURATION","15"),
    "wrk_threads": os.environ.get("WRK_THREADS","auto"),
    "wrk_conns": os.environ.get("WRK_CONNS","1,8,16,32,64,128"),
    "wrk_rounds": os.environ.get("WRK_ROUNDS","3"),
    "http_body_kb": os.environ.get("HTTP_BODY_KB","64"),
    "server_ip": os.environ.get("SERVER_IP",""),
    "tng_mode": "mapping",
    "no_ra": "false" if os.environ.get("RA_MODE", "0") == "1" else "true",
    "ra_mode": os.environ.get("RA_MODE", "0"),
    "attest_aa_type": "uds" if os.environ.get("RA_MODE", "0") == "1" else "",
    "attest_aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock" if os.environ.get("RA_MODE", "0") == "1" else "",
    "verify_as_type": "builtin" if os.environ.get("RA_MODE", "0") == "1" else "",
    "verify_attestation_policy": "hardware_only" if os.environ.get("RA_MODE", "0") == "1" else "",
  },
  "tools": tools,
}
with open(json_path, "w") as f:
    json.dump(meta, f, indent=2)
PY
}

write_results_json() {
    python3 - "$OUTDIR/bench-results.json" "$1" <<'PY'
import json, sys
data = json.loads(sys.argv[2]) if sys.argv[2].strip().startswith("{") else {}
# If $1 is a file path, load it; else treat as JSON string.
src = sys.argv[2]
try:
    data = json.load(open(src))
except Exception:
    data = json.loads(src) if src.strip() else {}
json.dump(data, open(sys.argv[1], "w"), indent=2)
PY
}

# Merge one iperf result line "gbps\tcpu\tmem" into the iperf JSON under (label, stream).
json_add_iperf() {
    python3 - "$@" <<'PY'
import json, sys
d = json.loads(sys.argv[1]); label = sys.argv[2]; s = sys.argv[3]; f = sys.argv[4].split('\t')
d.setdefault(label, {})[s] = {
    "throughput": float(f[0]), "cpu_pct": f[1], "mem_gb": f[2],
}
print(json.dumps(d))
PY
}

# Merge one wrk result line "gbps\trps\tmean\tp50\tp90\tp95\tp99\tsuccess\tsrv_cpu\tsrv_mem" into the http JSON.
# srv_cpu = server-side tunnel component CPU% (tng egress or haproxy master+workers),
# srv_mem = server-side RSS in MiB. No client-side proxy columns (excluded by convention).
json_add_http() {
    python3 - "$@" <<'PY'
import json, sys
d = json.loads(sys.argv[1]); label = sys.argv[2]; c = sys.argv[3]; f = sys.argv[4].split('\t')
d.setdefault(label, {})[c] = {
    "throughput": float(f[0]), "rps": float(f[1]),
    "mean_us": int(f[2]), "p50_us": int(f[3]), "p90_us": int(f[4]), "p95_us": int(f[5]), "p99_us": int(f[6]),
    "success_pct": float(f[7]), "srv_cpu_pct": f[8] if len(f) > 8 else "N/A", "srv_mem_mib": f[9] if len(f) > 9 else "N/A",
}
print(json.dumps(d))
PY
}

# Build bench-report.md from env.json + a results JSON file (template form).
# Usage: write_markdown <results_json_path>
write_markdown() {
    local results="$1"
    python3 - "$OUTDIR" "$results" <<'PY'
import json, os, sys
outdir, results_path = sys.argv[1], sys.argv[2]
env = json.load(open(os.path.join(outdir, "env.json")))
res = {}
if results_path:
    try: res = json.load(open(results_path))
    except Exception: res = {}
p = env.get("params", {})

IPERF_WL = ["iperf3+raw", "iperf3+stunnel", "iperf3+rats-tls", "iperf3+rats-tls+mux"]
HTTP_WL  = ["http+raw", "http+stunnel", "http+rats-tls", "http+rats-tls+mux", "http+ohttp"]
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
def row(cells): return "| " + " | ".join(str(c) for c in cells) + " |"
def num(v):
    try: return float(v)
    except Exception: return None

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
                if vn is None:
                    r.append("-"); continue
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
# 1. Environment
L.append("## 1. Test Environment")
L.append("")
L.append("| Item | Value |")
L.append("| --- | --- |")
L.append("| Client host | %s |" % env.get("host", ""))
L.append("| Kernel | %s |" % env.get("uname", ""))
L.append("| CPU | %s (%s vCPU) |" % (env.get("cpu_model", ""), env.get("cpu_count", "")))
L.append("| Memory | %s |" % env.get("mem", ""))
L.append("| TNG | %s (git %s) |" % (env.get("tng_version", ""), env.get("tng_git", "")))
L.append("| Container runtime | %s |" % env.get("runtime", ""))
L.append("| Server IP | %s |" % p.get("server_ip", ""))
L.append("")
# 2. Conditions
L.append("## 2. Test Conditions")
L.append("")
L.append("| Parameter | Value |")
L.append("| --- | --- |")
L.append("| TNG ingress/egress mode | %s |" % p.get("tng_mode", ""))
L.append("| Remote attestation | no_ra=%s |" % p.get("no_ra", ""))
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
L.append("| Tool | Image (resolved) | Version | Digest |")
L.append("| --- | --- | --- | --- |")
for name in ("iperf3", "nginx", "wrk", "stunnel"):
    t = env.get("tools", {}).get(name, {})
    L.append("| %s | %s | %s | %s |" % (name, t.get("image", ""), t.get("version", ""), t.get("digest", "")))
L.append("")
# 4. Methodology
L.append("## 4. Test Methodology")
L.append("")
L.append("Two hosts (server/P and client/D) reach each other over eth0. The server runs iperf3, nginx, and stunnel backends plus one TNG egress process (five `mapping` entries on ports 40001-40005); the client runs one TNG ingress process (five `mapping` entries on 50001-50005) plus stunnel clients. All load tools run in `--network host` containers pulled mirror-first; TNG runs as a host binary.")
L.append("")
L.append("iperf3 sweeps parallel streams (`-P`); HTTP (wrk) sweeps connections (`-c`), each for a fixed duration. Each `(workload, stream/conn)` point runs N rounds and records the median of each metric. wrk runs with `--latency` so p50/p90/p99 come from the latency distribution; the mean is wrk's Thread Stats average; the success rate is (completed requests - non-2xx) / (completed + socket errors).")
L.append("")
L.append("The Server CPU % and Server Mem (MiB) columns are sampled on the server host during the steady-state round via `pidstat -u -r -p <PIDs> 1 <duration>`, taking the Average row. For TNG workloads the sampled component is the tng egress process (by its listen port, all threads summed by pidstat); for the haproxy baseline the haproxy-srv master plus all workers (pgrep, summed across processes); for the stunnel baseline the stunnel-srv process. The same method is used for every component so they are directly comparable. CPU % is summed across the component's processes (100 = one logical core); RSS is summed (KiB) and reported in MiB. Client-side proxy, bench scripts, curl, the backend, NLB, OS cache, and other processes are NOT counted. Raw baselines have no tunnel component, shown as `-`. Every numeric metric on a non-raw row is annotated with its percent change versus the raw baseline at the same concurrency; `-` marks a metric the raw baseline has no value for. p95 comes from a wrk Lua done() callback (latency:percentile(95)) since wrk --latency omits the 95th percentile.")
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

open(os.path.join(outdir, "bench-report.md"), "w").write("\n".join(L))
print(os.path.join(outdir, "bench-report.md"))
PY
}

# Idempotent teardown.
cleanup_containers() { for n in "$@"; do "$CTR" rm -f "$n" >/dev/null 2>&1 || true; done; }
kill_pids()          { for p in "$@"; do kill "$p" >/dev/null 2>&1 || true; done; }
