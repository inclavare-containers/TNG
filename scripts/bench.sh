#!/usr/bin/env bash
# Benchmark: raw TCP vs stunnel vs TNG in isolated ip netns
# Usage: make bench
# Dependencies: ip, iptables, iperf3, stunnel4, openssl, python3, curl
set -euo pipefail

###############################################################################
# Configuration
###############################################################################
TNG_BIN="${TNG_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/tng}"
IPERF_DURATION="${IPERF_DURATION:-10}"
IPERF_ROUNDS="${IPERF_ROUNDS:-3}"
IPERF_STREAMS="${IPERF_STREAMS:-1,8}"

CLIENT_NS="tng_bench_client"
SERVER_NS="tng_bench_server"
VETH_C="veth_bench_c"
VETH_S="veth_bench_s"
IP_C="10.200.1.1"
IP_S="10.200.1.2"

# Ports
IPERF_PORT=5201
STUNNEL_SERVER_PORT=5601
STUNNEL_CLIENT_PORT=9001

TNG_EGRESS_LISTEN=40000
TNG_INGRESS_LISTEN=50000

BENCH_TMP=""

###############################################################################
# Helpers
###############################################################################
log()  { echo -e "\033[1;34m[$(date +%T)]\033[0m $*"; }
ok()   { echo -e "\033[1;32m  ✓\033[0m $*"; }
fail() { echo -e "\033[1;31m  ✗\033[0m $*" >&2; }

c_ns() { ip netns exec "$1" "${@:2}"; }

kill_ns_bg() {
    # Kill background stunnel/tng processes in a namespace
    local ns="$1"
    ip netns exec "$ns" pkill -f "stunnel.*/tmp/tng-bench" 2>/dev/null || true
    ip netns exec "$ns" pkill -f "tng launch --config-file /tmp/tng-bench" 2>/dev/null || true
    sleep 0.5
}

# Run one round of iperf3 and extract sender bandwidth in Gbps
run_iperf_one() {
    local host="$1" port="$2" ns="$3" streams="${4:-1}"
    ip netns exec "$ns" iperf3 -c "$host" -p "$port" -t "$IPERF_DURATION" -P "$streams" -J 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin)
bits = d['end']['sum_sent']['bits_per_second']
print(f'{bits / 1e9:.2f}')
" 2>/dev/null
}

# Run iperf3 multiple rounds and report median
run_iperf() {
    local host="$1" port="$2" ns="$3" label="$4" streams="${5:-1}"
    local -a results=()
    for i in $(seq 1 "$IPERF_ROUNDS"); do
        local bw
        bw=$(run_iperf_one "$host" "$port" "$ns" "$streams") || {
            fail "iperf3 round $i failed for $label"
            echo "0.00"
            return 1
        }
        results+=("$bw")
        echo -e "\033[1;32m  ✓\033[0m $label round $i: ${bw} Gbps" >&2
    done
    # Take median
    local median
    median=$(printf '%s\n' "${results[@]}" | sort -g | python3 -c "
import sys
vals = [float(x.strip()) for x in sys.stdin if x.strip()]
vals.sort()
n = len(vals)
if n % 2 == 1:
    print(f'{vals[n//2]:.2f}')
else:
    print(f'{(vals[n//2-1]+vals[n//2])/2:.2f}')
")
    echo -e "\033[1;32m  ✓\033[0m $label median (${IPERF_ROUNDS} rounds): ${median} Gbps" >&2
    echo "$median"
}

cleanup() {
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    rm -rf "$BENCH_TMP" 2>/dev/null || true
    log "Namespaces cleaned up."
}

###############################################################################
# Pre-flight
###############################################################################
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root" >&2; exit 1
fi
for cmd in ip iperf3 openssl python3; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: $cmd not found" >&2; exit 1
    fi
done
STUNNEL_BIN=$(command -v stunnel4 2>/dev/null || command -v stunnel 2>/dev/null || true)
if [ -z "$STUNNEL_BIN" ]; then
    echo "Error: stunnel4/stunnel not found. Install: yum install -y stunnel" >&2; exit 1
fi
if [ ! -f "$TNG_BIN" ]; then
    echo "Error: TNG binary not found at $TNG_BIN. Build with: cargo build --release -p tng" >&2; exit 1
fi

BENCH_TMP=$(mktemp -d /tmp/tng-bench.XXXXXX)
trap cleanup EXIT

log "=== Phase 0: Setting up network namespaces ==="
ip netns del "$CLIENT_NS" 2>/dev/null || true
ip netns del "$SERVER_NS" 2>/dev/null || true
ip netns add "$CLIENT_NS"
ip netns add "$SERVER_NS"

ip link del "$VETH_C" 2>/dev/null || true
ip link add "$VETH_C" type veth peer name "$VETH_S"
ip link set "$VETH_C" netns "$CLIENT_NS"
ip link set "$VETH_S" netns "$SERVER_NS"
c_ns "$CLIENT_NS" ip addr add "${IP_C}/24" dev "$VETH_C"
c_ns "$SERVER_NS" ip addr add "${IP_S}/24" dev "$VETH_S"
c_ns "$CLIENT_NS" ip link set lo up
c_ns "$SERVER_NS" ip link set lo up
c_ns "$CLIENT_NS" ip link set "$VETH_C" up
c_ns "$SERVER_NS" ip link set "$VETH_S" up

if ! c_ns "$CLIENT_NS" ping -c 1 -W 1 "$IP_S" &>/dev/null; then
    fail "Cannot ping between namespaces"; exit 1
fi
ok "Network: ${CLIENT_NS}(${IP_C}) ↔ ${SERVER_NS}(${IP_S})"

# Generate TLS cert for stunnel
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "${BENCH_TMP}/stunnel.pem" \
    -out    "${BENCH_TMP}/stunnel.pem" \
    -subj "/CN=localhost" 2>/dev/null
c_ns "$SERVER_NS" cp "${BENCH_TMP}/stunnel.pem" /tmp/tng-bench-stunnel.pem 2>/dev/null || {
    c_ns "$SERVER_NS" mkdir -p /tmp
    c_ns "$SERVER_NS" cp "${BENCH_TMP}/stunnel.pem" /tmp/tng-bench-stunnel.pem
}
c_ns "$CLIENT_NS" cp "${BENCH_TMP}/stunnel.pem" /tmp/tng-bench-stunnel.pem 2>/dev/null || {
    c_ns "$CLIENT_NS" mkdir -p /tmp
    c_ns "$CLIENT_NS" cp "${BENCH_TMP}/stunnel.pem" /tmp/tng-bench-stunnel.pem
}

###############################################################################
# Generate configs (used inside the benchmark loop)
###############################################################################

# Server: stunnel accept :5601 → connect 127.0.0.1:5201
cat > "${BENCH_TMP}/stunnel-server.conf" << 'EOF'
foreground = yes
pid = /tmp/tng-bench-stunnel-server.pid
debug = 0
[tng-bench]
accept = 5601
connect = 127.0.0.1:5201
cert = /tmp/tng-bench-stunnel.pem
verifyPeer = no
EOF

# Client: stunnel accept :9001 → connect server:5601
cat > "${BENCH_TMP}/stunnel-client.conf" << 'EOF'
foreground = yes
pid = /tmp/tng-bench-stunnel-client.pid
debug = 0
[tng-bench]
accept = 9001
connect = 10.200.1.2:5601
client = yes
verifyPeer = no
EOF

# TNG egress config (server side)
cat > "${BENCH_TMP}/egress.json" << 'EGRESS_EOF'
{
    "add_egress": [
        {
            "netfilter": {
                "capture_dst": [
                    {"port": 5201}
                ],
                "capture_local_traffic": true,
                "listen_port": 40000
            },
            "rats_tls": {
                "multiplex": false
            },
            "no_ra": true
        }
    ]
}
EGRESS_EOF

# TNG ingress config (client side)
cat > "${BENCH_TMP}/ingress.json" << 'INGRESS_EOF'
{
    "add_ingress": [
        {
            "netfilter": {
                "capture_dst": [
                    {"host": "10.200.1.2", "port": 5201}
                ],
                "listen_port": 50000
            },
            "rats_tls": {
                "multiplex": false
            },
            "no_ra": true
        }
    ]
}
INGRESS_EOF

c_ns "$SERVER_NS" mkdir -p /tmp/tng-bench
c_ns "$CLIENT_NS" mkdir -p /tmp/tng-bench

###############################################################################
# Benchmark loop: run for each stream count
###############################################################################
IFS=',' read -ra STREAM_COUNTS <<< "$IPERF_STREAMS"

declare -A RAW_RESULTS STUNNEL_RESULTS TNG_RESULTS

for streams in "${STREAM_COUNTS[@]}"; do
    log ""
    log "=== Stream count: $streams ==="

    ###########################################################################
    # Benchmark 1: Raw TCP
    ###########################################################################
    log "=== Benchmark 1: Raw TCP ==="
    c_ns "$SERVER_NS" iperf3 -s -D
    sleep 0.5
    RAW_RESULTS[$streams]=$(run_iperf "$IP_S" "$IPERF_PORT" "$CLIENT_NS" "Raw TCP ($streams streams)" "$streams")
    kill_ns_bg "$SERVER_NS"
    c_ns "$SERVER_NS" pkill iperf3 2>/dev/null || true

    ###########################################################################
    # Benchmark 2: stunnel
    ###########################################################################
    log "=== Benchmark 2: stunnel ==="

    c_ns "$SERVER_NS" cp "${BENCH_TMP}/stunnel-server.conf" /tmp/tng-bench-stunnel-server.conf
    c_ns "$CLIENT_NS" cp "${BENCH_TMP}/stunnel-client.conf" /tmp/tng-bench-stunnel-client.conf

    # Start services
    c_ns "$SERVER_NS" iperf3 -s -D
    sleep 0.5
    # Ensure clean ports
    c_ns "$SERVER_NS" pkill -f stunnel 2>/dev/null || true
    c_ns "$CLIENT_NS" pkill -f stunnel 2>/dev/null || true
    sleep 0.5

    c_ns "$SERVER_NS" $STUNNEL_BIN /tmp/tng-bench-stunnel-server.conf &
    c_ns "$CLIENT_NS" $STUNNEL_BIN /tmp/tng-bench-stunnel-client.conf &
    sleep 1

    STUNNEL_RESULTS[$streams]=$(run_iperf "$IP_C" "$STUNNEL_CLIENT_PORT" "$CLIENT_NS" "stunnel ($streams streams)" "$streams")
    kill_ns_bg "$SERVER_NS"
    kill_ns_bg "$CLIENT_NS"
    c_ns "$SERVER_NS" pkill iperf3 2>/dev/null || true

    ###########################################################################
    # Benchmark 3: TNG (no_ra)
    ###########################################################################
    log "=== Benchmark 3: TNG (rats-TLS, no_ra) ==="

    # Egress config (server side)
    c_ns "$SERVER_NS" cp "${BENCH_TMP}/egress.json" /tmp/tng-bench/egress.json

    # Ingress config (client side)
    c_ns "$CLIENT_NS" cp "${BENCH_TMP}/ingress.json" /tmp/tng-bench/ingress.json

    # Start iperf3
    c_ns "$SERVER_NS" iperf3 -s -D
    sleep 0.5

    # Start TNG egress
    log "Starting TNG egress..."
    c_ns "$SERVER_NS" "$TNG_BIN" launch --config-file /tmp/tng-bench/egress.json > /tmp/tng-bench/egress.log 2>&1 &
    sleep 2
    if ! c_ns "$SERVER_NS" ss -tlnp | grep -q "${TNG_EGRESS_LISTEN}"; then
        fail "TNG egress not listening on ${TNG_EGRESS_LISTEN}"
        c_ns "$SERVER_NS" cat /tmp/tng-bench/egress.log | tail -10
        exit 1
    fi
    ok "TNG egress on port ${TNG_EGRESS_LISTEN}"

    # Start TNG ingress
    log "Starting TNG ingress..."
    c_ns "$CLIENT_NS" "$TNG_BIN" launch --config-file /tmp/tng-bench/ingress.json > /tmp/tng-bench/ingress.log 2>&1 &
    sleep 2
    if ! c_ns "$CLIENT_NS" ss -tlnp | grep -q "${TNG_INGRESS_LISTEN}"; then
        fail "TNG ingress not listening on ${TNG_INGRESS_LISTEN}"
        c_ns "$CLIENT_NS" cat /tmp/tng-bench/ingress.log | tail -10
        exit 1
    fi
    ok "TNG ingress on port ${TNG_INGRESS_LISTEN}"

    TNG_RESULTS[$streams]=$(run_iperf "$IP_S" "$IPERF_PORT" "$CLIENT_NS" "TNG ($streams streams)" "$streams")
    kill_ns_bg "$SERVER_NS"
    kill_ns_bg "$CLIENT_NS"
    c_ns "$SERVER_NS" pkill iperf3 2>/dev/null || true
done

###############################################################################
# Results
###############################################################################
log ""
log "=========================================="
log "  Benchmark Results"
log "=========================================="
log ""

for streams in "${STREAM_COUNTS[@]}"; do
    raw="${RAW_RESULTS[$streams]}"
    stunnel="${STUNNEL_RESULTS[$streams]}"
    tng="${TNG_RESULTS[$streams]}"

    log "--- $streams stream(s) ---"
    python3 << PYEOF
raw = float("${raw}")
stunnel = float("${stunnel}")
tng = float("${tng}")

w = 20
print(f"  {'Method':<{w}} {'Bandwidth':<{w}} {'vs Raw':<{w}} {'vs stunnel':<{w}}")
print(f"  {'-' * (w * 4 - 4)}")
print(f"  {'Raw TCP':<{w}} {f'{raw} Gbps':<{w}} {'100%':<{w}}")
if raw > 0:
    print(f"  {'stunnel':<{w}} {f'{stunnel} Gbps':<{w}} {f'{stunnel/raw*100:.0f}%':<{w}}")
else:
    print(f"  {'stunnel':<{w}} {f'{stunnel} Gbps':<{w}} {'N/A':<{w}}")
if raw > 0:
    tng_raw = f'{tng/raw*100:.0f}%'
else:
    tng_raw = 'N/A'
if stunnel > 0:
    tng_st = f'{tng/stunnel*100:.0f}%'
else:
    tng_st = 'N/A'
print(f"  {'TNG (rats-TLS)':<{w}} {f'{tng} Gbps':<{w}} {tng_raw:<{w}} {tng_st}")
print()

if stunnel > 0 and tng > 0:
    gap = stunnel - tng
    pct_gap = (gap / stunnel) * 100
    if tng < stunnel:
        print(f"  TNG is {pct_gap:.0f}% slower than stunnel (gap: {gap:.1f} Gbps)")
    else:
        print(f"  TNG exceeds stunnel by {abs(pct_gap):.0f}%")
    if raw > 0:
        print(f"  TNG achieves {tng/raw*100:.0f}% of raw TCP throughput")
PYEOF
    log ""
done
