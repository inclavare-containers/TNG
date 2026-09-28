#!/usr/bin/env bash
# bench/client.sh <SERVER_IP> - run on the client (D) host. Drives all measurements + report.
# Usage: bash bench/client.sh <SERVER_IP> [--output-dir DIR]
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

SERVER_IP="${SERVER_IP:-}"
OUTPUT_DIR_ARG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --output-dir) shift; OUTPUT_DIR_ARG="$1"; shift;;
        *) [ -z "$SERVER_IP" ] && SERVER_IP="$1"; shift;;
    esac
done
[ -n "$SERVER_IP" ] || die "usage: bench/client.sh <SERVER_IP> [--output-dir DIR] (or set SERVER_IP)"
export SERVER_IP   # so collect_metadata records it in env.json

OUTDIR="$(make_outdir "$OUTPUT_DIR_ARG")"
TNG_BIN="${TNG_BIN:-./target/release/tng}"
IPERF_PORT=5201
NGINX_PORT=8080

preflight() {
    command -v python3 &>/dev/null || die "python3 not found"
    command -v openssl &>/dev/null || die "openssl not found (needed for stunnel cert)"
    [ -x "$TNG_BIN" ] || die "TNG binary not found at $TNG_BIN (build: cargo build --release -p tng)"
    # Clear orphaned tng ingress / stunnel clients from a previous (crashed) run, or the
    # new ingress cannot bind 50001-50005 / 5220 / 5221 ("Address already in use").
    pkill -f "tng launch" 2>/dev/null || true
    command -v podman &>/dev/null && podman rm -f bench-host-stunnel-client bench-host-stunnel-http-cli bench-host-haproxy-cli 2>/dev/null || true
    ensure_runtime
}

pull_tools() {
    pull_image mirrors-ssl.aliyuncs.com/networkstatic/iperf3:latest networkstatic/iperf3:latest
    IPERF3_IMAGE="$RESOLVED_IMAGE"; IPERF3_SOURCE="$RESOLVED_IMAGE_SOURCE"; IPERF3_DIGEST="$(image_digest "$IPERF3_IMAGE")"
    IPERF3_VERSION="$(image_version "$IPERF3_IMAGE" iperf3 --version)"
    _v=$(echo "$IPERF3_VERSION" | grep -oE '3\.[0-9]+' | head -1)
    if [ -n "$_v" ]; then
        python3 -c "
import sys
v = sys.argv[1].split('.')
bad = not (int(v[0]) > 3 or (int(v[0]) == 3 and int(v[1]) >= 21))
if bad: print('\033[1;33m  ! iperf3 %s < 3.21, pthreads server-side parallelism may be missing\033[0m' % sys.argv[1])
" "$_v" 2>/dev/null || true
    fi
    pull_image mirrors-ssl.aliyuncs.com/ghcr.io/william-yeh/wrk:latest ghcr.io/william-yeh/wrk:latest
    WRK_IMAGE="$RESOLVED_IMAGE"; WRK_SOURCE="$RESOLVED_IMAGE_SOURCE"; WRK_DIGEST="$(image_digest "$WRK_IMAGE")"
    WRK_VERSION="$(image_version "$WRK_IMAGE" --version 2>&1 | head -1)"
    pull_image mirrors-ssl.aliyuncs.com/dockurr/stunnel:latest dockurr/stunnel:latest
    STUNNEL_IMAGE="$RESOLVED_IMAGE"; STUNNEL_SOURCE="$RESOLVED_IMAGE_SOURCE"; STUNNEL_DIGEST="$(image_digest "$STUNNEL_IMAGE")"
    STUNNEL_VERSION="$("$CTR" run --rm --network host --entrypoint stunnel "$STUNNEL_IMAGE" -version 2>&1 | grep -m1 'stunnel [0-9]' || true)"
    pull_image mirrors-ssl.aliyuncs.com/library/haproxy:latest docker.io/library/haproxy:latest
    HAPROXY_IMAGE="$RESOLVED_IMAGE"; HAPROXY_SOURCE="$RESOLVED_IMAGE_SOURCE"; HAPROXY_DIGEST="$(image_digest "$HAPROXY_IMAGE")"
    HAPROXY_VERSION="$("$CTR" run --rm "$HAPROXY_IMAGE" haproxy -v 2>&1 | head -1)"
    NGINX_IMAGE="(server side)" NGINX_VERSION="" NGINX_DIGEST="" NGINX_SOURCE=""
    export IPERF3_IMAGE IPERF3_SOURCE IPERF3_VERSION IPERF3_DIGEST WRK_IMAGE WRK_SOURCE WRK_VERSION WRK_DIGEST
    export STUNNEL_IMAGE STUNNEL_SOURCE STUNNEL_VERSION STUNNEL_DIGEST NGINX_IMAGE NGINX_VERSION NGINX_DIGEST NGINX_SOURCE
    export HAPROXY_IMAGE HAPROXY_SOURCE HAPROXY_VERSION HAPROXY_DIGEST
}

start_ingress() {
    # RA_MODE=1: enable remote attestation (verify via builtin AS + hardware_only).
    if [ "${RA_MODE:-0}" = "1" ]; then
        RA_OPT='"no_ra": false, "verify": {"as_type": "builtin", "attestation_policy": {"type": "hardware_only"}}'
        ok "RA enabled: verify via builtin AS (hardware_only)"
    else
        RA_OPT='"no_ra": true'
    fi
    cat > "$OUTDIR/configs/ingress.json" <<EOF
{
  "add_ingress": [
    {"mapping":{"in":{"host":"0.0.0.0","port":50001},"out":{"host":"${SERVER_IP}","port":40001}},"rats_tls":{"multiplex":false},${RA_OPT}},
    {"mapping":{"in":{"host":"0.0.0.0","port":50002},"out":{"host":"${SERVER_IP}","port":40002}},"rats_tls":{"multiplex":true},${RA_OPT}},
    {"mapping":{"in":{"host":"0.0.0.0","port":50003},"out":{"host":"${SERVER_IP}","port":40003}},"rats_tls":{"multiplex":false},${RA_OPT}},
    {"mapping":{"in":{"host":"0.0.0.0","port":50004},"out":{"host":"${SERVER_IP}","port":40004}},"rats_tls":{"multiplex":true},${RA_OPT}},
    {"mapping":{"in":{"host":"0.0.0.0","port":50005},"out":{"host":"${SERVER_IP}","port":40005}},"ohttp":{},${RA_OPT}}
  ]
}
EOF
    "$TNG_BIN" launch --config-file "$OUTDIR/configs/ingress.json" > "$OUTDIR/logs/ingress.log" 2>&1 &
    INGRESS_PID=$!
    sleep ${INGRESS_WAIT:-5}
    ss -tlnp 2>/dev/null | grep -q ":50001" || { fail "TNG ingress not listening"; tail -20 "$OUTDIR/logs/ingress.log"; exit 1; }
    ok "TNG ingress listening on 50001-50005"

    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$OUTDIR/stunnel.pem" \
        -out "$OUTDIR/stunnel.pem" -subj "/CN=localhost" 2>/dev/null
    chmod 644 "$OUTDIR/stunnel.pem"   # HAProxy -W workers drop to the haproxy user; 600 (root) blocks them.
    cat > "$OUTDIR/stunnel-client.conf" <<EOF
foreground = yes
[bench]
client = yes
accept = 5220
connect = ${SERVER_IP}:5210
cert = /etc/stunnel/stunnel.pem
EOF
    "$CTR" rm -f bench-host-stunnel-client >/dev/null 2>&1 || true
    "$CTR" run -d --name bench-host-stunnel-client --network host --entrypoint stunnel \
        -v "$OUTDIR/stunnel-client.conf:/etc/stunnel/stunnel.conf:ro" \
        -v "$OUTDIR/stunnel.pem:/etc/stunnel/stunnel.pem:ro" \
        "$STUNNEL_IMAGE" /etc/stunnel/stunnel.conf \
        || die "stunnel client start failed"
    ok "stunnel client on :5220 -> ${SERVER_IP}:5210"

    # stunnel client for the http+stunnel baseline: :5221 -> SERVER:5211 (server's http stunnel -> nginx)
    cat > "$OUTDIR/stunnel-http-client.conf" <<EOF
foreground = yes
[bench]
client = yes
accept = 5221
connect = ${SERVER_IP}:5211
cert = /etc/stunnel/stunnel.pem
EOF
    "$CTR" rm -f bench-host-stunnel-http-cli >/dev/null 2>&1 || true
    "$CTR" run -d --name bench-host-stunnel-http-cli --network host --entrypoint stunnel \
        -v "$OUTDIR/stunnel-http-client.conf:/etc/stunnel/stunnel.conf:ro" \
        -v "$OUTDIR/stunnel.pem:/etc/stunnel/stunnel.pem:ro" \
        "$STUNNEL_IMAGE" /etc/stunnel/stunnel.conf \
        || die "stunnel http client start failed"
    ok "stunnel http client on :5221 -> ${SERVER_IP}:5211"

    # HAProxy client (modern TLS proxy baseline): plain frontends -> TLS backends on server.
    cat > "$OUTDIR/haproxy-client.cfg" <<EOF
global
    nbthread ${HAPROXY_THREADS:-4}
defaults
    mode tcp
    timeout connect 5s
    timeout client 30s
    timeout server 30s
frontend fe_iperf
    bind :5223
    default_backend be_iperf
backend be_iperf
    server srv ${SERVER_IP}:5213 ssl verify none
frontend fe_http
    bind :5222
    default_backend be_http
backend be_http
    server srv ${SERVER_IP}:5212 ssl verify none
EOF
    "$CTR" rm -f bench-host-haproxy-cli >/dev/null 2>&1 || true
    "$CTR" run -d --name bench-host-haproxy-cli --network host \
        -v "$OUTDIR/haproxy-client.cfg:/etc/haproxy/haproxy.cfg:ro" \
        "$HAPROXY_IMAGE" haproxy -f /etc/haproxy/haproxy.cfg -W \
        || die "haproxy client start failed"
    ok "haproxy client on :5223->srv:5213(iperf) :5222->srv:5212(http)"
}

client_cleanup() {
    # $! may be the launcher (which already exited), not the real tng child, so also
    # pkill any tng launch process to avoid orphaned ingresses holding ports 50001-50005.
    [ -n "${INGRESS_PID:-}" ] && kill_pids "$INGRESS_PID" 2>/dev/null || true
    pkill -f "tng launch" 2>/dev/null || true
    [ -n "${CTR:-}" ] && cleanup_containers bench-host-stunnel-client bench-host-stunnel-http-cli bench-host-haproxy-cli
    log "client cleaned up"
}
trap client_cleanup EXIT

run_all() {
    local streams_list="${IPERF_STREAMS:-1,8,16,32,64,128}"
    local conns_list="${WRK_CONNS:-1,8,16,32,64,128}"
    local TNG_T="tng:50001"
    local ST_T="stunnel:5220"
    local ST_HTTP_T="stunnel:5221"
    local HP_T="haproxy:5223"
    local HP_HTTP_T="haproxy:5222"
    local RAW_T="raw:"
    # Server-side sampling targets (host:kind:id) for the http workloads. tng/stunnel
    # id = the server-side listen port; haproxy id is unused (pgrep gathers master+workers).
    local SRV_TNG="${SERVER_IP}:tng:40003"
    local SRV_TNG_MUX="${SERVER_IP}:tng:40004"
    local SRV_OHTTP="${SERVER_IP}:tng:40005"
    local SRV_ST="${SERVER_IP}:stunnel:5211"
    local SRV_HP="${SERVER_IP}:haproxy:srv"
    local _iperf_json='{}' out
    for s in ${streams_list//,/ }; do
        out=$(run_iperf_median 127.0.0.1 50001 "$s" "iperf3+rats-tls" "$TNG_T")
        _iperf_json=$(json_add_iperf "$_iperf_json" "iperf3+rats-tls" "$s" "$out")
        out=$(run_iperf_median 127.0.0.1 50002 "$s" "iperf3+rats-tls+mux" "$TNG_T")
        _iperf_json=$(json_add_iperf "$_iperf_json" "iperf3+rats-tls+mux" "$s" "$out")
        out=$(run_iperf_median "$SERVER_IP" "$IPERF_PORT" "$s" "iperf3+raw" "$RAW_T")
        _iperf_json=$(json_add_iperf "$_iperf_json" "iperf3+raw" "$s" "$out")
        out=$(run_iperf_median 127.0.0.1 5220 "$s" "iperf3+stunnel" "$ST_T")
        _iperf_json=$(json_add_iperf "$_iperf_json" "iperf3+stunnel" "$s" "$out")
        out=$(run_iperf_median 127.0.0.1 5223 "$s" "iperf3+haproxy" "$HP_T")
        _iperf_json=$(json_add_iperf "$_iperf_json" "iperf3+haproxy" "$s" "$out")
    done

    local _http_json='{}'
    for c in ${conns_list//,/ }; do
        out=$(run_wrk_median "http://127.0.0.1:50003/file.bin" "$c" "http+rats-tls" "$SRV_TNG")
        _http_json=$(json_add_http "$_http_json" "http+rats-tls" "$c" "$out")
        out=$(run_wrk_median "http://127.0.0.1:50004/file.bin" "$c" "http+rats-tls+mux" "$SRV_TNG_MUX")
        _http_json=$(json_add_http "$_http_json" "http+rats-tls+mux" "$c" "$out")
        out=$(run_wrk_median "http://127.0.0.1:50005/file.bin" "$c" "http+ohttp" "$SRV_OHTTP")
        _http_json=$(json_add_http "$_http_json" "http+ohttp" "$c" "$out")
        out=$(run_wrk_median "http://${SERVER_IP}:${NGINX_PORT}/file.bin" "$c" "http+raw" "$RAW_T")
        _http_json=$(json_add_http "$_http_json" "http+raw" "$c" "$out")
        out=$(run_wrk_median "http://127.0.0.1:5221/file.bin" "$c" "http+stunnel" "$SRV_ST")
        _http_json=$(json_add_http "$_http_json" "http+stunnel" "$c" "$out")
        out=$(run_wrk_median "http://127.0.0.1:5222/file.bin" "$c" "http+haproxy" "$SRV_HP")
        _http_json=$(json_add_http "$_http_json" "http+haproxy" "$c" "$out")
    done

    python3 -c "import json,sys; a=json.loads(sys.argv[1]); b=json.loads(sys.argv[2]); a.update(b); print(json.dumps(a))" "$_iperf_json" "$_http_json" > "$OUTDIR/bench-results.json"
}

preflight
pull_tools
start_ingress
collect_info "$OUTDIR/client-info.json" client
run_all
log "Done. Results: $OUTDIR/bench-results.json; client info: $OUTDIR/client-info.json"
log "Generate the report with: bash bench/gen-report.sh <server-info.json> $OUTDIR/client-info.json $OUTDIR/bench-results.json"
