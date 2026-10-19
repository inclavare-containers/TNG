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
# WRK_SHORT_CONN was the old single-mode pin; every run now measures both HTTP
# scenarios (keep-alive + no keep-alive) in one pass. Honor nothing, warn loudly.
if [ -n "${WRK_SHORT_CONN:-}" ]; then
    fail "WRK_SHORT_CONN=$WRK_SHORT_CONN ignored: there is no single-mode pin anymore, each run measures keep-alive and no keep-alive"
fi

OUTDIR="$(make_outdir "$OUTPUT_DIR_ARG")"
TNG_BIN="${TNG_BIN:-./target/release/tng}"
IPERF_PORT=5201
NGINX_PORT=8080
# Server-side nginx reference proxy ports (must match bench/server.sh).
NGINX_STREAM_IPERF_PORT=5214
NGINX_STREAM_HTTP_PORT=5215
NGINX_HTTP_PORT=5216

preflight() {
    command -v python3 &>/dev/null || die "python3 not found"
    command -v openssl &>/dev/null || die "openssl not found (needed for stunnel cert)"
    [ -x "$TNG_BIN" ] || die "TNG binary not found at $TNG_BIN (build: cargo build --release -p tng)"
    # Clear orphaned tng ingress / stunnel clients from a previous (crashed) run, or the
    # new ingress cannot bind 50001-50005 / 5220 / 5221 ("Address already in use").
    pkill -f "tng launch" 2>/dev/null || true
    command -v podman &>/dev/null && podman rm -f bench-host-stunnel-client bench-host-stunnel-http-cli bench-host-haproxy-cli bench-host-nginx-stream-cli bench-host-nginx-http-cli 2>/dev/null || true
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
    # nginx also runs client-side now: the nginx reference forwarders are stream
    # proxies from the same image (previously "(server side)" only).
    pull_image mirrors-ssl.aliyuncs.com/library/nginx:stable-alpine lscr.io/linuxserver/nginx:latest
    NGINX_IMAGE="$RESOLVED_IMAGE"; NGINX_SOURCE="$RESOLVED_IMAGE_SOURCE"; NGINX_DIGEST="$(image_digest "$NGINX_IMAGE")"
    NGINX_VERSION="$("$CTR" run --rm --network host "$NGINX_IMAGE" nginx -v 2>&1 | grep -i 'nginx version' | head -1 || true)"
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
    # Optional mux pool sharding for the experimental side of a comparison run
    # (ingress-only knob). Unset keeps today's single-tunnel mux config.
    if [ -n "${MUX_MAX_STREAMS:-}" ]; then
        MUX_SHARD=",\"multiplex_max_streams_per_connection\":${MUX_MAX_STREAMS}"
        ok "mux sharding: multiplex_max_streams_per_connection=${MUX_MAX_STREAMS}"
    else
        MUX_SHARD=""
    fi
    cat > "$OUTDIR/configs/ingress.json" <<EOF
{
  "add_ingress": [
    {"mapping":{"in":{"host":"0.0.0.0","port":50001},"out":{"host":"${SERVER_IP}","port":40001}},"rats_tls":{"multiplex":false},${RA_OPT}},
    {"mapping":{"in":{"host":"0.0.0.0","port":50002},"out":{"host":"${SERVER_IP}","port":40002}},"rats_tls":{"multiplex":true${MUX_SHARD}},${RA_OPT}},
    {"mapping":{"in":{"host":"0.0.0.0","port":50003},"out":{"host":"${SERVER_IP}","port":40003}},"rats_tls":{"multiplex":false},${RA_OPT}},
    {"mapping":{"in":{"host":"0.0.0.0","port":50004},"out":{"host":"${SERVER_IP}","port":40004}},"rats_tls":{"multiplex":true${MUX_SHARD}},${RA_OPT}},
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

    # nginx reference forwarders (client side). Like the stunnel/haproxy clients
    # they accept plain TCP and speak TLS upstream (stream proxy_ssl); no client
    # cert needed (the server proxies do not verify). 5224/5225 front the
    # nginx-stream iperf/http server proxies, 5226 fronts the nginx-http L7 proxy.
    cat > "$OUTDIR/nginx-stream-client.conf" <<EOF
worker_processes auto;
worker_rlimit_nofile 20480;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
events { worker_connections 10240; }
stream {
    server {
        listen 5224;
        proxy_ssl on;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_pass ${SERVER_IP}:${NGINX_STREAM_IPERF_PORT};
        proxy_timeout 300s;
    }
    server {
        listen 5225;
        proxy_ssl on;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_pass ${SERVER_IP}:${NGINX_STREAM_HTTP_PORT};
        proxy_timeout 300s;
    }
}
EOF
    start_nginx_proxy bench-host-nginx-stream-cli "$OUTDIR/nginx-stream-client.conf" \
        || die "nginx stream client start failed"
    ok "nginx stream client on :5224->srv:${NGINX_STREAM_IPERF_PORT}(iperf) :5225->srv:${NGINX_STREAM_HTTP_PORT}(http)"

    cat > "$OUTDIR/nginx-http-client.conf" <<EOF
worker_processes auto;
worker_rlimit_nofile 20480;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
events { worker_connections 10240; }
stream {
    server {
        listen 5226;
        proxy_ssl on;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_pass ${SERVER_IP}:${NGINX_HTTP_PORT};
        proxy_timeout 300s;
    }
}
EOF
    start_nginx_proxy bench-host-nginx-http-cli "$OUTDIR/nginx-http-client.conf" \
        || die "nginx http client start failed"
    ok "nginx http client on :5226->srv:${NGINX_HTTP_PORT}(http)"
}

client_cleanup() {
    # Fresh-stack restarts replace the ingress process per cell, so INGRESS_PID
    # is often stale (and its number reusable). Kill the launcher by config path
    # instead, then the generic sweep for orphans from a crashed run.
    pkill -f "tng launch --config-file $OUTDIR/configs/ingress.json" 2>/dev/null || true
    pkill -f "tng launch" 2>/dev/null || true
    [ -n "${CTR:-}" ] && cleanup_containers bench-host-stunnel-client bench-host-stunnel-http-cli bench-host-haproxy-cli bench-host-nginx-stream-cli bench-host-nginx-http-cli
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
    local NG_STREAM_T="nginx:5224"
    local RAW_T="raw:"
    # Server-side sampling targets (host:kind:id) for the http workloads. tng/stunnel
    # id = the server-side listen port; haproxy id is unused (pgrep gathers master+workers).
    local SRV_TNG="${SERVER_IP}:tng:40003"
    local SRV_TNG_MUX="${SERVER_IP}:tng:40004"
    local SRV_OHTTP="${SERVER_IP}:tng:40005"
    local SRV_ST="${SERVER_IP}:stunnel:5211"
    local SRV_HP="${SERVER_IP}:haproxy:srv"
    # nginx ids = the server-side listen port of the instance being measured; the
    # kind sums every worker holding that port (kind: tng/stunnel use head -1).
    local SRV_NG_STREAM="${SERVER_IP}:nginx:5215"
    local SRV_NG_HTTP="${SERVER_IP}:nginx:5216"
    local _iperf_json='{}' out
    for s in ${streams_list//,/ }; do
        # Every workload cell with a proxy/tunnel process restarts that process
        # set first (fresh stack), so each cell's memory peak is its own cost.
        fresh_stack_tng "iperf3+rats-tls s=$s" "$SERVER_IP"
        out=$(run_iperf_median 127.0.0.1 50001 "$s" "iperf3+rats-tls" "$TNG_T")
        _iperf_json=$(json_add_iperf "$_iperf_json" "iperf3+rats-tls" "$s" "$out")
        fresh_stack_tng "iperf3+rats-tls+mux s=$s" "$SERVER_IP"
        out=$(run_iperf_median 127.0.0.1 50002 "$s" "iperf3+rats-tls+mux" "$TNG_T")
        _iperf_json=$(json_add_iperf "$_iperf_json" "iperf3+rats-tls+mux" "$s" "$out")
        out=$(run_iperf_median "$SERVER_IP" "$IPERF_PORT" "$s" "iperf3+raw" "$RAW_T")
        _iperf_json=$(json_add_iperf "$_iperf_json" "iperf3+raw" "$s" "$out")
        fresh_stack_containers "iperf3+stunnel s=$s" "$SERVER_IP" bench-host-stunnel-client 5220 bench-host-stunnel-server 5210
        out=$(run_iperf_median 127.0.0.1 5220 "$s" "iperf3+stunnel" "$ST_T")
        _iperf_json=$(json_add_iperf "$_iperf_json" "iperf3+stunnel" "$s" "$out")
        fresh_stack_containers "iperf3+haproxy s=$s" "$SERVER_IP" bench-host-haproxy-cli "5222 5223" bench-host-haproxy-srv "5212 5213"
        out=$(run_iperf_median 127.0.0.1 5223 "$s" "iperf3+haproxy" "$HP_T")
        _iperf_json=$(json_add_iperf "$_iperf_json" "iperf3+haproxy" "$s" "$out")
        fresh_stack_containers "iperf3+nginx-stream s=$s" "$SERVER_IP" bench-host-nginx-stream-cli "5224 5225" bench-host-nginx-stream-srv "5214 5215"
        out=$(run_iperf_median 127.0.0.1 5224 "$s" "iperf3+nginx-stream" "$NG_STREAM_T")
        _iperf_json=$(json_add_iperf "$_iperf_json" "iperf3+nginx-stream" "$s" "$out")
    done

    # The HTTP matrix runs once per scenario: keep-alive (report Scenario B, keys
    # "http+<wl>") and no keep-alive (Scenario C, keys "http-shortconn+<wl>"). The
    # results JSON is flat; the key prefix carries the scenario so both coexist and
    # keep-alive data stays readable by the old single-scenario report shape.
    local _http_json='{}'
    local prefix mode c
    for prefix_mode in "http+:keepalive" "http-shortconn+:shortconn"; do
        prefix="${prefix_mode%%:*}"; mode="${prefix_mode##*:}"
        for c in ${conns_list//,/ }; do
            fresh_stack_tng "${prefix}rats-tls c=$c" "$SERVER_IP"
            out=$(run_wrk_median "http://127.0.0.1:50003/file.bin" "$c" "${prefix}rats-tls" "$SRV_TNG" "$mode")
            _http_json=$(json_add_http "$_http_json" "${prefix}rats-tls" "$c" "$out")
            fresh_stack_tng "${prefix}rats-tls+mux c=$c" "$SERVER_IP"
            out=$(run_wrk_median "http://127.0.0.1:50004/file.bin" "$c" "${prefix}rats-tls+mux" "$SRV_TNG_MUX" "$mode")
            _http_json=$(json_add_http "$_http_json" "${prefix}rats-tls+mux" "$c" "$out")
            fresh_stack_tng "${prefix}ohttp c=$c" "$SERVER_IP"
            out=$(run_wrk_median "http://127.0.0.1:50005/file.bin" "$c" "${prefix}ohttp" "$SRV_OHTTP" "$mode")
            _http_json=$(json_add_http "$_http_json" "${prefix}ohttp" "$c" "$out")
            out=$(run_wrk_median "http://${SERVER_IP}:${NGINX_PORT}/file.bin" "$c" "${prefix}raw" "$RAW_T" "$mode")
            _http_json=$(json_add_http "$_http_json" "${prefix}raw" "$c" "$out")
            fresh_stack_containers "${prefix}stunnel c=$c" "$SERVER_IP" bench-host-stunnel-http-cli 5221 bench-host-stunnel-http-srv 5211
            out=$(run_wrk_median "http://127.0.0.1:5221/file.bin" "$c" "${prefix}stunnel" "$SRV_ST" "$mode")
            _http_json=$(json_add_http "$_http_json" "${prefix}stunnel" "$c" "$out")
            fresh_stack_containers "${prefix}haproxy c=$c" "$SERVER_IP" bench-host-haproxy-cli "5222 5223" bench-host-haproxy-srv "5212 5213"
            out=$(run_wrk_median "http://127.0.0.1:5222/file.bin" "$c" "${prefix}haproxy" "$SRV_HP" "$mode")
            _http_json=$(json_add_http "$_http_json" "${prefix}haproxy" "$c" "$out")
            fresh_stack_containers "${prefix}nginx-stream c=$c" "$SERVER_IP" bench-host-nginx-stream-cli "5224 5225" bench-host-nginx-stream-srv "5214 5215"
            out=$(run_wrk_median "http://127.0.0.1:5225/file.bin" "$c" "${prefix}nginx-stream" "$SRV_NG_STREAM" "$mode")
            _http_json=$(json_add_http "$_http_json" "${prefix}nginx-stream" "$c" "$out")
            fresh_stack_containers "${prefix}nginx-http c=$c" "$SERVER_IP" bench-host-nginx-http-cli 5226 bench-host-nginx-http-srv 5216
            out=$(run_wrk_median "http://127.0.0.1:5226/file.bin" "$c" "${prefix}nginx-http" "$SRV_NG_HTTP" "$mode")
            _http_json=$(json_add_http "$_http_json" "${prefix}nginx-http" "$c" "$out")
        done
    done

    python3 -c "import json,sys; a=json.loads(sys.argv[1]); b=json.loads(sys.argv[2]); a.update(b); print(json.dumps(a))" "$_iperf_json" "$_http_json" > "$OUTDIR/bench-results.json"
}

preflight
verify_tng_build
pull_tools
start_ingress
collect_info "$OUTDIR/client-info.json" client
run_all
log "Done. Results: $OUTDIR/bench-results.json; client info: $OUTDIR/client-info.json"
log "Generate the report with: bash bench/gen-report.sh <server-info.json> $OUTDIR/client-info.json $OUTDIR/bench-results.json"
