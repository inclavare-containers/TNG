#!/usr/bin/env bash
# bench/server.sh - run on the server (P) host. Starts backends + TNG egress, stays foreground.
# Usage: bash bench/server.sh [--output-dir DIR]
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

OUTDIR="$(make_outdir)"
while [ $# -gt 0 ]; do
    case "$1" in
        --output-dir) shift; OUTDIR="$(make_outdir "$1")"; shift;;
        *) shift;;
    esac
done

TNG_BIN="${TNG_BIN:-./target/release/tng}"
IPERF_PORT=5201
NGINX_PORT=8080
CTR_NAME_IPERF="bench-host-iperf3-server"
CTR_NAME_NGINX="bench-host-nginx"
CTR_NAME_STUNNEL="bench-host-stunnel-server"
CTR_NAME_STUNNEL_HTTP="bench-host-stunnel-http-srv"
CTR_NAME_HAPROXY="bench-host-haproxy-srv"

preflight() {
    command -v python3 &>/dev/null || die "python3 not found"
    command -v openssl &>/dev/null || die "openssl not found (needed for stunnel cert)"
    [ -x "$TNG_BIN" ] || die "TNG binary not found at $TNG_BIN (build: cargo build --release -p tng)"
    # Clear orphaned tng egress / backend containers from a previous (crashed) run.
    pkill -f "tng launch" 2>/dev/null || true
    command -v podman &>/dev/null && podman rm -f "$CTR_NAME_IPERF" "$CTR_NAME_NGINX" "$CTR_NAME_STUNNEL" "$CTR_NAME_STUNNEL_HTTP" "$CTR_NAME_HAPROXY" 2>/dev/null || true
    ensure_runtime
}

pull_all() {
    pull_image mirrors-ssl.aliyuncs.com/networkstatic/iperf3:latest networkstatic/iperf3:latest
    IPERF3_IMAGE="$RESOLVED_IMAGE"; IPERF3_SOURCE="$RESOLVED_IMAGE_SOURCE"
    IPERF3_DIGEST="$(image_digest "$IPERF3_IMAGE")"
    IPERF3_VERSION="$(image_version "$IPERF3_IMAGE" iperf3 --version)"
    ok "iperf3: $IPERF3_VERSION"
    # Warn (not fail) if iperf3 < 3.21; pthreads server-side parallelism matters.
    _v=$(echo "$IPERF3_VERSION" | grep -oE '3\.[0-9]+' | head -1)
    if [ -n "$_v" ]; then
        python3 -c "
import sys
v = sys.argv[1].split('.')
bad = not (int(v[0]) > 3 or (int(v[0]) == 3 and int(v[1]) >= 21))
if bad: print('\033[1;33m  ! iperf3 %s < 3.21, pthreads server-side parallelism may be missing\033[0m' % sys.argv[1])
" "$_v" 2>/dev/null || true
    fi

    pull_image mirrors-ssl.aliyuncs.com/library/nginx:stable-alpine lscr.io/linuxserver/nginx:latest
    NGINX_IMAGE="$RESOLVED_IMAGE"; NGINX_SOURCE="$RESOLVED_IMAGE_SOURCE"
    NGINX_DIGEST="$(image_digest "$NGINX_IMAGE")"
    NGINX_VERSION="$("$CTR" run --rm --network host "$NGINX_IMAGE" nginx -v 2>&1 | grep -i 'nginx version' | head -1 || true)"

    pull_image mirrors-ssl.aliyuncs.com/dockurr/stunnel:latest dockurr/stunnel:latest
    STUNNEL_IMAGE="$RESOLVED_IMAGE"; STUNNEL_SOURCE="$RESOLVED_IMAGE_SOURCE"
    STUNNEL_DIGEST="$(image_digest "$STUNNEL_IMAGE")"
    STUNNEL_VERSION="$("$CTR" run --rm --network host --entrypoint stunnel "$STUNNEL_IMAGE" -version 2>&1 | grep -m1 'stunnel [0-9]' || true)"

    pull_image mirrors-ssl.aliyuncs.com/library/haproxy:latest docker.io/library/haproxy:latest
    HAPROXY_IMAGE="$RESOLVED_IMAGE"; HAPROXY_SOURCE="$RESOLVED_IMAGE_SOURCE"
    HAPROXY_DIGEST="$(image_digest "$HAPROXY_IMAGE")"
    HAPROXY_VERSION="$("$CTR" run --rm "$HAPROXY_IMAGE" haproxy -v 2>&1 | head -1)"
}

start_backends() {
    "$CTR" rm -f "$CTR_NAME_IPERF" >/dev/null 2>&1 || true
    "$CTR" run -d --name "$CTR_NAME_IPERF" --network host \
        "$IPERF3_IMAGE" iperf3 -s || die "iperf3 server start failed"
    ok "iperf3 server on :$IPERF_PORT"

    mkdir -p "$OUTDIR/nginx/www" "$OUTDIR/nginx/conf.d"
    # Regular-sized HTTP body for the http workloads: small enough that per-request
    # latency is not dominated by transfer time, large enough that throughput (Gbps)
    # stays measurable. 64 KiB default; tune via HTTP_BODY_KB.
    dd if=/dev/zero of="$OUTDIR/nginx/www/file.bin" bs=1K count="${HTTP_BODY_KB:-64}" status=none
    cat > "$OUTDIR/nginx/conf.d/default.conf" <<EOF
server { listen ${NGINX_PORT}; root /usr/share/nginx/html; }
EOF
    "$CTR" rm -f "$CTR_NAME_NGINX" >/dev/null 2>&1 || true
    "$CTR" run -d --name "$CTR_NAME_NGINX" --network host \
        -v "$OUTDIR/nginx/www:/usr/share/nginx/html:ro" \
        -v "$OUTDIR/nginx/conf.d:/etc/nginx/conf.d:ro" \
        "$NGINX_IMAGE" || die "nginx start failed"
    ok "nginx on :$NGINX_PORT serving file.bin"

    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$OUTDIR/stunnel.pem" \
        -out "$OUTDIR/stunnel.pem" -subj "/CN=localhost" 2>/dev/null
    chmod 644 "$OUTDIR/stunnel.pem"   # HAProxy -W workers drop to the haproxy user; 600 (root) blocks them.
    cat > "$OUTDIR/stunnel-server.conf" <<EOF
foreground = yes
[bench]
accept = 5210
connect = 127.0.0.1:${IPERF_PORT}
cert = /etc/stunnel/stunnel.pem
EOF
    "$CTR" rm -f "$CTR_NAME_STUNNEL" >/dev/null 2>&1 || true
    "$CTR" run -d --name "$CTR_NAME_STUNNEL" --network host --entrypoint stunnel \
        -v "$OUTDIR/stunnel-server.conf:/etc/stunnel/stunnel.conf:ro" \
        -v "$OUTDIR/stunnel.pem:/etc/stunnel/stunnel.pem:ro" \
        "$STUNNEL_IMAGE" /etc/stunnel/stunnel.conf \
        || die "stunnel server start failed"
    ok "stunnel server on :5210 -> 127.0.0.1:${IPERF_PORT}"

    # stunnel server for the http+stunnel baseline: :5211 -> nginx (127.0.0.1:8080)
    cat > "$OUTDIR/stunnel-http-server.conf" <<EOF
foreground = yes
[bench]
accept = 5211
connect = 127.0.0.1:${NGINX_PORT}
cert = /etc/stunnel/stunnel.pem
EOF
    "$CTR" rm -f "$CTR_NAME_STUNNEL_HTTP" >/dev/null 2>&1 || true
    "$CTR" run -d --name "$CTR_NAME_STUNNEL_HTTP" --network host --entrypoint stunnel \
        -v "$OUTDIR/stunnel-http-server.conf:/etc/stunnel/stunnel.conf:ro" \
        -v "$OUTDIR/stunnel.pem:/etc/stunnel/stunnel.pem:ro" \
        "$STUNNEL_IMAGE" /etc/stunnel/stunnel.conf \
        || die "stunnel http server start failed"
    ok "stunnel http server on :5211 -> 127.0.0.1:${NGINX_PORT}"

    # HAProxy (modern multi-threaded TLS proxy baseline). TLS frontends -> plain backends.
    cat > "$OUTDIR/haproxy-server.cfg" <<EOF
global
    nbthread ${HAPROXY_THREADS:-4}
defaults
    mode tcp
    timeout connect 5s
    timeout client 30s
    timeout server 30s
frontend fe_iperf
    bind :5213 ssl crt /etc/haproxy/cert.pem
    default_backend be_iperf
backend be_iperf
    server iperf3 127.0.0.1:${IPERF_PORT}
frontend fe_http
    bind :5212 ssl crt /etc/haproxy/cert.pem
    default_backend be_http
backend be_http
    server nginx 127.0.0.1:${NGINX_PORT}
EOF
    "$CTR" rm -f "$CTR_NAME_HAPROXY" >/dev/null 2>&1 || true
    "$CTR" run -d --name "$CTR_NAME_HAPROXY" --network host \
        -v "$OUTDIR/haproxy-server.cfg:/etc/haproxy/haproxy.cfg:ro" \
        -v "$OUTDIR/stunnel.pem:/etc/haproxy/cert.pem:ro" \
        "$HAPROXY_IMAGE" haproxy -f /etc/haproxy/haproxy.cfg -W \
        || die "haproxy server start failed"
    ok "haproxy server on :5213->iperf3 :5212->nginx (TLS, ${HAPROXY_THREADS:-4} threads)"
}

start_egress() {
    # RA_MODE=1: enable remote attestation (attest via AA socket on this TEE host).
    if [ "${RA_MODE:-0}" = "1" ]; then
        RA_OPT='"no_ra": false, "attest": {"aa_type": "uds", "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"}'
        ok "RA enabled: attest via AA socket"
    else
        RA_OPT='"no_ra": true'
    fi
    cat > "$OUTDIR/configs/egress.json" <<EOF
{
  "add_egress": [
    {"mapping":{"in":{"host":"0.0.0.0","port":40001},"out":{"host":"127.0.0.1","port":${IPERF_PORT}}},"rats_tls":{"multiplex":false},${RA_OPT}},
    {"mapping":{"in":{"host":"0.0.0.0","port":40002},"out":{"host":"127.0.0.1","port":${IPERF_PORT}}},"rats_tls":{"multiplex":true},${RA_OPT}},
    {"mapping":{"in":{"host":"0.0.0.0","port":40003},"out":{"host":"127.0.0.1","port":${NGINX_PORT}}},"rats_tls":{"multiplex":false},${RA_OPT}},
    {"mapping":{"in":{"host":"0.0.0.0","port":40004},"out":{"host":"127.0.0.1","port":${NGINX_PORT}}},"rats_tls":{"multiplex":true},${RA_OPT}},
    {"mapping":{"in":{"host":"0.0.0.0","port":40005},"out":{"host":"127.0.0.1","port":${NGINX_PORT}}},"ohttp":{},${RA_OPT}}
  ]
}
EOF
    "$TNG_BIN" launch --config-file "$OUTDIR/configs/egress.json" > "$OUTDIR/logs/egress.log" 2>&1 &
    EGRESS_PID=$!
    sleep 2
    ss -tlnp 2>/dev/null | grep -q ":40001" || { fail "TNG egress not listening"; tail -20 "$OUTDIR/logs/egress.log"; exit 1; }
    ok "TNG egress listening on 40001-40005"
}

server_cleanup() {
    [ -n "${EGRESS_PID:-}" ] && kill_pids "$EGRESS_PID" 2>/dev/null || true
    pkill -f "tng launch" 2>/dev/null || true
    [ -n "${CTR:-}" ] && cleanup_containers "$CTR_NAME_IPERF" "$CTR_NAME_NGINX" "$CTR_NAME_STUNNEL" "$CTR_NAME_STUNNEL_HTTP" "$CTR_NAME_HAPROXY"
    log "server cleaned up"
}
trap server_cleanup EXIT

preflight
pull_all
# Record server-side info (host env + iperf3/nginx/stunnel tool metadata) for the report generator.
collect_info "$OUTDIR/server-info.json" server
ok "server-side info written to $OUTDIR/server-info.json"
start_backends
start_egress

log "============================================="
log "  Server ready. Tell the client this IP:"
log "  $(hostname -I 2>/dev/null | awk '{print $1}')"
log "  iperf3 raw :${IPERF_PORT} | nginx :${NGINX_PORT} | stunnel iperf3 :5210 | stunnel http :5211 | haproxy :5213/:5212"
log "  TNG egress :40001-40005"
log "  Output dir: $OUTDIR"
log "  Press Ctrl-C when the client is done."
log "============================================="
wait
