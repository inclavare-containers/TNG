#!/usr/bin/env bash
# daemon.sh — sourced by run.sh. Defines ONLY run_daemon().
#
# Owns the daemon method (method 1 of 4). Starts a TNG daemon on
# 127.0.0.1:$PROXY_PORT, routes the canonical completions request
# through it via all_proxy, and asserts that streamed model tokens come back.
#
# Globals used (set by the main arg parser before this is called):
#   AS_MODE  builtin|external
#   AS_URL   external attestation-service URL
#   COMPLETIONS_URL  full /v1/completions URL
#   TOKEN    Authorization header value
#   MODEL    model name
#   PROXY_PORT  local proxy listen port
#   TNG_BIN   command prefix, e.g. 'cargo run --release --'
#   REPO     /root/tng.fix-python-sdk
#   WORKDIR  temp dir
#   KEEP     1 = leave the daemon running / keep temp files
#
# Helpers (from the main script): log MSG | pass METHOD | fail METHOD REASON
#                              | skip METHOD REASON | cleanup_tng

run_daemon() {
    local method="daemon"
    local pid=""
    local pgid=""
    local cleaned=0
    local log="$WORKDIR/tng_daemon.log"
    : >"$log" 2>/dev/null || true

    # --- cleanup: kill the daemon we started unless KEEP==1. Idempotent so the
    # EXIT trap and explicit calls are both safe. Escalates SIGTERM→SIGKILL so a
    # hung tng can't keep the proxy port bound and block the next run.
    #
    # We launch the daemon in its own process group (setsid) so a single
    # `kill -- -pgid` reaps the whole tree — cargo + rustc + tng — instead of
    # orphaning grandchildren (kill on the subshell pid alone leaves cargo/tng
    # reparented to init and still running).
    _daemon_cleanup() {
        [ "$cleaned" = "1" ] && return 0
        cleaned=1
        if [ "${KEEP:-0}" = "1" ]; then return 0; fi
        # 1) Kill the whole daemon process group (cargo + rustc + tng).
        [ -n "$pgid" ] && kill -- -"$pgid" 2>/dev/null
        # 2) Kill whatever is listening on the proxy port (handles the real
        #    `target/release/tng` binary spawned by a `cargo run` wrapper, and
        #    the no-setsid fallback path).
        local listener
        listener=$(ss -tlnp 2>/dev/null | grep ":$PROXY_PORT " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
        [ -n "$listener" ] && kill "$listener" 2>/dev/null
        # 3) Kill the cargo/tng wrapper PID we captured.
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
        # 4) Fallback: any lingering tng launch process.
        pkill -f "target/release/tng launch" 2>/dev/null
        # Escalate: a stuck tng may ignore SIGTERM. SIGKILL anything still alive.
        sleep 1
        [ -n "$pgid" ] && kill -9 -- -"$pgid" 2>/dev/null
        [ -n "$listener" ] && kill -9 "$listener" 2>/dev/null
        [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
        pkill -9 -f "target/release/tng launch" 2>/dev/null
        [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
    }
    # Safety net for abnormal termination (SIGINT/SIGTERM/EXIT) between calls.
    # On normal return each path restores the outer cleanup_tng trap (the bare
    # `trap -` the old code used wiped it, leaving WORKDIR un-cleaned afterwards).
    #
    # _daemon_cleanup only kills the daemon and returns — it does NOT exit, so
    # explicit fail-path callers can `return` and let `-m all` continue to the
    # next method. A signal handler that did the same would be useless: in a
    # non-interactive script an INT/TERM trap that returns just resumes the
    # loop, so Ctrl-C looked inert while heartbeats kept printing. _daemon_abort
    # cleans up AND exits the whole script.
    _daemon_abort() {
        echo >&2
        log "interrupted by signal; cleaning up daemon and exiting"
        _daemon_cleanup
        trap - INT TERM EXIT
        trap cleanup_tng EXIT
        exit 130
    }
    trap _daemon_abort INT TERM
    trap _daemon_cleanup EXIT

    # 1. Build the launch config JSON.
    local verify_block
    if [ "$AS_MODE" = "builtin" ]; then
        # No variable expansion needed here; quoted heredoc keeps it literal.
        verify_block=$(cat <<'EOF'
"verify": {
        "model": "background_check",
        "as_type": "builtin",
        "attestation_policy": {"type": "default"},
        "reference_values": []
    }
EOF
)
    else
        verify_block=$(cat <<EOF
"verify": {
        "model": "background_check",
        "as_addr": "$AS_URL",
        "policy_ids": ["default"]
    }
EOF
)
    fi

    local cfg
    cfg=$(cat <<EOF
{
    "add_ingress": [{
        "http_proxy": {
            "proxy_listen": {"host": "127.0.0.1", "port": $PROXY_PORT}
        },
        "ohttp": {
            "path_default": "original"
        },
        $verify_block
    }]
}
EOF
)

    log "launching tng daemon ($AS_MODE AS) on 127.0.0.1:$PROXY_PORT (TNG_BIN=$TNG_BIN, startup_timeout=${STARTUP_TIMEOUT}s)"

    # 2. Start the daemon in its own process group (setsid) so cleanup can reap
    #    the whole cargo+rustc+tng tree with one `kill -- -pgid`. stdout+stderr
    #    go to $log so any failure is always diagnosable. Config is passed via
    #    env to avoid quoting headaches in the inner `bash -c`.
    # shellcheck disable=SC2086
    if command -v setsid >/dev/null 2>&1; then
        TNG_DAEMON_CFG="$cfg" TNG_BIN="$TNG_BIN" REPO="$REPO" setsid bash -c \
            'cd "$REPO" && exec $TNG_BIN launch --config-content "$TNG_DAEMON_CFG"' \
            >"$log" 2>&1 &
        pid=$!
        # setsid child is a session leader → its pgid == its pid. Read it back
        # to be safe (in case setsid forked); fall back to $pid.
        pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
        [ -z "$pgid" ] && pgid="$pid"
    else
        ( cd "$REPO" && $TNG_BIN launch --config-content "$cfg" ) >"$log" 2>&1 &
        pid=$!
        pgid=""
    fi

    # 3. Wait for the proxy port (or an early launch failure) with a heartbeat.
    #    A slow `cargo run` build or a tng stuck on RA/AS init used to look like
    #    a silent hang; now every 5s we print the last non-empty daemon log line
    #    so you can tell "still compiling" / "stuck on X" from a dead harness.
    local i=0 last
    while :; do
        i=$((i+1))
        # Early failure detected in the daemon log? ("address already in use"
        # catches a stale daemon from a previous run that didn't exit.)
        if grep -qiE "unknown variant|panic|failed to load config|error\[|error:|address already in use|fatal|cannot bind" "$log" 2>/dev/null; then
            if [ "$AS_MODE" = "builtin" ] && grep -qi "unknown variant.*builtin" "$log" 2>/dev/null; then
                skip "$method" "builtin AS needs a builtin-as-* build (docker image)"
                _daemon_cleanup
                trap cleanup_tng EXIT INT TERM
                return 0
            fi
            fail "$method" "tng launch failed (see daemon log below)"
            logtail "$log" >&2
            _daemon_cleanup
            trap cleanup_tng EXIT INT TERM
            return 1
        fi
        if ss -tlnp 2>/dev/null | grep -q ":$PROXY_PORT "; then
            break
        fi
        # Persistent remote-fetch failure (e.g. wrong --as-url → 4xx on the AS
        # certificate endpoint): tng retries forever and never opens the port.
        # After a short grace so a single transient blip can't false-fail, bail
        # with the log instead of hanging all the way to startup_timeout.
        if [ "$i" -ge "$AS_GRACE" ] && grep -qiE "HTTP status client error" "$log" 2>/dev/null; then
            fail "$method" "tng stuck fetching AS/remote resource — check --as-url/--completions-url (see daemon log below)"
            logtail "$log" >&2
            _daemon_cleanup
            trap cleanup_tng EXIT INT TERM
            return 1
        fi
        if [ "$i" -ge "$STARTUP_TIMEOUT" ]; then
            fail "$method" "proxy port $PROXY_PORT not listening after ${STARTUP_TIMEOUT}s (see daemon log below)"
            logtail "$log" >&2
            _daemon_cleanup
            trap cleanup_tng EXIT INT TERM
            return 1
        fi
        if [ $((i % 5)) -eq 0 ]; then
            last=$(grep -vE '^[[:space:]]*$' "$log" 2>/dev/null | tail -1)
            log "  waiting for port $PROXY_PORT (${i}/${STARTUP_TIMEOUT}s)… ${last:0:140}"
        fi
        sleep 1
    done

    log "daemon ready; sending canonical completions request (timeout ${REQ_TIMEOUT}s)"

    # 4. Send the canonical completions request through the proxy.
    #    Run curl in the background and heartbeat the daemon log while waiting,
    #    because tng may hang on AS/OHTTP verification without writing anything
    #    to curl's stderr — that used to look like a silent 60s hang.
    local body
    body=$(cat <<EOF
{"model":"$MODEL","prompt":"Do you know the book Traction by Gino Wickman","temperature":0.0,"best_of":1,"max_tokens":132,"stream":true}
EOF
)

    local resp_file="$WORKDIR/daemon_resp.txt"
    : >"$resp_file" 2>/dev/null || true
    env all_proxy="http://127.0.0.1:$PROXY_PORT/" \
        curl -sS -N --max-time "$REQ_TIMEOUT" "$COMPLETIONS_URL" \
        -X POST \
        -H "Authorization: $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$body" >"$resp_file" 2>&1 &
    local curl_pid=$!

    local j=0
    while kill -0 "$curl_pid" 2>/dev/null; do
        j=$((j+1))
        if [ "$j" -ge "$((REQ_TIMEOUT + 5))" ]; then
            kill "$curl_pid" 2>/dev/null
            break
        fi
        if [ $((j % 5)) -eq 0 ]; then
            last=$(grep -vE '^[[:space:]]*$' "$log" 2>/dev/null | tail -1)
            log "  waiting for model response (${j}/${REQ_TIMEOUT}s)… daemon: ${last:0:140}"
        fi
        sleep 1
    done
    wait "$curl_pid" 2>/dev/null
    local curl_rc=$?

    # 5. Evaluate. On any failure, dump BOTH the curl output and the daemon log
    #    so a hung tng (empty/timeout response) is diagnosable instead of silent.
    if grep -qE 'data:|"text"|"choices"' "$resp_file" 2>/dev/null; then
        pass "$method"
        _daemon_cleanup
        trap cleanup_tng EXIT INT TERM
        return 0
    fi

    fail "$method" "no model response (curl rc=$curl_rc; see curl output + daemon log below)"
    { echo "### curl output ($resp_file):"; cat "$resp_file" 2>/dev/null; } >&2
    logtail "$log" >&2
    _daemon_cleanup
    trap cleanup_tng EXIT INT TERM
    return 1
}
