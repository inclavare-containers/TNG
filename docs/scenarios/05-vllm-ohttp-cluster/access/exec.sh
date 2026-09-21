#!/usr/bin/env bash
# exec.sh — sourced by run.sh; defines run_exec() only.
#
# Method: `tng exec` (LD_PRELOAD hook) as a daemon alternative. Unlike the
# daemon method (http_proxy + all_proxy), here the client command runs as a
# child of `tng exec` with libtng_hook.so preloaded. The hook intercepts the
# child's outgoing connect() to the capture_dst port and transparently routes
# the connection through TNG's OHTTP+verify tunnel — the child (curl) needs no
# proxy environment, it just hits the URL directly.
#
# Globals used (set by run.sh before this is called):
#   AS_MODE  builtin|external
#   AS_URL   external attestation-service URL (unused under builtin)
#   COMPLETIONS_URL  full /v1/completions URL
#   TOKEN    Authorization header value
#   MODEL    model name (auto-detected upstream if omitted)
#   TNG_BIN  command prefix, e.g. 'cargo run --release --' or a binary path
#   REPO     repo root
#   WORKDIR  temp dir
#   KEEP     1 = leave the child / keep temp files
#   REQ_TIMEOUT  seconds for the inference request
# Helpers (from run.sh): log | pass | fail | skip | verify_json | logtail

run_exec() {
    local method="exec"
    local log="$WORKDIR/tng_exec.log"
    : >"$log" 2>/dev/null || true

    # --- Resolve a real tng binary (cargo run works but slows each invocation;
    # prefer a prebuilt one so the hook lib sits beside it). ---
    local tngpath=""
    if [[ -n "${TNG_BINARY:-}" && -f "$TNG_BINARY" ]]; then
        tngpath="$TNG_BINARY"
    fi
    if [[ -z "$tngpath" ]] && [[ -x "$REPO/target/release/tng" ]]; then
        tngpath="$REPO/target/release/tng"
    elif [[ -z "$tngpath" ]] && [[ -x "$REPO/target/debug/tng" ]]; then
        tngpath="$REPO/target/debug/tng"
    fi
    if [[ -z "$tngpath" ]]; then
        skip "$method" "no prebuilt tng binary (run cargo build --release); TNG_BIN='$TNG_BIN'"
        return 0
    fi

    # --- libtng_hook.so must exist beside the binary (or via $TNG_HOOK_LIB). ---
    local hooklib="${TNG_HOOK_LIB:-}"
    if [[ -z "$hooklib" ]]; then
        local bindir
        bindir="$(dirname "$tngpath")"
        hooklib="$bindir/libtng_hook.so"
    fi
    if [[ ! -f "$hooklib" ]]; then
        skip "$method" "libtng_hook.so not found (set \$TNG_HOOK_LIB or run: make tng-hook-build)"
        return 0
    fi
    export TNG_HOOK_LIB="$hooklib"

    # --- capture_dst port: parse from the completions URL (http→80, https→443,
    # or an explicit :port). The hook only intercepts this destination port, so
    # the child's other traffic (e.g. DNS) is untouched. ---
    local port urlport
    case "$COMPLETIONS_URL" in
        https://*) port=443;;
        http://*)  port=80;;
        *)         port=80;;
    esac
    urlport=$(printf '%s' "$COMPLETIONS_URL" | sed -nE 's#^[a-z]+://[^/]*:([0-9]+).*#\1#p')
    [[ -n "$urlport" ]] && port="$urlport"

    local cfg
    cfg=$(printf '{"add_ingress":[{"hook":{"capture_dst":[{"port":%s}]},"ohttp":{"path_default":"original"},"verify":%s}]}' \
          "$port" "$(verify_json)")

    log "launching tng exec (hook LD_PRELOAD) for port $port (hook=$hooklib)"

    # tng exec runs the child and exits when it does, so there's no long-lived
    # daemon to babysit — a single invocation suffices.
    local body
    body=$(cat <<EOF
{"model":"$MODEL","prompt":"Do you know the book Traction by Gino Wickman","temperature":0.0,"best_of":1,"max_tokens":132,"stream":true}
EOF
)

    local body_file="$WORKDIR/exec_body.txt"
    : >"$body_file" 2>/dev/null || true

    # Run tng exec with curl as the child. The hook intercepts curl's
    # connect() to the completions URL and tunnels it through TNG. Body →
    # body_file (clean, for the strict validator). tng exec's own tracing
    # mixes onto the child's stdout, so we can't read an HTTP status from
    # there; a non-2xx vLLM reply carries an {"error":...} body which the
    # validator rejects, so status is covered by body validation. Wrap in
    # timeout so a stuck hook/OHTTP stage can't hang past REQ_TIMEOUT.
    local run_prefix=""
    if command -v timeout >/dev/null 2>&1; then
        run_prefix="timeout $((REQ_TIMEOUT + 30))"
    fi

    (
        cd "$REPO"
        $run_prefix "$tngpath" exec --config-content "$cfg" -- \
            curl -sS -N --max-time "$REQ_TIMEOUT" -o "$body_file" "$COMPLETIONS_URL" \
            -X POST \
            -H "Authorization: $TOKEN" \
            -H "Content-Type: application/json" \
            -d "$body"
    ) >"$log" 2>&1 &
    local cpid=$!

    local j=0
    while kill -0 "$cpid" 2>/dev/null; do
        j=$((j+1))
        if [ "$j" -ge "$((REQ_TIMEOUT + 45))" ]; then
            kill "$cpid" 2>/dev/null; sleep 1; kill -9 "$cpid" 2>/dev/null
            break
        fi
        if [ $((j % 5)) -eq 0 ]; then
            local last
            last=$(grep -vE '^[[:space:]]*$' "$log" 2>/dev/null | tail -1)
            log "  waiting for exec (${j}s)… ${last:0:140}"
        fi
        sleep 1
    done
    wait "$cpid" 2>/dev/null; local rc=$?

    # Surface a tng-side failure (config reject, missing hook lib, RA/OHTTP
    # failure) clearly: the child curl gets nothing back in those cases. The
    # "not found" keyword covers `libtng_hook.so not found.`; we don't grep for
    # the bare lib name because the normal "Resolved hook library path" line
    # mentions it.
    if grep -qiE "not found|unknown variant|panic|failed to load config|error\[|error:|fatal|cannot bind|tng exec requires" "$log" 2>/dev/null; then
        fail "$method" "tng exec failed (rc=$rc; see exec log below)"
        logtail "$log" >&2
        return 1
    fi

    # Strict: require a valid vLLM completion body (non-empty choices text,
    # model match, [DONE]); a grep on "data:" alone would pass on a truncated
    # or error-shaped response.
    if [ "$rc" -eq 0 ] && validate_response "$body_file" "$MODEL"; then
        pass "$method"
        return 0
    fi

    fail "$method" "invalid/no model response (rc=$rc; see body + exec log below)"
    {
        printf -- '--- body (%s) ---\n' "$body_file"
        head -c 2000 "$body_file" 2>/dev/null
        printf -- '\n--- end ---\n'
    } >&2
    logtail "$log" >&2
    return 1
}
