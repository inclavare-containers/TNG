#!/usr/bin/env bash
# Internal test for the 05-vllm-ohttp-cluster scenario: exercise TNG's 4
# access methods (daemon / python / go / wasm) end-to-end.
#
# The four method implementations live in ./access/ (daemon.sh, python.sh,
# go.sh, wasm.sh) and are sourced by this entry; each defines only its
# run_<method>() function, sharing the globals/helpers set below.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKDIR="$(mktemp -d -t tngtest.XXXXXX)"
TNG_TEST_PIDS=()

# ---- defaults ---------------------------------------------------------------
METHOD="${TNG_TEST_METHOD:-all}"
AS_MODE="external"
AS_URL="${TNG_TEST_AS_URL:-}"
COMPLETIONS_URL="${TNG_TEST_COMPLETIONS_URL:-}"
TOKEN="${TNG_TEST_TOKEN:-}"
# Empty default: auto-detect the served model via /v1/models (see detect_model).
MODEL="${TNG_TEST_MODEL:-}"
PROXY_PORT="${TNG_TEST_PROXY_PORT:-41000}"
TNG_BIN="${TNG_TEST_BIN:-cargo run --release --}"
KEEP=0
# Per-phase timeouts (s) for the daemon method, overridable via env. Generous
# startup default because `cargo run --release` may recompile on first use.
STARTUP_TIMEOUT="${TNG_TEST_STARTUP_TIMEOUT:-240}"
REQ_TIMEOUT="${TNG_TEST_REQ_TIMEOUT:-90}"
# Grace (s) before fast-failing on a persistent AS/remote 4xx during daemon
# startup, so a wrong --as-url/--completions-url doesn't hang the test out to
# startup_timeout. tng retries such fetches forever and never opens the port.
AS_GRACE="${TNG_TEST_AS_GRACE:-15}"

# COMPLETIONS_BASE = COMPLETIONS_URL up to and including /v1
COMPLETIONS_BASE="${COMPLETIONS_URL%/v1/*}/v1"

# ---- helpers ----------------------------------------------------------------
log()  { printf '[tngtest] %s\n' "$*" >&2; }
pass() { printf 'PASS\t%s\n' "$1"; }
fail() { printf 'FAIL\t%s\t%s\n' "$1" "$2"; }
skip() { printf 'SKIP\t%s\t%s\n' "$1" "$2"; }

# logtail FILE [LINES] — print the last LINES (default 30) of FILE, framed so
# failure diagnostics are easy to spot. Used to surface daemon logs on failure.
logtail() {
  local f="$1" n="${2:-30}"
  if [ ! -f "$f" ]; then
    printf '(no log file: %s)\n' "$f"
    return 0
  fi
  printf -- '--- %s (last %s lines) ---\n' "$f" "$n"
  tail -n "$n" "$f" 2>/dev/null
  printf -- '--- end ---\n'
}

# verify_json — echo the verify config JSON object for the current AS_MODE.
# Shared by detect_model and the exec method so builtin/external stay in sync
# with daemon.sh's branch.
verify_json() {
  if [ "$AS_MODE" = "builtin" ]; then
    printf '{"model":"background_check","as_type":"builtin","attestation_policy":{"type":"default"},"reference_values":[]}'
  else
    printf '{"model":"background_check","as_addr":"%s","policy_ids":["default"]}' "$AS_URL"
  fi
}

# detect_model — auto-detect the served model by listing /v1/models through a
# one-shot TNG http_proxy daemon. Sets MODEL on success, bails on failure.
# Used when --model is omitted so the test works against any vLLM deployment
# without the caller knowing the model id up front.
detect_model() {
  local log="$WORKDIR/tng_detect.log"
  : >"$log" 2>/dev/null || true
  local cfg
  cfg=$(printf '{"add_ingress":[{"http_proxy":{"proxy_listen":{"host":"127.0.0.1","port":%s}},"ohttp":{"path_default":"original"},"verify":%s}]}' \
        "$PROXY_PORT" "$(verify_json)")

  log "auto-detecting model via /v1/models (one-shot daemon on 127.0.0.1:$PROXY_PORT)"
  if command -v setsid >/dev/null 2>&1; then
    TNG_DAEMON_CFG="$cfg" TNG_BIN="$TNG_BIN" REPO="$REPO" setsid bash -c \
      'cd "$REPO" && exec $TNG_BIN launch --config-content "$TNG_DAEMON_CFG"' >"$log" 2>&1 &
  else
    ( cd "$REPO" && $TNG_BIN launch --config-content "$cfg" ) >"$log" 2>&1 &
  fi
  local dpid=$!

  local i=0
  while :; do
    if grep -qiE "unknown variant|panic|failed to load config|error\[|error:|address already in use|fatal|cannot bind" "$log" 2>/dev/null; then
      log "model detection failed: tng launch error (see $log)"; logtail "$log" >&2
      kill "$dpid" 2>/dev/null; _kill_port "$PROXY_PORT"
      return 1
    fi
    if ss -tlnp 2>/dev/null | grep -q ":$PROXY_PORT "; then break; fi
    if [ "$i" -ge "$STARTUP_TIMEOUT" ]; then
      log "model detection failed: port $PROXY_PORT not up after ${STARTUP_TIMEOUT}s (see $log)"; logtail "$log" >&2
      kill "$dpid" 2>/dev/null; _kill_port "$PROXY_PORT"
      return 1
    fi
    sleep 1; i=$((i+1))
  done

  local models_url="$COMPLETIONS_BASE/models"
  local resp
  resp=$(env all_proxy="http://127.0.0.1:$PROXY_PORT/" curl -sS -m "$REQ_TIMEOUT" \
        "$models_url" -H "Authorization: $TOKEN" 2>&1) || true

  # stop the detect daemon (prebuilt binary → $dpid is the tng pid via exec).
  kill "$dpid" 2>/dev/null; sleep 1; kill -9 "$dpid" 2>/dev/null
  _kill_port "$PROXY_PORT"

  local id
  id=$(printf '%s' "$resp" | grep -oE '"id":"[^"]+"' | head -1 | sed 's/"id":"//;s/"$//')
  if [ -z "$id" ]; then
    log "model detection failed: no model id in /v1/models response"
    log "  response: $(printf '%s' "$resp" | head -c 300)"
    return 1
  fi
  MODEL="$id"
  log "detected model: $MODEL"
  return 0
}

# _kill_port — reap whatever still listens on $1, so a leftover daemon from
# detect_model can't keep the port bound and break the next method. Avoids
# `pkill -f` which would self-match the harness's own command line.
_kill_port() {
  local p="$1" pid
  pid=$(ss -tlnp 2>/dev/null | grep ":$p " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
  [ -n "$pid" ] && { kill "$pid" 2>/dev/null; sleep 1; kill -9 "$pid" 2>/dev/null; }
}

cleanup_tng() {
  if [ "${KEEP:-0}" = "1" ]; then return 0; fi
  for pid in "${TNG_TEST_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  [ -n "${WORKDIR:-}" ] && rm -rf "$WORKDIR" 2>/dev/null
}
trap cleanup_tng EXIT INT TERM

usage() {
  cat <<'USAGE'
Usage: docs/scenarios/05-vllm-ohttp-cluster/run.sh -m <daemon|exec|python|go|wasm|all> [options]

Drive TNG's access methods against a real /v1/completions endpoint.
Each method lives in ./access/<name>.sh and is sourced by this entry.

Methods:
  daemon   tng binary as an http_proxy ingress; request via all_proxy
  exec     tng exec (LD_PRELOAD hook) wrapping the client command; no proxy env
  python   tng-python SDK (requests session)
  go       tng-go SDK (go-openai streaming client)
  wasm     tng-wasm SDK (browser fetch via Playwright + Chrome)
  all      run every method above in turn (default)

Options:
  -m, --method METHOD      method to run (default: all)
  --builtin-as             use builtin AS verification (embedded TDX verifier;
                           no external AS needed). Default is external AS.
  --as-url URL             external AS URL (required unless --builtin-as; or
                           set $TNG_TEST_AS_URL)
  --completions-url URL    full /v1/completions URL of any vLLM-style
                           inference endpoint (required, or set
                           $TNG_TEST_COMPLETIONS_URL)
  --token TOKEN            endpoint auth token (required if $TNG_TEST_TOKEN unset)
  --model MODEL            model name; if omitted, auto-detected via /v1/models
                           (or set $TNG_TEST_MODEL)
  --proxy-port PORT        local proxy listen port for daemon (default: 41000)
  --tng-bin CMD            tng command prefix (default: 'cargo run --release --')
  --keep                   don't kill daemons / keep temp files
  -h, --help               show this help

Daemon-method timeouts (tune if your build/network is slow):
  $TNG_TEST_STARTUP_TIMEOUT  seconds to wait for the proxy port (default 240)
  $TNG_TEST_REQ_TIMEOUT      seconds per inference request   (default 90)
  $TNG_TEST_AS_GRACE         seconds before fast-failing on a persistent
                             AS/remote 4xx during startup (default 15)
On any daemon failure the daemon log tail is printed to stderr, and both
phases heartbeat every 5s so a stuck tng never looks like a silent hang.
Ctrl-C / SIGTERM abort immediately (cleaning up the daemon) instead of being
swallowed by the wait loop.

The token is read from --token or $TNG_TEST_TOKEN; nothing secret is
hard-coded, so this file is safe to commit. No EAS host or AS address is
baked in: pass them via flags or env.
USAGE
  exit 0
}

# ---- arg parsing ------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    -m|--method)    METHOD="$2"; shift 2;;
    --builtin-as)   AS_MODE="builtin"; shift;;
    --as-url)       AS_URL="$2"; shift 2;;
    --completions-url) COMPLETIONS_URL="$2"; shift 2;;
    --token)        TOKEN="$2"; shift 2;;
    --model)        MODEL="$2"; shift 2;;
    --proxy-port)   PROXY_PORT="$2"; shift 2;;
    --tng-bin)      TNG_BIN="$2"; shift 2;;
    --keep)         KEEP=1; shift;;
    -h|--help)      usage;;
    *) log "unknown arg: $1"; exit 2;;
  esac
done

# recompute COMPLETIONS_BASE if COMPLETIONS_URL was overridden
COMPLETIONS_BASE="${COMPLETIONS_URL%/v1/*}/v1"

[ -z "$COMPLETIONS_URL" ] && { log "missing --completions-url (or set TNG_TEST_COMPLETIONS_URL)"; exit 2; }
[ -z "$TOKEN" ] && { log "missing --token (or set TNG_TEST_TOKEN)"; exit 2; }
command -v curl >/dev/null || { log "curl required"; exit 2; }
if [ "$AS_MODE" != "builtin" ] && [ -z "$AS_URL" ]; then
  log "missing --as-url (or set TNG_TEST_AS_URL), or use --builtin-as"
  exit 2
fi

# ---- model auto-detection ---------------------------------------------------
# If the caller didn't name a model, probe /v1/models through TNG and use the
# first served id. Fails loudly: a stale hardcoded default would just paper
# over a real mismatch (the wrong model id 404s at the backend after RA+OHTTP
# succeed, which looks like a TNG bug).
if [ -z "$MODEL" ]; then
  detect_model || exit 1
fi

# ---- per-method implementations (sourced) ----------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=access/daemon.sh
source "$SCRIPT_DIR/access/daemon.sh"
# shellcheck source=access/exec.sh
source "$SCRIPT_DIR/access/exec.sh"
# shellcheck source=access/python.sh
source "$SCRIPT_DIR/access/python.sh"
# shellcheck source=access/go.sh
source "$SCRIPT_DIR/access/go.sh"
# shellcheck source=access/wasm.sh
source "$SCRIPT_DIR/access/wasm.sh"

# ---- dispatch ---------------------------------------------------------------
run_one() {
  case "$1" in
    daemon) run_daemon;;
    exec)   run_exec;;
    python) run_python;;
    go)     run_go;;
    wasm)   run_wasm;;
    *) log "unknown method: $1"; return 2;;
  esac
}

rc=0
if [ "$METHOD" = "all" ]; then
  for m in daemon exec python go wasm; do run_one "$m" || rc=$?; done
else
  run_one "$METHOD" || rc=$?
fi

exit "$rc"
