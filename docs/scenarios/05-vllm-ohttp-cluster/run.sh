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
AS_URL="${TNG_TEST_AS_URL:-http://8.130.97.127:8081/api/as/}"
COMPLETIONS_URL="${TNG_TEST_COMPLETIONS_URL:-}"
TOKEN="${TNG_TEST_TOKEN:-}"
MODEL="${TNG_TEST_MODEL:-Qwen3.5-0.8B}"
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
Usage: docs/scenarios/05-vllm-ohttp-cluster/run.sh -m <daemon|python|go|wasm|all> [options]

Drive TNG's 4 access methods against a real /v1/completions endpoint.
Each method lives in ./access/<name>.sh and is sourced by this entry.

Options:
  -m, --method METHOD      method to run (default: all)
  --builtin-as             use builtin AS verification (only supported by
                           docker-image / custom builtin-as-* builds; other
                           methods will SKIP)
  --as-url URL             external AS URL (default: $TNG_TEST_AS_URL or
                           http://8.130.97.127:8081/api/as/)
  --completions-url URL    full /v1/completions URL of any vLLM-style
                           inference endpoint (required, or set
                           $TNG_TEST_COMPLETIONS_URL)
  --token TOKEN            endpoint auth token (required if $TNG_TEST_TOKEN unset)
  --model MODEL            model name (default: Qwen3.5-0.8B)
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
hard-coded, so this file is safe to commit.
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

# ---- per-method implementations (sourced) ----------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=access/daemon.sh
source "$SCRIPT_DIR/access/daemon.sh"
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
    python) run_python;;
    go)     run_go;;
    wasm)   run_wasm;;
    *) log "unknown method: $1"; return 2;;
  esac
}

rc=0
if [ "$METHOD" = "all" ]; then
  for m in daemon python go wasm; do run_one "$m" || rc=$?; done
else
  run_one "$METHOD" || rc=$?
fi

exit "$rc"
