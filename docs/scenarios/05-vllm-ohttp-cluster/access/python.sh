#!/usr/bin/env bash
# python.sh — sourced by run.sh; defines run_python() only.
# Verifies the TNG Python SDK (method 2 of 4) end-to-end against the real
# completions service, per /tmp/tngtest/CONTRACT.md. Uses the contract's globals/helpers.
#
# Deviation note: CONTRACT.md says "run python3 $WORKDIR/run_python.py", but on
# this host python3 is 3.6.8 (the SDK requires >=3.8). We resolve a python >=3.8
# (python3 first, then python) and log which interpreter was used.

run_python() {
  log "python: start (AS_MODE=${AS_MODE:-external})"

  # ------------------------------------------------------------------
  # 1. Resolve a Python >=3.8
  # ------------------------------------------------------------------
  local PYTHON="" cand
  for cand in python3 python; do
    command -v "$cand" >/dev/null 2>&1 || continue
    if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
      PYTHON="$cand"; break
    fi
  done
  if [ -z "$PYTHON" ]; then
    fail python "no python >=3.8 found (python3=$(python3 --version 2>&1))"
    return
  fi
  log "python: using $PYTHON ($($PYTHON --version 2>&1))"

  # ------------------------------------------------------------------
  # 2. Ensure the SDK + requests are importable
  # ------------------------------------------------------------------
  # pip_install <spec...> — try --break-system-packages (newer pip / managed env),
  # then plain install (older pip or unmanaged env).
  pip_install() {
    "$PYTHON" -m pip install --break-system-packages "$@" >/dev/null 2>&1 \
      || "$PYTHON" -m pip install "$@" >/dev/null 2>&1
  }
  local installed=0 wheel
  # Prefer a built wheel from the repo (local, matches bundled binary), then
  # PyPI, then an editable install from source as last resort.
  wheel=$(ls "$REPO"/tng-python/dist/tng_sdk-*.whl 2>/dev/null | head -1)
  if [ -n "$wheel" ]; then
    pip_install "$wheel" requests && installed=1
  fi
  if [ "$installed" -ne 1 ]; then
    pip_install tng-sdk requests && installed=1
  fi
  if [ "$installed" -ne 1 ]; then
    pip_install -e "$REPO/tng-python" requests && installed=1
  fi
  # Verify the *installed* package is importable from a neutral cwd (running
  # from $REPO would pick up the Rust tng/ crate dir as a namespace package).
  if ! (cd /tmp && "$PYTHON" -c "from tng import Tng; import requests") >/dev/null 2>&1; then
    fail python "tng not installed"
    return
  fi
  log "python: SDK importable"

  # ------------------------------------------------------------------
  # 3. Point the SDK at a matching tng binary
  # ------------------------------------------------------------------
  local tng_bin=""
  if [ -x "$REPO/target/release/tng" ]; then
    tng_bin="$REPO/target/release/tng"
  elif [ -x "$REPO/target/debug/tng" ]; then
    tng_bin="$REPO/target/debug/tng"
  fi
  [ -n "$tng_bin" ] && log "python: TNG_BINARY=$tng_bin"

  # ------------------------------------------------------------------
  # 4. Generate the runner script
  # ------------------------------------------------------------------
  mkdir -p "$WORKDIR"
  cat > "$WORKDIR/run_python.py" <<'PYEOF'
import os, sys, glob, subprocess

AS_MODE = os.environ.get("AS_MODE", "external")
AS_URL  = os.environ.get("AS_URL", "")
COMPLETIONS_URL = os.environ.get("COMPLETIONS_URL", "")
TOKEN   = os.environ.get("TOKEN", "")
MODEL   = os.environ.get("MODEL", "")
TNG_BIN = os.environ.get("TNG_BINARY", "tng")

# ohttp path_default per CONTRACT.md
ohttp_cfg = {"path_default": "original"}
# verify config per CONTRACT.md (external vs builtin)
if AS_MODE == "builtin":
    verify_cfg = {"model": "background_check", "as_type": "builtin",
                  "attestation_policy": {"type": "default"}, "reference_values": []}
else:
    verify_cfg = {"model": "background_check", "as_addr": AS_URL, "policy_ids": ["default"]}

try:
    from tng import Tng
except Exception as e:
    print("__IMPORT_FAILED__: %s" % e); sys.exit(2)

try:
    tng = Tng(ohttp=ohttp_cfg, verify=verify_cfg)
except Exception as e:
    msg = str(e); detail = msg
    # Gather diagnostics: SDK-captured stderr logs + most recent generated config
    for log in sorted(glob.glob("/tmp/tng_stderr_*.log"), key=os.path.getmtime)[-3:]:
        try: detail += " | " + open(log).read()
        except Exception: pass
    cfgs = sorted(glob.glob("/tmp/tng_cfg_*.json"), key=os.path.getmtime)
    if cfgs:
        try:
            r = subprocess.run([TNG_BIN, "launch", "--config-file", cfgs[-1]],
                               capture_output=True, text=True, timeout=15,
                               env={**os.environ, "RUST_LOG": "error"})
            detail += " | rc=%d stderr=%s stdout=%s" % (r.returncode, r.stderr, r.stdout)
        except Exception as e2:
            detail += " | rerun-failed: %s" % e2
    low = detail.lower()
    # Published wheel lacks __builtin-as → binary rejects as_type:"builtin"
    if AS_MODE == "builtin" and ("unknown variant" in low or "builtin" in low):
        print("__BUILTIN_UNSUPPORTED__"); sys.exit(0)
    print("__START_FAILED__: %s" % detail[:1200]); sys.exit(3)

import requests
session = requests.Session()
tng.wrap_requests(session)
try:
    resp = session.post(COMPLETIONS_URL, headers={"Authorization": TOKEN}, json={
        "model": MODEL,
        "prompt": "Do you know the book Traction by Gino Wickman",
        "temperature": 0.0, "best_of": 1, "max_tokens": 132, "stream": True,
    }, stream=True, timeout=120)
    print("HTTP_STATUS:", resp.status_code)
    for line in resp.iter_lines():
        if line:
            print(line.decode(errors="replace"))
    sys.exit(0)
except Exception as e:
    print("__REQUEST_FAILED__: %s" % e); sys.exit(4)
finally:
    try: session.close()
    except Exception: pass
    try: tng.close()
    except Exception: pass
PYEOF

  # ------------------------------------------------------------------
  # 5. Run it (subshell-scoped EXIT trap for cleanup; run from $WORKDIR so the
  #    repo's Rust tng/ dir doesn't shadow the installed tng package)
  # ------------------------------------------------------------------
  local out rc
  out=$(
    if [ "${KEEP:-0}" != "1" ]; then
      trap 'command -v cleanup_tng >/dev/null 2>&1 && cleanup_tng' EXIT
    fi
    cd "$WORKDIR"
    timeout 200 env ${tng_bin:+TNG_BINARY=$tng_bin} AS_MODE="$AS_MODE" \
        AS_URL="$AS_URL" COMPLETIONS_URL="$COMPLETIONS_URL" TOKEN="$TOKEN" MODEL="$MODEL" \
        RUST_LOG=error "$PYTHON" run_python.py 2>&1
  )
  rc=$?
  log "python: runner exit=$rc"

  # Backup cleanup (python's finally/atexit should already have killed the
  # subprocess; this catches the killed-mid-run case).
  if [ "${KEEP:-0}" != "1" ]; then
    command -v cleanup_tng >/dev/null 2>&1 && cleanup_tng
  fi

  # ------------------------------------------------------------------
  # 6. Evaluate
  # ------------------------------------------------------------------
  if echo "$out" | grep -q "__BUILTIN_UNSUPPORTED__"; then
    skip python "builtin AS not in published wheel"
    return 0
  fi
  if echo "$out" | grep -q "__IMPORT_FAILED__"; then
    fail python "tng import failed: $(echo "$out" | grep '__IMPORT_FAILED__' | head -1)"
    return
  fi
  if echo "$out" | grep -q "__START_FAILED__"; then
    fail python "Tng() start failed: $(echo "$out" | grep '__START_FAILED__' | head -1)"
    return
  fi
  if echo "$out" | grep -q "__REQUEST_FAILED__"; then
    fail python "request failed: $(echo "$out" | grep '__REQUEST_FAILED__' | head -1)"
    return
  fi
  if echo "$out" | grep -Eq 'data:|"text"|"choices"'; then
    pass python
    return
  fi
  fail python "no streamed model output (rc=$rc): $(echo "$out" | tail -3 | tr '\n' ' ')"
}
