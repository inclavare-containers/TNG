#!/usr/bin/env bash
# wasm.sh — sourced by run.sh. Defines ONLY run_wasm().
#
# Verifies the JS SDK (browser, method 4 of 4) against the real completions
# service by driving a headless Chromium with Playwright (Python) and calling
# the wasm SDK's exported fetch(url, init, config) against $COMPLETIONS_URL.
#
# Why Playwright, not chromedriver/wasm-pack-test: the repo's BrowserClient
# path needs chromedriver, which mismatches the installed Chrome 146
# (ChromeDriver is 147/149/150); and `wasm-pack test` discovers 0 tests here
# (wasm-bindgen-test 0.3.34 cfg skew). Playwright drives Chrome directly via
# CDP — no chromedriver — so the version mismatch is irrelevant.
#
# Cross-origin: the wasm SDK issues browser fetch() to the AS ($AS_URL) and to
# the completions OHTTP gateway ($COMPLETIONS_URL origin). We launch Chrome with
# --disable-web-security (mirroring browser_client.rs:43) so neither side
# needs CORS. (A realistic no-security-disabled run would need CORS on BOTH,
# and the managed completions endpoint can't be configured — so we don't.)
#
# Uses the system google-chrome via executable_path (no ~150MB browser
# download); falls back to `playwright install chromium` if no system Chrome.
# Override the binary with $TNG_CHROME.
#
# Globals: AS_MODE, AS_URL, COMPLETIONS_URL, TOKEN, MODEL, REPO, WORKDIR
# Helpers: log | pass | fail | skip | cleanup_tng

run_wasm() {
    log "=== wasm (JS SDK / browser) ==="

    # The wasm crate enables only __ingress-common; the Builtin variant is
    # #[cfg(feature = "__builtin-as")] (ra.rs:518), so as_type:"builtin" is
    # rejected by the shipped wasm SDK. Skip cleanly.
    if [[ "${AS_MODE:-}" == "builtin" ]]; then
        skip wasm "wasm crate not built with __builtin-as (Builtin variant cfg-gated at ra.rs:518)"
        return 0
    fi

    # --- requirements: python >=3.8 + the built wasm pkg ---
    local PYTHON="" cand
    for cand in python3 python; do
        command -v "$cand" >/dev/null 2>&1 || continue
        if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
            PYTHON="$cand"; break
        fi
    done
    [[ -n "$PYTHON" ]] || { skip wasm "no python >=3.8 (for Playwright)"; return 0; }

    local pkg="$REPO/tng-wasm/pkg"
    [[ -f "$pkg/tng_wasm.js" && -f "$pkg/tng_wasm_bg.wasm" ]] || {
        skip wasm "wasm pkg not built ($pkg/tng_wasm.js missing); run: (cd tng-wasm && wasm-pack build --dev --target web)"
        return 0
    }

    # Resolve a Chrome binary: prefer the system google-chrome (no download);
    # allow override via $TNG_CHROME. If none, we let Playwright download its
    # bundled chromium below.
    local chrome="${TNG_CHROME:-}"
    [[ -z "$chrome" && -x /usr/bin/google-chrome ]] && chrome="/usr/bin/google-chrome"

    local testdir="$WORKDIR/wasm-test"
    local profile="$testdir/chrome-profile"
    mkdir -p "$profile"
    # harness.html lives inside the pkg dir so `import "./tng_wasm.js"` resolves.
    local harness="$pkg/harness.html"
    local driver="$testdir/wasm_driver.py"
    local driver_log="$testdir/driver.log"
    local pip_log="$testdir/pip.log"
    : > "$driver_log"

    _wasm_cleanup() {
        [[ "${KEEP:-0}" = "1" ]] && return 0
        rm -f "$harness"
        # reap any chromium we spawned with our profile dir (Playwright passes
        # --user-data-dir=$profile, so its cmdline contains this path).
        [[ -n "$profile" ]] && pkill -f "$profile" 2>/dev/null
    }
    trap _wasm_cleanup INT TERM EXIT

    # --- harness.html (static; dynamic values injected via window.__TNG_*) ---
    cat > "$harness" <<'HTMLEOF'
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>tng-wasm test</title></head>
<body>
<script type="module">
import tng_init, { fetch as tng_fetch } from "./tng_wasm.js";

const COMPLETIONS = window.__TNG_COMPLETIONS, AS = window.__TNG_AS, TOKEN = window.__TNG_TOKEN, MODEL = window.__TNG_MODEL;
const cfg = {
  ohttp: { path_default: "original" },
  verify: { model: "background_check", as_addr: AS, policy_ids: ["default"] },
};
const body = JSON.stringify({ model: MODEL, prompt: "Do you know the book Traction by Gino Wickman", temperature: 0.0, best_of: 1, max_tokens: 132, stream: true });

window.__TNG_RESULT = null;
console.log("[harness] init tng...");
tng_init().then(async () => {
  console.log("[harness] tng initialized; calling tng_fetch");
  try {
    const resp = await tng_fetch(COMPLETIONS, { method: "POST", headers: { "Authorization": TOKEN, "Content-Type": "application/json" }, body }, cfg);
    const text = await resp.text();
    console.log("[harness] response status=" + resp.status + " len=" + text.length);
    window.__TNG_RESULT = { ok: true, status: resp.status, text: text, attest: resp.attest_info || null };
  } catch (e) {
    console.error("[harness] tng_fetch error: " + (e && e.message || e));
    window.__TNG_RESULT = { ok: false, error: String(e && e.message || e), stack: String(e && e.stack || "") };
  }
}).catch(e => {
  console.error("[harness] tng_init error: " + (e && e.message || e));
  window.__TNG_RESULT = { ok: false, error: "init: " + String(e && e.message || e) };
});
</script>
</body></html>
HTMLEOF

    # --- wasm_driver.py (static; reads env, serves pkg, drives Playwright) ---
    cat > "$driver" <<'PYEOF'
import os, sys, json, threading, traceback, signal, atexit
import http.server, mimetypes

PKG = os.environ["TNG_WASM_PKG"]
COMPLETIONS = os.environ["TNG_COMPLETIONS"]
AS = os.environ["TNG_AS"]
TOKEN = os.environ["TNG_TOKEN"]
MODEL = os.environ["TNG_MODEL"]
PROFILE = os.environ["TNG_CHROME_PROFILE"]
CHROME = os.environ.get("TNG_CHROME", "")
TIMEOUT_MS = int(os.environ.get("TNG_TIMEOUT_MS", "90000"))

# .wasm MUST be served as application/wasm or instantiation fails.
mimetypes.add_type("application/wasm", ".wasm")
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/javascript", ".mjs")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=PKG, **kw)
    def log_message(self, *a):
        pass

httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
port = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()
sys.stderr.write("[driver] serving %s at http://127.0.0.1:%d\n" % (PKG, port)); sys.stderr.flush()

context = None
def cleanup():
    global context
    if context is not None:
        try: context.close()
        except Exception: pass
        context = None
    try: httpd.shutdown()
    except Exception: pass
atexit.register(cleanup)
signal.signal(signal.SIGTERM, lambda *a: (cleanup(), sys.exit(130)))

# Inject the run-specific values before the page's own scripts run. json.dumps
# produces a valid JS string literal, so the token is safely embedded.
inject = (
    "window.__TNG_COMPLETIONS=%s;window.__TNG_AS=%s;window.__TNG_TOKEN=%s;window.__TNG_MODEL=%s;"
    % (json.dumps(COMPLETIONS), json.dumps(AS), json.dumps(TOKEN), json.dumps(MODEL))
)

def _cl(m):
    sys.stderr.write("[browser:%s] %s\n" % (m.type, m.text)); sys.stderr.flush()
def _pe(e):
    sys.stderr.write("[pageerror] %s\n" % (e,)); sys.stderr.flush()
def _rf(r):
    try: f = r.failure
    except Exception: f = "?"
    sys.stderr.write("[reqfail] %s %s\n" % (r.url, f)); sys.stderr.flush()

try:
    from playwright.sync_api import sync_playwright
except Exception as e:
    sys.stderr.write("[driver] playwright import failed: %s\n" % (e,)); sys.exit(2)

result = None
try:
    with sync_playwright() as p:
        args = ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                "--disable-web-security", "--disable-features=IsolateOrigins,site-per-process"]
        kw = {"headless": True, "args": args}
        if CHROME:
            kw["executable_path"] = CHROME
        context = p.chromium.launch_persistent_context(PROFILE, **kw)
        context.add_init_script(inject)
        page = context.new_page()
        page.on("console", _cl)
        page.on("pageerror", _pe)
        page.on("requestfailed", _rf)
        page.goto("http://127.0.0.1:%d/harness.html" % (port,), wait_until="domcontentloaded")
        page.wait_for_function("window.__TNG_RESULT", timeout=TIMEOUT_MS)
        result = page.evaluate("window.__TNG_RESULT")
        context.close(); context = None
    httpd.shutdown()
    sys.stdout.write(json.dumps(result) + "\n"); sys.stdout.flush()
    ok = bool(result and result.get("ok") and
              any(s in (result.get("text") or "") for s in ("choices", '"text"', "data:")))
    sys.exit(0 if ok else 1)
except Exception as e:
    sys.stderr.write("[driver] ERROR %s\n" % (e,))
    traceback.print_exc(file=sys.stderr)
    cleanup()
    sys.exit(2)
PYEOF

    # --- install Playwright (pip) if missing ---
    if ! "$PYTHON" -c 'import playwright' >/dev/null 2>&1; then
        log "wasm: installing playwright via pip"
        if ! "$PYTHON" -m pip install --break-system-packages playwright >"$pip_log" 2>&1 \
           && ! "$PYTHON" -m pip install playwright >"$pip_log" 2>&1; then
            skip wasm "pip install playwright failed (no network? see $pip_log)"
            _wasm_cleanup; trap - INT TERM EXIT; trap cleanup_tng EXIT INT TERM; return 0
        fi
    fi

    # --- ensure a browser binary: system chrome, else download bundled chromium ---
    if [[ -z "$chrome" ]]; then
        log "wasm: no system chrome; downloading Playwright's bundled chromium"
        if ! "$PYTHON" -m playwright install chromium >"$pip_log" 2>&1; then
            skip wasm "playwright install chromium failed (no network? see $pip_log)"
            _wasm_cleanup; trap - INT TERM EXIT; trap cleanup_tng EXIT INT TERM; return 0
        fi
    fi

    local chrome_desc="$([ -n "$chrome" ] && echo "$chrome" || echo "bundled chromium")"
    log "wasm: launching headless chromium ($chrome_desc, --disable-web-security) + tng_fetch"
    TNG_WASM_PKG="$pkg" TNG_COMPLETIONS="$COMPLETIONS_URL" TNG_AS="$AS_URL" TNG_TOKEN="$TOKEN" \
      TNG_MODEL="$MODEL" TNG_CHROME="$chrome" TNG_CHROME_PROFILE="$profile" \
      TNG_TIMEOUT_MS=90000 timeout --kill-after=10 150 "$PYTHON" "$driver" >"$driver_log" 2>&1
    local rc=$?

    if [[ $rc -eq 0 ]]; then
        pass wasm
        _wasm_cleanup; trap - INT TERM EXIT; trap cleanup_tng EXIT INT TERM
        return 0
    fi

    local result
    result=$(grep -m1 '^{' "$driver_log" 2>/dev/null || true)
    fail wasm "wasm fetch did not return model output (rc=$rc; see $driver_log)"
    [[ -n "$result" ]] && printf '### result: %s\n' "$result" >&2
    printf '### last driver/browser lines:\n' >&2
    tail -n 30 "$driver_log" >&2
    _wasm_cleanup; trap - INT TERM EXIT; trap cleanup_tng EXIT INT TERM
    return 1
}
