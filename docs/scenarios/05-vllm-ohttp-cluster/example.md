# TNG Access-Method Test Harness

[中文文档](example_zh.md)

`run.sh` exercises TNG's five ways to reach a vLLM-style `/v1/completions`
endpoint end-to-end — with OHTTP encryption and remote-attestation verification
— and asserts that streamed model tokens come back.

| Method (`-m`) | What it drives |
| --- | --- |
| `tng-launch` | a TNG `http_proxy` ingress; the request is sent through `all_proxy` with `curl` |
| `tng-exec` | `tng exec` (LD_PRELOAD hook) wrapping the client command; no proxy env needed |
| `python-sdk` | the TNG Python SDK (`tng-sdk`), wrapping a `requests` session |
| `go-sdk` | the TNG Go SDK (`tng-go`), used as the `openai`-client `RoundTripper` |
| `js-sdk` | the TNG WASM/JS SDK in a headless Chromium, driven by Playwright |

Each method lives in `access/<name>.sh` and is sourced by `run.sh`. See
[README.md](README.md) for the cluster topology this scenario targets.

## Prerequisites

Common: `curl`; a `--token` and a `--completions-url`.

Per method:

- **tng-launch** — a `tng` binary that supports the `path_default` config field
  (TNG ≥ 2.8). Defaults to `cargo run --release --` (builds from source);
  override with `--tng-bin /path/to/tng`. `--proxy-port` selects the local
  proxy port (default 41000).
- **tng-exec** — a prebuilt `tng` binary plus `libtng_hook.so` beside it (build
  with `make tng-hook-build`, or point `$TNG_HOOK_LIB` at it). `tng exec`
  preloads the hook library into the client command, so the client (curl)
  hits the URL directly with no proxy environment.
- **python-sdk** — Python ≥ 3.8. `tng-sdk` and `requests` are auto-installed.
  Spawns a `tng` subprocess resolved from `target/release/tng` →
  `target/debug/tng` (build it first with `cargo build --release`).
- **go-sdk** — Go toolchain. Spawns a `tng` subprocess resolved from
  `$TNG_BINARY` → `target/release/tng` → `target/debug/tng` → `tng` on PATH.
- **js-sdk** — the WASM package built at `tng-wasm/pkg/`
  (`make wasm-build-debug`). A Chromium/Chrome binary (override with
  `$TNG_CHROME`; otherwise the system `google-chrome`, or Playwright downloads
  one). Python ≥ 3.8; `playwright` is auto-installed.

If `--model` is omitted, the harness probes `/v1/models` through a one-shot
TNG daemon and uses the first served model id, so it works against any
deployment without knowing the model name up front.

## Examples

Set the token once:

```bash
export TNG_TEST_TOKEN="<your-endpoint-token>"
```

### 1) tng-launch (http_proxy ingress; any HTTP client via `all_proxy`)

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m tng-launch \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct \
    --tng-bin         ./target/release/tng
```

### 2) tng-exec (LD_PRELOAD hook; client runs directly, no proxy env)

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m tng-exec \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --tng-bin         ./target/release/tng
```

### 3) python-sdk

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m python-sdk \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct
```

### 4) go-sdk

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m go-sdk \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct
```

### 5) js-sdk (browser, WASM)

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m js-sdk \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct
```

### All five, sequentially

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m all \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct
```

## Options

| Flag | Description |
| --- | --- |
| `-m, --method` | `tng-launch` / `tng-exec` / `python-sdk` / `go-sdk` / `js-sdk` / `all` (default `all`) |
| `--completions-url` | full `/v1/completions` URL (required, or `$TNG_TEST_COMPLETIONS_URL`) |
| `--as-url` | attestation-service URL (required unless `--builtin-as`, or `$TNG_TEST_AS_URL`) |
| `--token` | endpoint auth token (required, or `$TNG_TEST_TOKEN`) |
| `--model` | model name; if omitted, auto-detected via `/v1/models` (or `$TNG_TEST_MODEL`) |
| `--proxy-port` | local proxy port for tng-launch (default 41000) |
| `--tng-bin` | `tng` command prefix for tng-launch/tng-exec (default `cargo run --release --`) |
| `--builtin-as` | use builtin AS verification (embedded TDX verifier; no external AS needed) |
| `--keep` | don't kill daemons / keep temp files |
| `-h, --help` | show help |

## Environment variables

Every flag above has a matching `TNG_TEST_*` env var: `TNG_TEST_METHOD`,
`TNG_TEST_COMPLETIONS_URL`, `TNG_TEST_AS_URL`, `TNG_TEST_TOKEN`,
`TNG_TEST_MODEL`, `TNG_TEST_PROXY_PORT`, `TNG_TEST_BIN`. The tng-launch method also
reads `TNG_TEST_STARTUP_TIMEOUT` (default 240s), `TNG_TEST_REQ_TIMEOUT`
(default 90s), and `TNG_TEST_AS_GRACE` (default 15s). The go-sdk method honors
`TNG_BINARY` (subprocess binary); the tng-exec method honors `TNG_HOOK_LIB`
(hook library path); the js-sdk method honors `TNG_CHROME` (browser binary).

## Output

Each method prints exactly one result line: `PASS <method>`,
`FAIL <method> <reason>`, or `SKIP <method> <reason>` (e.g. when a prerequisite
is missing). On `FAIL` the tng-launch/tng-exec methods also dump their log tail to
stderr. The script exits non-zero if any selected method fails.
