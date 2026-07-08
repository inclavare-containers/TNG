# TNG Access-Method Test Harness

[中文文档](example_zh.md)

`run.sh` exercises TNG's four ways to reach a vLLM-style `/v1/completions`
endpoint end-to-end — with OHTTP encryption and remote-attestation verification
— and asserts that streamed model tokens come back.

| Method (`-m`) | What it drives |
| --- | --- |
| `daemon` | a TNG `http_proxy` ingress; the request is sent through `all_proxy` with `curl` |
| `python` | the TNG Python SDK (`tng-sdk`), wrapping a `requests` session |
| `go` | the TNG Go SDK (`tng-go`), used as the `openai`-client `RoundTripper` |
| `wasm` | the TNG WASM/JS SDK in a headless Chromium, driven by Playwright |

Each method lives in `access/<name>.sh` and is sourced by `run.sh`. See
[README.md](README.md) for the cluster topology this scenario targets.

## Prerequisites

Common: `curl`; a `--token` and a `--completions-url`.

Per method:

- **daemon** — a `tng` binary that supports the `path_default` config field
  (TNG ≥ 2.8). Defaults to `cargo run --release --` (builds from source);
  override with `--tng-bin /path/to/tng`. `--proxy-port` selects the local
  proxy port (default 41000).
- **python** — Python ≥ 3.8. `tng-sdk` and `requests` are auto-installed.
  Spawns a `tng` subprocess resolved from `target/release/tng` →
  `target/debug/tng` (build it first with `cargo build --release`).
- **go** — Go toolchain. Spawns a `tng` subprocess resolved from
  `$TNG_BINARY` → `target/release/tng` → `target/debug/tng` → `tng` on PATH.
- **wasm** — the WASM package built at `tng-wasm/pkg/`
  (`make wasm-build-debug`). A Chromium/Chrome binary (override with
  `$TNG_CHROME`; otherwise the system `google-chrome`, or Playwright downloads
  one). Python ≥ 3.8; `playwright` is auto-installed.

## Examples

Set the token once:

```bash
export TNG_TEST_TOKEN="<your-endpoint-token>"
```

### 1) Daemon (http_proxy ingress; any HTTP client via `all_proxy`)

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m daemon \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct \
    --tng-bin         ./target/release/tng
```

### 2) Python SDK

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m python \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct
```

### 3) Go SDK

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m go \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct
```

### 4) JS SDK (browser, WASM)

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m wasm \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct
```

### All four, sequentially

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
| `-m, --method` | `daemon` / `python` / `go` / `wasm` / `all` (default `all`) |
| `--completions-url` | full `/v1/completions` URL (required, or `$TNG_TEST_COMPLETIONS_URL`) |
| `--as-url` | attestation-service URL (default `$TNG_TEST_AS_URL`) |
| `--token` | endpoint auth token (required, or `$TNG_TEST_TOKEN`) |
| `--model` | model name (default `Qwen3.5-0.8B`) |
| `--proxy-port` | local proxy port for daemon (default 41000) |
| `--tng-bin` | `tng` command prefix for daemon (default `cargo run --release --`) |
| `--builtin-as` | use builtin AS verification (only docker-image / `builtin-as-*` builds; others SKIP) |
| `--keep` | don't kill daemons / keep temp files |
| `-h, --help` | show help |

## Environment variables

Every flag above has a matching `TNG_TEST_*` env var: `TNG_TEST_METHOD`,
`TNG_TEST_COMPLETIONS_URL`, `TNG_TEST_AS_URL`, `TNG_TEST_TOKEN`,
`TNG_TEST_MODEL`, `TNG_TEST_PROXY_PORT`, `TNG_TEST_BIN`. The daemon method also
reads `TNG_TEST_STARTUP_TIMEOUT` (default 240s), `TNG_TEST_REQ_TIMEOUT`
(default 90s), and `TNG_TEST_AS_GRACE` (default 15s). The go method honors
`TNG_BINARY` (subprocess binary); the wasm method honors `TNG_CHROME` (browser
binary).

## Output

Each method prints exactly one result line: `PASS <method>`,
`FAIL <method> <reason>`, or `SKIP <method> <reason>` (e.g. when a prerequisite
is missing or `--builtin-as` is used with a default build). On `FAIL` the daemon
method also dumps its log tail to stderr. The script exits non-zero if any
selected method fails.
