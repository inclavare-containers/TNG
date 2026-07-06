# Getting Started with the TNG Python SDK

## Installation

### From PyPI

```bash
pip install tng-sdk
```

### From a Pre-built Wheel

Download the appropriate wheel for your platform from [GitHub Releases](https://github.com/inclavare-containers/TNG/releases):

```bash
pip install tng_sdk-<version>-<platform>.whl
```

Available platforms:
- `x86_64-unknown-linux-gnu` (Linux x86_64)
- `aarch64-unknown-linux-gnu` (Linux ARM64)
- `x86_64-apple-darwin` (macOS Intel)
- `aarch64-apple-darwin` (macOS Apple Silicon)

### From Source

Requires Rust toolchain and maturin:

```bash
# Build the tng binary
cargo build --release -p tng
cp target/release/tng tng-python/bin/scripts/tng

# Build and install the Python SDK
cd tng-python
maturin develop
```

### TNG Binary Requirement

The SDK requires a `tng` binary available at one of these locations:
1. Set `TNG_BINARY` environment variable
2. On your `PATH` (`shutil.which("tng")`)
3. Development mode: `{module_dir}/../bin/tng`
4. System installed at `/usr/bin/tng`

## Quick Start

### Basic Usage with requests

```python
from tng import Tng
import requests

# Create TNG client
tng = Tng(no_ra=True)

# Wrap a requests session
session = requests.Session()
tng.wrap_requests(session)

# Send requests through the encrypted tunnel
resp = session.get("http://tng-server:10001/api/data")
print(resp.json())

# Clean up
tng.close()
```

### With httpx

```python
import httpx
from tng import Tng

tng = Tng(no_ra=True)

# Sync
client = httpx.Client()
tng.wrap_httpx(client)
resp = client.get("http://tng-server:10001/api/data")
client.close()

# Async
async def main():
    async with httpx.AsyncClient() as client:
        tng.wrap_httpx(client)
        resp = await client.get("http://tng-server:10001/api/data")
```

### With OpenAI

```python
from openai import OpenAI
from tng import Tng

tng = Tng(no_ra=True)

client = OpenAI(api_key="sk-xxx", base_url="http://tng-server:10001/v1")
tng.wrap_openai(client)

completion = client.chat.completions.create(
    model="my-model",
    messages=[{"role": "user", "content": "Hello"}],
)
```

## How It Works

The Python SDK manages a local TNG process that acts as an HTTP proxy:

```
Your Code -> requests/httpx (native proxy) -> TNG http_proxy (local)
    -> OHTTP/rats-TLS encryption -> TNG Server (remote) -> Backend
```

1. **You create `Tng()`** -- the SDK starts a TNG subprocess with an auto-configured `http_proxy` ingress
2. **You wrap your HTTP client** -- the SDK sets the native proxy to the local http_proxy port
3. **You send requests** -- your HTTP library routes through the proxy using standard HTTP proxy protocol
4. **TNG encrypts and forwards** -- the http_proxy ingress reads the target from the Host header, encrypts via OHTTP/rats-TLS, and sends to the remote TNG Server
5. **TNG Server decrypts and forwards** -- the remote egress decrypts and forwards to your backend

### Client vs Server

The Python SDK manages only the **client-side** (http_proxy ingress). The **server-side** (egress) must be deployed separately:

```
Client (Python SDK):              Server (deployed by you):
  Tng(no_ra=True)                   TNG Server config:
    -> http_proxy ingress              -> add_egress: [{ mapping }]
    -> OHTTP encryption                -> decrypts & forwards to backend
```

## Security Configuration

### Disable Remote Attestation (Testing Only)

```python
tng = Tng(no_ra=True)
```

### Verifier Mode

Verify the remote server's attestation:

```python
tng = Tng(
    verify={
        "as_addr": "http://127.0.0.1:8080/",
        "policy_ids": ["default"],
    },
)
```

### Attester Mode

Provide your own attestation to the server:

```python
tng = Tng(
    attest={
        "model": "passport",
        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
        "as_addr": "http://127.0.0.1:8080/",
        "policy_ids": ["default"],
    },
)
```

### Bidirectional Attestation

Both client and server verify each other:

```python
tng = Tng(
    attest={"aa_addr": "unix:///run/.../attestation-agent.sock"},
    verify={"as_addr": "http://127.0.0.1:8080/", "policy_ids": ["default"]},
)
```

### OHTTP Customization

```python
tng = Tng(
    no_ra=True,
    ohttp={
        "path_rewrites": [
            {"match_regex": "^/api/(.*)", "substitution": "/v1/\\1"},
        ],
    },
)
```

### rats-TLS Instead of OHTTP

```python
tng = Tng(
    rats_tls={"multiplex": True},
)
```

> **Note:** `ohttp` and `rats_tls` are mutually exclusive. If neither is specified, `ohttp={}` is used by default.

## Streaming Support

### SSE with requests

```python
resp = session.get("http://tng-server:10001/events", stream=True)
for line in resp.iter_lines():
    if line:
        print(line.decode())
```

### SSE with httpx (sync)

```python
with httpx.Client() as client:
    tng.wrap_httpx(client)
    with client.stream("GET", "http://tng-server:10001/events") as resp:
        for chunk in resp.iter_text():
            print(chunk)
```

### SSE with httpx (async)

```python
async with httpx.AsyncClient() as client:
    tng.wrap_httpx(client)
    async with client.stream("GET", "http://tng-server:10001/events") as resp:
        async for chunk in resp.aiter_text():
            print(chunk)
```

### LLM Streaming with OpenAI

```python
# Sync
for chunk in client.chat.completions.create(
    model="my-model",
    messages=[{"role": "user", "content": "Hello"}],
    stream=True,
):
    print(chunk.choices[0].delta.content or "", end="")

# Async
async for chunk in await async_client.chat.completions.create(
    model="my-model",
    messages=[{"role": "user", "content": "Hello"}],
    stream=True,
):
    print(chunk.choices[0].delta.content or "", end="")
```

## TNG Server Deployment

The server-side TNG process must be deployed separately. Here's a minimal config:

### OHTTP Server

```json
{
  "add_egress": [{
    "mapping": {
      "in":  { "host": "0.0.0.0", "port": 10001 },
      "out": { "host": "backend", "port": 30001 }
    },
    "ohttp": {},
    "no_ra": true
  }]
}
```

### rats-TLS Server

If the client uses rats-TLS, the server must match:

```json
{
  "add_egress": [{
    "mapping": {
      "in":  { "host": "0.0.0.0", "port": 10001 },
      "out": { "host": "backend", "port": 30001 }
    },
    "rats_tls": {},
    "no_ra": true
  }]
}
```

Run the server:

```bash
tng launch --config-file server-config.json
```

The client SDK connects to `<server-host>:10001` -- this address goes in your request URLs.

## Troubleshooting

### Enable Logging

```python
import os
os.environ["RUST_LOG"] = "debug"
tng = Tng(no_ra=True)
```

Supported levels: `error`, `warn`, `info`, `debug`, `trace`, `off`.

### Inspect Generated Config

The SDK writes its TNG config to a temp file. Find it:

```bash
ls -lt /tmp/tng_cfg_*.json | head -1
cat /tmp/tng_cfg_*.json
```

### Run TNG Independently

```bash
RUST_LOG=debug tng launch --config-file /tmp/tng_cfg_xxxxx.json
```

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `TNG binary not found` | `tng` not on PATH | Set `TNG_BINARY` env var or install tng on PATH |
| `Port ... not ready within 30s` | TNG failed to start | Check logs, verify config |
| `Connection refused` | TNG server not reachable | Verify server is running and port is correct |
| `ohttp and rats_tls are mutually exclusive` | Both specified | Remove one |

## Lifecycle Management

### Explicit Cleanup

```python
tng = Tng(no_ra=True)
try:
    session = requests.Session()
    tng.wrap_requests(session)
    resp = session.get("http://tng-server:10001/api/data")
    resp.raise_for_status()
    print(resp.json())
finally:
    tng.close()
```

### Context Manager (Recommended)

The ``Tng`` class supports the context manager protocol for automatic cleanup:

```python
import requests
from tng import Tng

with Tng(no_ra=True) as tng:
    session = requests.Session()
    tng.wrap_requests(session)
    resp = session.get("http://tng-server:10001/api/data")
    print(resp.json())
# TNG subprocess is automatically terminated on exit
```

### Automatic Cleanup

`tng.close()` is called automatically on:
- Object deletion (`__del__`)
- Interpreter exit (`atexit`)

### Safe to Call Multiple Times

```python
tng.close()
tng.close()  # no-op, safe
```
