# Getting Started with the TNG Go SDK

## Prerequisites

The TNG binary must be available on your system. The SDK discovers it at runtime:

1. **`TNG_BINARY` environment variable** (shared with the [Python SDK](../../tng-python))
2. **`PATH` lookup** — `tng` must be on your `PATH`

If neither is found, `NewRoundTripper` returns an error.

## Installation

```bash
go get github.com/inclavare-containers/tng/tng-go
```

No CGO required — pure Go build (`CGO_ENABLED=0 go build` works).

## Quick Start

### Basic Usage

```go
package main

import (
    "log"
    "net/http"

    tng "github.com/inclavare-containers/tng/tng-go"
)

func main() {
    // Create a RoundTripper (spawns TNG subprocess automatically)
    rt, err := tng.NewRoundTripper(&tng.Config{NoRA: true})
    if err != nil {
        log.Fatal(err)
    }
    defer rt.Close()

    // Use with standard http.Client
    client := &http.Client{Transport: rt}
    resp, err := client.Get("http://tng-server:10001/api/data")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    log.Printf("Status: %d", resp.StatusCode)
}
```

### With http_proxy Fallback for Non-TNG URLs

```go
rt, _ := tng.NewRoundTripper(cfg, tng.WithFallback(
    http.DefaultTransport,
    func(u *url.URL) bool {
        return u.Host != "tng-server:10001"
    },
))
```

## Security Configuration

### Disable Remote Attestation (Testing Only)

```go
cfg := &tng.Config{NoRA: true}
```

### Verifier Mode (Server Attestation)

```go
cfg := &tng.Config{
    Verify: map[string]any{
        "model":       "background_check",
        "as_provider": "coco",
        "as_type":     "restful",
        "as_addr":     "http://127.0.0.1:8080/",
        "policy_ids":  []string{"default"},
    },
}
```

### Attester Mode (Client Attestation)

```go
cfg := &tng.Config{
    Attest: map[string]any{
        "model":   "background_check",
        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
    },
}
```

### rats-TLS encryption

```go
cfg := &tng.Config{
    RatsTls: map[string]any{}, // uses default rats-TLS settings
    NoRA:    true,
}
```

> **Note:** `OHttp` and `RatsTls` are mutually exclusive. Set only one.

### Bidirectional Attestation

```go
cfg := &tng.Config{
    Attest: map[string]any{
        "model":   "background_check",
        "aa_addr": "unix:///run/.../attestation-agent.sock",
    },
    Verify: map[string]any{
        "as_addr":    "http://127.0.0.1:8080/",
        "policy_ids": []string{"default"},
    },
}
```

## Streaming Support

SSE and chunked transfer encoding work transparently — no special configuration needed:

```go
resp, err := client.Get("http://tng-server:10001/events")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

scanner := bufio.NewScanner(resp.Body)
for scanner.Scan() {
    fmt.Println(scanner.Text())
}
```

## How It Works

The SDK starts a TNG subprocess with an `http_proxy` ingress on a random localhost port. All HTTP requests are forwarded to this proxy, which encrypts them via OHTTP (or rats-TLS) before sending to the remote TNG server (egress). Response streaming works transparently via standard HTTP.

```
Your Code → http.Client → TNG http_proxy (127.0.0.1:port) → OHTTP → TNG Server → Backend
```

### Client vs Server

The Go SDK manages only the **client-side** (http_proxy ingress). The **server-side** (egress) must be deployed separately:

```
Client (Go SDK):                    Server (deployed by you):
  NewRoundTripper(cfg)                TNG Server config:
    -> http_proxy ingress                -> add_egress: [{ mapping }]
    -> OHTTP encryption                  -> decrypts & forwards to backend
```

## TNG Server Deployment

The server-side TNG process must be deployed separately. Minimal config:

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

Run the server:

```bash
tng launch --config-file server-config.json
```

Connect to `<server-host>:10001` from the Go client.

## Lifecycle Management

### Explicit Cleanup

```go
rt, _ := tng.NewRoundTripper(cfg)
defer rt.Close() // always defer Close
```

### Attestation Info

After a successful request, retrieve server attestation from the response:

```go
info := tng.GetAttestationInfo(resp)
if info != nil {
    fmt.Printf("Attestation token: %s\n", info.Token)
}
```

## Troubleshooting

### Enable Logging

```go
rt, _ := tng.NewRoundTripper(cfg, tng.WithLogFilter("debug"))
```

Supported levels: `error`, `warn`, `info`, `debug`, `trace`, `off`.

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `TNG binary not found` | `tng` not on PATH | Set `TNG_BINARY` env var or install tng |
| `Port ... not ready within 30s` | TNG failed to start | Check logs with `WithLogFilter("debug")` |
| `Connection refused` | TNG server not reachable | Verify server is running and port is correct |
