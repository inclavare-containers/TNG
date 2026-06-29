# TNG Go SDK

Go SDK for [Trusted Network Gateway](https://github.com/inclavare-containers/tng).
Encrypts HTTP traffic via OHTTP (Oblivious HTTP) or rats-TLS.

## Prerequisites

The TNG binary must be available on your system. Install it via:

- **PATH**: `tng` must be in your `PATH`
- **Environment**: Set `TNG_BINARY=/path/to/tng` to specify a custom path

The `TNG_BINARY` environment variable is shared with the [Python SDK](../tng-python).

## Installation

```bash
go get github.com/inclavare-containers/tng/sdk-go/tng-go
```

No CGO required — pure Go build.

## Quick Start

```go
import "github.com/inclavare-containers/tng/sdk-go/tng-go"

func main() {
    // Create a RoundTripper (spawns TNG subprocess automatically)
    rt, err := tng.NewRoundTripper(&tng.Config{NoRA: true})
    if err != nil {
        log.Fatal(err)
    }
    defer rt.Close()

    // Use with standard http.Client
    client := &http.Client{Transport: rt}
    resp, err := client.Get("http://target:30001/api/data")
    // ... response is encrypted via OHTTP
}
```

## Configuration

### NoRA (local development)

```go
cfg := &tng.Config{NoRA: true}
```

### Verify-only (server attestation)

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

### Mutual attestation

```go
cfg := &tng.Config{
    Attest: map[string]any{
        "model":   "background_check",
        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
    },
    Verify: map[string]any{
        "model":       "background_check",
        "as_provider": "coco",
        "as_addr":     "http://127.0.0.1:8080/",
        "policy_ids":  []string{"default"},
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

> **Note:** OHttp and RatsTls are mutually exclusive. Set only one.

### Fallback for non-TNG URLs

```go
rt, _ := tng.NewRoundTripper(cfg, tng.WithFallback(
    http.DefaultTransport,
    func(u *url.URL) bool {
        return u.Host != "target.internal:30001"
    },
))
```

## How It Works

The SDK starts a TNG subprocess with an `http_proxy` ingress on a random localhost port. All HTTP requests are forwarded to this proxy, which encrypts them via OHTTP (or rats-TLS) before sending to the remote TNG server (egress). Response streaming (SSE, chunked transfer) works transparently via standard HTTP.

```
Your Code → http.Client → TNG http_proxy (127.0.0.1:port) → OHTTP → TNG Server → Backend
```

## Architecture

- **No CGO**: Pure Go, no Rust FFI, no `.so` files
- **Subprocess**: TNG runs as a child process, managed by the SDK
- **Standard HTTP**: Requests flow through http_proxy, streaming works natively

## More Documentation

- [Getting Started Guide](docs/getting-started.md)
- [快速入门指南（中文）](docs/getting-started_zh.md)
