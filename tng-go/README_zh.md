# TNG Go SDK

[Trusted Network Gateway](https://github.com/inclavare-containers/tng) 的 Go SDK。
通过 OHTTP（Oblivious HTTP）或 rats-TLS 加密 HTTP 流量。

## 前置要求

系统中必须有 TNG 二进制可用：

- **PATH**：`tng` 必须在系统 `PATH` 中
- **环境变量**：设置 `TNG_BINARY=/path/to/tng` 指定自定义路径

`TNG_BINARY` 环境变量与 [Python SDK](../tng-python) 共享。

## 安装

```bash
go get github.com/inclavare-containers/tng/sdk-go/tng-go
```

无需 CGO — 纯 Go 构建。

## 快速开始

```go
import "github.com/inclavare-containers/tng/sdk-go/tng-go"

func main() {
    // 创建 RoundTripper（自动启动 TNG 子进程）
    rt, err := tng.NewRoundTripper(&tng.Config{NoRA: true})
    if err != nil {
        log.Fatal(err)
    }
    defer rt.Close()

    // 与标准 http.Client 配合使用
    client := &http.Client{Transport: rt}
    resp, err := client.Get("http://target:30001/api/data")
    // ... 响应通过 OHTTP 加密
}
```

## 配置

### NoRA（本地开发）

```go
cfg := &tng.Config{NoRA: true}
```

### 仅验证（服务器证明）

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

### 双向认证

```go
cfg := &tng.Config{
    Attest: map[string]any{
        "model":   "background_check",
        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
    },
    Verify: map[string]any{
        "model":       "background_check",
        "as_provider": "coco",
        "as_type":     "restful",
        "as_addr":     "http://127.0.0.1:8080/",
        "policy_ids":  []string{"default"},
    },
}
```

### 为非 TNG URL 设置回退

```go
rt, _ := tng.NewRoundTripper(cfg, tng.WithFallback(
    http.DefaultTransport,
    func(u *url.URL) bool {
        return u.Host != "target.internal:30001"
    },
))
```

## 工作原理

SDK 启动一个 TNG 子进程，在随机本地端口上配置 `http_proxy` ingress。所有 HTTP 请求被转发到此代理，通过 OHTTP（或 rats-TLS）加密后发送到远程 TNG 服务器（egress）。响应流式传输（SSE、分块传输）通过标准 HTTP 透明工作。

```
你的代码 → http.Client → TNG http_proxy (127.0.0.1:端口) → OHTTP → TNG Server → 后端服务
```

## 架构

- **无 CGO**：纯 Go，无 Rust FFI，无 `.so` 文件
- **子进程**：TNG 作为子进程运行，由 SDK 管理
- **标准 HTTP**：请求通过 http_proxy 流转，流式传输原生支持

## 更多文档

- [快速入门指南（中文）](docs/getting-started_zh.md)
- [Getting Started Guide (English)](docs/getting-started.md)
