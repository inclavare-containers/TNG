# TNG Go SDK 快速入门

## 前置要求

系统中必须有 TNG 二进制可用。SDK 在运行时自动发现：

1. **`TNG_BINARY` 环境变量**（与 [Python SDK](../../tng-python) 共享）
2. **`PATH` 查找** — `tng` 必须在系统 `PATH` 中

如果两者都未找到，`NewRoundTripper` 将返回错误。

## 安装

```bash
go get github.com/inclavare-containers/tng/sdk-go/tng-go
```

无需 CGO — 纯 Go 构建（`CGO_ENABLED=0 go build` 可用）。

## 快速开始

### 基本用法

```go
package main

import (
    "log"
    "net/http"

    tng "github.com/inclavare-containers/tng/sdk-go/tng-go"
)

func main() {
    // 创建 RoundTripper（自动启动 TNG 子进程）
    rt, err := tng.NewRoundTripper(&tng.Config{NoRA: true})
    if err != nil {
        log.Fatal(err)
    }
    defer rt.Close()

    // 与标准 http.Client 配合使用
    client := &http.Client{Transport: rt}
    resp, err := client.Get("http://tng-server:10001/api/data")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    log.Printf("Status: %d", resp.StatusCode)
}
```

### 为非 TNG URL 设置 http_proxy 回退

```go
rt, _ := tng.NewRoundTripper(cfg, tng.WithFallback(
    http.DefaultTransport,
    func(u *url.URL) bool {
        return u.Host != "tng-server:10001"
    },
))
```

## 安全配置

### 禁用远程证明（仅用于测试）

```go
cfg := &tng.Config{NoRA: true}
```

### 验证器模式（服务器证明）

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

### 证明者模式（客户端证明）

```go
cfg := &tng.Config{
    Attest: map[string]any{
        "model":   "background_check",
        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
    },
}
```

### 双向认证

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

## 流式支持

SSE 和分块传输编码透明工作 — 无需特殊配置：

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

## 工作原理

SDK 启动一个 TNG 子进程，在随机本地端口上配置 `http_proxy` ingress。所有 HTTP 请求被转发到此代理，通过 OHTTP（或 rats-TLS）加密后发送到远程 TNG 服务器（egress）。响应流式传输通过标准 HTTP 透明工作。

```
你的代码 → http.Client → TNG http_proxy (127.0.0.1:端口) → OHTTP → TNG Server → 后端服务
```

### 客户端 vs 服务器

Go SDK 仅管理**客户端侧**（http_proxy ingress）。**服务器侧**（egress）必须单独部署：

```
客户端（Go SDK）：                  服务器（你部署的）：
  NewRoundTripper(cfg)               TNG Server 配置：
    -> http_proxy ingress              -> add_egress: [{ mapping }]
    -> OHTTP 加密                       -> 解密并转发到后端
```

## TNG 服务器部署

服务器侧的 TNG 进程需要单独部署。最小配置：

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

启动服务器：

```bash
tng launch --config-file server-config.json
```

客户端通过 `<server-host>:10001` 连接。

## 生命周期管理

### 显式清理

```go
rt, _ := tng.NewRoundTripper(cfg)
defer rt.Close() // 始终 defer Close
```

### 获取证明信息

请求成功后，从响应中获取服务器证明：

```go
info := tng.GetAttestationInfo(resp)
if info != nil {
    fmt.Printf("Attestation token: %s\n", info.Token)
}
```

## 故障排查

### 启用日志

```go
rt, _ := tng.NewRoundTripper(cfg, tng.WithLogFilter("debug"))
```

支持的级别：`error`、`warn`、`info`、`debug`、`trace`、`off`。

### 常见错误

| 错误 | 原因 | 解决 |
|------|------|------|
| `TNG binary not found` | `tng` 不在 PATH 上 | 设置 `TNG_BINARY` 环境变量或安装 tng |
| `Port ... not ready within 30s` | TNG 启动失败 | 使用 `WithLogFilter("debug")` 检查日志 |
| `Connection refused` | TNG 服务器不可达 | 验证服务器运行正常且端口正确 |
