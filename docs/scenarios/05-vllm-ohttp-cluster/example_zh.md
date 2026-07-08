# TNG 接入方式测试脚本

[English](example.md)

`run.sh` 端到端验证 TNG 访问一个 vLLM 风格 `/v1/completions` 推理端点的四种方式 —— 全程 OHTTP 加密 + 远程证明校验 —— 并断言流式模型 token 正常返回。

| 方式（`-m`） | 驱动内容 |
| --- | --- |
| `daemon` | 以 TNG `http_proxy` 入口作为本地代理，请求经 `all_proxy` 用 `curl` 发出 |
| `python` | TNG Python SDK（`tng-sdk`），包装一个 `requests` 会话 |
| `go` | TNG Go SDK（`tng-go`），作为 `openai` 客户端的 `RoundTripper` |
| `wasm` | TNG WASM/JS SDK，在 headless Chromium 中由 Playwright 驱动 |

每种方式的实现位于 `access/<name>.sh`，由 `run.sh` source 进来。本场景的集群拓扑见
[README_zh.md](README_zh.md)。

## 前置条件

公共：`curl`；需要提供 `--token` 和 `--completions-url`。

各方式额外要求：

- **daemon** —— 一个支持 `path_default` 配置字段的 `tng` 二进制（TNG ≥ 2.8）。默认
  `cargo run --release --`（从源码编译）；可用 `--tng-bin /path/to/tng` 覆盖。
  `--proxy-port` 指定本地代理端口（默认 41000）。
- **python** —— Python ≥ 3.8。`tng-sdk` 与 `requests` 会自动安装。会拉起一个 `tng`
  子进程，按 `target/release/tng` → `target/debug/tng` 顺序解析（请先用
  `cargo build --release` 构建）。
- **go** —— Go 工具链。会拉起一个 `tng` 子进程，按 `$TNG_BINARY` →
  `target/release/tng` → `target/debug/tng` → PATH 上的 `tng` 顺序解析。
- **wasm** —— 已构建的 WASM 包（位于 `tng-wasm/pkg/`，用 `make wasm-build-debug`
  构建）。一个 Chromium/Chrome 二进制（用 `$TNG_CHROME` 覆盖；否则用系统
  `google-chrome`，或由 Playwright 下载）。Python ≥ 3.8；`playwright` 会自动安装。

## 用例

先设置 token：

```bash
export TNG_TEST_TOKEN="<你的端点 token>"
```

### 1）守护进程（http_proxy 入口；任意 HTTP 客户端经 `all_proxy`）

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m daemon \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct \
    --tng-bin         ./target/release/tng
```

### 2）Python SDK

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m python \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct
```

### 3）Go SDK

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m go \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct
```

### 4）JS SDK（浏览器，WASM）

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m wasm \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct
```

### 依次跑全部四种

```bash
docs/scenarios/05-vllm-ohttp-cluster/run.sh -m all \
    --completions-url http://inference.example.com/v1/completions \
    --as-url          http://as.example.com:8081/api/as/ \
    --token           "$TNG_TEST_TOKEN" \
    --model           Qwen2.5-3B-Instruct
```

## 选项

| 选项 | 说明 |
| --- | --- |
| `-m, --method` | `daemon` / `python` / `go` / `wasm` / `all`（默认 `all`） |
| `--completions-url` | 完整的 `/v1/completions` URL（必填，或设 `$TNG_TEST_COMPLETIONS_URL`） |
| `--as-url` | 证明服务（AS）地址（默认 `$TNG_TEST_AS_URL`） |
| `--token` | 端点鉴权 token（必填，或设 `$TNG_TEST_TOKEN`） |
| `--model` | 模型名（默认 `Qwen3.5-0.8B`） |
| `--proxy-port` | daemon 的本地代理端口（默认 41000） |
| `--tng-bin` | daemon 的 `tng` 命令前缀（默认 `cargo run --release --`） |
| `--builtin-as` | 使用内置 AS 验证（仅 docker 镜像 / `builtin-as-*` 构建可用；其余方式会 SKIP） |
| `--keep` | 不杀守护进程 / 保留临时文件 |
| `-h, --help` | 显示帮助 |

## 环境变量

上述每个选项都有对应的 `TNG_TEST_*` 环境变量：`TNG_TEST_METHOD`、
`TNG_TEST_COMPLETIONS_URL`、`TNG_TEST_AS_URL`、`TNG_TEST_TOKEN`、`TNG_TEST_MODEL`、
`TNG_TEST_PROXY_PORT`、`TNG_TEST_BIN`。daemon 方式还读取 `TNG_TEST_STARTUP_TIMEOUT`
（默认 240s）、`TNG_TEST_REQ_TIMEOUT`（默认 90s）、`TNG_TEST_AS_GRACE`（默认 15s）。
go 方式识别 `TNG_BINARY`（子进程二进制）；wasm 方式识别 `TNG_CHROME`（浏览器二进制）。

## 输出

每种方式恰好输出一行结果：`PASS <方式>`、`FAIL <方式> <原因>` 或 `SKIP <方式> <原因>`
（如缺少前置条件，或在默认构建上使用 `--builtin-as`）。`FAIL` 时 daemon 方式还会把
日志尾部打到 stderr。任一被选方式失败，脚本以非零码退出。
