# TNG Python SDK 快速入门

## 安装

### 从 PyPI 安装

```bash
pip install tng
```

### 从预构建的 wheel 安装

从 [GitHub Releases](https://github.com/inclavare-containers/tng/releases) 下载对应平台的 wheel：

```bash
pip install tng-0.1.0-cp38-abi3-linux_x86_64.whl
```

支持的平台：
- `x86_64-unknown-linux-gnu` (Linux x86_64)
- `aarch64-unknown-linux-gnu` (Linux ARM64)
- `x86_64-apple-darwin` (macOS Intel)
- `aarch64-apple-darwin` (macOS Apple Silicon)

### 从源码构建

需要 Rust 工具链和 maturin：

```bash
# 编译 tng 二进制
cargo build --release -p tng
cp target/release/tng tng-python/bin/scripts/tng

# 构建并安装 Python SDK
cd tng-python
maturin develop
```

### TNG 二进制要求

SDK 需要以下位置之一存在 `tng` 二进制文件：
1. 设置 `TNG_BINARY` 环境变量
2. 在系统 `PATH` 上（`shutil.which("tng")`）
3. 开发模式：`{module_dir}/../bin/tng`
4. 系统安装在 `/usr/bin/tng`

## 快速开始

### 使用 requests

```python
from tng import Tng
import requests

# 创建 TNG 客户端
tng = Tng(no_ra=True)

# 包装 requests session
session = requests.Session()
tng.wrap_requests(session)

# 通过加密隧道发送请求
resp = session.get("http://tng-server:10001/api/data")
print(resp.json())

# 清理
tng.close()
```

### 使用 httpx

```python
import httpx
from tng import Tng

tng = Tng(no_ra=True)

# 同步客户端
client = httpx.Client()
tng.wrap_httpx(client)
resp = client.get("http://tng-server:10001/api/data")
client.close()

# 异步客户端
async def main():
    async with httpx.AsyncClient() as client:
        tng.wrap_httpx(client)
        resp = await client.get("http://tng-server:10001/api/data")
```

### 使用 OpenAI

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

## 工作原理

Python SDK 管理一个本地 TNG 进程，作为 HTTP 代理：

```
你的代码 -> requests/httpx（原生代理）-> TNG http_proxy（本地）
    -> OHTTP/rats-TLS 加密 -> TNG Server（远程）-> 后端服务
```

1. **你创建 `Tng()`** — SDK 启动一个 TNG 子进程，自动配置 `http_proxy` ingress
2. **你包装 HTTP 客户端** — SDK 将原生代理设置到本地 http_proxy 端口
3. **你发送请求** — HTTP 库通过标准 HTTP 代理协议路由请求
4. **TNG 加密并转发** — http_proxy ingress 从 Host header 读取目标，通过 OHTTP/rats-TLS 加密发送到远程 TNG Server
5. **TNG Server 解密并转发** — 远程 egress 解密后转发到你的后端

### 客户端 vs 服务器

Python SDK 仅管理**客户端侧**（http_proxy ingress）。**服务器侧**（egress）必须单独部署：

```
客户端（Python SDK）：              服务器（你部署的）：
  Tng(no_ra=True)                   TNG Server 配置：
    -> http_proxy ingress              -> add_egress: [{ mapping }]
    -> OHTTP 加密                       -> 解密并转发到后端
```

## 安全配置

### 禁用远程证明（仅用于测试）

```python
tng = Tng(no_ra=True)
```

### 验证器模式

验证远程服务器的证明：

```python
tng = Tng(
    verify={
        "as_addr": "http://127.0.0.1:8080/",
        "policy_ids": ["default"],
    },
)
```

### 证明者模式

向服务器提供自己的证明：

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

### 双向认证

客户端和服务器互相验证：

```python
tng = Tng(
    attest={"aa_addr": "unix:///run/.../attestation-agent.sock"},
    verify={"as_addr": "http://127.0.0.1:8080/", "policy_ids": ["default"]},
)
```

### OHTTP 自定义

```python
tng = Tng(
    no_ra=True,
    ohttp={
        "key": {"source": "self_generated", "rotation_interval": 300},
        "path_rewrites": [
            {"match_regex": "^/api/(.*)", "substitution": "/v1/\\1"},
        ],
    },
)
```

### 使用 rats-TLS 代替 OHTTP

```python
tng = Tng(
    rats_tls={"multiplex": True},
)
```

> **注意：** `ohttp` 和 `rats_tls` 互斥。如果都不指定，默认使用 `ohttp={}`。

## 流式支持

### requests SSE

```python
resp = session.get("http://tng-server:10001/events", stream=True)
for line in resp.iter_lines():
    if line:
        print(line.decode())
```

### httpx SSE（同步）

```python
with httpx.Client() as client:
    tng.wrap_httpx(client)
    with client.stream("GET", "http://tng-server:10001/events") as resp:
        for chunk in resp.iter_text():
            print(chunk)
```

### httpx SSE（异步）

```python
async with httpx.AsyncClient() as client:
    tng.wrap_httpx(client)
    async with client.stream("GET", "http://tng-server:10001/events") as resp:
        async for chunk in resp.aiter_text():
            print(chunk)
```

### OpenAI LLM 流式

```python
# 同步
for chunk in client.chat.completions.create(
    model="my-model",
    messages=[{"role": "user", "content": "Hello"}],
    stream=True,
):
    print(chunk.choices[0].delta.content or "", end="")

# 异步
async for chunk in await async_client.chat.completions.create(
    model="my-model",
    messages=[{"role": "user", "content": "Hello"}],
    stream=True,
):
    print(chunk.choices[0].delta.content or "", end="")
```

## TNG 服务器部署

服务器侧的 TNG 进程需要单独部署。最小配置示例：

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

客户端 SDK 通过 `<server-host>:10001` 连接 — 这个地址放在你的请求 URL 中。

## 故障排查

### 启用日志

```python
import os
os.environ["RUST_LOG"] = "debug"
tng = Tng(no_ra=True)
```

支持的级别：`error`、`warn`、`info`、`debug`、`trace`、`off`。

### 检查生成的配置

SDK 将 TNG 配置写入临时文件：

```bash
ls -lt /tmp/tng_cfg_*.json | head -1
cat /tmp/tng_cfg_*.json
```

### 独立运行 TNG

```bash
RUST_LOG=debug tng launch --config-file /tmp/tng_cfg_xxxxx.json
```

### 常见错误

| 错误 | 原因 | 解决 |
|------|------|------|
| `TNG binary not found` | `tng` 不在 PATH 上 | 设置 `TNG_BINARY` 环境变量或安装 tng |
| `Port ... not ready within 30s` | TNG 启动失败 | 检查日志，验证配置 |
| `Connection refused` | TNG 服务器不可达 | 验证服务器运行正常且端口正确 |
| `ohttp and rats_tls are mutually exclusive` | 同时指定 | 移除其中一个 |

## 生命周期管理

### 显式清理

```python
tng = Tng(no_ra=True)
try:
    # 使用 tng
    ...
finally:
    tng.close()
```

### 自动清理

`tng.close()` 在以下情况自动调用：
- 对象被删除（`__del__`）
- 解释器退出（`atexit`）

### 可重复调用

```python
tng.close()
tng.close()  # 无操作，安全
```
