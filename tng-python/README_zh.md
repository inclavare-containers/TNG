# TNG Python SDK

[English](README.md)

Trusted Network Gateway (TNG) Python SDK — 加密 HTTP 请求与远程证明。

## 快速开始

```bash
pip install tng
```

```python
from tng import Tng
import requests

# 创建 TNG 客户端（no_ra = 禁用远程证明，仅用于测试）
tng = Tng(no_ra=True)

# 包装 requests session
session = requests.Session()
tng.wrap_requests(session)

# 所有请求通过加密的 TNG 隧道
resp = session.get("http://tng-server:10001/api/data")
print(resp.json())

tng.close()
```

## 支持的客户端

| 客户端 | 方法 |
|--------|------|
| **requests** | `tng.wrap_requests(session)` |
| **httpx** | `tng.wrap_httpx(client)` |
| **openai** | `tng.wrap_openai(client)` |

## 安全选项

```python
# 禁用远程证明（仅用于测试）
tng = Tng(no_ra=True)

# 使用验证器
tng = Tng(verify={"as_addr": "http://127.0.0.1:8080/", "policy_ids": ["default"]})

# 使用证明者
tng = Tng(attest={"aa_addr": "unix:///run/aa.sock", "model": "passport"})

# 双向认证
tng = Tng(
    attest={"aa_addr": "unix:///run/aa.sock"},
    verify={"as_addr": "http://127.0.0.1:8080/", "policy_ids": ["default"]}
)
```

## 文档

- **[快速入门](docs/getting-started_zh.md)** — 完整的安装、使用和配置指南
- **[Getting Started](docs/getting-started.md)** — Complete installation, usage, and configuration guide
- **[架构说明](#架构)** — 工作原理

## 架构

```
你的代码 → HTTP 库（原生代理）→ TNG http_proxy（本地）
    → OHTTP/rats-TLS → TNG Server（远程）→ 后端服务
```

SDK 启动一个 TNG 子进程，配置 `http_proxy` ingress。请求通过各 HTTP 库的原生代理支持路由，自动加密后发送到远程 TNG 服务器。

## 要求

- Python 3.8+
- `tng` 二进制在系统 PATH 上（wheel 中已包含，或单独安装）

详细安装说明请参阅[快速入门指南](docs/getting-started_zh.md)。
