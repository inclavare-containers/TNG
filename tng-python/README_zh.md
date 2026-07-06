# TNG Python SDK

[![PyPI](https://img.shields.io/pypi/v/tng-sdk?logo=pypi&label=pypi)](https://pypi.org/project/tng-sdk/)

[English](README.md)

Trusted Network Gateway (TNG) Python SDK — 加密 HTTP 请求与远程证明。

## 快速开始

```bash
pip install tng-sdk
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

## 加密协议

```python
# 默认使用 OHTTP
tng = Tng(no_ra=True)

# 使用 rats-TLS 替代 OHTTP（二者互斥）
tng = Tng(no_ra=True, rats_tls={"multiplex": True})
```

## 文档

- **[快速入门](https://github.com/inclavare-containers/TNG/blob/master/tng-python/docs/getting-started_zh.md)** — 完整的安装、使用和配置指南
- **[Getting Started](https://github.com/inclavare-containers/TNG/blob/master/tng-python/docs/getting-started.md)** — Complete installation, usage, and configuration guide
