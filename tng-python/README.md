# TNG Python SDK

[中文文档](README_zh.md)

Trusted Network Gateway (TNG) Python SDK — encrypted HTTP requests with remote attestation.

## Quick Start

```bash
pip install tng-sdk
```

```python
from tng import Tng
import requests

# Create TNG client (no_ra = disable remote attestation for testing)
tng = Tng(no_ra=True)

# Wrap a requests session
session = requests.Session()
tng.wrap_requests(session)

# All requests flow through the encrypted TNG tunnel
resp = session.get("http://tng-server:10001/api/data")
print(resp.json())

tng.close()
```

## Supported Clients

| Client | Method |
|--------|--------|
| **requests** | `tng.wrap_requests(session)` |
| **httpx** | `tng.wrap_httpx(client)` |
| **openai** | `tng.wrap_openai(client)` |

## Security Options

```python
# Disable remote attestation (testing only)
tng = Tng(no_ra=True)

# With verifier
tng = Tng(verify={"as_addr": "http://127.0.0.1:8080/", "policy_ids": ["default"]})

# With attester
tng = Tng(attest={"aa_addr": "unix:///run/aa.sock", "model": "passport"})

# Bidirectional attestation
tng = Tng(
    attest={"aa_addr": "unix:///run/aa.sock"},
    verify={"as_addr": "http://127.0.0.1:8080/", "policy_ids": ["default"]}
)
```

## Encryption Protocol

```python
# OHTTP is the default
tng = Tng(no_ra=True)

# Use rats-TLS instead of OHTTP (mutually exclusive)
tng = Tng(no_ra=True, rats_tls={"multiplex": True})

# Custom OHTTP
tng = Tng(no_ra=True, ohttp={"key": {"source": "self_generated", "rotation_interval": 300}})
```

## Documentation

- **[Getting Started](docs/getting-started.md)** — Complete installation, usage, and configuration guide
- **[Getting Started (中文)](docs/getting-started_zh.md)** — 完整的安装、使用和配置指南
