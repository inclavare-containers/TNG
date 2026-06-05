"""TNG (Trusted Network Gateway) Python SDK.

Provides encrypted HTTP requests with remote attestation by managing
a TNG subprocess (http_proxy ingress) and using each HTTP library's
native proxy support to route traffic through the encrypted tunnel.

The user only provides security options; the target address is carried
in the request URL's Host header and read by the http_proxy ingress.

Usage:
    from tng import Tng

    # Simplest: disable remote attestation (for testing)
    tng = Tng(no_ra=True)

    # With verifier
    tng = Tng(
        verify={
            "as_addr": "http://127.0.0.1:8080/",
            "policy_ids": ["default"],
        },
    )

    # Wrap requests.Session
    import requests
    session = requests.Session()
    tng.wrap_requests(session)
    resp = session.get("http://tng-server:10001/api/data")

    # Wrap httpx.Client
    import httpx
    client = httpx.Client()
    tng.wrap_httpx(client)
    resp = client.get("http://tng-server:10001/api/data")

    # Wrap OpenAI client
    from openai import OpenAI
    openai_client = OpenAI(api_key="sk-xxx", base_url="http://tng-server:10001/v1")
    tng.wrap_openai(openai_client)
    completion = openai_client.chat.completions.create(model="xxx", messages=[...])
"""

from tng._tng import Tng

__all__ = ["Tng"]
