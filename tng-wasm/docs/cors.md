# CORS Handling for Browser/WASM Requests

This document explains how to configure TNG Server to support browsers sending cross-origin encrypted requests via the TNG WASM SDK.

## Why CORS Gets Complicated with TNG

When the TNG WASM SDK sends requests from a browser, it uses the OHTTP protocol to encrypt the real "inner" HTTP request and encapsulate it inside the body of an "outer" HTTP request. The browser **only sees the outer request**, so its CORS checks (preflight + response header validation) apply exclusively to the **outer** request and response. The inner request's method and headers, as well as any `Access-Control-Allow-*` headers returned by the backend, are all encrypted inside the OHTTP body and are invisible to the browser.

As a result, how CORS should be handled depends on where the **CORS authority** (the component responsible for responding to preflight requests) sits in your architecture. The three scenarios below cover the most common deployment patterns.

---

## Scenario 1: CORS Authority in Front of TNG Server

A front-end gateway (e.g., Nginx, a cloud ALB, or any other reverse proxy) acts as the sole CORS authority and handles all CORS decisions.

This is the simplest scenario. **No additional configuration is required on TNG Server.** The gateway must:

- Respond to CORS preflight requests (`OPTIONS`) with the following headers:
  - `Access-Control-Allow-Origin`
  - `Access-Control-Allow-Methods` (must include at least `POST`)
  - `Access-Control-Allow-Headers` (must include at least `Content-Type` and `x-tng-ohttp-api`)
- Set `Access-Control-Allow-Origin` on actual responses

---

## Scenario 2: CORS Authority Behind TNG Server

There is no front-end gateway handling CORS. Instead, the backend service acts as the CORS authority and makes all CORS decisions itself. In this scenario, TNG Server must be configured as a **transparent relay** for CORS, forwarding preflight headers to the backend and passing the backend's CORS response headers back to the browser.

Specifically, TNG Server must be configured to:

- Forward preflight request headers from the browser to the backend service
- Pass the backend's CORS response headers through to the outer response, making them visible to the browser

Add the following to the TNG Server egress configuration:

```json
{
  "ohttp": {
    "header_passthrough": {
      "request_headers": [
        "origin",
        "access-control-request-method",
        "access-control-request-headers"
      ],
      "response_headers": [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-allow-credentials",
        "access-control-max-age"
      ]
    }
  }
}
```

Requirements for the backend service:

- Respond to CORS preflight requests (`OPTIONS`) with at least:
  - `Access-Control-Allow-Methods` (must include at least `POST`)
  - `Access-Control-Allow-Headers` (must include at least `Content-Type` and `x-tng-ohttp-api`, or use `Access-Control-Allow-Headers: *`)
- For non-preflight requests, set `Access-Control-Allow-Origin` based on the `Origin` header in the request

---

## Scenario 3: TNG as the CORS Authority (Not Recommended)

Configure `ohttp.cors` to have TNG handle preflight requests using its built-in CORS layer and inject `Access-Control-Allow-Origin` and related headers into actual responses.

```json
{
  "ohttp": {
    "cors": {
      "allow_origins": ["*"],
      "allow_methods": ["*"],
      "allow_headers": ["*"],
      "expose_headers": [],
      "allow_credentials": false
    }
  }
}
```

**Why is this not recommended?** TNG applies a single global CORS policy to all requests. Unlike the backend service in Scenario 2 or the gateway in Scenario 1, it cannot make per-resource, fine-grained `Access-Control-Allow-Origin` decisions.

**When it applies:** Your backend has no CORS support at all, and you only need to enable cross-origin browser access through TNG without any per-resource CORS logic.

> [!WARNING]
> Do not configure `ohttp.cors` alongside Scenario 1 or Scenario 2. Doing so creates two competing CORS authorities — TNG plus the gateway or backend — which will result in conflicting response headers. `ohttp.cors` is intended exclusively for this scenario.

---

## Scenario Comparison

|  | Scenario 1: Gateway in Front | Scenario 2: Backend as Authority | Scenario 3: TNG as Authority |
|---|---|---|---|
| Who responds to preflight requests | Front-end gateway | Backend service (forwarded by TNG) | TNG (`ohttp.cors`) |
| Who sets `Access-Control-Allow-Origin` | Front-end gateway | Backend service (passed through by TNG) | TNG (`ohttp.cors`) |
| `ohttp.cors` | Not configured | Not configured | Configured |
| `header_passthrough` | Not configured | Configured (passes `origin` and `access-control-*`) | Not needed |
| Does the backend participate in CORS | No | Yes, as the CORS authority | No (TNG decides) |
| Recommended | ✅ Preferred when a gateway is present | ✅ Suitable when the backend manages its own CORS | ⚠️ Only for simple backends with no CORS support |