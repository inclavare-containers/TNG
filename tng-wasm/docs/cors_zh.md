# 浏览器/WASM 请求的 CORS 处理

本文说明如何配置 TNG Server，以支持浏览器通过 TNG WASM SDK 发送跨域加密请求。

## 为什么引入 TNG 后 CORS 处理会变得复杂

TNG WASM SDK 在浏览器中发送请求时，底层采用 OHTTP 协议，将真实的"内层" HTTP 请求加密后封装进"外层" HTTP 请求的 body 中。浏览器**只感知外层请求**，因此其 CORS 检查（预检 + 响应头校验）仅作用于**外层**请求与响应。内层请求的 method、headers，以及后端服务返回的 `Access-Control-Allow-*` 等响应头，均被加密在 OHTTP body 中，浏览器无法读取。

因此，CORS 的处理方式取决于**"CORS 权威"**（即负责响应预检请求的主体）在整体架构中所处的位置。以下三种场景覆盖了常见部署情况。

---

## 场景 1：CORS 权威位于 TNG Server 前端

由前置网关（如 Nginx、云厂商 ALB 或其他反向代理）统一承担 CORS 职责，负责所有 CORS 决策。

这是最简单的场景，**TNG Server 无需任何额外配置**。前置网关需要：

- 响应 CORS 预检请求（`OPTIONS`），返回以下响应头：
  - `Access-Control-Allow-Origin`
  - `Access-Control-Allow-Methods`（至少包含 `POST`）
  - `Access-Control-Allow-Headers`（至少包含 `Content-Type` 和 `x-tng-ohttp-api`）
- 在实际响应中设置 `Access-Control-Allow-Origin`

---

## 场景 2：CORS 权威位于 TNG Server 后端

TNG Server 前端没有承担 CORS 的网关，由后端业务服务作为 CORS 权威，自行处理 CORS 决策。此场景需将 TNG Server 配置为 CORS 决策的**透明中继**，将预检请求转发给后端，并将后端的 CORS 响应头透传给浏览器。

具体而言，TNG Server 需要：

- 将浏览器发出的预检请求头转发给后端服务
- 将后端服务的 CORS 响应头透传至外层响应，使浏览器可见

在TNG Server的egress配置上增加如下内容
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

对后端业务服务的要求：

- 响应 CORS 预检请求（`OPTIONS`），返回至少：
  - `Access-Control-Allow-Methods`（至少包含 `POST`）
  - `Access-Control-Allow-Headers`（至少包含 `Content-Type` 和 `x-tng-ohttp-api`，或使用 `Access-Control-Allow-Headers: *`）
- 处理非预检请求时，根据请求中的 `Origin` 设置对应的 `Access-Control-Allow-Origin`

---

## 场景 3：由 TNG 承担 CORS 职责（不推荐）

通过配置 `ohttp.cors`，让 TNG 使用内置 CORS 层自行处理预检请求，并在实际响应中注入 `Access-Control-Allow-Origin` 等响应头。

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

**为何不推荐？** TNG 对所有请求统一套用同一份全局 CORS 策略，无法像场景 2 中的后端服务或场景 1 中的网关那样，针对不同资源进行细粒度的 `Access-Control-Allow-Origin` 决策。

**适用场景：** 后端服务完全不支持 CORS，且仅需通过 TNG 开放跨域浏览器访问，不涉及任何基于资源的 CORS 逻辑。

> [!WARNING]
> 请勿在场景 1 或场景 2 中同时配置 `ohttp.cors`。否则 TNG 将与前置网关或后端服务形成两个并存的 CORS 权威，导致响应头冲突。`ohttp.cors` 仅适用于本场景。

---

## 场景对比

|  | 场景 1：网关前置 | 场景 2：后端服务作为权威 | 场景 3：TNG 作为权威 |
|---|---|---|---|
| 预检请求由谁响应 | 前置网关 | TNG 转发给后端服务 | TNG（`ohttp.cors`） |
| `Access-Control-Allow-Origin` 由谁设置 | 前置网关 | 后端服务（经 TNG 透传） | TNG（`ohttp.cors`） |
| `ohttp.cors` | 不配置 | 不配置 | 配置 |
| `header_passthrough` | 不配置 | 配置（透传 `origin` 及 `access-control-*`） | 不需要 |
| 后端服务是否参与 CORS | 不需要 | 是，作为 CORS 权威 | 不参与（由 TNG 决定） |
| 是否推荐 | ✅ 有网关时首选 | ✅ 后端自管 CORS 时适用 | ⚠️ 仅用于无 CORS 支持的简单场景 |