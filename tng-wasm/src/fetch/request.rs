use anyhow::{Context as _, Result};
use futures::{AsyncReadExt, StreamExt, TryStreamExt};
use tng::tunnel::endpoint::TngEndpoint;
use wasm_bindgen::prelude::*;

use super::to_js_error;

/// Parse an absolute request URL into an `http::Uri`, mapping parse failures
/// across the JS boundary.
pub(super) fn parse_request_uri(url: &str) -> Result<http::Uri, JsValue> {
    url.parse::<http::Uri>()
        .context("Failed to parse request URL")
        .map_err(to_js_error)
}

/// Resolve the upstream TNG endpoint (host/port) from an absolute request URI.
///
/// Defaults to 443 for `https`, 80 otherwise — matches the daemon's http_proxy
/// forwarding (tng/src/tunnel/ingress/http_proxy.rs).
pub(super) fn upstream_endpoint(uri: &http::Uri) -> Result<TngEndpoint, JsValue> {
    let authority = uri
        .authority()
        .context("The authority is empty")
        .map_err(to_js_error)?;
    let default_port = if uri.scheme_str() == Some("https") {
        443
    } else {
        80
    };
    Ok(TngEndpoint::new(
        authority.host(),
        authority.port_u16().unwrap_or(default_port),
    ))
}

async fn read_body_to_bytes(
    body_stream: web_sys::ReadableStream,
) -> Result<Vec<u8>, anyhow::Error> {
    let stream = wasm_streams::ReadableStream::from_raw(body_stream)
        .into_stream()
        .map(|chunk| {
            chunk.and_then(|chunk| {
                let uint8_array = chunk.dyn_into::<js_sys::Uint8Array>().map_err(|e| {
                    JsValue::from(JsError::new(&format!(
                        "Failed to convert chunk to Expected Uint8Array: {e:?}"
                    )))
                })?;
                Ok(uint8_array.to_vec())
            })
        })
        .map_err(|e| std::io::Error::other(anyhow::anyhow!("Stream error: {:?}", e)));

    let mut reader = stream.into_async_read(); // This allows using async read methods
    let mut buffer = Vec::new();

    reader.read_to_end(&mut buffer).await.map_err(|error| {
        tracing::error!(?error, "Error in read_to_end()");
        error
    })?;
    Ok(buffer)
}

/// Build an `http::Request` from the browser `web_sys::Request` plus the
/// pre-parsed absolute URI.
///
/// The browser-built Request carries the full absolute URL but does NOT expose
/// a `Host` header (fetch sets it internally, outside Headers). The BHTTP
/// encoder (RFC 9292) encodes scheme+authority when the URI is absolute, and
/// the egress gateway reconstructs an absolute-form request line from them —
/// which the PAI-EAS backend rejects (404). The daemon's http_proxy path
/// forwards an origin-form URI (path+query only) plus a Host header, which the
/// backend accepts. Mirror that: strip scheme+authority so BHTTP encodes only
/// the path, and add a Host header derived from the original authority. (The
/// authority for the upstream TngEndpoint is parsed from the URL separately in
/// dispatch_request, since this URI no longer has it. The URI itself is parsed
/// once in dispatch_request and passed in here.)
pub(super) async fn build_http_request(
    web_request: web_sys::Request,
    abs_uri: http::Uri,
) -> Result<axum::extract::Request, JsValue> {
    let gloo_request = gloo::net::http::Request::from(web_request);

    // Get ReadableStream from web_sys::Request and convert to Vec<u8>
    let body = if let Some(body_stream) = gloo_request.body() {
        let body_bytes = read_body_to_bytes(body_stream).await.map_err(to_js_error)?;
        axum::body::Body::from(body_bytes)
    } else {
        axum::body::Body::empty()
    };

    let authority = abs_uri.authority().cloned();
    let mut parts = abs_uri.into_parts();
    parts.scheme = None;
    parts.authority = None;
    let origin_uri = http::Uri::from_parts(parts)
        .context("Failed to convert request URL to origin-form")
        .map_err(to_js_error)?;

    let mut builder = http::Request::builder()
        .uri(origin_uri)
        .method(gloo_request.method().as_ref())
        .version(http::Version::HTTP_11);

    for (key, value) in gloo_request.headers().entries() {
        builder = builder.header(key, value);
    }
    // Ensure a Host header exists. The browser fetch API treats `Host` as a
    // forbidden header and silently drops any value set via init.headers, so
    // one can never arrive via the loop above — set it unconditionally from the
    // original authority. Strip any userinfo (`user:pass@host` → `host`) so the
    // value is a well-formed RFC 7230 Host (`uri-host [":" port]`).
    if let Some(authority) = authority {
        let raw = authority.as_str();
        let host_value = raw.rsplit_once('@').map(|(_, host)| host).unwrap_or(raw);
        let hv = http::HeaderValue::from_str(host_value)
            .map_err(|e| JsError::new(&format!("invalid host header value: {e:?}")))?;
        builder = builder.header(http::header::HOST, hv);
    }

    let http_request = builder
        .body(body)
        .context("Failed to build http::Request")
        .map_err(to_js_error)?;

    Ok(http_request)
}
