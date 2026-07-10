use std::convert::Infallible;

use axum::{extract::Request, response::Response};
use http::HeaderValue;
use tower::{Layer, Service};

use crate::tunnel::egress::protocol::ohttp::security::context::TngStreamContext;
use crate::tunnel::ohttp::protocol::header::OhttpApi;

/// Installed on the egress OHTTP router iff `ohttp.cors` is `None`.
///
/// Keeps the backend as the CORS authority:
/// - CORS preflight (`OPTIONS` + `Access-Control-Request-Method`) is forwarded to
///   the backend as plaintext via `forward_request`; the backend's preflight
///   response (with its `Access-Control-Allow-*`) is relayed verbatim.
/// - key-config actual responses get `Access-Control-Allow-Origin: *`
///   (key-config is TNG-local metadata; no backend is contacted, no credentials
///   are sent, so `*` is safe).
/// - tunnel actual responses get no TNG-added CORS header — the backend's
///   `Access-Control-Allow-*` is relayed by the response `header_passthrough`.
#[derive(Clone)]
pub struct CorsFallbackLayer {
    state: TngStreamContext,
}

impl CorsFallbackLayer {
    pub fn new(state: TngStreamContext) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for CorsFallbackLayer {
    type Service = CorsFallbackService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        CorsFallbackService {
            inner,
            state: self.state.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CorsFallbackService<S> {
    inner: S,
    state: TngStreamContext,
}

/// A CORS preflight: OPTIONS + `Access-Control-Request-Method` (Fetch spec).
fn is_cors_preflight(method: &http::Method, headers: &http::HeaderMap) -> bool {
    *method == http::Method::OPTIONS && headers.contains_key("access-control-request-method")
}

/// The request targets the key-config API (`x-tng-ohttp-api: /tng/key-config`).
fn is_key_config(headers: &http::HeaderMap) -> bool {
    headers
        .get(OhttpApi::HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == OhttpApi::KEY_CONFIG)
        .unwrap_or(false)
}

/// Whether TNG should add `Access-Control-Allow-Origin: *` to this response:
/// key-config actual (non-preflight).
fn should_add_acao(method: &http::Method, headers: &http::HeaderMap) -> bool {
    is_key_config(headers) && !is_cors_preflight(method, headers)
}

impl<S> Service<Request> for CorsFallbackService<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // https://fetch.spec.whatwg.org/#cors-preflight-request: a CORS preflight
        // is an OPTIONS request that carries `Access-Control-Request-Method`.
        let is_preflight = is_cors_preflight(req.method(), req.headers());
        // key-config actual responses (non-preflight) get ACAO:*.
        let add_acao = should_add_acao(req.method(), req.headers());

        let mut inner = self.inner.clone();
        let ctx = self.state.clone();

        Box::pin(async move {
            if is_preflight {
                // Forward the bare preflight OPTIONS to the backend as plaintext.
                // The egress forwarding path reaches the backend exactly as it
                // does for the decrypted inner request; the preflight's path is
                // the outer request path. The backend's preflight response
                // (carrying its `Access-Control-Allow-*`) is relayed verbatim.
                match ctx.forward_request(req, None).await {
                    Ok(response) => Ok(response),
                    Err(error) => {
                        tracing::error!(
                            ?error,
                            "CORS fallback: failed to forward preflight to backend"
                        );
                        // 502-style: backend unreachable; browser will see a failed preflight,
                        // matching "backend is authoritative".
                        let mut response = http::Response::new(axum::body::Body::empty());
                        *response.status_mut() = http::StatusCode::BAD_GATEWAY;
                        Ok(response)
                    }
                }
            } else {
                let mut res = inner.call(req).await.unwrap_or_else(|_| {
                    let mut response = http::Response::new(axum::body::Body::empty());
                    *response.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                    response
                });
                if add_acao {
                    // key-config is public protocol metadata; no credentials on
                    // this fetch, so `Access-Control-Allow-Origin: *` is safe.
                    res.headers_mut().insert(
                        http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                        HeaderValue::from_static("*"),
                    );
                }
                Ok(res)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, api: Option<&str>, acrm: bool) -> http::Request<()> {
        let mut builder = http::Request::builder().method(method);
        if let Some(api) = api {
            builder = builder.header(OhttpApi::HEADER_NAME, api);
        }
        if acrm {
            builder = builder.header("access-control-request-method", "POST");
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn preflight_when_options_and_acrm() {
        let req = req("OPTIONS", Some(OhttpApi::KEY_CONFIG), true);
        assert!(is_cors_preflight(req.method(), req.headers()));
        // A preflight is NOT an actual — never add ACAO, even for key-config.
        assert!(!should_add_acao(req.method(), req.headers()));
    }

    #[test]
    fn key_config_actual_adds_acao() {
        let req = req("POST", Some(OhttpApi::KEY_CONFIG), false);
        assert!(!is_cors_preflight(req.method(), req.headers()));
        assert!(is_key_config(req.headers()));
        assert!(should_add_acao(req.method(), req.headers()));
    }

    #[test]
    fn tunnel_actual_does_not_add_acao() {
        let req = req("POST", Some("/tng/tunnel"), false);
        assert!(!is_cors_preflight(req.method(), req.headers()));
        assert!(!is_key_config(req.headers()));
        assert!(!should_add_acao(req.method(), req.headers()));
    }

    #[test]
    fn options_without_acrm_is_not_preflight() {
        let req = req("OPTIONS", Some(OhttpApi::KEY_CONFIG), false);
        assert!(!is_cors_preflight(req.method(), req.headers()));
    }

    #[test]
    fn no_api_header_is_not_key_config() {
        let req = req("POST", None, false);
        assert!(!is_key_config(req.headers()));
        assert!(!should_add_acao(req.method(), req.headers()));
    }
}
