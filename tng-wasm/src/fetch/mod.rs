use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use tng::{
    config::{
        ingress::{self, OHttpArgs},
        ra::RaArgs,
    },
    tunnel::{endpoint::TngEndpoint, ingress::protocol::ohttp::security::OHttpSecurityLayer},
    AttestationResult, RaContext, TokioRuntime,
};
use wasm_bindgen::prelude::*;

mod attestation;
mod request;
mod response;

use self::attestation::attach_attestation_info;
use self::request::{build_http_request, parse_request_uri, upstream_endpoint};
use self::response::convert_to_web_response;

/// Map an error into a JS-side error, preserving its Debug representation.
///
/// Uses Debug formatting (`{e:?}`) so an `anyhow::Error`'s "Caused by:" chain
/// survives across the FFI boundary (Display would drop it). Accepts any
/// `Debug` error (e.g. `TngError` from `into_checked`); JsError requires a
/// String, so the typed error cannot be handed over directly.
pub(super) fn to_js_error<E: std::fmt::Debug>(error: E) -> JsValue {
    JsError::new(&format!("{error:?}")).into()
}

#[wasm_bindgen]
pub async fn fetch(
    url: String,
    init: web_sys::RequestInit,
    config: JsValue,
) -> Result<web_sys::Response, JsValue> {
    let common_args: ingress::CommonArgs = serde_wasm_bindgen::from_value(config)
        .map_err(|e| JsError::new(&format!("Failed to parse config: {e:?}")))?;

    if common_args.web_page_inject {
        Err(anyhow!("The `web_page_inject` field is not supported")).map_err(to_js_error)?
    }

    let ohttp = common_args.ohttp.unwrap_or_default();
    let ra_args = common_args
        .ra_args
        .clone()
        .into_checked()
        .map_err(to_js_error)?;

    let (http_response, attestation_result) = dispatch_request(url, init, &ohttp, &ra_args).await?;

    let web_response = convert_to_web_response(http_response).await?;
    attach_attestation_info(web_response, attestation_result, &ra_args)
}

/// Build a browser-side `web_sys::Request` from the caller's URL/init, convert
/// it to an origin-form `http::Request`, and forward it through the OHTTP
/// tunnel. Returns the upstream response together with its attestation result.
async fn dispatch_request(
    url: String,
    init: web_sys::RequestInit,
    ohttp: &OHttpArgs,
    ra_args: &RaArgs,
) -> Result<(axum::response::Response, AttestationResult), JsValue> {
    // 1. Construct the browser-side Request from the caller's URL/init.
    let web_request = web_sys::Request::new_with_str_and_init(&url, &init)?;

    // 2. Parse the (browser-normalized) URL once. It is the source of truth for
    //    both the upstream endpoint (host/port) and the origin-form forwarded
    //    URI (path/query). Use web_request.url() — not the raw `url` — so the
    //    path stays in sync with the browser's normalization (e.g. a leading '/').
    let request_uri = parse_request_uri(&web_request.url())?;

    // 3. Resolve the upstream TNG endpoint from the URI's authority.
    // TODO: note that in wasm mode, this field should be same as the http request in the body
    let endpoint = upstream_endpoint(&request_uri)?;

    // 4. Build the http::Request (origin-form URI + Host header, matching the
    //    daemon's http_proxy forwarding) and forward it through the OHTTP layer.
    let http_request = build_http_request(web_request, request_uri).await?;
    forward_request(&endpoint, ohttp, ra_args, http_request)
        .await
        .map_err(to_js_error)
}

/// Forward a built `http::Request` through the OHTTP security layer to the
/// upstream endpoint, returning the response and its attestation result.
async fn forward_request(
    endpoint: &TngEndpoint,
    ohttp: &OHttpArgs,
    ra_args: &RaArgs,
    request: axum::extract::Request,
) -> Result<(axum::response::Response, AttestationResult)> {
    // Reassemble as http::Request (same type as axum::extract::Request) so the
    // parts can be logged once before forwarding.
    let request = {
        let (parts, body) = request.into_parts();
        tracing::debug!(
            request=?parts,
            ?ra_args,
            "http::Request to be send"
        );
        http::Request::from_parts(parts, body)
    };

    let shutdown = tokio_graceful::Shutdown::no_signal();
    let runtime = TokioRuntime::wasm_main_thread(shutdown.guard())?;

    let ra_context = Arc::new(RaContext::from_ra_args(ra_args).await?);
    let ohttp_security_layer = OHttpSecurityLayer::new(ohttp, ra_context, runtime.clone()).await?;

    let (response, attestation_result) = ohttp_security_layer
        .forward_http_request(endpoint, request)
        .await?;

    tracing::info!(?attestation_result, "start forward task");
    let Some(attestation_result) = attestation_result else {
        bail!("The attestation result is missing");
    };

    Ok((response, attestation_result))
}
