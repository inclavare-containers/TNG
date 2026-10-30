use std::sync::Arc;

use anyhow::{anyhow, Result};
use gloo::utils::format::JsValueSerdeExt;
use serde::Serialize;
use tng::{
    config::{ingress, ra::RaArgs},
    tunnel::{endpoint::TngEndpoint, ingress::protocol::ohttp::security::OHttpSecurityLayer},
    AttestationResult, RaContext, TokioRuntime,
};
use wasm_bindgen::prelude::*;

use super::attestation::{ra_summary, RaSummary};
use super::request::{parse_request_uri, upstream_endpoint};
use super::to_js_error;

/// Result of a standalone verification of a TNG ohttp endpoint, exposed to
/// JavaScript. `token` / `claims` / `exp` are absent in NoRa mode (no
/// verification configured); `verified` is false there and true whenever the
/// key-config handshake (and therefore the attestation verification) succeeded.
#[derive(Serialize)]
struct VerificationInfo {
    #[serde(flatten)]
    summary: RaSummary,
    endpoint: String,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
}

fn build_info(
    endpoint: &TngEndpoint,
    ra_args: &RaArgs,
    attestation_result: Option<AttestationResult>,
) -> VerificationInfo {
    let (verified, token, claims, exp) = match attestation_result {
        Some(result) => {
            // claims()/exp() are pure local JWT decodes; a decode failure
            // degrades the panel to the raw token instead of failing the call.
            (
                true,
                Some(result.token_str().to_string()),
                result.claims().ok(),
                result.exp().ok(),
            )
        }
        None => (false, None, None, None),
    };
    VerificationInfo {
        summary: ra_summary(ra_args),
        endpoint: endpoint.http_authority(),
        verified,
        token,
        claims,
        exp,
    }
}

/// Verify a TNG ohttp endpoint's remote attestation without sending an inner
/// HTTP request: run the key-config handshake (the protocol exchange that
/// carries attestation) and return the verification info for display. Mirrors
/// `fetch`'s config parsing so the same config object works for both.
#[wasm_bindgen]
pub async fn verify(url: String, config: JsValue) -> Result<JsValue, JsValue> {
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

    let uri = parse_request_uri(&url)?;
    let endpoint = upstream_endpoint(&uri)?;
    let url_scheme = OHttpSecurityLayer::scheme_from_url(uri.scheme_str());

    let shutdown = tokio_graceful::Shutdown::no_signal();
    let runtime = TokioRuntime::wasm_main_thread(shutdown.guard()).map_err(to_js_error)?;
    let ra_context = Arc::new(
        RaContext::from_ra_args(&ra_args)
            .await
            .map_err(to_js_error)?,
    );
    let layer = OHttpSecurityLayer::new(&ohttp, url_scheme, ra_context, runtime.clone())
        .await
        .map_err(to_js_error)?;
    let attestation_result = layer
        .verify_endpoint(&endpoint, uri.path())
        .await
        .map_err(to_js_error)?;

    let info = build_info(&endpoint, &ra_args, attestation_result);
    // The JSON round-trip (as `attest_info` in `fetch` already does) rather
    // than `serde_wasm_bindgen::to_value`: a struct containing a flattened
    // field serializes as a *map*, and serde_wasm_bindgen's default serializer
    // hands JS a `Map` where property access reads `undefined`.
    JsValue::from_serde(&info)
        .map_err(|e| JsError::new(&format!("Failed to serialize verification info: {e:?}")).into())
}
