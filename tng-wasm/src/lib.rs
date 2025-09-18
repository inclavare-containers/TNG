use anyhow::{bail, Result};
use http::{Method, Uri, Version};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use tng::{
    build,
    config::{
        ingress::OHttpArgs,
        ra::{AttestationServiceArgs, AttestationServiceTokenVerifyArgs, RaArgs, VerifyArgs},
    },
    tunnel::{endpoint::TngEndpoint, ingress::protocol::ohttp::security::OHttpSecurityLayer},
    AttestationResult, TokioRuntime,
};

use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer;
use tracing_wasm::{WASMLayer, WASMLayerConfig};
use wasm_bindgen::prelude::*;

pub mod fetch;

#[wasm_bindgen(start)]
pub fn init_tng() {
    // print pretty errors in wasm https://github.com/rustwasm/console_error_panic_hook
    // This is not needed for tracing_wasm to work, but it is a common tool for getting proper error line numbers for panics.
    console_error_panic_hook::set_once();

    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(
        WASMLayer::new(WASMLayerConfig::default()).with_filter(
            Into::<tracing_subscriber::EnvFilter>::into(
                "info,tokio_graceful=off,rats_cert=debug,tng=debug",
            ),
        ),
    ))
    .expect("failed to set tng default global tracing subscriber");

    tracing::info!(
        r#"
      _______   ________
     /_  __/ | / / ____/
      / / /  |/ / / __  
     / / / /|  / /_/ /  Welcome to the Trusted Network Gateway!
    /_/ /_/ |_/\____/   version: v{}  commit: {}  buildtime: {}"#,
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );
}

#[wasm_bindgen]
pub async fn send_demo_request() -> Result<JsValue, JsError> {
    let (response, attestation_result) = send_request_async_impl(
        &TngEndpoint::new("127.0.0.1", 30001),
        &Default::default(),
        &RaArgs::VerifyOnly(VerifyArgs::BackgroundCheck {
            as_args: AttestationServiceArgs {
                as_addr: "http://127.0.0.1:8080/".to_string(),
                as_is_grpc: false,
                token_verify: AttestationServiceTokenVerifyArgs {
                    policy_ids: vec!["default".to_string()],
                    trusted_certs_paths: None,
                },
            },
        }),
        http::Request::builder()
            .method(Method::GET)
            .uri(Uri::from_static("http://localhost:3000/hello"))
            .version(Version::HTTP_11)
            .header("content-type", "application/json")
            .header("user-agent", "axum/0.6")
            .body(axum::body::Body::from("{}"))
            .map_err(|err| anyhow::anyhow!("Failed to construct http request: {err:?}"))
            .map_err(|e: anyhow::Error| JsError::new(&format!("{e:?}")))?,
    )
    .await
    .map_err(|e: anyhow::Error| JsError::new(&format!("{e:?}")))?;

    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let body_str = String::from_utf8_lossy(&bytes);
    tracing::info!(status=?parts.status, body = %body_str, "Respone");

    serialize_json_compatible(attestation_result.claims())
        .map_err(|err| anyhow::anyhow!("Failed to convert response headers: {err:?}"))
        .map_err(|e: anyhow::Error| JsError::new(&format!("{e:?}")))
}

async fn send_request_async_impl(
    endpoint: &TngEndpoint,
    ohttp: &OHttpArgs,
    ra_args: &RaArgs,
    request: axum::extract::Request,
) -> Result<(axum::response::Response, AttestationResult)> {
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

    let ohttp_security_layer =
        OHttpSecurityLayer::new(ohttp, ra_args.clone(), runtime.clone()).await?;

    let (response, attestation_result) = ohttp_security_layer
        .forward_http_request(endpoint, request)
        .await?;

    tracing::info!(?attestation_result, "start forward task");
    let Some(attestation_result) = attestation_result else {
        bail!("The attestation result is missing")
    };

    Ok((response, attestation_result))
}

fn serialize_json_compatible<T>(obj: &T) -> Result<JsValue, serde_wasm_bindgen::Error>
where
    T: Serialize,
{
    Ok(obj.serialize(&Serializer::json_compatible())?)
}
