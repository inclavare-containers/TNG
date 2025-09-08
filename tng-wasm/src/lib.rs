use std::{io::Cursor, sync::Arc};

use anyhow::{bail, Context as _, Result};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use tng::{
    build,
    config::{
        ingress::{self, OHttpArgs},
        ra::{RaArgsUnchecked, VerifyArgs},
    },
    tunnel::{
        endpoint::TngEndpoint,
        ingress::stream_manager::{trusted::TrustedStreamManager, StreamManager},
    },
    AttestationResult, CommonStreamTrait, TokioRuntime,
};

use wasm_bindgen::prelude::*;

pub mod fetch;

#[wasm_bindgen(start)]
pub fn init_tng() {
    // print pretty errors in wasm https://github.com/rustwasm/console_error_panic_hook
    // This is not needed for tracing_wasm to work, but it is a common tool for getting proper error line numbers for panics.
    console_error_panic_hook::set_once();
    tracing_wasm::set_as_global_default();

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
    send_request_async_impl(
        "http://127.0.0.1:8080/".to_string(),
        vec!["default".to_string()],
        Cursor::new(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:30001\r\n\r\n".to_vec()),
        "127.0.0.1".to_string(),
        30001,
    )
    .await
    .and_then(|attestation_result| {
        serialize_json_compatible(attestation_result.claims())
            .map_err(|err| anyhow::anyhow!("Failed to convert response headers: {err:?}"))
    })
    .map_err(|e: anyhow::Error| JsError::new(&format!("{e:?}")))
}

async fn send_request_async_impl(
    as_addr: String,
    policy_ids: Vec<String>,
    downstream: impl CommonStreamTrait,
    host: String,
    port: u16,
) -> Result<AttestationResult> {
    tracing::debug!("TNG called");
    let common_args = ingress::CommonArgs {
        web_page_inject: false,
        ohttp: Some(OHttpArgs {
            path_rewrites: vec![],
        }),
        ra_args: RaArgsUnchecked {
            no_ra: false,
            attest: None,
            verify: Some(VerifyArgs {
                as_addr,
                as_is_grpc: false,
                policy_ids,
                trusted_certs_paths: None,
            }),
        },
    };

    let transport_so_mark = None;

    let shutdown = tokio_graceful::Shutdown::no_signal();
    let runtime = TokioRuntime::wasm_main_thread(shutdown.guard())?;
    let trusted_stream_manager =
        Arc::new(TrustedStreamManager::new(&common_args, transport_so_mark, runtime).await?);

    let (forward_task, attestation_result) = trusted_stream_manager
        .forward_stream(
            // TODO: note that in wasm mode, this field should be same as the http request in the body
            &TngEndpoint::new(host, port),
            downstream,
        )
        .await
        .context("failed to forward stream")?;

    tracing::info!(?attestation_result, "start forward task");

    let Some(attestation_result) = attestation_result else {
        bail!("The attestation result is missing")
    };

    tokio_with_wasm::task::spawn(async move {
        if let Err(err) = forward_task.await {
            tracing::error!("Forward task failed: {:?}", err);
        }
    });

    Ok(attestation_result)
}

fn serialize_json_compatible<T>(obj: &T) -> Result<JsValue, serde_wasm_bindgen::Error>
where
    T: Serialize,
{
    Ok(obj.serialize(&Serializer::json_compatible())?)
}
