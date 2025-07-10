use std::{io::Cursor, sync::Arc};

use anyhow::Result;
use tng::{
    build,
    config::{
        ingress::{self, EncapInHttp},
        ra::{RaArgs, VerifyArgs},
    },
    tunnel::{
        endpoint::TngEndpoint,
        ingress::core::stream_manager::{trusted::TrustedStreamManager, StreamManager},
    },
};

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
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
pub fn send_request() {
    wasm_bindgen_futures::spawn_local(send_request_async());
}

pub async fn send_request_async() {
    send_request_async_impl().await.unwrap_throw();
}

async fn send_request_async_impl() -> Result<()> {
    tracing::debug!("TNG called");

    let common_args = ingress::CommonArgs {
        web_page_inject: false,
        encap_in_http: Some(EncapInHttp {
            path_rewrites: vec![],
        }),
        ra_args: RaArgs {
            no_ra: false,
            attest: None,
            verify: Some(VerifyArgs {
                as_addr: "http://127.0.0.1:8080/".to_string(),
                as_is_grpc: false,
                policy_ids: vec!["default".to_string()],
                trusted_certs_paths: None,
            }),
        },
    };

    let transport_so_mark = None;
    let trusted_stream_manager =
        Arc::new(TrustedStreamManager::new(&common_args, transport_so_mark).await?);

    // async fn forward_stream<'a, 'b>(
    //     &self,
    //     endpoint: &'a TngEndpoint,
    //     downstream: impl tokio::io::AsyncRead
    //         + tokio::io::AsyncWrite
    //         + std::marker::Unpin
    //         + std::marker::Send
    //         + 'b,
    //     shutdown_guard: ShutdownGuard,
    //     metrics: ServiceMetrics,
    // ) -> Result<(
    //     impl Future<Output = Result<()>> + std::marker::Send + 'b,
    //     Option<AttestationResult>,
    // )>

    let shutdown = tokio_graceful::Shutdown::no_signal();

    match trusted_stream_manager
        .forward_stream(
            // TODO: note that in wasm mode, this field should be same as the http request in the body
            &TngEndpoint::new("127.0.0.1".to_string(), 30001),
            Cursor::new(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:30001\r\n\r\n".to_vec()),
            shutdown.guard(),
        )
        .await
    {
        Ok((forward_task, attestation_result)) => {
            tracing::info!(?attestation_result, "forward task started");
            forward_task.await?;
        }
        Err(error) => {
            tracing::error!(?error, "failed to forward stream")
        }
    };

    shutdown.shutdown().await;

    tracing::info!("exit now");

    Ok(())
}
