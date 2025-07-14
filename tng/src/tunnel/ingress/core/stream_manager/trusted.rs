use std::future::Future;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use auto_enums::auto_enum;
use http::Uri;
use tokio_graceful::ShutdownGuard;
use tower::Service;
use tracing::{Instrument, Span};

use crate::tunnel::ingress::core::stream_manager::TngEndpoint;
use crate::tunnel::utils::http_inspector::RequestInfo;
use crate::CommonStreamTrait;
use crate::{
    config::ingress::CommonArgs,
    tunnel::{
        attestation_result::AttestationResult,
        ingress::core::protocol::{
            security::{pool::PoolKey, SecurityLayer},
            transport::{extra_data::PoolKeyExtraDataInserter, TransportLayerCreator},
            wrapping,
        },
        utils::{
            self,
            http_inspector::{HttpRequestInspector, InspectionResult},
            runtime::TokioRuntime,
        },
    },
};

use super::StreamManager;

pub struct TrustedStreamManager {
    security_layer: SecurityLayer,

    connection_reuse: bool,

    // A standalone tokio runtime to run tasks related to the protocol module
    #[allow(unused)]
    rt: Arc<TokioRuntime>,
}

impl TrustedStreamManager {
    pub async fn new(common_args: &CommonArgs, transport_so_mark: Option<u32>) -> Result<Self> {
        if common_args.web_page_inject {
            bail!("The `web_page_inject` field is not supported")
        }

        let transport_layer_creator =
            TransportLayerCreator::new(transport_so_mark, common_args.encap_in_http.clone())?;

        #[cfg(feature = "unix")]
        let rt = TokioRuntime::new_multi_thread()?.into_shared();
        #[cfg(not(feature = "unix"))]
        let rt = TokioRuntime::wasm_main_thread()?.into_shared();

        Ok(Self {
            security_layer: SecurityLayer::new(
                transport_layer_creator,
                &common_args.ra_args,
                rt.clone(),
            )
            .await?,
            connection_reuse: common_args.encap_in_http.is_none(),
            rt,
        })
    }
}

impl StreamManager for TrustedStreamManager {
    async fn prepare(&self, shutdown_guard: ShutdownGuard) -> Result<()> {
        self.security_layer.prepare(shutdown_guard).await
    }

    #[auto_enum]
    async fn forward_stream<'a, 'b>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: impl tokio::io::AsyncRead
            + tokio::io::AsyncWrite
            + std::marker::Unpin
            + std::marker::Send
            + 'b,
        shutdown_guard: ShutdownGuard,
    ) -> Result<(
        impl Future<Output = Result<()>> + std::marker::Send + 'b,
        Option<AttestationResult>,
    )> {
        let mut pool_key = PoolKey::new(endpoint.clone());

        let transport_layer_creator = self.security_layer.transport_layer_creator_ref();

        #[auto_enum(tokio1::AsyncRead, tokio1::AsyncWrite)]
        let downstream = {
            if transport_layer_creator.need_to_insert_extra_data() {
                // If the transport layer creator need to insert extra data, we need to inspect the http request from downstream.

                let InspectionResult {
                    unmodified_stream,
                    result,
                } = HttpRequestInspector::inspect_stream(downstream).await;

                let request_info =
                    result.context("Failed to check the protocol from the request")?;

                tracing::debug!(?request_info, "Got request protocol info");

                if !matches!(
                    request_info,
                    RequestInfo::Http1 { .. } | RequestInfo::Http2 { .. }
                ) {
                    bail!("The incomming stream should be either HTTP1 or HTTP2 request when `encap_in_http = true`")
                }

                // Call the transport_layer_creator to insert extra data into the pool key.
                transport_layer_creator
                    .insert_extra_data_to_pool_key(&request_info, &mut pool_key)?;

                unmodified_stream
            } else {
                // Or we can just use the original stream.
                downstream
            }
        };

        let (upstream, attestation_result) = if self.connection_reuse {
            let client = self
                .security_layer
                .get_client(&pool_key, shutdown_guard)
                .await?;

            let (upstream, attestation_result) = wrapping::create_stream_from_hyper(&client)
                .instrument(tracing::info_span!("wrapping"))
                .await?;

            (
                Box::new(upstream) as Box<dyn CommonStreamTrait>,
                attestation_result,
            )
        } else {
            let mut connector = self
                .security_layer
                .create_security_connector(&pool_key, shutdown_guard, Span::current())
                .await?;

            let io = connector
                .call(
                    // TODO: pass the real uri from argument
                    Uri::builder()
                        .scheme("https")
                        .authority(format!("{}:{}", endpoint.host(), endpoint.port()))
                        .path_and_query("/")
                        .build()
                        .context("Failed to build uri")?,
                )
                .await?;

            let (upstream, attestation_result) = io.into_parts();

            (
                Box::new(upstream.into_inner()) as Box<dyn CommonStreamTrait>,
                attestation_result,
            )
        };

        Ok((
            async { utils::forward::forward_stream(upstream, downstream).await },
            attestation_result,
        ))
    }
}
