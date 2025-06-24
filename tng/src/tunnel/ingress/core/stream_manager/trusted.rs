use std::future::Future;

use anyhow::{bail, Context, Result};
use auto_enums::auto_enum;
use tokio_graceful::ShutdownGuard;
use tracing::Instrument;

use crate::{
    config::ingress::CommonArgs,
    observability::metric::stream::StreamWithCounter,
    tunnel::{
        attestation_result::AttestationResult,
        ingress::core::{
            protocol::{
                security::{pool::PoolKey, SecurityLayer},
                transport::{extra_data::PoolKeyExtraDataInserter, TransportLayerCreator},
                wrapping,
            },
            TngEndpoint,
        },
        service_metrics::ServiceMetrics,
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
    // A standalone tokio runtime to run tasks related to the protocol module
    #[allow(unused)]
    rt: TokioRuntime,
}

impl TrustedStreamManager {
    pub async fn new(common_args: &CommonArgs, transport_so_mark: Option<u32>) -> Result<Self> {
        if common_args.web_page_inject {
            bail!("The `web_page_inject` field is not supported")
        }

        let transport_layer_creator =
            TransportLayerCreator::new(transport_so_mark, common_args.encap_in_http.clone())?;

        let rt = TokioRuntime::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?,
        );

        Ok(Self {
            security_layer: SecurityLayer::new(
                transport_layer_creator,
                &common_args.ra_args,
                rt.handle(),
            )
            .await?,
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
        metrics: ServiceMetrics,
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
                    result.context("Failed to inspect http request from downstream")?;

                tracing::debug!(?request_info, "A http request has been inspected");

                // Call the transport_layer_creator to insert extra data into the pool key.
                transport_layer_creator
                    .insert_extra_data_to_pool_key(&request_info, &mut pool_key)?;

                unmodified_stream
            } else {
                // Or we can just use the original stream.
                downstream
            }
        };

        let downstream = StreamWithCounter {
            inner: downstream,
            tx_bytes_total: metrics.tx_bytes_total,
            rx_bytes_total: metrics.rx_bytes_total,
        };

        let client = self
            .security_layer
            .get_client(&pool_key, shutdown_guard)
            .await?;

        let (upstream, attestation_result) = wrapping::create_stream_from_hyper(&client)
            .instrument(tracing::info_span!("wrapping"))
            .await?;

        Ok((
            async { utils::forward::forward_stream(upstream, downstream).await },
            attestation_result,
        ))
    }
}
