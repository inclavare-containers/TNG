use std::sync::Arc;

use crate::{
    config::egress::CommonArgs,
    observability::log::ShutdownGuardExt,
    tunnel::{
        attestation_result::AttestationResult,
        egress::core::protocol::{
            security::SecurityLayer, transport::TransportLayerDecoder, wrapping::WrappingLayer,
        },
    },
};
use anyhow::Result;
use futures::StreamExt;
use hyper::upgrade::Upgraded;
use tokio::{net::TcpStream, sync::mpsc};
use tokio_graceful::ShutdownGuard;

use super::StreamManager;

pub struct TrustedStreamManager {
    common_args: CommonArgs,
    security_layer: Arc<SecurityLayer>,
}

impl TrustedStreamManager {
    pub async fn new(common_args: &CommonArgs) -> Result<Self> {
        Ok(Self {
            common_args: common_args.clone(),
            security_layer: Arc::new(SecurityLayer::new(&common_args.ra_args).await?),
        })
    }
}

impl StreamManager for TrustedStreamManager {
    type Sender = mpsc::UnboundedSender<(Upgraded, Option<AttestationResult>)>;

    async fn prepare(&self, shutdown_guard: ShutdownGuard) -> Result<()> {
        self.security_layer.prepare(shutdown_guard).await
    }

    async fn consume_stream(
        &self,
        in_stream: TcpStream,
        sender: Self::Sender,
        shutdown_guard: ShutdownGuard,
    ) -> Result<()> {
        let transport = TransportLayerDecoder::new(self.common_args.decap_from_http.clone());

        let mut next_stream = transport.decode(in_stream).await?;
        while let Some(stream) = next_stream.next().await {
            // TODO: handle allow_non_tng_traffic_regexes
            match stream {
                Err(e) => {
                    tracing::error!(error=?e, "Failed to decode stream");
                    continue;
                }
                Ok(stream) => {
                    let security_layer = self.security_layer.clone();
                    let channel = sender.clone();

                    shutdown_guard.spawn_task_fn_current_span(|shutdown_guard| async move {
                        let (tls_stream, attestation_result) =
                            match security_layer.from_stream(stream).await {
                                Ok(v) => v,
                                Err(e) => {
                                    tracing::error!(%e, "Failed to enstablish security session");
                                    return;
                                }
                            };

                        WrappingLayer::unwrap_stream(
                            tls_stream,
                            attestation_result,
                            channel,
                            shutdown_guard,
                        )
                        .await
                    });
                }
            }
        }

        Ok(())
    }
}
