use std::sync::Arc;

use crate::{
    config::egress::CommonArgs,
    tunnel::egress::core::protocol::{
        security::SecurityLayer, transport::TransportLayerDecoder, wrapping::WrappingLayer,
    },
};
use anyhow::Result;
use futures::StreamExt;
use hyper::upgrade::Upgraded;
use tokio::{net::TcpStream, sync::mpsc};
use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

use super::StreamManager;

pub struct TrustedStreamManager {
    common_args: CommonArgs,
    security_layer: Arc<SecurityLayer>,
}

impl TrustedStreamManager {
    pub async fn new(common_args: &CommonArgs, shutdown_guard: ShutdownGuard) -> Result<Self> {
        Ok(Self {
            common_args: common_args.clone(),
            security_layer: Arc::new(
                SecurityLayer::new(&common_args.ra_args, shutdown_guard).await?,
            ),
        })
    }
}

impl StreamManager for TrustedStreamManager {
    type Sender = mpsc::UnboundedSender<Upgraded>;
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
                    let error = format!("{e:#}");
                    tracing::error!(%error, "Failed to decode stream");
                    continue;
                }
                Ok(stream) => {
                    let security_layer = self.security_layer.clone();
                    let channel = sender.clone();

                    let span = Span::current();
                    shutdown_guard.spawn_task_fn(|shutdown_guard| {
                        async move {
                            let tls_stream = security_layer.from_stream(stream).await?;

                            WrappingLayer::unwrap_stream(tls_stream, channel, shutdown_guard).await
                        }
                        .instrument(span)
                    });
                }
            }
        }

        Ok(())
    }
}
