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
use tracing::Instrument;

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
    type Sender = mpsc::UnboundedSender<Upgraded>;
    async fn consume_stream(&self, in_stream: TcpStream, sender: Self::Sender) -> Result<()> {
        let transport = TransportLayerDecoder::new(self.common_args.decap_from_http.clone());

        let mut next_stream = transport
            .decode(in_stream)
            .instrument(tracing::info_span!("transport"))
            .await?;
        while let Some(stream) = next_stream
            .next()
            .instrument(tracing::info_span!("transport"))
            .await
        {
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

                    tokio::task::spawn(
                        async move {
                            let tls_stream = security_layer.from_stream(stream).await?;

                            WrappingLayer::unwrap_stream(tls_stream, channel).await
                        }
                        .in_current_span(),
                    );
                }
            }
        }

        Ok(())
    }
}
