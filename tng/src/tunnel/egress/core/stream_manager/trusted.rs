use std::sync::Arc;

use crate::{
    config::egress::CommonArgs,
    tunnel::{
        attestation_result::AttestationResult,
        egress::core::protocol::{
            security::SecurityLayer,
            transport::{DecodeResult, TransportLayer},
            wrapping::WrappingLayer,
        },
        stream::CommonStreamTrait,
        utils::runtime::TokioRuntime,
    },
};
use anyhow::Context;
use anyhow::{bail, Result};
use tokio::sync::mpsc;

use super::StreamManager;

pub struct TrustedStreamManager {
    transport_layer: TransportLayer,

    security_layer: Arc<SecurityLayer>,

    connection_reuse: bool,

    runtime: TokioRuntime,
}

impl TrustedStreamManager {
    pub async fn new(common_args: &CommonArgs, runtime: TokioRuntime) -> Result<Self> {
        Ok(Self {
            transport_layer: TransportLayer::new(
                common_args.direct_forward.clone(),
                common_args.decap_from_http.clone(),
            )?,
            security_layer: Arc::new(
                SecurityLayer::new(&common_args.ra_args, runtime.clone()).await?,
            ),
            connection_reuse: common_args.decap_from_http.is_none(),
            runtime,
        })
    }
}

impl StreamManager for TrustedStreamManager {
    type Sender = mpsc::UnboundedSender<(StreamType, Option<AttestationResult>)>;

    async fn prepare(&self) -> Result<()> {
        self.security_layer.prepare().await
    }

    async fn consume_stream(
        &self,
        in_stream: Box<(dyn CommonStreamTrait + std::marker::Send + 'static)>,
        sender: Self::Sender,
    ) -> Result<()> {
        let decode_result = self
            .transport_layer
            .decode(in_stream, self.runtime.clone())
            .await
            .context("Failed to decode stream")?;

        match decode_result {
            DecodeResult::ContinueAsTngTraffic(stream) => {
                let security_layer = self.security_layer.clone();
                let channel = sender.clone();

                {
                    let connection_reuse = self.connection_reuse;

                    self.runtime
                        .spawn_supervised_task_fn_current_span(move |runtime| async move {
                            let (tls_stream, attestation_result) = match security_layer
                                .handshake(stream)
                                .await
                            {
                                Ok(v) => v,
                                Err(e) => {
                                    tracing::error!(%e, "Failed to enstablish security session");
                                    return;
                                }
                            };

                            if connection_reuse {
                                WrappingLayer::unwrap_stream(
                                    tls_stream,
                                    attestation_result,
                                    channel,
                                    runtime,
                                )
                                .await;
                            } else {
                                // Return the stream directly
                                if let Err(e) = channel.send((
                                    StreamType::SecuredStream(Box::new(tls_stream)),
                                    attestation_result,
                                )) {
                                    tracing::error!("Failed to send stream via channel: {e:#}");
                                }
                            }
                        });
                }
            }
            DecodeResult::DirectlyForward(stream) => {
                if let Err(e) =
                    sender.send((StreamType::DirectlyForwardStream(Box::new(stream)), None))
                {
                    bail!("Got a directly forward stream but failed to send via channel: {e:#}");
                }
            }
        }

        Ok(())
    }
}

pub enum StreamType {
    SecuredStream(Box<dyn CommonStreamTrait>),
    DirectlyForwardStream(Box<dyn CommonStreamTrait>),
}

impl StreamType {
    pub fn is_secured(&self) -> bool {
        match self {
            StreamType::SecuredStream(_) => true,
            StreamType::DirectlyForwardStream(_) => false,
        }
    }

    pub fn into_stream(self) -> Box<dyn CommonStreamTrait> {
        match self {
            StreamType::SecuredStream(stream) => stream,
            StreamType::DirectlyForwardStream(stream) => stream,
        }
    }
}
