use std::sync::Arc;

use crate::{
    config::egress::CommonArgs,
    tunnel::{
        attestation_result::AttestationResult,
        egress::protocol::{
            common::transport::{DecodeResult, TransportLayer},
            tcp::{security::TcpSecurityLayer, wrapping::TcpWrappingLayer},
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

    security_layer: Arc<TcpSecurityLayer>,

    runtime: TokioRuntime,
}

impl TrustedStreamManager {
    pub async fn new(common_args: &CommonArgs, runtime: TokioRuntime) -> Result<Self> {
        if common_args.decap_from_http.is_some() {
            todo!("decap_from_http is not implemented")
        }
        Ok(Self {
            transport_layer: TransportLayer::new(
                common_args.direct_forward.clone(),
                common_args.decap_from_http.clone(),
            )?,
            security_layer: Arc::new(
                TcpSecurityLayer::new(&common_args.ra_args, runtime.clone()).await?,
            ),
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
            DecodeResult::ContinueAsTngTrafficTcp(stream) => {
                let security_layer = self.security_layer.clone();
                let channel = sender.clone();

                {
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

                            TcpWrappingLayer::unwrap_stream(
                                tls_stream,
                                attestation_result,
                                channel,
                                runtime,
                            )
                            .await;
                        });
                }
            }
            DecodeResult::ContinueAsTngTrafficHttp(common_stream_trait) => todo!("not implemented"),
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
