use std::sync::Arc;

use crate::{
    config::egress::CommonArgs,
    tunnel::{
        attestation_result::AttestationResult,
        egress::protocol::{
            common::transport::{DecodeResult, TransportLayer},
            ohttp::security::OHttpSecurityLayer,
            rats_tls::{security::RatsTlsSecurityLayer, wrapping::RatsTlsWrappingLayer},
        },
        stream::CommonStreamTrait,
        utils::runtime::TokioRuntime,
    },
};
use anyhow::Context;
use anyhow::{bail, Result};

use super::StreamManager;

pub struct TrustedStreamManager {
    transport_layer: TransportLayer,

    security_layer: SecurityLayer,

    runtime: TokioRuntime,
}

impl TrustedStreamManager {
    pub async fn new(common_args: &CommonArgs, runtime: TokioRuntime) -> Result<Self> {
        let ra_args = common_args.ra_args.clone().into_checked()?;

        Ok(Self {
            transport_layer: TransportLayer::new(
                common_args.direct_forward.clone(),
                common_args.ohttp.clone(),
            )?,
            security_layer: match &common_args.ohttp {
                // Note that ohttp args is handled by TransportLayer so we don't need to handle it here.
                Some(_) => SecurityLayer::OHttp(Arc::new(
                    OHttpSecurityLayer::new(ra_args, runtime.clone()).await?,
                )),
                None => SecurityLayer::RatsTls(Arc::new(
                    RatsTlsSecurityLayer::new(ra_args, runtime.clone()).await?,
                )),
            },
            runtime,
        })
    }
}

impl StreamManager for TrustedStreamManager {
    type Sender = tokio::sync::mpsc::UnboundedSender<(StreamType, Option<AttestationResult>)>;

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
            DecodeResult::ContinueAsTngTraffic(stream) => match &self.security_layer {
                SecurityLayer::RatsTls(security_layer) => {
                    let security_layer = security_layer.clone();

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

                            RatsTlsWrappingLayer::unwrap_stream(
                                tls_stream,
                                attestation_result,
                                sender,
                                runtime,
                            )
                            .await;
                        });
                }
                SecurityLayer::OHttp(security_layer) => {
                    security_layer.handle_stream(stream, sender).await?;
                }
            },
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

pub enum SecurityLayer {
    RatsTls(Arc<RatsTlsSecurityLayer>),
    OHttp(Arc<OHttpSecurityLayer>),
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
