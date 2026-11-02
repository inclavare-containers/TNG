use std::sync::Arc;

use crate::error::TngError;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::{
    config::egress::CommonArgs,
    tunnel::{
        egress::{
            protocol::{
                common::transport::{MaybeDirectlyForward, TransportLayer},
                ohttp::security::OHttpSecurityLayer,
                rats_tls::RatsTlsStreamDecoder,
            },
            stream_manager::NextStream,
        },
        ra_context::RaContext,
        stream::CommonStreamTrait,
        upstream::UpstreamConnector,
        utils::runtime::TokioRuntime,
    },
    AttestationState,
};
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use async_stream::stream;
use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;

use super::StreamManager;

pub type ProtocolStreamDecoderOutput =
    BoxStream<'static, Result<(Box<dyn CommonStreamTrait + Sync>, AttestationState)>>;

#[async_trait]
pub trait ProtocolStreamDecoder: StatusProvider {
    async fn decode_stream(
        &self,
        input: Box<dyn CommonStreamTrait + Sync + 'static>,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<ProtocolStreamDecoderOutput>;
}

/// The protocol this egress terminates, decided once from the config. Each
/// accepted connection is claimed by exactly one of these handlers, and the
/// two differ in how they own the connection: OHTTP claims it outright (its
/// security layer serves the outer HTTP and dials backend legs itself
/// through the connection's `UpstreamConnector`), while RATS-TLS runs the
/// decoder contract and hands decoded byte legs back to the flow loop.
enum TerminatedProtocol {
    OHttp(Arc<OHttpSecurityLayer>),
    RatsTls(Box<dyn ProtocolStreamDecoder + Send + Sync + 'static>),
}

pub struct TrustedStreamManager {
    transport_layer: TransportLayer,

    protocol: TerminatedProtocol,

    runtime: TokioRuntime,
}

impl TrustedStreamManager {
    pub async fn new(common_args: &CommonArgs, parent_runtime: TokioRuntime) -> Result<Self> {
        if common_args.ohttp.is_some() && common_args.rats_tls.is_some() {
            bail!("Cannot specify both `ohttp` and `rats_tls` — they are mutually exclusive");
        }

        let ra_args = common_args.ra_args.clone().into_checked()?;
        let ra_context = Arc::new(RaContext::from_ra_args(&ra_args).await?);

        // Use a standalone runtime for ohttp and H2 multiplex scenarios to avoid
        // contention with the traffic capture module. For multiplex=false (single TLS
        // per stream), share the parent runtime since there is no H2 task scheduling overhead.
        let is_h2_or_ohttp = common_args.ohttp.is_some()
            || common_args
                .rats_tls
                .as_ref()
                .unwrap_or(&Default::default())
                .multiplex;
        let runtime = if is_h2_or_ohttp {
            #[cfg(not(wasm))]
            {
                TokioRuntime::new_multi_thread(parent_runtime.shutdown_guard().clone())?
            }
            #[cfg(wasm)]
            {
                TokioRuntime::wasm_main_thread(parent_runtime.shutdown_guard().clone())?
            }
        } else {
            #[cfg(not(wasm))]
            {
                TokioRuntime::current(parent_runtime.shutdown_guard().clone())?
            }
            #[cfg(wasm)]
            {
                TokioRuntime::wasm_main_thread(parent_runtime.shutdown_guard().clone())?
            }
        };

        let protocol = match &common_args.ohttp {
            Some(ohttp_args) => TerminatedProtocol::OHttp(Arc::new(
                OHttpSecurityLayer::new(ra_context, ohttp_args.clone(), runtime.clone()).await?,
            )),
            None => {
                let multiplex = common_args
                    .rats_tls
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .multiplex;
                TerminatedProtocol::RatsTls(Box::new(
                    RatsTlsStreamDecoder::new(ra_context, runtime.clone(), multiplex).await?,
                ))
            }
        };

        Ok(Self {
            transport_layer: TransportLayer::new(
                common_args.direct_forward.clone(),
                &common_args.ohttp,
            )?,
            protocol,
            runtime,
        })
    }
}

impl StreamManager for TrustedStreamManager {
    async fn consume_stream(
        &self,
        in_stream: Box<dyn CommonStreamTrait + Sync + 'static>,
        peer: Option<std::net::SocketAddr>,
        connector: Arc<UpstreamConnector>,
    ) -> Result<BoxStream<'static, Result<NextStream>>> {
        let maybe_direct_forward = self
            .transport_layer
            .check_direct_forward(in_stream, self.runtime.clone())
            .await
            .context("Failed to decode stream")?;

        match maybe_direct_forward {
            MaybeDirectlyForward::ContinueAsTngTraffic(stream) => match &self.protocol {
                // OHTTP claims the whole connection here, at the same level
                // as a direct-forward match claims its plain stream: the
                // security layer serves the outer HTTP and forwards each
                // decrypted request to the backend itself, dialling through
                // `connector`. No legs come back for the flow to forward, so
                // the stream the flow loop reads is empty.
                TerminatedProtocol::OHttp(security_layer) => {
                    let security_layer = security_layer.clone();
                    self.runtime.spawn_supervised_task(async move {
                        if let Err(error) =
                            security_layer.handle_stream(stream, connector, peer).await
                        {
                            tracing::error!(?error, "Failed to handle OHTTP stream")
                        }
                    });
                    Ok(futures::stream::empty().boxed())
                }
                TerminatedProtocol::RatsTls(decoder) => {
                    let mut pending = decoder
                        .decode_stream(stream, peer)
                        .await
                        .context("Failed to decode stream")?;
                    Ok(stream! {
                        while let Some(result) = pending.next().await {
                            yield result.map(|(stream, att)| NextStream::Secured(stream, att));
                        }
                    }
                    .boxed())
                }
            },
            MaybeDirectlyForward::DirectlyForward(stream) => Ok(stream! {
                yield Ok(NextStream::DirectlyForward(Box::new(stream)));
            }
            .boxed()),
        }
    }
}

#[async_trait]
impl StatusProvider for TrustedStreamManager {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        match path {
            [] => Ok(StatusQueryResult::Subtree(vec!["ohttp".into()])),
            ["ohttp", rest @ ..] => match &self.protocol {
                TerminatedProtocol::OHttp(security_layer) => {
                    security_layer.query_status(rest).await
                }
                TerminatedProtocol::RatsTls(decoder) => decoder.query_status(rest).await,
            },
            _ => Err(TngError::StatusPathNotFound),
        }
    }
}
