use std::sync::Arc;

use crate::error::TngError;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::{
    config::egress::CommonArgs,
    tunnel::{
        egress::{
            protocol::{
                common::transport::{MaybeDirectlyForward, TransportLayer},
                ohttp::OHttpStreamDecoder,
                rats_tls::RatsTlsStreamDecoder,
            },
            stream_manager::NextStream,
        },
        ra_context::RaContext,
        stream::CommonStreamTrait,
        upstream::UpstreamConnector,
        utils::runtime::TokioRuntime,
    },
};
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use async_stream::stream;
use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;

use super::StreamManager;

pub enum ProtocolStreamDecoderOutput {
    /// The decoder yields decoded byte sub-streams; the flow forwards each
    /// one to the upstream itself (rats_tls, direct-forward matches).
    ByteStreams(BoxStream<'static, Result<NextStream>>),
    /// The decoder's protocol forwards to the upstream itself, dialing
    /// through the connection's `UpstreamConnector`; the flow must not
    /// spawn forwarding tasks for this connection (ohttp).
    SelfForwarded,
}

#[async_trait]
pub trait ProtocolStreamDecoder: StatusProvider {
    async fn decode_stream(
        &self,
        input: Box<dyn CommonStreamTrait + Sync + 'static>,
        peer: Option<std::net::SocketAddr>,
        connector: Arc<UpstreamConnector>,
    ) -> Result<ProtocolStreamDecoderOutput>;
}

pub struct TrustedStreamManager {
    transport_layer: TransportLayer,

    decoder: Box<dyn ProtocolStreamDecoder + Send + Sync + 'static>,

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

        Ok(Self {
            transport_layer: TransportLayer::new(
                common_args.direct_forward.clone(),
                &common_args.ohttp,
            )?,
            decoder: match &common_args.ohttp {
                Some(ohttp_args) => Box::new(
                    OHttpStreamDecoder::new(ra_context, ohttp_args.clone(), runtime.clone())
                        .await?,
                ),
                None => {
                    let multiplex = common_args
                        .rats_tls
                        .as_ref()
                        .unwrap_or(&Default::default())
                        .multiplex;
                    Box::new(
                        RatsTlsStreamDecoder::new(ra_context, runtime.clone(), multiplex).await?,
                    )
                }
            },
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
    ) -> Result<ProtocolStreamDecoderOutput> {
        let maybe_direct_forward = self
            .transport_layer
            .check_direct_forward(in_stream, self.runtime.clone())
            .await
            .context("Failed to decode stream")?;

        match maybe_direct_forward {
            MaybeDirectlyForward::ContinueAsTngTraffic(stream) => self
                .decoder
                .decode_stream(stream, peer, connector)
                .await
                .context("Failed to decode stream"),
            MaybeDirectlyForward::DirectlyForward(stream) => {
                Ok(ProtocolStreamDecoderOutput::ByteStreams(
                    stream! {
                        yield Ok(NextStream::DirectlyForward(Box::new(stream)));
                    }
                    .boxed(),
                ))
            }
        }
    }
}

#[async_trait]
impl StatusProvider for TrustedStreamManager {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        match path {
            [] => Ok(StatusQueryResult::Subtree(vec!["ohttp".into()])),
            ["ohttp", rest @ ..] => self.decoder.query_status(rest).await,
            _ => Err(TngError::StatusPathNotFound),
        }
    }
}
