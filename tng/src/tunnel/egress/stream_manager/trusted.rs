use std::sync::Arc;

use crate::error::TngError;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::{
    config::egress::CommonArgs,
    tunnel::{
        attestation_result::AttestationResult,
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

pub type ProtocolStreamDecoderOutput =
    BoxStream<'static, Result<(Box<dyn CommonStreamTrait + Sync>, Option<AttestationResult>)>>;

#[async_trait]
pub trait ProtocolStreamDecoder: StatusProvider {
    async fn decode_stream(
        &self,
        input: Box<dyn CommonStreamTrait + Sync + 'static>,
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
                .map(|a| a.multiplex)
                .unwrap_or(true);
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
                        .map(|a| a.multiplex)
                        .unwrap_or(true);
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
    ) -> Result<BoxStream<'static, Result<NextStream>>> {
        let maybe_direct_forward = self
            .transport_layer
            .check_direct_forward(in_stream, self.runtime.clone())
            .await
            .context("Failed to decode stream")?;

        match maybe_direct_forward {
            MaybeDirectlyForward::ContinueAsTngTraffic(stream) => {
                let mut pending = self
                    .decoder
                    .decode_stream(stream)
                    .await
                    .context("Failed to decode stream")?;
                Ok(stream! {
                    while let Some(result) = pending.next().await {
                        yield result.map(|(stream, att)| NextStream::Secured(stream, att));
                    }
                }
                .boxed())
            }
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
            ["ohttp", rest @ ..] => self.decoder.query_status(rest).await,
            _ => Err(TngError::StatusPathNotFound),
        }
    }
}
