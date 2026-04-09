use std::sync::Arc;

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
pub trait ProtocolStreamDecoder {
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
    pub async fn new(common_args: &CommonArgs, runtime: TokioRuntime) -> Result<Self> {
        let ra_args = common_args.ra_args.clone().into_checked()?;
        let ra_context = Arc::new(RaContext::from_ra_args(&ra_args).await?);

        Ok(Self {
            transport_layer: TransportLayer::new(
                common_args.direct_forward.clone(),
                common_args.ohttp.clone(),
            )?,
            decoder: match &common_args.ohttp {
                // Note that ohttp.allow_non_tng_traffic_regexes is handled by TransportLayer so we don't need to handle it here.
                Some(ohttp) => Box::new(
                    OHttpStreamDecoder::new(ra_context, ohttp.clone(), runtime.clone()).await?,
                ),
                None => Box::new(RatsTlsStreamDecoder::new(ra_context, runtime.clone()).await?),
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
