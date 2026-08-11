use std::sync::Arc;

use crate::status::{StatusProvider, StatusQueryResult};
use crate::tunnel::egress::protocol::common::transport::TngTransportStream;
use crate::tunnel::egress::stream_manager::DecodedStream;
use crate::{
    config::egress::OHttpArgs,
    tunnel::{
        egress::{
            protocol::ohttp::security::OHttpSecurityLayer,
            stream_manager::trusted::{ProtocolStreamDecoder, ProtocolStreamDecoderOutput},
        },
        ra_context::RaContext,
    },
    TokioRuntime,
};

use anyhow::Result;
use async_stream::stream;
use async_trait::async_trait;
use futures::StreamExt;

pub mod security;

pub struct OHttpStreamDecoder {
    security_layer: Arc<OHttpSecurityLayer>,
    runtime: TokioRuntime,
}

impl OHttpStreamDecoder {
    pub async fn new(
        ra_context: Arc<RaContext>,
        ohttp_args: OHttpArgs,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        Ok(Self {
            security_layer: Arc::new(
                OHttpSecurityLayer::new(ra_context, ohttp_args, runtime.clone()).await?,
            ),
            runtime,
        })
    }
}

#[async_trait]
impl ProtocolStreamDecoder for OHttpStreamDecoder {
    async fn decode_stream(
        &self,
        input: TngTransportStream,
    ) -> Result<ProtocolStreamDecoderOutput> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

        // Should be spawned as background task
        let security_layer = self.security_layer.clone();
        self.runtime.spawn_supervised_task(async move {
            let result = match input {
                TngTransportStream::Inspected(preluded_stream) => {
                    security_layer.handle_stream(preluded_stream, sender).await
                }
                TngTransportStream::Uninspected(first_byte_read_timeout_stream) => {
                    security_layer
                        .handle_stream(first_byte_read_timeout_stream, sender)
                        .await
                }
            };
            if let Err(error) = result {
                tracing::error!(?error, "Failed to handle OHTTP stream")
            }
        });

        Ok(stream! {
            while let Some((stream, attestation_result)) = receiver.recv().await {
                yield Ok((DecodedStream::Opaque(stream), attestation_result)); // TODO: replace the handle_stream above with return stream directly and pass error here
            }
        }
        .boxed())
    }
}

#[async_trait]
impl StatusProvider for OHttpStreamDecoder {
    async fn query_status(
        &self,
        path: &[&str],
    ) -> Result<StatusQueryResult, crate::error::TngError> {
        self.security_layer.query_status(path).await
    }
}
