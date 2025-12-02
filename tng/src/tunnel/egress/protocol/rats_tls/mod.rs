use crate::{
    config::ra::RaArgs,
    tunnel::egress::{
        protocol::rats_tls::{security::RatsTlsSecurityLayer, wrapping::RatsTlsWrappingLayer},
        stream_manager::trusted::{ProtocolStreamDecoder, ProtocolStreamDecoderOutput},
    },
    CommonStreamTrait, TokioRuntime,
};

use anyhow::Result;
use async_stream::stream;
use async_trait::async_trait;
use futures::StreamExt;

pub mod security;
pub mod wrapping;

pub struct RatsTlsStreamDecoder {
    security_layer: RatsTlsSecurityLayer,
    runtime: TokioRuntime,
}

impl RatsTlsStreamDecoder {
    pub async fn new(ra_args: RaArgs, runtime: TokioRuntime) -> Result<Self> {
        Ok(Self {
            security_layer: RatsTlsSecurityLayer::new(ra_args, runtime.clone()).await?,
            runtime,
        })
    }
}

#[async_trait]
impl ProtocolStreamDecoder for RatsTlsStreamDecoder {
    async fn decode_stream(
        &self,
        input: Box<dyn CommonStreamTrait + Sync + 'static>,
    ) -> Result<ProtocolStreamDecoderOutput> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

        let (tls_stream, attestation_result) = self.security_layer.handshake(input).await?;

        // Should be spawned as background task
        self.runtime
            .spawn_supervised_task_fn_current_span(move |runtime| async move {
                RatsTlsWrappingLayer::unwrap_stream(
                    tls_stream,
                    attestation_result,
                    sender,
                    runtime,
                )
                .await;
            });

        Ok(stream! {
            while let Some(value) = receiver.recv().await {
                yield Ok(value); // TODO: remove the spawn_supervised_task_fn_current_span above and pass error here
            }
        }
        .boxed())
    }
}
