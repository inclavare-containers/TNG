use std::sync::Arc;

use crate::{
    config::{egress::OHttpArgs, ra::RaArgs},
    tunnel::egress::{
        protocol::ohttp::security::OHttpSecurityLayer,
        stream_manager::trusted::{ProtocolStreamDecoder, ProtocolStreamDecoderOutput},
    },
    CommonStreamTrait, TokioRuntime,
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
        ra_args: RaArgs,
        ohttp_args: OHttpArgs,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        Ok(Self {
            security_layer: Arc::new(
                OHttpSecurityLayer::new(ra_args, ohttp_args, runtime.clone()).await?,
            ),
            runtime,
        })
    }
}

#[async_trait]
impl ProtocolStreamDecoder for OHttpStreamDecoder {
    async fn decode_stream(
        &self,
        input: Box<dyn CommonStreamTrait + Sync + 'static>,
    ) -> Result<ProtocolStreamDecoderOutput> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

        // Should be spawned as background task
        let security_layer = self.security_layer.clone();
        self.runtime.spawn_supervised_task(async move {
            if let Err(error) = security_layer.handle_stream(input, sender).await {
                tracing::error!(?error, "Failed to handle OHTTP stream")
            }
        });

        Ok(stream! {
            while let Some(value) = receiver.recv().await {
                yield Ok(value); // TODO: replace the handle_stream above with return stream directly and pass error here
            }
        }
        .boxed())
    }
}
