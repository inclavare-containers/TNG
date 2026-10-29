use std::sync::Arc;

use crate::status::{StatusProvider, StatusQueryResult};
use crate::{
    config::egress::OHttpArgs,
    tunnel::{
        egress::{
            protocol::ohttp::security::OHttpSecurityLayer,
            stream_manager::trusted::{ProtocolStreamDecoder, ProtocolStreamDecoderOutput},
        },
        ra_context::RaContext,
        upstream::UpstreamConnector,
    },
    CommonStreamTrait, TokioRuntime,
};

use anyhow::Result;
use async_trait::async_trait;

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
        input: Box<dyn CommonStreamTrait + Sync + 'static>,
        peer: Option<std::net::SocketAddr>,
        connector: Arc<UpstreamConnector>,
    ) -> Result<ProtocolStreamDecoderOutput> {
        // Should be spawned as background task
        let security_layer = self.security_layer.clone();
        self.runtime.spawn_supervised_task(async move {
            if let Err(error) = security_layer.handle_stream(input, connector, peer).await {
                tracing::error!(?error, "Failed to handle OHTTP stream")
            }
        });

        // The decrypted requests are forwarded to the backend by the request
        // handlers themselves (dialing through `connector`), so this
        // connection yields no byte streams for the flow to forward.
        Ok(ProtocolStreamDecoderOutput::SelfForwarded)
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
