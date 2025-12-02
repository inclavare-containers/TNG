use std::net::SocketAddr;

use crate::{
    config::ra::RaArgs,
    tunnel::{
        endpoint::TngEndpoint,
        ingress::protocol::{
            rats_tls::security::RatsTlsSecurityLayer, ProtocolStreamForwarder,
            ProtocolStreamForwarderOutput,
        },
        utils,
    },
    AttestationResult, CommonStreamTrait, TokioRuntime,
};

use anyhow::Result;
use async_trait::async_trait;

mod security;
mod transport;
mod wrapping;

pub struct RatsTlsStreamForwarder {
    security_layer: RatsTlsSecurityLayer,
}

impl RatsTlsStreamForwarder {
    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ra_args: RaArgs,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        Ok(Self {
            security_layer: RatsTlsSecurityLayer::new(
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                transport_so_mark,
                ra_args,
                runtime,
            )
            .await?,
        })
    }

    pub async fn connect(
        &self,
        endpoint: TngEndpoint,
    ) -> Result<(
        impl CommonStreamTrait + Sync,
        /* local_addr */ SocketAddr,
        Option<AttestationResult>,
    )> {
        self.security_layer.allocate_secured_stream(endpoint).await
    }
}

#[async_trait]
impl ProtocolStreamForwarder for RatsTlsStreamForwarder {
    async fn forward_stream<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: Box<dyn CommonStreamTrait + 'static>,
    ) -> Result<ProtocolStreamForwarderOutput> {
        let (upstream, _local_addr, attestation_result) = self.connect(endpoint.clone()).await?;
        Ok((
            Box::pin(async { utils::forward::forward_stream(upstream, downstream).await }),
            attestation_result,
        ))
    }
}
