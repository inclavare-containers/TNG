use std::future::Future;

use anyhow::{bail, Result};
use tracing::Instrument;

use crate::tunnel::ingress::protocol::tcp::transport::TcpTransportLayerCreator;
use crate::tunnel::ingress::protocol::tcp::wrapping::TcpWrappingLayer;
use crate::tunnel::ingress::stream_manager::TngEndpoint;
use crate::CommonStreamTrait;
use crate::{
    config::ingress::CommonArgs,
    tunnel::{
        attestation_result::AttestationResult,
        ingress::protocol::tcp::security::{pool::PoolKey, TcpSecurityLayer},
        utils::{self, runtime::TokioRuntime},
    },
};

use super::StreamManager;

pub struct TrustedStreamManager {
    security_layer: TcpSecurityLayer,

    #[allow(unused)]
    runtime: TokioRuntime,
}

impl TrustedStreamManager {
    pub async fn new(
        common_args: &CommonArgs,
        transport_so_mark: Option<u32>,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        if common_args.web_page_inject {
            bail!("The `web_page_inject` field is not supported")
        }

        if common_args.encap_in_http.is_some() {
            todo!("encap_in_http is not implemented");
        };

        let transport_layer_creator = TcpTransportLayerCreator::new(transport_so_mark);

        Ok(Self {
            security_layer: TcpSecurityLayer::new(
                transport_layer_creator,
                &common_args.ra_args,
                runtime.clone(),
            )
            .await?,
            runtime,
        })
    }
}

impl StreamManager for TrustedStreamManager {
    async fn prepare(&self) -> Result<()> {
        self.security_layer.prepare().await
    }

    async fn forward_stream<'a, 'b>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: impl tokio::io::AsyncRead
            + tokio::io::AsyncWrite
            + std::marker::Unpin
            + std::marker::Send
            + 'b,
    ) -> Result<(
        impl Future<Output = Result<()>> + std::marker::Send + 'b,
        Option<AttestationResult>,
    )> {
        let pool_key = PoolKey::new(endpoint.clone());

        let client = self.security_layer.get_client(&pool_key).await?;

        let (upstream, attestation_result) = TcpWrappingLayer::create_stream_from_hyper(&client)
            .instrument(tracing::info_span!("wrapping"))
            .await?;

        let upstream = Box::new(upstream) as Box<dyn CommonStreamTrait>;

        Ok((
            async { utils::forward::forward_stream(upstream, downstream).await },
            attestation_result,
        ))
    }
}
