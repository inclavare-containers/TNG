use std::{future::Future, net::SocketAddr, pin::Pin};

use anyhow::{Context as _, Result};

use crate::{
    tunnel::{
        attestation_result::AttestationState, endpoint::TngEndpoint, utils,
        utils::forward::normal::AppSide, utils::runtime::TokioRuntime,
    },
    CommonStreamTrait, ContextualStream,
};

use super::StreamManager;

pub struct UnprotectedStreamManager {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    transport_so_mark: Option<u32>,
    runtime: TokioRuntime,
    app_side: AppSide,
}

impl UnprotectedStreamManager {
    pub fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        runtime: TokioRuntime,
        app_side: AppSide,
    ) -> Self {
        Self {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            transport_so_mark,
            runtime,
            app_side,
        }
    }
}

impl StreamManager for UnprotectedStreamManager {
    async fn forward_stream<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: Box<dyn CommonStreamTrait + 'static>,
    ) -> Result<(
        /* forward_stream_task */
        Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>,
        AttestationState,
        /* upstream_local */ Option<SocketAddr>,
    )> {
        let upstream = endpoint
            .tcp_connect(
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                self.transport_so_mark,
            )
            .await
            .with_context(|| {
                format!("Failed to establish TCP connection with upstream '{endpoint}'")
            })?;
        let upstream_local = upstream.local_addr().context("Failed to get local addr")?;
        let upstream = ContextualStream::new(upstream, "ingress-unprotected-tcp");

        let drain = self.runtime.drain_registry();
        let app_side = self.app_side;
        Ok((
            Box::pin(async move {
                let _: () = utils::forward::normal::forward_stream_with_drain(
                    upstream, downstream, drain, app_side,
                )
                .await;
                Ok(())
            }) as Pin<Box<_>>,
            AttestationState::Unattested,
            Some(upstream_local),
        ))
    }
}
