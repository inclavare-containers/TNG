use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};

use anyhow::{Context as _, Result};

use crate::{
    tunnel::{
        attestation_result::AttestationResult, endpoint::TngEndpoint,
        ingress::flow::IncomingStream, service_metrics::ServiceMetrics, utils,
    },
    ContextualStream,
};

use super::StreamManager;

pub struct UnprotectedStreamManager {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    transport_so_mark: Option<u32>,
}

impl UnprotectedStreamManager {
    pub fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
    ) -> Self {
        Self {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            transport_so_mark,
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
impl Default for UnprotectedStreamManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamManager for UnprotectedStreamManager {
    async fn forward_stream(
        &self,
        endpoint: &TngEndpoint,
        downstream: IncomingStream,
        metrics: Arc<ServiceMetrics>,
    ) -> Result<(
        /* forward_stream_task */
        Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>,
        Option<AttestationResult>,
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

        Ok((
            Box::pin(async move {
                let downstream = downstream.into_dyn();
                let downstream = metrics.new_wrapped_stream(downstream); // for counting bytes
                let _: () = utils::forward::normal::forward_stream(upstream, downstream).await;
                Ok(())
            }) as Pin<Box<_>>,
            None,
            Some(upstream_local),
        ))
    }
}
