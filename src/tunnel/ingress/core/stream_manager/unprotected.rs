use std::future::Future;

use anyhow::{Context as _, Result};
use tokio::net::TcpStream;
use tokio_graceful::ShutdownGuard;

use crate::{
    observability::metric::stream::StreamWithCounter,
    tunnel::{
        attestation_result::AttestationResult, ingress::core::TngEndpoint,
        service_metrics::ServiceMetrics, utils,
    },
};

use super::StreamManager;

pub struct UnprotectedStreamManager {}

impl UnprotectedStreamManager {
    pub fn new() -> Self {
        Self {}
    }
}

impl StreamManager for UnprotectedStreamManager {
    async fn prepare(&self, _shutdown_guard: ShutdownGuard) -> Result<()> {
        /* Nothing */
        Ok(())
    }

    async fn forward_stream<'a, 'b>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: impl tokio::io::AsyncRead
            + tokio::io::AsyncWrite
            + std::marker::Unpin
            + std::marker::Send
            + 'b,
        _shutdown_guard: ShutdownGuard,
        metrics: ServiceMetrics,
    ) -> Result<(
        impl Future<Output = Result<()>> + std::marker::Send + 'b,
        Option<AttestationResult>,
    )> {
        let upstream = TcpStream::connect((endpoint.host(), endpoint.port()))
            .await
            .with_context(|| {
                format!("Failed to establish TCP connection with upstream '{endpoint}'")
            })?;

        let downstream = StreamWithCounter {
            inner: downstream,
            tx_bytes_total: metrics.tx_bytes_total,
            rx_bytes_total: metrics.rx_bytes_total,
        };

        Ok((
            async { utils::forward_stream(upstream, downstream).await },
            None,
        ))
    }
}
