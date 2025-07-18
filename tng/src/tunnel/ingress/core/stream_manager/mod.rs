pub mod trusted;
pub mod unprotected;

use std::future::Future;

use crate::tunnel::{
    attestation_result::AttestationResult, endpoint::TngEndpoint, service_metrics::ServiceMetrics,
};
use anyhow::Result;
use tokio_graceful::ShutdownGuard;

pub trait StreamManager {
    /// This function will be called after the tunnel runtime is created but before the up-layer service is started and ready for accepting connections.
    async fn prepare(&self, shutdown_guard: ShutdownGuard) -> Result<()>;

    async fn forward_stream<'a, 'b>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: impl tokio::io::AsyncRead
            + tokio::io::AsyncWrite
            + std::marker::Unpin
            + std::marker::Send
            + 'b,
        shutdown_guard: ShutdownGuard,
        metrics: ServiceMetrics,
    ) -> Result<(
        /* forward_stream_task */ impl Future<Output = Result<()>> + std::marker::Send + 'b,
        Option<AttestationResult>,
    )>;
}
