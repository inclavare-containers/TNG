pub mod trusted;
pub mod unprotected;

use crate::tunnel::{attestation_result::AttestationResult, ingress::core::TngEndpoint};
use anyhow::Result;
use tokio_graceful::ShutdownGuard;

pub trait StreamManager {
    type StreamType: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin;

    /// This function will be called after the tunnel runtime is created but before the up-layer service is started and ready for accepting connections.
    async fn prepare(&self, shutdown_guard: ShutdownGuard) -> Result<()>;

    async fn new_stream(
        &self,
        endpoint: &TngEndpoint,
        shutdown_guard: ShutdownGuard,
    ) -> Result<(Self::StreamType, Option<AttestationResult>)>;
}
