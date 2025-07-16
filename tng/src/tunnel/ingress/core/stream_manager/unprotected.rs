use std::future::Future;

use anyhow::{Context as _, Result};
use tokio_graceful::ShutdownGuard;

use crate::tunnel::{
    attestation_result::AttestationResult,
    endpoint::TngEndpoint,
    utils::{self, socket::tcp_connect_with_so_mark},
};

use super::StreamManager;

pub struct UnprotectedStreamManager {
    transport_so_mark: Option<u32>,
}

impl UnprotectedStreamManager {
    pub fn new(transport_so_mark: Option<u32>) -> Self {
        Self { transport_so_mark }
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
    ) -> Result<(
        impl Future<Output = Result<()>> + std::marker::Send + 'b,
        Option<AttestationResult>,
    )> {
        let upstream =
            tcp_connect_with_so_mark((endpoint.host(), endpoint.port()), self.transport_so_mark)
                .await
                .with_context(|| {
                    format!("Failed to establish TCP connection with upstream '{endpoint}'")
                })?;

        Ok((
            async { utils::forward::forward_stream(upstream, downstream).await },
            None,
        ))
    }
}
