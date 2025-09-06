pub mod trusted;
#[cfg(unix)]
pub mod unprotected;

use std::{future::Future, pin::Pin};

use crate::tunnel::{attestation_result::AttestationResult, endpoint::TngEndpoint};
use anyhow::Result;

#[allow(async_fn_in_trait)]
pub trait StreamManager {
    /// This function will be called after the tunnel runtime is created but before the up-layer service is started and ready for accepting connections.
    async fn prepare(&self) -> Result<()>;

    async fn forward_stream<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: impl tokio::io::AsyncRead
            + tokio::io::AsyncWrite
            + std::marker::Unpin
            + std::marker::Send
            + 'static,
    ) -> Result<(
        /* forward_stream_task */
        Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>,
        Option<AttestationResult>,
    )>;

    async fn is_forward_http_request_supported() -> bool;

    async fn forward_http_request<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>)>;
}
