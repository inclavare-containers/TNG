use std::{future::Future, pin::Pin};

use anyhow::{bail, Context as _, Result};

use crate::tunnel::{
    attestation_result::AttestationResult,
    endpoint::TngEndpoint,
    utils::{self, socket::tcp_connect},
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

impl StreamManager for UnprotectedStreamManager {
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
    )> {
        let upstream = tcp_connect(
            (endpoint.host(), endpoint.port()),
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            self.transport_so_mark,
        )
        .await
        .with_context(|| {
            format!("Failed to establish TCP connection with upstream '{endpoint}'")
        })?;

        Ok((
            Box::pin(async { utils::forward::forward_stream(upstream, downstream).await })
                as Pin<Box<_>>,
            None,
        ))
    }

    async fn is_forward_http_request_supported() -> bool {
        false
    }

    async fn forward_http_request<'a>(
        &self,
        _endpoint: &'a TngEndpoint,
        _request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>)> {
        bail!("unsupported")
    }
}
