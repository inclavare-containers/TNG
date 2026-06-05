use std::{future::Future, net::SocketAddr, pin::Pin};

use anyhow::{Context as _, Result};

use crate::{
    tunnel::{
        attestation_result::AttestationResult,
        endpoint::TngEndpoint,
        utils::{self, socket::tcp_connect},
    },
    CommonStreamTrait, ContextualStream,
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
    async fn forward_stream<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        downstream: Box<dyn CommonStreamTrait + 'static>,
    ) -> Result<(
        /* forward_stream_task */
        Pin<Box<dyn Future<Output = Result<()>> + std::marker::Send + 'static>>,
        Option<AttestationResult>,
        /* upstream_local */ Option<SocketAddr>,
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
        let upstream_local = upstream.local_addr().ok();
        let upstream = ContextualStream::new(upstream, "ingress-unprotected-tcp");

        Ok((
            Box::pin(async { utils::forward::forward_stream(upstream, downstream).await })
                as Pin<Box<_>>,
            None,
            upstream_local,
        ))
    }
}
