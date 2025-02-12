use anyhow::{Context as _, Result};
use tokio::net::TcpStream;

use crate::tunnel::{attestation_result::AttestationResult, ingress::core::TngEndpoint};

use super::StreamManager;

pub struct UnprotectedStreamManager {}

impl UnprotectedStreamManager {
    pub fn new() -> Self {
        Self {}
    }
}

impl StreamManager for UnprotectedStreamManager {
    type StreamType = TcpStream;

    async fn new_stream(
        &self,
        endpoint: &TngEndpoint,
    ) -> Result<(
        <Self as StreamManager>::StreamType,
        Option<AttestationResult>,
    )> {
        let upstream = TcpStream::connect((endpoint.host(), endpoint.port()))
            .await
            .with_context(|| {
                format!("Failed to establish TCP connection with upstream '{endpoint}'")
            })?;

        Ok((upstream, None))
    }
}
