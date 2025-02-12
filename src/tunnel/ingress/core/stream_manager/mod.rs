pub mod trusted;
pub mod unprotected;

use crate::tunnel::{attestation_result::AttestationResult, ingress::core::TngEndpoint};
use anyhow::Result;

pub trait StreamManager {
    type StreamType: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin;

    async fn new_stream(
        &self,
        endpoint: &TngEndpoint,
    ) -> Result<(Self::StreamType, Option<AttestationResult>)>;
}
