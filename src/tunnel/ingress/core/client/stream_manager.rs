use crate::tunnel::ingress::core::TngEndpoint;
use anyhow::Result;

pub trait StreamManager {
    type StreamType: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin;

    async fn new_stream(&self, endpoint: &TngEndpoint) -> Result<Self::StreamType>;
}
