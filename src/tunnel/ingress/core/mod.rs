pub mod client;
pub mod server;

use std::fmt::Display;

use anyhow::{Context as _, Result};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct TngEndpoint {
    host: String,
    port: u16,
}

impl TngEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Display for TngEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("tcp://{}:{}", self.host, self.port))
    }
}

pub trait StreamManager {
    type StreamType: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin;

    async fn new_stream(&self, endpoint: &TngEndpoint) -> Result<Self::StreamType>;
}

pub struct RawStreamManager {}

impl RawStreamManager {
    pub fn new() -> Self {
        Self {}
    }
}

impl StreamManager for RawStreamManager {
    type StreamType = TcpStream;

    async fn new_stream(
        &self,
        endpoint: &TngEndpoint,
    ) -> Result<<Self as StreamManager>::StreamType> {
        let upstream = TcpStream::connect((endpoint.host(), endpoint.port()))
            .await
            .with_context(|| {
                format!("Failed to establish TCP connection with upstream '{endpoint}'")
            })?;

        Ok(upstream)
    }
}
