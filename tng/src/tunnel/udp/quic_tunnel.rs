// QUIC tunnel client (ingress side).
//
// QuicDatagramTunnelClient connects to egress with RA-TLS config and
// sends/receives pure UDP datagrams. Reuses TlsConfigGenerator
// pattern from peer_shared for rustls-to-quinn config conversion.
//
// The server side (egress QUIC listener) is implemented by the
// `EgressDatagramTrait` in egress/mapping_udp.rs, which creates
// the quinn::Endpoint directly.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;

use crate::config::Endpoint;
use crate::tunnel::utils::rustls::config::{alpn::Alpn, client::BlockingOnetimeTlsClientConfig};

/// QUIC Datagram tunnel client (ingress side).
///
/// Connects to egress QUIC endpoint with RA-based TLS config.
/// The QUIC connection carries pure UDP datagrams as datagram payloads —
/// no metadata headers, no framing beyond QUIC's own datagram encoding.
pub struct QuicDatagramTunnelClient {
    pub connection: quinn::Connection,
    max_datagram_size: Option<usize>,
}

impl QuicDatagramTunnelClient {
    /// Connect to egress QUIC endpoint with RA-based TLS config.
    pub async fn connect(
        target: &Endpoint,
        _alpn: Alpn,
        max_datagram_size: Option<usize>,
        tls_config: BlockingOnetimeTlsClientConfig,
    ) -> Result<Self> {
        let listen_addr: SocketAddr = "0.0.0.0:0".parse()?;

        let mut endpoint = quinn::Endpoint::client(listen_addr)?;
        let quinn_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config.0)?));
        endpoint.set_default_client_config(quinn_config);

        let server_name = target
            .host
            .as_deref()
            .context("target host is required for QUIC connection")?
            .to_owned();

        let connection = endpoint
            .connect(
                format!("{}:{}", server_name, target.port).parse()?,
                &server_name,
            )
            .context("Failed to establish QUIC connection")?
            .await
            .context("QUIC connection handshake failed")?;

        Ok(Self {
            connection,
            max_datagram_size,
        })
    }

    /// Send a datagram through the QUIC connection (pure payload, no metadata).
    pub fn send_datagram(&self, payload: Bytes) -> Result<()> {
        if let Some(max_size) = self.max_datagram_size {
            if payload.len() > max_size {
                anyhow::bail!(
                    "datagram size {} exceeds max_datagram_size {}",
                    payload.len(),
                    max_size
                );
            }
        }

        self.connection
            .send_datagram(payload)
            .context("Failed to send QUIC datagram")?;
        Ok(())
    }

    /// Receive a datagram from the QUIC connection.
    pub async fn receive_datagram(&self) -> Result<Bytes> {
        let datagram = self
            .connection
            .read_datagram()
            .await
            .context("Failed to receive QUIC datagram")?;
        Ok(datagram)
    }
}
