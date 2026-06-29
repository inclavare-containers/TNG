use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use bytes::Bytes;
use indexmap::IndexMap;
use quinn::crypto::rustls::QuicServerConfig;

use crate::config::egress::EgressMappingUdpArgs;
use crate::tunnel::egress::datagram_flow::{
    EgressDatagramConnection, EgressDatagramListener, EgressDatagramTrait,
};
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::utils::rustls::config::alpn::Alpn;
use crate::tunnel::utils::rustls::config::TlsConfigGenerator;

/// QUIC-backed connection implementing `EgressDatagramConnection`.
struct QuicEgressConnection {
    inner: quinn::Connection,
    max_datagram_size: Option<usize>,
}

#[async_trait]
impl EgressDatagramConnection for QuicEgressConnection {
    fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    async fn read_datagram(&self) -> Result<Bytes> {
        let datagram = self
            .inner
            .read_datagram()
            .await
            .context("Failed to read QUIC datagram")?;
        Ok(datagram)
    }

    fn send_datagram(&self, payload: Bytes) -> Result<()> {
        if let Some(max_size) = self.max_datagram_size {
            if payload.len() > max_size {
                anyhow::bail!(
                    "datagram size {} exceeds max_datagram_size {}",
                    payload.len(),
                    max_size
                );
            }
        }
        self.inner
            .send_datagram(payload)
            .context("Failed to send QUIC datagram")?;
        Ok(())
    }

    fn close(&self, error_code: u32, reason: &[u8]) {
        self.inner.close(error_code.into(), reason);
    }
}

/// QUIC listener implementing `EgressDatagramListener`.
struct QuicEgressListener {
    endpoint: quinn::Endpoint,
    max_datagram_size: Option<usize>,
}

#[async_trait]
impl EgressDatagramListener for QuicEgressListener {
    fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("Failed to get QUIC local address")
    }

    async fn accept(&self) -> Result<Arc<dyn EgressDatagramConnection>> {
        let connecting = self
            .endpoint
            .accept()
            .await
            .context("QUIC endpoint closed")?;
        let connection = connecting
            .await
            .context("QUIC connection handshake failed")?;
        Ok(Arc::new(QuicEgressConnection {
            inner: connection,
            max_datagram_size: self.max_datagram_size,
        }))
    }
}

/// UDP mapping egress configuration.
///
/// Holds parsed config values. The actual datagram forwarding loop
/// is managed by `DatagramEgressFlow`.
pub struct MappingUdpEgress {
    pub id: usize,
    pub listen_addr: String,
    pub listen_port: u16,
    pub backend_addr: String,
    pub backend_port: u16,
    pub max_datagram_size: Option<usize>,
    pub idle_timeout_secs: u64,
}

impl MappingUdpEgress {
    pub async fn new(id: usize, mapping_args: &EgressMappingUdpArgs) -> Result<Self> {
        Ok(Self {
            id,
            listen_addr: mapping_args
                .r#in
                .host
                .as_deref()
                .unwrap_or("0.0.0.0")
                .to_owned(),
            listen_port: mapping_args.r#in.port,

            backend_addr: mapping_args
                .out
                .host
                .as_deref()
                .context("'host' of 'out' field must be set for mapping_udp egress")?
                .to_owned(),
            backend_port: mapping_args.out.port,

            max_datagram_size: None,
            idle_timeout_secs: mapping_args.idle_timeout_secs.unwrap_or(30),
        })
    }

    /// Set max_datagram_size from top-level quic config.
    pub fn set_max_datagram_size(&mut self, size: Option<usize>) {
        self.max_datagram_size = size;
    }

    pub fn metric_attributes(&self) -> IndexMap<String, String> {
        [
            ("egress_type".to_owned(), "mapping_udp".to_owned()),
            ("egress_id".to_owned(), self.id.to_string()),
            (
                "egress_in".to_owned(),
                format!("{}:{}", self.listen_addr, self.listen_port),
            ),
            (
                "egress_out".to_owned(),
                format!("{}:{}", self.backend_addr, self.backend_port),
            ),
        ]
        .into()
    }
}

#[async_trait]
impl EgressDatagramTrait for MappingUdpEgress {
    fn metric_attributes(&self) -> IndexMap<String, String> {
        self.metric_attributes()
    }

    fn backend_endpoint(&self) -> TngEndpoint {
        TngEndpoint::new(self.backend_addr.clone(), self.backend_port)
    }

    fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    async fn bind_listener(
        &self,
        tls_gen: &TlsConfigGenerator,
    ) -> Result<Arc<dyn EgressDatagramListener>> {
        let listen_addr: SocketAddr =
            format!("{}:{}", self.listen_addr, self.listen_port).parse()?;

        let tls_config = tls_gen
            .get_blocking_one_time_rustls_server_config(Alpn::RatsQuic)
            .await?;

        let server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config.0)?));
        let endpoint = quinn::Endpoint::server(server_config, listen_addr)
            .context("Failed to bind QUIC endpoint")?;

        Ok(Arc::new(QuicEgressListener {
            endpoint,
            max_datagram_size: self.max_datagram_size,
        }))
    }
}
