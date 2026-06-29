use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use bytes::Bytes;
use indexmap::IndexMap;

use crate::config::ingress::IngressMappingUdpArgs;
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::ingress::datagram_flow::{IngressDatagramTrait, IngressDatagramTunnel};
use crate::tunnel::udp::quic_tunnel::QuicDatagramTunnelClient;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::rustls::config::alpn::Alpn;
use crate::tunnel::utils::rustls::config::TlsConfigGenerator;

/// QUIC-backed tunnel implementing `IngressDatagramTunnel`.
struct QuicIngressTunnel {
    inner: QuicDatagramTunnelClient,
}

#[async_trait]
impl IngressDatagramTunnel for QuicIngressTunnel {
    fn send_datagram(&self, payload: Bytes) -> Result<()> {
        self.inner.send_datagram(payload)
    }

    async fn read_datagram(&self) -> Result<Bytes> {
        self.inner.receive_datagram().await
    }

    fn close(&self, error_code: u32, reason: &[u8]) {
        self.inner.connection.close(error_code.into(), reason);
    }
}

/// UDP mapping ingress configuration.
///
/// Holds parsed config values. The actual datagram forwarding loop
/// is managed by `DatagramIngressFlow`.
pub struct MappingUdpIngress {
    pub id: usize,
    pub listen_addr: String,
    pub listen_port: u16,
    pub egress_addr: String,
    pub egress_port: u16,
    pub max_datagram_size: Option<usize>,
    pub idle_timeout_secs: u64,
}

impl MappingUdpIngress {
    pub async fn new(id: usize, mapping_args: &IngressMappingUdpArgs) -> Result<Self> {
        let listen_addr = mapping_args
            .r#in
            .host
            .as_deref()
            .unwrap_or("0.0.0.0")
            .to_owned();
        let listen_port = mapping_args.r#in.port;

        let egress_addr = mapping_args
            .out
            .host
            .as_deref()
            .context("'host' of 'out' field must be set for mapping_udp ingress")?
            .to_owned();
        let egress_port = mapping_args.out.port;

        let idle_timeout_secs = mapping_args.idle_timeout_secs.unwrap_or(30);

        Ok(Self {
            id,
            listen_addr,
            listen_port,
            egress_addr,
            egress_port,
            max_datagram_size: None,
            idle_timeout_secs,
        })
    }

    /// Set max_datagram_size from top-level quic config.
    pub fn set_max_datagram_size(&mut self, size: Option<usize>) {
        self.max_datagram_size = size;
    }

    pub fn metric_attributes(&self) -> IndexMap<String, String> {
        [
            ("ingress_type".to_owned(), "mapping_udp".to_owned()),
            ("ingress_id".to_owned(), self.id.to_string()),
            (
                "ingress_in".to_owned(),
                format!("{}:{}", self.listen_addr, self.listen_port),
            ),
            (
                "ingress_out".to_owned(),
                format!("{}:{}", self.egress_addr, self.egress_port),
            ),
        ]
        .into()
    }
}

#[async_trait]
impl IngressDatagramTrait for MappingUdpIngress {
    fn metric_attributes(&self) -> IndexMap<String, String> {
        self.metric_attributes()
    }

    fn listen_endpoint(&self) -> (String, u16) {
        (self.listen_addr.clone(), self.listen_port)
    }

    fn egress_endpoint(&self) -> TngEndpoint {
        TngEndpoint::new(self.egress_addr.clone(), self.egress_port)
    }

    fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    async fn create_tunnel(
        &self,
        _client_addr: SocketAddr,
        tls_gen: &TlsConfigGenerator,
        _runtime: TokioRuntime,
    ) -> Result<Arc<dyn IngressDatagramTunnel>> {
        use crate::config::Endpoint;

        let egress_endpoint = Endpoint {
            host: Some(self.egress_addr.clone()),
            port: self.egress_port,
        };

        let tls_config = tls_gen
            .get_blocking_one_time_rustls_client_config(Alpn::RatsQuic)
            .await?;

        let quic_tunnel = QuicDatagramTunnelClient::connect(
            &egress_endpoint,
            Alpn::RatsQuic,
            self.max_datagram_size,
            tls_config,
        )
        .await?;

        Ok(Arc::new(QuicIngressTunnel { inner: quic_tunnel }))
    }
}
