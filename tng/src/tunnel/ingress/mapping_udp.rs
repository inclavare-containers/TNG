use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use bytes::Bytes;
use indexmap::IndexMap;
use tokio::net::UdpSocket;

use crate::config::ingress::IngressMappingUdpArgs;
use crate::tunnel::access_log::IngressAccessMode;
use crate::tunnel::endpoint::EndpointAddr;
use crate::tunnel::ingress::datagram_flow::{
    IngressDatagramListener, IngressDatagramTrait, IngressDatagramTunnel, QuicIngressTunnel,
};
use crate::tunnel::udp::quic_tunnel::QuicDatagramTunnelClient;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::rustls::config::alpn::Alpn;
use crate::tunnel::utils::rustls::config::TlsConfigGenerator;
use crate::tunnel::utils::socket::resolve_ipv4_addr;

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
            idle_timeout_secs,
        })
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

    /// The fixed original destination a captured client packet is mapped to.
    /// Mirrors the former `recv_datagram` logic: an IPv4 egress endpoint yields
    /// its address; a domain endpoint is resolved to its first IPv4 address
    /// (the netfilter_udp/datagram_flow path is IPv4-only, so non-IPv4 results
    /// are skipped and a v6-only domain errors out).
    async fn fixed_original_dst(&self) -> Result<SocketAddr> {
        let original_dst = match EndpointAddr::from_host(&self.egress_addr) {
            EndpointAddr::Ipv4(ip) => SocketAddr::new(std::net::IpAddr::V4(ip), self.egress_port),
            EndpointAddr::Domain(d) => resolve_ipv4_addr(&d, self.egress_port)
                .await
                .with_context(|| format!("resolve mapping_udp egress domain {d}"))?,
        };
        Ok(original_dst)
    }
}

/// Plain UDP listener for mapping_udp — owns a bound `UdpSocket` and the fixed
/// original destination. All client datagram I/O goes through the flow, which
/// calls `recv_datagram` / `send_to_client` here.
struct MappingUdpListener {
    socket: Arc<UdpSocket>,
    original_dst: SocketAddr,
}

#[async_trait]
impl IngressDatagramListener for MappingUdpListener {
    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .context("get mapping listener local addr")
    }

    async fn recv_datagram(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr, SocketAddr)> {
        let (n, client_src) = self.socket.recv_from(buf).await?;
        Ok((n, client_src, self.original_dst))
    }

    async fn send_to_client(
        &self,
        data: &Bytes,
        client_addr: SocketAddr,
        _original_dst: SocketAddr,
    ) -> Result<()> {
        self.socket.send_to(data, client_addr).await?;
        Ok(())
    }
}

#[async_trait]
impl IngressDatagramTrait for MappingUdpIngress {
    fn metric_attributes(&self) -> IndexMap<String, String> {
        self.metric_attributes()
    }

    fn access_mode(&self) -> IngressAccessMode {
        IngressAccessMode::MappingUdp
    }

    fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    async fn create_tunnel(
        &self,
        _client_addr: SocketAddr,
        _original_dst: SocketAddr,
        max_datagram_size: Option<usize>,
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
            max_datagram_size,
            tls_config,
            // mapping_udp installs no iptables OUTPUT capture rule, so no
            // SO_MARK is needed on the QUIC client socket.
            None,
        )
        .await?;

        Ok(Arc::new(QuicIngressTunnel::new(quic_tunnel)))
    }

    async fn bind_listener(&self) -> Result<Arc<dyn IngressDatagramListener>> {
        let listen_str = format!("{}:{}", self.listen_addr, self.listen_port);
        let socket = UdpSocket::bind(&listen_str)
            .await
            .with_context(|| format!("Failed to bind mapping_udp listener on {listen_str}"))?;
        tracing::info!("UDP mapping ingress listening on {}", listen_str);

        Ok(Arc::new(MappingUdpListener {
            socket: Arc::new(socket),
            original_dst: self.fixed_original_dst().await?,
        }))
    }
}
