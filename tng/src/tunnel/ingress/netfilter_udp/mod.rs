mod iptables;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use bytes::Bytes;
use indexmap::IndexMap;

use crate::config::ingress::{IngressNetfilterCaptureDst, IngressNetfilterUdpArgs};
use crate::tunnel::access_log::IngressAccessMode;
use crate::tunnel::ingress::datagram_flow::{
    IngressDatagramListener, IngressDatagramTrait, IngressDatagramTunnel, QuicIngressTunnel,
};
use crate::tunnel::udp::quic_tunnel::QuicDatagramTunnelClient;
use crate::tunnel::utils::iptables::{IptablesExecutor, IptablesGuard};
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::rustls::config::alpn::Alpn;
use crate::tunnel::utils::rustls::config::TlsConfigGenerator;
use crate::tunnel::utils::socket::TCP_CONNECT_SO_MARK_DEFAULT;
use crate::tunnel::utils::udp::tproxy_recv::TproxyRecvSocket;
use crate::tunnel::utils::udp::tproxy_send::RawUdpSender;

/// Default idle-timeout for a netfilter_udp ingress session when the
/// `idle_timeout_secs` config field is unset.
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;

/// UDP netfilter ingress configuration.
///
/// Intercepts UDP packets via iptables TPROXY, extracts the original
/// destination via IP_ORIGDSTADDR, and establishes per-(client, dst)
/// QUIC datagram tunnels to egress. The forwarding loop, session map, and
/// idle cleanup are owned by `DatagramIngressFlow`; this struct only holds
/// parsed config and provides the listener + tunnel creation.
pub struct NetfilterUdpIngress {
    pub id: usize,
    pub listen_port: u16,
    pub so_mark: u32,
    pub capture_dst: Vec<IngressNetfilterCaptureDst>,
    pub capture_cgroup: Vec<String>,
    pub nocapture_cgroup: Vec<String>,
    pub idle_timeout_secs: u64,
}

/// Pick a free port that does not fall inside any `capture_dst` port range,
/// re-rolling (up to a bounded number of attempts) when the random pick
/// collides with a captured range. Host/ipset-only rules (no port) are
/// ignored — they match all ports and cannot be avoided by picking a port.
fn pick_port_avoiding(capture_dst: &[IngressNetfilterCaptureDst]) -> Result<u16> {
    for _ in 0..64 {
        let p = portpicker::pick_unused_port().context("Failed to pick a free port")?;
        let mut collided = false;
        for cap in capture_dst {
            if let Some((start, end)) = cap.port_range() {
                if (start..=end).contains(&p) {
                    collided = true;
                    break;
                }
            }
        }
        if !collided {
            return Ok(p);
        }
    }
    anyhow::bail!("Failed to pick a free port outside `capture_dst` ranges after 64 attempts")
}

impl NetfilterUdpIngress {
    pub async fn new(id: usize, args: &IngressNetfilterUdpArgs) -> Result<Self> {
        let so_mark = args.so_mark.unwrap_or(TCP_CONNECT_SO_MARK_DEFAULT);
        let capture_dst: Vec<IngressNetfilterCaptureDst> = args
            .capture_dst
            .iter()
            .map(Clone::clone)
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>>>()?;

        // `listen_port` is the TPROXY interception socket's receive port. It is
        // optional: when unset, a free port is picked randomly — just like the
        // TCP `netfilter` ingress. It MUST NOT overlap any `capture_dst` port,
        // otherwise the listener would intercept its own traffic and recurse.
        // When the port is auto-picked, we re-roll until it lands outside
        // every `capture_dst` port range.
        let listen_port = match args.listen_port {
            Some(p) => {
                for cap in &capture_dst {
                    if let Some((start, end)) = cap.port_range() {
                        if (start..=end).contains(&p) {
                            anyhow::bail!(
                                "netfilter_udp ingress `listen_port` ({}) must not overlap a \
                                 `capture_dst` port range ({}-{}); the TPROXY listener would \
                                 intercept its own traffic",
                                p,
                                start,
                                end
                            );
                        }
                    }
                }
                p
            }
            None => pick_port_avoiding(&capture_dst)?,
        };

        let idle_timeout_secs = args.idle_timeout_secs.unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS);

        Ok(Self {
            id,
            listen_port,
            so_mark,
            capture_dst,
            capture_cgroup: args.capture_cgroup.clone(),
            nocapture_cgroup: args.nocapture_cgroup.clone(),
            idle_timeout_secs,
        })
    }
}

/// TPROXY listener for netfilter_udp — owns the TPROXY interception socket
/// (wrapped in [`TproxyRecvSocket`], which drives `AsyncFd` readiness +
/// `clear_ready()` and `recvmsg`) and the cached `SOCK_RAW` reply socket, plus
/// the iptables guard whose drop revokes the TPROXY rules on shutdown.
///
/// Reads via raw `recvmsg` to obtain `IP_ORIGDSTADDR`. Because tokio's own
/// `UdpSocket::readable()` readiness flag is only cleared by tokio's own
/// `recv`/`try_recv` (not raw `recvmsg`), the receive path wraps the socket in
/// `AsyncFd` and manually `clear_ready()`s on `WouldBlock` — otherwise the
/// readiness flag is never cleared and the loop busy-spins forever. That logic
/// lives inside [`TproxyRecvSocket`].
struct NetfilterUdpTproxyListener {
    /// The downstream (client-facing) TPROXY interception socket, wrapped for
    /// tokio readiness and `recvmsg` (`IP_ORIGDSTADDR` extraction).
    downstream_recv: TproxyRecvSocket,
    /// The downstream (client-facing) reply socket — a cached `SOCK_RAW` +
    /// `IP_HDRINCL` socket that sends replies back to the client with the IPv4
    /// source spoofed to `orig_dst:port` (no `bind`, so a co-located backend on
    /// that port need not set `SO_REUSEADDR`). `so_mark` is baked in at
    /// creation so the reply bypasses this node's own mangle `OUTPUT` capture.
    downstream_reply_sender: RawUdpSender,
    local_addr: SocketAddr,
    _iptables_guard: IptablesGuard,
}

#[async_trait]
impl IngressDatagramListener for NetfilterUdpTproxyListener {
    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.local_addr)
    }

    async fn recv_datagram(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr, SocketAddr)> {
        let packet = self.downstream_recv.recv(buf).await?;
        Ok((packet.len, packet.peer, packet.orig_dst))
    }

    async fn send_to_client(
        &self,
        data: &Bytes,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> Result<()> {
        // Reply from the original destination the client dialed (spoofed via
        // the cached `SOCK_RAW` + `IP_HDRINCL` socket), not from the TPROXY
        // listener socket (bound 127.0.0.1:listen_port) — a connected client
        // socket only accepts replies from the peer it dialed (original_dst).
        self.downstream_reply_sender
            .send(data.as_ref(), original_dst, client_addr)
            .context("netfilter_udp reply send failed")?;
        Ok(())
    }
}

#[async_trait]
impl IngressDatagramTrait for NetfilterUdpIngress {
    fn metric_attributes(&self) -> IndexMap<String, String> {
        [
            ("ingress_type".to_owned(), "netfilter_udp".to_owned()),
            ("ingress_id".to_owned(), self.id.to_string()),
            (
                "ingress_listen_port".to_owned(),
                self.listen_port.to_string(),
            ),
        ]
        .into()
    }

    fn access_mode(&self) -> IngressAccessMode {
        IngressAccessMode::NetfilterUdp
    }

    fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    async fn create_tunnel(
        &self,
        _client_addr: SocketAddr,
        original_dst: SocketAddr,
        max_datagram_size: Option<usize>,
        tls_gen: &TlsConfigGenerator,
        _runtime: TokioRuntime,
    ) -> Result<Arc<dyn IngressDatagramTunnel>> {
        let tls_config = tls_gen
            .get_blocking_one_time_rustls_client_config(Alpn::RatsQuic)
            .await?;

        let ep = match original_dst.ip() {
            std::net::IpAddr::V4(ip) => crate::config::Endpoint {
                host: Some(ip.to_string()),
                port: original_dst.port(),
            },
            std::net::IpAddr::V6(_) => {
                anyhow::bail!("IPv6 original destination not supported for netfilter_udp");
            }
        };

        let quic_tunnel = QuicDatagramTunnelClient::connect(
            &ep,
            Alpn::RatsQuic,
            max_datagram_size,
            tls_config,
            // SO_MARK so the ingress's own QUIC handshake packets bypass the
            // local OUTPUT capture rule (the `--mark {so_mark} -j RETURN`
            // escape hatch). Without this, the QUIC connection to the egress
            // (which is exactly a capture_dst) would be swallowed locally.
            Some(self.so_mark),
        )
        .await?;

        Ok(Arc::new(QuicIngressTunnel::new(quic_tunnel)))
    }

    async fn bind_listener(&self) -> Result<Arc<dyn IngressDatagramListener>> {
        // 1. Create the TPROXY interception socket (IP_TRANSPARENT +
        // IP_RECVORIGDSTADDR, bound 127.0.0.1:listen_port, nonblocking) and
        // wrap it in `TproxyRecvSocket` (`AsyncFd` readiness + `recvmsg` +
        // `clear_ready()` — see `NetfilterUdpTproxyListener::recv_datagram`).
        let bind_addr: std::net::SocketAddr = format!("127.0.0.1:{}", self.listen_port).parse()?;
        let downstream_recv = TproxyRecvSocket::new(bind_addr)?;
        let local_addr = downstream_recv.local_addr();

        // Cached SOCK_RAW + IP_HDRINCL reply socket with `so_mark` baked in so
        // replies (spoofed from `orig_dst:port`) bypass this node's own mangle
        // OUTPUT capture (the `--mark {so_mark} -j RETURN` escape).
        let downstream_reply_sender = RawUdpSender::new(Some(self.so_mark))?;

        // 2. Iptables setup — the guard is held by the listener and revoked on
        // drop (when the flow's `serve` returns / the listener is dropped).
        let _iptables_guard = IptablesExecutor::setup(self).await?;

        tracing::info!(
            "netfilter_udp ingress listening on {} (TPROXY on 127.0.0.1:{})",
            local_addr,
            self.listen_port
        );

        Ok(Arc::new(NetfilterUdpTproxyListener {
            downstream_recv,
            downstream_reply_sender,
            local_addr,
            _iptables_guard,
        }))
    }
}
