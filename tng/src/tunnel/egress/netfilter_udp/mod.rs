mod iptables;
mod quinn_tproxy_bridge;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use bytes::Bytes;
use indexmap::IndexMap;

use crate::config::egress::{CommonArgs, EgressNetfilterCaptureDst, EgressNetfilterUdpArgs};
use crate::tunnel::egress::datagram_flow::{
    AcceptedConnection, EgressDatagramConnection, EgressDatagramListener, EgressDatagramTrait,
};
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::utils::iptables::IptablesExecutor;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::rustls::config::alpn::Alpn;
use crate::tunnel::utils::rustls::config::TlsConfigGenerator;
use crate::tunnel::utils::socket::TCP_CONNECT_SO_MARK_DEFAULT;

use self::quinn_tproxy_bridge::QuinnTproxyBridgeSocket;

/// A hack to bridge quinn's `AsyncUdpSocket` interface with the netfilter_udp
/// business requirement of replying from the spoofed `orig_dst`.
///
/// quinn hands us a `Transmit` whose `destination` is the downstream's address
/// but gives no way to recover the original destination that TPROXY captured for
/// that downstream's packets. So at `poll_recv` time — when we *do* have both the
/// downstream address and the `IP_ORIGDSTADDR` (`orig_dst`) — we record the
/// downstream → `orig_dst` correspondence here, and at `try_send` time we look
/// it up to spoof the reply's IPv4 source as `orig_dst:port` (so the
/// downstream's connected QUIC socket accepts the reply). It is also queried at
/// `accept` time to derive the backend address to forward to.
///
/// ("downstream" = the tunnel-facing peer — the ingress QUIC client — never the
/// upstream backend. The earlier `peer` wording was dropped because in this code
/// "peer" ambiguously meant either side.)
#[derive(Default)]
pub struct DownstreamOrigDstMap {
    /// downstream address → its TPROXY-captured original destination.
    ///
    /// A synchronous (`parking_lot`) `Mutex` — not `tokio::sync::Mutex` — because
    /// the map is read/written from quinn's *synchronous* trait methods
    /// `AsyncUdpSocket::poll_recv` (`insert`) and `try_send` (`get`), which
    /// cannot `.await` an async lock. The critical section is a single
    /// `HashMap` `insert`/`get` with effectively no contention (one
    /// downstream peer at a time), so the uncontended fast-path — a CAS, no
    /// futex/syscall, sub-microsecond — is well within tokio's tolerance for
    /// short synchronous work; only long/blocking operations need
    /// `spawn_blocking`/`block_in_place`. `tokio::sync::Mutex` is additionally
    /// unsuitable because its guard cannot be held across the `Poll` return.
    map: parking_lot::Mutex<HashMap<SocketAddr, SocketAddr>>,
}

impl DownstreamOrigDstMap {
    /// Record that `downstream`'s TPROXY-captured original destination is
    /// `orig_dst`.
    pub fn insert(&self, downstream: SocketAddr, orig_dst: SocketAddr) {
        self.map.lock().insert(downstream, orig_dst);
    }

    /// Look up the original destination recorded for `downstream`.
    pub fn get(&self, downstream: &SocketAddr) -> Option<SocketAddr> {
        self.map.lock().get(downstream).copied()
    }

    #[allow(dead_code)]
    pub fn remove(&self, downstream: &SocketAddr) {
        self.map.lock().remove(downstream);
    }
}

/// One accepted QUIC connection on the egress, wrapped as an
/// [`EgressDatagramConnection`] for the flow's per-connection forwarding.
struct NetfilterUdpQuicConnection {
    /// The underlying quinn connection (downstream / tunnel side).
    connection: quinn::Connection,
}

#[async_trait]
impl EgressDatagramConnection for NetfilterUdpQuicConnection {
    fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    async fn read_datagram(&self) -> Result<Bytes> {
        self.connection
            .read_datagram()
            .await
            .context("QUIC datagram read failed")
    }

    fn send_datagram(&self, payload: Bytes) -> Result<()> {
        self.connection
            .send_datagram(payload)
            .context("QUIC datagram send failed")
    }

    fn close(&self, error_code: u32, reason: &[u8]) {
        self.connection.close(error_code.into(), reason);
    }
}

/// Default idle-timeout for a netfilter_udp egress session when the
/// `idle_timeout_secs` config field is unset.
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;

/// UDP netfilter egress configuration (parsed from [`EgressNetfilterUdpArgs`]).
///
/// The actual QUIC accept loop + per-connection forwarding is owned by
/// `DatagramEgressFlow`; this struct holds parsed config and provides the
/// listener via `bind_listener`.
pub struct NetfilterUdpEgress {
    /// Instance index within the egress list; added to the per-mode fwmark /
    /// routing-table bases so concurrent instances get disjoint iptables state.
    pub id: usize,
    /// The TPROXY interception socket's receive port (the QUIC listener port).
    pub listen_port: u16,
    /// SO_MARK set on TNG's own backend-forward UDP sockets so they bypass the
    /// local mangle TPROXY capture (the `--mark so_mark -j RETURN` escape).
    pub so_mark: u32,
    /// Destination rules defining which UDP traffic TPROXY intercepts.
    pub capture_dst: Vec<EgressNetfilterCaptureDst>,
    /// Whether to also intercept locally-generated traffic (`--src-type LOCAL`).
    pub capture_local_traffic: bool,
    /// cgroup v2 paths to capture (allowlist); empty = capture all matched.
    pub capture_cgroup: Vec<String>,
    /// cgroup v2 paths to exclude from capture (denylist).
    pub nocapture_cgroup: Vec<String>,
    /// Idle timeout (seconds) for a backend UDP session; idle in both
    /// directions closes it. Defaults to [`DEFAULT_IDLE_TIMEOUT_SECS`].
    pub idle_timeout_secs: u64,
    /// Downstream → `orig_dst` correspondence (see [`DownstreamOrigDstMap`]),
    /// shared between the egress config and the quinn bridge socket so
    /// `poll_recv` can record and `try_send` / `accept` can look it up.
    pub downstream_orig_dst_map: Arc<DownstreamOrigDstMap>,
}

/// Pick a free port that does not fall inside any `capture_dst` port range,
/// re-rolling (up to a bounded number of attempts) when the random pick
/// collides with a captured range. Host/ipset-only rules (no port) are
/// ignored — they match all ports and cannot be avoided by picking a port.
fn pick_port_avoiding(capture_dst: &[EgressNetfilterCaptureDst]) -> Result<u16> {
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

impl NetfilterUdpEgress {
    pub async fn new(
        id: usize,
        args: &EgressNetfilterUdpArgs,
        _common_args: &CommonArgs,
        _runtime: TokioRuntime,
    ) -> Result<Self> {
        let capture_dst: Vec<EgressNetfilterCaptureDst> = args
            .capture_dst
            .iter()
            .map(Clone::clone)
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>>>()?;

        // `listen_port` is the TPROXY interception socket's receive port (the
        // QUIC listener). It is optional: when unset, a free port is picked
        // randomly — just like the TCP `netfilter` egress. It MUST NOT overlap
        // any `capture_dst` port, otherwise the listener would intercept its
        // own traffic and recurse. When the port is auto-picked, we re-roll
        // until it lands outside every `capture_dst` port range.
        let listen_port = match args.listen_port {
            Some(p) => {
                for cap in &capture_dst {
                    if let Some((start, end)) = cap.port_range() {
                        if (start..=end).contains(&p) {
                            anyhow::bail!(
                                "netfilter_udp egress `listen_port` ({}) must not overlap a \
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

        let so_mark = args.so_mark.unwrap_or(TCP_CONNECT_SO_MARK_DEFAULT);
        let idle_timeout_secs = args.idle_timeout_secs.unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS);

        Ok(Self {
            id,
            listen_port,
            so_mark,
            capture_dst,
            capture_local_traffic: args.capture_local_traffic,
            capture_cgroup: args.capture_cgroup.clone(),
            nocapture_cgroup: args.nocapture_cgroup.clone(),
            idle_timeout_secs,
            downstream_orig_dst_map: Arc::new(DownstreamOrigDstMap::default()),
        })
    }
}

#[async_trait]
impl EgressDatagramTrait for NetfilterUdpEgress {
    fn metric_attributes(&self) -> IndexMap<String, String> {
        [
            ("egress_type".to_owned(), "netfilter_udp".to_owned()),
            ("egress_id".to_owned(), self.id.to_string()),
            (
                "egress_listen_port".to_owned(),
                self.listen_port.to_string(),
            ),
        ]
        .into()
    }

    fn access_mode(&self) -> crate::tunnel::access_log::EgressAccessMode {
        crate::tunnel::access_log::EgressAccessMode::NetfilterUdp
    }

    fn so_mark(&self) -> Option<u32> {
        Some(self.so_mark)
    }

    fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    async fn bind_listener(
        &self,
        tls_gen: &TlsConfigGenerator,
        max_datagram_size: Option<usize>,
    ) -> Result<Arc<dyn EgressDatagramListener>> {
        use crate::tunnel::utils::iptables::IptablesGuard;

        let tls_config = tls_gen
            .get_blocking_one_time_rustls_server_config(Alpn::RatsQuic)
            .await?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config.0)?,
        ));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(0u32.into());
        transport_config.max_concurrent_uni_streams(0u32.into());
        if let Some(size) = max_datagram_size {
            transport_config.datagram_receive_buffer_size(Some(size));
            transport_config.datagram_send_buffer_size(size);
        }
        server_config.transport_config(Arc::new(transport_config));

        // Wrap the downstream TPROXY socket as quinn's `AsyncUdpSocket`;
        // `QuinnTproxyBridgeSocket::new` creates the TPROXY interception
        // socket (bound to `0.0.0.0:listen_port`) and wraps it for tokio
        // readiness + the cached `SOCK_RAW` reply socket.
        let bind_addr: std::net::SocketAddr = format!("0.0.0.0:{}", self.listen_port).parse()?;
        let netfilter_socket =
            QuinnTproxyBridgeSocket::new(bind_addr, Arc::clone(&self.downstream_orig_dst_map))?;

        // Create quinn endpoint with our custom socket
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            Arc::new(netfilter_socket),
            Arc::new(quinn::TokioRuntime),
        )?;

        // Setup iptables
        let iptables_guard: IptablesGuard = IptablesExecutor::setup(self).await?;

        // The QUIC listener itself is logged by `DatagramEgressFlow::serve`
        // (shared with the mapping_udp egress); here we only log the TPROXY
        // interception setup.
        tracing::info!(
            "netfilter_udp egress TPROXY on 0.0.0.0:{}",
            self.listen_port
        );

        Ok(Arc::new(NetfilterUdpQuicListener {
            endpoint,
            downstream_orig_dst_map: Arc::clone(&self.downstream_orig_dst_map),
            _iptables_guard: iptables_guard,
        }))
    }
}

/// The egress's QUIC listener (`quinn::Endpoint`) exposed as an
/// [`EgressDatagramListener`]. Accepts the ingress's QUIC connections and
/// derives each connection's backend address from the `orig_dst` TPROXY
/// recorded for that downstream. Holds the iptables guard so the TPROXY rules
/// are revoked when the listener (and thus the flow) is dropped.
struct NetfilterUdpQuicListener {
    /// The quinn QUIC endpoint (downstream / tunnel-facing listener).
    endpoint: quinn::Endpoint,
    /// Downstream → `orig_dst` correspondence; queried at `accept` time to
    /// derive the backend address to forward to (and, in the bridge socket, at
    /// `try_send` time to spoof the reply source).
    downstream_orig_dst_map: Arc<DownstreamOrigDstMap>,
    /// Revokes the TPROXY iptables rules on drop (when the flow stops).
    _iptables_guard: crate::tunnel::utils::iptables::IptablesGuard,
}

#[async_trait]
impl EgressDatagramListener for NetfilterUdpQuicListener {
    fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("get netfilter_udp egress listener local addr")
    }

    async fn accept(&self) -> Result<AcceptedConnection> {
        let connecting = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("QUIC endpoint closed"))?;
        let connection = connecting
            .await
            .context("QUIC connection handshake failed")?;

        let downstream = connection.remote_address();

        // Derive the backend address from the IP_ORIGDSTADDR that TPROXY
        // interception recorded for this downstream when its QUIC packets were
        // redirected to the listener. This is the original destination the
        // client intended to reach — i.e. the real backend service.
        let orig_dst = self
            .downstream_orig_dst_map
            .get(&downstream)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no orig_dst mapping for downstream {} — the packet may have arrived \
                     before TPROXY interception populated the map, or the connection \
                     was established via a different path",
                    downstream
                )
            })?;
        let backend_addr = TngEndpoint::new(orig_dst.ip().to_string(), orig_dst.port());

        tracing::debug!(
            %downstream, %backend_addr,
            "Accepted QUIC connection on netfilter_udp egress"
        );

        Ok(AcceptedConnection {
            connection: Arc::new(NetfilterUdpQuicConnection { connection }),
            backend_addr,
        })
    }
}
