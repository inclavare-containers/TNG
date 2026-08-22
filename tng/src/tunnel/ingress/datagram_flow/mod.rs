use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use web_time_compat::{Duration, Instant, InstantExt};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use indexmap::IndexMap;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::config::ingress::CommonArgs as IngressCommonArgs;
use crate::error::TngError;
use crate::service::RegistedService;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::tunnel::access_log::{AccessAccepted, AccessEstablished, IngressAccessMode};
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::service_metrics::ServiceMetrics;
use crate::tunnel::service_metrics::ServiceMetricsCreator;
use crate::tunnel::udp::quic_tunnel::QuicDatagramTunnelClient;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::rustls::config::TlsConfigGenerator;

/// QUIC-backed tunnel wrapper shared by all ingress datagram modes
/// (mapping_udp, netfilter_udp).
///
/// The Flow owns the UDP socket and session map; the tunnel handles
/// communication with the egress endpoint.
pub(super) struct QuicIngressTunnel {
    inner: QuicDatagramTunnelClient,
}

impl QuicIngressTunnel {
    pub(super) fn new(inner: QuicDatagramTunnelClient) -> Self {
        Self { inner }
    }
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

/// Trait for QUIC tunnel operations on the ingress side.
///
/// Implemented by protocol-specific tunnel wrappers (e.g. QUIC-based).
/// The Flow owns the UDP socket and session map; the tunnel handles
/// communication with the egress endpoint.
#[async_trait]
pub(super) trait IngressDatagramTunnel: Send + Sync {
    /// Send a datagram to the egress endpoint.
    fn send_datagram(&self, payload: Bytes) -> Result<()>;

    /// Read a datagram from the egress endpoint.
    async fn read_datagram(&self) -> Result<Bytes>;

    /// Close the tunnel connection with the given error code and reason.
    fn close(&self, error_code: u32, reason: &[u8]);
}

/// Trait for an ingress datagram listener — owns the client-side UDP socket
/// and provides datagram I/O. Mirrors `EgressDatagramListener` on the egress
/// side: the Flow calls `bind_listener()` once, then drives `recv_datagram`
/// and `send_to_client` on the returned listener.
#[async_trait]
pub(super) trait IngressDatagramListener: Send + Sync {
    /// Get the local address the listener is bound to.
    fn local_addr(&self) -> Result<SocketAddr>;

    /// Receive a datagram from a client, returning
    /// `(bytes_read, client_source, original_destination)`.
    ///
    /// For `mapping_udp`: uses `udp_socket.recv_from()`, `original_dst` =
    /// the resolved egress endpoint. For `netfilter_udp`: uses `AsyncFd +
    /// recvmsg` to extract `IP_ORIGDSTADDR`.
    async fn recv_datagram(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr, SocketAddr)>;

    /// Send a datagram back to a client.
    ///
    /// `original_dst` is the destination the client dialed; `netfilter_udp`
    /// spoofs the reply source from it (via an `IP_TRANSPARENT` socket bound to
    /// `original_dst`), `mapping_udp` ignores it and sends from the listener.
    async fn send_to_client(
        &self,
        data: &Bytes,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> Result<()>;
}

/// Trait for ingress datagram configurations.
///
/// Implemented by protocol-specific ingress configurations (e.g. mapping_udp,
/// netfilter_udp). The Flow manages the session map, idle cleanup, and TLS
/// config; this trait provides listener binding and QUIC tunnel creation.
#[async_trait]
pub(super) trait IngressDatagramTrait: Send + Sync {
    /// Return the metric attributes of this ingress.
    fn metric_attributes(&self) -> IndexMap<String, String>;

    /// Return the access-log mode of this ingress.
    fn access_mode(&self) -> IngressAccessMode;

    /// The idle timeout in seconds for client sessions.
    fn idle_timeout_secs(&self) -> u64;

    /// Create a new QUIC tunnel to the egress endpoint for the given client.
    /// `original_dst` is the original destination address (from IP_ORIGDSTADDR
    /// for netfilter_udp, or the fixed egress endpoint for mapping_udp).
    /// `max_datagram_size` is the top-level `quic.max_datagram_size` (the Flow
    /// owns it so RA context is managed centrally). The Flow provides the TLS
    /// config generator so RA context is managed centrally.
    async fn create_tunnel(
        &self,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
        max_datagram_size: Option<usize>,
        tls_gen: &TlsConfigGenerator,
        runtime: TokioRuntime,
    ) -> Result<Arc<dyn IngressDatagramTunnel>>;

    /// Bind the client-side UDP listener and return it. The listener owns the
    /// socket (a plain `UdpSocket` for mapping_udp; a TPROXY socket with the
    /// iptables guard for netfilter_udp).
    async fn bind_listener(&self) -> Result<Arc<dyn IngressDatagramListener>>;
}

/// Per-client QUIC session on ingress.
struct ClientSession {
    tunnel: Arc<dyn IngressDatagramTunnel>,
    last_activity: Arc<Mutex<Instant>>,
    /// Access log guard — logs on drop when the session is removed.
    #[allow(dead_code)]
    access_established: AccessEstablished,
}

pub struct DatagramIngressFlow {
    ingress: Arc<dyn IngressDatagramTrait>,
    tls_gen: TlsConfigGenerator,
    metrics: ServiceMetrics,
    runtime: TokioRuntime,
    /// Top-level `quic.max_datagram_size`, captured in `new()` from the common
    /// args and passed to `create_tunnel` per session.
    max_datagram_size: Option<usize>,
}

impl DatagramIngressFlow {
    #[allow(private_bounds)]
    pub async fn new(
        ingress: impl IngressDatagramTrait + 'static,
        common_args: &IngressCommonArgs,
        service_metrics_creator: &ServiceMetricsCreator,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let metric_attributes = ingress.metric_attributes();
        let metrics = service_metrics_creator.new_service_metrics(metric_attributes);

        let ra_args = common_args.ra_args.clone().into_checked()?;
        let ra_context =
            Arc::new(crate::tunnel::ra_context::RaContext::from_ra_args(&ra_args).await?);
        let tls_gen = TlsConfigGenerator::new(ra_context, runtime.clone()).await?;

        let max_datagram_size = common_args.quic.as_ref().and_then(|q| q.max_datagram_size);

        Ok(Self {
            ingress: Arc::new(ingress),
            tls_gen,
            metrics,
            runtime,
            max_datagram_size,
        })
    }
}

#[async_trait::async_trait]
impl RegistedService for DatagramIngressFlow {
    async fn serve(&self, ready: Sender<()>) -> Result<()> {
        let listener = self.ingress.bind_listener().await?;
        let listener_addr = listener.local_addr()?;
        let access_mode = self.ingress.access_mode();
        tracing::info!("UDP {} ingress listening on {}", access_mode, listener_addr);

        ready.send(()).await?;

        let idle_timeout_secs = self.ingress.idle_timeout_secs();
        // Idle-timeout probe cadence: the `sleep` arms below fire every 5s to
        // check whether a session has been idle past `idle_timeout_secs` (both
        // the per-session forward task and the periodic map sweep). 5s is coarse
        // but fine — the timeout itself is ~30s.
        let check_interval = Duration::from_secs(5);

        // client_addr -> ClientSession
        // Key is (client_src, original_dst) — for mapping_udp, original_dst is fixed.
        let client_map: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), ClientSession>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                // Direction A: Client -> QUIC
                recv_result = listener.recv_datagram(&mut buf) => {
                    let (n, client_src, original_dst) = recv_result?;
                    let payload = Bytes::copy_from_slice(&buf[..n]);

                    let session_key = (client_src, original_dst);

                    let mut map = client_map.lock().await;
                    let session = match map.get(&session_key) {
                        Some(s) => s,
                        None => {
                            tracing::info!(
                                %client_src, %original_dst,
                                "Creating QUIC connection for new client"
                            );

                            let tunnel = self.ingress
                                .create_tunnel(client_src, original_dst, self.max_datagram_size, &self.tls_gen, self.runtime.clone())
                                .await?;

                            let access_accepted = AccessAccepted::new_ingress(
                                client_src,
                                listener_addr,
                                access_mode,
                            );
                            // For the access log only: derive the upstream
                            // remote from `original_dst`. For mapping_udp this
                            // is the resolved egress endpoint; for netfilter_udp
                            // it is the per-packet captured destination.
                            let backend_ep = TngEndpoint::new(
                                original_dst.ip().to_string(),
                                original_dst.port(),
                            );
                            let access_routed = access_accepted.into_routed(
                                &backend_ep,
                                true,
                            );
                            let access_established =
                                access_routed.into_established(None, false);

                            let last_activity = Arc::new(Mutex::new(Instant::get()));

                            let metrics = self.metrics.clone();
                            let active_cx = metrics.new_cx();

                            // Spawn QUIC -> Client forwarding task
                            let listener = Arc::clone(&listener);
                            let last_activity_clone = last_activity.clone();
                            let idle_timeout = Duration::from_secs(idle_timeout_secs);
                            let client_src_for_task = session_key.0;
                            // The reply must come from the destination the client
                            // dialed (`original_dst`); the listener's
                            // `send_to_client` uses it (netfilter spoofs the
                            // source, mapping ignores it).
                            let original_dst_for_task = session_key.1;
                            let runtime_clone = self.runtime.clone();
                            let tunnel_clone = tunnel.clone();

                            runtime_clone.spawn_supervised_task(async move {
                                let mut success = false;
                                loop {
                                    tokio::select! {
                                        datagram_result = tunnel_clone.read_datagram() => {
                                            match datagram_result {
                                                Ok(datagram) => {
                                                    if let Err(e) = listener
                                                        .send_to_client(&datagram, client_src_for_task, original_dst_for_task)
                                                        .await
                                                    {
                                                        tracing::warn!(
                                                            %client_src_for_task,
                                                            error = %e,
                                                            "Failed to send datagram to client"
                                                        );
                                                    } else {
                                                        *last_activity_clone.lock().await = Instant::get();
                                                        success = true;
                                                    }
                                                }
                                                Err(_) => break,
                                            }
                                        }
                                        _ = sleep(check_interval) => {
                                            let last = *last_activity_clone.lock().await;
                                            if last.elapsed() >= idle_timeout {
                                                tracing::debug!(
                                                    %client_src_for_task,
                                                    "Idle timeout - closing QUIC connection"
                                                );
                                                tunnel_clone.close(0, b"idle");
                                                break;
                                            }
                                        }
                                    }
                                }
                                if success {
                                    active_cx.mark_finished_successfully();
                                }
                            });

                            map.entry(session_key).or_insert(ClientSession {
                                tunnel,
                                last_activity,
                                access_established,
                            })
                        }
                    };

                    // Update activity and forward
                    *session.last_activity.lock().await = Instant::get();
                    if let Err(e) = session.tunnel.send_datagram(payload) {
                        tracing::warn!(
                            %client_src, %original_dst,
                            error = %e,
                            "Failed to send datagram to QUIC"
                        );
                    }
                }
                // Periodic cleanup of idle sessions
                _ = sleep(check_interval) => {
                    let mut map = client_map.lock().await;
                    let idle_timeout = Duration::from_secs(idle_timeout_secs);

                    map.retain(|(client_addr, _orig_dst), session| {
                        let last = session.last_activity.try_lock();
                        match last {
                            Ok(guard) => {
                                if guard.elapsed() >= idle_timeout {
                                    tracing::debug!(
                                        %client_addr,
                                        "Idle timeout - removing client session"
                                    );
                                    session.tunnel.close(0, b"idle");
                                    false
                                } else {
                                    true
                                }
                            }
                            Err(_) => true,
                        }
                    });
                }
            }
        }
    }
}

#[async_trait]
impl StatusProvider for DatagramIngressFlow {
    async fn query_status(&self, _path: &[&str]) -> Result<StatusQueryResult, TngError> {
        Err(TngError::StatusPathNotFound)
    }
}
