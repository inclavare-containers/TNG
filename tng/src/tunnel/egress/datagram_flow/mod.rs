use std::net::SocketAddr;
use std::sync::Arc;
use web_time_compat::{Duration, Instant, InstantExt};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use indexmap::IndexMap;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::config::egress::CommonArgs as EgressCommonArgs;
use crate::error::TngError;
use crate::service::RegistedService;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::tunnel::access_log::AccessAccepted;
use crate::tunnel::endpoint::{EndpointAddr, TngEndpoint};
use crate::tunnel::service_metrics::ServiceMetrics;
use crate::tunnel::service_metrics::ServiceMetricsCreator;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::rustls::config::TlsConfigGenerator;
use crate::tunnel::utils::socket::resolve_ipv4_addr;

/// Trait for a single QUIC connection on the egress side.
///
/// Wraps the protocol-specific connection (e.g. quinn::Connection)
/// and provides datagram I/O operations.
#[async_trait]
pub(super) trait EgressDatagramConnection: Send + Sync {
    /// The remote address of the QUIC connection.
    fn remote_address(&self) -> SocketAddr;

    /// Read a datagram from the QUIC connection.
    async fn read_datagram(&self) -> Result<Bytes>;

    /// Send a datagram through the QUIC connection.
    fn send_datagram(&self, payload: Bytes) -> Result<()>;

    /// Close the QUIC connection.
    fn close(&self, error_code: u32, reason: &[u8]);
}

/// Trait for the QUIC listener on the egress side.
///
/// Accepts incoming QUIC connections and yields `AcceptedConnection` objects.
#[async_trait]
pub(super) trait EgressDatagramListener: Send + Sync {
    /// Get the local address the listener is bound to.
    fn local_addr(&self) -> Result<SocketAddr>;

    /// Accept the next QUIC connection, returning the connection paired with
    /// its original destination address (from IP_ORIGDSTADDR for netfilter_udp,
    /// or the fixed backend endpoint for mapping_udp).
    async fn accept(&self) -> Result<AcceptedConnection>;
}

/// An accepted QUIC connection paired with its backend address.
pub(super) struct AcceptedConnection {
    pub connection: Arc<dyn EgressDatagramConnection>,
    pub backend_addr: TngEndpoint,
}

/// Trait for egress datagram listeners.
///
/// Implemented by protocol-specific egress configurations (e.g. mapping_udp).
/// The Flow manages the QUIC accept loop, per-connection forwarding, idle timeout, and TLS config;
/// this trait provides the listener binding and backend endpoint info.
#[async_trait]
pub(super) trait EgressDatagramTrait: Send + Sync {
    /// Return the metric attributes of this egress.
    fn metric_attributes(&self) -> IndexMap<String, String>;

    /// Return the access log mode for this egress.
    fn access_mode(&self) -> crate::tunnel::access_log::EgressAccessMode;

    /// The idle timeout in seconds for connections.
    fn idle_timeout_secs(&self) -> u64;

    /// The SO_MARK value to set on backend UDP sockets (to bypass TPROXY rules).
    /// Returns `None` if no mark is needed (e.g., no TPROXY in use).
    fn so_mark(&self) -> Option<u32> {
        None
    }

    /// Bind the QUIC listener. The Flow provides the TLS config generator
    /// so RA context is managed centrally (same pattern as ingress).
    /// `max_datagram_size` is the top-level `quic.max_datagram_size` (the Flow
    /// owns it so RA context is managed centrally).
    async fn bind_listener(
        &self,
        tls_gen: &TlsConfigGenerator,
        max_datagram_size: Option<usize>,
    ) -> Result<Arc<dyn EgressDatagramListener>>;
}

pub struct DatagramEgressFlow {
    egress: Box<dyn EgressDatagramTrait>,
    tls_gen: TlsConfigGenerator,
    metrics: ServiceMetrics,
    runtime: TokioRuntime,
    /// Top-level `quic.max_datagram_size`, captured in `new()` from the common
    /// args and passed to `bind_listener`.
    max_datagram_size: Option<usize>,
}

impl DatagramEgressFlow {
    #[allow(private_bounds)]
    pub async fn new(
        egress: impl EgressDatagramTrait + 'static,
        common_args: &EgressCommonArgs,
        service_metrics_creator: &ServiceMetricsCreator,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let metric_attributes = egress.metric_attributes();
        let metrics = service_metrics_creator.new_service_metrics(metric_attributes);

        let ra_args = common_args.ra_args.clone().into_checked()?;
        let ra_context =
            Arc::new(crate::tunnel::ra_context::RaContext::from_ra_args(&ra_args).await?);
        let tls_gen = TlsConfigGenerator::new(ra_context, runtime.clone()).await?;

        let max_datagram_size = common_args.quic.as_ref().and_then(|q| q.max_datagram_size);

        Ok(Self {
            egress: Box::new(egress),
            tls_gen,
            metrics,
            runtime,
            max_datagram_size,
        })
    }
}

#[async_trait::async_trait]
impl RegistedService for DatagramEgressFlow {
    async fn serve(&self, ready: Sender<()>) -> Result<()> {
        let listener = self
            .egress
            .bind_listener(&self.tls_gen, self.max_datagram_size)
            .await?;
        let actual_addr = listener.local_addr()?;
        let access_mode = self.egress.access_mode();
        tracing::info!(
            "UDP {} egress QUIC listener on {}",
            access_mode,
            actual_addr
        );

        ready.send(()).await?;

        let idle_timeout_secs = self.egress.idle_timeout_secs();
        let listener_addr = actual_addr;

        loop {
            let AcceptedConnection {
                connection,
                backend_addr: backend_ep,
            } = listener.accept().await?;
            let remote = connection.remote_address();

            tracing::info!(
                %remote,
                "Accepted QUIC connection from ingress"
            );

            let access_accepted = AccessAccepted::new_egress(remote, listener_addr, access_mode);
            let access_routed = access_accepted.into_routed(
                &backend_ep,
                true, // from_trusted_tunnel
            );
            let access_established = access_routed.into_established(None, false);

            // Spawn per-connection forwarding task — access_established logs on drop
            // when this task ends (connection close or error).
            let metrics = self.metrics.clone();
            let active_cx = metrics.new_cx();
            let runtime_spawn = self.runtime.clone();
            let runtime_for_task = self.runtime.clone();
            let idle_timeout = idle_timeout_secs;
            let connection_clone = connection.clone();
            let so_mark = self.egress.so_mark();

            runtime_spawn.spawn_supervised_task(async move {
                if let Err(e) = Self::forward_connection(
                    connection_clone,
                    &backend_ep,
                    idle_timeout,
                    &runtime_for_task,
                    so_mark,
                )
                .await
                {
                    tracing::error!(error = %e, "Per-connection forwarding failed");
                } else {
                    active_cx.mark_finished_successfully();
                }
                drop(access_established);
            });
        }
    }
}

impl DatagramEgressFlow {
    /// Per-connection bidirectional forwarding: QUIC <-> Backend UDP.
    async fn forward_connection(
        connection: Arc<dyn EgressDatagramConnection>,
        backend_ep: &TngEndpoint,
        idle_timeout_secs: u64,
        runtime: &TokioRuntime,
        so_mark: Option<u32>,
    ) -> Result<()> {
        // SO_MARK is Linux-only; `so_mark` is only `Some` for netfilter_udp
        // egress (Linux-only). On other platforms it is always `None`, so
        // consume it to avoid an unused-variable warning there.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        let _ = so_mark;

        let backend_addr = match backend_ep.addr() {
            EndpointAddr::Ipv4(ip) => SocketAddr::new(std::net::IpAddr::V4(*ip), backend_ep.port()),
            EndpointAddr::Domain(d) => resolve_ipv4_addr(d, backend_ep.port())
                .await
                .with_context(|| format!("resolve egress backend domain {d}"))?,
        };

        // Create a UDP socket with socket2 crate so that we can set the SO_MARK option
        let std_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        std_socket.set_nonblocking(true)?;
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(mark) = so_mark {
            std_socket.set_mark(mark)?;
        }
        const ANY: SocketAddr =
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        std_socket.bind(&ANY.into())?;
        let backend_socket = Arc::new(UdpSocket::from_std(std_socket.into())?);
        backend_socket.connect(backend_addr).await?;

        let idle_timeout = Duration::from_secs(idle_timeout_secs);
        let last_activity = Arc::new(Mutex::new(Instant::get()));
        // Idle-timeout probe cadence: when neither direction has moved for this
        // long, the `sleep` arm in each forward task fires and checks whether
        // the session has been idle past `idle_timeout`. 5s is coarse but fine
        // — the timeout itself is ~30s.
        let check_interval = Duration::from_secs(5);

        let conn_clone = connection.clone();
        let last_act_a = last_activity.clone();
        let timeout_a = idle_timeout;
        let backend_socket_a = backend_socket.clone();
        let runtime_a = runtime.clone();

        // Task A: QUIC -> Backend
        let task_a = runtime_a.spawn_supervised_task(async move {
            loop {
                tokio::select! {
                    datagram_result = conn_clone.read_datagram() => {
                        match datagram_result {
                            Ok(payload) => {
                                tracing::debug!(len = payload.len(), "egress A: forward QUIC->backend");
                                if let Err(e) = backend_socket_a.send(&payload).await {
                                    tracing::warn!(error = %e, "egress A: backend_socket send failed");
                                }
                                *last_act_a.lock().await = Instant::get();
                            }
                            Err(e) => { tracing::debug!(error=%e, "egress A: read_datagram ended"); break; }
                        }
                    }
                    _ = sleep(check_interval) => {
                        // Idle-timeout probe: if neither direction has moved
                        // for `timeout_a`, tear down the connection.
                        let last = *last_act_a.lock().await;
                        if last.elapsed() >= timeout_a {
                            break;
                        }
                    }
                }
            }
        });

        let last_act_b = last_activity.clone();
        let timeout_b = idle_timeout;

        // Task B: Backend -> QUIC
        let mut recv_buf = vec![0u8; 65535];
        let connection_send = connection.clone();
        let backend_socket_b = backend_socket.clone();
        let runtime_b = runtime.clone();

        let task_b = runtime_b.spawn_supervised_task(async move {
            loop {
                tokio::select! {
                    recv_result = backend_socket_b.recv(&mut recv_buf) => {
                        match recv_result {
                            Ok(n) => {
                                tracing::debug!(len = n, "egress B: recv backend->QUIC");
                                let payload = Bytes::copy_from_slice(&recv_buf[..n]);
                                if let Err(e) = connection_send.send_datagram(payload) {
                                    tracing::warn!(error = %e, "Failed to send datagram to QUIC");
                                    break;
                                }
                                *last_act_b.lock().await = Instant::get();
                            }
                            Err(e) => { tracing::debug!(error=%e, "egress B: recv ended"); break; }
                        }
                    }
                    _ = sleep(check_interval) => {
                        // Idle-timeout probe (same as task A).
                        let last = *last_act_b.lock().await;
                        if last.elapsed() >= timeout_b {
                            break;
                        }
                    }
                }
            }
        });

        // Wait for either task to finish (idle timeout or error)
        let _ = tokio::join!(task_a, task_b);

        // Clean up
        connection.close(0u32, b"done");

        Ok(())
    }
}

#[async_trait]
impl StatusProvider for DatagramEgressFlow {
    async fn query_status(&self, _path: &[&str]) -> Result<StatusQueryResult, TngError> {
        Err(TngError::StatusPathNotFound)
    }
}
