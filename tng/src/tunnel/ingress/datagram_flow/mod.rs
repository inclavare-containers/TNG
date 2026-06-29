use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use indexmap::IndexMap;
use tokio::net::UdpSocket;
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
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::rustls::config::TlsConfigGenerator;

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

/// Trait for ingress datagram listeners.
///
/// Implemented by protocol-specific ingress configurations (e.g. mapping_udp).
/// The Flow manages the UDP socket, session map, idle cleanup, and TLS config;
/// this trait only provides the ability to create QUIC tunnels to egress.
#[async_trait]
pub(super) trait IngressDatagramTrait: Send + Sync {
    /// Return the metric attributes of this ingress.
    fn metric_attributes(&self) -> IndexMap<String, String>;

    /// The UDP listen address for this ingress.
    fn listen_endpoint(&self) -> (String, u16);

    /// The egress endpoint this ingress forwards to.
    fn egress_endpoint(&self) -> TngEndpoint;

    /// The idle timeout in seconds for client sessions.
    fn idle_timeout_secs(&self) -> u64;

    /// Create a new QUIC tunnel to the egress endpoint for the given client.
    /// The Flow provides the TLS config generator so RA context is managed centrally.
    async fn create_tunnel(
        &self,
        client_addr: SocketAddr,
        tls_gen: &TlsConfigGenerator,
        runtime: TokioRuntime,
    ) -> Result<Arc<dyn IngressDatagramTunnel>>;
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
    ingress: Box<dyn IngressDatagramTrait>,
    tls_gen: TlsConfigGenerator,
    metrics: ServiceMetrics,
    runtime: TokioRuntime,
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

        Ok(Self {
            ingress: Box::new(ingress),
            tls_gen,
            metrics,
            runtime,
        })
    }
}

#[async_trait::async_trait]
impl RegistedService for DatagramIngressFlow {
    async fn serve(&self, ready: Sender<()>) -> Result<()> {
        let (listen_addr, listen_port) = self.ingress.listen_endpoint();
        let listen_str = format!("{}:{}", listen_addr, listen_port);
        let udp_socket = Arc::new(UdpSocket::bind(&listen_str).await?);
        let listener_addr = udp_socket.local_addr()?;
        tracing::info!("UDP mapping ingress listening on {}", listen_str);

        ready.send(()).await?;

        let idle_timeout_secs = self.ingress.idle_timeout_secs();
        let egress_ep = self.ingress.egress_endpoint();
        let check_interval = Duration::from_secs(5);

        // client_addr -> ClientSession
        let client_map: Arc<Mutex<HashMap<SocketAddr, ClientSession>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                // Direction A: Client -> QUIC
                recv_result = udp_socket.recv_from(&mut buf) => {
                    let (n, client_src) = recv_result?;
                    let payload = Bytes::copy_from_slice(&buf[..n]);

                    let mut map = client_map.lock().await;
                    let session = match map.get(&client_src) {
                        Some(s) => s,
                        None => {
                            tracing::info!(
                                %client_src,
                                egress = %egress_ep,
                                "Creating QUIC connection for new client"
                            );

                            let tunnel = self.ingress
                                .create_tunnel(client_src, &self.tls_gen, self.runtime.clone())
                                .await?;

                            let access_accepted = AccessAccepted::new_ingress(
                                client_src,
                                listener_addr,
                                IngressAccessMode::MappingUdp,
                            );
                            let access_routed = access_accepted.into_routed(
                                &egress_ep,
                                true, // to_trusted_tunnel
                            );
                            let access_established =
                                access_routed.into_established(None, false);

                            let last_activity = Arc::new(Mutex::new(Instant::now()));

                            let metrics = self.metrics.clone();
                            let active_cx = metrics.new_cx();

                            // Spawn QUIC -> Client forwarding task
                            let udp_socket_clone = udp_socket.clone();
                            let last_activity_clone = last_activity.clone();
                            let idle_timeout = Duration::from_secs(idle_timeout_secs);
                            let client_src_for_task = client_src;
                            let runtime_clone = self.runtime.clone();
                            let tunnel_clone = tunnel.clone();

                            runtime_clone.spawn_supervised_task(async move {
                                let mut success = false;
                                loop {
                                    tokio::select! {
                                        datagram_result = tunnel_clone.read_datagram() => {
                                            match datagram_result {
                                                Ok(datagram) => {
                                                    if let Err(e) = udp_socket_clone
                                                        .send_to(&datagram, client_src_for_task)
                                                        .await
                                                    {
                                                        tracing::warn!(
                                                            %client_src_for_task,
                                                            error = %e,
                                                            "Failed to send datagram to client"
                                                        );
                                                    } else {
                                                        *last_activity_clone.lock().await = Instant::now();
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

                            map.entry(client_src).or_insert(ClientSession {
                                tunnel,
                                last_activity,
                                access_established,
                            })
                        }
                    };

                    // Update activity and forward
                    *session.last_activity.lock().await = Instant::now();
                    if let Err(e) = session.tunnel.send_datagram(payload) {
                        tracing::warn!(
                            %client_src,
                            error = %e,
                            "Failed to send datagram to QUIC"
                        );
                    }
                }
                // Periodic cleanup of idle sessions
                _ = sleep(check_interval) => {
                    let mut map = client_map.lock().await;
                    let idle_timeout = Duration::from_secs(idle_timeout_secs);

                    map.retain(|addr, session| {
                        let last = session.last_activity.try_lock();
                        match last {
                            Ok(guard) => {
                                if guard.elapsed() >= idle_timeout {
                                    tracing::debug!(
                                        %addr,
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
