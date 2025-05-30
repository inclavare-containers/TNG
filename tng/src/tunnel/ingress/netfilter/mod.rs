use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use opentelemetry::metrics::MeterProvider;
use socket2::SockRef;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tokio_graceful::ShutdownGuard;

use crate::config::ingress::CommonArgs;
use crate::config::ingress::IngressNetfilterArgs;
use crate::config::Endpoint;
use crate::observability::trace::shutdown_guard_ext::ShutdownGuardExt;
use crate::service::RegistedService;
use crate::tunnel::access_log::AccessLog;
use crate::tunnel::ingress::core::stream_manager::trusted::TrustedStreamManager;
use crate::tunnel::ingress::core::stream_manager::StreamManager;
use crate::tunnel::ingress::core::TngEndpoint;
use crate::tunnel::service_metrics::ServiceMetrics;
use crate::tunnel::utils::iptables::IptablesExecutor;
use crate::tunnel::utils::socket::SetListenerSockOpts;
use crate::tunnel::utils::socket::TCP_CONNECT_SO_MARK_DEFAULT;

mod iptables;

pub struct NetfilterIngress {
    id: usize,
    capture_dst: Vec<Endpoint>,
    capture_cgroup: Vec<String>,
    nocapture_cgroup: Vec<String>,
    listen_port: u16,
    so_mark: u32,
    metrics: ServiceMetrics,
    trusted_stream_manager: Arc<TrustedStreamManager>,
}

impl NetfilterIngress {
    pub async fn new(
        id: usize,
        netfilter_args: &IngressNetfilterArgs,
        common_args: &CommonArgs,
        meter_provider: Arc<dyn MeterProvider + Send + Sync>,
    ) -> Result<Self> {
        let listen_port = match netfilter_args.listen_port {
            Some(p) => p,
            None => portpicker::pick_unused_port().context("Failed to pick a free port")?,
        };

        if netfilter_args.capture_dst.is_empty() && netfilter_args.capture_cgroup.is_empty() {
            bail!("At least one of capture_dst, capture_cgroup must be set and not empty");
        }

        // ingress_type=netfilter,ingress_id={id},ingress_listen_port={listen_port}
        let metrics = ServiceMetrics::new(
            meter_provider,
            [
                ("ingress_type".to_owned(), "netfilter".to_owned()),
                ("ingress_id".to_owned(), id.to_string()),
                ("ingress_listen_port".to_owned(), listen_port.to_string()),
            ],
        );

        let so_mark = TCP_CONNECT_SO_MARK_DEFAULT;

        let trusted_stream_manager =
            Arc::new(TrustedStreamManager::new(common_args, so_mark).await?);

        Ok(Self {
            id,
            capture_dst: netfilter_args.capture_dst.clone(),
            capture_cgroup: netfilter_args.capture_cgroup.clone(),
            nocapture_cgroup: netfilter_args.nocapture_cgroup.clone(),
            listen_port,
            so_mark,
            metrics,
            trusted_stream_manager,
        })
    }
}

#[async_trait]
impl RegistedService for NetfilterIngress {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()> {
        self.trusted_stream_manager
            .prepare(shutdown_guard.clone())
            .await?;

        let listen_addr = format!("127.0.0.1:{}", self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        // Setup iptables
        let _iptables_guard = IptablesExecutor::setup(self).await?;

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;
        listener.set_listener_tproxy_sock_opts()?;

        ready.send(()).await?;

        loop {
            async {
                let (downstream, peer_addr) = listener.accept().await?;

                let socket_ref = SockRef::from(&downstream);
                // Note here since we are using TPROXY, the original destination is recorded in the local address.
                let orig_dst = socket_ref
                    .local_addr()
                    .context("failed to get original destination")?
                    .as_socket()
                    .context("should be a ip address")?;

                // Check if the original destination is the same as the listener port to prevert from the recursion.
                let listen_addr = listener.local_addr()?;
                if listen_addr.port() == orig_dst.port() && orig_dst.ip().is_loopback() {
                    bail!("The original destination is the same as the listener port, recursion is detected")
                }

                let orig_dst = TngEndpoint::new(orig_dst.ip().to_string(), orig_dst.port());

                let trusted_stream_manager = self.trusted_stream_manager.clone();

                self.metrics.cx_total.add(1);
                let metrics = self.metrics.clone();

                let task = shutdown_guard.spawn_supervised_task_fn_with_span(
                    tracing::info_span!("serve", client=?peer_addr),
                    move |shutdown_guard| async move {
                        let fut = async move {
                            tracing::trace!("Start serving new connection from client");

                            // Forward via trusted tunnel
                            match trusted_stream_manager
                                .forward_stream(&orig_dst, downstream, shutdown_guard, metrics)
                                .await
                            {
                                Ok((forward_stream_task, attestation_result)) => {
                                    // Print access log
                                    let access_log = AccessLog::Ingress {
                                        downstream: peer_addr,
                                        upstream: orig_dst.clone(),
                                        to_trusted_tunnel: true,
                                        peer_attested: attestation_result,
                                    };
                                    tracing::info!(?access_log);

                                    if let Err(e) = forward_stream_task.await {
                                        let error = format!("{e:#}");
                                        tracing::error!(
                                            %orig_dst,
                                            error,
                                            "Failed during forwarding to upstream via trusted tunnel"
                                        );
                                    }
                                }
                                Err(e) => {
                                    let error = format!("{e:#}");
                                    tracing::error!(
                                        %orig_dst,
                                        error,
                                        "Failed to connect to upstream via trusted tunnel"
                                    );
                                }
                            };

                            Ok::<(), anyhow::Error>(())
                        };

                        if let Err(e) = fut.await {
                            tracing::error!(error=?e, "Failed to forward stream");
                        }
                    },
                );

                // Spawn a task to trace the connection status.
                shutdown_guard.spawn_supervised_task_current_span({
                    let cx_active = self.metrics.cx_active.clone();
                    let cx_failed = self.metrics.cx_failed.clone();
                    async move {
                        cx_active.add(1);
                        if !matches!(task.await, Ok(())) {
                            cx_failed.add(1);
                        }
                        cx_active.add(-1);
                    }
                });
                Ok::<_, anyhow::Error>(())
            }.await.unwrap_or_else(|e| {
                tracing::error!(error=?e, "Failed to serve incoming connection from client");
            })
        }
    }
}
