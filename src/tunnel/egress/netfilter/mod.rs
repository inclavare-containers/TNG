use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use socket2::{Domain, SockRef, Socket, Type};
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::mpsc::{self, Sender},
};
use tokio_graceful::ShutdownGuard;

use crate::{
    config::{
        egress::{CommonArgs, EgressNetfilterArgs},
        Endpoint,
    },
    observability::{metric::stream::StreamWithCounter, trace::ShutdownGuardExt},
    service::RegistedService,
    tunnel::{
        access_log::AccessLog,
        egress::core::stream_manager::{trusted::TrustedStreamManager, StreamManager},
        service_metrics::ServiceMetrics,
        utils::{
            self,
            iptables::IptablesExecutor,
            socket::{SetListenerSockOpts, TCP_CONNECT_SO_MARK_DEFAULT},
        },
    },
};

mod iptables;

pub struct NetfilterEgress {
    id: usize,
    capture_dst: Endpoint,
    capture_local_traffic: bool,
    listen_port: u16,
    so_mark: u32,
    metrics: ServiceMetrics,
    trusted_stream_manager: Arc<TrustedStreamManager>,
}

impl NetfilterEgress {
    pub async fn new(
        id: usize,
        netfilter_args: &EgressNetfilterArgs,
        common_args: &CommonArgs,
    ) -> Result<Self> {
        let listen_port = match netfilter_args.listen_port {
            Some(p) => p,
            None => portpicker::pick_unused_port().context("Failed to pick a free port")?,
        };

        let so_mark = netfilter_args
            .so_mark
            .unwrap_or(TCP_CONNECT_SO_MARK_DEFAULT);

        // egress_type=netfilter,egress_id={id},egress_listen_port={listen_port}
        let metrics = ServiceMetrics::new([
            ("egress_type".to_owned(), "netfilter".to_owned()),
            ("egress_id".to_owned(), id.to_string()),
            ("egress_listen_port".to_owned(), listen_port.to_string()),
        ]);

        let trusted_stream_manager = Arc::new(TrustedStreamManager::new(&common_args).await?);

        Ok(Self {
            id,
            capture_dst: netfilter_args.capture_dst.clone(),
            capture_local_traffic: netfilter_args.capture_local_traffic,
            listen_port,
            so_mark,
            metrics,
            trusted_stream_manager,
        })
    }
}

#[async_trait]
impl RegistedService for NetfilterEgress {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()> {
        self.trusted_stream_manager
            .prepare(shutdown_guard.clone())
            .await?;

        let listen_addr = format!("127.0.0.1:{}", self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        // Setup iptables
        let _iptables_guard = IptablesExecutor::setup(self)?;

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;

        ready.send(()).await?;

        let so_mark = self.so_mark;

        loop {
            let (downstream, _) = tokio::select! {
                res = listener.accept() => res?,
                _ = shutdown_guard.cancelled() => {
                    tracing::debug!("Shutdown signal received, stop accepting new connections");
                    break;
                }
            };
            let peer_addr = downstream.peer_addr()?;

            let socket_ref = SockRef::from(&downstream);
            let orig_dst = socket_ref
                .original_dst()
                .context("failed to get original destination")?
                .as_socket()
                .context("should be a ip address")?;

            let trusted_stream_manager = self.trusted_stream_manager.clone();

            let cx_total = self.metrics.cx_total.clone();
            let cx_active = self.metrics.cx_active.clone();
            let cx_failed = self.metrics.cx_failed.clone();
            let tx_bytes_total = self.metrics.tx_bytes_total.clone();
            let rx_bytes_total = self.metrics.rx_bytes_total.clone();

            shutdown_guard.spawn_task_fn_with_span(
                tracing::info_span!("serve", client=?peer_addr),
                move |shutdown_guard| {
                    async move {
                        tracing::debug!("Start serving new connection from client");

                        let (sender, mut receiver) = mpsc::unbounded_channel();

                        shutdown_guard.spawn_task_fn_current_span(move |shutdown_guard| {
                            async move {
                                while let Some((downstream, attestation_result)) =
                                    receiver.recv().await
                                {
                                    cx_total.add(1);

                                    let tx_bytes_total = tx_bytes_total.clone();
                                    let rx_bytes_total = rx_bytes_total.clone();

                                    // Spawn a task to handle the connection
                                    let task = shutdown_guard.spawn_task_current_span({
                                        async move {
                                            let fut = async {
                                                // Print access log
                                                let access_log = AccessLog {
                                                    downstream: peer_addr,
                                                    upstream: orig_dst,
                                                    to_trusted_tunnel: true, // TODO: handle allow_non_tng_traffic
                                                    peer_attested: attestation_result,
                                                };
                                                tracing::info!(?access_log);

                                                let upstream = async {
                                                    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
                                                    socket.set_nonblocking(true)?;
                                                    socket.set_mark(so_mark)?; // Prevent from been redirected by iptables
                                                    let socket = TcpSocket::from_std_stream(socket.into());
                                                    socket.connect(orig_dst).await
                                                }.await.context("Failed to connect to upstream")?;

                                                let downstream = StreamWithCounter {
                                                    inner: TokioIo::new(downstream),
                                                    tx_bytes_total,
                                                    rx_bytes_total,
                                                };

                                                utils::forward_stream(upstream, downstream).await
                                            };

                                            if let Err(e) = fut.await {
                                                tracing::error!(error=?e, "Failed to forward stream");
                                            }
                                        }
                                    });

                                    // Spawn a task to trace the connection status.
                                    shutdown_guard.spawn_task_current_span({
                                        let cx_active = cx_active.clone();
                                        let cx_failed = cx_failed.clone();
                                        async move {
                                            cx_active.add(1);
                                            if !matches!(task.await, Ok(())) {
                                                cx_failed.add(1);
                                            }
                                            cx_active.add(-1);
                                        }
                                    });
                                }
                            }
                        });

                        // Consume streams come from downstream
                        match trusted_stream_manager
                            .consume_stream(downstream, sender, shutdown_guard)
                            .await
                        {
                            Ok(()) => {}
                            Err(e) => {
                                tracing::error!(error=?e, "Failed to consume stream from client");
                            }
                        }
                    }
                },
            );
        }

        Ok(())
    }
}
