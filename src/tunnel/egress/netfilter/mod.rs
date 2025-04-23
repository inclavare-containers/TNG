use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use socket2::SockRef;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Sender},
};
use tokio_graceful::ShutdownGuard;
use tracing::Instrument;

use crate::{
    config::egress::{CommonArgs, EgressNetfilterArgs},
    executor::iptables::IpTablesAction,
    observability::metric::stream::StreamWithCounter,
    tunnel::{
        access_log::AccessLog,
        egress::core::stream_manager::{trusted::TrustedStreamManager, StreamManager},
        service_metrics::ServiceMetrics,
        utils, RegistedService,
    },
};

const NETFILTER_LISTEN_PORT_BEGIN_DEFAULT: u16 = 40000;
const NETFILTER_SO_MARK_DEFAULT: u32 = 565;

pub struct NetfilterEgress {
    listen_port: u16,
    so_mark: u32,
    common_args: CommonArgs,
    metrics: ServiceMetrics,
}

impl NetfilterEgress {
    pub fn new(
        id: usize,
        netfilter_args: &EgressNetfilterArgs,
        common_args: &CommonArgs,
        iptables_actions: &mut Vec<IpTablesAction>,
    ) -> Result<Self> {
        let listen_port = netfilter_args
            .listen_port
            .unwrap_or(NETFILTER_LISTEN_PORT_BEGIN_DEFAULT + (id as u16));
        let so_mark = netfilter_args.so_mark.unwrap_or(NETFILTER_SO_MARK_DEFAULT);

        iptables_actions.push(IpTablesAction::Redirect {
            capture_dst: netfilter_args.capture_dst.clone(),
            capture_local_traffic: netfilter_args.capture_local_traffic,
            listen_port,
            so_mark,
        });

        // egress_type=netfilter,egress_id={id},egress_port={port}
        let metrics = ServiceMetrics::new([
            ("egress_type".to_owned(), "netfilter".to_owned()),
            ("egress_id".to_owned(), id.to_string()),
            ("egress_port".to_owned(), listen_port.to_string()),
        ]);

        Ok(Self {
            listen_port,
            so_mark,
            common_args: common_args.clone(),
            metrics,
        })
    }
}

#[async_trait]
impl RegistedService for NetfilterEgress {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()> {
        let trusted_stream_manager =
            Arc::new(TrustedStreamManager::new(&self.common_args, shutdown_guard.clone()).await?);

        let listen_addr = format!("127.0.0.1:{}", self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await?;
        // TODO: ENVOY_LISTENER_SOCKET_OPTIONS
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
                .original_dst()?
                .as_socket()
                .context("should be a tcp socket")?;

            let trusted_stream_manager = trusted_stream_manager.clone();

            let cx_total = self.metrics.cx_total.clone();
            let cx_active = self.metrics.cx_active.clone();
            let cx_failed = self.metrics.cx_failed.clone();
            let tx_bytes_total = self.metrics.tx_bytes_total.clone();
            let rx_bytes_total = self.metrics.rx_bytes_total.clone();

            let span = tracing::info_span!("serve", client=?peer_addr);
            shutdown_guard.spawn_task_fn(move |shutdown_guard| {
                async move {
                    tracing::debug!("Start serving new connection from client");

                    let (sender, mut receiver) = mpsc::unbounded_channel();

                    shutdown_guard.spawn_task_fn(move |shutdown_guard| {
                        async move {
                            while let Some((downstream, attestation_result)) = receiver.recv().await
                            {
                                cx_total.add(1);

                                let tx_bytes_total = tx_bytes_total.clone();
                                let rx_bytes_total = rx_bytes_total.clone();

                                // Spawn a task to handle the connection
                                let task = shutdown_guard.spawn_task({
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

                                            let upstream = TcpStream::connect(orig_dst)
                                                .await
                                                .context("Failed to connect to upstream")?;

                                            // Prevent from been redirected by iptables
                                            let socket_ref = SockRef::from(&upstream);
                                            socket_ref.set_mark(so_mark)?;

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
                                    .in_current_span()
                                });

                                // Spawn a task to trace the connection status.
                                shutdown_guard.spawn_task({
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
                        .in_current_span()
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
                .instrument(span)
            });
        }

        Ok(())
    }
}
