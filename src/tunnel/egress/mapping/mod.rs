use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use opentelemetry::metrics::MeterProvider;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Sender},
};
use tokio_graceful::ShutdownGuard;

use crate::{
    config::egress::{CommonArgs, EgressMappingArgs},
    observability::{
        metric::stream::StreamWithCounter, trace::shutdown_guard_ext::ShutdownGuardExt as _,
    },
    service::RegistedService,
    tunnel::{
        access_log::AccessLog,
        egress::core::stream_manager::{trusted::TrustedStreamManager, StreamManager},
        ingress::core::TngEndpoint,
        service_metrics::ServiceMetrics,
        utils::{self, socket::SetListenerSockOpts},
    },
};

pub struct MappingEgress {
    listen_addr: String,
    listen_port: u16,
    upstream_addr: String,
    upstream_port: u16,
    metrics: ServiceMetrics,
    trusted_stream_manager: Arc<TrustedStreamManager>,
}

impl MappingEgress {
    pub async fn new(
        id: usize,
        mapping_args: &EgressMappingArgs,
        common_args: &CommonArgs,
        meter_provider: Arc<dyn MeterProvider + Send + Sync>,
    ) -> Result<Self> {
        let listen_addr = mapping_args
            .r#in
            .host
            .as_deref()
            .unwrap_or("0.0.0.0")
            .to_owned();
        let listen_port = mapping_args.r#in.port;

        let upstream_addr = mapping_args
            .out
            .host
            .as_deref()
            .context("'host' of 'out' field must be set")?
            .to_owned();
        let upstream_port = mapping_args.out.port;

        // egress_type=netfilter,egress_id={id},egress_in={in.host}:{in.port},egress_out={out.host}:{out.port}
        let metrics = ServiceMetrics::new(
            meter_provider,
            [
                ("egress_type".to_owned(), "mapping".to_owned()),
                ("egress_id".to_owned(), id.to_string()),
                (
                    "egress_in".to_owned(),
                    format!("{}:{}", listen_addr, listen_port),
                ),
                (
                    "egress_out".to_owned(),
                    format!("{}:{}", upstream_addr, upstream_port),
                ),
            ],
        );

        let trusted_stream_manager = Arc::new(TrustedStreamManager::new(&common_args).await?);

        Ok(Self {
            listen_addr: mapping_args
                .r#in
                .host
                .as_deref()
                .unwrap_or("0.0.0.0")
                .to_owned(),
            listen_port: mapping_args.r#in.port,

            upstream_addr: mapping_args
                .out
                .host
                .as_deref()
                .context("'host' of 'out' field must be set")?
                .to_owned(),
            upstream_port: mapping_args.out.port,
            metrics,
            trusted_stream_manager,
        })
    }
}

#[async_trait]
impl RegistedService for MappingEgress {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()> {
        self.trusted_stream_manager
            .prepare(shutdown_guard.clone())
            .await?;

        let listen_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;

        ready.send(()).await?;

        loop {
            let (downstream, _) = tokio::select! {
                res = listener.accept() => res?,
                _ = shutdown_guard.cancelled() => {
                    tracing::debug!("Shutdown signal received, stop accepting new connections");
                    break;
                }
            };
            let peer_addr = downstream.peer_addr()?;
            let upstream_addr = self.upstream_addr.clone();
            let upstream_port = self.upstream_port;

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
                                        let upstream_addr = upstream_addr.clone();

                                        async move {
                                            let fut = async {
                                                // Print access log
                                                let access_log = AccessLog {
                                                    downstream: peer_addr,
                                                    upstream: TngEndpoint::new(
                                                        &upstream_addr,
                                                        upstream_port,
                                                    ),
                                                    to_trusted_tunnel: true, // TODO: handle allow_non_tng_traffic
                                                    peer_attested: attestation_result,
                                                };
                                                tracing::info!(?access_log);

                                                let upstream = TcpStream::connect((
                                                    upstream_addr.as_str(),
                                                    upstream_port,
                                                ))
                                                .await
                                                .context("Failed to connect to upstream")?;

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
