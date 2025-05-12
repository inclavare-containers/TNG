use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use opentelemetry::metrics::MeterProvider;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tokio_graceful::ShutdownGuard;

use crate::config::{ingress::CommonArgs, ingress::IngressMappingArgs};
use crate::observability::trace::shutdown_guard_ext::ShutdownGuardExt;
use crate::service::RegistedService;
use crate::tunnel::access_log::AccessLog;
use crate::tunnel::ingress::core::stream_manager::trusted::TrustedStreamManager;
use crate::tunnel::ingress::core::stream_manager::StreamManager;
use crate::tunnel::ingress::core::TngEndpoint;
use crate::tunnel::service_metrics::ServiceMetrics;
use crate::tunnel::utils::socket::{SetListenerSockOpts, TCP_CONNECT_SO_MARK_DEFAULT};

pub struct MappingIngress {
    listen_addr: String,
    listen_port: u16,
    upstream_addr: String,
    upstream_port: u16,
    metrics: ServiceMetrics,
    trusted_stream_manager: Arc<TrustedStreamManager>,
}

impl MappingIngress {
    pub async fn new(
        id: usize,
        mapping_args: &IngressMappingArgs,
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

        // ingress_type=mapping,ingress_id={id},ingress_in={in.host}:{in.port},ingress_out={out.host}:{out.port}
        let metrics = ServiceMetrics::new(
            meter_provider,
            [
                ("ingress_type".to_owned(), "mapping".to_owned()),
                ("ingress_id".to_owned(), id.to_string()),
                (
                    "ingress_in".to_owned(),
                    format!("{}:{}", listen_addr, listen_port),
                ),
                (
                    "ingress_out".to_owned(),
                    format!("{}:{}", upstream_addr, upstream_port),
                ),
            ],
        );

        let trusted_stream_manager =
            Arc::new(TrustedStreamManager::new(&common_args, TCP_CONNECT_SO_MARK_DEFAULT).await?);

        Ok(Self {
            listen_addr,
            listen_port,
            upstream_addr,
            upstream_port,
            metrics,
            trusted_stream_manager,
        })
    }
}

#[async_trait]
impl RegistedService for MappingIngress {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()> {
        self.trusted_stream_manager
            .prepare(shutdown_guard.clone())
            .await?;

        let listen_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await?;
        listener.set_listener_common_sock_opts()?;

        ready.send(()).await?;

        let loop_task = async {
            loop {
                async {
                        let (downstream, peer_addr) = listener.accept().await?;

                        let dst = TngEndpoint::new(self.upstream_addr.clone(), self.upstream_port);

                        let trusted_stream_manager = self.trusted_stream_manager.clone();

                        self.metrics.cx_total.add(1);
                        let metrics = self.metrics.clone();

                        let task = shutdown_guard.spawn_task_fn_with_span(
                            tracing::info_span!("serve", client=?peer_addr),
                            move |shutdown_guard| async move {
                                let fut = async move {
                                    tracing::trace!("Start serving new connection from client");

                                    // Forward via trusted tunnel
                                    match trusted_stream_manager
                                        .forward_stream(&dst, downstream, shutdown_guard, metrics)
                                        .await
                                    {
                                        Ok((forward_stream_task, attestation_result)) => {
                                            // Print access log
                                            let access_log = AccessLog::Ingress {
                                                downstream: peer_addr,
                                                upstream: dst.clone(),
                                                to_trusted_tunnel: true,
                                                peer_attested: attestation_result,
                                            };
                                            tracing::info!(?access_log);

                                            if let Err(e) = forward_stream_task.await {
                                                let error = format!("{e:#}");
                                                tracing::error!(
                                                    %dst,
                                                    error,
                                                    "Failed during forwarding to upstream via trusted tunnel"
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            let error = format!("{e:#}");
                                            tracing::error!(
                                                %dst,
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
                        shutdown_guard.spawn_task_current_span({
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
        };

        tokio::select! {
            () = loop_task => {/* should not be here */},
            _ = shutdown_guard.cancelled() => {
                tracing::debug!("Shutdown signal received, stop accepting new connections");
            }
        };

        Ok(())
    }
}
