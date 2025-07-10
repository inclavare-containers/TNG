use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use auto_enums::auto_enum;
use futures::Stream;
use futures::StreamExt;
use indexmap::IndexMap;
use tokio::sync::mpsc::Sender;
use tokio_graceful::ShutdownGuard;

use crate::config::egress::CommonArgs;
use crate::observability::trace::shutdown_guard_ext::ShutdownGuardExt as _;
use crate::tunnel::access_log::AccessLog;
use crate::tunnel::egress::core::stream_manager::trusted::StreamType;
use crate::tunnel::service_metrics::ServiceMetrics;
use crate::tunnel::service_metrics::ServiceMetricsCreator;
use crate::tunnel::utils;
use crate::tunnel::utils::socket::tcp_connect_with_so_mark;
use crate::{service::RegistedService, tunnel::stream::CommonStreamTrait};

use super::core::stream_manager::{trusted::TrustedStreamManager, StreamManager};
use crate::tunnel::endpoint::TngEndpoint;

pub struct EgressFlow {
    egress: Box<dyn EgressTrait>,
    trusted_stream_manager: Arc<TrustedStreamManager>,
    metrics: ServiceMetrics,
}

#[async_trait]
pub(super) trait EgressTrait: Sync + Send {
    /// Return the metric attributes of this egress.
    fn metric_attributes(&self) -> IndexMap<String, String>;

    /// Return the so_mark which should be used for creating new tcp stream to upstream.
    fn transport_so_mark(&self) -> Option<u32>;

    /// Accept incomming streams. The returned stream should be a stream of incomming accepted streams.
    /// Note that this method should be called only once.
    async fn accept(&self, shutdown_guard: ShutdownGuard) -> Result<Incomming>;
}

pub(super) type Incomming<'a> = Box<dyn Stream<Item = Result<AcceptedStream>> + Send + 'a>;

pub(super) struct AcceptedStream {
    pub stream: Box<dyn CommonStreamTrait + Send>,
    pub src: SocketAddr,
    pub dst: TngEndpoint,
}

#[async_trait]
impl RegistedService for EgressFlow {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()> {
        // Prepare the stream manager
        self.trusted_stream_manager
            .prepare(shutdown_guard.clone())
            .await?;

        // Accept incomming streams
        let mut incomming = Box::into_pin(self.egress.accept(shutdown_guard.clone()).await?);

        ready.send(()).await?;

        while let Some(next) = incomming.next().await {
            let accepted_stream = match next {
                Ok(next) => next,
                Err(error) => {
                    tracing::error!(?error, "Failed to accept incomming stream");
                    continue;
                }
            };

            let transport_so_mark = self.egress.transport_so_mark();

            self.serve_in_async_task_no_throw_error(
                accepted_stream,
                transport_so_mark,
                shutdown_guard.clone(),
            )
            .await;
        }

        Ok(())
    }
}

impl EgressFlow {
    #[allow(private_bounds)]
    pub async fn new(
        egress: impl EgressTrait + 'static,
        common_args: &CommonArgs,
        service_metrics_creator: &ServiceMetricsCreator,
    ) -> Result<Self> {
        let egress = Box::new(egress);

        let metric_attributes = egress.metric_attributes();
        let metrics = service_metrics_creator.new_service_metrics(metric_attributes);

        let trusted_stream_manager = Arc::new(TrustedStreamManager::new(common_args).await?);

        Ok(Self {
            egress,
            metrics,
            trusted_stream_manager,
        })
    }

    #[auto_enum]
    async fn serve_in_async_task_no_throw_error(
        &self,
        accepted_stream: AcceptedStream,
        transport_so_mark: Option<u32>,
        shutdown_guard: ShutdownGuard,
    ) {
        let AcceptedStream { stream, src, dst } = accepted_stream;

        let trusted_stream_manager = self.trusted_stream_manager.clone();
        let metrics = self.metrics.clone();

        // TODO: stop all task when downstream is already closed

        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<(StreamType, _)>();

        let span = tracing::info_span!("serve", client=?src);

        shutdown_guard.spawn_supervised_task_fn_with_span(span.clone(), move |shutdown_guard| {
            async move {
                tracing::debug!("Start serving new connection from client");

                // Consume streams come from downstream
                match trusted_stream_manager
                    .consume_stream(stream, sender, shutdown_guard)
                    .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!(error=?e, "Failed to consume stream from client");
                    }
                }
            }
        });

        shutdown_guard.spawn_supervised_task_fn_with_span(span, move |shutdown_guard| {
            async move {
                while let Some((stream_type, attestation_result)) = receiver.recv().await {
                    let metrics = metrics.clone();

                    // Spawn a task to handle the connection
                    shutdown_guard.spawn_supervised_task_current_span({
                        let dst = dst.clone();

                        async move {
                            let fut = async {
                                let active_cx = metrics.new_cx();

                                // Print access log
                                let access_log = AccessLog::Egress {
                                    downstream: src,
                                    upstream: &dst,
                                    from_trusted_tunnel: stream_type.is_secured(),
                                    peer_attested: attestation_result,
                                };
                                tracing::info!(?access_log);

                                let downstream = stream_type.into_stream();

                                let upstream = tcp_connect_with_so_mark(
                                    (dst.host(), dst.port()),
                                    transport_so_mark,
                                )
                                .await
                                .context("Failed to connect to upstream")?;

                                let downstream = metrics.new_wrapped_stream(downstream);

                                utils::forward::forward_stream(upstream, downstream).await?;

                                active_cx.mark_finished_successfully();
                                Ok::<_, anyhow::Error>(())
                            };

                            if let Err(e) = fut.await {
                                tracing::error!(error=?e, "Failed to forward stream");
                            }
                        }
                    });
                }
            }
        });
    }
}
