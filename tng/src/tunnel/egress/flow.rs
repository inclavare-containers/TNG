use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use auto_enums::auto_enum;
use futures::Stream;
use futures::StreamExt;
use indexmap::IndexMap;
use tokio::sync::mpsc::Sender;

use crate::config::egress::CommonArgs;
use crate::tunnel::access_log::{AccessLog, EgressMode};
use crate::tunnel::service_metrics::ServiceMetrics;
use crate::tunnel::service_metrics::ServiceMetricsCreator;
use crate::tunnel::utils;
use crate::tunnel::utils::socket::tcp_connect;
use crate::{service::RegistedService, CommonStreamTrait, ContextualStream};

use super::stream_manager::{trusted::TrustedStreamManager, StreamManager};
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::utils::runtime::TokioRuntime;

pub struct EgressFlow {
    egress: Box<dyn EgressTrait>,
    trusted_stream_manager: Arc<TrustedStreamManager>,
    metrics: ServiceMetrics,
    runtime: TokioRuntime,
}

#[async_trait]
pub(super) trait EgressTrait: Sync + Send {
    /// Return the metric attributes of this egress.
    fn metric_attributes(&self) -> IndexMap<String, String>;

    /// Return the so_mark which should be used for creating new tcp stream to upstream.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn transport_so_mark(&self) -> Option<u32>;

    /// Accept incomming streams. The returned stream should be a stream of incomming accepted streams.
    /// Note that this method should be called only once.
    async fn accept(&self, runtime: TokioRuntime) -> Result<Incomming>;
}

pub(super) type Incomming<'a> = Box<dyn Stream<Item = Result<AcceptedStream>> + Send + 'a>;

pub(super) struct AcceptedStream {
    pub stream: Box<dyn CommonStreamTrait + Sync>,
    pub src: SocketAddr,
    pub dst: TngEndpoint,
    pub listener_addr: SocketAddr,
    pub egress_mode: EgressMode,
}

impl EgressFlow {
    #[allow(private_bounds)]
    pub async fn new(
        egress: impl EgressTrait + 'static,
        common_args: &CommonArgs,
        service_metrics_creator: &ServiceMetricsCreator,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let egress = Box::new(egress);

        let metric_attributes = egress.metric_attributes();
        let metrics = service_metrics_creator.new_service_metrics(metric_attributes);

        let trusted_stream_manager =
            Arc::new(TrustedStreamManager::new(common_args, runtime.clone()).await?);

        Ok(Self {
            egress,
            metrics,
            trusted_stream_manager,
            runtime,
        })
    }
}

#[async_trait]
impl RegistedService for EgressFlow {
    async fn serve(&self, ready: Sender<()>) -> Result<()> {
        // Accept incomming streams
        let mut incomming = Box::into_pin(self.egress.accept(self.runtime.clone()).await?);

        ready.send(()).await?;

        while let Some(next) = incomming.next().await {
            let accepted_stream = match next {
                Ok(next) => next,
                Err(error) => {
                    tracing::error!(?error, "Failed to accept incomming stream");
                    continue;
                }
            };

            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            let transport_so_mark = self.egress.transport_so_mark();

            self.serve_in_async_task_no_throw_error(
                accepted_stream,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                transport_so_mark,
                self.runtime.clone(),
            )
            .await;
        }

        Ok(())
    }
}

impl EgressFlow {
    #[auto_enum]
    async fn serve_in_async_task_no_throw_error(
        &self,
        accepted_stream: AcceptedStream,
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        runtime: TokioRuntime,
    ) {
        let AcceptedStream {
            stream,
            src,
            dst,
            listener_addr,
            egress_mode,
        } = accepted_stream;

        let trusted_stream_manager = self.trusted_stream_manager.clone();
        let metrics = self.metrics.clone();

        // TODO: stop all task when downstream is already closed

        let span = tracing::info_span!("serve", client=?src);
        let runtime_cloned = runtime.clone();
        runtime.spawn_supervised_task_with_span(span, async move {
            tracing::debug!("Start serving new connection from client");

            // Consume streams come from downstream
            let mut pending = match trusted_stream_manager.consume_stream(stream).await {
                Ok(pending) => pending,
                Err(error) => {
                    tracing::error!(?error, "Failed to consume stream from client");
                    return;
                }
            };

            while let Some(next_stream) = pending.next().await {
                let next_stream = match next_stream {
                    Ok(next_stream) => next_stream,
                    Err(error) => {
                        tracing::error!(?error, "Failed to get next stream");
                        continue;
                    }
                };

                let metrics = metrics.clone();

                // Spawn a task to handle the connection
                runtime_cloned.spawn_supervised_task_current_span({
                    let dst = dst.clone();

                    async move {
                        let fut = async {
                            let active_cx = metrics.new_cx();

                            let from_trusted_tunnel = next_stream.is_secured();
                            let attestation_info =
                                next_stream.attestation_result().cloned().map(Cow::Owned);
                            let downstream = next_stream.into_stream();

                            let upstream = tcp_connect(
                                (dst.host(), dst.port()),
                                #[cfg(any(
                                    target_os = "android",
                                    target_os = "fuchsia",
                                    target_os = "linux"
                                ))]
                                transport_so_mark,
                            )
                            .await
                            .context("Failed to connect to upstream")?;
                            let egress_local = upstream.local_addr().ok();
                            let upstream = ContextualStream::new(upstream, "egress-tcp-connect");

                            // Print access log
                            let access_log = AccessLog::Egress {
                                downstream_remote: src,
                                upstream_remote: &dst,
                                from_trusted_tunnel,
                                attestation_info,
                                downstream_local: listener_addr,
                                egress_mode,
                                upstream_local: egress_local,
                            };
                            tracing::info!(%access_log);

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
        });
    }
}
