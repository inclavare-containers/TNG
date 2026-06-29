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
use crate::error::TngError;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::tunnel::access_log::{AccessAccepted, EgressAccessMode};
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

#[allow(dead_code)]
pub(super) struct AcceptedStream {
    pub stream: Box<dyn CommonStreamTrait + Sync>,
    pub src: SocketAddr,
    pub dst: Arc<TngEndpoint>,
    pub listener_addr: SocketAddr,
    pub egress_mode: EgressAccessMode,
    pub access_accepted: AccessAccepted,
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

#[async_trait]
impl RegistedService for Arc<EgressFlow> {
    async fn serve(&self, ready: Sender<()>) -> Result<()> {
        (**self).serve(ready).await
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
            listener_addr: _,
            egress_mode: _,
            // Egress processes multiple upstream connections per accepted downstream.
            // Extract access_accepted fields here so they can be cloned per inner-loop iteration.
            mut access_accepted,
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
                    let access_accepted = access_accepted.clone_for_multiplexing();

                    async move {
                        let fut = async {
                            let active_cx = metrics.new_cx();

                            let from_trusted_tunnel = next_stream.is_secured();
                            let attested = next_stream.attestation_result().is_some();
                            let downstream = next_stream.into_stream();

                            // Transition to AccessRouted: dst and from_trusted_tunnel are known
                            let access_routed =
                                access_accepted.into_routed(&dst, from_trusted_tunnel);

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
                            let egress_local =
                                upstream.local_addr().context("Failed to get local addr")?;
                            let upstream = ContextualStream::new(upstream, "egress-tcp-connect");

                            // Print access log — Transition to AccessEstablished: upstream connected, then drop immediately to log
                            access_routed.into_established(Some(egress_local), attested);

                            let downstream = metrics.new_wrapped_stream(downstream);

                            utils::forward::forward_stream(upstream, downstream).await?;

                            active_cx.mark_finished_successfully();
                            Ok::<_, anyhow::Error>(())
                        };

                        if let Err(error) = fut.await {
                            tracing::error!(?error, "Failed to forward stream");
                        }
                    }
                });
            }
        });
    }
}

#[async_trait]
impl StatusProvider for EgressFlow {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        self.trusted_stream_manager.query_status(path).await
    }
}
