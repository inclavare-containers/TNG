use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::Stream;
use futures::StreamExt;
use indexmap::IndexMap;
use tokio::sync::mpsc::Sender;

use crate::config::ingress::CommonArgs;
use crate::tunnel::access_log::{AccessLog, IngressMode};
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::service_metrics::ServiceMetrics;
use crate::tunnel::service_metrics::ServiceMetricsCreator;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::{service::RegistedService, tunnel::stream::CommonStreamTrait};

use super::stream_manager::{
    trusted::TrustedStreamManager, unprotected::UnprotectedStreamManager, StreamManager,
};

pub mod stream_router;

pub struct IngressFlow {
    ingress: Box<dyn IngressTrait>,
    trusted_stream_manager: Arc<TrustedStreamManager>,
    unprotected_stream_manager: Arc<UnprotectedStreamManager>,
    metrics: ServiceMetrics,
    runtime: TokioRuntime,
}

#[async_trait]
pub(super) trait IngressTrait: Sync + Send {
    /// Return the metric attributes of this ingress.
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
    pub stream: Box<dyn CommonStreamTrait + Send>,
    pub src: SocketAddr,
    pub dst: TngEndpoint,
    pub via_tunnel: bool,
    pub listener_addr: SocketAddr,
    pub ingress_mode: IngressMode,
}

impl IngressFlow {
    #[allow(private_bounds)]
    pub async fn new(
        ingress: impl IngressTrait + 'static,
        common_args: &CommonArgs,
        service_metrics_creator: &ServiceMetricsCreator,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let ingress = Box::new(ingress);

        let metric_attributes = ingress.metric_attributes();
        let metrics = service_metrics_creator.new_service_metrics(metric_attributes);

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        let transport_so_mark = ingress.transport_so_mark();

        let trusted_stream_manager = Arc::new(
            TrustedStreamManager::new(
                common_args,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                transport_so_mark,
                runtime.clone(),
            )
            .await?,
        );
        let unprotected_stream_manager = Arc::new(UnprotectedStreamManager::new(
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            transport_so_mark,
        ));

        Ok(Self {
            ingress,
            metrics,
            trusted_stream_manager,
            unprotected_stream_manager,
            runtime,
        })
    }
}

#[async_trait]
impl RegistedService for IngressFlow {
    async fn serve(&self, ready: Sender<()>) -> Result<()> {
        // Accept incomming streams
        let mut incomming = Box::into_pin(self.ingress.accept(self.runtime.clone()).await?);

        ready.send(()).await?;

        while let Some(next) = incomming.next().await {
            let accepted_stream = match next {
                Ok(next) => next,
                Err(error) => {
                    tracing::error!(?error, "Failed to accept incomming stream");
                    continue;
                }
            };

            self.serve_in_async_task_no_throw_error(accepted_stream, self.runtime.clone())
                .await;
        }

        Ok(())
    }
}

impl IngressFlow {
    async fn serve_in_async_task_no_throw_error(
        &self,
        accepted_stream: AcceptedStream,
        runtime: TokioRuntime,
    ) {
        let AcceptedStream {
            stream,
            src,
            dst,
            via_tunnel,
            listener_addr,
            ingress_mode,
        } = accepted_stream;

        let trusted_stream_manager = self.trusted_stream_manager.clone();
        let unprotected_stream_manager = self.unprotected_stream_manager.clone();
        let metrics = self.metrics.clone();

        // TODO: stop all task when downstream is already closed

        runtime.spawn_supervised_task_with_span(
            tracing::info_span!("serve", client=?src),
            async move {
                let fut = async move {
                    tracing::debug!(%src, %dst, via_tunnel, "Acquire connection to upstream");

                    // TODO: merge .new_cx() and .new_wrapped_stream()
                    let active_cx = metrics.new_cx();
                    let stream = metrics.new_wrapped_stream(stream);

                    let attestation_result;
                    let upstream_local;
                    let forward_stream_task = if !via_tunnel {
                        // Forward via unprotected tcp
                        let (forward_stream_task, att, up_local) = unprotected_stream_manager
                            .forward_stream(&dst, Box::new(stream))
                            .await
                            .with_context(|| {
                                format!("Failed to connect to upstream {dst} via unprotected tcp")
                            })?;

                        attestation_result = att;
                        upstream_local = up_local;
                        forward_stream_task
                    } else {
                        // Forward via trusted tunnel
                        let (forward_stream_task, att, up_local) = trusted_stream_manager
                            .forward_stream(&dst, Box::new(stream))
                            .await
                            .with_context(|| {
                                format!("Failed to connect to upstream {dst} via trusted tunnel")
                            })?;

                        attestation_result = att;
                        upstream_local = up_local;
                        forward_stream_task
                    };

                    // Print access log
                    let access_log = AccessLog::Ingress {
                        downstream_remote: src,
                        upstream_remote: &dst,
                        to_trusted_tunnel: via_tunnel,
                        attestation_result: attestation_result.map(Cow::Owned),
                        downstream_local: listener_addr,
                        ingress_mode,
                        upstream_local,
                    };
                    tracing::info!(%access_log);

                    // let forward_stream_task = pin!(forward_stream_task);
                    match forward_stream_task.await {
                        Err(error) => {
                            tracing::error!(
                                %dst,
                                ?error,
                                "Stream forwarding failed"
                            );
                        }
                        Ok(()) => {
                            active_cx.mark_finished_successfully();
                        }
                    }

                    Ok::<(), anyhow::Error>(())
                };

                if let Err(error) = fut.await {
                    tracing::error!(?error, "Failed to forward stream");
                }
            },
        );
    }
}
