use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
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
use crate::tunnel::upstream::UpstreamConnector;
use crate::{service::RegistedService, CommonStreamTrait};

use super::stream_manager::{
    trusted::{ProtocolStreamDecoderOutput, TrustedStreamManager},
    StreamManager,
};
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
    /// Whether this connection should go through the encryption/decryption path.
    /// When false, the stream is forwarded directly to the upstream.
    pub encrypted: bool,
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
            listener_addr: _,
            egress_mode: _,
            access_accepted,
            encrypted,
        } = accepted_stream;

        let trusted_stream_manager = self.trusted_stream_manager.clone();
        let metrics = self.metrics.clone();

        // TODO: stop all task when downstream is already closed

        let span = tracing::info_span!("serve", client=?src);
        let runtime_cloned = runtime.clone();
        runtime.spawn_supervised_task_with_span(span, async move {
            tracing::debug!("Start serving new connection from client");

            // One connector per outer connection. It owns the accept-time
            // resolved upstream endpoint, the access-log state (cloned per
            // backend leg), and the cx accounting shared by every leg —
            // whether the leg is forwarded by the loop below or, for ohttp,
            // dialed directly by the request handlers behind the decoder.
            let connector = Arc::new(UpstreamConnector::new(
                dst,
                metrics,
                access_accepted,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                transport_so_mark,
            ));

            if !encrypted {
                // Transport-level direct forward: determined at accept time by the
                // egress mode's host/ifname filter (HookEgress::encrypted checks whether
                // the connection's local_addr.ip() matches a configured host and ifname).
                // When the IP doesn't match any rule, the entire connection bypasses
                // the trusted stream manager — no OHTTP/RATS-TLS processing happens.
                // This is a per-connection decision, made once when the TCP accept occurs.
                if let Err(error) = connector
                    .connect_and_forward_bytes(stream, false, false)
                    .await
                {
                    tracing::error!(?error, "Failed to forward stream");
                }
                return;
            }

            // Existing trusted stream path
            let mut pending = match trusted_stream_manager
                .consume_stream(stream, Some(src), connector.clone())
                .await
            {
                Ok(ProtocolStreamDecoderOutput::ByteStreams(pending)) => pending,
                Ok(ProtocolStreamDecoderOutput::SelfForwarded) => {
                    // The decoder's protocol (ohttp) forwards decrypted
                    // requests to the backend itself through the connector;
                    // the flow must not spawn copy tasks for them.
                    return;
                }
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

                // Spawn a task to handle the connection
                runtime_cloned.spawn_supervised_task_current_span({
                    let connector = connector.clone();

                    async move {
                        // Protocol-level direct forward: determined by TransportLayer
                        // inside consume_stream. The first bytes of the stream are inspected
                        // as HTTP; if the path matches a configured direct_forward regex
                        // (common_args.direct_forward_rules), the request bypasses OHTTP
                        // decryption entirely and is forwarded as plain HTTP to upstream.
                        //
                        // This is a per-request decision, distinct from the transport-level
                        // decision above. A connection can pass the transport-level IP/ifname
                        // check (encrypted=true, entering the trusted stream path) yet
                        // still yield DirectlyForward NextStreams when individual request
                        // paths match the direct_forward rules.
                        //
                        // Three sub-stream outcomes:
                        // - Secured(stream, Fresh/Resumed): decrypted + attested
                        // - Secured(stream, Unattested): OHTTP/RATS-TLS decrypted, no attestation
                        // - DirectlyForward(stream): plain HTTP matched by direct_forward rule
                        let encrypted = next_stream.is_secured();
                        let attested = next_stream.attestation_state().is_attested();
                        let downstream = next_stream.into_stream();

                        if let Err(error) = connector
                            .connect_and_forward_bytes(downstream, encrypted, attested)
                            .await
                        {
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
