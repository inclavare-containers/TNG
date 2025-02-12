use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Sender},
};
use tokio_graceful::ShutdownGuard;
use tracing::Instrument;

use crate::{
    config::egress::{CommonArgs, EgressMappingArgs},
    tunnel::{
        access_log::AccessLog,
        egress::core::stream_manager::{trusted::TrustedStreamManager, StreamManager},
        ingress::core::TngEndpoint,
        utils, RegistedService,
    },
};

pub struct MappingEgress {
    listen_addr: String,
    listen_port: u16,
    upstream_addr: String,
    upstream_port: u16,
    common_args: CommonArgs,
}

impl MappingEgress {
    pub fn new(mapping_args: &EgressMappingArgs, common_args: &CommonArgs) -> Result<Self> {
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
            common_args: common_args.clone(),
        })
    }
}

#[async_trait]
impl RegistedService for MappingEgress {
    async fn serve(&self, shutdown_guard: ShutdownGuard, ready: Sender<()>) -> Result<()> {
        let trusted_stream_manager =
            Arc::new(TrustedStreamManager::new(&self.common_args, shutdown_guard.clone()).await?);

        let listen_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", listen_addr);

        let listener = TcpListener::bind(listen_addr).await.unwrap();
        // TODO: ENVOY_LISTENER_SOCKET_OPTIONS
        ready.send(()).await?;

        loop {
            let (downstream, _) = tokio::select! {
                res = listener.accept() => res.unwrap(),
                _ = shutdown_guard.cancelled() => {
                    tracing::debug!("Shutdown signal received, stop accepting new connections");
                    break;
                }
            };
            let peer_addr = downstream.peer_addr().unwrap();
            let upstream_addr = self.upstream_addr.clone();
            let upstream_port = self.upstream_port;

            let trusted_stream_manager = trusted_stream_manager.clone();

            let span = tracing::info_span!("serve", client=?peer_addr);
            shutdown_guard.spawn_task_fn(move |shutdown_guard| {
                async move {
                    tracing::debug!("Start serving new connection from client");

                    let (sender, mut receiver) = mpsc::unbounded_channel();

                    shutdown_guard.spawn_task(
                        async move {
                            while let Some((stream, attestation_result)) = receiver.recv().await {
                                let fut = async {
                                    // Print access log
                                    let access_log = AccessLog {
                                        downstream: peer_addr,
                                        upstream: TngEndpoint::new(&upstream_addr, upstream_port),
                                        to_trusted_tunnel: true, // TODO: handle allow_non_tng_traffic
                                        peer_attested: attestation_result,
                                    };
                                    tracing::info!(?access_log);

                                    let upstream =
                                        TcpStream::connect((upstream_addr.as_str(), upstream_port))
                                            .await?;

                                    utils::forward_stream(upstream, TokioIo::new(stream)).await
                                };

                                if let Err(e) = fut.await {
                                    tracing::error!(error=?e, "Failed to forward stream");
                                }
                            }
                        }
                        .in_current_span(),
                    );

                    // Consume streams come from downstream
                    match trusted_stream_manager
                        .consume_stream(downstream, sender, shutdown_guard)
                        .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            let error = format!("{e:#}");
                            tracing::error!(error, "Failed to consume stream from client");
                        }
                    }
                }
                .instrument(span)
            });
        }

        Ok(())
    }
}
