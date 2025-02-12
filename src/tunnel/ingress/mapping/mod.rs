use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tokio_graceful::ShutdownGuard;
use tracing::Instrument;

use crate::config::{ingress::CommonArgs, ingress::IngressMappingArgs};
use crate::tunnel::access_log::AccessLog;
use crate::tunnel::ingress::core::stream_manager::trusted::TrustedStreamManager;
use crate::tunnel::ingress::core::stream_manager::StreamManager;
use crate::tunnel::ingress::core::TngEndpoint;
use crate::tunnel::{utils, RegistedService};

pub struct MappingIngress {
    listen_addr: String,
    listen_port: u16,
    upstream_addr: String,
    upstream_port: u16,
    common_args: CommonArgs,
}

impl MappingIngress {
    pub fn new(mapping_args: &IngressMappingArgs, common_args: &CommonArgs) -> Result<Self> {
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
impl RegistedService for MappingIngress {
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
            let dst = TngEndpoint::new(self.upstream_addr.clone(), self.upstream_port);

            let trusted_stream_manager = trusted_stream_manager.clone();

            shutdown_guard.spawn_task({
                let fut = async move {
                    tracing::trace!("Start serving new connection from client");

                    // Forward via trusted tunnel
                    match trusted_stream_manager.new_stream(&dst).await {
                        Ok((upstream, attestation_result)) => {
                            // Print access log
                            let access_log = AccessLog {
                                downstream: downstream.peer_addr().unwrap(),
                                upstream: dst.clone(),
                                to_trusted_tunnel: true,
                                peer_attested: attestation_result,
                            };
                            tracing::info!(?access_log);

                            if let Err(e) = utils::forward_stream(upstream, downstream)
                                .in_current_span()
                                .await
                            {
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
                    }
                };

                fut.instrument(tracing::info_span!("serve", client=?peer_addr))
            });
        }

        Ok(())
    }
}
