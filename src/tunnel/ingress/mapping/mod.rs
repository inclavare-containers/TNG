use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::Instrument;

use crate::config::{ingress::CommonArgs, ingress::MappingArgs};
use crate::tunnel::ingress::core::client::stream_manager::StreamManager;
use crate::tunnel::ingress::core::TngEndpoint;
use crate::tunnel::ingress::utils;

use super::core::client::trusted::TrustedStreamManager;

pub struct MappingIngress {
    listen_addr: String,
    listen_port: u16,
    upstream_addr: String,
    upstream_port: u16,
    trusted_stream_manager: Arc<TrustedStreamManager>,
}

impl MappingIngress {
    pub fn new(mapping_args: &MappingArgs, common_args: &CommonArgs) -> Result<Self> {
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
            trusted_stream_manager: Arc::new(TrustedStreamManager::new(common_args)?),
        })
    }

    pub async fn serve(&self) -> Result<()> {
        let ingress_addr = format!("{}:{}", self.listen_addr, self.listen_port);
        tracing::debug!("Add TCP listener on {}", ingress_addr);

        let listener = TcpListener::bind(ingress_addr).await.unwrap();
        // TODO: ENVOY_LISTENER_SOCKET_OPTIONS

        loop {
            let (downstream, _) = listener.accept().await.unwrap();
            let peer_addr = downstream.peer_addr().unwrap();
            let dst = TngEndpoint::new(self.upstream_addr.clone(), self.upstream_port);

            let trusted_stream_manager = self.trusted_stream_manager.clone();

            tokio::task::spawn({
                let fut = async move {
                    tracing::debug!("Start serving connection from client");

                    // Forward via trusted tunnel

                    match trusted_stream_manager.new_stream(&dst).await {
                        Ok(upstream) => {
                            if let Err(e) = utils::forward_stream(upstream, downstream).await {
                                tracing::error!(
                                    "Failed during forwarding to upstream {dst} via trusted tunnel: {e}"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to connect to upstream {dst} via trusted tunnel: {e}"
                            );
                        }
                    }
                };

                fut.instrument(tracing::info_span!("serve", client=?peer_addr))
            });
        }
    }
}
