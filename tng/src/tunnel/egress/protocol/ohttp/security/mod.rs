use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use tower::Service;
use tracing::Instrument;

use crate::error::TngError;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::{
    config::egress::OHttpArgs,
    tunnel::{
        connection_fault::{classify_boxed_failure, ConnectionFault, DownstreamSetupError},
        egress::protocol::ohttp::security::{context::TngStreamContext, server::OhttpServer},
        ra_context::RaContext,
        upstream::UpstreamConnector,
    },
    CommonStreamTrait, TokioRuntime,
};

mod api;
pub mod context;
pub mod cors_fallback;
#[allow(dead_code)]
pub mod key_manager;
pub mod server;
pub mod ws;

/// Hyper reports an incomplete message when a request was only partially read.
/// That verdict has no io source of its own, so it belongs at this boundary
/// where hyper's error type is in scope.
fn incomplete_message_fault(error: &(dyn std::error::Error + 'static)) -> Option<ConnectionFault> {
    let mut node = Some(error);
    while let Some(current) = node {
        if let Some(hyper_error) = current.downcast_ref::<hyper::Error>() {
            if hyper_error.is_incomplete_message() {
                return Some(ConnectionFault::PeerVanished);
            }
        }
        node = current.source();
    }
    None
}

pub struct OHttpSecurityLayer {
    runtime: TokioRuntime,
    ohttp_server: OhttpServer,
}

impl OHttpSecurityLayer {
    pub async fn new(
        ra_context: Arc<RaContext>,
        ohttp_args: OHttpArgs,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        Ok(Self {
            runtime: runtime.clone(),
            ohttp_server: OhttpServer::new(ra_context, ohttp_args, runtime).await?,
        })
    }
    pub async fn handle_stream(
        &self,
        stream: impl CommonStreamTrait,
        connector: Arc<UpstreamConnector>,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<()> {
        async {
            let access_connector = Arc::clone(&connector);
            let state = TngStreamContext {
                runtime: self.runtime.clone(),
                connector,
                peer_addr: peer,
                backend: Arc::default(),
            };
            let app = self
                .ohttp_server
                .create_routes(state.clone())
                .with_state(state);

            let hyper_service = hyper::service::service_fn(
                move |request: axum::extract::Request<hyper::body::Incoming>| {
                    app.clone().call(request)
                },
            );

            hyper_util::server::conn::auto::Builder::new(self.runtime.clone())
                .serve_connection_with_upgrades(TokioIo::new(stream), hyper_service)
                .await
                .map_err(|error| {
                    // Keep the boxed chain so the log shows the underlying
                    // cause. Hyper's own verdict is not visible to the generic
                    // io walk, so it is added here before tagging.
                    let fault = incomplete_message_fault(&*error)
                        .unwrap_or_else(|| classify_boxed_failure(&*error));
                    DownstreamSetupError::tag_boxed_with_fault(fault, error)
                        .context("failed to serve egress OHTTP security layer connection")
                })?;

            // The HTTP connection ended normally. That covers an idle close, a
            // key-config request, and a completed exchange; hyper reports Ok
            // for all of them. Record it as a per-connection event so the
            // access-log line stays at debug. A connection that dialled a
            // backend has already emitted its own access-log line, so this
            // fault no longer prints.
            access_connector
                .record_fault(ConnectionFault::PeerVanished)
                .await;

            Ok(())
        }
        .instrument(tracing::info_span!("security"))
        .await
    }
}

#[async_trait]
impl StatusProvider for OHttpSecurityLayer {
    async fn query_status(&self, path: &[&str]) -> Result<StatusQueryResult, TngError> {
        self.ohttp_server.query_status(path).await
    }
}
