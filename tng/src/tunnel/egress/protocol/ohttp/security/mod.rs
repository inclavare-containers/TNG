use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

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
        connection_fault::DownstreamSetupError,
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
            // Whether the outer HTTP server parsed at least one request. A
            // connection that ends without one never became a TNG session: an
            // SLB probe or a client that went away, not a tunnel fault.
            let served_any_request = Arc::new(AtomicBool::new(false));

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

            let hyper_service = hyper::service::service_fn({
                let served_any_request = Arc::clone(&served_any_request);
                move |request: axum::extract::Request<hyper::body::Incoming>| {
                    served_any_request.store(true, Ordering::Relaxed);
                    app.clone().call(request)
                }
            });

            hyper_util::server::conn::auto::Builder::new(self.runtime.clone())
                .serve_connection_with_upgrades(TokioIo::new(stream), hyper_service)
                .await
                .map_err(|error| {
                    // Keep the boxed chain: the classification walks it to tell
                    // a vanished peer from a protocol disagreement. Formatting
                    // the error into a string would erase that.
                    DownstreamSetupError::tag_boxed(error)
                        .context("failed to serve egress OHTTP security layer connection")
                })?;

            if !served_any_request.load(Ordering::Relaxed) {
                // A clean close before any request is the same benign class as
                // the TLS handshake reading EOF. Report it as a setup failure
                // so the caller records it and logs both lines at debug.
                return Err(DownstreamSetupError::tag(
                    anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
                        .context("downstream closed before sending an OHTTP request"),
                ));
            }

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
