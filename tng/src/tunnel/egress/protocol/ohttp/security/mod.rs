use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use tower::Service;
use tracing::Instrument;

use crate::error::TngError;
use crate::status::{StatusProvider, StatusQueryResult};
use crate::{
    config::egress::OHttpArgs,
    tunnel::{
        egress::protocol::ohttp::security::{context::TngStreamContext, server::OhttpServer},
        ra_context::RaContext,
    },
    AttestationResult, CommonStreamTrait, TokioRuntime,
};

mod api;
pub mod context;
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
        sender: tokio::sync::mpsc::UnboundedSender<(
            Box<dyn CommonStreamTrait + Sync>,
            Option<AttestationResult>,
        )>,
    ) -> Result<()> {
        async {
            let app = self
                .ohttp_server
                .create_routes()
                .with_state(TngStreamContext {
                    runtime: self.runtime.clone(),
                    sender,
                });

            let hyper_service = hyper::service::service_fn(
                move |request: axum::extract::Request<hyper::body::Incoming>| {
                    app.clone().call(request)
                },
            );

            hyper_util::server::conn::auto::Builder::new(self.runtime.clone())
                .serve_connection_with_upgrades(TokioIo::new(stream), hyper_service)
                .await
                .map_err(|error| {
                    anyhow!("failed to serve egress OHTTP security layer connection: {error:?}")
                })
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
