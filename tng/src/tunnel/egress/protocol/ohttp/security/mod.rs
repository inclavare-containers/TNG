use anyhow::{anyhow, Result};
use hyper_util::rt::TokioIo;
use tower::Service;
use tracing::Instrument;
pub mod server;

use crate::{
    config::{egress::OHttpArgs, ra::RaArgs},
    tunnel::egress::{
        protocol::ohttp::security::{
            keystore::ServerKeyStore, server::OhttpServer, state::OhttpServerState,
        },
        stream_manager::trusted::StreamType,
    },
    AttestationResult, CommonStreamTrait, TokioRuntime,
};

mod keystore;
mod state;

pub struct OHttpSecurityLayer {
    runtime: TokioRuntime,
    ohttp_server: OhttpServer,
}

impl OHttpSecurityLayer {
    pub async fn new(
        ra_args: RaArgs,
        ohttp_args: OHttpArgs,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let key_store = ServerKeyStore::new(ra_args)?;

        Ok(Self {
            runtime,
            ohttp_server: OhttpServer::new(key_store, ohttp_args)?,
        })
    }
    pub async fn handle_stream(
        &self,
        stream: impl CommonStreamTrait,
        sender: tokio::sync::mpsc::UnboundedSender<(StreamType, Option<AttestationResult>)>,
    ) -> Result<()> {
        async {
            let app = self
                .ohttp_server
                .create_routes()
                .with_state(OhttpServerState {
                    runtime: self.runtime.clone(),
                    sender,
                });

            let hyper_service = hyper::service::service_fn(
                move |request: axum::extract::Request<hyper::body::Incoming>| {
                    app.clone().call(request)
                },
            );

            Ok(
                hyper_util::server::conn::auto::Builder::new(self.runtime.clone())
                    .serve_connection_with_upgrades(TokioIo::new(stream), hyper_service)
                    .await
                    .map_err(|error| anyhow!("failed to serve connection: {error:?}"))?,
            )
        }
        .instrument(tracing::info_span!("security"))
        .await
    }
}
