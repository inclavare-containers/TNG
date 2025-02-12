use anyhow::Result;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio_graceful::ShutdownGuard;
use tracing::Instrument;

use crate::{
    config::ingress::CommonArgs,
    tunnel::{
        attestation_result::AttestationResult,
        ingress::core::{
            protocol::{security::SecurityLayer, transport::TransportLayerCreator, wrapping},
            TngEndpoint,
        },
    },
};

use super::StreamManager;

pub struct TrustedStreamManager {
    security_layer: SecurityLayer,
}

impl TrustedStreamManager {
    pub async fn new(common_args: &CommonArgs, shutdown_guard: ShutdownGuard) -> Result<Self> {
        let connector_creator =
            TransportLayerCreator::new(common_args.encap_in_http.clone(), shutdown_guard.clone());

        Ok(Self {
            security_layer: SecurityLayer::new(
                connector_creator,
                &common_args.ra_args,
                shutdown_guard,
            )
            .await?,
        })
    }
}

impl StreamManager for TrustedStreamManager {
    type StreamType = TokioIo<Upgraded>;

    async fn new_stream(
        &self,
        dst: &TngEndpoint,
    ) -> Result<(Self::StreamType, Option<AttestationResult>)> {
        let client = self.security_layer.get_client(dst).await?;

        wrapping::create_stream_from_hyper(&client)
            .instrument(tracing::info_span!("wrapping"))
            .await
    }
}
