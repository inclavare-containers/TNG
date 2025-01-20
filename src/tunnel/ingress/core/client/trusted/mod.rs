mod cert_resolver;
mod security;
mod transport;
mod verifier;
mod wrapping;

use anyhow::Result;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tracing::Instrument;
use transport::TransportLayerCreator;

use crate::{config::ingress::CommonArgs, tunnel::ingress::core::TngEndpoint};

use self::security::SecurityLayer;

use super::stream_manager::StreamManager;

pub struct TrustedStreamManager {
    security_layer: SecurityLayer,
}

impl TrustedStreamManager {
    pub fn new(common_args: &CommonArgs) -> Result<Self> {
        let connector_creator = TransportLayerCreator::new(common_args.encap_in_http.clone());

        Ok(Self {
            security_layer: SecurityLayer::new(connector_creator, &common_args.ra_args)?,
        })
    }
}

impl StreamManager for TrustedStreamManager {
    type StreamType = TokioIo<Upgraded>;

    async fn new_stream(&self, dst: &TngEndpoint) -> Result<Self::StreamType> {
        let client = self.security_layer.get_client(dst).await?;

        let stream = wrapping::create_stream_from_hyper(&client)
            .instrument(tracing::info_span!(
                "trust_tunnel",
                rats_tls_session_id = client.id
            ))
            .await?;

        Ok(stream)
    }
}
