use std::net::SocketAddr;

use anyhow::{bail, Context as _, Result};
use http::{Request, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use tower::Service;

use crate::{
    tunnel::{
        attestation_result::AttestationResult,
        endpoint::TngEndpoint,
        ingress::protocol::rats_tls::security::pool::PoolKey,
        utils::{self, runtime::TokioRuntime, rustls_config::TlsConfigGenerator},
    },
    CommonStreamTrait,
};

use super::security::rustls_config::OnetimeTlsClientConfig;
use super::security::RatsTlsClient;
use super::transport::RatsTlsTransportLayerCreator;

pub struct RatsTlsWrappingLayer {}

impl RatsTlsWrappingLayer {
    pub async fn create_stream_from_hyper(
        client: &RatsTlsClient,
    ) -> Result<(
        impl CommonStreamTrait + Sync,
        /* local_addr */ Option<SocketAddr>,
        Option<AttestationResult>,
        /* session_id */ u64,
    )> {
        let req = Request::connect("https://tng.internal/")
            .version(Version::HTTP_2)
            .body(BoxBody::new(http_body_util::Empty::new()))?;

        tracing::debug!("Establishing the wrapping layer");

        let mut resp = client
            .hyper
            .request(req)
            .await
            .context("Failed to send HTTP/2 CONNECT request")?;

        let attestation_result = resp
            .extensions()
            .get::<Option<AttestationResult>>()
            .context("Can not find attestation result")?
            .clone();

        if resp.status() != StatusCode::OK {
            bail!(
                "Failed to send HTTP/2 CONNECT request, bad status '{}', got: {:?}",
                resp.status(),
                resp
            );
        }

        let local_addr = resp
            .extensions()
            .get::<hyper_util::client::legacy::connect::HttpInfo>()
            .context("Can not get local addr")?
            .local_addr();

        let upgraded = hyper::upgrade::on(&mut resp)
            .await
            .context("Failed to establish HTTP/2 CONNECT tunnel")?;

        let Ok(stream) = utils::hyper::downcast_h2upgraded(upgraded) else {
            bail!("failed to downcast to inner stream");
        };

        tracing::debug!("Trusted tunnel established");

        Ok((stream, Some(local_addr), attestation_result, client.id))
    }

    /// Create a direct TLS stream without HTTP/2 CONNECT tunneling.
    /// Used when `raw-tls` ALPN is negotiated (no_ra mode).
    pub async fn create_stream_raw(
        transport_layer_creator: &RatsTlsTransportLayerCreator,
        tls_config_generator: &TlsConfigGenerator,
        endpoint: &TngEndpoint,
        _runtime: &TokioRuntime,
    ) -> Result<(
        impl CommonStreamTrait + Sync,
        /* local_addr */ Option<SocketAddr>,
        Option<AttestationResult>,
        /* session_id */ u64,
    )> {
        let parent_span = tracing::info_span!("wrapping", mode = "raw-tls");

        let mut connector =
            transport_layer_creator.create(&PoolKey::new(endpoint.clone()), parent_span.clone())?;

        let OnetimeTlsClientConfig(mut tls_client_config, _verifier) = tls_config_generator
            .get_one_time_rustls_client_config()
            .await?;

        // Override ALPN to prefer raw-tls
        tls_client_config.alpn_protocols = vec![b"raw-tls".to_vec(), b"h2".to_vec()];

        let tcp_stream: tokio::net::TcpStream = connector
            .call(http::Request::new(()))
            .await
            .context("Failed to establish TCP connection for raw-tls")?
            .into_inner();

        let local_addr = tcp_stream.local_addr().ok();

        let tls_stream = TlsConnector::from(std::sync::Arc::new(tls_client_config))
            .connect(
                ServerName::try_from(endpoint.host())
                    .context("Invalid host for raw-tls")?
                    .to_owned(),
                tcp_stream,
            )
            .await
            .context("Failed to establish raw-tls connection")?;

        tracing::debug!("Raw-TLS tunnel established");

        Ok((tls_stream, local_addr, None, 0))
    }
}
