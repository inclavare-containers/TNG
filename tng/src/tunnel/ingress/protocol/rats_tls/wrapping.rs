use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use http::{Request, StatusCode, Version};
use http_body_util::combinators::BoxBody;

use super::security::{pool::PoolKey, RatsTlsClient};
use super::transport::RatsTlsTransportLayerCreator;
use crate::{
    tunnel::{
        attestation_result::AttestationState,
        endpoint::TngEndpoint,
        utils,
        utils::rustls::config::{alpn::Alpn, TlsConfigGenerator},
    },
    CommonStreamTrait,
};
use tower::Service;

pub struct RatsTlsWrappingLayer {}

impl RatsTlsWrappingLayer {
    pub async fn create_stream_from_hyper(
        client: &RatsTlsClient,
    ) -> Result<(
        impl CommonStreamTrait + Sync,
        /* local_addr */ Option<SocketAddr>,
        AttestationState,
        /* session_id */ u64,
    )> {
        let req = Request::connect("https://tng.internal/")
            .version(Version::HTTP_2)
            .body(BoxBody::new(http_body_util::Empty::new()))?;

        tracing::debug!(
            session_id = client.id,
            "Establishing the wrapping layer (H2 CONNECT)"
        );

        let mut resp = client
            .hyper
            .request(req)
            .await
            .context("Failed to send HTTP/2 CONNECT request")?;

        tracing::debug!(session_id = client.id, "H2 CONNECT response received");

        let attestation_state = resp
            .extensions()
            .get::<AttestationState>()
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

        tracing::debug!(
            session_id = client.id,
            "Trusted tunnel established (H2 upgrade OK)"
        );

        Ok((stream, Some(local_addr), attestation_state, client.id))
    }

    /// Open the non-multiplex upstream TLS connection for 0-RTT.
    ///
    /// Returns the raw `TlsStream` (possibly in tokio-rustls `EarlyData`
    /// state, handshake NOT complete), the shared lazy RA verifier handle, and
    /// the local address. The caller primes the handshake (a write or flush),
    /// then reads `handshake_kind()` off the stream to classify attestation:
    /// on a full handshake it fetches the peer cert via `peer_certificates()`
    /// and runs `verifier.verify_cert(peer_cert)`; on a resumed handshake the
    /// verifier is skipped and the PSK binding is trusted.
    pub async fn create_stream_raw_0rtt(
        transport_layer_creator: &RatsTlsTransportLayerCreator,
        tls_config_generator: &TlsConfigGenerator,
        endpoint: &TngEndpoint,
    ) -> Result<(
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        Option<Arc<crate::tunnel::utils::rustls::ra::server_cert_verifier::LazyServerCertVerifier>>,
        Option<SocketAddr>,
    )> {
        let parent_span = tracing::info_span!("wrapping", mode = "rats-tls-0rtt");
        let mut connector =
            transport_layer_creator.create(&PoolKey::new(endpoint.clone()), parent_span.clone())?;
        let tls_client_config = tls_config_generator
            .get_lazy_one_time_rustls_client_config(Alpn::RatsTls)
            .await?;
        let tcp_stream: tokio::net::TcpStream = connector
            .call(http::Request::new(()))
            .await
            .context("Failed to establish TCP connection for rats-tls")?
            .into_inner();
        let local_addr = tcp_stream.local_addr().ok();
        let (tls_stream, verifier_opt) = tls_client_config
            .connect_early(endpoint.addr(), tcp_stream)
            .await?;
        Ok((tls_stream, verifier_opt, local_addr))
    }
}
