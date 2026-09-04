use std::net::SocketAddr;

use anyhow::{bail, Context as _, Result};
use http::{Request, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use tower::Service;

use super::security::RatsTlsClient;
use super::transport::RatsTlsTransportLayerCreator;
use crate::{
    tunnel::{
        attestation_result::AttestationResult,
        endpoint::TngEndpoint,
        ingress::protocol::rats_tls::security::pool::PoolKey,
        utils::{
            self,
            rustls::{
                config::{alpn::Alpn, TlsConfigGenerator},
                TlsOutcome,
            },
        },
    },
    CommonStreamTrait,
};

pub struct RatsTlsWrappingLayer {}

impl RatsTlsWrappingLayer {
    pub async fn create_stream_from_hyper(
        client: &RatsTlsClient,
    ) -> Result<(
        impl CommonStreamTrait + Sync,
        /* local_addr */ Option<SocketAddr>,
        Option<AttestationResult>,
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

        tracing::debug!(
            session_id = client.id,
            "Trusted tunnel established (H2 upgrade OK)"
        );

        Ok((stream, Some(local_addr), attestation_result))
    }

    /// Create a direct TLS stream without HTTP/2 CONNECT tunneling.
    /// Used when `multiplex=false` is configured.
    pub async fn create_stream_raw(
        transport_layer_creator: &RatsTlsTransportLayerCreator,
        tls_config_generator: &TlsConfigGenerator,
        endpoint: &TngEndpoint,
        #[cfg(target_os = "linux")] ktls: crate::config::ktls::EnvCheckedKtls,
    ) -> Result<(
        TlsOutcome,
        /* local_addr */ Option<SocketAddr>,
        Option<AttestationResult>,
    )> {
        let parent_span = tracing::info_span!("wrapping", mode = "rats-tls");

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

        #[cfg(target_os = "linux")]
        let (outcome, attestation_result) = {
            if !ktls.engages() {
                use crate::tunnel::utils::rustls::TlsOutcome;

                let (tls_stream, attestation_result) = tls_client_config
                    .handshake_with_stream(endpoint.addr(), tcp_stream)
                    .await?;

                (TlsOutcome::Rustls(Box::new(tls_stream)), attestation_result)
            } else {
                use crate::tunnel::utils::rustls::config::ktls::KtlsClientHandshakeConfig;

                utils::rustls::config::ktls::handshake_ktls(
                    KtlsClientHandshakeConfig::new(tls_client_config, endpoint.addr()),
                    tcp_stream,
                    ktls,
                )
                .await?
            }
        };
        #[cfg(not(target_os = "linux"))]
        let (outcome, attestation_result) = {
            let (tls_stream, attestation_result) = tls_client_config
                .handshake_with_stream(endpoint.addr(), tcp_stream)
                .await?;

            (TlsOutcome::Rustls(Box::new(tls_stream)), attestation_result)
        };

        tracing::debug!("Rats-TLS tunnel established");

        Ok((outcome, local_addr, attestation_result))
    }
}
