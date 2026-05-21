mod cert_verifier;
mod rustls_config;

use std::sync::Arc;

use crate::tunnel::{
    attestation_result::AttestationResult,
    ra_context::RaContext,
    stream::CommonStreamTrait,
    utils::{runtime::TokioRuntime, rustls_config::TlsConfigGenerator},
};
use anyhow::{Context as _, Result};
use tracing::Instrument;

pub(super) struct RatsTlsSecurityLayer {
    tls_config_generator: TlsConfigGenerator,
    multiplex: bool,
}

impl RatsTlsSecurityLayer {
    pub async fn new(
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
        multiplex: bool,
    ) -> Result<Self> {
        let tls_config_generator = TlsConfigGenerator::new(ra_context, runtime).await?;

        Ok(Self {
            tls_config_generator,
            multiplex,
        })
    }

    pub async fn handshake<T: CommonStreamTrait + std::marker::Sync>(
        &self,
        stream: T,
    ) -> Result<(
        tokio_rustls::server::TlsStream<T>,
        Option<AttestationResult>,
    )> {
        async {
            // Prepare TLS config
            let mut tls_server_config = self
                .tls_config_generator
                .get_one_time_rustls_server_config()
                .await?;

            // Set ALPN: H2-only when multiplex=true, rats-tls-only when multiplex=false
            if self.multiplex {
                tls_server_config.0.alpn_protocols = vec![b"h2".to_vec()];
            } else {
                tls_server_config.0.alpn_protocols = vec![b"rats-tls".to_vec()];
            }

            tracing::debug!("Start to estabilish rats-tls connection");

            let (security_layer_stream, attestation_result) = tls_server_config
                .handshake_with_stream(stream)
                .await
                .context("Failed to accept rats-tls connection from downstream")?;

            tracing::debug!("New rats-tls connection established");
            Ok((security_layer_stream, attestation_result))
        }
        .instrument(tracing::info_span!("security"))
        .await
    }
}
