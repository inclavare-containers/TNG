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
use rustls_config::OnetimeTlsServerConfig;
use tokio_rustls::TlsAcceptor;
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
            let OnetimeTlsServerConfig(mut tls_server_config, verifier) = self
                .tls_config_generator
                .get_one_time_rustls_server_config()
                .await?;

            // Set ALPN: H2-only when multiplex=true, rats-tls-only when multiplex=false
            if self.multiplex {
                tls_server_config.alpn_protocols = vec![b"h2".to_vec()];
            } else {
                tls_server_config.alpn_protocols = vec![b"rats-tls".to_vec()];
            }

            let tls_acceptor = TlsAcceptor::from(Arc::new(tls_server_config));
            tracing::debug!("Start to estabilish rats-tls connection");

            async {
                let security_layer_stream = tls_acceptor.accept(stream).await?;

                let attestation_result = match verifier {
                    Some(verifier) => Some(
                        verifier
                            .verity_pending_cert()
                            .await
                            .context("No attestation result found")?,
                    ),
                    None => None,
                };

                tracing::debug!("New rats-tls connection established");
                Ok::<_, anyhow::Error>((security_layer_stream, attestation_result))
            }
            .await
            .context("Failed to accept rats-tls connection from downstream")
        }
        .instrument(tracing::info_span!("security"))
        .await
    }
}
