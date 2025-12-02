mod cert_verifier;
mod rustls_config;

use std::sync::Arc;

use crate::{
    config::ra::RaArgs,
    tunnel::{
        attestation_result::AttestationResult,
        stream::CommonStreamTrait,
        utils::{runtime::TokioRuntime, rustls_config::TlsConfigGenerator},
    },
};
use anyhow::{Context as _, Result};
use rustls_config::OnetimeTlsServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

pub(super) struct RatsTlsSecurityLayer {
    tls_config_generator: TlsConfigGenerator,
}

impl RatsTlsSecurityLayer {
    pub async fn new(ra_args: RaArgs, runtime: TokioRuntime) -> Result<Self> {
        let tls_config_generator = TlsConfigGenerator::new(ra_args, runtime).await?;

        Ok(Self {
            tls_config_generator,
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
            let OnetimeTlsServerConfig(tls_server_config, verifier) = self
                .tls_config_generator
                .get_one_time_rustls_server_config()
                .await?;

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
