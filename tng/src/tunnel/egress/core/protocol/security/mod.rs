mod cert_verifier;
mod rustls_config;

use std::sync::Arc;

use crate::{
    config::ra::RaArgs,
    tunnel::{attestation_result::AttestationResult, utils::rustls_config::TlsConfigGenerator},
};
use anyhow::{Context as _, Result};
use rustls_config::OnetimeTlsServerConfig;
use tokio_graceful::ShutdownGuard;
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

pub struct SecurityLayer {
    tls_config_generator: TlsConfigGenerator,
}

impl SecurityLayer {
    pub async fn new(ra_args: &RaArgs) -> Result<Self> {
        let tls_config_generator = TlsConfigGenerator::new(ra_args).await?;

        Ok(Self {
            tls_config_generator,
        })
    }

    pub async fn prepare(&self, shutdown_guard: ShutdownGuard) -> Result<()> {
        self.tls_config_generator.prepare(shutdown_guard).await
    }

    pub async fn handshake(
        &self,
        stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
    ) -> Result<(
        impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
        Option<AttestationResult>,
    )> {
        async {
            // Prepare TLS config
            let OnetimeTlsServerConfig(tls_server_config, verifier) = self
                .tls_config_generator
                .get_one_time_rustls_server_config()
                .await?;

            let tls_acceptor = TlsAcceptor::from(Arc::new(tls_server_config));
            let tls_stream = async move {
                tracing::trace!("Start to estabilish rats-tls session");
                tls_acceptor.accept(stream).await.map(|v| {
                    tracing::debug!("New rats-tls session established");
                    v
                })
            }
            .await?;

            let attestation_result = match verifier {
                Some(verifier) => Some(
                    verifier
                        .get_attestation_result()
                        .await
                        .context("No attestation result found")?,
                ),
                None => None,
            };

            Ok((tls_stream, attestation_result))
        }
        .instrument(tracing::info_span!("security"))
        .await
    }
}
