mod cert_verifier;
mod rustls_config;

use std::sync::Arc;

use crate::{
    config::ra::RaArgs,
    tunnel::{
        attestation_result::AttestationResult, stream::CommonStreamTrait,
        utils::rustls_config::TlsConfigGenerator,
    },
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
        stream: impl CommonStreamTrait,
    ) -> Result<(impl CommonStreamTrait, Option<AttestationResult>)> {
        async {
            // Prepare TLS config
            let OnetimeTlsServerConfig(tls_server_config, verifier) = self
                .tls_config_generator
                .get_one_time_rustls_server_config()
                .await?;

            let tls_acceptor = TlsAcceptor::from(Arc::new(tls_server_config));
            tracing::trace!("Start to estabilish rats-tls session");

            // Here we run the security layer in blocking thread since the API of ClientCertVerifier is blocking.
            let tls_accept_task = async move {
                Ok::<_, anyhow::Error>(tls_acceptor.accept(stream).await.map(|v| {
                    tracing::debug!("New rats-tls session established");
                    v
                })?)
            };

            // Spawn a async task to handle all the async certificate verification tasks
            if let Some(verifier) = &verifier {
                verifier.spawn_verify_task_handler().await
            };

            // Spawn a blocking task to perform the TLS handshake.
            #[cfg(all(
                target_arch = "wasm32",
                target_vendor = "unknown",
                target_os = "unknown"
            ))]
            let security_layer_stream = tokio_with_wasm::task::spawn_blocking(move || {
                futures::executor::block_on(tls_accept_task)
            })
            .await
            .map_err(anyhow::Error::from)
            .and_then(|e| e)
            .context("Failed to estabilish rats-tls session")?;

            #[cfg(not(all(
                target_arch = "wasm32",
                target_vendor = "unknown",
                target_os = "unknown"
            )))]
            let security_layer_stream =
                tokio::task::spawn_blocking(move || futures::executor::block_on(tls_accept_task))
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(|e| e)
                    .context("Failed to estabilish rats-tls session")?;

            let attestation_result = match verifier {
                Some(verifier) => Some(
                    verifier
                        .get_attestation_result()
                        .await
                        .context("No attestation result found")?,
                ),
                None => None,
            };

            Ok((security_layer_stream, attestation_result))
        }
        .instrument(tracing::info_span!("security"))
        .await
    }
}
