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

pub struct TcpSecurityLayer {
    tls_config_generator: TlsConfigGenerator,
    runtime: TokioRuntime,
}

impl TcpSecurityLayer {
    pub async fn new(ra_args: &RaArgs, runtime: TokioRuntime) -> Result<Self> {
        let tls_config_generator = TlsConfigGenerator::new(ra_args).await?;

        Ok(Self {
            tls_config_generator,
            runtime,
        })
    }

    pub async fn prepare(&self) -> Result<()> {
        self.tls_config_generator
            .prepare(self.runtime.clone())
            .await
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
            .context("Failed to setup rats-tls connection")
        }
        .instrument(tracing::info_span!("security"))
        .await
    }
}
