use std::sync::Arc;

#[cfg(target_os = "linux")]
use crate::tunnel::utils::rustls::TlsOutcome;
use crate::{
    config::egress::RatsTlsArgs,
    tunnel::{
        attestation_result::AttestationResult,
        egress::protocol::common::transport::TngTransportStream,
        ra_context::RaContext,
        utils::{
            runtime::TokioRuntime,
            rustls::config::{alpn::Alpn, server::LazyOnetimeTlsServerConfig, TlsConfigGenerator},
        },
    },
    CommonStreamTrait,
};
use anyhow::Result;

pub(super) struct RatsTlsSecurityLayer {
    tls_config_generator: TlsConfigGenerator,
    multiplex: bool,
    // Read only on the Linux kTLS handshake path; unused (but stored) elsewhere.
    #[cfg(target_os = "linux")]
    ktls: crate::config::ktls::EnvCheckedKtls,
}

impl RatsTlsSecurityLayer {
    pub async fn new(
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
        rats_tls: &RatsTlsArgs,
    ) -> Result<Self> {
        let tls_config_generator = TlsConfigGenerator::new(ra_context, runtime).await?;

        #[cfg(target_os = "linux")]
        let ktls = rats_tls
            .ktls
            .resolve(&crate::config::ktls::KtlsEnvConstraints::link(
                rats_tls.multiplex,
            ))?;

        Ok(Self {
            tls_config_generator,
            multiplex: rats_tls.multiplex,
            #[cfg(target_os = "linux")]
            ktls,
        })
    }

    async fn prepare_tls_config(&self) -> Result<LazyOnetimeTlsServerConfig> {
        // Prepare TLS config
        let alpn = if self.multiplex {
            Alpn::Http2
        } else {
            Alpn::RatsTls
        };
        self.tls_config_generator
            .get_lazy_one_time_rustls_server_config(alpn)
            .await
    }

    #[cfg(target_os = "linux")]
    #[tracing::instrument(skip_all, name = "security", level = "info")]
    pub async fn handshake_try_ktls(
        &self,
        stream: TngTransportStream,
    ) -> Result<(TlsOutcome, Option<AttestationResult>)> {
        use crate::tunnel::utils::rustls::config::ktls::KtlsServerHandshakeConfig;

        let tls_server_config = self.prepare_tls_config().await?;

        match stream {
            TngTransportStream::Inspected(preluded_stream) => {
                crate::tunnel::utils::rustls::config::ktls::handshake_ktls(
                    KtlsServerHandshakeConfig::new(tls_server_config),
                    preluded_stream,
                    self.ktls,
                )
                .await
            }
            TngTransportStream::Uninspected(first_byte_read_timeout_stream) => {
                crate::tunnel::utils::rustls::config::ktls::handshake_ktls(
                    KtlsServerHandshakeConfig::new(tls_server_config),
                    first_byte_read_timeout_stream,
                    self.ktls,
                )
                .await
            }
        }
    }

    #[tracing::instrument(skip_all, name = "security", level = "info")]
    pub async fn handshake_rustls(
        &self,
        stream: TngTransportStream,
    ) -> Result<(Box<dyn CommonStreamTrait + Sync>, Option<AttestationResult>)> {
        let tls_server_config = self.prepare_tls_config().await?;

        Ok(match stream {
            TngTransportStream::Inspected(preluded_stream) => {
                let (tls_stream, attestation_result) = tls_server_config
                    .handshake_with_stream(preluded_stream)
                    .await?;

                (Box::new(tls_stream), attestation_result)
            }
            TngTransportStream::Uninspected(first_byte_read_timeout_stream) => {
                let (tls_stream, attestation_result) = tls_server_config
                    .handshake_with_stream(first_byte_read_timeout_stream)
                    .await?;
                (Box::new(tls_stream), attestation_result)
            }
        })
    }
}
