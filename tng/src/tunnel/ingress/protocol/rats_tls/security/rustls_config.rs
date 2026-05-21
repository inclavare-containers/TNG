use std::sync::Arc;

use crate::tunnel::{
    attestation_result::AttestationResult, utils::rustls_config::TlsConfigGenerator,
};
use anyhow::{Context as _, Result};
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use tokio_rustls::TlsConnector;

use super::cert_verifier::{dummy::DummyServerCertVerifier, ra::TngServerCertVerifier};

impl TlsConfigGenerator {
    pub async fn get_one_time_rustls_client_config(&self) -> Result<OnetimeTlsClientConfig> {
        let mut config =
            match self {
                TlsConfigGenerator::NoRa => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_no_client_auth();

                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                    OnetimeTlsClientConfig(tls_client_config, None)
                }
                TlsConfigGenerator::Verify(verify_ctx) => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_no_client_auth();

                    let verifier: Arc<TngServerCertVerifier> =
                        Arc::new(TngServerCertVerifier::new(verify_ctx.clone())?);
                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(verifier.clone());

                    OnetimeTlsClientConfig(tls_client_config, Some(verifier))
                }
                #[cfg(unix)]
                TlsConfigGenerator::Attest(cert_manager) => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                    OnetimeTlsClientConfig(tls_client_config, None)
                }
                #[cfg(unix)]
                TlsConfigGenerator::AttestAndVerify(cert_manager, verify_ctx) => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));

                    let verifier: Arc<TngServerCertVerifier> =
                        Arc::new(TngServerCertVerifier::new(verify_ctx.clone())?);
                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(verifier.clone());

                    OnetimeTlsClientConfig(tls_client_config, Some(verifier))
                }
            };

        config.0.alpn_protocols = vec![b"h2".to_vec()];

        Ok(config)
    }
}

/// Bundled TLS client config with post-handshake verifier.
///
/// The verifier field is private — callers must use [`Self::handshake_with_stream`]
/// to perform the TLS handshake followed by `verity_pending_cert`, ensuring the
/// attestation check cannot be accidentally skipped.
pub struct OnetimeTlsClientConfig(pub rustls::ClientConfig, Option<Arc<TngServerCertVerifier>>);

impl OnetimeTlsClientConfig {
    /// Perform TLS handshake on an already-connected TCP stream, then verify
    /// the peer certificate if a verifier was configured.
    ///
    /// This bundles the two steps that must always occur together:
    /// 1. TLS handshake (which stores the peer cert in the verifier)
    /// 2. `verity_pending_cert` (which validates the stored cert)
    pub async fn handshake_with_stream<S>(
        self,
        server_name: &str,
        stream: S,
    ) -> Result<(
        tokio_rustls::client::TlsStream<S>,
        Option<AttestationResult>,
    )>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let tls_stream = TlsConnector::from(std::sync::Arc::new(self.0))
            .connect(
                ServerName::try_from(server_name)
                    .context("Invalid server name for TLS handshake")?
                    .to_owned(),
                stream,
            )
            .await
            .context("Failed to establish TLS connection")?;

        let attestation_result = match self.1 {
            Some(verifier) => Some(
                verifier
                    .verity_pending_cert()
                    .await
                    .context("Failed to verify pending certificate")?,
            ),
            None => None,
        };

        Ok((tls_stream, attestation_result))
    }
}
