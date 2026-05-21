use std::sync::Arc;

use crate::tunnel::{
    attestation_result::AttestationResult,
    utils::rustls_config::{RustlsDummyCert, TlsConfigGenerator},
};
use anyhow::{Context as _, Result};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use super::cert_verifier::TngClientCertVerifier;

impl TlsConfigGenerator {
    pub async fn get_one_time_rustls_server_config(&self) -> Result<OnetimeTlsServerConfig> {
        let mut config = match self {
            TlsConfigGenerator::NoRa => {
                let tls_server_config =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                OnetimeTlsServerConfig(tls_server_config, None)
            }
            TlsConfigGenerator::Verify(verify_ctx) => {
                let verifier = Arc::new(TngClientCertVerifier::new(verify_ctx.clone())?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier.clone())
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                OnetimeTlsServerConfig(tls_server_config, Some(verifier))
            }
            TlsConfigGenerator::Attest(cert_manager) => {
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                OnetimeTlsServerConfig(tls_server_config, None)
            }
            TlsConfigGenerator::AttestAndVerify(cert_manager, verify_ctx) => {
                let verifier = Arc::new(TngClientCertVerifier::new(verify_ctx.clone())?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier.clone())
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                OnetimeTlsServerConfig(tls_server_config, Some(verifier))
            }
        };
        config.0.alpn_protocols = vec![b"h2".to_vec()];

        Ok(config)
    }
}

/// Bundled TLS server config with post-handshake verifier.
///
/// The verifier field is private — callers must use [`Self::handshake_with_stream`]
/// to perform the TLS handshake followed by `verity_pending_cert`, ensuring the
/// attestation check cannot be accidentally skipped.
pub struct OnetimeTlsServerConfig(pub rustls::ServerConfig, Option<Arc<TngClientCertVerifier>>);

impl OnetimeTlsServerConfig {
    /// Perform TLS handshake on an already-connected stream, then verify
    /// the peer certificate if a verifier was configured.
    ///
    /// This bundles the two steps that must always occur together:
    /// 1. TLS accept/handshake (which stores the peer cert in the verifier)
    /// 2. `verity_pending_cert` (which validates the stored cert)
    pub async fn handshake_with_stream<S>(
        self,
        stream: S,
    ) -> Result<(
        tokio_rustls::server::TlsStream<S>,
        Option<AttestationResult>,
    )>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let tls_acceptor = TlsAcceptor::from(Arc::new(self.0));
        let tls_stream = tls_acceptor
            .accept(stream)
            .await
            .context("Failed to accept TLS connection")?;

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
