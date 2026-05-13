use std::sync::Arc;

use anyhow::{Context as _, Result};
use rustls::ServerConfig;

use crate::tunnel::utils::rustls::{
    config::{alpn::Alpn, TlsConfigGenerator},
    dummy::RustlsDummyCert,
    ra::client_cert_verifier::LazyClientCertVerifier,
};

impl TlsConfigGenerator {
    pub async fn get_lazy_one_time_rustls_server_config(
        &self,
        alpn: Alpn,
    ) -> Result<LazyOnetimeTlsServerConfig> {
        let mut config = match self {
            TlsConfigGenerator::NoRa => {
                let tls_server_config =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                LazyOnetimeTlsServerConfig(tls_server_config, None)
            }
            TlsConfigGenerator::Verify(verify_ctx) => {
                let verifier = Arc::new(LazyClientCertVerifier::new(verify_ctx.clone())?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier.clone())
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                LazyOnetimeTlsServerConfig(tls_server_config, Some(verifier))
            }
            TlsConfigGenerator::Attest(cert_manager) => {
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                LazyOnetimeTlsServerConfig(tls_server_config, None)
            }
            TlsConfigGenerator::AttestAndVerify(cert_manager, verify_ctx) => {
                let verifier = Arc::new(LazyClientCertVerifier::new(verify_ctx.clone())?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier.clone())
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                LazyOnetimeTlsServerConfig(tls_server_config, Some(verifier))
            }
        };
        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }
}

pub struct LazyOnetimeTlsServerConfig(
    pub rustls::ServerConfig,
    pub Option<Arc<LazyClientCertVerifier>>,
);

impl LazyOnetimeTlsServerConfig {
    /// Perform TLS handshake then verify the peer certificate if a verifier was configured.
    pub async fn handshake_with_stream<S>(
        self,
        stream: S,
    ) -> Result<(
        tokio_rustls::server::TlsStream<S>,
        Option<crate::tunnel::attestation_result::AttestationResult>,
    )>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(self.0));
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

#[cfg(not(wasm))]
impl TlsConfigGenerator {
    pub async fn get_blocking_one_time_rustls_server_config(
        &self,
        alpn: Alpn,
    ) -> Result<BlockingOnetimeTlsServerConfig> {
        use crate::tunnel::utils::rustls::ra::client_cert_verifier::BlockingClientCertVerifier;

        let mut config = match self {
            TlsConfigGenerator::NoRa => {
                let tls_server_config =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
            TlsConfigGenerator::Verify(verify_ctx) => {
                let verifier = Arc::new(BlockingClientCertVerifier::new(verify_ctx.clone())?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier)
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
            TlsConfigGenerator::Attest(cert_manager) => {
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
            TlsConfigGenerator::AttestAndVerify(cert_manager, verify_ctx) => {
                let verifier = Arc::new(BlockingClientCertVerifier::new(verify_ctx.clone())?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier)
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
        };
        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }
}

#[cfg(not(wasm))]
pub struct BlockingOnetimeTlsServerConfig(pub rustls::ServerConfig);
