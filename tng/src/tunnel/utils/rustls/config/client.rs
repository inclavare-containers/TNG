#[cfg(not(wasm))]
use std::sync::Arc;

#[cfg(not(wasm))]
use anyhow::{Context as _, Result};
#[cfg(not(wasm))]
use rustls::RootCertStore;

#[cfg(unix)]
use crate::tunnel::utils::cert_manager::DynamicCertResolver;
#[cfg(not(wasm))]
use crate::tunnel::utils::rustls::{
    config::{alpn::Alpn, TlsConfigGenerator},
    dummy::verifier::DummyServerCertVerifier,
    ra::server_cert_verifier::LazyServerCertVerifier,
};

#[cfg(not(wasm))]
impl TlsConfigGenerator {
    pub async fn get_lazy_one_time_rustls_client_config(
        &self,
        alpn: Alpn,
    ) -> Result<LazyOnetimeTlsClientConfig> {
        let mut config = match self {
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

                LazyOnetimeTlsClientConfig(tls_client_config, None)
            }
            TlsConfigGenerator::Verify(verify_ctx) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_no_client_auth();

                let verifier: Arc<LazyServerCertVerifier> =
                    Arc::new(LazyServerCertVerifier::new(verify_ctx.clone())?);
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                LazyOnetimeTlsClientConfig(tls_client_config, Some(verifier))
            }
            #[cfg(unix)]
            TlsConfigGenerator::Attest(cert_manager) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_client_cert_resolver(Arc::new(
                        DynamicCertResolver::new(cert_manager.clone()),
                    ));
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                LazyOnetimeTlsClientConfig(tls_client_config, None)
            }
            #[cfg(unix)]
            TlsConfigGenerator::AttestAndVerify(cert_manager, verify_ctx) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_client_cert_resolver(Arc::new(
                        DynamicCertResolver::new(cert_manager.clone()),
                    ));

                let verifier: Arc<LazyServerCertVerifier> =
                    Arc::new(LazyServerCertVerifier::new(verify_ctx.clone())?);
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                LazyOnetimeTlsClientConfig(tls_client_config, Some(verifier))
            }
        };

        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }
}

#[cfg(not(wasm))]
pub struct LazyOnetimeTlsClientConfig(rustls::ClientConfig, Option<Arc<LazyServerCertVerifier>>);

#[cfg(not(wasm))]
impl LazyOnetimeTlsClientConfig {
    /// Perform TLS handshake then verify the peer certificate if a verifier was configured.
    pub async fn handshake_with_stream<S>(
        self,
        server_name: &str,
        stream: S,
    ) -> Result<(
        tokio_rustls::client::TlsStream<S>,
        Option<crate::tunnel::attestation_result::AttestationResult>,
    )>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        use rustls::pki_types::ServerName;

        let tls_stream = tokio_rustls::TlsConnector::from(std::sync::Arc::new(self.0))
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

#[cfg(not(wasm))]
impl TlsConfigGenerator {
    pub async fn get_blocking_one_time_rustls_client_config(
        &self,
        alpn: Alpn,
    ) -> Result<BlockingOnetimeTlsClientConfig> {
        use crate::tunnel::utils::rustls::ra::server_cert_verifier::BlockingServerCertVerifier;

        let mut config = match self {
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

                BlockingOnetimeTlsClientConfig(tls_client_config)
            }
            TlsConfigGenerator::Verify(verify_ctx) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_no_client_auth();

                let verifier: Arc<BlockingServerCertVerifier> =
                    Arc::new(BlockingServerCertVerifier::new(verify_ctx.clone())?);
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                BlockingOnetimeTlsClientConfig(tls_client_config)
            }
            #[cfg(unix)]
            TlsConfigGenerator::Attest(cert_manager) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_client_cert_resolver(Arc::new(
                        DynamicCertResolver::new(cert_manager.clone()),
                    ));
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                BlockingOnetimeTlsClientConfig(tls_client_config)
            }
            #[cfg(unix)]
            TlsConfigGenerator::AttestAndVerify(cert_manager, verify_ctx) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_client_cert_resolver(Arc::new(
                        DynamicCertResolver::new(cert_manager.clone()),
                    ));

                let verifier: Arc<BlockingServerCertVerifier> =
                    Arc::new(BlockingServerCertVerifier::new(verify_ctx.clone())?);
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                BlockingOnetimeTlsClientConfig(tls_client_config)
            }
        };

        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }
}

#[cfg(not(wasm))]
pub struct BlockingOnetimeTlsClientConfig(pub rustls::ClientConfig);
