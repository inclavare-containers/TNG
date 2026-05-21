mod alpn;

use std::sync::Arc;

use crate::tunnel::ra_context::{RaContext, VerifyContext};
use crate::tunnel::utils::rustls::dummy::{DummyServerCertVerifier, TNG_DUMMY_CERT, TNG_DUMMY_KEY};
use crate::tunnel::utils::{cert_manager::CertManager, runtime::TokioRuntime};
use anyhow::{Context as _, Result};
use rustls::RootCertStore;

pub use alpn::Alpn;

use super::ra::client_cert_verifier::LazyClientCertVerifier;
use super::ra::server_cert_verifier::LazyServerCertVerifier;

#[derive(Clone, Copy)]
pub struct RustlsDummyCert {}

impl RustlsDummyCert {
    pub fn new_rustls_cert() -> Result<Arc<rustls::sign::SingleCertAndKey>> {
        let cert_chain =
            rustls_pemfile::certs(&mut TNG_DUMMY_CERT.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        let key_der = rustls_pemfile::private_key(&mut TNG_DUMMY_KEY.as_bytes())?
            .context("No private key found")?;
        let crypto_provider = rustls::crypto::CryptoProvider::get_default()
            .context("rustls crypto provider not installed")?;

        let certified_key =
            rustls::sign::CertifiedKey::from_der(cert_chain, key_der, crypto_provider)?;

        Ok(Arc::new(rustls::sign::SingleCertAndKey::from(
            certified_key,
        )))
    }
}

pub enum TlsConfigGenerator {
    NoRa,
    Verify(Arc<VerifyContext>),
    #[cfg(unix)]
    Attest(Arc<CertManager>),
    #[cfg(unix)]
    AttestAndVerify(Arc<CertManager>, Arc<VerifyContext>),
}

impl TlsConfigGenerator {
    pub async fn new(ra_context: Arc<RaContext>, runtime: TokioRuntime) -> Result<Self> {
        Ok(match ra_context.as_ref() {
            RaContext::AttestOnly(attest_ctx) => Self::Attest(Arc::new(
                CertManager::new(attest_ctx.clone(), runtime).await?,
            )),
            RaContext::VerifyOnly(verify_ctx) => Self::Verify(verify_ctx.clone()),
            RaContext::AttestAndVerify { attest, verify } => Self::AttestAndVerify(
                Arc::new(CertManager::new(attest.clone(), runtime).await?),
                verify.clone(),
            ),
            RaContext::NoRa => Self::NoRa,
        })
    }
}

// ── Client config ──────────────────────────────────────────────────────────

pub struct LazyOnetimeTlsClientConfig(
    pub rustls::ClientConfig,
    pub Option<Arc<LazyServerCertVerifier>>,
);

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

impl TlsConfigGenerator {
    pub async fn get_lazy_one_time_rustls_client_config(
        &self,
        alpn: Alpn,
    ) -> Result<LazyOnetimeTlsClientConfig> {
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
                        .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
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
                        .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));

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

// ── Server config ──────────────────────────────────────────────────────────

use rustls::ServerConfig;

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
            #[cfg(unix)]
            TlsConfigGenerator::Attest(cert_manager) => {
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                LazyOnetimeTlsServerConfig(tls_server_config, None)
            }
            #[cfg(unix)]
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
