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

/// On Linux, kTLS needs the negotiated key material extractable so it can be
/// installed in-kernel via `setsockopt(TLS_TX/TLS_RX)`. No-op on non-Linux
/// (kTLS is absent there). Not gated by the resolved kTLS tier: the config is
/// built once and shared/pooled across connections before per-link kTLS
/// resolution, so the tier is not known at config-build time. Setting the flag
/// unconditionally on Linux matches the prior inline sites; gating by
/// `engages()` is deferred to a per-link-config change.
#[cfg(target_os = "linux")]
pub fn enable_secret_extraction_client(config: &mut rustls::ClientConfig) {
    config.enable_secret_extraction = true;
}

#[cfg(not(target_os = "linux"))]
pub fn enable_secret_extraction_client(_config: &mut rustls::ClientConfig) {}

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

                enable_secret_extraction_client(&mut tls_client_config);

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

                enable_secret_extraction_client(&mut tls_client_config);

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
                enable_secret_extraction_client(&mut tls_client_config);
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

                enable_secret_extraction_client(&mut tls_client_config);

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
    ///
    /// Takes the peer as an `EndpointAddr` rather than a pre-formatted string so that
    /// IPv4 addresses become `ServerName::IpAddress` directly (no allocation) and
    /// domains become `ServerName::DnsName` from the borrowed string.
    pub async fn handshake_with_stream<S>(
        self,
        server_name: &crate::tunnel::endpoint::EndpointAddr,
        stream: S,
    ) -> Result<(
        tokio_rustls::client::TlsStream<S>,
        Option<crate::tunnel::attestation_result::AttestationResult>,
    )>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        use rustls::pki_types::{DnsName, IpAddr, ServerName};

        // Build the borrowing `ServerName` from the structured address: IPv4 →
        // `IpAddress` (no string allocation), domain → `DnsName` from the
        // borrowed string. `to_owned()` then lifts it to `ServerName<'static>`
        // (a cheap IpAddr copy for IPv4; an owned copy of the DNS name for
        // domains, which is unavoidable for the async connect future).
        let server_name = match server_name {
            crate::tunnel::endpoint::EndpointAddr::Ipv4(ip) => {
                ServerName::IpAddress(IpAddr::V4((*ip).into()))
            }
            crate::tunnel::endpoint::EndpointAddr::Domain(d) => ServerName::DnsName(
                DnsName::try_from(d.as_str())
                    .with_context(|| format!("Invalid server name for TLS handshake ({d})"))?,
            ),
        };

        let tls_stream = tokio_rustls::TlsConnector::from(std::sync::Arc::new(self.0))
            .connect(server_name.to_owned(), stream)
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

                enable_secret_extraction_client(&mut tls_client_config);

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

                enable_secret_extraction_client(&mut tls_client_config);

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
                enable_secret_extraction_client(&mut tls_client_config);
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

                enable_secret_extraction_client(&mut tls_client_config);

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
