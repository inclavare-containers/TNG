use std::sync::Arc;

use crate::tunnel::utils::rustls_config::TlsConfigGenerator;
use anyhow::Result;
use rustls::RootCertStore;

use super::cert_verifier::{coco::CoCoServerCertVerifier, dummy::DummyServerCertVerifier};

impl TlsConfigGenerator {
    pub async fn get_one_time_rustls_client_config(&self) -> Result<OnetimeTlsClientConfig> {
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

                Ok(OnetimeTlsClientConfig(tls_client_config, None))
            }
            TlsConfigGenerator::Verify(verify_args) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_no_client_auth();

                let verifier: Arc<CoCoServerCertVerifier> =
                    Arc::new(CoCoServerCertVerifier::new(verify_args.clone())?);
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                Ok(OnetimeTlsClientConfig(tls_client_config, Some(verifier)))
            }
            TlsConfigGenerator::Attest(cert_manager) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_client_cert_resolver(Arc::new(
                        rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        ),
                    ));
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                Ok(OnetimeTlsClientConfig(tls_client_config, None))
            }
            TlsConfigGenerator::AttestAndVerify(cert_manager, verify_args) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_client_cert_resolver(Arc::new(
                        rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        ),
                    ));

                let verifier: Arc<CoCoServerCertVerifier> =
                    Arc::new(CoCoServerCertVerifier::new(verify_args.clone())?);
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                Ok(OnetimeTlsClientConfig(tls_client_config, Some(verifier)))
            }
        }
    }
}

pub struct OnetimeTlsClientConfig(
    pub rustls::ClientConfig,
    pub Option<Arc<CoCoServerCertVerifier>>,
);
