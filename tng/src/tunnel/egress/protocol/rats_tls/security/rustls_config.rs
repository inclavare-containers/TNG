use std::sync::Arc;

use crate::tunnel::utils::rustls_config::{RustlsDummyCert, TlsConfigGenerator};
use anyhow::Result;
use rustls::ServerConfig;

use super::cert_verifier::CoCoClientCertVerifier;

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
            TlsConfigGenerator::Verify(verify_args) => {
                let verifier = Arc::new(CoCoClientCertVerifier::new(verify_args.clone())?);
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
            TlsConfigGenerator::AttestAndVerify(cert_manager, verify_args) => {
                let verifier = Arc::new(CoCoClientCertVerifier::new(verify_args.clone())?);
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

pub struct OnetimeTlsServerConfig(
    pub rustls::ServerConfig,
    pub Option<Arc<CoCoClientCertVerifier>>,
);
