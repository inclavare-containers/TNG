use std::sync::Arc;

use rustls::client::ResolvesClientCert;

use crate::tunnel::utils::cert_manager::CertManager;

#[derive(Debug)]
pub struct CoCoClientCertResolver {
    cert_manager: Arc<CertManager>,
}

impl CoCoClientCertResolver {
    pub fn new(cert_manager: Arc<CertManager>) -> Self {
        Self { cert_manager }
    }
}

impl ResolvesClientCert for CoCoClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        Some(self.cert_manager.get_latest_cert())
    }

    fn has_certs(&self) -> bool {
        true
    }
}
