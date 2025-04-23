use rustls::server::ResolvesServerCert;
use std::sync::Arc;

use crate::tunnel::utils::cert_manager::CertManager;

#[derive(Debug)]
pub struct CoCoServerCertResolver {
    cert_manager: Arc<CertManager>,
}

impl CoCoServerCertResolver {
    pub fn new(cert_manager: Arc<CertManager>) -> Self {
        Self { cert_manager }
    }
}

impl ResolvesServerCert for CoCoServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.cert_manager.get_latest_cert()
    }
}
