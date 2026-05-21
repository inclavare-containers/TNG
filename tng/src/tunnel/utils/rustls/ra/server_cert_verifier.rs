use std::sync::Arc;

use anyhow::Result;
use rustls::client::{danger::ServerCertVerified, WebPkiServerVerifier};
use tokio_rustls::rustls::RootCertStore;

use crate::tunnel::{
    attestation_result::AttestationResult,
    ra_context::VerifyContext,
    utils::rustls::{dummy::TNG_DUMMY_CERT, ra::common::LazyCertVerifier},
};

#[derive(Debug)]
pub struct LazyServerCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
    common: LazyCertVerifier,
}

impl LazyServerCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>) -> Result<Self> {
        let mut cert = TNG_DUMMY_CERT.as_bytes();
        let certs = rustls_pemfile::certs(&mut cert).collect::<Result<Vec<_>, _>>()?;
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(certs);
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots)).build()?;

        Ok(Self {
            inner: verifier,
            common: LazyCertVerifier::new(verify_ctx),
        })
    }

    pub async fn verity_pending_cert(&self) -> Result<AttestationResult> {
        self.common.verify_pending_cert().await
    }
}

impl rustls::client::danger::ServerCertVerifier for LazyServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.common
            .set_to_pending_cert(end_entity)
            .map(|_| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
