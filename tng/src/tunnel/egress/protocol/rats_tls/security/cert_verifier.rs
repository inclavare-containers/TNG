use std::sync::Arc;

use anyhow::Result;
use rustls::{
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        WebPkiClientVerifier,
    },
    Error,
};
use tokio_rustls::rustls::RootCertStore;

use crate::tunnel::{
    attestation_result::AttestationResult, cert_verifier::TngCommonCertVerifier,
    ra_context::VerifyContext, utils::certs::TNG_DUMMY_CERT,
};

#[derive(Debug)]
pub struct TngClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    common: TngCommonCertVerifier,
}

impl TngClientCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>) -> Result<Self> {
        let mut cert = TNG_DUMMY_CERT.as_bytes();
        let certs = rustls_pemfile::certs(&mut cert).collect::<Result<Vec<_>, _>>()?;
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(certs);
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

        Ok(Self {
            inner: verifier,
            common: TngCommonCertVerifier::new(verify_ctx),
        })
    }

    pub async fn verity_pending_cert(&self) -> Result<AttestationResult> {
        self.common.verity_pending_cert().await
    }
}

impl rustls::server::danger::ClientCertVerifier for TngClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, Error> {
        self.common
            .verify_cert(end_entity)
            .map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
