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

use crate::{
    config::ra::VerifyArgs,
    executor::envoy::confgen::ENVOY_DUMMY_CERT,
    tunnel::{attestation_result::AttestationResult, cert_verifier::CoCoCommonCertVerifier},
};

#[derive(Debug)]
pub struct CoCoClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    common: CoCoCommonCertVerifier,
}

impl CoCoClientCertVerifier {
    pub fn new(verify: VerifyArgs) -> Result<Self> {
        let mut cert = ENVOY_DUMMY_CERT.as_bytes();
        let certs = rustls_pemfile::certs(&mut cert).collect::<Result<Vec<_>, _>>()?;
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(certs);
        /* The WebPkiServerVerifier requires that the root certs not empty, or it will failed with 'no root trust anchors were provided'. So let's put a dummy cert here as a root cert to make WebPkiServerVerifier happy. */
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

        Ok(Self {
            inner: verifier,
            common: CoCoCommonCertVerifier::new(verify),
        })
    }

    pub async fn get_attestation_result(&self) -> Option<AttestationResult> {
        self.common.get_attestation_result().await
    }
}

impl rustls::server::danger::ClientCertVerifier for CoCoClientCertVerifier {
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
            .map(|_| ClientCertVerified::assertion())
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
