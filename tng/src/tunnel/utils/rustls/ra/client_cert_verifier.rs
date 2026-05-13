use std::sync::Arc;

use anyhow::Result;
use rustls::server::{
    danger::{ClientCertVerified, ClientCertVerifier},
    WebPkiClientVerifier,
};
use tokio_rustls::rustls::RootCertStore;

use crate::tunnel::{
    attestation_result::AttestationResult,
    ra_context::VerifyContext,
    utils::rustls::{
        dummy::TNG_DUMMY_CERT,
        ra::common::{BlockingCertVerifier, LazyCertVerifier},
    },
};

fn webpki_client_verifier() -> Result<Arc<dyn ClientCertVerifier>, anyhow::Error> {
    let mut cert = TNG_DUMMY_CERT.as_bytes();
    let certs = rustls_pemfile::certs(&mut cert).collect::<Result<Vec<_>, _>>()?;
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(certs);
    Ok(WebPkiClientVerifier::builder(Arc::new(roots)).build()?)
}

#[derive(Debug)]
pub struct LazyClientCertVerifier(Arc<dyn ClientCertVerifier>, LazyCertVerifier);

impl LazyClientCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>) -> Result<Self> {
        Ok(Self(
            webpki_client_verifier()?,
            LazyCertVerifier::new(verify_ctx),
        ))
    }

    pub async fn verity_pending_cert(&self) -> Result<AttestationResult> {
        self.1.verify_pending_cert().await
    }
}

impl rustls::server::danger::ClientCertVerifier for LazyClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.1
            .set_to_pending_cert(end_entity)
            .map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

#[cfg(not(wasm))]
#[derive(Debug)]
pub struct BlockingClientCertVerifier(Arc<dyn ClientCertVerifier>, BlockingCertVerifier);

impl BlockingClientCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>) -> Result<Self> {
        Ok(Self(
            webpki_client_verifier()?,
            BlockingCertVerifier::new(verify_ctx),
        ))
    }
}

#[cfg(not(wasm))]
impl rustls::server::danger::ClientCertVerifier for BlockingClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let _: AttestationResult = self.1.verify_cert_blocking(end_entity).map_err(|error| {
            tracing::error!(?error, "Failed to verify client certificate");
            rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
                Arc::from(error.into_boxed_dyn_error()),
            )))
        })?;

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
