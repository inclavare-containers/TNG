//! Rustls server certificate verifier that validates the peer using remote attestation
//! ([`TngCommonCertVerifier`]) when the client is configured to verify the server.

use std::sync::Arc;

use anyhow::Result;
use rustls::client::{danger::ServerCertVerified, WebPkiServerVerifier};
use tokio_rustls::rustls::RootCertStore;

use crate::tunnel::{
    attestation_result::AttestationResult,
    ra_context::VerifyContext,
    utils::rustls::{
        dummy::TNG_DUMMY_CERT,
        ra::cert_cache::CertVerifyCache,
        ra::common::{BlockingCertVerifier, LazyCertVerifier},
    },
};

fn webpki_server_verifier() -> Result<Arc<WebPkiServerVerifier>, anyhow::Error> {
    let mut cert = TNG_DUMMY_CERT.as_bytes();
    let certs = rustls_pemfile::certs(&mut cert).collect::<Result<Vec<_>, _>>()?;
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(certs);
    Ok(WebPkiServerVerifier::builder(Arc::new(roots)).build()?)
}

#[derive(Debug)]
pub struct LazyServerCertVerifier(Arc<WebPkiServerVerifier>, LazyCertVerifier);

impl LazyServerCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>, cache: Arc<CertVerifyCache>) -> Result<Self> {
        Ok(Self(
            webpki_server_verifier()?,
            LazyCertVerifier::new(verify_ctx, cache),
        ))
    }

    /// Borrow the inner stateless lazy verifier so callers can pass a uniform
    /// `&LazyCertVerifier` to `classify_attestation` regardless of whether the
    /// wrapper is the client- or server-side cert verifier.
    pub fn lazy_verifier(&self) -> &LazyCertVerifier {
        &self.1
    }
}

impl rustls::client::danger::ServerCertVerifier for LazyServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // No-op: the cert is fetched and verified post-handshake via
        // `peer_certificates()`. Returning success here without storing state
        // keeps the verifier stateless so one Arc can be shared across
        // handshakes, which rustls requires (`Weak::ptr_eq`) for resumption.
        Ok(ServerCertVerified::assertion())
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
pub struct BlockingServerCertVerifier(Arc<WebPkiServerVerifier>, BlockingCertVerifier);

impl BlockingServerCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>, cache: Arc<CertVerifyCache>) -> Result<Self> {
        Ok(Self(
            webpki_server_verifier()?,
            BlockingCertVerifier::new(verify_ctx, cache),
        ))
    }
}

#[cfg(not(wasm))]
impl rustls::client::danger::ServerCertVerifier for BlockingServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let _: AttestationResult = self.1.verify_cert_blocking(end_entity).map_err(|error| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
                Arc::from(error.into_boxed_dyn_error()),
            )))
        })?;

        Ok(ServerCertVerified::assertion())
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
