use std::sync::Arc;

use anyhow::Result;
use rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::RootCertStore;

use super::TNG_DUMMY_CERT;

#[derive(Debug)]
pub struct DummyServerCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl DummyServerCertVerifier {
    pub fn new() -> Result<Self> {
        let mut cert = TNG_DUMMY_CERT.as_bytes();
        let certs = rustls_pemfile::certs(&mut cert).collect::<Result<Vec<_>, _>>()?;
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(certs);
        /* The WebPkiServerVerifier requires that the root certs not empty, or it will failed with 'no root trust anchors were provided'. So let's put a dummy cert here as a root cert to make WebPkiServerVerifier happy. */
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots)).build()?;
        Ok(Self { inner: verifier })
    }
}

impl rustls::client::danger::ServerCertVerifier for DummyServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
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

/// A `ResolvesClientCert` that never presents a client certificate.
///
/// Stateless so it can be shared as one `Arc` across handshakes. rustls gates
/// client-side TLS 1.3 resumption on `Weak::ptr_eq` of the
/// `ResolvesClientCert` (`persist.rs`), so the no-client-auth modes (NoRa,
/// Verify) must reuse a single `Arc<NoClientCertResolver>` per generator
/// rather than calling `with_no_client_auth()` (which builds a fresh
/// `FailResolveClientCert` each call and breaks resumption).
#[derive(Debug)]
pub struct NoClientCertResolver;

impl rustls::client::ResolvesClientCert for NoClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}
