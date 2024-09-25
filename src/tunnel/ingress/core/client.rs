use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use http::{Request, StatusCode};
use hyper::upgrade::Upgraded;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use rustls::client::WebPkiServerVerifier;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::executor::envoy::confgen::ENVOY_DUMMY_CERT;

#[derive(Debug)]
struct NoRaCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl NoRaCertVerifier {
    pub fn new() -> Result<Self> {
        let mut cert = ENVOY_DUMMY_CERT.as_bytes();
        let certs = rustls_pemfile::certs(&mut cert).collect::<Result<Vec<_>, _>>()?;
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(certs);
        /* The WebPkiServerVerifier requires that the root certs not empty, or it will failed with 'no root trust anchors were provided'. So let's put a dummy cert here as a root cert to make WebPkiServerVerifier happy. */
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots)).build()?;
        Ok(Self { inner: verifier })
    }
}

impl rustls::client::danger::ServerCertVerifier for NoRaCertVerifier {
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

pub async fn get_stream_for_addr(host_addr: impl AsRef<str>) -> Result<Upgraded> {
    let host_addr_owned = host_addr.as_ref().to_owned();
    let http_connector = tower::service_fn(move |_dst| {
        let host_addr_owned = host_addr_owned.to_owned(); // TODO: optimize this doulbe clone
        tracing::debug!("Establish TCP connection to '{host_addr_owned}'");

        async {
            TcpStream::connect(host_addr_owned)
                .await
                .map(|s| TokioIo::new(s))
        }
    });

    // TLS client config using the custom CA store for lookups
    let mut tls = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth(); // TODO: use with_client_cert_resolver() to provide client cert
    tls.dangerous()
        .set_certificate_verifier(Arc::new(NoRaCertVerifier::new()?));

    // Prepare the HTTPS connector
    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only() // TODO: support returning notification message on non rats-tls request with https_or_http()
        .enable_http2()
        .wrap_connector(http_connector);

    // Build the hyper client from the HTTPS connector.
    let client = Client::builder(TokioExecutor::new()).build(https_connector);

    let req = Request::connect(
        "https://tng.internal/", /* This is just a placeholder string with no meaning */
    )
    .body(axum::body::Body::empty())
    .unwrap();

    tracing::debug!("Send HTTP/2 CONNECT request to '{}'", host_addr.as_ref(),);
    let mut resp = client
        .request(req)
        .await
        .context("Failed to send HTTP/2 CONNECT request")?;

    if resp.status() != StatusCode::OK {
        bail!(
            "Failed to send HTTP/2 CONNECT request, bad status '{}', got: {:?}",
            resp.status(),
            resp
        );
    }
    let upgraded = hyper::upgrade::on(&mut resp).await.with_context(|| {
        format!(
            "Failed to establish HTTP/2 CONNECT tunnel with '{}'",
            host_addr.as_ref(),
        )
    })?;

    Ok(upgraded)
}
