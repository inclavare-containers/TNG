pub mod verifier;

use anyhow::{Context as _, Result};
use std::sync::Arc;

pub const TNG_DUMMY_CERT: &str = include_str!("servercert.pem");
#[allow(dead_code)]
pub const TNG_DUMMY_KEY: &str = include_str!("serverkey.pem");

#[derive(Clone, Copy)]
pub struct RustlsDummyCert {}

impl RustlsDummyCert {
    pub fn new_rustls_cert() -> Result<Arc<rustls::sign::SingleCertAndKey>> {
        let cert_chain =
            rustls_pemfile::certs(&mut TNG_DUMMY_CERT.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        let key_der = rustls_pemfile::private_key(&mut TNG_DUMMY_KEY.as_bytes())?
            .context("No private key found")?;
        let crypto_provider = rustls::crypto::CryptoProvider::get_default()
            .context("rustls crypto provider not installed")?;

        let certified_key =
            rustls::sign::CertifiedKey::from_der(cert_chain, key_der, crypto_provider)?;

        Ok(Arc::new(rustls::sign::SingleCertAndKey::from(
            certified_key,
        )))
    }
}
