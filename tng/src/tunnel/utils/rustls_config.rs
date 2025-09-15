use std::sync::Arc;

use crate::config::ra::{RaArgs, VerifyArgs};
use crate::tunnel::utils::{cert_manager::CertManager, runtime::TokioRuntime};
use anyhow::{Context as _, Result};

use super::certs::{TNG_DUMMY_CERT, TNG_DUMMY_KEY};

#[allow(unused)]
pub struct RustlsDummyCert {}

impl RustlsDummyCert {
    #[allow(unused)]
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

pub enum TlsConfigGenerator {
    NoRa,
    Verify(VerifyArgs),
    Attest(Arc<super::cert_manager::CertManager>),
    AttestAndVerify(Arc<super::cert_manager::CertManager>, VerifyArgs),
}

impl TlsConfigGenerator {
    pub async fn new(ra_args: RaArgs, runtime: TokioRuntime) -> Result<Self> {
        Ok(match &ra_args {
            RaArgs::AttestOnly(attest) => {
                Self::Attest(Arc::new(CertManager::new(attest.clone(), runtime).await?))
            }
            RaArgs::VerifyOnly(verify) => Self::Verify(verify.clone()),
            RaArgs::AttestAndVerify(attest, verify) => Self::AttestAndVerify(
                Arc::new(CertManager::new(attest.clone(), runtime).await?),
                verify.clone(),
            ),
            RaArgs::NoRa => Self::NoRa,
        })
    }
}
