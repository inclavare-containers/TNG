use std::sync::Arc;

use crate::config::ra::{RaArgs, RaArgsUnchecked, VerifyArgs};
use crate::tunnel::utils::runtime::TokioRuntime;
use anyhow::{bail, Context as _, Result};

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
    #[cfg(unix)]
    Attest(Arc<super::cert_manager::CertManager>),
    #[cfg(unix)]
    AttestAndVerify(Arc<super::cert_manager::CertManager>, VerifyArgs),
}

impl TlsConfigGenerator {
    pub async fn new(ra_args: RaArgs) -> Result<Self> {
        Ok(match &ra_args {
            RaArgs::AttestOnly(attest) => {
                #[cfg(unix)]
                {
                    use super::cert_manager::CertManager;
                    Self::Attest(Arc::new(CertManager::new(attest.clone()).await?))
                }
                #[cfg(wasm)]
                {
                    let _ = attest;
                    bail!("`attest` option is not supported since attestation is not supported on this platform.")
                }
            }
            RaArgs::VerifyOnly(verify) => Self::Verify(verify.clone()),
            RaArgs::AttestAndVerify(attest, verify) => {
                #[cfg(unix)]
                {
                    use super::cert_manager::CertManager;

                    Self::AttestAndVerify(
                        Arc::new(CertManager::new(attest.clone()).await?),
                        verify.clone(),
                    )
                }
                #[cfg(wasm)]
                {
                    let _ = attest;
                    let _ = verify;

                    bail!("`attest` option is not supported since attestation is not supported on this platform.")
                }
            }
            RaArgs::NoRa => Self::NoRa,
        })
    }

    pub async fn prepare(&self, runtime: TokioRuntime) -> Result<()> {
        match &self {
            #[cfg(unix)]
            TlsConfigGenerator::Attest(cert_manager)
            | TlsConfigGenerator::AttestAndVerify(cert_manager, _) => {
                cert_manager
                    .launch_refresh_task_if_required(runtime)
                    .await?
            }
            _ => {
                let _ = runtime;
                /* Nothing */
            }
        }

        Ok(())
    }
}
