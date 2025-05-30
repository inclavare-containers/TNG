use std::sync::Arc;

use crate::{
    config::ra::{RaArgs, VerifyArgs},
    tunnel::utils::cert_manager::CertManager,
};
use anyhow::{bail, Context as _, Result};
use tokio_graceful::ShutdownGuard;

use super::certs::{TNG_DUMMY_CERT, TNG_DUMMY_KEY};

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

pub enum TlsConfigGenerator {
    NoRa,
    Verify(VerifyArgs),
    Attest(Arc<CertManager>),
    AttestAndVerify(Arc<CertManager>, VerifyArgs),
}

impl TlsConfigGenerator {
    pub async fn new(ra_args: &RaArgs) -> Result<Self> {
        Ok(if ra_args.no_ra {
            // Sanity check for ra_args
            if ra_args.verify.is_some() {
                bail!("The 'no_ra: true' flag should not be used with 'verify' field");
            }

            if ra_args.attest.is_some() {
                bail!("The 'no_ra: true' flag should not be used with 'attest' field");
            }

            tracing::warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment");

            Self::NoRa
        } else {
            match (&ra_args.attest, &ra_args.verify) {
                (None, None) => {
                    bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_egress'");
                }
                (None, Some(verfiy)) => Self::Verify(verfiy.clone()),
                (Some(attest), None) => {
                    Self::Attest(Arc::new(CertManager::new(attest.clone()).await?))
                }
                (Some(attest), Some(verfiy)) => Self::AttestAndVerify(
                    Arc::new(CertManager::new(attest.clone()).await?),
                    verfiy.clone(),
                ),
            }
        })
    }

    pub async fn prepare(&self, shutdown_guard: ShutdownGuard) -> Result<()> {
        match &self {
            TlsConfigGenerator::Attest(cert_manager)
            | TlsConfigGenerator::AttestAndVerify(cert_manager, _) => {
                cert_manager
                    .launch_refresh_task_if_required(shutdown_guard)
                    .await?
            }
            _ => { /* Nothing */ }
        }

        Ok(())
    }
}
