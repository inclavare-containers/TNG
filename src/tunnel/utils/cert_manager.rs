use anyhow::{Context, Result};
use rats_cert::{
    cert::create::CertBuilder,
    crypto::{AsymmetricAlgo, HashAlgo},
    tee::coco::attester::CocoAttester,
};
use rustls::pki_types::pem::{PemObject, SectionKind};
use std::sync::{Arc, Mutex};
use tokio_graceful::ShutdownGuard;

use crate::config::ra::AttestArgs;

const CERT_UPDATE_INTERVAL_SECOND: usize = 60 * 60; // 1 hour
const CREATE_CERT_TIMEOUT_SECOND: usize = 30;

#[derive(Debug)]
pub struct CertManager {
    latest_cert: Arc<Mutex<Arc<rustls::sign::CertifiedKey>>>,
}

impl CertManager {
    // TODO: make CertManager a singleton for each AttestArgs
    pub async fn create_and_launch(
        attest_args: AttestArgs,
        shutdown_guard: ShutdownGuard,
    ) -> Result<Self> {
        // Fetch the cert first time
        let certed_key = {
            let attest_args = attest_args.clone();
            tokio::task::spawn_blocking(move || -> Result<_> {
                Self::update_cert_blocking(attest_args)
            })
            .await??
        };

        let latest_cert = Arc::new(Mutex::new(certed_key));

        // TODO: terminate the task when CertManager is dropped
        {
            let latest_cert = latest_cert.clone();
            shutdown_guard.spawn_task_fn(|shutdown_guard| async move {
                loop {
                    let attest_args = attest_args.clone();
                    let latest_cert = latest_cert.clone();
                    let join_handle =
                        tokio::task::spawn_blocking(move || -> Result<_, anyhow::Error> {
                            let certed_key: Arc<rustls::sign::CertifiedKey> =
                                Self::update_cert_blocking(attest_args)?;
                            *latest_cert.lock().unwrap() = certed_key;
                            Ok(())
                        });

                    let abort_handle = join_handle.abort_handle();
                    tokio::select! {
                        _ = shutdown_guard.cancelled() => {
                            abort_handle.abort();
                            break;
                        }
                        result = join_handle => {
                            result??;
                        }
                    }

                    // Update every hour
                    tokio::time::sleep(tokio::time::Duration::from_secs(
                        CERT_UPDATE_INTERVAL_SECOND as u64,
                    ))
                    .await;
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            });
        }

        Ok(Self { latest_cert })
    }

    fn update_cert_blocking(attest_args: AttestArgs) -> Result<Arc<rustls::sign::CertifiedKey>> {
        let coco_attester = CocoAttester::new_with_timeout_nano(
            &attest_args.aa_addr,
            (CREATE_CERT_TIMEOUT_SECOND as i64) * 1000 * 1000 * 1000,
        )?;
        let cert = CertBuilder::new(coco_attester, HashAlgo::Sha256)
            .with_subject("CN=TNG,O=Inclavare Containers")
            .build(AsymmetricAlgo::P256)?;

        let der_cert = cert.cert_to_der()?;
        let privkey = cert.private_key().to_pkcs8_pem()?;
        let crypto_provider = rustls::crypto::CryptoProvider::get_default()
            .context("rustls crypto provider not installed")?;
        let certified_key = rustls::sign::CertifiedKey::new(
            vec![rustls::pki_types::CertificateDer::from(der_cert)],
            crypto_provider.key_provider.load_private_key(
                rustls::pki_types::PrivateKeyDer::from_pem(
                    SectionKind::PrivateKey,
                    privkey.as_bytes().into(),
                )
                .context("bug")?,
            )?,
        );
        Ok(Arc::new(certified_key))
    }

    pub fn get_latest_cert(&self) -> Arc<rustls::sign::CertifiedKey> {
        self.latest_cert.lock().unwrap().clone()
    }
}
