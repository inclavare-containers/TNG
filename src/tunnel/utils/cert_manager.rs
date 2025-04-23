use again::RetryPolicy;
use anyhow::{anyhow, Context as _, Result};
use rats_cert::{
    cert::create::CertBuilder,
    crypto::{AsymmetricAlgo, HashAlgo},
    tee::coco::attester::CocoAttester,
};
use scopeguard::defer;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

use crate::config::ra::AttestArgs;

const CERT_UPDATE_INTERVAL_SECOND: usize = 60 * 60; // 1 hour
const CREATE_CERT_TIMEOUT_SECOND: usize = 120; // 2 min

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
                Self::update_cert_blocking(&attest_args)
            })
            .await??
        };

        let latest_cert = Arc::new(Mutex::new(certed_key));

        // TODO: terminate the task when CertManager is dropped
        {
            let latest_cert = latest_cert.clone();
            let span = Span::current();
            shutdown_guard.spawn_task_fn(|shutdown_guard| {
                async move {
                    let res = async {
                        loop {
                            // Update certs in loop
                            tokio::select! {
                                _ = shutdown_guard.cancelled() => {
                                    break;
                                }
                                _ = tokio::time::sleep(tokio::time::Duration::from_secs(
                                    CERT_UPDATE_INTERVAL_SECOND as u64,
                                )) => {}
                            }

                            let retry_policy =
                                RetryPolicy::fixed(Duration::from_secs(1)).with_max_retries(3);
                            let update_cert_result = retry_policy.retry(|| {
                                let attest_args = attest_args.clone();
                                let latest_cert = latest_cert.clone();
                                async {
                                    let join_handle = tokio::task::spawn_blocking(
                                        move || -> Result<_, anyhow::Error> {
                                            let certed_key: Arc<rustls::sign::CertifiedKey> =
                                                Self::update_cert_blocking(&attest_args)?;

                                            let mut lock = latest_cert.lock().map_err(|e| {
                                                anyhow!("Failed to get lock: {e:#}")
                                            })?;
                                            *lock = certed_key;

                                            Ok(())
                                        },
                                    );
                                    let abort_handle = join_handle.abort_handle();
                                    defer! {
                                        abort_handle.abort();
                                    }
                                    join_handle
                                        .await
                                        .map_err(anyhow::Error::from)
                                        .and_then(|r| r)
                                }
                            });

                            tokio::select! {
                                _ = shutdown_guard.cancelled() => {
                                    break;
                                }
                                result = update_cert_result => {
                                    if let Err(e) = result {
                                        tracing::error!(error=?e,"Failed to update cert");
                                    }
                                }
                            }
                        }
                        #[allow(unreachable_code)]
                        Ok::<(), anyhow::Error>(())
                    }
                    .await;

                    if let Err(e) = res {
                        tracing::error!("Failed to update cert: {:#}", e);
                    }
                }
                .instrument(span)
            });
        }

        Ok(Self { latest_cert })
    }

    fn update_cert_blocking(attest_args: &AttestArgs) -> Result<Arc<rustls::sign::CertifiedKey>> {
        let timeout_sec = CREATE_CERT_TIMEOUT_SECOND as i64;
        tracing::trace!(
            aa_addr = &attest_args.aa_addr,
            timeout_sec,
            "Generate new cert with rats-rs"
        );
        let coco_attester = CocoAttester::new_with_timeout_nano(
            &attest_args.aa_addr,
            timeout_sec * 1000 * 1000 * 1000,
        )?;
        let cert = CertBuilder::new(coco_attester, HashAlgo::Sha256)
            .with_subject("CN=TNG,O=Inclavare Containers")
            .build(AsymmetricAlgo::P256)?;

        let der_cert = cert.cert_to_der()?;
        let privkey = cert.private_key().to_pkcs8_pem()?;
        tracing::trace!(
            cert = cert.cert_to_pem()?,
            timeout_sec,
            "Generated new cert"
        );

        let crypto_provider = rustls::crypto::CryptoProvider::get_default()
            .context("rustls crypto provider not installed")?;
        let certified_key = rustls::sign::CertifiedKey::new(
            vec![rustls::pki_types::CertificateDer::from(der_cert)],
            crypto_provider.key_provider.load_private_key(
                rustls_pemfile::private_key(&mut privkey.as_bytes())?
                    .context("No private key found")?,
            )?,
        );
        Ok(Arc::new(certified_key))
    }

    pub fn get_latest_cert(&self) -> Option<Arc<rustls::sign::CertifiedKey>> {
        match self.latest_cert.lock() {
            Ok(v) => Some(v.clone()),
            Err(e) => {
                tracing::error!(error=?e, "Failed to get latest cert");
                None
            }
        }
    }
}
