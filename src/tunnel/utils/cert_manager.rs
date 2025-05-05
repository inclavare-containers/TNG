use again::RetryPolicy;
use anyhow::{bail, Context as _, Result};
use rats_cert::{
    cert::create::CertBuilder,
    crypto::{AsymmetricAlgo, HashAlgo},
    tee::coco::attester::CocoAttester,
};
use scopeguard::defer;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio_graceful::ShutdownGuard;

use crate::config::ra::AttestArgs;
use crate::observability::trace::shutdown_guard_ext::ShutdownGuardExt;

const CERT_REFRESH_INTERVAL_SECOND: u64 = 10 * 60; // 10 minutes
const CREATE_CERT_TIMEOUT_SECOND: u64 = 120; // 2 min

#[derive(Debug)]
pub struct CertManager {
    aa_addr: String,
    strategy: RefreshStrategy,
}

#[derive(Debug)]
pub enum RefreshStrategy {
    Periodically {
        interval: u64,
        latest_cert: (
            tokio::sync::watch::Sender<Arc<rustls::sign::CertifiedKey>>,
            tokio::sync::watch::Receiver<Arc<rustls::sign::CertifiedKey>>,
        ),
        refresh_task: Mutex<Option<RefreshTask>>,
    },
    WhenRequired,
}

#[derive(Debug)]
pub struct RefreshTask {}

impl CertManager {
    pub async fn new(attest_args: AttestArgs) -> Result<Self> {
        // Sanity check for the attest_args.
        let aa_sock_file = attest_args
            .aa_addr
            .strip_prefix("unix:///")
            .context("AA address must start with unix:///")?;
        let aa_sock_file = Path::new("/").join(aa_sock_file);
        if !Path::new(&aa_sock_file).exists() {
            bail!("AA socket file {aa_sock_file:?} not found")
        }

        // Fetch the cert first time
        tracing::info!(aa_addr = attest_args.aa_addr, "Generating new X509 cert");
        let certed_key = Self::fetch_new_cert(&attest_args.aa_addr).await?;

        let refresh_interval = attest_args
            .refresh_interval
            .unwrap_or(CERT_REFRESH_INTERVAL_SECOND);

        let strategy = if refresh_interval == 0 {
            RefreshStrategy::WhenRequired
        } else {
            RefreshStrategy::Periodically {
                interval: refresh_interval,
                latest_cert: tokio::sync::watch::channel(certed_key),
                refresh_task: Mutex::new(None),
            }
        };

        Ok(Self {
            aa_addr: attest_args.aa_addr,
            strategy,
        })
    }

    // TODO: terminate the task when CertManager is dropped

    pub async fn launch_refresh_task_if_required(
        &self,
        shutdown_guard: ShutdownGuard,
    ) -> Result<()> {
        match &self.strategy {
            RefreshStrategy::Periodically {
                interval,
                latest_cert,
                refresh_task,
            } => {
                let mut refresh_task = refresh_task.lock().await;
                if refresh_task.is_some() {
                    bail!("There is already a refresh task has been launched earlier")
                }

                let interval = *interval;
                let aa_addr = self.aa_addr.clone();
                let latest_cert = latest_cert.clone();

                shutdown_guard.spawn_task_fn_current_span(move |shutdown_guard| async move {
                    let res = async {
                        loop {
                            // Update certs in loop
                            let fut = async {
                                tokio::time::sleep(tokio::time::Duration::from_secs(
                                    interval as u64,
                                ))
                                .await;

                                let certed_key = Self::fetch_new_cert(&aa_addr).await?;

                                latest_cert
                                    .0
                                    .send(certed_key)
                                    .context("Failed to set the latest cert")
                            };

                            tokio::select! {
                                _ = shutdown_guard.cancelled() => {
                                    break;
                                }
                                result = fut => {
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
                        tracing::error!(error=?e, "Failed to update cert");
                    }
                });

                *refresh_task = Some(RefreshTask {})
            }
            RefreshStrategy::WhenRequired => {
                // Do nothing
            }
        }

        Ok(())
    }

    async fn fetch_new_cert(aa_addr: &str) -> Result<Arc<rustls::sign::CertifiedKey>> {
        let retry_policy = RetryPolicy::fixed(Duration::from_secs(1)).with_max_retries(3);
        retry_policy
            .retry(|| async {
                let aa_addr = aa_addr.to_owned();

                let join_handle =
                    tokio::task::spawn_blocking(move || -> Result<_, anyhow::Error> {
                        Self::fetch_new_cert_blocking(&aa_addr)
                    });

                let abort_handle = join_handle.abort_handle();
                defer! {
                    abort_handle.abort();
                }
                join_handle
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(|r| r)
                    .context("Failed to generate new cert")
            })
            .await
    }

    fn fetch_new_cert_blocking(aa_addr: &str) -> Result<Arc<rustls::sign::CertifiedKey>> {
        let timeout_sec = CREATE_CERT_TIMEOUT_SECOND as i64;
        tracing::trace!(aa_addr, timeout_sec, "Generate new cert with rats-rs");
        let coco_attester =
            CocoAttester::new_with_timeout_nano(aa_addr, timeout_sec * 1000 * 1000 * 1000)?;
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

    pub async fn get_latest_cert(&self) -> Result<Arc<rustls::sign::CertifiedKey>> {
        match &self.strategy {
            RefreshStrategy::Periodically {
                interval: _,
                latest_cert,
                refresh_task: _,
            } => Ok(latest_cert.1.borrow().clone()),
            RefreshStrategy::WhenRequired => Self::fetch_new_cert(&self.aa_addr).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_cert_gen_with_nonzero_interval() -> Result<()> {
        let mut cert_manager = CertManager::new(AttestArgs {
            aa_addr: "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                .to_owned(),
            refresh_interval: Some(3),
        })
        .await?;

        let old_cert = cert_manager.get_latest_cert().await?;
        assert!(Arc::ptr_eq(
            &old_cert,
            &cert_manager.get_latest_cert().await?
        ));

        match &cert_manager.strategy {
            RefreshStrategy::Periodically {
                interval: _,
                latest_cert: _,
                refresh_task,
            } => {
                let refresh_task = refresh_task.lock().await;
                assert!(refresh_task.is_none());
            }
            RefreshStrategy::WhenRequired => {
                bail!("wrong strategy")
            }
        }

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        defer! {
            cancel_clone.cancel();
        }
        let cancel_clone = cancel.clone();
        let shutdown = tokio_graceful::Shutdown::new(async move { cancel_clone.cancelled().await });
        cert_manager
            .launch_refresh_task_if_required(shutdown.guard())
            .await?;

        match &mut cert_manager.strategy {
            RefreshStrategy::Periodically {
                interval: _,
                latest_cert,
                refresh_task,
            } => {
                let refresh_task = refresh_task.lock().await;
                assert!(refresh_task.is_some());

                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                        bail!("The test is time out");
                    }
                    res = latest_cert.1.changed() => {
                        res?;

                        let new_cert = (*latest_cert.1.borrow_and_update()).clone();

                        assert!(!Arc::ptr_eq(&old_cert, &new_cert));
                    }
                };
            }
            RefreshStrategy::WhenRequired => {
                bail!("wrong strategy")
            }
        }

        cancel.cancel();
        shutdown.shutdown().await;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_cert_gen_with_zero_interval() -> Result<()> {
        let mut cert_manager = CertManager::new(AttestArgs {
            aa_addr: "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                .to_owned(),
            refresh_interval: Some(0),
        })
        .await?;

        let old_cert = cert_manager.get_latest_cert().await?;

        match &cert_manager.strategy {
            RefreshStrategy::Periodically { .. } => {
                bail!("wrong strategy")
            }
            RefreshStrategy::WhenRequired => {}
        }

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        defer! {
            cancel_clone.cancel();
        }
        let cancel_clone = cancel.clone();
        let shutdown = tokio_graceful::Shutdown::new(async move { cancel_clone.cancelled().await });
        cert_manager
            .launch_refresh_task_if_required(shutdown.guard())
            .await?;

        match &mut cert_manager.strategy {
            RefreshStrategy::Periodically { .. } => {
                bail!("wrong strategy")
            }
            RefreshStrategy::WhenRequired => {}
        }

        let new_cert = cert_manager.get_latest_cert().await?;
        assert!(!Arc::ptr_eq(&old_cert, &new_cert));

        cancel.cancel();
        shutdown.shutdown().await;

        Ok(())
    }
}
