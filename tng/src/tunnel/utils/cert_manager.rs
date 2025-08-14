use again::RetryPolicy;
use anyhow::{bail, Context as _, Result};
use rats_cert::{
    cert::create::CertBuilder,
    crypto::{AsymmetricAlgo, HashAlgo},
    tee::{
        coco::{attester::CocoAttester, converter::CocoConverter},
        AttesterPipeline,
    },
};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{sync::Mutex, task::JoinHandle};

use crate::{
    config::ra::{AttestArgs, AttestationAgentArgs},
    tunnel::utils::runtime::{supervised_task::SupervisedTaskResult, TokioRuntime},
};

const CERT_REFRESH_INTERVAL_SECOND: u64 = 10 * 60; // 10 minutes
const CREATE_CERT_TIMEOUT_SECOND: u64 = 120; // 2 min

#[derive(Debug)]
pub struct CertManager {
    attest_args: AttestArgs,
    refresh_strategy: RefreshStrategy,
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
pub struct RefreshTask {
    join_handle: JoinHandle<SupervisedTaskResult<()>>,
}

impl CertManager {
    pub async fn new(attest_args: AttestArgs) -> Result<Self> {
        // Sanity check for the attest_args.
        let refresh_interval = match &attest_args {
            AttestArgs::Passport {
                aa_args:
                    AttestationAgentArgs {
                        aa_addr,
                        refresh_interval,
                    },
                ..
            }
            | AttestArgs::BackgroundCheck {
                aa_args:
                    AttestationAgentArgs {
                        aa_addr,
                        refresh_interval,
                    },
            } => {
                let aa_sock_file = aa_addr
                    .strip_prefix("unix:///")
                    .context("AA address must start with unix:///")?;
                let aa_sock_file = Path::new("/").join(aa_sock_file);
                if !Path::new(&aa_sock_file).exists() {
                    bail!("AA socket file {aa_sock_file:?} not found")
                }

                refresh_interval
            }
        };

        // Fetch the cert first time
        let certed_key = Self::fetch_new_cert(&attest_args).await?;

        let refresh_interval = refresh_interval.unwrap_or(CERT_REFRESH_INTERVAL_SECOND);

        let refresh_strategy = if refresh_interval == 0 {
            RefreshStrategy::WhenRequired
        } else {
            RefreshStrategy::Periodically {
                interval: refresh_interval,
                latest_cert: tokio::sync::watch::channel(certed_key),
                refresh_task: Mutex::new(None),
            }
        };

        Ok(Self {
            attest_args,
            refresh_strategy,
        })
    }

    pub async fn launch_refresh_task_if_required(&self, runtime: TokioRuntime) -> Result<()> {
        match &self.refresh_strategy {
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
                let attest_args = self.attest_args.clone();
                let latest_cert = latest_cert.clone();

                let join_handle = runtime.spawn_supervised_task_current_span(async move {
                    let fut = async {
                        loop {
                            // Update certs in loop
                            let fut = async {
                                tokio::time::sleep(tokio::time::Duration::from_secs(interval))
                                    .await;

                                let certed_key = Self::fetch_new_cert(&attest_args).await?;

                                latest_cert
                                    .0
                                    .send(certed_key)
                                    .context("Failed to set the latest cert")
                            };

                            if let Err(e) = fut.await {
                                tracing::error!(error=?e,"Failed to update cert");
                            }
                        }
                        #[allow(unreachable_code)]
                        Ok::<(), anyhow::Error>(())
                    };

                    if let Err(e) = fut.await {
                        tracing::error!(error=?e, "Failed to update cert");
                    }
                });
                *refresh_task = Some(RefreshTask { join_handle })
            }
            RefreshStrategy::WhenRequired => {
                // Do nothing
            }
        }

        Ok(())
    }

    async fn fetch_new_cert(attest_args: &AttestArgs) -> Result<Arc<rustls::sign::CertifiedKey>> {
        let retry_policy = RetryPolicy::fixed(Duration::from_secs(1)).with_max_retries(3);
        retry_policy
            .retry(|| async {
                Self::fetch_new_cert_inner(attest_args)
                    .await
                    .map_err(anyhow::Error::from)
                    .context("Failed to generate new cert")
            })
            .await
    }

    async fn fetch_new_cert_inner(
        attest_args: &AttestArgs,
    ) -> Result<Arc<rustls::sign::CertifiedKey>> {
        let timeout_sec = CREATE_CERT_TIMEOUT_SECOND as i64;
        tracing::debug!(?attest_args, timeout_sec, "Generate new cert with rats-rs");

        let (der_cert, privkey) = match attest_args {
            AttestArgs::Passport { aa_args, as_args } => {
                let coco_attester = CocoAttester::new_with_timeout_nano(
                    &aa_args.aa_addr,
                    timeout_sec * 1000 * 1000 * 1000,
                )?;

                let coco_converter = CocoConverter::new(
                    &as_args.as_addr,
                    &as_args.token_verify.policy_ids,
                    as_args.as_is_grpc,
                )?;
                let attester_pipeline = AttesterPipeline::new(coco_attester, coco_converter);
                let cert = CertBuilder::new(attester_pipeline, HashAlgo::Sha256)
                    .with_subject("CN=TNG,O=Inclavare Containers")
                    .build(AsymmetricAlgo::P256)
                    .await?;

                tracing::debug!(
                    cert = cert.cert_to_pem()?,
                    timeout_sec,
                    "Generated new cert"
                );

                (cert.cert_to_der()?, cert.private_key().to_pkcs8_pem()?)
            }
            AttestArgs::BackgroundCheck { aa_args } => {
                let coco_attester = CocoAttester::new_with_timeout_nano(
                    &aa_args.aa_addr,
                    timeout_sec * 1000 * 1000 * 1000,
                )?;

                let cert = CertBuilder::new(coco_attester, HashAlgo::Sha256)
                    .with_subject("CN=TNG,O=Inclavare Containers")
                    .build(AsymmetricAlgo::P256)
                    .await?;

                tracing::debug!(
                    cert = cert.cert_to_pem()?,
                    timeout_sec,
                    "Generated new cert"
                );

                (cert.cert_to_der()?, cert.private_key().to_pkcs8_pem()?)
            }
        };

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
        match &self.refresh_strategy {
            RefreshStrategy::Periodically {
                interval: _,
                latest_cert,
                refresh_task: _,
            } => Ok(latest_cert.1.borrow().clone()),
            RefreshStrategy::WhenRequired => Self::fetch_new_cert(&self.attest_args).await,
        }
    }
}

impl Drop for RefreshTask {
    fn drop(&mut self) {
        // terminate the task when dropped
        self.join_handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use scopeguard::defer;
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_cert_gen_with_nonzero_interval() -> Result<()> {
        let mut cert_manager = CertManager::new(AttestArgs::BackgroundCheck {
            aa_args: AttestationAgentArgs {
                aa_addr:
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        .to_owned(),
                refresh_interval: Some(3),
            },
        })
        .await?;

        let old_cert = cert_manager.get_latest_cert().await?;
        assert!(Arc::ptr_eq(
            &old_cert,
            &cert_manager.get_latest_cert().await?
        ));

        match &cert_manager.refresh_strategy {
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
            .launch_refresh_task_if_required(TokioRuntime::current(shutdown.guard())?)
            .await?;

        match &mut cert_manager.refresh_strategy {
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
        let mut cert_manager = CertManager::new(AttestArgs::BackgroundCheck {
            aa_args: AttestationAgentArgs {
                aa_addr:
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        .to_owned(),
                refresh_interval: Some(0),
            },
        })
        .await?;

        let old_cert = cert_manager.get_latest_cert().await?;

        match &cert_manager.refresh_strategy {
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
            .launch_refresh_task_if_required(TokioRuntime::current(shutdown.guard())?)
            .await?;

        match &mut cert_manager.refresh_strategy {
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
