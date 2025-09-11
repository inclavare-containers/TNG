use again::RetryPolicy;
use anyhow::{Context as _, Result};
use rats_cert::{
    cert::create::CertBuilder,
    crypto::{AsymmetricAlgo, HashAlgo},
    tee::{
        coco::{attester::CocoAttester, converter::CocoConverter},
        AttesterPipeline,
    },
};
use std::{pin::Pin, sync::Arc, time::Duration};

use crate::{
    config::ra::AttestArgs,
    tunnel::utils::{
        maybe_cached::{Expire, MaybeCached},
        runtime::TokioRuntime,
    },
};

const CREATE_CERT_TIMEOUT_SECOND: u64 = 120; // 2 min

pub struct CertManager {
    cert: MaybeCached<rustls::sign::CertifiedKey, anyhow::Error>,
}

impl CertManager {
    pub async fn new(attest_args: AttestArgs, runtime: TokioRuntime) -> Result<Self> {
        let refresh_strategy = match &attest_args {
            AttestArgs::Passport { aa_args, .. } | AttestArgs::BackgroundCheck { aa_args } => {
                aa_args.refresh_strategy()
            }
        };

        let cert = MaybeCached::new(runtime, refresh_strategy, move || {
            let attest_args = attest_args.clone();
            Box::pin(
                async move { Ok((Self::fetch_new_cert(&attest_args).await?, Expire::NoExpire)) },
            ) as Pin<Box<_>>
        })
        .await?;

        Ok(Self { cert })
    }

    async fn fetch_new_cert(attest_args: &AttestArgs) -> Result<rustls::sign::CertifiedKey> {
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

    async fn fetch_new_cert_inner(attest_args: &AttestArgs) -> Result<rustls::sign::CertifiedKey> {
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
        Ok(certified_key)
    }

    pub async fn get_latest_cert(&self) -> Result<Arc<rustls::sign::CertifiedKey>> {
        self.cert.get_latest().await
    }
}

#[cfg(test)]
mod tests {
    use anyhow::bail;

    use crate::{config::ra::AttestationAgentArgs, tests::run_test_with_tokio_runtime};

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_cert_gen_with_nonzero_interval() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let mut cert_manager = CertManager::new(AttestArgs::BackgroundCheck {
                aa_args: AttestationAgentArgs {
                    aa_addr:
                        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                            .to_owned(),
                    refresh_interval: Some(3),
                },
            }, runtime)
            .await?;

            let old_cert = cert_manager.get_latest_cert().await?;
            assert!(Arc::ptr_eq(
                &old_cert,
                &cert_manager.get_latest_cert().await?
            ));

            match &mut cert_manager.cert {
                MaybeCached::Periodically {
                    interval,
                    ref mut latest,
                    refresh_task,
                    ..
                } => {
                    assert_eq!(*interval, 3);

                    assert!(!refresh_task.is_finished());

                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                            bail!("The test is time out");
                        }
                        res = latest.1.changed() => {
                            res?;

                            let new_cert = (*latest.1.borrow_and_update()).clone();

                            assert!(!Arc::ptr_eq(&old_cert, &new_cert));
                        }
                    };
                }
                MaybeCached::Always { .. } => {
                    bail!("wrong strategy")
                }
            }

            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_cert_gen_with_zero_interval() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let cert_manager = CertManager::new(AttestArgs::BackgroundCheck {
                aa_args: AttestationAgentArgs {
                    aa_addr:
                        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                            .to_owned(),
                    refresh_interval: Some(0),
                },
            },runtime)
            .await?;

            let old_cert = cert_manager.get_latest_cert().await?;

            match &cert_manager.cert {
                MaybeCached::Periodically { .. } => {
                    bail!("wrong strategy")
                }
                MaybeCached::Always { .. } => {}
            }

            let new_cert = cert_manager.get_latest_cert().await?;
            assert!(!Arc::ptr_eq(&old_cert, &new_cert));

            Ok(())
        })
        .await
    }
}
