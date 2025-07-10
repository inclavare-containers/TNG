use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::{anyhow, Context};
use futures::StreamExt as _;
use rats_cert::cert::verify::{
    CertVerifier, ClaimsCheck, CocoVerifyMode, VerifyPolicy, VerifyPolicyOutput,
};
use rustls::Error;
use tokio::sync::Mutex;

use crate::{config::ra::VerifyArgs, tunnel::attestation_result::AttestationResult};

pub type CertVerifyTaskFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Debug)]
pub struct CoCoCommonCertVerifier {
    verify: Arc<VerifyArgs>,
    attestation_result: Arc<Mutex<Option<AttestationResult>>>,
    task_sender: flume::Sender<CertVerifyTaskFuture>,
    task_receiver: flume::Receiver<CertVerifyTaskFuture>,
}

impl CoCoCommonCertVerifier {
    pub fn new(verify: VerifyArgs) -> Self {
        let (task_sender, task_receiver) = flume::unbounded();

        Self {
            verify: Arc::new(verify),
            attestation_result: Arc::new(Mutex::new(None)),
            task_sender,
            task_receiver,
        }
    }

    pub async fn get_attestation_result(&self) -> Option<AttestationResult> {
        (*self.attestation_result.lock().await).clone()
    }

    /// Spawn a async task to handle all the async certificate verification tasks
    /// Note this should be called in non-blocking async context only
    pub async fn spawn_verify_task_handler(&self) {
        let task_receiver = self.task_receiver.clone();
        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        {
            tokio_with_wasm::task::spawn(async {
                let next = task_receiver.into_stream();
                while let Some(task) = next.await {
                    tokio_with_wasm::task::spawn(task)
                }
            });
        }

        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        {
            tokio::task::spawn(async move {
                let mut next = task_receiver.into_stream();
                while let Some(task) = next.next().await {
                    tokio::task::spawn(task);
                }
            });
        }
    }

    pub fn verify_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
    ) -> std::result::Result<(), rustls::Error> {
        tracing::debug!("Verifying rats-tls cert");

        let end_entity = end_entity.to_vec();
        let verify = self.verify.clone();
        let attestation_result = self.attestation_result.clone();

        let verify_func = || {
            let (result_tx, result_rx) = tokio::sync::oneshot::channel();
            self.task_sender
                .send(Box::pin(async move {
                    let res = CertVerifier::new(VerifyPolicy::Coco {
                        verify_mode: CocoVerifyMode::Evidence {
                            as_addr: verify.as_addr.to_owned(),
                            as_is_grpc: verify.as_is_grpc,
                        },
                        policy_ids: verify.policy_ids.to_owned(),
                        trusted_certs_paths: verify.trusted_certs_paths.clone(),
                        claims_check: ClaimsCheck::Custom(Box::new(move |claims| {
                            let claims = claims.to_owned();
                            let attestation_result = attestation_result.clone();
                            Box::pin(async move {
                                *attestation_result.lock().await =
                                    Some(AttestationResult::from_claims(&claims));
                                // We do not check the claims here, just leave it to be checked by attestation service.
                                VerifyPolicyOutput::Passed
                            })
                        })),
                    })
                    .verify_der(&end_entity)
                    .await;

                    tracing::debug!(result=?res, "rats-rs cert verify finished");

                    if let Err(_) = result_tx.send(res) {
                        tracing::error!("Failed to send verification result")
                    }
                }))
                .map_err(|_| anyhow!("Failed to send cert verify task"))?;

            // Note: will panic when used in asynchronous context.
            result_rx
                .blocking_recv()
                .context("Failed to receive cert verify result")
                .and_then(|e| Ok(e?))
        };

        match verify_func() {
            Ok(VerifyPolicyOutput::Passed) => Ok(()),
            Ok(VerifyPolicyOutput::Failed) => Err(Error::General(
                "Verify failed because of claims".to_string(),
            )),
            Err(err) => Err(Error::General(
                format!("Verify failed with err: {:?}", err).to_string(),
            )),
        }
    }
}
