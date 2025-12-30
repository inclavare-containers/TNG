use anyhow::{bail, Context, Result};
use rats_cert::cert::verify::{
    CertVerifier, ClaimsCheck, CocoVerifyMode, VerifyPolicy, VerifyPolicyOutput,
};

use crate::{
    config::ra::{AttestationServiceArgs, VerifyArgs},
    tunnel::attestation_result::AttestationResult,
};

#[derive(Debug)]
pub struct CoCoCommonCertVerifier {
    verify_args: VerifyArgs,
    pending_cert: spin::mutex::spin::SpinMutex<Option<Vec<u8>>>,
}

impl CoCoCommonCertVerifier {
    pub fn new(verify_args: VerifyArgs) -> Self {
        Self {
            verify_args,
            pending_cert: spin::mutex::spin::SpinMutex::new(None),
        }
    }

    pub async fn verity_pending_cert(&self) -> Result<AttestationResult> {
        tracing::debug!("Verifying rats-tls cert");

        let pending_cert = self
            .pending_cert
            .lock()
            .take()
            .context("No rats-tls cert received")?;

        let (tx, mut rx) = tokio::sync::oneshot::channel();

        let (verify_mode, policy_ids, trusted_certs_paths) = match &self.verify_args {
            VerifyArgs::Passport { token_verify } => (
                CocoVerifyMode::Token,
                token_verify.policy_ids.clone(),
                token_verify.trusted_certs_paths.clone(),
            ),
            VerifyArgs::BackgroundCheck {
                as_args:
                    AttestationServiceArgs {
                        as_addr,
                        as_is_grpc,
                        token_verify,
                        as_headers,
                    },
            } => (
                CocoVerifyMode::Evidence {
                    as_addr: as_addr.to_owned(),
                    as_is_grpc: *as_is_grpc,
                    as_headers: as_headers.clone(),
                },
                token_verify.policy_ids.clone(),
                token_verify.trusted_certs_paths.clone(),
            ),
        };

        let res = CertVerifier::new(VerifyPolicy::Coco {
            verify_mode,
            policy_ids,
            trusted_certs_paths,
            claims_check: ClaimsCheck::Custom(Box::new(move |claims| {
                let claims = claims.to_owned();
                let _ = tx.send(AttestationResult::from_claims(claims)); // Ignore the error here.
                Box::pin(async move {
                    // We do not check the claims here, just leave it to be checked by attestation service.
                    VerifyPolicyOutput::Passed
                })
            })),
        })
        .verify_der(&pending_cert)
        .await;

        tracing::debug!(result=?res, "rats-rs cert verify finished");

        match res? {
            VerifyPolicyOutput::Passed => {
                Ok(rx.try_recv().context("Failed to get attestation result")?)
            }
            VerifyPolicyOutput::Failed => {
                bail!("Verify failed because denied by attestation policy")
            }
        }
    }

    pub fn verify_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
    ) -> std::result::Result<(), rustls::Error> {
        // We just return ok here, and store the end entity certificate and verify it later.
        self.pending_cert.lock().replace(end_entity.to_vec());
        Ok(())
    }
}
