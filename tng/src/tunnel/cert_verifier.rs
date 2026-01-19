use anyhow::{Context, Result};
use rats_cert::cert::verify::{CertVerifier, CocoVerifyMode, CocoVerifyPolicy};

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

        let verify_policy = match &self.verify_args {
            VerifyArgs::Passport { token_verify } => CocoVerifyPolicy {
                verify_mode: CocoVerifyMode::Token,
                policy_ids: token_verify.policy_ids.clone(),
                trusted_certs_paths: token_verify.trusted_certs_paths.clone(),
                as_addr: token_verify.as_addr.clone(),
            },
            VerifyArgs::BackgroundCheck {
                as_args:
                    AttestationServiceArgs {
                        as_addr,
                        as_is_grpc,
                        as_headers,
                        policy_ids,
                    },
                token_verify,
            } => CocoVerifyPolicy {
                verify_mode: CocoVerifyMode::Evidence {
                    as_addr: as_addr.to_owned(),
                    as_is_grpc: *as_is_grpc,
                    as_headers: as_headers.clone(),
                },
                policy_ids: policy_ids.clone(),
                trusted_certs_paths: token_verify.trusted_certs_paths.clone(),
                as_addr: Some(as_addr.clone()),
            },
        };

        let res = CertVerifier::new(verify_policy)
            .verify_der(&pending_cert)
            .await;

        tracing::debug!(passed = res.is_ok(), "rats-rs cert verify finished");

        res.map(AttestationResult::from_coco_as_token)
            .map_err(|e| anyhow::anyhow!("Verify failed: {:?}", e))
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
