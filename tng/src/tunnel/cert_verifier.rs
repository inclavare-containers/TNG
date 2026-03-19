use anyhow::{Context, Result};
use rats_cert::cert::verify::CertVerifier;

use crate::{
    config::ra::VerifyArgs,
    tunnel::{
        attestation_result::AttestationResult,
        provider::create_verify_policy,
    },
};

#[derive(Debug)]
pub struct CommonCertVerifier {
    verify_args: VerifyArgs,
    pending_cert: spin::mutex::spin::SpinMutex<Option<Vec<u8>>>,
}

impl CommonCertVerifier {
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

        let verify_policy = create_verify_policy(&self.verify_args);

        let res = CertVerifier::new(verify_policy)
            .verify_der(&pending_cert)
            .await;

        tracing::debug!(passed = res.is_ok(), "rats-rs cert verify finished");

        res.map(AttestationResult::from_token)
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
