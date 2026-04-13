use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rats_cert::cert::verify::CertVerifier;
use rats_cert::tee::GenericConverter;
use rats_cert::tee::GenericEvidence;
use rats_cert::tee::GenericVerifier;

use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::provider::{TngEvidence, TngToken};
use crate::tunnel::ra_context::VerifyContext;

#[derive(Debug)]
pub struct TngCommonCertVerifier {
    verify_ctx: Arc<VerifyContext>,
    pending_cert: spin::mutex::spin::SpinMutex<Option<Vec<u8>>>,
}

impl TngCommonCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>) -> Self {
        Self {
            verify_ctx,
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

        // Step 1: Extract evidence from certificate
        let pending_result = CertVerifier::new()
            .verify_der(&pending_cert)
            .await
            .map_err(|e| anyhow!("Failed to extract evidence from certificate: {:?}", e))?;

        // Step 2: Based on verify mode, convert evidence to token and verify
        let token = match &*self.verify_ctx {
            VerifyContext::Passport { verifier } => {
                // Passport mode: certificate should contain a token
                let parse_result: rats_cert::errors::Result<TngToken> =
                    TngToken::create_evidence_from_dice(
                        pending_result.cbor_tag,
                        &pending_result.raw_evidence,
                    )
                    .into();
                let token = parse_result.map_err(|e| {
                    anyhow!(
                        "Failed to parse token from DICE cert (cbor_tag={:#x}): {:?}",
                        pending_result.cbor_tag,
                        e
                    )
                })?;

                verifier
                    .verify_evidence(&token, &pending_result.report_data)
                    .await
                    .map_err(|e| anyhow!("Token verification failed: {:?}", e))?;

                token
            }
            VerifyContext::BackgroundCheck {
                converter,
                verifier,
            } => {
                 // BackgroundCheck mode: certificate should contain raw evidence
                let parse_result: rats_cert::errors::Result<TngEvidence> =
                    TngEvidence::create_evidence_from_dice(
                        pending_result.cbor_tag,
                        &pending_result.raw_evidence,
                    )
                    .into();
                let evidence = parse_result.map_err(|e| {
                    anyhow!(
                        "Failed to parse evidence from DICE cert (cbor_tag={:#x}): {:?}",
                        pending_result.cbor_tag,
                        e
                    )
                })?;

                // Convert evidence to token via remote AS
                let token = converter
                    .convert(&evidence)
                    .await
                    .map_err(|e| anyhow!("Failed to convert evidence to token: {:?}", e))?;

                // Verify the token
                verifier
                    .verify_evidence(&token, &pending_result.report_data)
                    .await
                    .map_err(|e| anyhow!("Token verification failed: {:?}", e))?;

                token
            }
        };

        tracing::debug!("rats-rs cert verify finished successfully");

        Ok(AttestationResult::from_token(token))
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
