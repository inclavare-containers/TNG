use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rats_cert::cert::verify::CertVerifier;
use rats_cert::tee::GenericConverter;
use rats_cert::tee::GenericEvidence;
use rats_cert::tee::GenericVerifier;

use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::provider::{TngEvidence, TngToken};
use crate::tunnel::ra_context::VerifyContext;

fn parse_token_from_dice_cert(cbor_tag: u64, raw_evidence: &[u8]) -> Result<TngToken> {
    rats_cert::errors::Result::from(TngToken::create_evidence_from_dice(cbor_tag, raw_evidence))
        .map_err(|e| {
            anyhow!(
                "Failed to parse AS token from DICE cert (cbor_tag={:#x}): {e:#}",
                cbor_tag
            )
        })
}

fn parse_evidence_from_dice_cert(cbor_tag: u64, raw_evidence: &[u8]) -> Result<TngEvidence> {
    rats_cert::errors::Result::from(TngEvidence::create_evidence_from_dice(
        cbor_tag,
        raw_evidence,
    ))
    .map_err(|e| {
        anyhow!(
            "Failed to parse evidence from DICE cert (cbor_tag={:#x}): {e:#}",
            cbor_tag
        )
    })
}

#[derive(Debug)]
pub struct LazyCertVerifier {
    verify_ctx: Arc<VerifyContext>,
    pending_cert: spin::mutex::spin::SpinMutex<Option<Vec<u8>>>,
}

impl LazyCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>) -> Self {
        Self {
            verify_ctx,
            pending_cert: spin::mutex::spin::SpinMutex::new(None),
        }
    }

    /// Stores the peer's certificate for later async RA verification.
    ///
    /// This method is called during the TLS handshake by rustls's
    /// `verify_client_cert()` / `verify_server_cert()` callbacks, which are
    /// **synchronous**. Since RA verification requires contacting a remote
    /// Attestation Service (HTTP call with evidence conversion), it cannot be
    /// done synchronously.
    ///
    /// Instead, we capture the raw certificate here and return `Ok(())` to let
    /// the TLS handshake complete. After the handshake, the caller must invoke
    /// [`Self::verity_pending_cert`] (async) to perform the actual RA
    /// verification. If that step fails, the connection is rejected.
    ///
    /// Call chain:
    ///   1. TLS handshake → rustls calls `verify_client_cert()` (sync)
    ///      → this method stores the cert in `pending_cert`
    ///   2. Handshake complete → caller awaits `verity_pending_cert()` (async)
    ///      → extracts evidence, converts via AS, verifies token
    pub fn set_to_pending_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
    ) -> std::result::Result<(), rustls::Error> {
        // We just return ok here, and store the end entity certificate and verify it later.
        self.pending_cert.lock().replace(end_entity.to_vec());
        Ok(())
    }

    pub async fn verify_pending_cert(&self) -> Result<AttestationResult> {
        let pending_cert = self
            .pending_cert
            .lock()
            .take()
            .context("No rats-tls cert received")?;

        verify_cert(&self.verify_ctx, pending_cert).await
    }
}

#[cfg(not(wasm))]
#[derive(Debug)]
pub struct BlockingCertVerifier {
    verify_ctx: Arc<VerifyContext>,
}

#[cfg(not(wasm))]
impl BlockingCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>) -> Self {
        Self { verify_ctx }
    }

    pub fn verify_cert_blocking(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
    ) -> Result<AttestationResult> {
        let end_entity = end_entity.to_vec();
        let verify_ctx = self.verify_ctx.clone();

        // Note: other code running concurrently **in the same task** will be suspended
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(verify_cert(&verify_ctx, end_entity))
        })
        .context("Failed to get cert verify result")
    }
}

async fn verify_cert(verify_ctx: &VerifyContext, end_entity: Vec<u8>) -> Result<AttestationResult> {
    tracing::debug!("Verifying rats-tls cert");

    // Step 1: Extract evidence from certificate
    let pending_result = CertVerifier::new()
        .verify_der(&end_entity)
        .await
        .map_err(|e| anyhow!("Failed to extract evidence from certificate: {:?}", e))?;

    // Step 2: Based on verify mode, convert evidence to token and verify
    let token = match verify_ctx {
        VerifyContext::Passport { verifier } => {
            // Passport: extension must parse as an AS token (not raw evidence).
            let token =
                parse_token_from_dice_cert(pending_result.cbor_tag, &pending_result.raw_evidence)?;

            // Verify the token using pre-instantiated verifier
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
            // BackgroundCheck: extension must parse as raw evidence (then convert via AS).
            let evidence = parse_evidence_from_dice_cert(
                pending_result.cbor_tag,
                &pending_result.raw_evidence,
            )?;

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
