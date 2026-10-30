//! Certificate-file appraisal shared by native RA-TLS and browser tools.
//! This validates supplied bytes; callers must independently establish that
//! these are the bytes their browser received and approve the expected policy.
use super::{
    provider::{TngEvidence, TngToken},
    ra_context::VerifyContext,
};
use crate::{config::ra::VerifyArgs, AttestationResult};
use anyhow::{anyhow, bail, Context, Result};
use rats_cert::{
    cert::verify::CertVerifier,
    tee::{GenericConverter, GenericEvidence, GenericVerifier},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use web_time_compat::{SystemTime, SystemTimeExt};
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};

#[derive(Serialize)]
pub struct VerifiedCertificate {
    pub certificate_sha256: String,
    pub public_key_sha256: String,
    pub attestation_result: AttestationResult,
}

/// Appraise a browser-exported DER certificate against caller-approved policy.
/// No remote endpoint, page assertion or certificate download is treated as a
/// statement about which certificate the browser's TLS stack actually used.
pub async fn verify_certificate(
    certificate: &[u8],
    verify: &VerifyArgs,
) -> Result<VerifiedCertificate> {
    if certificate.len() > 65536 {
        bail!("Certificate exceeds 64 KiB");
    }
    let cert = Certificate::from_der(certificate).context("Parse certificate DER")?;
    let now = SystemTime::get();
    let validity = &cert.tbs_certificate.validity;
    if now < validity.not_before.to_system_time() || now > validity.not_after.to_system_time() {
        bail!("Certificate is not currently valid");
    }
    let context = VerifyContext::from_verify_args(verify).await?;
    let attestation_result = verify_for_context(&context, certificate).await?;
    Ok(VerifiedCertificate {
        certificate_sha256: hex::encode(Sha256::digest(certificate)),
        public_key_sha256: hex::encode(Sha256::digest(
            cert.tbs_certificate.subject_public_key_info.to_der()?,
        )),
        attestation_result,
    })
}

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

pub(crate) async fn verify_for_context(
    verify_ctx: &VerifyContext,
    end_entity: &[u8],
) -> Result<AttestationResult> {
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

    Ok(AttestationResult::from_token(token))
}
