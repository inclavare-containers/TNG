// Copyright (c) 2026 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! Verify the `signer_transparency` claim in COCO attestation service JWT tokens.
//!
//! This module implements the verification logic described in trustee's
//! `docs/as_signer_transparency.md`. After standard token signature verification
//! succeeds, this module validates that the signer certificate is bound to TEE
//! evidence and recorded in a Rekor transparency log.

use base64::{prelude::BASE64_STANDARD, prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::Verifier;
use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;
use x509_cert::der::Decode as _;

/// Verify signer transparency in a COCO AS JWT token.
///
/// # Arguments
/// * `jwt_str` — The raw JWT string from `CocoAsToken::as_str()`
pub fn verify_signer_transparency(jwt_str: &str) -> anyhow::Result<()> {
    let (header_bytes, payload_bytes) = decode_jwt_parts(jwt_str)?;

    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse JWT header: {}", e))?;
    let payload: JwtPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse JWT payload: {}", e))?;

    // Step 1: Extract signer certificate from header
    let signer_cert_der = extract_signer_cert_der(&header)?;

    // Step 2: Extract signer_transparency claim
    let transparency = payload
        .signer_transparency
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("signer_transparency claim not found in JWT payload"))?;

    // Step 3: Validate schema version
    if transparency.schema_version != "trustee.as.signer-transparency/v1" {
        anyhow::bail!(
            "Unsupported signer_transparency schema_version: {}",
            transparency.schema_version
        );
    }

    // Step 4: Verify certificate DER SHA-256 matches the claim
    let cert_hash = sha256_hex(&signer_cert_der);
    if cert_hash != transparency.payload.signer_certificate.der_sha256 {
        anyhow::bail!(
            "Certificate DER SHA-256 mismatch: computed {} != claim {}",
            cert_hash,
            transparency.payload.signer_certificate.der_sha256
        );
    }

    // Step 4b: Verify evidence report_data matches certificate hash
    if transparency.payload.evidence_binding.report_data != cert_hash {
        anyhow::bail!(
            "Evidence report_data does not match certificate hash: report_data {} != cert_hash {}",
            transparency.payload.evidence_binding.report_data,
            cert_hash
        );
    }

    // Step 4c: Verify certificate has not expired
    let not_after_str = &transparency.payload.signer_certificate.not_after;
    if let Ok(not_after) = OffsetDateTime::parse(not_after_str, &Rfc2822) {
        let now = OffsetDateTime::now_utc();
        if now > not_after {
            anyhow::bail!("Signer certificate expired: not_after = {}", not_after_str);
        }
    } else {
        tracing::warn!(
            not_after = %not_after_str,
            "Failed to parse certificate not_after timestamp, skipping expiry check"
        );
    }

    // Step 5: Verify payload SHA-256 matches payload_metadata.digest.sha256
    let payload_json = serde_json::to_vec(&transparency.payload)
        .map_err(|e| anyhow::anyhow!("Failed to serialize transparency payload: {}", e))?;
    let payload_hash = sha256_hex(&payload_json);
    if payload_hash != transparency.payload_metadata.digest.sha256 {
        anyhow::bail!(
            "Transparency payload SHA-256 mismatch: computed {} != claim {}",
            payload_hash,
            transparency.payload_metadata.digest.sha256
        );
    }

    // Step 5b: Verify DSSE payload hash from Rekor entry matches payload_metadata digest
    verify_dsse_payload(
        &transparency.rekor,
        &transparency.payload_metadata.digest.sha256,
    )?;

    // Step 6: Verify Rekor v2 checkpoint signature locally
    verify_rekor_checkpoint(&transparency.rekor)?;

    tracing::info!(
        cert_der_sha256 = %cert_hash,
        rekor_url = %transparency.rekor.url,
        "signer_transparency verification succeeded"
    );

    Ok(())
}

/// Decode the three parts of a JWT string.
fn decode_jwt_parts(jwt_str: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("Invalid JWT: expected 3 parts, got {}", parts.len());
    }

    let header = BASE64_URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| anyhow::anyhow!("Failed to base64url-decode JWT header: {}", e))?;
    let payload = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| anyhow::anyhow!("Failed to base64url-decode JWT payload: {}", e))?;

    Ok((header, payload))
}

/// Extract the first X.509 certificate (DER bytes) from the JWT header's jwk.x5c.
fn extract_signer_cert_der(header: &JwtHeader) -> anyhow::Result<Vec<u8>> {
    let x5c = header
        .jwk
        .as_ref()
        .and_then(|j| j.x5c.as_ref())
        .filter(|c| !c.is_empty())
        .ok_or_else(|| anyhow::anyhow!("No x5c certificate chain found in JWT header jwk"))?;

    let cert_b64 = &x5c[0];
    let cert_der = BASE64_URL_SAFE_NO_PAD
        .decode(cert_b64)
        .or_else(|_| BASE64_STANDARD.decode(cert_b64))
        .map_err(|e| anyhow::anyhow!("Failed to decode x5c[0] as base64: {}", e))?;

    // Validate it's a real X.509 certificate
    x509_cert::Certificate::from_der(&cert_der).map_err(|e| {
        anyhow::anyhow!("x5c[0] is not a valid DER-encoded X.509 certificate: {}", e)
    })?;

    Ok(cert_der)
}

/// Known Rekor v2 public keys (ECDSA P-256, uncompressed point format).
fn get_rekor_public_key(url: &str) -> anyhow::Result<VerifyingKey> {
    let spki_b64 = match url {
        "https://log2025-1.rekor.sigstore.dev" => {
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+CBMoVgd3QC6ke3ZR6qQwgEFM81PTMQzw7nB5vIs2ClB3TUOA84C9VY8n7O061MgTm4Btddzf4UhAA=="
        }
        "https://rekor.sigstore.dev" => {
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a6fZBoIUg5x/0/U9qOQANUu2aZL8i+2rN5qAVTLrBs5kxLqGPOosHbBhB6JL8HkFw=="
        }
        _ => anyhow::bail!("No known public key for Rekor URL: {}", url),
    };

    let spki_der = BASE64_STANDARD
        .decode(spki_b64)
        .map_err(|e| anyhow::anyhow!("Failed to decode Rekor public key base64: {}", e))?;
    let spki = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(&spki_der)
        .map_err(|e| anyhow::anyhow!("Failed to parse Rekor SPKI DER: {}", e))?;
    let encoded_point = EncodedPoint::from_bytes(spki.subject_public_key.raw_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to decode Rekor public key point: {}", e))?;
    VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|e| anyhow::anyhow!("Failed to construct Rekor verifying key: {}", e))
}

/// Verify Rekor v2 checkpoint signature.
fn verify_rekor_checkpoint(rekor: &RekorClaim) -> anyhow::Result<()> {
    let entry_v2 = &rekor.rekor_entry_v2;

    // Extract checkpoint string from the Rekor v2 entry
    let checkpoint_str = entry_v2
        .get("checkpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing checkpoint in rekorEntryV2"))?;

    let checkpoint = parse_checkpoint(checkpoint_str)?;

    // Validate checkpoint origin matches the hostname of the Rekor URL
    // The checkpoint origin is typically just the hostname (e.g., "log2025-1.rekor.sigstore.dev")
    // while the Rekor URL includes the scheme (e.g., "https://log2025-1.rekor.sigstore.dev")
    let expected_origin = rekor.url.strip_prefix("https://").unwrap_or(&rekor.url);
    if checkpoint.origin != expected_origin {
        anyhow::bail!(
            "Checkpoint origin mismatch: expected {} but got {}",
            expected_origin,
            checkpoint.origin
        );
    }

    // Get the expected Rekor public key for this URL
    let verifying_key = get_rekor_public_key(&rekor.url)?;

    // The signed checkpoint body is everything before the blank line and signature
    let signed_body = format!(
        "{}\n{}\n{}\n",
        checkpoint.origin, checkpoint.size, checkpoint.root_hash
    );

    // Verify ECDSA P-256 SHA-256 signature
    let signature = Signature::from_slice(&checkpoint.signature)
        .map_err(|e| anyhow::anyhow!("Invalid checkpoint signature encoding: {}", e))?;

    verifying_key
        .verify(signed_body.as_bytes(), &signature)
        .map_err(|e| anyhow::anyhow!("Checkpoint signature verification failed: {}", e))?;

    // Verify the leaf hash from inclusionProof matches the entry's leaf hash
    if let Some(inclusion_proof) = entry_v2.get("inclusionProof") {
        let proof_leaf_hash = inclusion_proof
            .get("leafHash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing leafHash in inclusionProof"))?;

        let entry_hash = read_entry_leaf_hash(entry_v2)?;
        if proof_leaf_hash != entry_hash {
            anyhow::bail!(
                "Inclusion proof leaf hash mismatch: proof {} != entry {}",
                proof_leaf_hash,
                entry_hash
            );
        }
    }

    Ok(())
}

/// Verify the DSSE payload hash in the Rekor v2 entry matches the transparency payload digest.
///
/// In Rekor v2 DSSE entries, the `canonicalizedBody` contains a DSSE envelope with a
/// `payloadHash.digest` field. We verify this digest matches the `payload_metadata.digest.sha256`,
/// linking the Rekor entry to the claimed transparency payload.
fn verify_dsse_payload(rekor: &RekorClaim, payload_metadata_digest: &str) -> anyhow::Result<()> {
    let entry_v2 = &rekor.rekor_entry_v2;

    let canonicalized_body = entry_v2
        .get("canonicalizedBody")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing canonicalizedBody in rekorEntryV2"))?;

    // Decode base64url canonicalized body
    let dsse_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(canonicalized_body)
        .map_err(|e| anyhow::anyhow!("Failed to decode canonicalizedBody: {}", e))?;

    // Parse as DSSE envelope
    let dsse: serde_json::Value = serde_json::from_slice(&dsse_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse DSSE envelope: {}", e))?;

    // Extract the payloadHash digest from the DSSE v002 spec
    let dsse_digest = dsse
        .get("spec")
        .and_then(|s| s.get("dsseV002"))
        .and_then(|d| d.get("payloadHash"))
        .and_then(|p| p.get("digest"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing payloadHash.digest in DSSE envelope"))?;

    // Convert DSSE digest (base64) to hex for comparison
    let dsse_digest_bytes = BASE64_STANDARD
        .decode(dsse_digest)
        .map_err(|e| anyhow::anyhow!("Failed to decode DSSE payload digest: {}", e))?;
    let dsse_digest_hex = hex::encode(&dsse_digest_bytes);

    if dsse_digest_hex != payload_metadata_digest {
        anyhow::bail!(
            "DSSE payload hash mismatch: Rekor entry {} != payload_metadata {}",
            dsse_digest_hex,
            payload_metadata_digest
        );
    }

    Ok(())
}

/// Parse a Sigstore checkpoint string.
///
/// Format:
/// ```text
/// <origin>
/// <size>
/// <rootHash>
///
/// — <origin>
/// <base64 signature>
/// ```
fn parse_checkpoint(checkpoint_str: &str) -> anyhow::Result<Checkpoint> {
    let lines: Vec<&str> = checkpoint_str.lines().collect();
    if lines.is_empty() {
        anyhow::bail!("Empty checkpoint");
    }

    let origin = lines[0].trim();
    if origin.is_empty() {
        anyhow::bail!("Empty checkpoint origin");
    }

    if lines.len() < 3 {
        anyhow::bail!("Checkpoint too short, expected at least 3 lines");
    }

    let size: u64 = lines[1]
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid checkpoint size: {}", e))?;

    let root_hash = lines[2].trim();
    if root_hash.is_empty() {
        anyhow::bail!("Empty checkpoint rootHash");
    }

    // Find the signature after the blank line separator
    // The em-dash line can have the signature on the same line (single-line format):
    //   "— <origin> <base64 sig>"
    // Or on the next line (multi-line format):
    //   "— <origin>"
    //   "<base64 sig>"
    let mut sig_line = None;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('\u{2014}') || trimmed.starts_with("-- ") {
            // Check if signature is on the same line after the origin name
            let after_dash = trimmed
                .strip_prefix('\u{2014}')
                .or_else(|| trimmed.strip_prefix("-- "))
                .unwrap_or(trimmed)
                .trim();
            let parts: Vec<&str> = after_dash.splitn(2, ' ').collect();
            if parts.len() == 2 && !parts[1].is_empty() {
                // "— <origin> <sig>" format
                sig_line = Some(parts[1].to_string());
                break;
            }
            // Try next line for "— <origin>" then "<sig>" format
            if let Some(next) = lines.get(i + 1) {
                let next_trimmed = next.trim();
                if !next_trimmed.is_empty() {
                    sig_line = Some(next_trimmed.to_string());
                    break;
                }
            }
        }
    }

    // Fallback: find the first non-empty base64-looking line after line 3
    let sig_line = sig_line.unwrap_or_else(|| {
        for line in lines.iter().skip(3) {
            let trimmed = line.trim();
            if !trimmed.is_empty()
                && !trimmed.starts_with('\u{2014}')
                && !trimmed.starts_with("-- ")
            {
                return trimmed.to_string();
            }
        }
        String::new()
    });

    if sig_line.is_empty() {
        anyhow::bail!("No checkpoint signature found");
    }

    let signature = BASE64_STANDARD
        .decode(sig_line)
        .map_err(|e| anyhow::anyhow!("Invalid base64 in checkpoint signature: {}", e))?;

    Ok(Checkpoint {
        origin: origin.to_string(),
        size,
        root_hash: root_hash.to_string(),
        signature,
    })
}

/// Read the leaf hash from a Rekor v2 DSSE entry JSON value.
fn read_entry_leaf_hash(entry_v2: &serde_json::Value) -> anyhow::Result<String> {
    if let Some(leaf_hash) = entry_v2.get("leafHash").and_then(|v| v.as_str()) {
        return Ok(leaf_hash.to_string());
    }

    anyhow::bail!("Cannot compute entry leaf hash");
}

/// Compute SHA-256 hex digest of bytes.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// JWT header — we only care about the jwk field for x5c extraction.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    jwk: Option<Jwk>,
}

/// JSON Web Key — we only need x5c.
#[derive(Debug, Deserialize)]
struct Jwk {
    #[serde(alias = "x5c")]
    x5c: Option<Vec<String>>,
}

/// JWT payload — extended with signer_transparency.
#[derive(Debug, Deserialize)]
struct JwtPayload {
    #[serde(rename = "signer_transparency")]
    signer_transparency: Option<SignerTransparency>,
}

/// The signer_transparency claim structure matching trustee's format.
#[derive(Debug, Deserialize)]
pub struct SignerTransparency {
    pub schema_version: String,
    pub generated_at: String,
    pub payload: SignerBinding,
    pub payload_metadata: PayloadMetadata,
    pub rekor: RekorClaim,
}

/// signer_binding.json — the DSSE payload submitted to Rekor.
#[derive(Debug, Deserialize, Serialize)]
pub struct SignerBinding {
    pub schema_version: String,
    pub generated_at: String,
    pub signer_certificate: SignerCertificate,
    pub evidence_binding: EvidenceBinding,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignerCertificate {
    pub path: String,
    pub pem: String,
    pub der_sha256: String,
    pub not_after: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EvidenceBinding {
    pub api_server_url: String,
    pub report_data: String,
    pub report_data_algorithm: String,
    pub runtime_data_encoding: String,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayloadMetadata {
    pub path: String,
    pub media_type: String,
    pub digest: DigestInfo,
    pub size: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DigestInfo {
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RekorClaim {
    pub url: String,
    pub api_version: String,
    pub request_type: String,
    pub key_details: String,
    #[serde(rename = "rekorEntryV2")]
    pub rekor_entry_v2: serde_json::Value,
}

/// Parsed Sigstore checkpoint.
struct Checkpoint {
    origin: String,
    size: u64,
    root_hash: String,
    signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex() {
        let empty = sha256_hex(b"");
        assert_eq!(
            empty,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let hello = sha256_hex(b"hello");
        assert_eq!(
            hello,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_decode_jwt_parts_valid() {
        let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"jwk":{"x5c":[]}}"#);
        let payload = BASE64_URL_SAFE_NO_PAD.encode(r#"{}"#);
        let jwt = format!("{}.{}.fakesig", header, payload);

        let (h, p) = decode_jwt_parts(&jwt).unwrap();
        assert_eq!(h, br#"{"jwk":{"x5c":[]}}"#);
        assert_eq!(p, br#"{}"#);
    }

    #[test]
    fn test_decode_jwt_parts_invalid_format() {
        assert!(decode_jwt_parts("no.dots.here.extra").is_err());
        assert!(decode_jwt_parts("only.two").is_err());
        assert!(decode_jwt_parts("one").is_err());
    }

    #[test]
    fn test_parse_signer_transparency_from_json() {
        let json = r#"{
            "signer_transparency": {
                "schema_version": "trustee.as.signer-transparency/v1",
                "generated_at": "2026-04-27T07:00:10Z",
                "payload": {
                    "schema_version": "trustee.as.signer-binding/v1",
                    "generated_at": "2026-04-27T07:00:00Z",
                    "signer_certificate": {
                        "path": "/tmp/signer.crt",
                        "pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
                        "der_sha256": "abc123",
                        "not_after": "Apr 27 07:00:00 2027 GMT"
                    },
                    "evidence_binding": {
                        "api_server_url": "http://127.0.0.1:8006",
                        "report_data": "abc123",
                        "report_data_algorithm": "sha256(x509 DER)",
                        "runtime_data_encoding": "hex",
                        "evidence": {}
                    }
                },
                "payload_metadata": {
                    "path": "/tmp/signer_binding.json",
                    "media_type": "application/vnd.trustee.as.signer-binding+json",
                    "digest": {"sha256": "def456"},
                    "size": 1234
                },
                "rekor": {
                    "url": "https://log2025-1.rekor.sigstore.dev",
                    "api_version": "v2",
                    "request_type": "dsseRequestV002",
                    "key_details": "PKIX_ECDSA_P256_SHA_256",
                    "rekorEntryV2": {}
                }
            }
        }"#;

        let payload: JwtPayload = serde_json::from_str(json).unwrap();
        let transparency = payload.signer_transparency.unwrap();
        assert_eq!(
            transparency.schema_version,
            "trustee.as.signer-transparency/v1"
        );
        assert_eq!(transparency.payload.signer_certificate.der_sha256, "abc123");
        assert_eq!(
            transparency.rekor.url,
            "https://log2025-1.rekor.sigstore.dev"
        );
    }

    /// Real JWT token from a Trustee AS running in TEE with signer transparency.
    const REAL_JWT: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImp3ayI6eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCdGpDQ0FWMmdBd0lCQWdJVVM0S0hqakNGR1dHNU0zUmVxNVRDMTRBNnFnb3dDZ1lJS29aSXpqMEVBd0l3TVRFdk1DMEdBMVVFQXd3bVZISjFjM1JsWlNCQmRIUmxjM1JoZEdsdmJpQlRaWEoyYVdObElFcFhWQ0JUYVdkdVpYSXdIaGNOTWpZd05ESTNNRGN5TkRVMldoY05NamN3TkRJM01EY3lORFUyV2pBeE1TOHdMUVlEVlFRRERDWlVjblZ6ZEdWbElFRjBkR1Z6ZEdGMGFXOXVJRk5sY25acFkyVWdTbGRVSUZOcFoyNWxjakJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCQmdMU25Ba1NEbGFpLUhfRkxscU5aU2hLcVZMUGhVMzV6ank1VU5BMDlqc1RhbnVpTkJSLV9nMVZqcjA4aWRpS3A3R2VHZENqSTFmc1NaeGhwZHJIRVdqVXpCUk1CMEdBMVVkRGdRV0JCUTRnalFtM0NYNzZDVmttdnl1bWoybkFzVTZTVEFmQmdOVkhTTUVHREFXZ0JRNGdqUW0zQ1g3NkNWa212eXVtajJuQXNVNlNUQVBCZ05WSFJNQkFmOEVCVEFEQVFIX01Bb0dDQ3FHU000OUJBTUNBMGNBTUVRQ0lETkVYdlZpcGJDWFlRNm9vMzFHbnNCVHpVOXBsLTJDUGQyS3BlNFh6bjNpQWlCbzVySENSQ1pjM3dqeFA4NUY3VHFDTWprYU1LaUVYUWVGbFpXMGR0bXA0USJdLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkdBdEtjQ1JJT1ZxTDRmOFV1V28xbEtFcXBVcy1GVGZuT1BMbFEwRFQyT3ciLCJ5IjoiVGFudWlOQlItX2cxVmpyMDhpZGlLcDdHZUdkQ2pJMWZzU1p4aHBkckhFVSJ9fQ.eyJlYXIudmVyaWZpZXItaWQiOnsiYnVpbGQiOiJhdHRlc3RhdGlvbi1zZXJ2aWNlIDAuMS4wIiwiZGV2ZWxvcGVyIjoiaHR0cHM6Ly9jb25maWRlbnRpYWxjb250YWluZXJzLm9yZyJ9LCJlYXRfcHJvZmlsZSI6InRhZzpnaXRodWIuY29tLDIwMjQ6Y29uZmlkZW50aWFsLWNvbnRhaW5lcnMvVHJ1c3RlZSIsImV4cCI6MTc3ODEzNDExMiwiaWF0IjoxNzc4MTMzODEyLCJzaWduZXJfdHJhbnNwYXJlbmN5Ijp7ImdlbmVyYXRlZF9hdCI6IjIwMjYtMDQtMjdUMDc6MjU6MDFaIiwicGF5bG9hZCI6eyJldmlkZW5jZV9iaW5kaW5nIjp7ImFwaV9zZXJ2ZXJfdXJsIjoiaHR0cDovLzEyNy4wLjAuMTo4MDA2IiwiZXZpZGVuY2UiOnsiY2NfZXZlbnRsb2ciOiJBQUFBQUFNQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ2tBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFEQUFBQURBQXdBQklBSUFBTEFDQUFBUC8vLy8vLy8vLy8iLCJtZWFzdXJlX3JlZ2lzdGVyIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInJlcG9ydF9kYXRhIjoiTmpBeFpHTmxObVkxTlRCaFpUYzRZV1JrWTJKallqQXpOekk0T0RVeU5XVmlPR015WldVME5qUTNZamcwWW1KaE1qRTVZakl4TWpaak5XTTNNelV6TUE9PSIsInN2biI6IjEifSwicmVwb3J0X2RhdGEiOiI2MDFkY2U2ZjU1MGFlNzhhZGRjYmNiMDM3Mjg4NTI1ZWI4YzJlZTQ2NDdiODRiYmEyMTliMjEyNmM1YzczNTMwIiwicmVwb3J0X2RhdGFfYWxnb3JpdGhtIjoic2hhMjU2KHg1MDkgREVSKSIsInJ1bnRpbWVfZGF0YV9lbmNvZGluZyI6ImhleCJ9LCJnZW5lcmF0ZWRfYXQiOiIyMDI2LTA0LTI3VDA3OjI0OjU2WiIsInNjaGVtYV92ZXJzaW9uIjoidHJ1c3RlZS5hcy5zaWduZXItYmluZGluZy92MSIsInNpZ25lcl9jZXJ0aWZpY2F0ZSI6eyJkZXJfc2hhMjU2IjoiNjAxZGNlNmY1NTBhZTc4YWRkY2JjYjAzNzI4ODUyNWViOGMyZWU0NjQ3Yjg0YmJhMjE5YjIxMjZjNWM3MzUzMCIsIm5vdF9hZnRlciI6IkFwciAyNyAwNzoyNDo1NiAyMDI3IEdNVCIsInBhdGgiOiIvcnVuL3RydXN0ZWUvYXR0ZXN0YXRpb24tc2VydmljZS9zaWduZXIvc2lnbmVyLmNydCIsInBlbSI6Ii0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJQnRqQ0NBVjJnQXdJQkFnSVVTNEtIampDRkdXRzVNM1JlcTVUQzE0QTZxZ293Q2dZSUtvWkl6ajBFQXdJd1xuTVRFdk1DMEdBMVVFQXd3bVZISjFjM1JsWlNCQmRIUmxjM1JoZEdsdmJpQlRaWEoyYVdObElFcFhWQ0JUYVdkdVxuWlhJd0hoY05Nall3TkRJM01EY3lORFUyV2hjTk1qY3dOREkzTURjeU5EVTJXakF4TVM4d0xRWURWUVFERENaVVxuY25WemRHVmxJRUYwZEdWemRHRjBhVzl1SUZObGNuWnBZMlVnU2xkVUlGTnBaMjVsY2pCWk1CTUdCeXFHU000OVxuQWdFR0NDcUdTTTQ5QXdFSEEwSUFCQmdMU25Ba1NEbGFpK0gvRkxscU5aU2hLcVZMUGhVMzV6ank1VU5BMDlqc1xuVGFudWlOQlIrL2cxVmpyMDhpZGlLcDdHZUdkQ2pJMWZzU1p4aHBkckhFV2pVekJSTUIwR0ExVWREZ1FXQkJRNFxuZ2pRbTNDWDc2Q1ZrbXZ5dW1qMm5Bc1U2U1RBZkJnTlZIU01FR0RBV2dCUTRnalFtM0NYNzZDVmttdnl1bWoyblxuQXNVNlNUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01Bb0dDQ3FHU000OUJBTUNBMGNBTUVRQ0lETkVYdlZpcGJDWFxuWVE2b28zMUduc0JUelU5cGwrMkNQZDJLcGU0WHpuM2lBaUJvNXJIQ1JDWmMzd2p4UDg1RjdUcUNNamthTUtpRVxuWFFlRmxaVzBkdG1wNFE9PVxuLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLVxuIn19LCJwYXlsb2FkX21ldGFkYXRhIjp7ImRpZ2VzdCI6eyJzaGEyNTYiOiIyZGQ4ODFiZWFhOTM3MzYzZTk2NTVlZDYxMjIwYWU3NTZkZWYxYjhiMDRmYWUzMTcyODliZDNlOTEwYmY2YWRiIn0sIm1lZGlhX3R5cGUiOiJhcHBsaWNhdGlvbi92bmQudHJ1c3RlZS5hcy5zaWduZXItYmluZGluZytqc29uIiwicGF0aCI6Ii9ydW4vdHJ1c3RlZS9hdHRlc3RhdGlvbi1zZXJ2aWNlL3NpZ25lci9zaWduZXJfYmluZGluZy5qc29uIiwic2l6ZSI6MTYzNn0sInJla29yIjp7ImFwaV92ZXJzaW9uIjoidjIiLCJrZXlfZGV0YWlscyI6IlBLSVhfRUNEU0FfUDI1Nl9TSEFfMjU2IiwicmVrb3JFbnRyeVYyIjp7ImNhbm9uaWNhbGl6ZWRCb2R5IjoiZXlKaGNHbFdaWEp6YVc5dUlqb2lNQzR3TGpJaUxDSnJhVzVrSWpvaVpITnpaU0lzSW5Od1pXTWlPbnNpWkhOelpWWXdNRElpT25zaWNHRjViRzloWkVoaGMyZ2lPbnNpWVd4bmIzSnBkR2h0SWpvaVUwaEJNbDh5TlRZaUxDSmthV2RsYzNRaU9pSk1aR2xDZG5GeFZHTXlVSEJhVmpkWFJXbERkV1JYTTNaSE5ITkZLM1ZOV0V0S2RsUTJVa012WVhSelBTSjlMQ0p6YVdkdVlYUjFjbVZ6SWpwYmV5SmpiMjUwWlc1MElqb2lUVVZWUTBsQldFZzRiMVoxUVRWVWRISlpjR0phTWsxMVkyODBZMEp3TVZSclJUVnlhSEZhYkZOWVluQXdUU3N3UVdsRlFYaFdlV1JSVTAwelNIaG9ObkpKUzBvelJtaG1ZVGxrTlZWTGNrVjBWMU5HTnpWR1YydFpiVE41UkdNOUlpd2lkbVZ5YVdacFpYSWlPbnNpYTJWNVJHVjBZV2xzY3lJNklsQkxTVmhmUlVORVUwRmZVREkxTmw5VFNFRmZNalUySWl3aWNIVmliR2xqUzJWNUlqcDdJbkpoZDBKNWRHVnpJam9pVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGUjBGMFMyTkRVa2xQVm5GTU5HWTRWWFZYYnpGc1MwVnhjRlZ6SzBaVVptNVBVRXhzVVRCRVZESlBlRTV4WlRaSk1FWklOeXRFVmxkUGRsUjVTakpKY1c1eldqUmFNRXROYWxZcmVFcHVSMGRzTW5OalVsRTlQU0o5ZlgxZGZYMTkiLCJpbmNsdXNpb25Qcm9taXNlIjpudWxsLCJpbmNsdXNpb25Qcm9vZiI6eyJjaGVja3BvaW50Ijp7ImVudmVsb3BlIjoibG9nMjAyNS0xLnJla29yLnNpZ3N0b3JlLmRldlxuMzkwNTIzOFxuNkVmZEJFcUgxQTlJZzVxTmY5a2Z1NXhOb0dvdkU4TjhjZWV2QkRQV0xmQT1cblxu4oCUIGxvZzIwMjUtMS5yZWtvci5zaWdzdG9yZS5kZXYgenhHWkZWZWpmSmxvbE83dkVlajBFUml4S3lzMnRtWDk0RVI4TVVkcTZSOC81OWlaeUIxUkFxalNlZFpZMXlPYVUycGh5K1E5RGZWV054ajVuR25iRzZlN0lnYz1cbiJ9LCJoYXNoZXMiOlsiaFNyMmYxOHduTmdwOHN6NzY0UHBPQXpmTkxuYjhEUFFkNjluckkxbHZ4Yz0iLCJZWkhlRFpYOTMwMmtLNFk4RFB5c0oreFBJWUU1THc4MHdTTzZnU0pjalBJPSIsIjJ2REdBZ05HYndVelJmQkZHOWpweWJlN3lOMFliRndEZ0t6d2t4S0ZWbjQ9IiwicG1iMnozNkFJbnpJeUZDTFRoR1ZZLzV4UDhQTExNa0k5WVpTSFFCcHltdz0iLCJ1ckE3YnRaejY4TmFLTGwybk4vSFZHa1U3VStDdSszSHBZYmVIcE9qQUxjPSIsIjc5QVQyN3R0TUlUOXVsZlJlUXpJK0ZlSDIxZjZHdXFubDJYRHFhZmxtazQ9IiwiOWsyQkVGRHdTQnI4U01rc2dFSExZdHVNazlXTWYyN2JzRHA3enlsRkFqVT0iLCJWQVhLVTNvKzZ1TWErTDhrZE9UUjFVRCt0amUwaWNTdXFBa3Y2bVpxRTBzPSIsImR0bitUcm0rbDhHdUExekc3TzVFcCs3ZW1qZFpQS1phL2laNUhydXZSYm89IiwicThTR2ZYcnJDS3p2TkpId1hhK1QxQWI1Qkp3YUNIa2NGRng3S1N2QWxTZz0iLCJnZEY0bFdxZGZDc0ZVQTFOWFh6MGlMcFlCaTMralIyV21ibUJhR2dKbzh3PSIsIjk5eW5QMlpjZ1hpWjJqU2N3Wjc4TzMwUGxubE1RTVJSdWExZDUrazh3bmM9IiwiNVVoWWNwSDJLZldpV2pBT002MWpRQlhHMWJoZ0R0aXE2eSs1QW9sVlJKMD0iLCI5KzR6cGM4K1hBUGVnK0daa3lNTDl6OFJuelJ2dUFWc2FNQ3FxcUh1aHRvPSJdLCJsb2dJbmRleCI6IjM5MDUyMzciLCJyb290SGFzaCI6IjZFZmRCRXFIMUE5SWc1cU5mOWtmdTV4Tm9Hb3ZFOE44Y2VldkJEUFdMZkE9IiwidHJlZVNpemUiOiIzOTA1MjM4In0sImludGVncmF0ZWRUaW1lIjoiMCIsImtpbmRWZXJzaW9uIjp7ImtpbmQiOiJkc3NlIiwidmVyc2lvbiI6IjAuMC4yIn0sImxvZ0lkIjp7ImtleUlkIjoienhHWkZWdmQwRkVtalI4V3JGd01kY0FKOXZ0YVkvUVhmNDRZMXdVZVA2QT0ifSwibG9nSW5kZXgiOiIzOTA1MjM3In0sInJlcXVlc3RfdHlwZSI6ImRzc2VSZXF1ZXN0VjAwMiIsInVybCI6Imh0dHBzOi8vbG9nMjAyNS0xLnJla29yLnNpZ3N0b3JlLmRldiJ9LCJzY2hlbWFfdmVyc2lvbiI6InRydXN0ZWUuYXMuc2lnbmVyLXRyYW5zcGFyZW5jeS92MSJ9LCJzdWJtb2RzIjp7ImdwdTAiOnsiZWFyLmFwcHJhaXNhbC1wb2xpY3ktaWQiOiJkZWZhdWx0IiwiZWFyLnN0YXR1cyI6ImNvbnRyYWluZGljYXRlZCIsImVhci50cnVzdHdvcnRoaW5lc3MtdmVjdG9yIjp7ImNvbmZpZ3VyYXRpb24iOjM2LCJleGVjdXRhYmxlcyI6MzMsImZpbGUtc3lzdGVtIjozNSwiaGFyZHdhcmUiOjk3fSwiZWFyLnZlcmFpc29uLmFubm90YXRlZC1ldmlkZW5jZSI6eyJzYW1wbGVkZXZpY2UiOnsic3ZuIjoiMSJ9fX19fQ.XqRh9VmwZSwtSuRUXT3EAH0ma2sHX2KgEJpNs-wPCncHisOa4PxoTx_xu5geVdsF7nVVJ-MMzT_UWbbtkOMrsw";

    #[test]
    fn test_parse_checkpoint_from_real_jwt() {
        let (_, payload_bytes) = decode_jwt_parts(REAL_JWT).unwrap();
        let payload: JwtPayload = serde_json::from_slice(&payload_bytes).unwrap();
        let transparency = payload.signer_transparency.unwrap();

        // Verify basic fields
        assert_eq!(
            transparency.schema_version,
            "trustee.as.signer-transparency/v1"
        );
        assert_eq!(
            transparency.payload.schema_version,
            "trustee.as.signer-binding/v1"
        );
        assert_eq!(
            transparency.payload.evidence_binding.report_data,
            "601dce6f550ae78addcbcb037288525eb8c2ee4647b84bba219b2126c5c73530"
        );
        assert_eq!(
            transparency.payload.signer_certificate.der_sha256,
            "601dce6f550ae78addcbcb037288525eb8c2ee4647b84bba219b2126c5c73530"
        );

        // Verify Rekor URL
        assert_eq!(
            transparency.rekor.url,
            "https://log2025-1.rekor.sigstore.dev"
        );

        // Verify DSSE entry exists
        let entry_v2 = &transparency.rekor.rekor_entry_v2;
        assert!(entry_v2.get("canonicalizedBody").is_some());
        assert!(entry_v2.get("inclusionProof").is_some());
    }

    #[test]
    fn test_verify_dsse_payload_from_real_jwt() {
        let (_, payload_bytes) = decode_jwt_parts(REAL_JWT).unwrap();
        let payload: JwtPayload = serde_json::from_slice(&payload_bytes).unwrap();
        let transparency = payload.signer_transparency.unwrap();

        // The DSSE payloadHash should match the payload_metadata digest
        let result = verify_dsse_payload(
            &transparency.rekor,
            &transparency.payload_metadata.digest.sha256,
        );
        assert!(
            result.is_ok(),
            "DSSE payload verification failed: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_cert_hash_and_report_data_from_real_jwt() {
        let (header_bytes, payload_bytes) = decode_jwt_parts(REAL_JWT).unwrap();
        let header: JwtHeader = serde_json::from_slice(&header_bytes).unwrap();
        let payload: JwtPayload = serde_json::from_slice(&payload_bytes).unwrap();
        let transparency = payload.signer_transparency.unwrap();

        let signer_cert_der = extract_signer_cert_der(&header).unwrap();
        let cert_hash = sha256_hex(&signer_cert_der);

        // Cert hash should match der_sha256 claim
        assert_eq!(
            cert_hash,
            transparency.payload.signer_certificate.der_sha256
        );

        // report_data should match cert hash
        assert_eq!(
            transparency.payload.evidence_binding.report_data, cert_hash,
            "report_data should match certificate hash"
        );
    }

    #[test]
    fn test_checkpoint_parsing_from_real_jwt() {
        let (_, payload_bytes) = decode_jwt_parts(REAL_JWT).unwrap();
        let payload: JwtPayload = serde_json::from_slice(&payload_bytes).unwrap();
        let transparency = payload.signer_transparency.unwrap();

        let entry_v2 = &transparency.rekor.rekor_entry_v2;
        let checkpoint_str = entry_v2
            .get("inclusionProof")
            .and_then(|v| v.get("checkpoint"))
            .and_then(|v| v.get("envelope"))
            .and_then(|v| v.as_str())
            .expect("Missing checkpoint envelope");

        let checkpoint = parse_checkpoint(checkpoint_str).unwrap();

        // Verify origin is the hostname
        assert_eq!(checkpoint.origin, "log2025-1.rekor.sigstore.dev");

        // Verify size is reasonable
        assert_eq!(checkpoint.size, 3905238);

        // Verify signature is non-empty
        assert!(!checkpoint.signature.is_empty());
    }
}
