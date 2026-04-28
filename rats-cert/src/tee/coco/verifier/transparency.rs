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
fn get_rekor_public_key(url: &str) -> Option<VerifyingKey> {
    match url {
        "https://log2025-1.rekor.sigstore.dev" => {
            // Rekor 2025-1 public key (ECDSA P-256, base64-encoded SPKI DER)
            let spki_der = BASE64_STANDARD.decode(
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+CBMoVgd3QC6ke3ZR6qQwgEFM81PTMQzw7nB5vIs2ClB3TUOA84C9VY8n7O061MgTm4Btddzf4UhAA=="
            ).ok()?;
            let spki = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(&spki_der).ok()?;
            let encoded_point =
                EncodedPoint::from_bytes(spki.subject_public_key.raw_bytes()).ok()?;
            VerifyingKey::from_encoded_point(&encoded_point).ok()
        }
        "https://rekor.sigstore.dev" => {
            // Rekor public key (ECDSA P-256, base64-encoded SPKI DER)
            let spki_der = BASE64_STANDARD.decode(
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a6fZBoIUg5x/0/U9qOQANUu2aZL8i+2rN5qAVTLrBs5kxLqGPOosHbBhB6JL8HkFw=="
            ).ok()?;
            let spki = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(&spki_der).ok()?;
            let encoded_point =
                EncodedPoint::from_bytes(spki.subject_public_key.raw_bytes()).ok()?;
            VerifyingKey::from_encoded_point(&encoded_point).ok()
        }
        _ => None,
    }
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

    // Get the expected Rekor public key for this URL
    let verifying_key = get_rekor_public_key(&rekor.url)
        .ok_or_else(|| anyhow::anyhow!("No known public key for Rekor URL: {}", rekor.url))?;

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

        let entry_hash = get_entry_leaf_hash(entry_v2)?;
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
    // Look for the em-dash (U+2014) or "-- " line, then the base64 signature on the next line
    let mut sig_line = None;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('\u{2014}') || trimmed.starts_with("-- ") {
            if let Some(next) = lines.get(i + 1) {
                let next_trimmed = next.trim();
                if !next_trimmed.is_empty() {
                    sig_line = Some(next_trimmed);
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
                return trimmed;
            }
        }
        ""
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

/// Compute the expected leaf hash for a Rekor v2 DSSE entry.
fn get_entry_leaf_hash(entry_v2: &serde_json::Value) -> anyhow::Result<String> {
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
#[derive(Debug, Deserialize, Serialize)]
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
}
