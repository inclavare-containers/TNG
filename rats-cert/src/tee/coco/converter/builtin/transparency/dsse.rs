//! DSSE and canonical-JSON primitives shared by every transparency-log path.
//!
//! The policy-load bake, the artifact-server resolve, and the rekor on-demand
//! fallback all verify the same publisher signature over the same canonical
//! payload, so the primitives live here once instead of being restated in each
//! caller.

use anyhow::{Context, Result};
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::VerifyingKey;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::EncodedPoint;
use sha2::{Digest, Sha256};
use x509_cert::der::Decode as _;
use x509_cert::spki::SubjectPublicKeyInfoRef;

/// DSSE payload type for the ReleaseManifest signatures. Hardcoded to the
/// release-manifest payload type
/// `application/vnd.alibabacloud.confidential-computing.release+json`
/// (the `payloadType` the publisher signs over).
pub(crate) const DSSE_PAYLOAD_TYPE: &str =
    "application/vnd.alibabacloud.confidential-computing.release+json";

/// The built-in DSSE publisher key, used as the fail-closed default when no
/// publisher key is configured. DSSE verification is mandatory, so there is
/// always a trusted publisher key.
pub(crate) const BUILTIN_LOG_ENTRY_PUB_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsGjh0eIF22/JwEkRvU5KROvNsL/F\nK6qP/kbKO0CoelOqRKJQuC9z0ruwyx12S94/m69+iaan0SKR1IJjIbbfHw==\n-----END PUBLIC KEY-----";

/// DSSE v1 pre-authentication encoding:
/// `DSSEv1 {len(ptype)} {ptype} {len(payload)} {payload}`. The PAE (with the
/// payload bytes appended after the space-terminated prefix) is what a DSSE
/// publisher signature is computed over.
pub(crate) fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let prefix = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut out = prefix.into_bytes();
    out.extend_from_slice(payload);
    out
}

/// The trusted publisher PEM: the configured key when non-empty, the built-in
/// key otherwise. Every transparency path requires a publisher key, so this
/// never returns an empty string.
pub(crate) fn effective_publisher_pem(configured: Option<&str>) -> &str {
    configured
        .filter(|s| !s.is_empty())
        .unwrap_or(BUILTIN_LOG_ENTRY_PUB_KEY_PEM)
}

/// Resolve the DSSE signature to bake into a `transparency_log` entry.
///
/// A real rekor v1 `dsse` entry always carries a signature in
/// `body.spec.signatures[0].signature`. An empty signature therefore means a
/// malformed/non-dsse entry: fail closed rather than silently emitting a
/// weaker payloadHash-only policy.
pub(crate) fn require_dsse_signature(dsse_signature: &str) -> Result<&str> {
    if dsse_signature.is_empty() {
        anyhow::bail!(
            "rekor entry has no DSSE signature (malformed/non-dsse entry; \
             body.spec.signatures[0].signature is required)"
        );
    }
    Ok(dsse_signature)
}

/// Serialize a `serde_json::Value` as RFC 8785 JCS canonical JSON (sorted
/// keys, compact) via the `canon-json` crate. The manifest shapes here are
/// number-free, so this also equals Rego's `json.marshal` output, keeping the
/// load-time `payloadHash` consistent with the appraisal-time recomputation.
pub(crate) fn canonical_json(value: &serde_json::Value) -> Result<String> {
    let mut buf = Vec::new();
    let mut ser =
        serde_json::Serializer::with_formatter(&mut buf, canon_json::CanonicalFormatter::new());
    serde::Serialize::serialize(value, &mut ser).context("serialize canonical JSON")?;
    String::from_utf8(buf).context("canonical JSON is not valid UTF-8")
}

/// JCS (RFC 8785) canonical bytes of a manifest, the intermediate shared by
/// the `payloadHash` comparison and the DSSE PAE construction so both paths
/// agree on the canonical payload for a given manifest.
pub(crate) fn canonical_manifest_bytes(manifest: &serde_json::Value) -> Result<String> {
    canonical_json(manifest)
}

/// Canonicalize a manifest and sha256 it, returning the lowercase-hex digest
/// the rekor entry publishes as `payloadHash`.
pub(crate) fn canonical_manifest_sha256(manifest: &serde_json::Value) -> Result<String> {
    let canon = canonical_manifest_bytes(manifest)?;
    let mut hasher = Sha256::new();
    hasher.update(canon.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Strip PEM `-----BEGIN/END PUBLIC KEY-----` wrappers, return the base64 body.
pub(crate) fn pem_to_spki_b64(pem: &str) -> Result<String> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .collect();
    Ok(b64)
}

/// Construct a P-256 verifying key from PKIX-SPKI DER bytes.
pub(crate) fn verifying_key_from_spki_der(spki_der: &[u8]) -> Result<VerifyingKey> {
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der).context("parse public key SPKI DER")?;
    let encoded_point = EncodedPoint::from_bytes(spki.subject_public_key.raw_bytes())
        .context("decode public key point")?;
    VerifyingKey::from_encoded_point(&encoded_point).context("construct verifying key")
}

/// Parse a PEM-encoded P-256 public key (`-----BEGIN PUBLIC KEY-----`) into
/// a `VerifyingKey`.
pub(crate) fn parse_p256_public_key(pem: &str) -> Result<VerifyingKey> {
    let spki_b64 = pem_to_spki_b64(pem)?;
    let spki_der = base64::engine::general_purpose::STANDARD
        .decode(spki_b64.as_bytes())
        .context("base64-decode publisher public key SPKI")?;
    verifying_key_from_spki_der(&spki_der)
}

/// Verify a base64-encoded DER ECDSA publisher signature over
/// `sha256(DSSEPAE(canonical_manifest))` with the P-256 publisher key.
/// `VerifyingKey::verify` hashes the PAE with SHA-256 internally, equivalent
/// to an ECDSA P-256 `VerifyASN1(sha256(pae), sig)`.
pub(crate) fn verify_publisher_signature(
    publisher_pem: &str,
    canonical_manifest: &[u8],
    dsse_signature_b64: &str,
) -> Result<()> {
    let publisher_key = parse_p256_public_key(publisher_pem)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(dsse_signature_b64)
        .context("base64-decode DSSE publisher signature")?;
    let signature = p256::ecdsa::Signature::from_der(&sig_bytes)
        .context("parse DSSE publisher ECDSA signature")?;
    let pae = dsse_pae(DSSE_PAYLOAD_TYPE, canonical_manifest);
    publisher_key
        .verify(&pae, &signature)
        .context("DSSE publisher signature verification failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::tee::coco::converter::builtin::test_fixtures::{
        jcs_compact, manifest, sha256_hex, REKOR_V1_ENTRY_JSON,
    };
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use serde_json::Value;

    use super::*;

    /// A real rekor v1 `dsse` entry always carries a signature, so an empty
    /// signature means a malformed/non-dsse entry and must fail closed.
    #[test]
    fn require_dsse_signature_matches_expectations() {
        assert_eq!(require_dsse_signature("sig").expect("sig -> Ok"), "sig");
        let err = require_dsse_signature("").expect_err("empty must fail closed");
        assert!(
            err.to_string().contains("no DSSE signature"),
            "error should describe the missing signature, got: {err}"
        );
    }

    /// A non-empty configured key wins; an empty/absent one falls back to the
    /// built-in publisher key.
    #[test]
    fn effective_publisher_pem_falls_back_to_builtin() {
        assert_eq!(effective_publisher_pem(None), BUILTIN_LOG_ENTRY_PUB_KEY_PEM);
        assert_eq!(
            effective_publisher_pem(Some("")),
            BUILTIN_LOG_ENTRY_PUB_KEY_PEM
        );
        assert_eq!(effective_publisher_pem(Some("configured")), "configured");
    }

    /// The canonical form sorts object keys and drops whitespace.
    #[test]
    fn canonical_json_is_sorted_and_compact() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{ "b": 1, "a": [{ "z": true, "y": "x" }] }"#).unwrap();
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":[{"y":"x","z":true}],"b":1}"#
        );
    }

    #[test]
    fn serde_json_serialization_matches_real_rekor_payload_hash() {
        let logged = manifest(
            "1.0.0",
            &[(
                "container.image.cmaas-runtime",
                "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
            )],
        );
        assert_eq!(
            sha256_hex(jcs_compact(&logged).as_bytes()),
            "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8",
            "JCS (sorted compact) form must equal the real rekor payloadHash"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_dsse_signature_validates_real_fixture_signature() {
        use p256::ecdsa::signature::Verifier;

        let entry_raw = REKOR_V1_ENTRY_JSON;
        let entry: Value = serde_json::from_str(entry_raw).expect("parse fixture");
        let body_bytes = BASE64_STANDARD
            .decode(entry["body"].as_str().expect("body"))
            .expect("decode entry body");
        let body: Value = serde_json::from_slice(&body_bytes).expect("parse body");
        let sig0 = &body["spec"]["signatures"][0];
        let sig_b64 = sig0["signature"].as_str().expect("signature").to_string();
        let verifier_pem = String::from_utf8(
            BASE64_STANDARD
                .decode(sig0["verifier"].as_str().expect("verifier"))
                .expect("decode verifier b64"),
        )
        .expect("publisher PEM utf8");

        let logged = manifest(
            "1.0.0",
            &[(
                "container.image.cmaas-runtime",
                "sha256:d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
            )],
        );
        let payload = jcs_compact(&logged);

        let verify = |payload_str: &str, sig_b64: &str, key_pem: &str| -> bool {
            (|| -> anyhow::Result<bool> {
                let key = parse_p256_public_key(key_pem)?;
                let sig_bytes = BASE64_STANDARD.decode(sig_b64)?;
                let signature = p256::ecdsa::Signature::from_der(&sig_bytes)?;
                let pae = dsse_pae(DSSE_PAYLOAD_TYPE, payload_str.as_bytes());
                key.verify(&pae, &signature)?;
                Ok(true)
            })()
            .unwrap_or(false)
        };

        assert!(
            verify(&payload, &sig_b64, &verifier_pem),
            "real fixture DSSE signature must verify with its publisher key"
        );

        let tampered = payload.replace(
            "d42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
            "e42f6e1b2aafb59383d0892824aebf5e0a2e27dad989a3fb26552a6e77e4be46",
        );
        assert_ne!(payload, tampered, "tamper did not change payload");
        assert!(
            !verify(&tampered, &sig_b64, &verifier_pem),
            "tampered manifest must fail DSSE verification"
        );

        let wrong_pem = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n\
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n\
-----END PUBLIC KEY-----\n";
        assert!(
            !verify(&payload, &sig_b64, wrong_pem),
            "wrong publisher key must fail DSSE verification"
        );
    }
}
