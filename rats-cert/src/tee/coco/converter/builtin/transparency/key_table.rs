//! The built-in Rekor v1 key table and key resolution.
//!
//! Rekor keys are resolved either from an explicit PEM, from the built-in table
//! by log URL hostname, or, when the URL is an artifact-server proxy whose
//! hostname matches no built-in key, by matching the entry's `logID` against
//! each built-in key.

use anyhow::{Context, Result};
use base64::Engine;
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};

use super::dsse::{pem_to_spki_b64, verifying_key_from_spki_der};
use super::rekor_v1::RekorEntry;

/// A resolved Rekor public key: the P-256 verifying key plus its PKIX-SPKI
/// DER bytes (needed because `logID` = `sha256(SPKI DER)`).
#[derive(Debug)]
pub(crate) struct RekorKey {
    pub(crate) verifying_key: VerifyingKey,
    pub(crate) spki_der: Vec<u8>,
}

/// Sigstore Rekor v1 public key as base64 SPKI.
const SIGSTORE_REKOR_V1_SPKI_B64: &str =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==";

/// OpenAnolis Rekor v1 public key as base64 SPKI.
const OPENANOLIS_REKOR_V1_SPKI_B64: &str =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXQ2ngaAbWq3XILAb3ZlIpZ/AIdUjkcjkZNjAeQmDGY9qqbNmT/eQZ1nBJw6vd6S0Rq5F9rb3oYLTNejEEhCd0A==";

/// Built-in Rekor v1 `(hostname, base64-SPKI)` pairs, the single source of
/// truth that [`rekor_public_key`] matches on. Callers that enumerate every
/// built-in key (the `logID` fallback in [`resolve_rekor_key`]) iterate this
/// table instead of restating the hostnames.
pub(crate) fn known_rekor_keys() -> &'static [(&'static str, &'static str)] {
    &[
        ("rekor.sigstore.dev", SIGSTORE_REKOR_V1_SPKI_B64),
        ("rekor.openanolis.cn", OPENANOLIS_REKOR_V1_SPKI_B64),
    ]
}

/// Resolve the Rekor public key: an explicit PEM if provided, else a built-in
/// table keyed by `log_url` hostname.
pub(crate) fn rekor_public_key(log_url: &str, explicit: Option<&str>) -> Result<RekorKey> {
    let spki_b64: String = match explicit {
        Some(p) if !p.is_empty() => pem_to_spki_b64(p)?,
        _ => match hostname_of(log_url)?.as_str() {
            "rekor.sigstore.dev" => SIGSTORE_REKOR_V1_SPKI_B64.to_string(),
            "rekor.openanolis.cn" => OPENANOLIS_REKOR_V1_SPKI_B64.to_string(),
            other => {
                anyhow::bail!(
                    "no built-in Rekor v1 public key for {other:?}; set rekorPublicKeyPem"
                )
            }
        },
    };
    let spki_der = base64::engine::general_purpose::STANDARD
        .decode(spki_b64.as_bytes())
        .context("base64-decode Rekor public key SPKI")?;
    let verifying_key = verifying_key_from_spki_der(&spki_der)?;
    Ok(RekorKey {
        verifying_key,
        spki_der,
    })
}

/// Resolve the Rekor public key for a fetched entry. Tries hostname-based
/// resolution first; if that fails (the `log_url` is an artifact-server proxy
/// whose hostname matches no built-in key, e.g. a wiremock test URL or an
/// internal proxy), fall back to trying each built-in key by `verify_log_id`
/// against the entry's `logID` (= `sha256(SPKI DER)`). This keeps the on-demand
/// fallback working when the artifact-server proxy fronts a real Rekor instance
/// under a different hostname, without duplicating the key table.
pub(crate) fn resolve_rekor_key(entry: &RekorEntry, log_url: &str) -> Result<RekorKey> {
    // Fast path: hostname-based resolution.
    if let Ok(key) = rekor_public_key(log_url, None) {
        return Ok(key);
    }
    // Fallback: unknown hostname (artifact-server proxy / test mock). Try the
    // built-in keys by logID match. Iterate the single-source-of-truth table so
    // a third built-in key is picked up automatically.
    for (host, _) in known_rekor_keys() {
        if let Ok(key) = rekor_public_key(&format!("https://{host}"), None) {
            if verify_log_id(entry, &key).is_ok() {
                return Ok(key);
            }
        }
    }
    anyhow::bail!(
        "could not resolve Rekor public key for log_url {log_url} \
         (entry logID {} matched no built-in key; set rekorPublicKeyPem)",
        entry.log_id
    );
}

fn hostname_of(url: &str) -> Result<String> {
    let no_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = no_scheme.split('/').next().unwrap_or(no_scheme);
    Ok(host.to_string())
}

/// Compute the Rekor public key ID: `hex(sha256(PKIX-SPKI DER))`.
pub(crate) fn public_key_id(spki_der: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(spki_der);
    hex::encode(h.finalize())
}

/// Verify the Rekor log ID: entry.log_id == public_key_id(key), compared
/// case-insensitively. Rekor logIDs are lowercase hex sha256(SPKI), but a
/// response/fixture may carry an uppercase encoding; the identity check is
/// encoding-agnostic.
pub(crate) fn verify_log_id(entry: &RekorEntry, key: &RekorKey) -> Result<()> {
    let want = public_key_id(&key.spki_der);
    if !entry.log_id.eq_ignore_ascii_case(&want) {
        anyhow::bail!("Rekor logID mismatch: entry={} key={}", entry.log_id, want);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::coco::converter::builtin::policies::test_support::fixtures;

    fn fixture_entry() -> RekorEntry {
        serde_json::from_str(fixtures::REKOR_V1_ENTRY_JSON).expect("parse fixture entry")
    }

    #[test]
    fn fixture_log_id_matches_sigstore_key() {
        let entry = fixture_entry();
        let key = rekor_public_key("https://rekor.sigstore.dev", None).expect("resolve key");
        verify_log_id(&entry, &key).expect("logID must match Sigstore key");
    }

    /// `verify_log_id` compares case-insensitively: an uppercase-hex logID that
    /// decodes to the same bytes as the key's `sha256(SPKI)` must still match.
    #[test]
    fn verify_log_id_is_case_insensitive() {
        let mut entry = fixture_entry();
        let key = rekor_public_key("https://rekor.sigstore.dev", None).expect("resolve key");
        entry.log_id = entry.log_id.to_uppercase();
        verify_log_id(&entry, &key).expect("uppercase logID must match (case-insensitive)");
    }

    /// An explicit PEM wins over the hostname table.
    #[test]
    fn explicit_pem_resolves_the_key() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----\n";
        let key = rekor_public_key("https://unknown.example", Some(pem)).expect("explicit key");
        assert_eq!(key.spki_der.len(), 91);
    }

    /// An unknown hostname and a logID matching no built-in key is an error.
    #[test]
    fn resolve_rekor_key_bails_when_no_key_matches() {
        let entry = RekorEntry {
            body: String::new(),
            integrated_time: 0,
            log_id: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            log_index: 0,
            verification: super::super::rekor_v1::RekorVerification {
                inclusion_proof: super::super::rekor_v1::InclusionProof {
                    checkpoint: String::new(),
                    hashes: vec![],
                    log_index: 0,
                    root_hash: String::new(),
                    tree_size: 1,
                },
                signed_entry_timestamp: String::new(),
            },
        };
        let err = resolve_rekor_key(&entry, "http://127.0.0.1:99999").unwrap_err();
        assert!(
            err.to_string()
                .contains("could not resolve Rekor public key"),
            "got: {err}"
        );
    }

    /// The fixture entry resolves through the `logID` fallback even when the
    /// URL's hostname is not a built-in one (the artifact-server proxy case).
    #[test]
    fn resolve_rekor_key_matches_log_id_for_proxy_url() {
        let entry = fixture_entry();
        let key = resolve_rekor_key(&entry, "http://127.0.0.1:1234").expect("logID fallback");
        verify_log_id(&entry, &key).expect("resolved key must match the entry");
    }
}
