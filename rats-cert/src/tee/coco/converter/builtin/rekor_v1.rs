//! Rekor v1 transparency-log entry fetch + authentication (by logIndex):
//! fetch a Rekor v1 entry by logIndex, authenticate it via checkpoint +
//! Merkle inclusion + SET, and return the trusted `payloadHash` (from
//! `body.spec.payloadHash.value`) plus the in-band DSSE signature
//! (`body.spec.signatures[0].signature`).
//!
//! This module only EXTRACTS the DSSE signature; the actual signature
//! verification (DSSEPAE + SHA-256 + ECDSA P-256) and JCS canonicalization
//! happen later, at appraisal time, in the generated Rego policy's
//! `verify_dsse_signature` host-await layer (see the supplement spec
//! `docs/superpowers/specs/2026-08-23-rekor-transparency-policy-dsse-supplement-design.md`).

use anyhow::{Context, Result};
use base64::Engine;
use serde::Deserialize;

/// A Rekor v1 transparency-log entry (the raw object returned by
/// `GET /api/v1/log/entries?logIndex=<n>`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RekorEntry {
    pub(crate) body: String,
    pub(crate) integrated_time: i64,
    // JSON key is `logID` (capital ID); camelCase would yield `logId`.
    #[serde(rename = "logID")]
    pub(crate) log_id: String,
    pub(crate) log_index: i64,
    pub(crate) verification: RekorVerification,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RekorVerification {
    pub(crate) inclusion_proof: InclusionProof,
    pub(crate) signed_entry_timestamp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InclusionProof {
    pub(crate) checkpoint: String,
    pub(crate) hashes: Vec<String>,
    pub(crate) log_index: i64,
    pub(crate) root_hash: String,
    pub(crate) tree_size: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RekorBody {
    #[serde(rename = "apiVersion")]
    // Parsed from the wire `apiVersion` field but never read by the fetch/
    // authenticate/bake pipeline — keep it (part of the wire format) but scope
    // the dead-code suppression here instead of module-wide.
    #[allow(dead_code)]
    pub(crate) api_version: Option<String>,
    pub(crate) kind: Option<String>,
    pub(crate) spec: RekorBodySpec,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RekorBodySpec {
    #[serde(rename = "payloadHash")]
    pub(crate) payload_hash: Option<PayloadHash>,
    // DSSE signatures carried in-band in the Rekor entry body
    // (`body.spec.signatures[0]`). `verifier` is the base64-encoded publisher
    // PEM embedded by the signer — it is NOT the trust anchor (the config
    // `rekorPublicKeyPem` / built-in Rekor key is). Extracted here so the
    // generated Rego policy can verify the DSSE signature at appraisal time.
    #[serde(default)]
    pub(crate) signatures: Option<Vec<RekorSignature>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RekorSignature {
    pub(crate) signature: String,
    // Structural wire field; deserialized but not read in the non-test build
    // (only the fixture round-trip test accesses it). Kept so the full
    // `RekorSignature` wire type round-trips; silence dead-code as for
    // `api_version` above.
    #[allow(dead_code)]
    pub(crate) verifier: String,
}

/// The authenticated result of verifying a Rekor v1 transparency-log entry:
/// the trusted `payloadHash` (from `body.spec.payloadHash.value`) plus the
/// in-band DSSE signature (`body.spec.signatures[0].signature`) extracted for
/// downstream policy verification.
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) struct AuthenticatedRekorEntry {
    pub(crate) payload_hash: String,
    // Read in the non-test build via `resolve_dsse_signature` (builtin/mod.rs),
    // which threads it into the generated Rego policy as the DSSE signature
    // literal for `verify_dsse_signature`.
    pub(crate) dsse_signature: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PayloadHash {
    pub(crate) algorithm: String,
    pub(crate) value: String,
}

/// Base64-decode `entry.body` and deserialize into [`RekorBody`]. Requires
/// `kind == "dsse"`.
pub(crate) fn decode_rekor_body(entry: &RekorEntry) -> Result<RekorBody> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&entry.body)
        .context("base64-decode Rekor entry body")?;
    let body: RekorBody = serde_json::from_slice(&raw).context("parse Rekor body JSON")?;
    if body.kind.as_deref() != Some("dsse") {
        anyhow::bail!(
            "unsupported Rekor body kind: {:?} (expected dsse)",
            body.kind
        );
    }
    Ok(body)
}

#[cfg(feature = "crypto-rustcrypto")]
mod key {
    use super::{InclusionProof, RekorEntry};
    use anyhow::{Context, Result};
    use base64::Engine;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::EncodedPoint;
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use x509_cert::der::Decode as _;
    use x509_cert::spki::SubjectPublicKeyInfoRef;

    /// A resolved Rekor public key: the P-256 verifying key plus its PKIX-SPKI
    /// DER bytes (needed because `logID` = `sha256(SPKI DER)`).
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

    /// Resolve the Rekor public key: an explicit PEM if provided, else a built-in
    /// table keyed by `log_url` hostname, using base64 SPKI + `x509_cert` decode
    /// with the v1 keys.
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
        let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).context("parse Rekor SPKI DER")?;
        let encoded_point = EncodedPoint::from_bytes(spki.subject_public_key.raw_bytes())
            .context("decode Rekor public key point")?;
        let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
            .context("construct Rekor verifying key")?;
        Ok(RekorKey {
            verifying_key,
            spki_der,
        })
    }

    /// Strip PEM `-----BEGIN/END PUBLIC KEY-----` wrappers, return the base64 body.
    fn pem_to_spki_b64(pem: &str) -> Result<String> {
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .flat_map(|l| l.chars())
            .collect();
        Ok(b64)
    }

    /// Parse a PEM-encoded P-256 public key (`-----BEGIN PUBLIC KEY-----`) into
    /// a `VerifyingKey`. Reused by the `verify_dsse_signature` host-await
    /// primitive to parse the transparency-log publisher key — the same SPKI
    /// decode path as `rekor_public_key`, minus the built-in hostname table.
    pub(crate) fn parse_p256_public_key(pem: &str) -> Result<VerifyingKey> {
        let spki_b64 = pem_to_spki_b64(pem)?;
        let spki_der = base64::engine::general_purpose::STANDARD
            .decode(spki_b64.as_bytes())
            .context("base64-decode publisher public key SPKI")?;
        let spki = SubjectPublicKeyInfoRef::from_der(&spki_der)
            .context("parse publisher public key SPKI DER")?;
        let encoded_point = EncodedPoint::from_bytes(spki.subject_public_key.raw_bytes())
            .context("decode publisher public key point")?;
        VerifyingKey::from_encoded_point(&encoded_point)
            .context("construct publisher verifying key")
    }

    fn hostname_of(url: &str) -> Result<String> {
        let no_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        let host = no_scheme.split('/').next().unwrap_or(no_scheme);
        Ok(host.to_string())
    }

    /// RFC 6962 SHA-256 tree hashing, matching Go's
    /// `github.com/transparency-dev/merkle/rfc6962.DefaultHasher`.
    fn hash_leaf(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x00]); // leaf prefix
        h.update(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }

    fn hash_intermediate(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x01]); // node prefix
        h.update(left);
        h.update(right);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }

    /// Merkle inclusion proof verification. Leaf =
    /// `HashLeaf(base64-decoded entry.body bytes)`; walk `proof.hashes` per RFC
    /// 6962 inclusion (transparency-dev/merkle/proof `VerifyInclusion`) and
    /// require the final hash == `proof.root_hash`.
    ///
    /// The proof list carries only the siblings that *exist* along the path, so
    /// it is shorter than the tree height: at each level the current node is
    /// combined with the next proof hash only when its sibling exists; when the
    /// node is the last in its level (no right sibling) it is carried up
    /// unchanged and no hash is consumed. This mirrors the canonical
    /// transparency-dev walk: track `fn` (current node index) and `sn` (index of
    /// the last node at the current level, starting at `treeSize - 1`); loop
    /// until both reach the root (`fn == sn && sn == 0`).
    pub(crate) fn verify_inclusion_proof(entry: &RekorEntry) -> Result<()> {
        let proof = &entry.verification.inclusion_proof;
        if proof.tree_size <= 0 {
            anyhow::bail!("non-positive treeSize");
        }
        if !(0..proof.tree_size).contains(&proof.log_index) {
            anyhow::bail!("logIndex out of range for treeSize");
        }
        let leaf_input = base64::engine::general_purpose::STANDARD
            .decode(&entry.body)
            .context("base64-decode entry body for leaf hash")?;
        let mut node = hash_leaf(&leaf_input);
        // Pre-decode all sibling hashes once.
        let siblings: Vec<[u8; 32]> = proof
            .hashes
            .iter()
            .map(|hb| {
                let h =
                    hex::decode(hb).with_context(|| format!("hex-decode inclusion hash {hb}"))?;
                h.as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("inclusion hash not 32 bytes: {hb}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut fn_ = proof.log_index as u64;
        let mut sn = (proof.tree_size - 1) as u64;
        let mut pi = 0usize;
        while fn_ != sn || sn != 0 {
            if pi >= siblings.len() {
                anyhow::bail!("Merkle inclusion proof too short for treeSize/logIndex");
            }
            // RFC 6962: a right child (odd index) is hashed with its sibling on
            // the left; a left child (even index) is hashed with its right
            // sibling only if that sibling exists (`fn < sn`); otherwise the
            // node is the last in its level and is carried up unchanged.
            if fn_ % 2 == 1 {
                node = hash_intermediate(&siblings[pi], &node);
                pi += 1;
            } else if fn_ < sn {
                node = hash_intermediate(&node, &siblings[pi]);
                pi += 1;
            }
            fn_ >>= 1;
            // Parent of the last node: a right child (odd) collapses with its
            // left sibling (`(sn - 1) >> 1`); a left child (even) is the sole
            // node of its subtree and its parent is `sn >> 1`.
            sn = if sn % 2 == 1 { (sn - 1) >> 1 } else { sn >> 1 };
        }
        if pi != siblings.len() {
            anyhow::bail!(
                "Merkle inclusion proof failed: consumed {pi} of {} sibling hashes",
                siblings.len()
            );
        }
        let root = hex::decode(&proof.root_hash).context("hex-decode rootHash")?;
        if node.as_slice() != root.as_slice() {
            anyhow::bail!("Merkle inclusion proof failed: computed root != proof rootHash");
        }
        Ok(())
    }

    /// Compute the Rekor public key ID: `hex(sha256(PKIX-SPKI DER))`.
    pub(crate) fn public_key_id(spki_der: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(spki_der);
        hex::encode(h.finalize())
    }

    /// Verify the Rekor log ID: entry.log_id == public_key_id(key).
    pub(crate) fn verify_log_id(entry: &RekorEntry, key: &RekorKey) -> Result<()> {
        let want = public_key_id(&key.spki_der);
        if entry.log_id != want {
            anyhow::bail!("Rekor logID mismatch: entry={} key={}", entry.log_id, want);
        }
        Ok(())
    }

    /// Rekor v1 checkpoint verification. The checkpoint is a Sigstore
    /// "note"-signed blob: split on `"\n\u{2014} "` into noteBody + signature line;
    /// the signature line is `"<origin> <base64-sig>"`; base64-decode, skip the
    /// first 4 bytes (note name/hash-alg header), verify ECDSA P-256 SHA-256 over
    /// `noteBody`. Then require checkpoint treeSize == proof.tree_size and
    /// checkpoint rootHash (base64) == proof.root_hash (hex).
    pub(crate) fn verify_checkpoint(proof: &InclusionProof, key: &RekorKey) -> Result<()> {
        let parts: Vec<&str> = proof.checkpoint.splitn(2, "\n\u{2014} ").collect();
        if parts.len() != 2 {
            anyhow::bail!("invalid Rekor checkpoint format (missing note signature)");
        }
        let note_body = parts[0];
        let sig_line = parts[1].trim_end_matches('\n');
        let sig_parts: Vec<&str> = sig_line.splitn(2, ' ').collect();
        if sig_parts.len() != 2 {
            anyhow::bail!("invalid Rekor checkpoint signature line");
        }
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_parts[1])
            .context("base64-decode checkpoint signature")?;
        if sig_bytes.len() < 5 {
            anyhow::bail!("Rekor checkpoint signature too short");
        }
        let raw_sig = &sig_bytes[4..]; // skip 4-byte Sigstore note header
        let signature = p256::ecdsa::Signature::from_der(raw_sig)
            .context("parse checkpoint ECDSA signature")?;
        // p256 VerifyingKey::verify hashes the message with SHA-256 internally —
        // equivalent to `sha256(noteBody); VerifyASN1`.
        key.verifying_key
            .verify(note_body.as_bytes(), &signature)
            .context("Rekor checkpoint signature verification failed")?;

        // Parse noteBody lines: origin / treeSize / rootHash(base64).
        let lines: Vec<&str> = note_body.trim_end_matches('\n').split('\n').collect();
        if lines.len() < 3 {
            anyhow::bail!("Rekor checkpoint noteBody has too few lines");
        }
        let cp_tree_size: i64 = lines[1]
            .parse()
            .with_context(|| format!("parse checkpoint treeSize {}", lines[1]))?;
        let cp_root = base64::engine::general_purpose::STANDARD
            .decode(lines[2])
            .context("base64-decode checkpoint rootHash")?;
        let proof_root = hex::decode(&proof.root_hash).context("hex-decode proof rootHash")?;
        if cp_tree_size != proof.tree_size {
            anyhow::bail!(
                "checkpoint treeSize {cp_tree_size} != proof treeSize {}",
                proof.tree_size
            );
        }
        if cp_root != proof_root {
            anyhow::bail!("checkpoint rootHash != proof rootHash");
        }
        Ok(())
    }

    /// SET payload with fixed field order + key names matching the signed SET
    /// payload: body, integratedTime, logID, logIndex. Field
    /// declaration order here == serialization order (serde preserves it for
    /// structs). `logID` is an explicit rename (camelCase would yield `logId`).
    #[derive(Serialize)]
    struct SetPayload<'a> {
        body: &'a str,
        #[serde(rename = "integratedTime")]
        integrated_time: i64,
        #[serde(rename = "logID")]
        log_id: &'a str,
        #[serde(rename = "logIndex")]
        log_index: i64,
    }

    /// Signed Entry Timestamp verification. Serialize the 4-field payload with
    /// fixed key order/names, `sha256` it (p256 verify hashes internally), verify
    /// ECDSA P-256 over it with the Rekor public key. Signature is base64-decoded
    /// DER, no prefix skip (unlike checkpoint).
    pub(crate) fn verify_set(entry: &RekorEntry, key: &RekorKey) -> Result<()> {
        let payload = SetPayload {
            body: &entry.body,
            integrated_time: entry.integrated_time,
            log_id: &entry.log_id,
            log_index: entry.log_index,
        };
        // serde_json::to_vec preserves struct field declaration order == Go json.Marshal order.
        let canonical = serde_json::to_vec(&payload).context("serialize SET payload")?;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&entry.verification.signed_entry_timestamp)
            .context("base64-decode signedEntryTimestamp")?;
        let signature =
            p256::ecdsa::Signature::from_der(&sig_bytes).context("parse SET ECDSA signature")?;
        key.verifying_key
            .verify(&canonical, &signature)
            .context("Rekor SET signature verification failed")?;
        Ok(())
    }
}

#[cfg(feature = "crypto-rustcrypto")]
pub(crate) use key::{
    parse_p256_public_key, public_key_id, rekor_public_key, verify_checkpoint,
    verify_inclusion_proof, verify_log_id, verify_set, RekorKey,
};

/// Fetch a Rekor v1 entry: `GET {log_url}/api/v1/log/entries?logIndex={n}`,
/// 30s timeout, `Accept: application/json`. The response is a map `{uuid: entry}`;
/// take the single value.
pub(crate) async fn fetch_rekor_entry(log_url: &str, log_index: i64) -> Result<RekorEntry> {
    let url = format!(
        "{}/api/v1/log/entries?logIndex={}",
        log_url.trim_end_matches('/'),
        log_index
    );
    let client = {
        let builder = reqwest::Client::builder();
        // wasm reqwest's ClientBuilder has no `.timeout()` (fetch API can't
        // control timeouts); only native builds set one. Shadowing (no `mut`)
        // keeps the wasm path warning-free.
        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let builder = builder.timeout(std::time::Duration::from_secs(30));
        builder.build().context("build Rekor HTTP client")?
    };
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let text = resp.text().await.context("read Rekor response body")?;
    if !status.is_success() {
        // Char-boundary-safe preview: `&text[..n]` panics if byte `n` lands inside
        // a multibyte UTF-8 char (Rekor error bodies are usually ASCII, but this
        // is a security-sensitive init path — avoid a latent panic).
        let preview: String = text.chars().take(200).collect();
        anyhow::bail!("Rekor GET {url} returned {status}: {preview}");
    }
    // Response is {uuid: entry}; take the single value.
    let map: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&text).context("parse Rekor response as {uuid: entry}")?;
    let (_uuid, entry_val) = map
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Rekor response has no entry"))?;
    let entry: RekorEntry = serde_json::from_value(entry_val).context("parse Rekor entry")?;
    Ok(entry)
}

/// Run all offline authentication checks (logID, checkpoint, inclusion, SET)
/// and return the trusted `payloadHash` plus the in-band DSSE signature. Pure
/// (no HTTP) so it is unit-testable against a fixture entry.
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) fn authenticate_entry(
    entry: &RekorEntry,
    key: &RekorKey,
) -> Result<AuthenticatedRekorEntry> {
    tracing::debug!(log_id = %entry.log_id, log_index = entry.log_index, integrated_time = entry.integrated_time, "Authenticating Rekor entry");
    verify_log_id(entry, key)?;
    let body = decode_rekor_body(entry)?;
    tracing::debug!(
        "Rekor entry body decoded: kind={:?}, payloadHash={}",
        body.kind,
        body.spec
            .payload_hash
            .as_ref()
            .map_or("(none)".to_string(), |h| h.value.clone())
    );
    let payload_hash = body
        .spec
        .payload_hash
        .as_ref()
        .context("Rekor body has no payloadHash")?;
    if payload_hash.algorithm != "sha256" {
        anyhow::bail!(
            "unsupported payloadHash algorithm: {}",
            payload_hash.algorithm
        );
    }
    verify_checkpoint(&entry.verification.inclusion_proof, key)?;
    verify_inclusion_proof(entry)?;
    verify_set(entry, key)?;
    // Extract the in-band DSSE signature (body.spec.signatures[0].signature);
    // empty string when absent — S5 threads this into the generated policy.
    let dsse_signature = body
        .spec
        .signatures
        .as_ref()
        .and_then(|s| s.first())
        .map(|s| s.signature.clone())
        .unwrap_or_default();
    tracing::info!(payload_hash = %payload_hash.value, dsse_signature_len = dsse_signature.len(), "Rekor entry authenticated: all checks passed");
    Ok(AuthenticatedRekorEntry {
        payload_hash: payload_hash.value.clone(),
        dsse_signature,
    })
}

/// Full init pipeline: fetch + authenticate + return the authenticated entry
/// (trusted payloadHash + in-band DSSE signature).
#[cfg(feature = "crypto-rustcrypto")]
pub async fn fetch_trusted_payload_hash(
    log_url: &str,
    log_index: i64,
    rekor_public_key_pem: Option<&str>,
) -> Result<AuthenticatedRekorEntry> {
    let entry = fetch_rekor_entry(log_url, log_index).await?;
    let key = rekor_public_key(log_url, rekor_public_key_pem)?;
    authenticate_entry(&entry, &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_entry() -> RekorEntry {
        let raw = include_str!("tests/fixtures/rekor_v1_entry.json");
        // The fixture is the raw entry object (body/integratedTime/logID/logIndex/verification).
        serde_json::from_str(raw).expect("parse fixture entry")
    }

    #[test]
    fn decode_fixture_body_extracts_payload_hash() {
        let entry = fixture_entry();
        assert_eq!(entry.log_index, 2279770888);
        assert_eq!(
            entry.log_id,
            "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
        );
        let body = decode_rekor_body(&entry).expect("decode body");
        assert_eq!(body.kind.as_deref(), Some("dsse"));
        let ph = body.spec.payload_hash.as_ref().expect("payloadHash");
        assert_eq!(ph.algorithm, "sha256");
        assert_eq!(
            ph.value,
            "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8"
        );
        assert_eq!(
            entry.verification.inclusion_proof.root_hash,
            "1c87a9b9ad2118a053035e7b39486227141af9a86b21cc221db26186be103583"
        );
        assert_eq!(entry.verification.inclusion_proof.tree_size, 2157944460);
        assert!(!entry.verification.signed_entry_timestamp.is_empty());
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn fixture_log_id_matches_sigstore_key() {
        let entry = fixture_entry();
        let key = rekor_public_key("https://rekor.sigstore.dev", None).expect("resolve key");
        verify_log_id(&entry, &key).expect("logID must match Sigstore key");
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn fixture_checkpoint_verifies_against_sigstore_key() {
        let entry = fixture_entry();
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        verify_checkpoint(&entry.verification.inclusion_proof, &key)
            .expect("checkpoint must verify");
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn fixture_inclusion_proof_verifies() {
        let entry = fixture_entry();
        verify_inclusion_proof(&entry).expect("inclusion proof must verify");
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn fixture_set_verifies_against_sigstore_key() {
        let entry = fixture_entry();
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        verify_set(&entry, &key).expect("SET must verify");
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn authenticate_fixture_entry_returns_trusted_payload_hash() {
        let entry = fixture_entry();
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        let auth = authenticate_entry(&entry, &key).expect("authenticate");
        assert_eq!(
            auth.payload_hash,
            "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8"
        );
    }

    #[test]
    fn decode_fixture_body_extracts_dsse_signature() {
        let entry = fixture_entry();
        let body = decode_rekor_body(&entry).expect("decode body");
        let sigs = body.spec.signatures.as_ref().expect("signatures");
        assert_eq!(sigs.len(), 1);
        let sig = &sigs[0];
        assert!(!sig.signature.is_empty());
        assert!(!sig.verifier.is_empty());
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn authenticate_fixture_entry_returns_signature() {
        let entry = fixture_entry();
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        let auth = authenticate_entry(&entry, &key).expect("authenticate");
        assert_eq!(
            auth.payload_hash,
            "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8"
        );
        assert!(!auth.dsse_signature.is_empty());
    }
}
