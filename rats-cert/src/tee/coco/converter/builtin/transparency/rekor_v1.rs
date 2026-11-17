//! Rekor v1 transparency-log entry fetch + verification (by logIndex):
//! fetch a Rekor v1 entry by logIndex, verify it via checkpoint +
//! Merkle inclusion + SET, and return the trusted `payloadHash` (from
//! `body.spec.payloadHash.value`) plus the in-band DSSE signature
//! (`body.spec.signatures[0].signature`).
//!
//! This module only EXTRACTS the DSSE signature; the actual signature
//! verification (DSSEPAE + SHA-256 + ECDSA P-256) and JCS canonicalization
//! happen later, at appraisal time, in the generated Rego policy's
//! `tng.verify_dsse_signature` host-await layer.

use anyhow::{Context, Result};
use base64::Engine;
use serde::Deserialize;
use sha2::Digest as _;

use super::cache::{RekorCacheKey, TransparencyCaches};
use super::dsse;
#[cfg(feature = "crypto-rustcrypto")]
use super::rekor_keys::verify_log_id;
use super::rekor_keys::{rekor_public_key, RekorPublicKey};
use super::{RekorBaseline, VerifyOutcome};
use crate::tee::coco::converter::builtin::policy_config::RekorV1Service;

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
    // An entry may legitimately carry no SET. With `#[serde(default)]` an absent
    // `signedEntryTimestamp` deserializes to empty, and `verify_entry`
    // skips SET verification in that case; without the default the whole entry
    // parse would bail and reject a valid SET-less entry.
    #[serde(default)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedRekorEntry {
    pub(crate) payload_hash: String,
    // Read by the seam's rekor adapter: the load path threads it into the
    // generated Rego policy for `tng.verify_dsse_signature`, and the on-demand
    // path verifies it directly.
    pub(crate) dsse_signature: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PayloadHash {
    pub(crate) algorithm: String,
    pub(crate) value: String,
}

/// Base64-decode `entry.body` and deserialize into [`RekorBody`]. Requires
/// `kind == "dsse"`.
pub(crate) fn decode_body(entry: &RekorEntry) -> Result<RekorBody> {
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

/// RFC 6962 SHA-256 tree hashing, matching Go's
/// `github.com/transparency-dev/merkle/rfc6962.DefaultHasher`.
fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    sha2::Digest::update(&mut h, [0x00]); // leaf prefix
    sha2::Digest::update(&mut h, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&sha2::Digest::finalize(h));
    out
}

fn hash_intermediate(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    sha2::Digest::update(&mut h, [0x01]); // node prefix
    sha2::Digest::update(&mut h, left);
    sha2::Digest::update(&mut h, right);
    let mut out = [0u8; 32];
    out.copy_from_slice(&sha2::Digest::finalize(h));
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
            let h = hex::decode(hb).with_context(|| format!("hex-decode inclusion hash {hb}"))?;
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

/// Rekor v1 checkpoint verification. The checkpoint is a Sigstore
/// "note"-signed blob: split on `"\n\u{2014} "` into noteBody + signature line;
/// the signature line is `"<origin> <base64-sig>"`; base64-decode, skip the
/// first 4 bytes (note name/hash-alg header), verify ECDSA P-256 SHA-256 over
/// `noteBody`. Then require checkpoint treeSize == proof.tree_size and
/// checkpoint rootHash (base64) == proof.root_hash (hex).
pub(crate) fn verify_checkpoint(proof: &InclusionProof, key: &RekorPublicKey) -> Result<()> {
    use p256::ecdsa::signature::Verifier as _;

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
    let signature =
        p256::ecdsa::Signature::from_der(raw_sig).context("parse checkpoint ECDSA signature")?;
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
/// payload: body, integratedTime, logID, logIndex. Field declaration order
/// here == serialization order (serde preserves it for structs). `logID` is an
/// explicit rename (camelCase would yield `logId`).
#[derive(serde::Serialize)]
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
pub(crate) fn verify_set(entry: &RekorEntry, key: &RekorPublicKey) -> Result<()> {
    use p256::ecdsa::signature::Verifier as _;

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

/// Fetch a Rekor v1 entry: `GET {log_url}/api/v1/log/entries?logIndex={n}`,
/// 30s timeout, `Accept: application/json`. The response is a map `{uuid: entry}`;
/// take the single value.
pub(crate) async fn fetch_entry(log_url: &str, log_index: i64) -> Result<RekorEntry> {
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
pub(crate) fn verify_entry(entry: &RekorEntry, key: &RekorPublicKey) -> Result<VerifiedRekorEntry> {
    tracing::debug!(log_id = %entry.log_id, log_index = entry.log_index, integrated_time = entry.integrated_time, "Authenticating Rekor entry");
    verify_log_id(entry, key)?;
    let body = decode_body(entry)?;
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
    // SET is optional. A rekor entry may legitimately omit it (e.g. a freshly
    // integrated entry whose SET has not propagated); requiring it would fail
    // closed on valid entries. Skip the check when the field is empty rather
    // than bailing on the empty base64.
    if !entry.verification.signed_entry_timestamp.is_empty() {
        verify_set(entry, key)?;
    }
    // Extract the in-band DSSE signature (body.spec.signatures[0].signature);
    // empty string when absent; the policy generator threads this into the generated Rego.
    let dsse_signature = body
        .spec
        .signatures
        .as_ref()
        .and_then(|s| s.first())
        .map(|s| s.signature.clone())
        .unwrap_or_default();
    tracing::debug!(payload_hash = %payload_hash.value, dsse_signature_len = dsse_signature.len(), "Rekor entry authenticated: all checks passed");
    Ok(VerifiedRekorEntry {
        payload_hash: payload_hash.value.clone(),
        dsse_signature,
    })
}

/// Load the rekor-v1 baseline a policy bakes at render time: fetch the entry,
/// verify it against the configured-or-built-in rekor key, and return the
/// trusted payload hash, the in-band DSSE signature, and the configured
/// publisher key.
///
/// The entry is deliberately not cached: a load must re-verify against the
/// configured `rekorPublicKeyPem`, so a cached success from a different key
/// configuration must not satisfy it.
pub(crate) async fn load_baseline(service: &RekorV1Service) -> Result<RekorBaseline> {
    let RekorV1Service {
        log_url,
        log_index,
        rekor_public_key_pem,
        publisher_public_key_pem,
    } = service;
    // A rekor-v1 entry carries no verifier keys of its own, so the DSSE
    // publisher key has to come from the configuration. Fail before the
    // network fetch.
    let publisher_key =
        dsse::required_publisher_pem(publisher_public_key_pem.as_deref())?.to_string();

    tracing::info!(
        log_url,
        log_index,
        "Loading transparency_log entry: fetching Rekor v1 entry"
    );
    let entry = fetch_entry(log_url, *log_index).await?;
    let key = rekor_public_key(log_url, rekor_public_key_pem.as_deref())?;
    let verified = verify_entry(&entry, &key)?;
    Ok(RekorBaseline {
        entry: VerifiedRekorEntry {
            payload_hash: verified.payload_hash,
            dsse_signature: dsse::require_dsse_signature(&verified.dsse_signature)?.to_string(),
        },
        publisher_key,
    })
}

/// Verify a manifest bound to a rekor-direct entry at appraisal time: fetch and
/// verify the entry (caching the verified entry on success), verify the
/// publisher signature over the canonical manifest, and compare the trusted
/// payload hash. A cached entry still goes through the publisher signature
/// check, so a cache hit does not weaken the binding.
pub(crate) async fn verify_manifest(
    manifest: &serde_json::Value,
    service: &RekorV1Service,
    caches: &TransparencyCaches,
) -> Result<VerifyOutcome> {
    // A rekor-v1 entry carries no verifier keys, so a configured publisher key
    // is mandatory. Fail before fetching.
    let publisher_pem = dsse::required_publisher_pem(service.publisher_public_key_pem.as_deref())?;
    let expected = dsse::canonical_manifest_sha256(manifest)?;
    let cache_key = RekorCacheKey {
        log_url: service.log_url.clone(),
        log_index: service.log_index,
    };
    let entry = match caches.rekor_entry(&cache_key).await {
        Some(entry) => entry,
        None => {
            let entry = fetch_entry(&service.log_url, service.log_index).await?;
            let key = super::rekor_keys::resolve_rekor_public_key(&entry, &service.log_url)?;
            let entry = verify_entry(&entry, &key)?;
            // The entry is authentic even when the bound manifest does not
            // match it, so cache it before the manifest-specific checks.
            caches.insert_rekor(cache_key, entry.clone()).await;
            entry
        }
    };

    let dsse_signature = dsse::require_dsse_signature(&entry.dsse_signature)?;
    let canonical_manifest = dsse::canonical_manifest_bytes(manifest)?;
    dsse::verify_publisher_signature(publisher_pem, canonical_manifest.as_bytes(), dsse_signature)?;
    if entry.payload_hash != expected {
        anyhow::bail!(
            "payloadHash mismatch: entry={} expected={}",
            entry.payload_hash,
            expected
        );
    }
    Ok(VerifyOutcome::Verified)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "crypto-rustcrypto")]
    use super::super::rekor_keys::{rekor_public_key, verify_log_id};
    use super::*;
    use crate::tee::coco::converter::builtin::test_fixtures;

    fn fixture_entry() -> RekorEntry {
        let raw = test_fixtures::REKOR_V1_ENTRY_JSON;
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
        let body = decode_body(&entry).expect("decode body");
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

    /// `verify_log_id` compares case-insensitively: an uppercase-hex logID that
    /// decodes to the same bytes as the key's `sha256(SPKI)` must still match.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_log_id_is_case_insensitive() {
        let mut entry = fixture_entry();
        let key = rekor_public_key("https://rekor.sigstore.dev", None).expect("resolve key");
        // Uppercase the fixture's lowercase-hex logID; the SPKI hash is
        // unchanged, so the case-insensitive compare must still match.
        entry.log_id = entry.log_id.to_uppercase();
        verify_log_id(&entry, &key).expect("uppercase logID must match (case-insensitive)");
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
    fn verify_fixture_entry_returns_trusted_payload_hash() {
        let entry = fixture_entry();
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        let auth = verify_entry(&entry, &key).expect("authenticate");
        assert_eq!(
            auth.payload_hash,
            "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8"
        );
    }

    #[test]
    fn decode_fixture_body_extracts_dsse_signature() {
        let entry = fixture_entry();
        let body = decode_body(&entry).expect("decode body");
        let sigs = body.spec.signatures.as_ref().expect("signatures");
        assert_eq!(sigs.len(), 1);
        let sig = &sigs[0];
        assert!(!sig.signature.is_empty());
        assert!(!sig.verifier.is_empty());
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_fixture_entry_returns_signature() {
        let entry = fixture_entry();
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        let auth = verify_entry(&entry, &key).expect("authenticate");
        assert_eq!(
            auth.payload_hash,
            "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8"
        );
        assert!(!auth.dsse_signature.is_empty());
    }

    /// Helper: load the fixture JSON, apply a mutation, deserialize into a
    /// `RekorEntry`. Used to construct malformed entries for the error-path
    /// tests below without needing a full wire fixture for each case.
    fn mutated_fixture_entry(mutate: impl FnOnce(&mut serde_json::Value)) -> RekorEntry {
        let raw = test_fixtures::REKOR_V1_ENTRY_JSON;
        let mut v: serde_json::Value = serde_json::from_str(raw).unwrap();
        mutate(&mut v);
        serde_json::from_value(v).expect("mutated entry must still deserialize")
    }

    /// Helper: build a `RekorEntry` whose `body` base64-encodes the given JSON
    /// value as the `spec` payload, with the given `kind`. The verification
    /// fields (log_id, integrated_time, etc.) are inherited from the fixture so
    /// `verify_log_id` passes; the tests bail before any verification that
    /// depends on the body being the original.
    fn entry_with_body(kind: &str, spec: serde_json::Value) -> RekorEntry {
        let body_json = serde_json::json!({"apiVersion":"0.0.1","kind":kind,"spec":spec});
        let body_b64 = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&body_json).unwrap());
        let mut entry = fixture_entry();
        entry.body = body_b64;
        entry
    }

    /// Lines 146-147: `decode_body` rejects `kind != "dsse"`.
    #[test]
    fn decode_body_rejects_non_dsse_kind() {
        let entry = entry_with_body("intoto", serde_json::json!({}));
        let err = decode_body(&entry).unwrap_err();
        assert!(
            err.to_string().contains("unsupported Rekor body kind"),
            "got: {err}"
        );
    }

    /// Line 299: `verify_inclusion_proof` rejects non-positive `treeSize`.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_inclusion_proof_rejects_non_positive_tree_size() {
        let entry = mutated_fixture_entry(|v| {
            v["verification"]["inclusionProof"]["treeSize"] = 0.into();
        });
        let err = verify_inclusion_proof(&entry).unwrap_err();
        assert!(
            err.to_string().contains("non-positive treeSize"),
            "got: {err}"
        );
    }

    /// Line 302: `verify_inclusion_proof` rejects `logIndex >= treeSize`.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_inclusion_proof_rejects_log_index_out_of_range() {
        let entry = mutated_fixture_entry(|v| {
            let ts = v["verification"]["inclusionProof"]["treeSize"]
                .as_i64()
                .unwrap();
            v["verification"]["inclusionProof"]["logIndex"] = ts.into();
        });
        let err = verify_inclusion_proof(&entry).unwrap_err();
        assert!(
            err.to_string().contains("logIndex out of range"),
            "got: {err}"
        );
    }

    /// Line 352: `verify_inclusion_proof` rejects computed root != proof
    /// rootHash. Keep the proof structure valid (same hashes, same treeSize)
    /// but change the `rootHash` so the computed root won't match.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_inclusion_proof_rejects_wrong_root_hash() {
        let entry = mutated_fixture_entry(|v| {
            v["verification"]["inclusionProof"]["rootHash"] =
                "0000000000000000000000000000000000000000000000000000000000000000".into();
        });
        let err = verify_inclusion_proof(&entry).unwrap_err();
        assert!(
            err.to_string().contains("computed root != proof rootHash"),
            "got: {err}"
        );
    }

    /// Lines 345-347: after the Merkle walk, if not all sibling hashes were
    /// consumed (`pi != siblings.len()`), bail. Append one extra hash so the
    /// walk consumes fewer than the total.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_inclusion_proof_rejects_extra_sibling_hashes() {
        let entry = mutated_fixture_entry(|v| {
            v["verification"]["inclusionProof"]["hashes"]
                .as_array_mut()
                .unwrap()
                .push("0000000000000000000000000000000000000000000000000000000000000000".into());
        });
        let err = verify_inclusion_proof(&entry).unwrap_err();
        assert!(err.to_string().contains("consumed"), "got: {err}");
    }

    /// Helper: construct an `InclusionProof` with a custom checkpoint. The
    /// other fields are irrelevant for the pre-signature checkpoint format
    /// checks; the error fires before they're read.
    #[cfg(feature = "crypto-rustcrypto")]
    fn proof_with_checkpoint(checkpoint: &str) -> InclusionProof {
        InclusionProof {
            checkpoint: checkpoint.to_string(),
            hashes: vec![],
            log_index: 0,
            root_hash: String::new(),
            tree_size: 1,
        }
    }

    /// Line 382: `verify_checkpoint` rejects a checkpoint missing the
    /// `"\n\u{2014} "` note-signature separator.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_checkpoint_rejects_invalid_format() {
        let proof = proof_with_checkpoint("no note signature separator here");
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        let err = verify_checkpoint(&proof, &key).unwrap_err();
        assert!(
            err.to_string().contains("invalid Rekor checkpoint format"),
            "got: {err}"
        );
    }

    /// Line 388: the signature line has no space separating origin from
    /// base64-sig.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_checkpoint_rejects_invalid_signature_line() {
        let proof = proof_with_checkpoint("line1\nline2\nline3\n\u{2014} nospacehere\n");
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        let err = verify_checkpoint(&proof, &key).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid Rekor checkpoint signature line"),
            "got: {err}"
        );
    }

    /// Line 394: base64-decoded checkpoint signature is < 5 bytes.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_checkpoint_rejects_short_signature() {
        // "AAAA" base64-decodes to 3 bytes (< 5).
        let proof = proof_with_checkpoint("line1\nline2\nline3\n\u{2014} origin AAAA\n");
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        let err = verify_checkpoint(&proof, &key).unwrap_err();
        assert!(
            err.to_string().contains("checkpoint signature too short"),
            "got: {err}"
        );
    }

    /// Lines 548-549: `verify_entry` rejects a non-sha256 payloadHash
    /// algorithm. The body is decoded (kind=dsse) but the payloadHash
    /// algorithm is sha512, so the check at line 547-549 bails before any
    /// checkpoint/inclusion/SET verification.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_entry_rejects_non_sha256_payload_hash() {
        let entry = entry_with_body(
            "dsse",
            serde_json::json!({
                "payloadHash": {"algorithm":"sha512","value":"deadbeef"},
                "signatures": [{"signature":"sig","verifier":"v"}]
            }),
        );
        // log_id must match the key for verify_log_id (called first) to pass.
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        let err = verify_entry(&entry, &key).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported payloadHash algorithm"),
            "got: {err}"
        );
    }

    /// `verify_entry` skips SET verification when
    /// `signedEntryTimestamp` is empty. The fixture carries a real SET; clear it
    /// and assert authentication still succeeds (checkpoint + inclusion are the
    /// gating checks for this path).
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_entry_skips_set_when_signed_entry_timestamp_empty() {
        let mut entry = fixture_entry();
        entry.verification.signed_entry_timestamp = String::new();
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        let auth = verify_entry(&entry, &key)
            .expect("auth must succeed with empty SET (skipped, not rejected)");
        assert_eq!(
            auth.payload_hash,
            "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8"
        );
    }

    /// An entry whose JSON omits `signedEntryTimestamp` entirely must
    /// deserialize (defaulting to empty) and then skip SET — not bail on a
    /// missing-field deserialize error. Absent → empty → skip SET.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn verify_entry_skips_set_when_signed_entry_timestamp_absent() {
        // Remove the `signedEntryTimestamp` key from the fixture JSON entirely,
        // then deserialize — must succeed because `#[serde(default)]` defaults it
        // to an empty string.
        let entry = mutated_fixture_entry(|v| {
            v["verification"]
                .as_object_mut()
                .expect("verification object")
                .remove("signedEntryTimestamp");
        });
        assert!(entry.verification.signed_entry_timestamp.is_empty());
        let key = rekor_public_key("https://rekor.sigstore.dev", None).unwrap();
        let auth = verify_entry(&entry, &key)
            .expect("auth must succeed with absent SET (defaulted empty, skipped)");
        assert_eq!(
            auth.payload_hash,
            "1011b70c962b91eb9233dbdb39bb3fdf61723619ca7cc5b46bed0512f976d9b8"
        );
    }
}
