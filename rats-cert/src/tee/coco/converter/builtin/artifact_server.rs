//! Artifact-server and on-demand rekor host-await functions for the
//! transparency_log policy (artifact-server primary path).
//!
//! The generated Rego policy calls `tng.fetch_rekor_on_demand` at appraisal
//! time as the **fallback** when the artifact-server primary path fails to
//! resolve a measurement. It fetches a Rekor v1 entry by `logIndex` on demand,
//! authenticates it (reusing the offline auth in `rekor_v1.rs`), and compares
//! the entry's trusted `payloadHash` to `sha256(canonical manifest)`.
//!
//! Successes are cached in a process-global `moka` cache keyed by
//! `(log_url, log_index)`; failures are never cached (re-try every failed
//! appraisal, then Rego falls back).

#[cfg(feature = "crypto-rustcrypto")]
use std::sync::Arc;

#[cfg(feature = "crypto-rustcrypto")]
use anyhow::Result;

#[cfg(feature = "crypto-rustcrypto")]
use attestation_service::policy_engine::opa::ExtensionFunction;
#[cfg(feature = "crypto-rustcrypto")]
use moka::future::Cache;
#[cfg(feature = "crypto-rustcrypto")]
use once_cell::sync::Lazy;
#[cfg(feature = "crypto-rustcrypto")]
use sha2::Digest;

#[cfg(feature = "crypto-rustcrypto")]
use crate::tee::coco::converter::builtin::rekor_v1;

#[cfg(feature = "crypto-rustcrypto")]
use artifact_resolve_sdk::{Client as ResolveClient, LogService, ReleaseManifest, ResolveRequest};

/// Process-global cache: `(log_url, log_index) -> authenticated payload_hash`.
/// Successes only; failures are never cached (re-try every failed appraisal).
// Capacity 64 is plenty for the small set of transparency-log entries a single
// builtin-AS instance appraises (one per published measurement, typically
// 1-3). `moka` evicts LRU past capacity; cached values are immutable strings.
#[cfg(feature = "crypto-rustcrypto")]
static REKOR_ON_DEMAND_CACHE: Lazy<Cache<(String, i64), String>> =
    Lazy::new(|| Cache::builder().max_capacity(64).build());

/// `tng.fetch_rekor_on_demand(log_url, log_index, manifest_json) -> bool`.
///
/// Fallback path: fetch a Rekor v1 entry by `logIndex` on demand, authenticate
/// it (checkpoint + Merkle inclusion + SET, reusing `rekor_v1`), and compare
/// its trusted `payloadHash` to `sha256(canonical manifest)`. The canonical
/// manifest is the JCS (RFC 8785) sorted-compact serialization — exactly what
/// Rego's `json.marshal(manifest)` produces for this (number-free) shape, so
/// the comparison agrees with the init-bake `tng.sha256` path.
///
/// Cache **successes only**: after a successful fetch+authenticate, the
/// authenticated `payload_hash` is cached under `(log_url, log_index)`;
/// subsequent calls compare the manifest hash to the cached value without
/// hitting the network. The cache insert happens only AFTER
/// `authenticate_entry` succeeds, so returning `Ok(false)` on fetch/auth
/// failure still never caches and still re-tries the next appraisal.
///
/// Fail-closed / clean-deny: ALL failures (bad args, fetch failure, key
/// resolution failure, auth failure, manifest mismatch) return
/// `Ok(Bool(false))` — never `Err`. The Rego caller is
/// `tng.fetch_rekor_on_demand(...) == true`; an `Err` would abort the entire
/// policy evaluation (verified via the in-tree
/// `evaluate_with_regovm_propagates_async_builtin_error` test in
/// attestation-service's `opa/mod.rs`), breaking the §11 clean-deny contract
/// (`fallback_ok → false → transparency_verified → executables := 97`). A
/// clean `false` lets Rego fall through to the reject arm. This mirrors the
/// established `verify_dsse_signature_host_await` pattern (which swallows all
/// errors to `Ok(Bool(false))`).
///
/// Gated on `crypto-rustcrypto`: `authenticate_entry`/`rekor_public_key`/
/// `RekorKey` (in `rekor_v1::key`) all require `p256`+`x509-cert`, the same
/// crates `crypto-rustcrypto` pulls in. The Rego policy that calls this is
/// itself only generated under that feature.
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) fn fetch_rekor_on_demand_host_await() -> ExtensionFunction {
    use regorus::Value;

    Arc::new(move |argument: regorus::Value| {
        Box::pin(async move {
            // All failures map to a clean `false` (clean-deny, never `Err`).
            // `inner` returns `Option<bool>`: `Some(hash == expected)` on a
            // successful fetch+auth+compare, `None` on any failure (bad args /
            // fetch / key-resolution / auth / manifest parse). `.unwrap_or(false)`
            // then yields the clean deny.
            let inner = || async {
                let arr = argument.as_array().ok()?;
                if arr.len() != 3 {
                    return None;
                }
                let log_url = arr[0].as_string().ok()?.to_string();
                let log_index = arr[1].as_i64().ok()?;
                let manifest_json = arr[2].as_string().ok()?.to_string();
                let expected = canonical_manifest_sha256(&manifest_json).ok()?;

                let cached = REKOR_ON_DEMAND_CACHE
                    .get(&(log_url.clone(), log_index))
                    .await;
                let payload_hash = match cached {
                    Some(h) => h,
                    None => {
                        let entry = rekor_v1::fetch_rekor_entry(&log_url, log_index)
                            .await
                            .ok()?;
                        let key = resolve_rekor_key(&entry, &log_url).ok()?;
                        let auth = rekor_v1::authenticate_entry(&entry, &key).ok()?;
                        // Cache the authenticated payload_hash on success. A
                        // manifest mismatch (below) still counts as a successful
                        // fetch+auth — the entry is authentic, just not the
                        // one this manifest claims to be — so its hash is
                        // cached; the mismatch is reported as `false`, not a
                        // cache miss.
                        REKOR_ON_DEMAND_CACHE
                            .insert((log_url, log_index), auth.payload_hash.clone())
                            .await;
                        auth.payload_hash
                    }
                };
                Some(payload_hash == expected)
            };
            Ok(Value::Bool(inner().await.unwrap_or(false)))
        })
    })
}

/// Resolve the Rekor public key for a fetched entry. Tries hostname-based
/// resolution first (`rekor_v1::rekor_public_key`); if that fails (the
/// `log_url` is an artifact-server proxy whose hostname matches no built-in
/// key — e.g. a wiremock test URL or an internal proxy), fall back to trying
/// each built-in key (Sigstore, OpenAnolis) by `verify_log_id` against the
/// entry's `logID` (= `sha256(SPKI DER)`). This keeps the on-demand fallback
/// working when the artifact-server proxy fronts a real Rekor instance under
/// a different hostname, without duplicating the key table.
#[cfg(feature = "crypto-rustcrypto")]
fn resolve_rekor_key(entry: &rekor_v1::RekorEntry, log_url: &str) -> Result<rekor_v1::RekorKey> {
    // Fast path: hostname-based resolution.
    if let Ok(key) = rekor_v1::rekor_public_key(log_url, None) {
        return Ok(key);
    }
    // Fallback: unknown hostname (artifact-server proxy / test mock). Try the
    // built-in keys by logID match. Iterate the single-source-of-truth table in
    // `rekor_v1` so a third built-in added there is picked up automatically
    // (rather than silently missed by a restated hostname list here).
    for (host, _) in rekor_v1::known_rekor_keys() {
        if let Ok(key) = rekor_v1::rekor_public_key(&format!("https://{host}"), None) {
            if rekor_v1::verify_log_id(entry, &key).is_ok() {
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

/// Canonicalize a manifest JSON string and sha256 it. The canonical form is
/// RFC 8785 JCS (sorted compact) — exactly what Rego's `json.marshal` produces
/// for this manifest shape (object keys sorted, compact separators, no
/// numbers: `schemaVersion` is a string and measurement `value`s are digest
/// strings). So `sha256(canonical_manifest_sha256(m))` agrees with the Rego
/// `tng.sha256(json.marshal(manifest))` used in the init-bake path.
///
/// Parses the manifest string as a `serde_json::Value` (so a caller-supplied
/// manifest with unsorted / whitespace-padded keys is normalized) then
/// re-serializes via the shared `rekor_v1::jcs_compact` (single source of
/// truth shared with the init-bake tests in `mod.rs`) and sha256s it.
#[cfg(feature = "crypto-rustcrypto")]
fn canonical_manifest_sha256(manifest_json: &str) -> Result<String> {
    let canon = canonical_manifest_bytes(manifest_json)?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(canon.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// JCS (RFC 8785) canonical bytes of a manifest JSON string — the shared
/// intermediate used by both `canonical_manifest_sha256` (for the payloadHash
/// comparison) and the DSSE PAE construction (for the publisher-signature
/// verification), so both paths agree on the canonical payload for a given
/// manifest. See `canonical_manifest_sha256` for the canonicalization rationale.
#[cfg(feature = "crypto-rustcrypto")]
fn canonical_manifest_bytes(manifest_json: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(manifest_json)?;
    Ok(rekor_v1::jcs_compact(&v))
}

/// DSSE Pre-Authentication Encoding (DSSEv1), mirroring cmaas's
/// `utils.DSSEPAE`. Format: `DSSEv1 <len(type)> <type> <len(payload)> <payload>`
/// where `<len>` is the ASCII decimal byte length. The DSSE publisher signature
/// is verified over `sha256(PAE(canonical_manifest))` — see
/// `verify_entry_dsse_signature` — matching cmaas's `verifyLogEntrySignature`
/// (`pae := DSSEPAE(DSSEPayloadType, payload); h := sha256(pae);
/// ecdsa.VerifyASN1(pub, h, sig)`).
#[cfg(feature = "crypto-rustcrypto")]
fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
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

/// The DSSE payload type for an Alibaba Cloud CMAAS release manifest, mirroring
/// cmaas's `DSSEPayloadType` constant (`source/pkg/transparency/transparency.go`).
#[cfg(feature = "crypto-rustcrypto")]
const DSSE_PAYLOAD_TYPE: &str = "application/vnd.alibabacloud.confidential-computing.release+json";

/// Process-global cache for `tng.resolve_artifact_server`: successes only,
/// keyed by `(manifest_hash, canonical_log_services)`. Failures are never
/// cached (re-try every failed appraisal, then Rego falls back to
/// `tng.fetch_rekor_on_demand`).
#[cfg(feature = "crypto-rustcrypto")]
static RESOLVE_CACHE: Lazy<Cache<([u8; 32], String), ()>> =
    Lazy::new(|| Cache::builder().max_capacity(1024).build());

/// `tng.resolve_artifact_server(artifact_server_url, manifest_json, log_services_json) -> bool`.
///
/// Primary artifact-server path. Resolve the manifest via the Artifact Server
/// `POST /api/v1/transparency/resolve` (using `artifact_resolve_sdk`), then
/// authenticate each returned rekor-v1 entry locally (checkpoint + Merkle
/// inclusion + SET, reusing `rekor_v1::authenticate_entry`) and verify each
/// entry's authenticated `payloadHash == sha256(JCS(manifest))`. On success
/// returns `Ok(Bool(true))` and caches the result keyed by
/// `(manifest_hash, canonical_log_services)`; on ANY failure returns
/// `Ok(Bool(false))` (not cached) so the Rego caller falls back to
/// `tng.fetch_rekor_on_demand`.
///
/// Fail-closed / clean-deny: ALL failures (bad args, HTTP, decode, key
/// resolution, auth, manifest mismatch) return `Ok(Bool(false))` — never `Err`.
/// An `Err` would abort the entire policy evaluation (verified via the
/// in-tree `evaluate_with_regovm_propagates_async_builtin_error` test),
/// breaking the §11 clean-deny contract. This mirrors the established
/// `fetch_rekor_on_demand` pattern (Option + `unwrap_or(false)`).
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) fn resolve_artifact_server_host_await() -> ExtensionFunction {
    use regorus::Value;

    Arc::new(move |argument: regorus::Value| {
        Box::pin(async move {
            // All failures map to a clean `false` (clean-deny, never `Err`).
            // `inner` returns `Option<bool>`: `Some(true)` on a successful
            // resolve+authenticate+compare, `None` on any failure. `.unwrap_or(false)`
            // then yields the clean deny.
            let inner = || async {
                let arr = argument.as_array().ok()?;
                if arr.len() != 3 {
                    return None;
                }
                let url = arr[0].as_string().ok()?.to_string();
                let manifest_json = arr[1].as_string().ok()?.to_string();
                let log_services_json = arr[2].as_string().ok()?.to_string();

                let expected = canonical_manifest_sha256(&manifest_json).ok()?;

                // Decode the hex sha256 to a 32-byte array for the cache key. A
                // non-32-byte hash (e.g. a malformed manifest that produced a
                // non-sha256 digest) is reported via tracing and maps to
                // `None`→`Ok(Bool(false))` (clean-deny) — the `inner` closure
                // returns `Option<bool>`, so the `return None` below keeps the
                // `Ok(Bool(false))` contract intact (never `Err`).
                let expected_bytes: [u8; 32] = match hex::decode(&expected) {
                    Ok(b) => match b.as_slice().try_into() {
                        Ok(arr) => arr,
                        Err(_) => {
                            tracing::warn!(
                                len = b.len(),
                                "resolve_artifact_server: manifest sha256 must be 32 bytes, got {} bytes — denying",
                                b.len()
                            );
                            return None;
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "resolve_artifact_server: manifest sha256 hex decode failed — denying"
                        );
                        return None;
                    }
                };
                let ls_canon = canonicalize_log_services(&log_services_json).ok()?;

                if RESOLVE_CACHE
                    .get(&(expected_bytes, ls_canon.clone()))
                    .await
                    .is_some()
                {
                    return Some(true);
                }

                let ok =
                    resolve_and_authenticate(&url, &manifest_json, &log_services_json, &expected)
                        .await
                        .is_ok();
                if ok {
                    RESOLVE_CACHE.insert((expected_bytes, ls_canon), ()).await;
                    Some(true)
                } else {
                    None
                }
            };
            Ok(Value::Bool(inner().await.unwrap_or(false)))
        })
    })
}

/// Resolve the manifest via the Artifact Server and authenticate every
/// returned rekor-v1 entry. Returns `Ok(())` only when:
/// - the resolve status is `"resolved"`,
/// - at least one entry is returned,
/// - every returned entry's `(type, url)` matches exactly one requested
///   `logService` (no unrequested, duplicate, or missing entries — request
///   binding for a non-trusted resolver, spec §7/§8.1; URLs are normalized by
///   trimming trailing slashes),
/// - every entry authenticates (checkpoint + inclusion + SET via
///   `rekor_v1::authenticate_entry`), and
/// - every entry's `payloadHash == expected_hash`.
///
/// Any error → `Err` (mapped to `false` by the caller, never cached).
#[cfg(feature = "crypto-rustcrypto")]
async fn resolve_and_authenticate(
    url: &str,
    manifest_json: &str,
    log_services_json: &str,
    expected_hash: &str,
) -> Result<()> {
    let manifest: ReleaseManifest = serde_json::from_str(manifest_json)?;
    let log_services: Vec<LogService> = serde_json::from_str(log_services_json)?;
    // Build the requested (type, url) set BEFORE moving `log_services` into
    // the request — used to verify the response covers exactly the requested
    // services (no unrequested / duplicate / missing entries). URLs are
    // normalized by trimming trailing slashes so a caller that appends `/`
    // still matches a response without one.
    let mut remaining: std::collections::HashSet<(String, String)> = log_services
        .iter()
        .map(|ls| {
            (
                ls.type_.clone(),
                ls.url
                    .as_deref()
                    .unwrap_or("")
                    .trim_end_matches('/')
                    .to_string(),
            )
        })
        .collect();
    let req = ResolveRequest::new(manifest).with_log_services(log_services);
    let client = ResolveClient::new(url)?;
    let resp = client.resolve(&req).await?;
    if resp.status != "resolved" {
        anyhow::bail!(
            "artifact-server resolve status {:?} != resolved",
            resp.status
        );
    }
    if resp.log_entries.is_empty() {
        anyhow::bail!("artifact-server resolve returned no log entries");
    }
    // Canonical manifest bytes, shared by the payloadHash comparison and the
    // DSSE PAE construction (publisher-signature verification) below — computed
    // once so every entry sees the same canonical payload.
    let canonical_manifest = canonical_manifest_bytes(manifest_json)?;
    for entry in &resp.log_entries {
        if entry.type_ != "rekor-v1" {
            anyhow::bail!("unsupported log entry type {:?}", entry.type_);
        }
        // Request-binding: each returned entry must match exactly one requested
        // logService. `remove` returns false on an unrequested OR duplicate
        // entry → reject. A malicious resolver cannot substitute a valid entry
        // for an unrequested rekor instance to yield `true`.
        let entry_key = (
            entry.type_.clone(),
            entry.url.trim_end_matches('/').to_string(),
        );
        if !remaining.remove(&entry_key) {
            anyhow::bail!(
                "unrequested or duplicate log entry: type={:?} url={:?}",
                entry.type_,
                entry.url
            );
        }
        // The sdk's `log_entry` is a raw JSON value carrying the rekor v1
        // entry object (body/integratedTime/logID/logIndex/verification).
        let rekor_entry: rekor_v1::RekorEntry = serde_json::from_value(entry.log_entry.clone())?;
        // Rekor key (checkpoint + inclusion + SET): prefer the response
        // `log_verifier.public_key_pem` (cmaas-audit's `VerifyLogEntry`
        // response-key path — the artifact-server is semi-trusted for key
        // transport); fall back to the built-in hostname→logID resolution when
        // the response omits it (so proxy / mock URLs still resolve via the
        // built-in key table). Mirrors cmaas `VerifyLogEntry` lines 183-187.
        let key = if !entry.log_verifier.public_key_pem.is_empty() {
            rekor_v1::rekor_public_key(&entry.url, Some(&entry.log_verifier.public_key_pem))?
        } else {
            resolve_rekor_key(&rekor_entry, &entry.url)?
        };
        let auth = rekor_v1::authenticate_entry(&rekor_entry, &key)?;
        if auth.payload_hash != expected_hash {
            anyhow::bail!(
                "payloadHash mismatch: entry={} expected={}",
                auth.payload_hash,
                expected_hash
            );
        }
        // DSSE publisher-signature verification with the response
        // `entry_verifier` (cmaas-audit's `verifyLogEntrySignature`). The
        // signature in `body.spec.signatures[0].signature` is verified over
        // `sha256(DSSEPAE(canonical_manifest))` (the PAE — NOT the bare
        // manifest — per cmaas `verifyLogEntrySignature` lines 386-400). TNG is
        // lenient where cmaas-audit requires both verifiers together: if
        // `entry_verifier` is absent or has an unsupported type, DSSE
        // verification is SKIPPED (not rejected) — this keeps the built-in-only
        // fallback working for resolvers that omit the response verifiers while
        // still failing closed on a present-but-wrong key.
        if entry.entry_verifier.type_ == "public_key" && !entry.entry_verifier.content.is_empty() {
            verify_entry_dsse_signature(
                &rekor_entry,
                &entry.entry_verifier.content,
                canonical_manifest.as_bytes(),
            )?;
        }
        // Baseline-compare + warn (cmaas `VerifyLogEntry` lines 195-200): after
        // successful verification with the response key, compare it to the SDK
        // built-in key for this URL by SPKI DER. A mismatch is logged but NOT
        // rejected (cmaas-audit warns + passes). Best-effort: if the built-in
        // resolution fails (e.g. a proxy URL with no built-in hostname match),
        // skip the compare silently rather than denying.
        if !entry.log_verifier.public_key_pem.is_empty() {
            if let Ok(builtin) = rekor_v1::rekor_public_key(&entry.url, None) {
                if key.spki_der != builtin.spki_der {
                    tracing::warn!(
                        url = %entry.url,
                        "transparency verification key differs from built-in baseline; \
                         the artifact-server supplied a different rekor key"
                    );
                }
            }
        }
    }
    // Every requested logService must have been covered exactly once.
    if !remaining.is_empty() {
        anyhow::bail!(
            "artifact-server resolve did not cover all requested log services; missing: {:?}",
            remaining
        );
    }
    Ok(())
}

/// Verify the DSSE publisher signature carried in a Rekor v1 entry body against
/// the response-supplied `entry_verifier` public key, mirroring cmaas-audit's
/// `verifyLogEntrySignature` (rekorv1.go lines 386-400). The signature
/// (`body.spec.signatures[0].signature`, base64) is verified over
/// `sha256(DSSEPAE(canonical_manifest))` — `VerifyingKey::verify` hashes the PAE
/// with SHA-256 internally, which is equivalent to Go's
/// `h := sha256(pae); ecdsa.VerifyASN1(pub, h, sig)`. Returns `Err` on any
/// decode/parse/verify failure (the caller's `inner` closure maps `Err`→`None`
/// → clean-deny `Ok(Bool(false))`, per the §11 contract).
#[cfg(feature = "crypto-rustcrypto")]
fn verify_entry_dsse_signature(
    entry: &rekor_v1::RekorEntry,
    publisher_pem: &str,
    canonical_manifest: &[u8],
) -> Result<()> {
    use anyhow::Context;
    use base64::Engine;
    use p256::ecdsa::signature::Verifier;

    let publisher_key = rekor_v1::parse_p256_public_key(publisher_pem)?;
    let body = rekor_v1::decode_rekor_body(entry)?;
    let sigs = body
        .spec
        .signatures
        .as_ref()
        .context("Rekor body has no DSSE signatures")?;
    let sig_str = sigs
        .first()
        .context("Rekor body has zero DSSE signatures")?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&sig_str.signature)
        .context("base64-decode DSSE publisher signature")?;
    let signature = p256::ecdsa::Signature::from_der(&sig_bytes)
        .context("parse DSSE publisher ECDSA signature")?;
    let pae = dsse_pae(DSSE_PAYLOAD_TYPE, canonical_manifest);
    publisher_key
        .verify(&pae, &signature)
        .context("DSSE publisher signature verification failed")?;
    Ok(())
}

/// Canonicalize a `log_services_json` string into a stable cache-key component:
/// parse to a `serde_json::Value` (normalizing key order / whitespace) then
/// re-serialize via the shared `rekor_v1::jcs_compact` (sorted compact). Two
/// semantically-equal log-services lists produce the same canonical string.
#[cfg(feature = "crypto-rustcrypto")]
fn canonicalize_log_services(log_services_json: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(log_services_json)?;
    Ok(rekor_v1::jcs_compact(&v))
}

/// Test-only helper: clear both process-global host-await caches so a test can
/// exercise the real network path (and avoid cross-test cache pollution). The
/// mod.rs Branch-B short-circuit test uses this to force the artifact-server
/// mock to be hit rather than served from a stale `RESOLVE_CACHE` entry.
/// `moka`'s `invalidate_all` is synchronous (it marks entries for lazy
/// eviction); no `async` needed.
#[cfg(test)]
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) fn invalidate_host_await_caches_for_test() {
    RESOLVE_CACHE.invalidate_all();
    REKOR_ON_DEMAND_CACHE.invalidate_all();
}

#[cfg(test)]
#[cfg(feature = "crypto-rustcrypto")]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Reuse the existing rekor_v1 fixture entry to build a mock
    // /api/v1/log/entries response: the wire format is `{uuid: entry}`.
    fn rekor_entries_response_body() -> String {
        let raw = include_str!("tests/fixtures/rekor_v1_entry.json");
        let uuid = "00000000-0000-0000-0000-000000000000";
        serde_json::json!({ uuid: serde_json::from_str::<serde_json::Value>(raw).unwrap() })
            .to_string()
    }

    /// The Sigstore Rekor v1 public key PEM (checkpoint + SET verification key),
    /// copied from cmaas's `SigstoreRekorV1PubKeyPEM` constant
    /// (`source/pkg/transparency/rekorv1.go`). The fixture entry's `logID` ==
    /// `sha256(SPKI)` of this key, so `authenticate_entry` (logID + checkpoint +
    /// inclusion + SET) verifies against it.
    const SIGSTORE_REKOR_V1_PUB_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----";

    /// The DSSE publisher PEM that signed the fixture's DSSE envelope, copied
    /// from cmaas's `LogEntryPubKeyPEM` constant (same key the fixture carries
    /// in `body.spec.signatures[0].verifier`). `verify_entry_dsse_signature`
    /// verifies `body.spec.signatures[0].signature` over
    /// `sha256(DSSEPAE(canonical_manifest))` with this key.
    const LOG_ENTRY_PUB_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsGjh0eIF22/JwEkRvU5KROvNsL/F\nK6qP/kbKO0CoelOqRKJQuC9z0ruwyx12S94/m69+iaan0SKR1IJjIbbfHw==\n-----END PUBLIC KEY-----";

    /// A manifest that does NOT hash to the fixture entry's payloadHash.
    /// Used to assert the *mismatch* path (bool false) while still exercising
    /// fetch+auth+cache. The fixture entry's payloadHash is
    /// `1011b70c...` (pinned by `decode_fixture_body_extracts_payload_hash`);
    /// an empty manifest hashes to a different value → comparison is false,
    /// but authentication of the fixture entry succeeds (real crypto), so the
    /// authenticated payload_hash is cached.
    const DUMMY_MISMATCH_MANIFEST: &str = r#"{"schemaVersion":"1.0.0","measurements":[]}"#;

    /// Call an `ExtensionFunction` closure the same way the regorus VM does:
    /// the closure takes an owned `regorus::Value` and returns a boxed future.
    /// Clone the Arc, hand over the Value, await, and unwrap the Result so a
    /// host-side error surfaces as a test failure (not a silent `false`).
    async fn invoke_extension(
        hv: &attestation_service::policy_engine::opa::ExtensionFunction,
        arg: regorus::Value,
    ) -> regorus::Value {
        let hv = hv.clone();
        hv(arg).await.expect("host-await call must succeed")
    }

    #[tokio::test]
    async fn fetch_rekor_on_demand_caches_after_first_hit() {
        let server = MockServer::start().await;
        let body = rekor_entries_response_body();
        Mock::given(method("GET"))
            .and(path("/api/v1/log/entries"))
            .and(query_param("logIndex", "2279770888"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body.clone()))
            .up_to_n_times(1) // only ONE real hit; second call must come from cache
            .mount(&server)
            .await;

        let url = server.uri();
        let hv = fetch_rekor_on_demand_host_await();
        let arg = regorus::Value::from(vec![
            regorus::Value::from(url.as_str()),
            regorus::Value::from(2279770888i64),
            regorus::Value::from(DUMMY_MISMATCH_MANIFEST),
        ]);
        // first call hits the mock; auth succeeds; manifest mismatches → false;
        // the authenticated payload_hash is cached under (url, logIndex).
        let r1 = invoke_extension(&hv, arg.clone()).await;
        assert_eq!(r1, regorus::Value::Bool(false));
        // second call must NOT hit the mock (would 404 / fail) — served from cache.
        let r2 = invoke_extension(&hv, arg).await;
        assert_eq!(r2, regorus::Value::Bool(false));
    }

    /// §11 clean-deny: a fetch/auth failure MUST return `Ok(Bool(false))`,
    /// never `Err` — an `Err` aborts the entire policy evaluation and breaks
    /// the `fallback_ok → false → executables := 97` contract. Point the
    /// `log_url` at a dead port so `fetch_rekor_entry` fails to connect; the
    /// closure must swallow the error into a clean `false`. Asserts on the
    /// raw `Result` (not `invoke_extension`'s `.expect()`, which would mask
    /// an `Err` as a test failure rather than proving the `Ok(false)` outcome).
    #[tokio::test]
    async fn fetch_rekor_on_demand_returns_clean_false_on_fetch_failure() {
        // 127.0.0.1:1 is guaranteed to refuse the TCP connection (no listener
        // on port 1 on the loopback interface) — `fetch_rekor_entry` returns a
        // connection-refused `Err`, which the closure must map to `Ok(false)`.
        // Use a distinct (log_url, log_index) not exercised by the cache test
        // so the process-global cache cannot short-circuit this into a hit.
        let url = "http://127.0.0.1:1";
        let hv = fetch_rekor_on_demand_host_await();
        let arg = regorus::Value::from(vec![
            regorus::Value::from(url),
            regorus::Value::from(9999999999i64),
            regorus::Value::from(DUMMY_MISMATCH_MANIFEST),
        ]);
        let hv = hv.clone();
        let result: Result<regorus::Value, _> = hv(arg).await;
        assert!(
            result.is_ok(),
            "host-await must return Ok(Bool(false)) on fetch failure, got Err: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap(), regorus::Value::Bool(false));
    }

    // ---- tng.resolve_artifact_server tests (Task 5) ----

    /// Build a rekor `/api/v1/log/entries` response body (`{uuid: entry}`) from
    /// the cmaas evidence fixture's matched `(release_manifest, log_entry)`
    /// pair. The entry's authenticated `payloadHash` ==
    /// `sha256(JCS(release_manifest))` == `b40611d4...` (pinned by the
    /// `mod.rs`/fixture tests), so a `fetch_rekor_on_demand` call passing the
    /// cmaas release manifest exercises the full fetch → authenticate →
    /// payloadHash-compare → `Ok(Bool(true))` happy path.
    fn cmaas_fetch_rekor_response_body() -> (String, String, i64) {
        let evidence: serde_json::Value = serde_json::from_str(include_str!(
            "tests/fixtures/cmaas_evidence_with_rekor_v1_transparency.json"
        ))
        .unwrap();
        let manifest = evidence["transparency"]["release_manifest"].clone();
        let log_entry = evidence["transparency"]["log_entries"][0]["log_entry"].clone();
        let log_index = evidence["transparency"]["log_entries"][0]["log_entry"]["logIndex"]
            .as_i64()
            .unwrap();
        let uuid = "00000000-0000-0000-0000-000000000000";
        let body = serde_json::json!({ uuid: log_entry }).to_string();
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        (body, manifest_json, log_index)
    }

    /// True-path: `tng.fetch_rekor_on_demand` returns `Ok(Bool(true))` when a
    /// real rekor entry's authenticated `payloadHash` matches
    /// `sha256(JCS(manifest))`. Uses the cmaas evidence fixture's matched
    /// `(release_manifest, log_entry)` pair (logIndex 2310520944, payloadHash
    /// `b40611d4...`). Wiremock mocks `GET /api/v1/log/entries?logIndex=...`
    /// returning the cmaas entry as the `{uuid: entry}` rekor response. Asserts
    /// directly on the raw `Result` (not `invoke_extension`'s `.expect()`, which
    /// would mask an `Err` as a test failure rather than proving the `Ok(true)`
    /// outcome). `#[serial]` + `invalidate_host_await_caches_for_test()` avoids
    /// cache cross-talk with the `caches_after_first_hit` test (distinct
    /// logIndex, but the process-global cache is shared).
    #[tokio::test]
    #[serial_test::serial]
    async fn fetch_rekor_on_demand_true_on_matched_payload_hash() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (body, manifest_json, log_index) = cmaas_fetch_rekor_response_body();
        Mock::given(method("GET"))
            .and(path("/api/v1/log/entries"))
            .and(query_param("logIndex", &log_index.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;

        let hv = fetch_rekor_on_demand_host_await();
        let arg = regorus::Value::from(vec![
            regorus::Value::from(server.uri().as_str()),
            regorus::Value::from(log_index),
            regorus::Value::from(manifest_json.as_str()),
        ]);
        let hv = hv.clone();
        let result: Result<regorus::Value, _> = hv(arg).await;
        assert!(
            result.is_ok(),
            "host-await must return Ok(Bool(true)) on a matched payloadHash, got Err: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap(), regorus::Value::Bool(true));
    }

    /// Load the cmaas evidence fixture and extract the matched
    /// `(release_manifest, log_entry, entry_url)` triple: the entry's
    /// `payloadHash` == `sha256(JCS(release_manifest))` (verified in
    /// `mod.rs`/fixture tests), so a resolve response built from it exercises
    /// both `authenticate_entry` (real inclusion/checkpoint/SET crypto) and the
    /// payloadHash comparison → `true`.
    fn cmaas_resolve_triple() -> (serde_json::Value, serde_json::Value, String) {
        let evidence: serde_json::Value = serde_json::from_str(include_str!(
            "tests/fixtures/cmaas_evidence_with_rekor_v1_transparency.json"
        ))
        .unwrap();
        let manifest = evidence["transparency"]["release_manifest"].clone();
        let log_entry = evidence["transparency"]["log_entries"][0]["log_entry"].clone();
        let entry_url = evidence["transparency"]["log_entries"][0]["url"]
            .as_str()
            .unwrap()
            .to_string();
        (manifest, log_entry, entry_url)
    }

    /// Build a resolve-response JSON body from the cmaas fixture pair. The
    /// `entry_verifier.content` / `log_verifier.public_key_pem` are now USED by
    /// the impl (cmaas-audit response-key path): the real Sigstore rekor PEM
    /// (for checkpoint/SET) and the real DSSE publisher PEM (for the publisher
    /// signature) must be supplied so the full verification succeeds. Negative
    /// tests pass a WRONG pem for one of the two to exercise the fail-closed
    /// paths.
    fn resolve_response_body(
        manifest: &serde_json::Value,
        log_entry: &serde_json::Value,
        entry_url: &str,
        entry_verifier_content: &str,
        log_verifier_pem: &str,
    ) -> String {
        serde_json::json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": [{
                "type": "rekor-v1",
                "url": entry_url,
                "log_entry": log_entry,
                "entry_verifier": {"type": "public_key", "content": entry_verifier_content},
                "log_verifier": {"public_key_pem": log_verifier_pem}
            }]
        })
        .to_string()
    }

    /// Primary path: the Artifact Server resolves the manifest and returns a
    /// rekor-v1 entry whose authenticated `payloadHash` matches
    /// `sha256(JCS(manifest))` → `Ok(Bool(true))`.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_true_on_valid_entries() {
        // `RESOLVE_CACHE` is process-global and `cargo test` runs tests in
        // parallel — clear it so a prior success in `caches_success` (same
        // cache key) cannot short-circuit this call into a no-network hit.
        RESOLVE_CACHE.invalidate_all();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        let body = resolve_response_body(
            &manifest,
            &log_entry,
            &entry_url,
            LOG_ENTRY_PUB_KEY_PEM,
            SIGSTORE_REKOR_V1_PUB_KEY_PEM,
        );
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1) // must hit the network (not a stale cache hit)
            .mount(&server)
            .await;

        let hv = resolve_artifact_server_host_await();
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let ls = format!(r#"[{{"type":"rekor-v1","url":"{entry_url}"}}]"#);
        let arg = regorus::Value::from(vec![
            regorus::Value::from(server.uri().as_str()),
            regorus::Value::from(manifest_json.as_str()),
            regorus::Value::from(ls.as_str()),
        ]);
        let r = invoke_extension(&hv, arg).await;
        assert_eq!(r, regorus::Value::Bool(true));
    }

    /// §11 clean-deny on network failure: a dead port → any error →
    /// `Ok(Bool(false))`, never `Err`. Asserts on the raw `Result` (not
    /// `invoke_extension`'s `.expect()`, which would mask an `Err`).
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_network_error() {
        let hv = resolve_artifact_server_host_await();
        let arg = regorus::Value::from(vec![
            regorus::Value::from("http://127.0.0.1:1"),
            regorus::Value::from(
                r#"{"schemaVersion":"1.0.0","measurements":[{"type":"tdx.td-shim","value":"sha256:deadbeef"}]}"#,
            ),
            regorus::Value::from(r#"[{"type":"rekor-v1","url":"https://rekor.sigstore.dev"}]"#),
        ]);
        let hv = hv.clone();
        let result: Result<regorus::Value, _> = hv(arg).await;
        assert!(
            result.is_ok(),
            "host-await must return Ok(Bool(false)) on network error, got Err: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap(), regorus::Value::Bool(false));
    }

    /// payloadHash mismatch: the mock returns a valid (authentic) entry but the
    /// manifest arg does NOT hash to the entry's `payloadHash` → authenticate
    /// succeeds, the comparison fails → `Ok(Bool(false))`, and the failure is
    /// NOT cached.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_payload_hash_mismatch() {
        let server = MockServer::start().await;
        let (_manifest, log_entry, entry_url) = cmaas_resolve_triple();
        // A manifest with a different measurement value → different sha256.
        let mismatch_manifest = serde_json::json!({"schemaVersion":"1.0.0","measurements":[{"type":"tdx.td-shim","value":"sha256:deadbeef"}]});
        let body = resolve_response_body(
            &mismatch_manifest,
            &log_entry,
            &entry_url,
            LOG_ENTRY_PUB_KEY_PEM,
            SIGSTORE_REKOR_V1_PUB_KEY_PEM,
        );
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let hv = resolve_artifact_server_host_await();
        let manifest_json = serde_json::to_string(&mismatch_manifest).unwrap();
        let ls = format!(r#"[{{"type":"rekor-v1","url":"{entry_url}"}}]"#);
        let arg = regorus::Value::from(vec![
            regorus::Value::from(server.uri().as_str()),
            regorus::Value::from(manifest_json.as_str()),
            regorus::Value::from(ls.as_str()),
        ]);
        let hv = hv.clone();
        let result: Result<regorus::Value, _> = hv(arg).await;
        assert!(result.is_ok(), "got Err: {:?}", result.err());
        assert_eq!(result.unwrap(), regorus::Value::Bool(false));
    }

    /// Request-binding (dedup): the mock returns TWO copies of the same valid
    /// entry (both authenticable, payloadHash matches). The second is a
    /// duplicate of a requested logService → `remaining.remove` returns false
    /// → reject → `Ok(Bool(false))`. Without the dedup check both would
    /// authenticate and the call would (incorrectly) return `true`, so this
    /// test pins Finding 1's contract.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_duplicate_entry() {
        RESOLVE_CACHE.invalidate_all();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        // Two copies of the same (type, url) entry — a malicious resolver
        // trying to pad the response. Both are individually authenticable (real
        // response verifiers supplied).
        let body = serde_json::json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": [
                {
                    "type": "rekor-v1",
                    "url": entry_url,
                    "log_entry": log_entry,
                    "entry_verifier": {"type": "public_key", "content": LOG_ENTRY_PUB_KEY_PEM},
                    "log_verifier": {"public_key_pem": SIGSTORE_REKOR_V1_PUB_KEY_PEM}
                },
                {
                    "type": "rekor-v1",
                    "url": entry_url,
                    "log_entry": log_entry,
                    "entry_verifier": {"type": "public_key", "content": LOG_ENTRY_PUB_KEY_PEM},
                    "log_verifier": {"public_key_pem": SIGSTORE_REKOR_V1_PUB_KEY_PEM}
                }
            ]
        })
        .to_string();
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let hv = resolve_artifact_server_host_await();
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let ls = format!(r#"[{{"type":"rekor-v1","url":"{entry_url}"}}]"#);
        let arg = regorus::Value::from(vec![
            regorus::Value::from(server.uri().as_str()),
            regorus::Value::from(manifest_json.as_str()),
            regorus::Value::from(ls.as_str()),
        ]);
        let hv = hv.clone();
        let result: Result<regorus::Value, _> = hv(arg).await;
        assert!(result.is_ok(), "got Err: {:?}", result.err());
        assert_eq!(result.unwrap(), regorus::Value::Bool(false));
    }

    /// Negative: the response supplies a WRONG `entry_verifier.content` (a
    /// different valid P-256 PEM — the Sigstore rekor key, NOT the DSSE
    /// publisher key). Rekor auth (logID/checkpoint/inclusion/SET) passes (the
    /// `log_verifier` is the real Sigstore key) and payloadHash matches, but the
    /// DSSE publisher signature fails to verify against the wrong key over
    /// `sha256(DSSEPAE(canonical_manifest))` → `Ok(Bool(false))`. Mirrors
    /// cmaas-audit's `verifyLogEntrySignature` failure path.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_wrong_entry_verifier() {
        RESOLVE_CACHE.invalidate_all();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        // Wrong publisher PEM (the Sigstore rekor key — a valid P-256 key that
        // did NOT sign the DSSE envelope) → DSSE verification fails.
        let body = resolve_response_body(
            &manifest,
            &log_entry,
            &entry_url,
            SIGSTORE_REKOR_V1_PUB_KEY_PEM, // wrong publisher key
            SIGSTORE_REKOR_V1_PUB_KEY_PEM, // correct rekor key
        );
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let hv = resolve_artifact_server_host_await();
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let ls = format!(r#"[{{"type":"rekor-v1","url":"{entry_url}"}}]"#);
        let arg = regorus::Value::from(vec![
            regorus::Value::from(server.uri().as_str()),
            regorus::Value::from(manifest_json.as_str()),
            regorus::Value::from(ls.as_str()),
        ]);
        let hv = hv.clone();
        let result: Result<regorus::Value, _> = hv(arg).await;
        assert!(result.is_ok(), "got Err: {:?}", result.err());
        assert_eq!(result.unwrap(), regorus::Value::Bool(false));
    }

    /// Negative: the response supplies a WRONG `log_verifier.public_key_pem`
    /// (a different valid P-256 PEM — the DSSE publisher key, NOT the Sigstore
    /// rekor key). `authenticate_entry`'s `verify_log_id` fails (the entry's
    /// `logID` == `sha256(Sigstore SPKI)`, not `sha256(wrong SPKI)`) →
    /// `Ok(Bool(false))`. Mirrors cmaas-audit's `verifyRekorLogID` failure path.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_wrong_log_verifier() {
        RESOLVE_CACHE.invalidate_all();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        // Wrong rekor PEM (the DSSE publisher key — a valid P-256 key whose
        // SPKI hash != the entry's logID) → rekor logID verification fails.
        let body = resolve_response_body(
            &manifest,
            &log_entry,
            &entry_url,
            LOG_ENTRY_PUB_KEY_PEM, // correct publisher key
            LOG_ENTRY_PUB_KEY_PEM, // wrong rekor key
        );
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let hv = resolve_artifact_server_host_await();
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let ls = format!(r#"[{{"type":"rekor-v1","url":"{entry_url}"}}]"#);
        let arg = regorus::Value::from(vec![
            regorus::Value::from(server.uri().as_str()),
            regorus::Value::from(manifest_json.as_str()),
            regorus::Value::from(ls.as_str()),
        ]);
        let hv = hv.clone();
        let result: Result<regorus::Value, _> = hv(arg).await;
        assert!(result.is_ok(), "got Err: {:?}", result.err());
        assert_eq!(result.unwrap(), regorus::Value::Bool(false));
    }
    /// mock returns only one (the fixture sigstore entry). After the loop
    /// `remaining` still contains the uncovered openanolis service → reject
    /// → `Ok(Bool(false))`. Pins Finding 1's "all requested must be covered"
    /// contract.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_missing_requested_log_service() {
        RESOLVE_CACHE.invalidate_all();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        let body = resolve_response_body(
            &manifest,
            &log_entry,
            &entry_url,
            LOG_ENTRY_PUB_KEY_PEM,
            SIGSTORE_REKOR_V1_PUB_KEY_PEM,
        );
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let hv = resolve_artifact_server_host_await();
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        // Request two log services; only the sigstore one is returned.
        let ls = format!(
            r#"[{{"type":"rekor-v1","url":"{entry_url}"}},{{"type":"rekor-v1","url":"https://rekor.openanolis.cn"}}]"#
        );
        let arg = regorus::Value::from(vec![
            regorus::Value::from(server.uri().as_str()),
            regorus::Value::from(manifest_json.as_str()),
            regorus::Value::from(ls.as_str()),
        ]);
        let hv = hv.clone();
        let result: Result<regorus::Value, _> = hv(arg).await;
        assert!(result.is_ok(), "got Err: {:?}", result.err());
        assert_eq!(result.unwrap(), regorus::Value::Bool(false));
    }

    /// Cache hit: after a successful resolve, a second call with the same
    /// `(manifest, log_services)` returns `true` WITHOUT hitting the mock
    /// again. `expect(1)` requires EXACTLY one network hit — without the
    /// cache the second call would hit the mock a second time (panicking on
    /// verify); with the cache the second call is served from cache (0
    /// additional hits → verify passes). `invalidate_all()` at the start
    /// prevents cross-test pollution from `true_on_valid_entries`, which
    /// shares the same `(manifest_hash, canonical_log_services)` cache key.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_caches_success() {
        RESOLVE_CACHE.invalidate_all();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        let body = resolve_response_body(
            &manifest,
            &log_entry,
            &entry_url,
            LOG_ENTRY_PUB_KEY_PEM,
            SIGSTORE_REKOR_V1_PUB_KEY_PEM,
        );
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1) // exactly ONE network hit — second call must come from cache
            .mount(&server)
            .await;

        let hv = resolve_artifact_server_host_await();
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let ls = format!(r#"[{{"type":"rekor-v1","url":"{entry_url}"}}]"#);
        let arg = regorus::Value::from(vec![
            regorus::Value::from(server.uri().as_str()),
            regorus::Value::from(manifest_json.as_str()),
            regorus::Value::from(ls.as_str()),
        ]);
        // first call hits the mock → success → cached.
        let r1 = invoke_extension(&hv, arg.clone()).await;
        assert_eq!(r1, regorus::Value::Bool(true));
        // second call must NOT hit the mock (expect(1) would panic on a 2nd)
        // — served from cache.
        let r2 = invoke_extension(&hv, arg).await;
        assert_eq!(r2, regorus::Value::Bool(true));
    }
}
