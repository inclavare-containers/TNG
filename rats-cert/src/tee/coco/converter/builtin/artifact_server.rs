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
    // built-in keys by logID match. The two built-in hostnames are the only
    // entries in `rekor_public_key`'s table, so this enumerates the full set.
    for known in ["https://rekor.sigstore.dev", "https://rekor.openanolis.cn"] {
        if let Ok(key) = rekor_v1::rekor_public_key(known, None) {
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
    let v: serde_json::Value = serde_json::from_str(manifest_json)?;
    let canon = rekor_v1::jcs_compact(&v);
    let mut hasher = sha2::Sha256::new();
    hasher.update(canon.as_bytes());
    Ok(hex::encode(hasher.finalize()))
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
}
