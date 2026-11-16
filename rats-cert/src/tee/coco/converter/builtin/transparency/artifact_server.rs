//! Artifact-server and on-demand rekor authentication for the
//! transparency_log policy.
//!
//! The generated Rego policy calls `tng.resolve_artifact_server` for the
//! artifact-server primary and `tng.fetch_rekor_on_demand` as the fallback
//! when the primary fails to resolve a measurement. Both are thin wrappers
//! over the transparency seam; the authentication and caching live in
//! [`super::authenticate`] and the two adapters.

#[cfg(feature = "crypto-rustcrypto")]
use std::sync::Arc;

#[cfg(feature = "crypto-rustcrypto")]
use anyhow::Result;

#[cfg(feature = "crypto-rustcrypto")]
use attestation_service::policy_engine::opa::ExtensionFunction;

#[cfg(feature = "crypto-rustcrypto")]
use super::cache::{
    CanonicalLogServices, ManifestDigest, PublisherKeyId, ResolveCacheKey, TransparencyCaches,
};
#[cfg(feature = "crypto-rustcrypto")]
use super::{dsse, key_table, rekor_v1, Authentication};
use crate::tee::coco::converter::builtin::policy_config::{
    ArtifactLogService, TransparencyServiceConfig,
};

// Wire types and the resolve POST live in the upstream `artifact-resolve-sdk`
// crate (`ResolveRequest`, `ReleaseManifest`, `LogService`, `ResolveResponse`,
// `LogEntry`, `EntryVerifier`, `LogVerifier`, `Client`).

/// The artifact-server adapter for the transparency seam.
///
/// Resolve the manifest, authenticate every returned rekor-v1 entry, verify
/// each entry's publisher signature over the canonical manifest, and compare
/// each trusted `payloadHash`. The resolve is cached under the server URL, the
/// manifest digest, the canonical log-services list, and the publisher key, so
/// a success is only reused for the identical trust configuration. An explicit
/// revocation is returned as [`Authentication::Revoked`] and never cached.
pub(crate) async fn authenticate(
    manifest: &serde_json::Value,
    service: &TransparencyServiceConfig,
    caches: &TransparencyCaches,
) -> Result<Authentication> {
    let TransparencyServiceConfig::ArtifactServer {
        url,
        log_services,
        publisher_public_key_pem,
    } = service
    else {
        anyhow::bail!("artifact_server::authenticate called with a non-artifact service");
    };
    let expected = dsse::canonical_manifest_sha256(manifest)?;
    let cache_key = ResolveCacheKey {
        artifact_server_url: url.clone(),
        manifest_digest: ManifestDigest::new(&expected)?,
        log_services: CanonicalLogServices::new(&serde_json::to_string(log_services)?)?,
        publisher_key: PublisherKeyId::new(publisher_public_key_pem.as_deref()),
    };
    if caches.resolve_hit(&cache_key).await {
        return Ok(Authentication::Verified);
    }
    match resolve_and_authenticate(
        manifest,
        url,
        log_services,
        &expected,
        publisher_public_key_pem.as_deref(),
    )
    .await?
    {
        ResolveStatus::Verified => {
            caches.insert_resolve(cache_key).await;
            Ok(Authentication::Verified)
        }
        ResolveStatus::Revoked => Ok(Authentication::Revoked),
    }
}

/// `tng.fetch_rekor_on_demand(log_url, log_index, manifest_json,
/// publisher_key_pem?) -> bool`.
///
/// Fallback path: fetch a Rekor v1 entry by `logIndex` on demand, authenticate
/// it (checkpoint + Merkle inclusion + SET), verify its DSSE publisher
/// signature over `sha256(DSSEPAE(canonical manifest))` with the
/// configured-or-built-in publisher key, and compare its trusted `payloadHash`
/// to `sha256(canonical manifest)`. The canonical manifest is the JCS (RFC
/// 8785) sorted-compact serialization, exactly what Rego's
/// `json.marshal(manifest)` produces for this (number-free) shape, so the
/// comparison agrees with the load-time `tng.sha256` path.
///
/// The optional 4th arg is a configured publisher PEM (from the fallback
/// `RekorV1` service's `publisherPublicKeyPem`); empty/absent falls back to
/// the built-in publisher key.
///
/// Fail-closed / clean-deny: all failures return `Ok(Bool(false))`, never
/// `Err`. An `Err` would abort the entire policy evaluation and break the
/// fallback contract.
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) fn fetch_rekor_on_demand_host_await() -> ExtensionFunction {
    use regorus::Value;

    Arc::new(move |argument: regorus::Value| {
        Box::pin(async move {
            let inner = async {
                let arr = argument.as_array().ok()?;
                if !(arr.len() == 3 || arr.len() == 4) {
                    return None;
                }
                let log_url = arr[0].as_string().ok()?.to_string();
                let log_index = arr[1].as_i64().ok()?;
                let manifest: serde_json::Value =
                    serde_json::from_str(arr[2].as_string().ok()?).ok()?;
                let publisher_public_key_pem = if arr.len() == 4 {
                    Some(arr[3].as_string().ok()?.to_string())
                } else {
                    None
                };
                let service = TransparencyServiceConfig::RekorV1 {
                    log_url,
                    log_index,
                    rekor_public_key_pem: None,
                    publisher_public_key_pem,
                };
                match super::authenticate(Some(&manifest), &service, &TransparencyCaches::shared())
                    .await
                {
                    Ok(Authentication::Verified) => Some(true),
                    _ => None,
                }
            };
            Ok(Value::Bool(inner.await.unwrap_or(false)))
        })
    })
}

/// `tng.resolve_artifact_server(artifact_server_url, manifest_json,
/// log_services_json, publisher_key_pem?) -> "ok" | "deny" | "fail"`.
///
/// Returns a tri-state string so the Rego policy can tell an explicit
/// revocation apart from an ordinary failure:
/// - `"ok"`: resolve succeeded and every entry authenticated (or a cached
///   prior success).
/// - `"deny"`: the artifact server answered `measurement_revoked`. A hard
///   denial: the rekor fallback MUST NOT run for it, because the append-only
///   rekor log still carries the revoked manifest's (immutable, fully
///   authentic) entry, so the fallback would pass and bypass the revocation.
///   Never cached: the revocation state is the server's to change.
/// - `"fail"`: any other failure (bad args, HTTP, decode, key resolution,
///   auth, manifest mismatch, `measurement_not_found`, ...). The Rego caller
///   falls back to `tng.fetch_rekor_on_demand`. Never cached.
///
/// Fail-closed / clean-deny: all outcomes return `Ok(String)`, never `Err`.
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) fn resolve_artifact_server_host_await() -> ExtensionFunction {
    use regorus::Value;

    Arc::new(move |argument: regorus::Value| {
        Box::pin(async move {
            let inner = async {
                let arr = argument.as_array().ok()?;
                if !(arr.len() == 3 || arr.len() == 4) {
                    return None;
                }
                let url = arr[0].as_string().ok()?.to_string();
                let manifest: serde_json::Value =
                    serde_json::from_str(arr[1].as_string().ok()?).ok()?;
                let log_services: Vec<ArtifactLogService> =
                    serde_json::from_str(arr[2].as_string().ok()?).ok()?;
                let publisher_public_key_pem = if arr.len() == 4 {
                    Some(arr[3].as_string().ok()?.to_string())
                } else {
                    None
                };
                let service = TransparencyServiceConfig::ArtifactServer {
                    url,
                    log_services,
                    publisher_public_key_pem,
                };
                match super::authenticate(Some(&manifest), &service, &TransparencyCaches::shared())
                    .await
                {
                    Ok(Authentication::Verified) => Some("ok"),
                    Ok(Authentication::Revoked) => Some("deny"),
                    _ => None,
                }
            };
            Ok(Value::from(inner.await.unwrap_or("fail")))
        })
    })
}

/// Resolve the manifest via the Artifact Server and authenticate every
/// returned rekor-v1 entry. Returns `Ok(())` only when:
/// - the resolve status is `"resolved"`,
/// - at least one entry is returned,
/// - every returned entry's `(type, url)` matches exactly one requested
///   `logService` (no unrequested, duplicate, or missing entries, request
///   binding for a non-trusted resolver; URLs are normalized by
///   trimming trailing slashes),
/// - every entry authenticates (checkpoint + inclusion + SET via
///   `rekor_v1::authenticate_entry`),
/// - every entry's DSSE publisher signature verifies over
///   `sha256(DSSEPAE(canonical manifest))` with a trusted publisher key
///   (response `entry_verifier.content` when both verifiers are present, or
///   the configured/built-in publisher key when both are absent; mixed
///   one-present-one-absent is rejected),
///   and
/// - every entry's `payloadHash == expected_hash`.
///
/// `configured_publisher_pem` is the optional `ArtifactServer` config override;
/// empty/None falls back to the built-in publisher key.
///
/// Returns `Ok(ResolveStatus::Revoked)` (distinct from any error) when the
/// artifact server answers `measurement_revoked`, so the caller reports a
/// hard denial instead of an ordinary failure. Any error → `Err` (mapped to
/// `"fail"` by the caller, never cached).
#[cfg(feature = "crypto-rustcrypto")]
enum ResolveStatus {
    /// Resolve status `"resolved"` and every returned entry authenticated.
    Verified,
    /// The artifact server answered `measurement_revoked`.
    Revoked,
}

#[cfg(feature = "crypto-rustcrypto")]
async fn resolve_and_authenticate(
    manifest: &serde_json::Value,
    url: &str,
    log_services: &[ArtifactLogService],
    expected_hash: &str,
    configured_publisher_pem: Option<&str>,
) -> Result<ResolveStatus> {
    let sdk_manifest: artifact_resolve_sdk::ReleaseManifest =
        serde_json::from_value(manifest.clone())?;
    let sdk_log_services: Vec<artifact_resolve_sdk::LogService> = log_services
        .iter()
        .map(|ls| artifact_resolve_sdk::LogService {
            type_: ls.type_.clone(),
            url: Some(ls.url.clone()),
        })
        .collect();
    // Build the requested (type, url) set BEFORE moving `sdk_log_services`
    // into the request, used to verify the response covers exactly the
    // requested services (no unrequested / duplicate / missing entries). URLs
    // are normalized by trimming trailing slashes so a caller that appends `/`
    // still matches a response without one.
    let mut remaining: std::collections::HashSet<(String, String)> = log_services
        .iter()
        .map(|ls| (ls.type_.clone(), ls.url.trim_end_matches('/').to_string()))
        .collect();
    let req =
        artifact_resolve_sdk::ResolveRequest::new(sdk_manifest).with_log_services(sdk_log_services);
    let resp = match artifact_resolve_sdk::Client::new(url)?.resolve(&req).await {
        Ok(resp) => resp,
        // An explicit revocation is a hard denial, not an ordinary failure:
        // the caller reports "deny" so the rekor fallback does not fire (the
        // append-only rekor entry of a revoked manifest is immutable and
        // would still fully authenticate).
        Err(err) if err.is_measurement_revoked() => return Ok(ResolveStatus::Revoked),
        Err(err) => return Err(err.into()),
    };
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
    // DSSE PAE construction (publisher-signature verification) below, computed
    // once so every entry sees the same canonical payload.
    let canonical_manifest = dsse::canonical_manifest_bytes(manifest)?;
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
        // `log_verifier.public_key_pem` (response-key path: the
        // artifact-server is semi-trusted for key transport); fall back to
        // the built-in hostname→logID resolution when the response omits it
        // (so proxy / mock URLs still resolve via the built-in key table).
        let key = if !entry.log_verifier.public_key_pem.is_empty() {
            key_table::rekor_public_key(&entry.url, Some(&entry.log_verifier.public_key_pem))?
        } else {
            key_table::resolve_rekor_key(&rekor_entry, &entry.url)?
        };
        let auth = rekor_v1::authenticate_entry(&rekor_entry, &key)?;
        if auth.payload_hash != expected_hash {
            anyhow::bail!(
                "payloadHash mismatch: entry={} expected={}",
                auth.payload_hash,
                expected_hash
            );
        }
        // DSSE publisher-signature verification — ALWAYS run with a trusted
        // publisher key. The publisher key is the response
        // `entry_verifier.content` when both verifiers are present
        // (response-key path), or the configured-or-built-in publisher key when
        // both are absent (configured-key path). A mixed (one present, one
        // absent) is rejected: the two verifiers must be both-present-or-both
        // -absent. The signature
        // (`body.spec.signatures[0].signature`, base64) is verified over
        // `sha256(DSSEPAE(canonical_manifest))`.
        let (publisher_pem, used_response_key) =
            resolve_publisher_key(entry, configured_publisher_pem)?;
        dsse::verify_publisher_signature(
            &publisher_pem,
            canonical_manifest.as_bytes(),
            &auth.dsse_signature,
        )?;
        // Baseline-compare + warn (#9): after successful verification, compare
        // BOTH the rekor key AND the publisher key to the SDK built-in
        // baseline by SPKI DER. A mismatch is logged but NOT rejected
        // (warn-and-pass). Best effort: if a built-in resolution fails (e.g.
        // a proxy URL with no built-in hostname match), skip that compare
        // silently rather than denying.
        if !entry.log_verifier.public_key_pem.is_empty() {
            if let Ok(builtin) = key_table::rekor_public_key(&entry.url, None) {
                if key.spki_der != builtin.spki_der {
                    tracing::warn!(
                        url = %entry.url,
                        "transparency verification key differs from built-in baseline; \
                         the artifact-server supplied a different rekor key"
                    );
                }
            }
        }
        if used_response_key {
            // Compare the response publisher key to the configured/built-in
            // baseline publisher key (warn-and-pass). The baseline is the
            // configured key when one is set, else the built-in publisher key.
            // Compare by the encoded SEC1 point bytes (VerifyingKey has no
            // SPKI DER field, but the encoded point is a canonical public-key
            // identity).
            let baseline_pem = dsse::effective_publisher_pem(configured_publisher_pem);
            if let (Ok(resp_key), Ok(baseline_key)) = (
                dsse::parse_p256_public_key(&publisher_pem),
                dsse::parse_p256_public_key(baseline_pem),
            ) {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                if resp_key.to_encoded_point(false) != baseline_key.to_encoded_point(false) {
                    tracing::warn!(
                        url = %entry.url,
                        "transparency publisher key differs from built-in baseline; \
                         the artifact-server supplied a different DSSE publisher key"
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
    Ok(ResolveStatus::Verified)
}

/// Resolve the trusted DSSE publisher key for a resolve response entry
/// (response-key vs configured-key rule):
/// - **valid**: `entry_verifier.type_ == "public_key"` with non-empty
///   `content` AND `log_verifier.public_key_pem` non-empty → use the
///   response publisher key.
/// - **present-but-empty**: `entry_verifier.type_ == "public_key"` but
///   `content` is empty, OR `log_verifier.public_key_pem` is empty (with the
///   verifier objects present) → REJECT (fail-closed). cmaas rejects this with
///   `"empty verifier public key"` (`rekorv1.go:179-181`); the previous TNG
///   behavior treated present-but-empty as "absent" and fell back to the
///   built-in/configured key, which could succeed against a real DSSE
///   signature — a fail-open gap. Do NOT fall back for this case.
/// - **wrong type** (`type_` non-empty and `!= "public_key"`): rejected (R2)
///   regardless of `LogVerifier`.
/// - **mixed** (one verifier declared, the other empty): rejected (the two
///   verifiers must be both-present-or-both-absent).
/// - **both-absent** (genuinely empty-struct `entry_verifier` with empty
///   `type_` paired with empty `public_key_pem`): fall back to the
///   configured-or-built-in publisher key (R5: when the transparency config
///   supplies no `publisherPublicKeyPem`, the built-in
///   `BUILTIN_LOG_ENTRY_PUB_KEY_PEM` is the default DSSE key). This is the
///   only response shape that still deserializes without a declared verifier
///   type and is kept reachable for a genuinely empty-struct response.
///
/// Returns the resolved publisher PEM to verify DSSE against, plus a flag
/// indicating whether the response key was used (for the baseline-compare warn
/// in #9).
///
/// The SDK's `EntryVerifier`/`LogVerifier` are always-present (non-Optional)
/// types, so an absent on-the-wire `entry_verifier` is represented here as a
/// genuinely empty struct (`type_` empty). A `type_ == "public_key"` with empty
/// `content` is NOT absent — it is present-but-empty and is rejected. A
/// present-but-wrong-type `entry_verifier` (non-empty `type_` that is not
/// `"public_key"`) is also NOT "absent" — a wrong verifier type is rejected
/// (fail-closed) regardless of `LogVerifier`. Distinguish the three so a
/// wrong-type or present-but-empty verifier is rejected (fail-closed) instead
/// of silently falling back to the built-in key (which could succeed against a
/// real DSSE signature).
#[cfg(feature = "crypto-rustcrypto")]
fn resolve_publisher_key(
    entry: &artifact_resolve_sdk::LogEntry,
    configured_publisher_pem: Option<&str>,
) -> Result<(String, bool)> {
    let ev = &entry.entry_verifier;
    let lv = &entry.log_verifier;
    // R2: a present EntryVerifier with a non-public_key type is an unsupported
    // verifier and is rejected regardless of LogVerifier.
    if !ev.type_.is_empty() && ev.type_ != "public_key" {
        anyhow::bail!("unsupported entry_verifier type {:?}", ev.type_);
    }
    // "Absent" = the verifier object deserialized as a genuinely empty struct
    // (no `type_` declared). A `type_ == "public_key"` with empty `content`
    // is NOT absent — it is present-but-empty, rejected below (cmaas "empty
    // verifier public key", rekorv1.go:179-181) instead of falling back to the
    // built-in key (which could succeed against a real DSSE signature).
    let ev_absent = ev.type_.is_empty();
    let lv_absent = lv.public_key_pem.is_empty();
    // Mixed (one verifier declared, the other empty) → reject: the two
    // verifiers must be both-present-or-both-absent.
    if ev_absent != lv_absent {
        anyhow::bail!(
            "entry_verifier and log_verifier must be provided together (one is empty/unsupported)"
        );
    }
    if ev_absent {
        // Both absent (genuinely empty struct) → configured-or-built-in
        // publisher key (R5: the built-in BUILTIN_LOG_ENTRY_PUB_KEY_PEM is
        // the config-default DSSE key when no publisherPublicKeyPem is set).
        let pem = dsse::effective_publisher_pem(configured_publisher_pem);
        return Ok((pem.to_string(), false));
    }
    // Both verifiers are present (`type_ == "public_key"`). A
    // present-but-empty `entry_verifier.content` is rejected (cmaas "empty
    // verifier public key") — do NOT fall back to the built-in key.
    // (`log_verifier.public_key_pem` is guaranteed non-empty here: a
    // present-but-empty pem would have been rejected above as mixed, since
    // `ev_absent=false != lv_absent=true`.)
    if ev.content.is_empty() {
        anyhow::bail!("empty verifier public key (present-but-empty entry_verifier content)");
    }
    Ok((ev.content.clone(), true))
}

/// Test-only helper: clear the shared transparency caches so a test can
/// exercise the real network path (and avoid cross-test cache pollution).
#[cfg(test)]
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) fn invalidate_host_await_caches_for_test() {
    TransparencyCaches::shared().invalidate_all();
}

#[cfg(test)]
#[cfg(feature = "crypto-rustcrypto")]
mod tests {
    use super::*;
    use crate::tee::coco::converter::builtin::policies::test_support::{
        cmaas_transparency_tuple, fixtures, invoke_extension, rekor_entries_body,
        DSSE_PUBLISHER_PUB_KEY_PEM, SIGSTORE_REKOR_V1_PUB_KEY_PEM,
    };
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Link smoke for the `artifact-resolve-sdk` crate: construct the basic
    /// request types and assert the wire-shape constants are reachable, so a
    /// future change that drops `dep:artifact-resolve-sdk` from the
    /// `__builtin-as` feature list (or bumps the sdk past the pinned rev)
    /// fails here rather than silently reverting the resolve path to a dead
    /// import. No network: `Client::new` only validates the base URL.
    #[test]
    fn artifact_resolve_sdk_link_smoke() {
        let manifest =
            artifact_resolve_sdk::ReleaseManifest::new([artifact_resolve_sdk::Measurement::text(
                "tdx.td-shim",
                "sha256:deadbeef",
            )]);
        assert_eq!(
            manifest.schema_version,
            artifact_resolve_sdk::SCHEMA_VERSION
        );
        let req = artifact_resolve_sdk::ResolveRequest::new(manifest).with_log_service(
            artifact_resolve_sdk::LogService::rekor_v1("https://rekor.example.com"),
        );
        let ls = req.log_services.expect("log_services set");
        assert_eq!(ls[0].type_, artifact_resolve_sdk::LOG_SERVICE_REKOR_V1);
        assert_eq!(ls[0].url.as_deref(), Some("https://rekor.example.com"));
        // `Client::new` builds the HTTP client (validates base_url); no I/O.
        let client = artifact_resolve_sdk::Client::new("http://127.0.0.1:1");
        assert!(client.is_ok());
    }

    // Reuse the existing rekor_v1 fixture entry to build a mock
    // /api/v1/log/entries response: the wire format is `{uuid: entry}`.
    fn rekor_entries_response_body() -> String {
        let entry: serde_json::Value = serde_json::from_str(fixtures::REKOR_V1_ENTRY_JSON).unwrap();
        rekor_entries_body(&entry)
    }

    /// A manifest that does NOT hash to the fixture entry's payloadHash.
    /// Used to assert the *mismatch* path (bool false) while still exercising
    /// fetch+auth+cache. The fixture entry's payloadHash is
    /// `1011b70c...` (pinned by `decode_fixture_body_extracts_payload_hash`);
    /// an empty manifest hashes to a different value → comparison is false,
    /// but authentication of the fixture entry succeeds (real crypto), so the
    /// authenticated payload_hash is cached.
    const DUMMY_MISMATCH_MANIFEST: &str = r#"{"schemaVersion":"1.0.0","measurements":[]}"#;

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
        // second call must NOT hit the mock (would 404 / fail); served from cache.
        let r2 = invoke_extension(&hv, arg).await;
        assert_eq!(r2, regorus::Value::Bool(false));
    }

    /// Fail-closed fallback: a fetch/auth failure MUST return `Ok(Bool(false))`,
    /// never `Err`; an `Err` aborts the entire policy evaluation and breaks
    /// the `fallback_ok → false → executables := 97` contract. Point the
    /// `log_url` at a dead port so `fetch_rekor_entry` fails to connect; the
    /// closure must swallow the error into a clean `false`. Asserts on the
    /// raw `Result` (not `invoke_extension`'s `.expect()`, which would mask
    /// an `Err` as a test failure rather than proving the `Ok(false)` outcome).
    #[tokio::test]
    async fn fetch_rekor_on_demand_returns_clean_false_on_fetch_failure() {
        // 127.0.0.1:1 is guaranteed to refuse the TCP connection (no listener
        // on port 1 on the loopback interface), `fetch_rekor_entry` returns a
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

    /// Build a rekor `/api/v1/log/entries` response body (`{uuid: entry}`) from
    /// the evidence fixture's matched `(release_manifest, log_entry)` pair. The
    /// entry's authenticated `payloadHash` ==
    /// `sha256(JCS(release_manifest))` == `b40611d4...` (pinned by the
    /// `mod.rs`/fixture tests), so a `fetch_rekor_on_demand` call passing the
    /// release manifest exercises the full fetch → authenticate →
    /// payloadHash-compare → `Ok(Bool(true))` happy path.
    fn cmaas_fetch_rekor_response_body() -> (String, String, i64) {
        let (manifest, log_entry, _entry_url, log_index) = cmaas_transparency_tuple();
        (
            rekor_entries_body(&log_entry),
            manifest.to_string(),
            log_index,
        )
    }

    /// True-path: `tng.fetch_rekor_on_demand` returns `Ok(Bool(true))` when a
    /// real rekor entry's authenticated `payloadHash` matches
    /// `sha256(JCS(manifest))`. Uses the evidence fixture's matched
    /// `(release_manifest, log_entry)` pair (logIndex 2310520944, payloadHash
    /// `b40611d4...`). Wiremock mocks `GET /api/v1/log/entries?logIndex=...`
    /// returning the entry as the `{uuid: entry}` rekor response. Asserts
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
            .and(query_param("logIndex", log_index.to_string()))
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

    /// DSSE verification is mandatory in the on-demand fallback. Passing a
    /// WRONG publisher key as the 4th arg must fail DSSE → `Ok(Bool(false))`
    /// even though the entry's payloadHash matches the manifest. Uses the
    /// fixture (real DSSE signature signed by the built-in publisher key);
    /// the Sigstore rekor key (a valid P-256 key that did NOT sign the envelope)
    /// is the wrong publisher → DSSE verify fails → clean-deny.
    #[tokio::test]
    #[serial_test::serial]
    async fn fetch_rekor_on_demand_false_on_wrong_publisher_key() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (body, manifest_json, log_index) = cmaas_fetch_rekor_response_body();
        Mock::given(method("GET"))
            .and(path("/api/v1/log/entries"))
            .and(query_param("logIndex", log_index.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;

        let hv = fetch_rekor_on_demand_host_await();
        let arg = regorus::Value::from(vec![
            regorus::Value::from(server.uri().as_str()),
            regorus::Value::from(log_index),
            regorus::Value::from(manifest_json.as_str()),
            // Wrong publisher key (the Sigstore rekor key, not the DSSE
            // publisher key that signed the fixture envelope).
            regorus::Value::from(SIGSTORE_REKOR_V1_PUB_KEY_PEM),
        ]);
        let hv = hv.clone();
        let result: Result<regorus::Value, _> = hv(arg).await;
        assert!(result.is_ok(), "got Err: {:?}", result.err());
        assert_eq!(
            result.unwrap(),
            regorus::Value::Bool(false),
            "on-demand fallback must reject when DSSE publisher signature fails"
        );
    }

    /// Load the evidence fixture and extract the matched
    /// `(release_manifest, log_entry, entry_url)` triple: the entry's
    /// `payloadHash` == `sha256(JCS(release_manifest))` (verified in
    /// `mod.rs`/fixture tests), so a resolve response built from it exercises
    /// both `authenticate_entry` (real inclusion/checkpoint/SET crypto) and the
    /// payloadHash comparison → `true`.
    fn cmaas_resolve_triple() -> (serde_json::Value, serde_json::Value, String) {
        let (manifest, log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        (manifest, log_entry, entry_url)
    }

    /// Build a resolve-response JSON body from the fixture pair. The
    /// `entry_verifier.content` / `log_verifier.public_key_pem` are now USED by
    /// the impl (response-key path): the real Sigstore rekor PEM (for
    /// checkpoint/SET) and the real DSSE publisher PEM (for the publisher
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
        // The shared cache is process-global and `cargo test` runs tests in
        // parallel; clear it so a prior success in `caches_success` (same
        // cache key) cannot short-circuit this call into a no-network hit.
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        let body = resolve_response_body(
            &manifest,
            &log_entry,
            &entry_url,
            DSSE_PUBLISHER_PUB_KEY_PEM,
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
        assert_eq!(r, regorus::Value::from("ok"));
    }

    /// Fail-closed fallback on network failure: a dead port → any error →
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
        assert_eq!(result.unwrap(), regorus::Value::from("fail"));
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
            DSSE_PUBLISHER_PUB_KEY_PEM,
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
        assert_eq!(result.unwrap(), regorus::Value::from("fail"));
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
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        // Two copies of the same (type, url) entry, a malicious resolver
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
                    "entry_verifier": {"type": "public_key", "content": DSSE_PUBLISHER_PUB_KEY_PEM},
                    "log_verifier": {"public_key_pem": SIGSTORE_REKOR_V1_PUB_KEY_PEM}
                },
                {
                    "type": "rekor-v1",
                    "url": entry_url,
                    "log_entry": log_entry,
                    "entry_verifier": {"type": "public_key", "content": DSSE_PUBLISHER_PUB_KEY_PEM},
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
        assert_eq!(result.unwrap(), regorus::Value::from("fail"));
    }

    /// Negative: the response supplies a WRONG `entry_verifier.content` (a
    /// different valid P-256 PEM, the Sigstore rekor key, NOT the DSSE
    /// publisher key). Rekor auth (logID/checkpoint/inclusion/SET) passes (the
    /// `log_verifier` is the real Sigstore key) and payloadHash matches, but the
    /// DSSE publisher signature fails to verify against the wrong key over
    /// `sha256(DSSEPAE(canonical_manifest))` → `Ok(Bool(false))`. This is the
    /// DSSE publisher-signature failure path.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_wrong_entry_verifier() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        // Wrong publisher PEM (the Sigstore rekor key, a valid P-256 key that
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
        assert_eq!(result.unwrap(), regorus::Value::from("fail"));
    }

    /// Negative: the response supplies a WRONG `log_verifier.public_key_pem`
    /// (a different valid P-256 PEM, the DSSE publisher key, NOT the Sigstore
    /// rekor key). `authenticate_entry`'s `verify_log_id` fails (the entry's
    /// `logID` == `sha256(Sigstore SPKI)`, not `sha256(wrong SPKI)`) →
    /// `Ok(Bool(false))`. This is the rekor logID verification failure path.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_wrong_log_verifier() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        // Wrong rekor PEM (the DSSE publisher key, a valid P-256 key whose
        // SPKI hash != the entry's logID) → rekor logID verification fails.
        let body = resolve_response_body(
            &manifest,
            &log_entry,
            &entry_url,
            DSSE_PUBLISHER_PUB_KEY_PEM, // correct publisher key
            DSSE_PUBLISHER_PUB_KEY_PEM, // wrong rekor key
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
        assert_eq!(result.unwrap(), regorus::Value::from("fail"));
    }
    /// mock returns only one (the fixture sigstore entry). After the loop
    /// `remaining` still contains the uncovered openanolis service → reject
    /// → `Ok(Bool(false))`. Pins Finding 1's "all requested must be covered"
    /// contract.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_missing_requested_log_service() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        let body = resolve_response_body(
            &manifest,
            &log_entry,
            &entry_url,
            DSSE_PUBLISHER_PUB_KEY_PEM,
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
        assert_eq!(result.unwrap(), regorus::Value::from("fail"));
    }

    /// Cache hit: after a successful resolve, a second call with the same
    /// `(manifest, log_services)` returns `true` WITHOUT hitting the mock
    /// again. `expect(1)` requires EXACTLY one network hit; without the
    /// cache the second call would hit the mock a second time (panicking on
    /// verify); with the cache the second call is served from cache (0
    /// additional hits → verify passes). `invalidate_all()` at the start
    /// prevents cross-test pollution from `true_on_valid_entries`, which
    /// shares the same `(manifest_hash, canonical_log_services)` cache key.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_caches_success() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        let body = resolve_response_body(
            &manifest,
            &log_entry,
            &entry_url,
            DSSE_PUBLISHER_PUB_KEY_PEM,
            SIGSTORE_REKOR_V1_PUB_KEY_PEM,
        );
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1) // exactly ONE network hit; second call must come from cache
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
        assert_eq!(r1, regorus::Value::from("ok"));
        // second call must NOT hit the mock (expect(1) would panic on a 2nd)
        // served from cache.
        let r2 = invoke_extension(&hv, arg).await;
        assert_eq!(r2, regorus::Value::from("ok"));
    }

    /// `measurement_revoked` from the artifact server is a hard denial
    /// (`"deny"`, no rekor fallback) and is never cached: both calls hit the
    /// mock (`expect(2)`), the second would be served from the cache if a
    /// revocation were cached like a success.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_deny_on_revoked() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, _log_entry, entry_url) = cmaas_resolve_triple();
        let body = serde_json::json!({
            "error_code": "measurement_revoked",
            "error_message": "the measurement was revoked",
            "request_id": "test-req-1"
        })
        .to_string();
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(403).set_body_string(body))
            .expect(2) // both calls must hit the network: revocations are not cached
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
        let result: Result<regorus::Value, _> = hv(arg.clone()).await;
        assert!(result.is_ok(), "got Err: {:?}", result.err());
        assert_eq!(
            result.unwrap(),
            regorus::Value::from("deny"),
            "an explicit server-side revocation is a hard denial"
        );
        // Second call re-asks the artifact server: the revocation state is
        // the server's to change, so it must not be cached.
        let result: Result<regorus::Value, _> = hv(arg).await;
        assert!(result.is_ok(), "got Err: {:?}", result.err());
        assert_eq!(result.unwrap(), regorus::Value::from("deny"));
    }

    /// `measurement_not_found` is an ordinary failure (`"fail"`, rekor
    /// fallback allowed), NOT a hard denial: only an explicit revocation
    /// denies. Pins the deny/fail boundary.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_fail_on_measurement_not_found() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, _log_entry, entry_url) = cmaas_resolve_triple();
        let body = serde_json::json!({
            "error_code": "measurement_not_found",
            "error_message": "no published release matches the manifest",
            "request_id": "test-req-2"
        })
        .to_string();
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(404).set_body_string(body))
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
        assert_eq!(
            result.unwrap(),
            regorus::Value::from("fail"),
            "not-found is an ordinary failure, not a hard denial"
        );
    }

    /// The resolve cache key includes the artifact-server URL: a success
    /// cached under URL A must not satisfy a call against URL B (the cache is
    /// process-global and outlives policy reloads that point at a different
    /// server). Server B's mock requires exactly one hit; a URL-less cache
    /// key would serve the second call from the cache and starve it.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_cache_key_includes_url() {
        invalidate_host_await_caches_for_test();
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        let body = resolve_response_body(
            &manifest,
            &log_entry,
            &entry_url,
            DSSE_PUBLISHER_PUB_KEY_PEM,
            SIGSTORE_REKOR_V1_PUB_KEY_PEM,
        );
        let server_a = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body.clone()))
            .expect(1)
            .mount(&server_a)
            .await;
        let server_b = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1) // MUST be hit: the cached A-success must not satisfy B
            .mount(&server_b)
            .await;

        let hv = resolve_artifact_server_host_await();
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let ls = format!(r#"[{{"type":"rekor-v1","url":"{entry_url}"}}]"#);
        let arg_for = |uri: &str| {
            regorus::Value::from(vec![
                regorus::Value::from(uri),
                regorus::Value::from(manifest_json.as_str()),
                regorus::Value::from(ls.as_str()),
            ])
        };
        let r_a = invoke_extension(&hv, arg_for(&server_a.uri())).await;
        assert_eq!(r_a, regorus::Value::from("ok"));
        let r_b = invoke_extension(&hv, arg_for(&server_b.uri())).await;
        assert_eq!(r_b, regorus::Value::from("ok"));
        // Verify the expect counts here rather than at mock teardown, so a
        // starved mock fails the test at the assertion site.
        server_b.verify().await;
        server_a.verify().await;
    }

    /// Line 90: `fetch_rekor_on_demand` returns `Ok(Bool(false))` (clean-deny)
    /// when the argument array has the wrong length (!= 3).
    #[tokio::test]
    async fn fetch_rekor_on_demand_false_on_wrong_arg_count() {
        let hv = fetch_rekor_on_demand_host_await();
        let arg = regorus::Value::from(vec![
            regorus::Value::from("http://example.com"),
            regorus::Value::from(1i64), // only 2 args, not 3
        ]);
        let r = invoke_extension(&hv, arg).await;
        assert_eq!(r, regorus::Value::Bool(false));
    }

    /// Line 253: `resolve_artifact_server` returns `Ok(Bool(false))`
    /// (clean-deny) when the argument array has the wrong length (!= 3).
    #[tokio::test]
    async fn resolve_artifact_server_false_on_wrong_arg_count() {
        let hv = resolve_artifact_server_host_await();
        let arg = regorus::Value::from(vec![
            regorus::Value::from("http://example.com"),
            regorus::Value::from("{}"), // only 2 args, not 3
        ]);
        let r = invoke_extension(&hv, arg).await;
        assert_eq!(r, regorus::Value::from("fail"));
    }

    /// Lines 357-358: resolve status != "resolved" → `Ok(Bool(false))`.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_non_resolved_status() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        // Valid response structure but with status != "resolved" so the SDK
        // deserializes it, then the status check fires.
        let body = serde_json::json!({
            "status": "pending",
            "release_manifest": manifest,
            "log_entries": [{
                "type": "rekor-v1",
                "url": entry_url,
                "log_entry": log_entry,
                "entry_verifier": {"type": "public_key", "content": ""},
                "log_verifier": {"public_key_pem": ""}
            }]
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
        assert_eq!(result.unwrap(), regorus::Value::from("fail"));
    }

    /// Line 363: resolve returns zero log entries → `Ok(Bool(false))`.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_empty_log_entries() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, _log_entry, entry_url) = cmaas_resolve_triple();
        let body = serde_json::json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": []
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
        assert_eq!(result.unwrap(), regorus::Value::from("fail"));
    }

    /// Line 371: log entry type != "rekor-v1" → `Ok(Bool(false))`.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_unsupported_entry_type() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, _log_entry, entry_url) = cmaas_resolve_triple();
        let body = serde_json::json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": [{
                "type": "rekor-v2",
                "url": entry_url,
                "log_entry": {},
                "entry_verifier": {"type": "public_key", "content": ""},
                "log_verifier": {"public_key_pem": ""}
            }]
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
        assert_eq!(result.unwrap(), regorus::Value::from("fail"));
    }

    /// Present-but-empty response verifiers must be REJECTED (fail-closed):
    /// when `entry_verifier.type_ == "public_key"` but `content` is empty
    /// (and/or `log_verifier.public_key_pem` is empty), cmaas rejects with
    /// `"empty verifier public key"` (`rekorv1.go:179-181`). The previous TNG
    /// behavior treated present-but-empty as "absent" and fell back to the
    /// built-in publisher key — here the fixture's DSSE signature is signed by
    /// the built-in key, so that fallback would SUCCEED (`Ok(Bool(true))`),
    /// a fail-open gap. After the fix `resolve_publisher_key` rejects
    /// present-but-empty instead of falling back → `Ok(Bool(false))`.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_empty_verifier_content() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        // Both verifiers present-but-empty (`type_ == "public_key"`, empty
        // content + empty pem) → reject (NOT built-in fallback).
        let body = resolve_response_body(
            &manifest, &log_entry, &entry_url,
            "", // empty entry_verifier content → present-but-empty → reject
            "", // empty log_verifier pem → present-but-empty → reject
        );
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
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
        assert_eq!(
            result.unwrap(),
            regorus::Value::from("fail"),
            "present-but-empty verifiers must reject, not fall back to the built-in key"
        );
    }

    /// Mixed verifiers (entry_verifier absent/unsupported + log_verifier
    /// present, or vice versa) must reject: `entry_verifier` and
    /// `log_verifier` must be both-present-or-both-absent. DSSE verification is
    /// now always mandatory: when both are present it runs against the response
    /// publisher key; when both are absent it runs against the
    /// configured/built-in publisher key; a mixed pair is rejected. Here
    /// `entry_verifier.type_ == "other"` (not `public_key`, so treated as
    /// absent) while `log_verifier` is present → mixed → `Ok(Bool(false))`.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_mixed_verifiers() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        let body = serde_json::json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": [{
                "type": "rekor-v1",
                "url": entry_url,
                "log_entry": log_entry,
                "entry_verifier": {"type": "other", "content": ""},
                "log_verifier": {"public_key_pem": SIGSTORE_REKOR_V1_PUB_KEY_PEM}
            }]
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
        assert_eq!(
            result.unwrap(),
            regorus::Value::from("fail"),
            "mixed verifiers (one present, one absent) must reject"
        );
    }

    /// A present-but-wrong-type `entry_verifier` must be rejected even when
    /// `log_verifier` is ALSO absent (empty): any non-absent `entry_verifier`
    /// whose `type_` != "public_key" is an unsupported verifier type, rejected
    /// regardless of `log_verifier`.
    /// Before R2, TNG treated `type_ == "other"` as `ev_present=false`; paired
    /// with an absent `log_verifier` (`lv_present=false`) this collapsed into
    /// the both-absent branch → built-in publisher key fallback → DSSE would
    /// verify against the built-in key (the fixture's signature is signed by
    /// it) and the resolve would SUCCEED — a wrong-type verifier silently
    /// bypassed. After R2 the wrong-type check fires first → reject (false).
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_false_on_wrong_type_entry_verifier_with_absent_log_verifier() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, log_entry, entry_url) = cmaas_resolve_triple();
        // entry_verifier carries an unsupported type ("other"); log_verifier is
        // absent (empty pem). The fixture's DSSE signature is signed by the
        // built-in publisher key, so without the wrong-type guard the
        // both-absent fallback would verify DSSE and return true (bug). The
        // guard must reject before the fallback.
        let body = serde_json::json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": [{
                "type": "rekor-v1",
                "url": entry_url,
                "log_entry": log_entry,
                "entry_verifier": {"type": "other", "content": ""},
                "log_verifier": {"public_key_pem": ""}
            }]
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
        assert_eq!(
            result.unwrap(),
            regorus::Value::from("fail"),
            "present-but-wrong-type entry_verifier must reject even when log_verifier is absent"
        );
    }

    /// Lines 436-443 (baseline-compare + warn): the response supplies the
    /// Sigstore rekor key, but the entry URL is `https://rekor.openanolis.cn`
    /// (whose built-in key is the OpenAnolis key). The entry authenticates
    /// with the Sigstore key (its logID matches), but the baseline compare
    /// finds `sigstore.spki != openanolis.spki` → `tracing::warn!`. The path
    /// still succeeds → `Ok(Bool(true))`.
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_artifact_server_warns_on_baseline_key_mismatch() {
        invalidate_host_await_caches_for_test();
        let server = MockServer::start().await;
        let (manifest, log_entry, _entry_url) = cmaas_resolve_triple();
        // Use the OpenAnolis URL so the built-in baseline key differs from
        // the response-supplied Sigstore key.
        let openanolis_url = "https://rekor.openanolis.cn";
        let body = resolve_response_body(
            &manifest,
            &log_entry,
            openanolis_url,
            DSSE_PUBLISHER_PUB_KEY_PEM,
            SIGSTORE_REKOR_V1_PUB_KEY_PEM,
        );
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;

        let hv = resolve_artifact_server_host_await();
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let ls = format!(r#"[{{"type":"rekor-v1","url":"{openanolis_url}"}}]"#);
        let arg = regorus::Value::from(vec![
            regorus::Value::from(server.uri().as_str()),
            regorus::Value::from(manifest_json.as_str()),
            regorus::Value::from(ls.as_str()),
        ]);
        let r = invoke_extension(&hv, arg).await;
        assert_eq!(r, regorus::Value::from("ok"));
    }
}
