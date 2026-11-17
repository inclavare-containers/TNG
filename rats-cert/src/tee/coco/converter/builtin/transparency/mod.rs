//! Transparency-log verification.
//!
//! Two seams serve the three callers. [`load_rekor_baseline`] is the policy-load
//! path for a rekor-v1 primary, which bakes the verified entry into Rego.
//! [`verify_manifest`] is the appraisal path for the artifact-server resolve and
//! the rekor on-demand fallback. The adapters behind them are
//! [`rekor_v1::load_baseline`], [`rekor_v1::verify_manifest`], and
//! [`artifact_server::verify_manifest`].

pub(crate) mod artifact_server;
pub(crate) mod cache;
pub(crate) mod dsse;
pub(crate) mod rekor_keys;
pub(crate) mod rekor_v1;

pub use cache::TransparencyCaches;
pub(crate) use rekor_v1::VerifiedRekorEntry;

use super::policy_config::{ArtifactServerService, RekorV1Service, TransparencyServiceConfig};

/// The verified baseline a rekor-direct entry contributes to a policy: the
/// trusted entry data plus the effective publisher key its signature is
/// verified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RekorBaseline {
    pub(crate) entry: VerifiedRekorEntry,
    pub(crate) publisher_key: String,
}

/// The result of verifying a bound manifest against one log service.
#[derive(Debug)]
pub(crate) enum VerifyOutcome {
    /// The manifest verified against the log.
    Verified,
    /// The artifact server explicitly revoked the measurement.
    Revoked,
}

/// Load the baseline a rekor-v1 primary bakes into Rego at policy-load time.
///
/// Only a rekor-v1 service has a load-time baseline. An artifact-server primary
/// resolves at appraisal time and must not reach this call. The entry is
/// deliberately not cached: a load re-authenticates against the configured key,
/// so a cached success from a different key configuration cannot satisfy it.
pub(crate) async fn load_rekor_baseline(service: &RekorV1Service) -> anyhow::Result<RekorBaseline> {
    rekor_v1::load_baseline(service).await
}

/// Verify a bound manifest against a transparency-log service.
///
/// A rekor-v1 service fetches (or reuses a cached) entry and binds it to the
/// manifest; an artifact-server service resolves the measurement at appraisal
/// time. An explicit revocation is reported as [`VerifyOutcome::Revoked`] and
/// never cached; ordinary failures are `Err`.
pub(crate) async fn verify_manifest(
    manifest: &serde_json::Value,
    service: &TransparencyServiceConfig,
    caches: &TransparencyCaches,
) -> anyhow::Result<VerifyOutcome> {
    match service {
        TransparencyServiceConfig::RekorV1(service) => {
            rekor_v1::verify_manifest(manifest, service, caches).await
        }
        TransparencyServiceConfig::ArtifactServer(service) => {
            artifact_server::verify_manifest(manifest, service, caches).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::coco::converter::builtin::policy_config::{
        ArtifactLogService, TransparencyServiceConfig,
    };
    use crate::tee::coco::converter::builtin::test_fixtures::{
        cmaas_transparency_tuple, rekor_entries_body, resolve_response_body,
        DSSE_PUBLISHER_PUB_KEY_PEM, SIGSTORE_REKOR_V1_PUB_KEY_PEM,
    };
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn rekor_service(
        log_url: &str,
        log_index: i64,
        rekor_public_key_pem: Option<&str>,
        publisher_public_key_pem: Option<&str>,
    ) -> RekorV1Service {
        RekorV1Service {
            log_url: log_url.to_string(),
            log_index,
            rekor_public_key_pem: rekor_public_key_pem.map(str::to_string),
            publisher_public_key_pem: publisher_public_key_pem.map(str::to_string),
        }
    }

    fn rekor_config(
        log_url: &str,
        log_index: i64,
        rekor_public_key_pem: Option<&str>,
        publisher_public_key_pem: Option<&str>,
    ) -> TransparencyServiceConfig {
        TransparencyServiceConfig::RekorV1(rekor_service(
            log_url,
            log_index,
            rekor_public_key_pem,
            publisher_public_key_pem,
        ))
    }

    fn artifact_service(
        url: &str,
        log_services: Vec<ArtifactLogService>,
        publisher_public_key_pem: Option<&str>,
    ) -> TransparencyServiceConfig {
        TransparencyServiceConfig::ArtifactServer(ArtifactServerService {
            url: url.to_string(),
            log_services,
            publisher_public_key_pem: publisher_public_key_pem.map(str::to_string),
        })
    }

    fn log_service(url: &str) -> ArtifactLogService {
        ArtifactLogService {
            type_: "rekor-v1".to_string(),
            url: url.to_string(),
        }
    }

    async fn mount_rekor(server: &MockServer, log_index: i64, body: String) -> wiremock::MockGuard {
        Mock::given(method("GET"))
            .and(path("/api/v1/log/entries"))
            .and(query_param("logIndex", log_index.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount_as_scoped(server)
            .await
    }

    async fn mount_resolve(server: &MockServer, response: ResponseTemplate) -> wiremock::MockGuard {
        Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(response)
            .mount_as_scoped(server)
            .await
    }

    /// A rekor-direct entry verifies without a manifest and returns the
    /// trusted payload hash plus the in-band DSSE signature for the Rego bake.
    #[tokio::test]
    async fn rekor_load_time_returns_the_verified_entry() {
        let (_manifest, log_entry, _entry_url, log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let _mock = mount_rekor(&server, log_index, rekor_entries_body(&log_entry)).await;

        let service = rekor_service(
            &server.uri(),
            log_index,
            Some(SIGSTORE_REKOR_V1_PUB_KEY_PEM),
            Some(DSSE_PUBLISHER_PUB_KEY_PEM),
        );
        let outcome = load_rekor_baseline(&service)
            .await
            .expect("load-time verification");
        assert_eq!(
            outcome.entry.payload_hash,
            "b40611d4faa5c667f125fe2b9f52a9ef40171ff63b775a95d08b126fba640564"
        );
        assert!(!outcome.entry.dsse_signature.is_empty());
        assert_eq!(outcome.publisher_key, DSSE_PUBLISHER_PUB_KEY_PEM);
    }

    /// A rekor-v1 service carries no verifier keys, so a missing publisher key
    /// fails before the network fetch; there is no built-in fallback.
    #[tokio::test]
    async fn rekor_load_time_requires_a_publisher_key() {
        // The URL is a dead port: if the key check did not fire first, the
        // failure would be a connection error instead of the key error.
        let service = rekor_service("http://127.0.0.1:1", 1, None, None);
        let err = load_rekor_baseline(&service)
            .await
            .expect_err("a missing publisher key must fail");
        assert!(
            format!("{err:#}").contains("publisherPublicKeyPem"),
            "{err:#}"
        );

        let service = rekor_service("http://127.0.0.1:1", 1, None, Some(""));
        let err = load_rekor_baseline(&service)
            .await
            .expect_err("an empty publisher key must fail");
        assert!(
            format!("{err:#}").contains("publisherPublicKeyPem"),
            "{err:#}"
        );
    }

    /// A wrong explicit rekor key fails the logID check.
    #[tokio::test]
    async fn rekor_load_time_rejects_a_wrong_rekor_key() {
        let (_manifest, log_entry, _entry_url, log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let _mock = mount_rekor(&server, log_index, rekor_entries_body(&log_entry)).await;

        // The fixture publisher key is a valid P-256 key, but its SPKI hash
        // is not the fixture entry's logID.
        let service = rekor_service(
            &server.uri(),
            log_index,
            Some(DSSE_PUBLISHER_PUB_KEY_PEM),
            Some(DSSE_PUBLISHER_PUB_KEY_PEM),
        );
        let err = load_rekor_baseline(&service)
            .await
            .expect_err("a wrong rekor key must fail");
        assert!(err.to_string().contains("logID mismatch"), "{err}");
    }

    /// A bound manifest authenticates against a rekor-direct entry.
    #[tokio::test]
    async fn rekor_bound_manifest_verifies() {
        let (manifest, log_entry, _entry_url, log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let _mock = mount_rekor(&server, log_index, rekor_entries_body(&log_entry)).await;

        let service = rekor_config(
            &server.uri(),
            log_index,
            None,
            Some(DSSE_PUBLISHER_PUB_KEY_PEM),
        );
        let outcome = verify_manifest(&manifest, &service, &TransparencyCaches::new())
            .await
            .expect("bound rekor authentication");
        assert!(matches!(outcome, VerifyOutcome::Verified), "{outcome:?}");
    }

    /// The publisher signature must verify against the configured key, so a
    /// different valid P-256 key rejects even when the payloadHash matches.
    #[tokio::test]
    async fn rekor_bound_manifest_rejects_a_wrong_publisher_key() {
        let (manifest, log_entry, _entry_url, log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let _mock = mount_rekor(&server, log_index, rekor_entries_body(&log_entry)).await;

        let service = rekor_config(
            &server.uri(),
            log_index,
            None,
            Some(SIGSTORE_REKOR_V1_PUB_KEY_PEM),
        );
        let err = verify_manifest(&manifest, &service, &TransparencyCaches::new())
            .await
            .expect_err("a wrong publisher key must fail");
        assert!(
            format!("{err:#}").contains("DSSE publisher signature verification failed"),
            "{err:#}"
        );
    }

    /// The artifact-server adapter authenticates every returned entry. The
    /// response supplies both verifier keys, so no configured publisher key is
    /// needed.
    #[tokio::test]
    async fn artifact_server_resolve_verifies() {
        let (manifest, log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let body = resolve_response_body(&manifest, &log_entry, &entry_url);
        let _mock = mount_resolve(&server, ResponseTemplate::new(200).set_body_string(body)).await;

        let service = artifact_service(&server.uri(), vec![log_service(&entry_url)], None);
        let outcome = verify_manifest(&manifest, &service, &TransparencyCaches::new())
            .await
            .expect("artifact-server authentication");
        assert!(matches!(outcome, VerifyOutcome::Verified), "{outcome:?}");
    }

    /// An explicit server-side revocation is distinct from an ordinary
    /// failure so the Rego caller can skip the rekor fallback.
    #[tokio::test]
    async fn artifact_server_revocation_is_reported() {
        let (manifest, _log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let body = json!({
            "error_code": "measurement_revoked",
            "error_message": "the measurement was revoked",
            "request_id": "seam-revoked",
        })
        .to_string();
        let _mock = mount_resolve(&server, ResponseTemplate::new(403).set_body_string(body)).await;

        let service = artifact_service(&server.uri(), vec![log_service(&entry_url)], None);
        let outcome = verify_manifest(&manifest, &service, &TransparencyCaches::new())
            .await
            .expect("a revocation is not an error");
        assert!(matches!(outcome, VerifyOutcome::Revoked), "{outcome:?}");
    }

    /// Any other artifact-server failure is an ordinary error.
    #[tokio::test]
    async fn artifact_server_failure_is_an_error() {
        let (manifest, _log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let _mock = mount_resolve(
            &server,
            ResponseTemplate::new(500).set_body_string("upstream error"),
        )
        .await;

        let service = artifact_service(&server.uri(), vec![log_service(&entry_url)], None);
        assert!(
            verify_manifest(&manifest, &service, &TransparencyCaches::new())
                .await
                .is_err(),
            "a server error must be an ordinary failure"
        );
    }

    /// A response that omits both verifiers falls back to the configured
    /// publisher key; a configured key that did not sign the envelope rejects.
    #[tokio::test]
    async fn artifact_server_rejects_a_wrong_configured_publisher_key() {
        let (manifest, log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let body = json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": [{
                "type": "rekor-v1",
                "url": entry_url,
                "log_entry": log_entry,
                "entry_verifier": {"type": "", "content": ""},
                "log_verifier": {"public_key_pem": ""},
            }],
        })
        .to_string();
        let _mock = mount_resolve(&server, ResponseTemplate::new(200).set_body_string(body)).await;

        let service = artifact_service(
            &server.uri(),
            vec![log_service(&entry_url)],
            Some(SIGSTORE_REKOR_V1_PUB_KEY_PEM),
        );
        let err = verify_manifest(&manifest, &service, &TransparencyCaches::new())
            .await
            .expect_err("a wrong configured publisher key must fail");
        assert!(
            format!("{err:#}").contains("DSSE publisher signature verification failed"),
            "{err:#}"
        );
    }

    /// Every requested log service must be covered exactly once.
    #[tokio::test]
    async fn artifact_server_rejects_a_missing_log_entry() {
        let (manifest, log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let body = resolve_response_body(&manifest, &log_entry, &entry_url);
        let _mock = mount_resolve(&server, ResponseTemplate::new(200).set_body_string(body)).await;

        let service = artifact_service(
            &server.uri(),
            vec![
                log_service(&entry_url),
                log_service("https://rekor.openanolis.cn"),
            ],
            None,
        );
        let err = verify_manifest(&manifest, &service, &TransparencyCaches::new())
            .await
            .expect_err("a missing requested log entry must fail");
        assert!(
            err.to_string().contains("did not cover all requested"),
            "{err}"
        );
    }

    /// A duplicate entry is rejected: it does not match a distinct requested
    /// service.
    #[tokio::test]
    async fn artifact_server_rejects_a_duplicate_log_entry() {
        let (manifest, log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let entry = json!({
            "type": "rekor-v1",
            "url": entry_url,
            "log_entry": log_entry,
            "entry_verifier": {"type": "public_key", "content": DSSE_PUBLISHER_PUB_KEY_PEM},
            "log_verifier": {"public_key_pem": SIGSTORE_REKOR_V1_PUB_KEY_PEM},
        });
        let body = json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": [entry.clone(), entry],
        })
        .to_string();
        let _mock = mount_resolve(&server, ResponseTemplate::new(200).set_body_string(body)).await;

        let service = artifact_service(&server.uri(), vec![log_service(&entry_url)], None);
        let err = verify_manifest(&manifest, &service, &TransparencyCaches::new())
            .await
            .expect_err("a duplicate log entry must fail");
        assert!(
            err.to_string()
                .contains("unrequested or duplicate log entry"),
            "{err}"
        );
    }

    /// An entry for an unrequested log service is rejected.
    #[tokio::test]
    async fn artifact_server_rejects_an_unrequested_log_entry() {
        let (manifest, log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let body = resolve_response_body(&manifest, &log_entry, entry_url.as_str());
        let _mock = mount_resolve(&server, ResponseTemplate::new(200).set_body_string(body)).await;

        let service = artifact_service(
            &server.uri(),
            vec![log_service("https://rekor.openanolis.cn")],
            None,
        );
        let err = verify_manifest(&manifest, &service, &TransparencyCaches::new())
            .await
            .expect_err("an unrequested log entry must fail");
        assert!(
            err.to_string()
                .contains("unrequested or duplicate log entry"),
            "{err}"
        );
    }

    /// A response that omits both verifiers leaves the configured publisher
    /// key as the only trust anchor. With no configured key there is no
    /// built-in fallback, so the resolve is an ordinary error.
    #[tokio::test]
    async fn artifact_server_requires_a_publisher_key_when_verifiers_are_absent() {
        let (manifest, log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let body = json!({
            "status": "resolved",
            "release_manifest": manifest,
            "log_entries": [{
                "type": "rekor-v1",
                "url": entry_url,
                "log_entry": log_entry,
                "entry_verifier": {"type": "", "content": ""},
                "log_verifier": {"public_key_pem": ""},
            }],
        })
        .to_string();
        let _mock = mount_resolve(&server, ResponseTemplate::new(200).set_body_string(body)).await;

        let service = artifact_service(&server.uri(), vec![log_service(&entry_url)], None);
        let err = verify_manifest(&manifest, &service, &TransparencyCaches::new())
            .await
            .expect_err("no configured key and no response verifiers must fail");
        assert!(
            format!("{err:#}").contains("publisherPublicKeyPem"),
            "{err:#}"
        );
    }

    /// The resolve cache key includes the publisher key identity, so a success
    /// cached under one configured key does not satisfy a policy that differs
    /// only in `publisherPublicKeyPem`.
    #[tokio::test]
    async fn resolve_cache_key_includes_the_publisher_key() {
        let (manifest, log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let body = resolve_response_body(&manifest, &log_entry, &entry_url);
        let mock = Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(2) // both calls must reach the server: the keys differ
            .mount_as_scoped(&server)
            .await;

        let caches = TransparencyCaches::new();
        for publisher in [DSSE_PUBLISHER_PUB_KEY_PEM, SIGSTORE_REKOR_V1_PUB_KEY_PEM] {
            let service = artifact_service(
                &server.uri(),
                vec![log_service(&entry_url)],
                Some(publisher),
            );
            let outcome = verify_manifest(&manifest, &service, &caches)
                .await
                .expect("resolve authentication");
            assert!(matches!(outcome, VerifyOutcome::Verified), "{outcome:?}");
        }
        drop(mock);
        server.verify().await;
    }

    /// An unconfigured context and a configured one have distinct cache
    /// identities even when both resolves succeed through the response keys, so
    /// the second call must reach the server instead of reusing the first
    /// success.
    #[tokio::test]
    async fn resolve_cache_does_not_share_between_configured_and_unconfigured() {
        let (manifest, log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        // Both verifiers are present in the response, so both policies verify.
        let body = resolve_response_body(&manifest, &log_entry, &entry_url);
        let mock = Mock::given(method("POST"))
            .and(path("/api/v1/transparency/resolve"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(2) // both calls must reach the server: the key identities differ
            .mount_as_scoped(&server)
            .await;

        let caches = TransparencyCaches::new();
        for publisher in [None, Some(DSSE_PUBLISHER_PUB_KEY_PEM)] {
            let service = artifact_service(&server.uri(), vec![log_service(&entry_url)], publisher);
            let outcome = verify_manifest(&manifest, &service, &caches)
                .await
                .expect("resolve authentication");
            assert!(matches!(outcome, VerifyOutcome::Verified), "{outcome:?}");
        }
        drop(mock);
        server.verify().await;
    }
}
