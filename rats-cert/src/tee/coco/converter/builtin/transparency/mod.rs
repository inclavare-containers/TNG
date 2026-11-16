//! Transparency-log authentication.
//!
//! One seam, [`authenticate`], serves all three callers: the rekor-v1 primary
//! at policy-load time (which bakes the authenticated entry into Rego), the
//! artifact-server resolve at appraisal time, and the rekor on-demand fallback.
//! The two adapters behind it are [`rekor_v1::authenticate`] and
//! [`artifact_server::authenticate`].

pub(crate) mod artifact_server;
pub(crate) mod cache;
pub(crate) mod dsse;
pub(crate) mod key_table;
pub(crate) mod rekor_v1;

pub use cache::TransparencyCaches;

use super::policy_config::TransparencyServiceConfig;

/// The authenticated data a rekor-direct entry contributes to a policy: the
/// trusted `payloadHash`, the in-band DSSE signature, and the effective
/// publisher key the signature is verified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedRekor {
    pub(crate) payload_hash: String,
    pub(crate) dsse_signature: String,
    pub(crate) publisher_key: String,
}

/// The outcome of authenticating one log service.
#[derive(Debug)]
pub(crate) enum Authentication {
    /// A rekor-direct entry authenticated without a bound manifest (policy
    /// load). The trusted payload hash and signature are baked into Rego and
    /// bound to the manifest at appraisal time.
    Rekor(AuthenticatedRekor),
    /// A bound manifest authenticated.
    Verified,
    /// The artifact server explicitly revoked the measurement.
    Revoked,
}

/// Authenticate a log service, optionally binding the result to `manifest`.
///
/// `manifest` is `None` only for the policy-load rekor path: there is no
/// manifest yet, so the adapter returns the authenticated entry for the Rego
/// bake and the binding happens at appraisal time. An artifact-server primary
/// does no I/O at load; it resolves at appraisal, so a `None` manifest returns
/// `Verified` without touching the network.
pub(crate) async fn authenticate(
    manifest: Option<&serde_json::Value>,
    service: &TransparencyServiceConfig,
    caches: &TransparencyCaches,
) -> anyhow::Result<Authentication> {
    match service {
        TransparencyServiceConfig::RekorV1 { .. } => {
            rekor_v1::authenticate(manifest, service, caches).await
        }
        TransparencyServiceConfig::ArtifactServer { .. } => match manifest {
            // The artifact-server primary resolves at appraisal time.
            None => Ok(Authentication::Verified),
            Some(manifest) => artifact_server::authenticate(manifest, service, caches).await,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::coco::converter::builtin::policies::test_support::{
        cmaas_transparency_tuple, rekor_entries_body, resolve_response_body,
        DSSE_PUBLISHER_PUB_KEY_PEM, SIGSTORE_REKOR_V1_PUB_KEY_PEM,
    };
    use crate::tee::coco::converter::builtin::policy_config::{
        ArtifactLogService, TransparencyServiceConfig,
    };
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn rekor_service(
        log_url: &str,
        log_index: i64,
        rekor_public_key_pem: Option<&str>,
        publisher_public_key_pem: Option<&str>,
    ) -> TransparencyServiceConfig {
        TransparencyServiceConfig::RekorV1 {
            log_url: log_url.to_string(),
            log_index,
            rekor_public_key_pem: rekor_public_key_pem.map(str::to_string),
            publisher_public_key_pem: publisher_public_key_pem.map(str::to_string),
        }
    }

    fn artifact_service(
        url: &str,
        log_services: Vec<ArtifactLogService>,
        publisher_public_key_pem: Option<&str>,
    ) -> TransparencyServiceConfig {
        TransparencyServiceConfig::ArtifactServer {
            url: url.to_string(),
            log_services,
            publisher_public_key_pem: publisher_public_key_pem.map(str::to_string),
        }
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

    /// A rekor-direct entry authenticates without a manifest and returns the
    /// trusted payload hash plus the in-band DSSE signature for the Rego bake.
    #[tokio::test]
    async fn rekor_load_time_returns_the_authenticated_entry() {
        let (_manifest, log_entry, _entry_url, log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let _mock = mount_rekor(&server, log_index, rekor_entries_body(&log_entry)).await;

        let service = rekor_service(
            &server.uri(),
            log_index,
            Some(SIGSTORE_REKOR_V1_PUB_KEY_PEM),
            None,
        );
        let outcome = authenticate(None, &service, &TransparencyCaches::new())
            .await
            .expect("load-time authentication");
        let Authentication::Rekor(entry) = outcome else {
            panic!("expected the authenticated rekor entry, got {outcome:?}");
        };
        assert_eq!(
            entry.payload_hash,
            "b40611d4faa5c667f125fe2b9f52a9ef40171ff63b775a95d08b126fba640564"
        );
        assert!(!entry.dsse_signature.is_empty());
        assert_eq!(entry.publisher_key, dsse::BUILTIN_LOG_ENTRY_PUB_KEY_PEM);
    }

    /// A wrong explicit rekor key fails the logID check.
    #[tokio::test]
    async fn rekor_load_time_rejects_a_wrong_rekor_key() {
        let (_manifest, log_entry, _entry_url, log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let _mock = mount_rekor(&server, log_index, rekor_entries_body(&log_entry)).await;

        // The built-in publisher key is a valid P-256 key, but its SPKI hash
        // is not the fixture entry's logID.
        let service = rekor_service(
            &server.uri(),
            log_index,
            Some(DSSE_PUBLISHER_PUB_KEY_PEM),
            None,
        );
        let err = authenticate(None, &service, &TransparencyCaches::new())
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

        let service = rekor_service(&server.uri(), log_index, None, None);
        let outcome = authenticate(Some(&manifest), &service, &TransparencyCaches::new())
            .await
            .expect("bound rekor authentication");
        assert!(matches!(outcome, Authentication::Verified), "{outcome:?}");
    }

    /// The publisher signature must verify against the configured key, so a
    /// different valid P-256 key rejects even when the payloadHash matches.
    #[tokio::test]
    async fn rekor_bound_manifest_rejects_a_wrong_publisher_key() {
        let (manifest, log_entry, _entry_url, log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let _mock = mount_rekor(&server, log_index, rekor_entries_body(&log_entry)).await;

        let service = rekor_service(
            &server.uri(),
            log_index,
            None,
            Some(SIGSTORE_REKOR_V1_PUB_KEY_PEM),
        );
        let err = authenticate(Some(&manifest), &service, &TransparencyCaches::new())
            .await
            .expect_err("a wrong publisher key must fail");
        assert!(
            format!("{err:#}").contains("DSSE publisher signature verification failed"),
            "{err:#}"
        );
    }

    /// The artifact-server adapter authenticates every returned entry.
    #[tokio::test]
    async fn artifact_server_resolve_verifies() {
        let (manifest, log_entry, entry_url, _log_index) = cmaas_transparency_tuple();
        let server = MockServer::start().await;
        let body = resolve_response_body(&manifest, &log_entry, &entry_url);
        let _mock = mount_resolve(&server, ResponseTemplate::new(200).set_body_string(body)).await;

        let service = artifact_service(&server.uri(), vec![log_service(&entry_url)], None);
        let outcome = authenticate(Some(&manifest), &service, &TransparencyCaches::new())
            .await
            .expect("artifact-server authentication");
        assert!(matches!(outcome, Authentication::Verified), "{outcome:?}");
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
        let outcome = authenticate(Some(&manifest), &service, &TransparencyCaches::new())
            .await
            .expect("a revocation is not an error");
        assert!(matches!(outcome, Authentication::Revoked), "{outcome:?}");
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
            authenticate(Some(&manifest), &service, &TransparencyCaches::new())
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
        let err = authenticate(Some(&manifest), &service, &TransparencyCaches::new())
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
        let err = authenticate(Some(&manifest), &service, &TransparencyCaches::new())
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
        let err = authenticate(Some(&manifest), &service, &TransparencyCaches::new())
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
        let err = authenticate(Some(&manifest), &service, &TransparencyCaches::new())
            .await
            .expect_err("an unrequested log entry must fail");
        assert!(
            err.to_string()
                .contains("unrequested or duplicate log entry"),
            "{err}"
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
            let outcome = authenticate(Some(&manifest), &service, &caches)
                .await
                .expect("resolve authentication");
            assert!(matches!(outcome, Authentication::Verified), "{outcome:?}");
        }
        drop(mock);
        server.verify().await;
    }

    /// The artifact-server primary does no I/O at policy load.
    #[tokio::test]
    async fn artifact_server_load_time_is_deferred() {
        let service = artifact_service(
            "http://127.0.0.1:1",
            vec![log_service("https://rekor.sigstore.dev")],
            None,
        );
        let outcome = authenticate(None, &service, &TransparencyCaches::new())
            .await
            .expect("artifact-server load is deferred");
        assert!(matches!(outcome, Authentication::Verified), "{outcome:?}");
    }
}
