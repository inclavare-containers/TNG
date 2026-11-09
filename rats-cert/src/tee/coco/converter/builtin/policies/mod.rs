//! Policy dispatch for the builtin converter.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;

#[cfg(feature = "crypto-rustcrypto")]
use self::transparency_log::build_artifact_server_policy;
#[cfg(feature = "crypto-rustcrypto")]
use self::transparency_log::build_transparency_log_policy;
#[cfg(feature = "crypto-rustcrypto")]
use super::host_fns::resolve_dsse_signature;
use super::policy_config::PolicyConfig;
#[cfg(feature = "crypto-rustcrypto")]
use super::policy_config::TransparencyServiceConfig;
use crate::errors::*;

pub(crate) mod modules;
pub(crate) mod transparency_log;

/// Render the Rego source a builtin AS loads for `policy`.
///
/// This is the single `PolicyConfig`-to-Rego implementation. The tunnel's
/// `load_policy` base64-encodes the result and `tng tools policy export` writes
/// it verbatim.
pub async fn render_policy_source(policy: &PolicyConfig) -> Result<String> {
    match policy {
        PolicyConfig::HardwareOnly => Ok(include_str!("static/hardware_only.rego").to_string()),
        PolicyConfig::HardwareOnlyStrict => {
            Ok(include_str!("static/hardware_only_strict.rego").to_string())
        }
        PolicyConfig::TrustAll => Ok(include_str!("static/trust_all.rego").to_string()),
        // Fetch + authenticate the Rekor v1 entry by logIndex, then bake
        // the trusted payloadHash into Rego. The cryptography (P-256 ECDSA
        // SET verification + SHA-256 Merkle inclusion proof) lives behind
        // the `crypto-rustcrypto` feature; the arm is gated the same way so
        // a non-crypto build still compiles (and bails there instead).
        #[cfg(feature = "crypto-rustcrypto")]
        PolicyConfig::TransparencyLog {
            published_measurements,
            schema_version,
            services,
            fallback_published_measurements,
            fallback_services,
            static_reference_measurements,
        } => {
            // Validate the full config shape BEFORE dispatching on the
            // primary service type. This turns every operator-supplied config
            // violation (empty/missing fields, artifact-server-not-sole-primary,
            // fallback-requires-artifact-server-primary, non-rekor-v1 in
            // fallbackServices, fallbackPublishedMeasurements-not-subset,
            // duplicate logServices, etc.) into a clean `Err` at load time
            // rather than a process panic (e.g. `unreachable!` / `fs[0]` in
            // `build_artifact_server_policy`) downstream.
            policy
                .validate_transparency_config()
                .map_err(Error::TransparencyLogFetchFailed)?;
            // Dispatch on the primary service type. `RekorV1` keeps the
            // existing init-bake path verbatim (fetch + bake payloadHash);
            // `ArtifactServer` generates Rego that resolves the
            // manifest at appraisal time via `tng.resolve_artifact_server`
            // (with an optional `tng.fetch_rekor_on_demand` fallback) and
            // bakes NO payloadHash.
            let primary = services.first().ok_or_else(|| {
                Error::TransparencyLogFetchFailed(anyhow::anyhow!(
                    "transparency_log services must be non-empty"
                ))
            })?;
            match primary {
                TransparencyServiceConfig::RekorV1 { .. } => {
                    // EXISTING init-bake path, unchanged (fetch the rekor-v1
                    // entry by logIndex, authenticate it, bake the trusted
                    // payloadHash into Rego). The artifact-server primary path is a
                    // separate arm below; this stays verbatim for rekor-v1.
                    let svc = match services.as_slice() {
                        [TransparencyServiceConfig::RekorV1 {
                            log_url,
                            log_index,
                            rekor_public_key_pem,
                            publisher_public_key_pem,
                        }] => (
                            log_url.as_str(),
                            *log_index,
                            rekor_public_key_pem.as_deref(),
                            publisher_public_key_pem.as_deref(),
                        ),
                        _ => {
                            return Err(Error::TransparencyLogFetchFailed(anyhow::anyhow!(
                                "transparency_log policy requires exactly one rekor-v1 service"
                            )))
                        }
                    };
                    let (log_url, log_index, rekor_public_key_pem, publisher_public_key_pem) = svc;
                    tracing::info!(
                        log_url,
                        log_index,
                        "Loading transparency_log policy: fetching Rekor v1 entry"
                    );
                    let auth = transparency_log::rekor_v1::fetch_trusted_payload_hash(
                        log_url,
                        log_index,
                        rekor_public_key_pem,
                    )
                    .await
                    .map_err(Error::TransparencyLogFetchFailed)?;
                    // DSSE publisher-signature verification is mandatory:
                    // resolve the publisher key unconditionally — the
                    // configured `publisherPublicKeyPem`, or the built-in
                    // publisher key baseline when none is set — and always
                    // bake both the DSSE signature and the publisher key so
                    // the generated Rego emits the
                    // `tng.verify_dsse_signature` line. An empty
                    // `dsse_signature` means a malformed/non-dsse entry →
                    // fail closed. This mirrors
                    // `build_artifact_server_policy`'s approach (the
                    // publisher key literal is the configured value or
                    // empty→built-in).
                    let publisher_key = publisher_public_key_pem
                        .filter(|s| !s.is_empty())
                        .unwrap_or(
                            transparency_log::artifact_server::BUILTIN_LOG_ENTRY_PUB_KEY_PEM,
                        );
                    let dsse_signature = resolve_dsse_signature(&auth.dsse_signature)
                        .map_err(Error::TransparencyLogFetchFailed)?;
                    let policy = transparency_log::build_transparency_log_policy(
                        &auth.payload_hash,
                        schema_version,
                        published_measurements.as_deref(),
                        dsse_signature,
                        publisher_key,
                        static_reference_measurements.as_deref(),
                    );
                    tracing::info!(payload_hash = %auth.payload_hash, policy = %policy, "Transparency_log policy loaded: baking payloadHash + DSSE into Rego");
                    Ok(policy)
                }
                TransparencyServiceConfig::ArtifactServer {
                    url,
                    log_services,
                    publisher_public_key_pem,
                } => {
                    tracing::info!(
                        artifact_server_url = %url,
                        "Loading transparency_log policy: generating artifact-server-primary Rego"
                    );
                    let policy = transparency_log::build_artifact_server_policy(
                        schema_version,
                        published_measurements.as_deref(),
                        url,
                        log_services,
                        publisher_public_key_pem.as_deref(),
                        fallback_published_measurements.as_deref(),
                        fallback_services.as_deref(),
                        static_reference_measurements.as_deref(),
                    )?;
                    tracing::info!(policy = %policy, "Transparency_log policy loaded: artifact-server primary, no baked payloadHash");
                    Ok(policy)
                }
            }
        }
        #[cfg(not(feature = "crypto-rustcrypto"))]
        PolicyConfig::TransparencyLog { .. } => {
            Err(Error::TransparencyLogPolicyRequiresCryptoRustcrypto)
        }
        PolicyConfig::Modules { modules } => Ok(modules::build_modules_policy(modules)?),
        PolicyConfig::Inline { content } => {
            let decoded = BASE64_STANDARD
                .decode(content)
                .map_err(Error::DecodePolicyContentFailed)?;
            String::from_utf8(decoded).map_err(|e| {
                Error::BuiltinPolicyTemplateFailed(anyhow::anyhow!(
                    "inline policy is not UTF-8: {e}"
                ))
            })
        }
        #[cfg(not(wasm))]
        PolicyConfig::Path { path } => {
            let content_str =
                tokio::fs::read_to_string(path)
                    .await
                    .map_err(|e| Error::ReadPolicyFileFailed {
                        path: path.clone(),
                        source: e,
                    })?;
            Ok(content_str)
        }
    }
}

/// Load policy from configuration
/// Returns a URL-safe base64 encoding of the policy source.
pub(super) async fn load_policy(policy: &PolicyConfig) -> Result<Option<String>> {
    Ok(Some(
        URL_SAFE_NO_PAD.encode(render_policy_source(policy).await?),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::policy_config::{ModuleEntryConfig, ModuleGroupsConfig};
    use super::*;

    #[tokio::test]
    async fn test_load_inline_policy() {
        // Base64 encoded policy with EAR claims
        let policy_content = r#"package policy

default executables := 3
default hardware := 2
default configuration := 2
default file_system := 2"#;
        let policy_b64 = base64::engine::general_purpose::STANDARD.encode(policy_content);
        let policy_config = PolicyConfig::Inline {
            content: policy_b64,
        };

        let result = load_policy(&policy_config).await;
        assert!(result.is_ok());
        let encoded_content = result
            .unwrap()
            .expect("Should return Some for Inline policy");
        // Decode the URL_SAFE_NO_PAD encoded content to verify
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded_content)
            .expect("Failed to decode policy");
        let content = String::from_utf8(decoded).expect("Invalid UTF-8");
        assert!(content.contains("package policy"));
        assert!(content.contains("default executables"));
    }

    #[tokio::test]
    async fn test_load_hardware_only_policy() {
        let policy_config = PolicyConfig::HardwareOnly;
        let result = load_policy(&policy_config).await;
        assert!(result.is_ok());
        let encoded = result
            .unwrap()
            .expect("Should return Some for HardwareOnly policy");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("Failed to decode policy");
        let content = String::from_utf8(decoded).expect("Invalid UTF-8");
        assert!(content.contains("package policy"));
        assert!(content.contains("default hardware := 97"));
        assert!(content.contains("input.tdx.quote.header.tee_type"));
        assert!(content.contains(r#"vendor_id == "939a7233f79c4ca9940a0db3957f0607""#));
    }

    #[tokio::test]
    async fn test_load_hardware_only_strict_policy() {
        let policy_config = PolicyConfig::HardwareOnlyStrict;
        let result = load_policy(&policy_config).await;
        assert!(result.is_ok());
        let encoded = result
            .unwrap()
            .expect("Should return Some for HardwareOnlyStrict policy");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("Failed to decode policy");
        let content = String::from_utf8(decoded).expect("Invalid UTF-8");
        assert!(content.contains("package policy"));
        assert!(content.contains("tdx_debug_disabled"));
        assert!(content.contains("tdx_eventlog_present"));
    }

    #[tokio::test]
    async fn test_load_modules_policy() {
        let policy_config = PolicyConfig::Modules {
            modules: ModuleGroupsConfig::Single(vec![ModuleEntryConfig {
                module_type: "tdx".to_string(),
                value: serde_json::json!({}),
            }]),
        };
        let result = load_policy(&policy_config).await;
        assert!(result.is_ok());
        let encoded = result
            .unwrap()
            .expect("Should return Some for Modules policy");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("Failed to decode policy");
        let content = String::from_utf8(decoded).expect("Invalid UTF-8");
        assert!(content.contains("package policy"));
        assert!(content.contains("default hardware := 97"));
        assert!(content.contains("tdx_recognized if {"));
        assert!(!content.contains("input.csv"));
        assert!(!content.contains("input.tpm"));
        assert!(!content.contains("input.system"));
    }

    #[tokio::test]
    async fn test_load_trust_all_policy() {
        let policy_config = PolicyConfig::TrustAll;
        let result = load_policy(&policy_config).await;
        assert!(result.is_ok());
        let encoded = result
            .unwrap()
            .expect("Should return Some for TrustAll policy");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("Failed to decode policy");
        let content = String::from_utf8(decoded).expect("Invalid UTF-8");
        assert!(content.contains("package policy"));
        assert!(content.contains("default hardware := 2"));
    }

    #[tokio::test]
    async fn load_policy_is_base64_of_render_policy_source() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.rego");
        std::fs::write(&path, "package policy\n").expect("write policy file");

        let mut cases = vec![
            PolicyConfig::HardwareOnly,
            PolicyConfig::HardwareOnlyStrict,
            PolicyConfig::TrustAll,
            PolicyConfig::Modules {
                modules: ModuleGroupsConfig::Single(vec![]),
            },
            PolicyConfig::Inline {
                content: BASE64_STANDARD.encode("package policy\n"),
            },
        ];
        #[cfg(not(wasm))]
        cases.push(PolicyConfig::Path {
            path: path.to_string_lossy().into_owned(),
        });
        #[cfg(feature = "crypto-rustcrypto")]
        cases.push(
            serde_json::from_value(serde_json::json!({
                "type": "transparency_log",
                "publishedMeasurements": ["container.image.cmaas-runtime"],
                "schemaVersion": "1.0.0",
                "services": [{
                    "type": "artifact-server",
                    "url": "https://attest.example.com",
                    "logServices": [{"type": "rekor-v1", "url": "https://rekor.sigstore.dev"}]
                }]
            }))
            .expect("artifact-server policy config"),
        );

        for policy in cases {
            let source = render_policy_source(&policy).await.expect("render source");
            let loaded = load_policy(&policy)
                .await
                .expect("load policy")
                .expect("every current variant yields a policy");
            assert_eq!(
                URL_SAFE_NO_PAD.encode(source.as_bytes()),
                loaded,
                "policy {policy:?}"
            );
        }
    }

    #[tokio::test]
    async fn inline_policy_must_be_utf8() {
        let policy = PolicyConfig::Inline {
            content: BASE64_STANDARD.encode([0xff, 0xfe]),
        };
        let err = render_policy_source(&policy)
            .await
            .expect_err("non-UTF-8 inline policy must fail");
        assert!(err.to_string().contains("UTF-8"), "{err}");
    }
}
