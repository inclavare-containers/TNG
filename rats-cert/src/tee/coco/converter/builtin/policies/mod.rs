//! Policy dispatch for the builtin converter.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;

use super::policy_config::PolicyConfig;
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
        PolicyConfig::Modules { modules } => Ok(modules::build_modules_policy(modules).await?),
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
                "type": "modules",
                "modules": [{
                    "type": "transparency_log",
                    "value": {
                        "publishedMeasurements": ["container.image.cmaas-runtime"],
                        "schemaVersion": "1.0.0",
                        "services": [{
                            "type": "artifact-server",
                            "url": "https://attest.example.com",
                            "logServices": [{"type": "rekor-v1", "url": "https://rekor.sigstore.dev"}]
                        }]
                    }
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
