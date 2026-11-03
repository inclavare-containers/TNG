//! Policy dispatch for the builtin converter.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;

#[cfg(feature = "crypto-rustcrypto")]
use self::transparency_log::build_artifact_server_policy;
#[cfg(feature = "crypto-rustcrypto")]
use self::transparency_log::build_transparency_log_policy;
use self::transparency_log::static_reference_rules;
#[cfg(feature = "crypto-rustcrypto")]
use super::host_fns::resolve_dsse_signature;
use super::policy_config::PolicyConfig;
#[cfg(feature = "crypto-rustcrypto")]
use super::policy_config::TransparencyServiceConfig;
use crate::errors::*;

pub(crate) mod transparency_log;

/// Load policy from configuration
/// Returns None for the AS built-in default policy
/// (HardwareWithReferenceValues), and a URL-safe base64 encoding of the
/// policy source for the tng-bundled templates and the user-supplied
/// Inline/Path variants.
pub(super) async fn load_policy(policy: &PolicyConfig) -> Result<Option<String>> {
    match policy {
        PolicyConfig::HardwareWithReferenceValues => Ok(None),
        PolicyConfig::HardwareStrictWithReferenceValues => Ok(Some(
            URL_SAFE_NO_PAD.encode(build_hardware_strict_with_reference_values_policy()?),
        )),
        PolicyConfig::HardwareOnly => Ok(Some(
            URL_SAFE_NO_PAD.encode(include_str!("static/hardware_only.rego")),
        )),
        PolicyConfig::HardwareOnlyStrict => Ok(Some(
            URL_SAFE_NO_PAD.encode(include_str!("static/hardware_only_strict.rego")),
        )),
        PolicyConfig::TrustAll => Ok(Some(
            URL_SAFE_NO_PAD.encode(include_str!("static/trust_all.rego")),
        )),
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
                    Ok(Some(URL_SAFE_NO_PAD.encode(policy)))
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
                    Ok(Some(URL_SAFE_NO_PAD.encode(policy)))
                }
            }
        }
        #[cfg(not(feature = "crypto-rustcrypto"))]
        PolicyConfig::TransparencyLog { .. } => {
            Err(Error::TransparencyLogPolicyRequiresCryptoRustcrypto)
        }
        PolicyConfig::HardwareStrictWithMeasurements { measurements } => {
            let policy = build_hardware_strict_with_measurements_policy(measurements)?;
            Ok(Some(URL_SAFE_NO_PAD.encode(policy)))
        }
        PolicyConfig::Inline { content } => {
            // Decode base64 encoded policy
            let decoded = BASE64_STANDARD
                .decode(content)
                .map_err(Error::DecodePolicyContentFailed)?;
            Ok(Some(URL_SAFE_NO_PAD.encode(decoded)))
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
            Ok(Some(URL_SAFE_NO_PAD.encode(content_str)))
        }
    }
}

fn build_hardware_strict_with_reference_values_policy() -> Result<String> {
    const TDX_HARDWARE_RULE: &str = r#"hardware := 2 if {
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	# Check TDX Module version and its hash. Also check OVMF code hash.
	# input.tdx.quote.body.mr_seam in query_reference_value("tdx.mr_seam")
	# input.tdx.quote.body.tcb_svn in query_reference_value("tdx.tcb_svn")
	# input.tdx.quote.body.mr_td in query_reference_value("tdx.mr_td")
}"#;
    const TDX_HARDWARE_RULE_STRICT: &str = r#"hardware := 2 if {
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	tdx_debug_disabled
	tdx_eventlog_present
	# Check TDX Module version and its hash. Also check OVMF code hash.
	# input.tdx.quote.body.mr_seam in query_reference_value("tdx.mr_seam")
	# input.tdx.quote.body.tcb_svn in query_reference_value("tdx.tcb_svn")
	# input.tdx.quote.body.mr_td in query_reference_value("tdx.mr_td")
}"#;
    const TDX_STRICT_HELPERS: &str = r#"

# TNG strict TDX hardware predicates. The verifier has already replayed the
# event log against quote RTMRs before these claims reach policy evaluation.
tdx_debug_disabled if {
	regex.match("^[0-9a-f][02468ace]", input.tdx.quote.body.td_attributes)
}

tdx_eventlog_present if {
	count(input.tdx.uefi_event_logs) > 0
}
"#;

    let default_policy = attestation_service::token::ear_broker::DEFAULT_POLICY;
    if !default_policy.contains(TDX_HARDWARE_RULE) {
        return Err(Error::BuiltinPolicyTemplateFailed {
            detail: "TDX hardware rule not found in Trustee default policy".to_string(),
        });
    }

    Ok(
        default_policy.replacen(TDX_HARDWARE_RULE, TDX_HARDWARE_RULE_STRICT, 1)
            + TDX_STRICT_HELPERS,
    )
}

/// Build the `hardware_strict_with_measurements` builtin policy: the
/// `hardware_only_strict` platform posture plus the listed measurements
/// appraised against registered reference values. Without a valid
/// measurement list this is a config error (an empty list would silently
/// degrade to plain `hardware_only_strict`).
fn build_hardware_strict_with_measurements_policy(measurements: &[String]) -> Result<String> {
    if measurements.is_empty() {
        return Err(Error::BuiltinPolicyTemplateFailed {
            detail: "measurements must be non-empty".to_string(),
        });
    }
    let mut seen = std::collections::HashSet::new();
    for t in measurements {
        if !(t == "model" || t.starts_with("container.image.")) {
            return Err(Error::BuiltinPolicyTemplateFailed {
                detail: format!("unsupported measurements type {t}"),
            });
        }
        if !seen.insert(t) {
            return Err(Error::BuiltinPolicyTemplateFailed {
                detail: format!("duplicate measurements type {t}"),
            });
        }
    }

    let static_rules = static_reference_rules(measurements);

    Ok(format!(
        r#"package policy

import rego.v1

# Hardware platform posture from hardware_only_strict (TDX must be non-debug
# with an event log; the verifier has already replayed the event log against
# the quote RTMRs before these claims reach policy evaluation) plus the
# listed measurements: executables affirms only when every configured
# measurement matches its registered reference value.
default executables := 97
default configuration := 2
default file_system := 2
default hardware := 97

hardware := 2 if {{
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	tdx_debug_disabled
	tdx_eventlog_present
}}

hardware := 2 if {{
	input.csv.version in ["1", "2"]
}}

hardware := 2 if {{
	input.tpm
}}

hardware := 2 if {{
	input.system
}}

# td_attributes is serialized as lowercase hex. The debug bit is bit 0 of the
# first byte, so the low nibble of the first byte must be even.
tdx_debug_disabled if {{
	regex.match("^[0-9a-f][02468ace]", input.tdx.quote.body.td_attributes)
}}

tdx_eventlog_present if {{
	count(input.tdx.uefi_event_logs) > 0
}}

{static_rules}
# The measurements are read from the TDX event log, so executables affirms
# only on TDX evidence with every measurement check passing.
executables := 2 if {{
	input.tdx
	static_ok
}}
"#
    ))
}

#[cfg(test)]
mod tests {
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
    async fn test_load_hardware_with_reference_values_policy() {
        // Equivalent to the former Default: falls through to the AS built-in
        // trustee rego, so no inline content is registered.
        let policy_config = PolicyConfig::HardwareWithReferenceValues;
        let result = load_policy(&policy_config).await;
        assert!(result.is_ok());
        assert!(
            result.unwrap().is_none(),
            "HardwareWithReferenceValues policy should return None"
        );
    }

    #[tokio::test]
    async fn test_load_hardware_strict_with_reference_values_policy() {
        let policy_config = PolicyConfig::HardwareStrictWithReferenceValues;
        let result = load_policy(&policy_config).await;
        assert!(result.is_ok());
        let encoded = result
            .unwrap()
            .expect("Should return Some for HardwareStrictWithReferenceValues policy");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("Failed to decode policy");
        let content = String::from_utf8(decoded).expect("Invalid UTF-8");
        assert!(content.contains("tdx_debug_disabled"));
        assert!(content.contains("tdx_eventlog_present"));
        assert!(content.contains("validate_boot_measurements_uefi_event_log"));
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

    /// build_hardware_strict_with_measurements_policy rejects malformed configs.
    #[test]
    fn hardware_strict_with_measurements_policy_rejects_bad_configs() {
        for (types, expect) in [
            (vec![], "non-empty"),
            (vec!["gpu".to_string()], "unsupported"),
            (vec!["model".to_string(), "model".to_string()], "duplicate"),
        ] {
            let err = build_hardware_strict_with_measurements_policy(&types)
                .expect_err("must reject")
                .to_string();
            assert!(err.contains(expect), "expected {expect} in: {err}");
        }
    }
}
