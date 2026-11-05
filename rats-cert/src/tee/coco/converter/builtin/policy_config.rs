//! Serde configuration types for the builtin attestation converter.

use reference_value_provider_service::extractors::extractor_modules::sample::Provenance;
use reference_value_provider_service::rv_list::ReferenceValueListPayload;
use serde::{Deserialize, Serialize};

/// Configuration for policy loading
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyConfig {
    /// tng-bundled template: only hardware TEE recognition is enforced; the
    /// other three trustworthiness dimensions are affirming by default and
    /// `data.reference` is ignored. This is the default policy, suited to
    /// general-purpose deployments that only need to assert the hardware TEE.
    #[default]
    #[serde(alias = "default")]
    HardwareOnly,
    /// tng-bundled template: keeps the hardware-only posture for reference
    /// values, but TDX evidence must be non-debug and include an event log.
    HardwareOnlyStrict,
    /// Modular verification rules: a list of module entries, each declaring a
    /// verification requirement over one part of the evidence (platform
    /// posture, firmware/kernel/image/model measurement, GPU).
    /// Entries within one group are AND-ed; multiple groups are alternative
    /// baselines evaluated with OR. Measurement values are pinned inline in
    /// the entries, so this type must not be combined with external
    /// `reference_values`. Omitting a module type imposes no requirement on
    /// that part; listing one is fail-closed.
    Modules {
        /// Either a flat list (a single group, entries AND-ed) or a list of
        /// lists (one acceptable baseline per inner list). An empty list
        /// imposes no requirements (the `hardware_only` equivalent).
        #[serde(default)]
        modules: ModuleGroupsConfig,
    },
    /// tng-bundled template: every trustworthiness dimension is affirming
    /// regardless of input. **For development and testing only.**
    TrustAll,
    /// At init, fetch a Rekor v1 entry by logIndex, authenticate it
    /// (checkpoint + Merkle inclusion + SET), and bake the trusted
    /// `payloadHash` into Rego. At appraisal the Rego reconstructs the
    /// ReleaseManifest from the actual TDX measurement values, hashes it,
    /// and compares to the baked payloadHash. Mirrors the transparency-verification
    /// flow for signed release manifests.
    #[serde(rename = "transparency_log")]
    TransparencyLog {
        /// Ordered measurement types baked into the policy. When `None`
        /// (the `publishedMeasurements` JSON field is absent), the policy
        /// skips the measurement reconstruction + verification entirely and
        /// `executables` stays affirming (2) — only TDX platform checks
        /// gate the appraisal. An explicit `[]` still runs the check (and
        /// fails it, since no manifest can match the baked payloadHash).
        #[serde(rename = "publishedMeasurements", default)]
        published_measurements: Option<Vec<String>>,
        #[serde(rename = "schemaVersion", default = "default_schema_version")]
        schema_version: String,
        services: Vec<TransparencyServiceConfig>,
        /// Fallback measurement types used when the artifact-server primary
        /// cannot resolve a measurement; must be a subset of
        /// `publishedMeasurements`.
        #[serde(rename = "fallbackPublishedMeasurements", default)]
        fallback_published_measurements: Option<Vec<String>>,
        /// Fallback transparency-log services (rekor-v1 only) used when the
        /// artifact-server primary cannot resolve a measurement; only supported
        /// when the primary service is an `artifact-server`.
        #[serde(rename = "fallbackServices", default)]
        fallback_services: Option<Vec<TransparencyServiceConfig>>,
        /// Measurement types verified against statically registered reference
        /// values (the builtin AS `reference_values` / RVPS
        /// `query_reference_value`) instead of the transparency service. Used
        /// for user-owned artifacts the transparency service does not publish:
        /// `model` (the pai/load-model event, reference name
        /// `measurement.model.<model-id>`) and `container.image.<repo>`
        /// (reference name `measurement.container.image.<repo>`, digest
        /// extraction shared with the published container-image measurements).
        /// The static checks AND-gate `measurements_verified`: the appraisal
        /// passes only when the transparency-log manifest check AND every
        /// static check pass. Must be disjoint from `publishedMeasurements`
        /// and `fallbackPublishedMeasurements`.
        #[serde(rename = "staticReferenceMeasurements", default)]
        static_reference_measurements: Option<Vec<String>>,
    },
    /// Base64 encoded policy content
    Inline { content: String },
    /// Path to policy file
    #[cfg(not(wasm))]
    Path { path: String },
}

/// Default schema version for the transparency-log policy config.
fn default_schema_version() -> String {
    "1.0.0".to_string()
}

/// One entry in a `modules` attestation-policy group. `type` selects the
/// module family; `value` is a measurement string for the measurement families
/// (`tdx.*`, `com.alibabacloud.container.image.*`, `com.alibabacloud.ai.model.*`,
/// with the unprefixed `container.image.*` and `ai.model.*` spellings as
/// permanent aliases) and a posture object for the posture families (`tdx`,
/// `nvidia`, `com.alibabacloud.gpu`; the last takes an empty object). The
/// `value` shape is validated against the family at load time; an unrecognized
/// type, a malformed value, or a name-segment charset violation is a
/// configuration error rejected before any appraisal runs, never silently
/// ignored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModuleEntryConfig {
    #[serde(rename = "type")]
    pub module_type: String,
    pub value: serde_json::Value,
}

/// The `modules` list, in either accepted JSON shape. A flat array is a single
/// group whose entries AND; an array of arrays is multiple groups, each group
/// AND-ing within itself and OR-ing across groups. serde distinguishes them by
/// the outer array's element type (object vs array), so no tag field is needed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ModuleGroupsConfig {
    /// A single flat group.
    Single(Vec<ModuleEntryConfig>),
    /// Multiple groups, each a flat inner group.
    Groups(Vec<Vec<ModuleEntryConfig>>),
}

impl Default for ModuleGroupsConfig {
    fn default() -> Self {
        ModuleGroupsConfig::Single(Vec::new())
    }
}

impl ModuleGroupsConfig {
    /// Normalize both shapes to the list of groups a flat single group is a
    /// one-element list. An outer empty array (`[]`) is one empty group (no
    /// requirements), matching the `hardware_only` equivalence.
    pub fn as_groups(&self) -> Vec<&Vec<ModuleEntryConfig>> {
        match self {
            ModuleGroupsConfig::Single(entries) => vec![entries],
            ModuleGroupsConfig::Groups(groups) => groups.iter().collect(),
        }
    }
}

/// A `tdx` platform-posture module. Every field defaults to the strict choice,
/// so `{"type":"tdx","value":{}}` appraises the full strict posture. There is
/// no total on/off switch: the entry's presence in a group imposes the posture;
/// omitting the entry imposes none.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TdxPostureConfig {
    /// TD debug attribute gate. `deny` (default) requires the debug bit clear;
    /// `allow` skips the check.
    #[serde(default)]
    pub debug: TdxBit,
    /// SEPT #VE-disable attribute gate. `require` (default) demands the bit set;
    /// `allow` skips the check.
    #[serde(default)]
    pub sept_ve_disable: TdxSeptVe,
    /// Performance-counter attribute gate. `deny` (default) requires the bit
    /// clear; `allow` skips the check.
    #[serde(default)]
    pub perfmon: TdxBit,
    /// Service-TD (`mr_servicetd`) gate. `deny` (default) requires the field
    /// be all-zero or absent (quote v4); `allow` skips the check.
    #[serde(default)]
    pub service_td: TdxBit,
    /// TCB status/advisory gate. Opt-in: absent (the default) applies no TCB
    /// requirement, so the strict posture does not force `tcb_verification`
    /// claims that older deployments may not carry.
    #[serde(default)]
    pub tcb: Option<TdxTcbConfig>,
    /// Collateral freshness gate. Opt-in: absent applies no collateral check.
    #[serde(default)]
    pub collateral: Option<TdxCollateralConfig>,
    /// Event log must be present. `required` (default) demands a non-empty
    /// event log; `optional` skips the check.
    #[serde(default)]
    pub eventlog: TdxEventlog,
}

/// A boolean "deny the bit / allow the bit" posture switch. The default is the
/// denying (strict) side.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TdxBit {
    #[default]
    Deny,
    Allow,
}

/// The SEPT #VE-disable switch, which defaults to requiring the bit (opposite
/// polarity from the plain deny/allow [`TdxBit`]).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TdxSeptVe {
    #[default]
    Require,
    Allow,
}

/// An event-log requirement switch, defaulting to required. The "off" side is
/// spelled `optional` in the JSON schema.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TdxEventlog {
    #[default]
    Required,
    Optional,
}

/// TCB status/advisory configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields, default)]
pub struct TdxTcbConfig {
    /// Minimum TCB status rank. `up_to_date` (default) rejects the
    /// out-of-date ranks; `out_of_date` accepts them (Revoked is still rejected).
    pub min_status: TcbMinStatus,
    /// Advisory IDs that force a reject when present in the platform's
    /// affected list.
    pub reject_advisories: Vec<String>,
    /// Advisory IDs exempted from `reject_advisories`.
    pub allow_advisories: Vec<String>,
}

/// Minimum TCB status accepted by a `tcb` gate (the `min_status` field).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TcbMinStatus {
    /// Accept the out-of-date ranks as well; only Revoked is rejected.
    OutOfDate,
    /// Only accept ranks at or above UpToDate (reject the OutOfDate family).
    /// The default.
    #[default]
    UpToDate,
}

/// Collateral freshness configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields, default)]
pub struct TdxCollateralConfig {
    /// Allow expired TCB collateral. Defaults false (collateral must be fresh).
    pub allow_expired: bool,
    /// Minimum `tcb_level_date_tag` (YYYY-MM-DD). `None` means unset.
    #[serde(default)]
    pub min_tcb_date: Option<String>,
    /// Maximum collateral age in days from `latest_issue_date`. `None` unset.
    #[serde(default)]
    pub max_collateral_age_days: Option<u32>,
}

/// An `nvidia` GPU-appraisal module: the standard NVIDIA appraisal over the
/// evaluated per-GPU `nvidia_gpu.<i>` claims. Absent from a group, GPUs are not
/// appraised; present, the checks fail closed. The Alibaba AAEL attestation
/// event check is a separate `com.alibabacloud.gpu` entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NvidiaPostureConfig {
    /// Require every enumerated GPU to report `cc_enabled`.
    #[serde(default = "nvidia_default_true")]
    pub require_cc_mode: bool,
    /// Require every GPU to carry an evaluated `measurement`.
    #[serde(default = "nvidia_default_true")]
    pub require_report: bool,
    /// Minimum number of enumerated GPUs.
    #[serde(default = "nvidia_default_min_count")]
    pub min_count: u64,
    /// Allowed GPU UUIDs (empty = no whitelist).
    #[serde(default)]
    pub allow_uuids: Vec<String>,
    /// Allowed driver versions (empty = no whitelist).
    #[serde(default)]
    pub allow_driver_versions: Vec<String>,
    /// Allowed VBIOS versions (empty = no whitelist).
    #[serde(default)]
    pub allow_vbios_versions: Vec<String>,
    /// Allowed per-GPU measurement digests, each 96 lowercase hex
    /// (empty = no whitelist).
    #[serde(default)]
    pub measurement_digest: Vec<String>,
}

/// A `com.alibabacloud.gpu` module. It has no fields; the empty-object value is
/// enforced by `deny_unknown_fields`, which rejects any supplied field.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GpuPostureConfig {}

fn nvidia_default_true() -> bool {
    true
}

fn nvidia_default_min_count() -> u64 {
    1
}

/// Human-readable JSON value shape for config-error messages.
pub(crate) fn value_shape(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// A transparency-log service whose entry authenticates the reference
/// measurements. `rekor-v1` fetches an entry by logIndex; `artifact-server`
/// delegates to a log-services list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TransparencyServiceConfig {
    #[serde(rename = "rekor-v1")]
    RekorV1 {
        #[serde(rename = "logUrl")]
        log_url: String,
        #[serde(rename = "logIndex")]
        log_index: i64,
        #[serde(rename = "rekorPublicKeyPem", default)]
        rekor_public_key_pem: Option<String>,
        #[serde(rename = "publisherPublicKeyPem", default)]
        publisher_public_key_pem: Option<String>,
    },
    #[serde(rename = "artifact-server")]
    ArtifactServer {
        #[serde(rename = "url")]
        url: String,
        #[serde(rename = "logServices")]
        log_services: Vec<ArtifactLogService>,
        /// Optional DSSE publisher public key (PEM) overriding the built-in
        /// publisher key baseline: when empty, DSSE verification falls back to
        /// the built-in publisher key. Used for both the primary resolve path
        /// and (when absent) the built-in default.
        #[serde(rename = "publisherPublicKeyPem", default)]
        publisher_public_key_pem: Option<String>,
    },
}

/// A single log-service entry nested under an `artifact-server` transparency
/// service: `{"type":"rekor-v1","url":"..."}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ArtifactLogService {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "url")]
    pub url: String,
}

/// Configuration for sample provenance payload loading
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SampleProvenancePayloadConfig {
    /// Inline JSON content (Provenance)
    Inline { content: Provenance },
    /// Path to payload file
    #[cfg(not(wasm))]
    Path { path: String },
}

/// Configuration for SLSA reference value payload loading
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SlsaReferenceValuePayloadConfig {
    /// Inline JSON content (ReferenceValueListPayload)
    Inline { content: ReferenceValueListPayload },
    /// Path to payload file
    #[cfg(not(wasm))]
    Path { path: String },
}

/// Configuration for reference values
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReferenceValueConfig {
    /// Sample reference values (inline or from file)
    Sample {
        payload: SampleProvenancePayloadConfig,
    },
    /// SLSA-based reference values from Rekor
    Slsa {
        payload: SlsaReferenceValuePayloadConfig,
    },
    /// RV release manifest-based reference values
    ReleaseManifest {
        payload: SlsaReferenceValuePayloadConfig,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use reference_value_provider_service::rv_list::{
        ReferenceValueListItem, ReferenceValueProvenanceInfo, ReferenceValueProvenanceSource,
    };
    use serde_json::json;

    // === ReferenceValueConfig serialization/deserialization tests ===

    #[test]
    fn test_reference_value_config_sample_inline_serde() -> Result<(), serde_json::Error> {
        // Create a Provenance for testing
        let mut rvs = std::collections::HashMap::new();
        rvs.insert(
            "my-component".to_string(),
            json!(["expected-value-1", "expected-value-2"]),
        );
        let provenance = Provenance { rvs };

        let config = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Inline {
                content: provenance,
            },
        };

        // Serialize to JSON
        let json_str = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(json_str.contains("\"type\":\"sample\""));
        assert!(json_str.contains("\"type\":\"inline\""));
        assert!(json_str.contains("my-component"));

        // Deserialize back
        let deserialized: ReferenceValueConfig =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(deserialized)?
        );

        Ok(())
    }

    #[test]
    fn test_reference_value_config_sample_path_serde() -> Result<(), serde_json::Error> {
        let config = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Path {
                path: "/path/to/provenance.json".to_string(),
            },
        };

        let json_str = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(json_str.contains("\"type\":\"sample\""));
        assert!(json_str.contains("\"type\":\"path\""));
        assert!(json_str.contains("/path/to/provenance.json"));

        let deserialized: ReferenceValueConfig =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(deserialized)?
        );
        Ok(())
    }

    #[test]
    fn test_reference_value_config_slsa_inline_serde() -> Result<(), serde_json::Error> {
        // Create a ReferenceValueListPayload for testing
        let rv_item = ReferenceValueListItem {
            id: "test-artifact".to_string(),
            version: "1.0.0".to_string(),
            rv_type: "binary".to_string(),
            provenance_info: ReferenceValueProvenanceInfo {
                provenance_type: "slsa-intoto-statements".to_string(),
                rekor_url: "https://log2025-1.rekor.sigstore.dev".to_string(),
                rekor_api_version: Some(2),
            },
            provenance_source: Some(ReferenceValueProvenanceSource {
                protocol: "oci".to_string(),
                uri: "oci://127.0.0.1:5000/trustee/provenance:test-artifact-1.0.0".to_string(),
                artifact: Some("bundle".to_string()),
            }),
            operation_type: "refresh".to_string(),
            rv_name: None,
        };
        let payload = ReferenceValueListPayload {
            rv_list: vec![rv_item],
        };

        let config = ReferenceValueConfig::Slsa {
            payload: SlsaReferenceValuePayloadConfig::Inline { content: payload },
        };

        let json_str = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(json_str.contains("\"type\":\"slsa\""));
        assert!(json_str.contains("\"type\":\"inline\""));
        assert!(json_str.contains("\"rv_list\""));
        assert!(json_str.contains("test-artifact"));

        let deserialized: ReferenceValueConfig =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(deserialized)?
        );
        Ok(())
    }

    #[test]
    fn test_reference_value_config_slsa_path_serde() -> Result<(), serde_json::Error> {
        let config = ReferenceValueConfig::Slsa {
            payload: SlsaReferenceValuePayloadConfig::Path {
                path: "/path/to/slsa_payload.json".to_string(),
            },
        };

        let json_str = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(json_str.contains("\"type\":\"slsa\""));
        assert!(json_str.contains("\"type\":\"path\""));
        assert!(json_str.contains("/path/to/slsa_payload.json"));

        let deserialized: ReferenceValueConfig =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(deserialized)?
        );
        Ok(())
    }

    #[test]
    fn test_reference_value_config_release_manifest_inline_serde() -> Result<(), serde_json::Error>
    {
        let rv_item = ReferenceValueListItem {
            id: "cvm_uki".to_string(),
            version: "1.0.0".to_string(),
            rv_type: "uki".to_string(),
            provenance_info: ReferenceValueProvenanceInfo {
                provenance_type: "rv-release-manifest".to_string(),
                rekor_url: "https://log2025-1.rekor.sigstore.dev".to_string(),
                rekor_api_version: Some(2),
            },
            provenance_source: Some(ReferenceValueProvenanceSource {
                protocol: "oci".to_string(),
                uri: "oci://127.0.0.1:5000/trustee/provenance:cvm_uki-1.0.0".to_string(),
                artifact: Some("bundle".to_string()),
            }),
            operation_type: "refresh".to_string(),
            rv_name: None,
        };
        let payload = ReferenceValueListPayload {
            rv_list: vec![rv_item],
        };

        let config = ReferenceValueConfig::ReleaseManifest {
            payload: SlsaReferenceValuePayloadConfig::Inline { content: payload },
        };

        let json_str = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(json_str.contains("\"type\":\"release_manifest\""));

        let deserialized: ReferenceValueConfig =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(
            serde_json::to_value(config)?,
            serde_json::to_value(deserialized)?
        );
        Ok(())
    }

    #[test]
    fn test_reference_value_config_deserialize_from_json() {
        // Test deserializing Sample inline from raw JSON
        let sample_json = r#"{
            "type": "sample",
            "payload": {
                "type": "inline",
                "content": {"example-key": ["expected-value"]}
            }
        }"#;
        let config: ReferenceValueConfig =
            serde_json::from_str(sample_json).expect("Failed to parse");
        match config {
            ReferenceValueConfig::Sample { payload } => match payload {
                SampleProvenancePayloadConfig::Inline { content } => {
                    // Provenance uses flattened HashMap, verify it has the expected key
                    assert!(content.rvs.contains_key("example-key"));
                }
                _ => panic!("Expected Inline payload"),
            },
            _ => panic!("Expected Sample variant"),
        }

        // Test deserializing SLSA inline from raw JSON
        let slsa_json = r#"{
            "type": "slsa",
            "payload": {
                "type": "inline",
                "content": {
                    "rv_list": [{
                        "id": "test-artifact",
                        "version": "1.0.0",
                        "type": "binary",
                        "provenance_info": {
                            "type": "slsa-intoto-statements",
                            "rekor_url": "https://log2025-1.rekor.sigstore.dev",
                            "rekor_api_version": 2
                        },
                        "provenance_source": {
                            "protocol": "oci",
                            "uri": "oci://127.0.0.1:5000/trustee/provenance:test-artifact-1.0.0",
                            "artifact": "bundle"
                        },
                        "operation_type": "refresh"
                    }]
                }
            }
        }"#;
        let config: ReferenceValueConfig =
            serde_json::from_str(slsa_json).expect("Failed to parse");
        match config {
            ReferenceValueConfig::Slsa { payload } => match payload {
                SlsaReferenceValuePayloadConfig::Inline { content } => {
                    assert_eq!(content.rv_list.len(), 1);
                    assert_eq!(content.rv_list[0].id, "test-artifact");
                }
                _ => panic!("Expected Inline payload"),
            },
            _ => panic!("Expected Slsa variant"),
        }
    }
}
