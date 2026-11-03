//! Serde configuration types for the builtin attestation converter.

use reference_value_provider_service::extractors::extractor_modules::sample::Provenance;
use reference_value_provider_service::rv_list::ReferenceValueListPayload;
use serde::{Deserialize, Serialize};

/// Configuration for policy loading
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyConfig {
    /// Use the attestation-service default policy (the trustee
    /// `ear_default_policy_cpu.rego`): a comprehensive appraisal that checks
    /// hardware, boot measurements, configuration and filesystem against
    /// configured reference values. Suited to deployments where those
    /// reference values are available and mandatory.
    /// See: https://github.com/openanolis/trustee/blob/7a6a7b8a2554295bcd296963d353761eaf4f70eb/attestation-service/src/token/ear_default_policy_cpu.rego
    HardwareWithReferenceValues,
    /// Trustee default reference-value appraisal with stricter TDX hardware
    /// requirements: TDX evidence must be non-debug and include an event log.
    HardwareStrictWithReferenceValues,
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
    /// tng-bundled template: the `hardware_only_strict` platform posture (TDX
    /// must be non-debug and include an event log) plus an explicit
    /// measurement list appraised against the builtin AS's registered
    /// reference values (RVPS `query_reference_value`), so user-owned
    /// artifacts (the model, user-provided container images) can be verified
    /// without a transparency service. Same measurement types and
    /// reference-value names as the transparency_log policy's
    /// `staticReferenceMeasurements`. The `strict` infix follows
    /// `hardware_strict_with_reference_values`: non-debug TDX with an event
    /// log is required.
    HardwareStrictWithMeasurements {
        #[serde(rename = "measurements")]
        measurements: Vec<String>,
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
