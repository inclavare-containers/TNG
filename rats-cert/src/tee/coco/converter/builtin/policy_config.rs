//! Serde configuration types for the builtin attestation converter.

use reference_value_provider_service::extractors::extractor_modules::sample::Provenance;
use reference_value_provider_service::rv_list::ReferenceValueListPayload;
use serde::{Deserialize, Serialize};

use super::policies::modules::families;

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
    /// posture, firmware/kernel/image/model measurement, GPU, transparency
    /// log). Entries within one group are AND-ed; multiple groups are
    /// alternative baselines evaluated with OR. Measurement values are pinned
    /// inline in the entries or anchored in a transparency log, so this type
    /// must not be combined with external `reference_values`. Omitting a module
    /// type imposes no requirement on that part; listing one is fail-closed. A
    /// `transparency_log` entry takes an options object and anchors its
    /// baseline in a transparency log instead of pinning a digest in the
    /// policy.
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
    /// Base64 encoded policy content
    Inline { content: String },
    /// Path to policy file
    #[cfg(not(wasm))]
    Path { path: String },
}

impl PolicyConfig {
    /// Whether this policy's verification rules may consume external
    /// reference values. The bundled templates and `modules` pin or anchor
    /// their baselines directly, so a non-empty `reference_values` list would
    /// be silently inert; construction rejects it instead. `inline` and `path`
    /// policies are user content and may query the reference-value store.
    pub fn accepts_reference_values(&self) -> bool {
        match self {
            Self::Inline { .. } => true,
            #[cfg(not(wasm))]
            Self::Path { .. } => true,
            Self::HardwareOnly
            | Self::HardwareOnlyStrict
            | Self::TrustAll
            | Self::Modules { .. } => false,
        }
    }

    /// Short policy name used in configuration errors and as the `type` tag.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::HardwareOnly => "hardware_only",
            Self::HardwareOnlyStrict => "hardware_only_strict",
            Self::TrustAll => "trust_all",
            Self::Modules { .. } => "modules",
            Self::Inline { .. } => "inline",
            #[cfg(not(wasm))]
            Self::Path { .. } => "path",
        }
    }

    /// Human-readable name for consumers that render a policy chooser.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::HardwareOnly => "Hardware only",
            Self::HardwareOnlyStrict => "Hardware only, strict",
            Self::TrustAll => "Trust all",
            Self::Modules { .. } => "Modules",
            Self::Inline { .. } => "Inline",
            #[cfg(not(wasm))]
            Self::Path { .. } => "Path",
        }
    }

    /// Every policy kind compiled for this target, in display order. One entry
    /// per variant; `path` is absent on wasm because file access is not
    /// available there.
    pub fn capabilities() -> Vec<PolicyCapability> {
        [
            PolicyConfig::HardwareOnly,
            PolicyConfig::HardwareOnlyStrict,
            PolicyConfig::Modules {
                modules: ModuleGroupsConfig::default(),
            },
            PolicyConfig::TrustAll,
            PolicyConfig::Inline {
                content: String::new(),
            },
            #[cfg(not(wasm))]
            PolicyConfig::Path {
                path: String::new(),
            },
        ]
        .iter()
        .map(|policy| PolicyCapability {
            policy_type: policy.name(),
            name: policy.display_name(),
            accepts_reference_values: policy.accepts_reference_values(),
            is_default: matches!(policy, PolicyConfig::HardwareOnly),
            has_content: matches!(policy, PolicyConfig::Inline { .. }),
        })
        .collect()
    }
}

/// One selectable policy kind, described for consumers that build a policy
/// chooser (for example the browser demo).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PolicyCapability {
    /// The `type` tag this policy kind uses in configuration.
    #[serde(rename = "type")]
    pub policy_type: &'static str,
    /// Human-readable name for this policy kind.
    pub name: &'static str,
    /// Whether the kind accepts a non-empty external `reference_values` list.
    pub accepts_reference_values: bool,
    /// Whether the kind is the default when `attestation_policy` is omitted.
    pub is_default: bool,
    /// Whether this kind's config object carries user-supplied `content`.
    pub has_content: bool,
}

/// Default schema version for a transparency-log module entry.
fn default_schema_version() -> String {
    "1.0.0".to_string()
}

/// A `transparency_log` module entry: the published measurements whose trusted
/// baseline is a ReleaseManifest recorded in a transparency log. A rekor-v1
/// primary is fetched and authenticated when the policy loads; an
/// artifact-server primary is resolved at appraisal time. The entry gates the
/// `executables` dimension; platform posture stays a separate `tdx` entry.
///
/// Each measurement type is listed once. At appraisal a `container.image.*`
/// type expands to one manifest entry per digest observed in the evidence, so
/// the reconstructed manifest keeps a repeated entry for that type; every other
/// type contributes exactly one entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "TransparencyLogEntryConfigRepr")]
pub struct TransparencyLogEntryConfig {
    /// Non-empty measurement types. At appraisal the policy
    /// reconstructs the manifest from the actual TDX measurement values and
    /// compares it to the logged reference.
    #[serde(rename = "publishedMeasurements")]
    pub published_measurements: Vec<String>,
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub services: Vec<TransparencyServiceConfig>,
    /// Fallback measurement types used when the artifact-server primary
    /// cannot resolve a measurement; must be a subset of
    /// `publishedMeasurements`.
    #[serde(rename = "fallbackPublishedMeasurements")]
    pub fallback_published_measurements: Option<Vec<String>>,
    /// Fallback transparency-log services (rekor-v1 only) used when the
    /// artifact-server primary cannot resolve a measurement; only supported
    /// when the primary service is an `artifact-server`.
    #[serde(rename = "fallbackServices")]
    pub fallback_services: Option<Vec<TransparencyServiceConfig>>,
}

/// Deserialization mirror for [`TransparencyLogEntryConfig`]. The public type
/// derives `Serialize`, so its field renames stay there; this mirror carries
/// the defaults and `deny_unknown_fields` and feeds the validating conversion.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransparencyLogEntryConfigRepr {
    #[serde(rename = "publishedMeasurements")]
    published_measurements: Vec<String>,
    #[serde(rename = "schemaVersion", default = "default_schema_version")]
    schema_version: String,
    services: Vec<TransparencyServiceConfig>,
    #[serde(rename = "fallbackPublishedMeasurements", default)]
    fallback_published_measurements: Option<Vec<String>>,
    #[serde(rename = "fallbackServices", default)]
    fallback_services: Option<Vec<TransparencyServiceConfig>>,
}

impl TryFrom<TransparencyLogEntryConfigRepr> for TransparencyLogEntryConfig {
    type Error = anyhow::Error;

    fn try_from(repr: TransparencyLogEntryConfigRepr) -> anyhow::Result<Self> {
        Self::try_new(
            repr.published_measurements,
            repr.schema_version,
            repr.services,
            repr.fallback_published_measurements,
            repr.fallback_services,
        )
    }
}

impl TransparencyLogEntryConfig {
    /// Construct a validated entry. Deserialization goes through this, and
    /// callers that build one programmatically should use it too.
    pub fn try_new(
        published_measurements: Vec<String>,
        schema_version: String,
        services: Vec<TransparencyServiceConfig>,
        fallback_published_measurements: Option<Vec<String>>,
        fallback_services: Option<Vec<TransparencyServiceConfig>>,
    ) -> anyhow::Result<Self> {
        let cfg = Self {
            published_measurements,
            schema_version,
            services,
            fallback_published_measurements,
            fallback_services,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Check the entry's structural invariants. These run at policy load,
    /// before any Rekor fetch or appraisal, so a malformed entry is a
    /// configuration error rather than a panic downstream.
    fn validate(&self) -> anyhow::Result<()> {
        if self.published_measurements.is_empty() {
            anyhow::bail!("publishedMeasurements must be non-empty");
        }
        let mut seen_measurement_types = std::collections::HashSet::new();
        for measurement_type in &self.published_measurements {
            families::validate_published_type(measurement_type)?;
            if !seen_measurement_types.insert(measurement_type) {
                anyhow::bail!("duplicate publishedMeasurements type {measurement_type}");
            }
        }

        if self.services.is_empty() {
            anyhow::bail!("services must be non-empty");
        }
        let mut artifact_server = false;
        for service in &self.services {
            match service {
                TransparencyServiceConfig::ArtifactServer {
                    url, log_services, ..
                } => {
                    artifact_server = true;
                    if self.services.len() != 1 {
                        anyhow::bail!("artifact-server must be the only primary service");
                    }
                    if url.is_empty() {
                        anyhow::bail!("artifact-server url is required");
                    }
                    if log_services.is_empty() {
                        anyhow::bail!("artifact-server logServices non-empty");
                    }
                    let mut seen_log_services = std::collections::HashSet::new();
                    for log_service in log_services {
                        if log_service.type_ != "rekor-v1" {
                            anyhow::bail!("artifact-server logServices type must be rekor-v1");
                        }
                        if log_service.url.is_empty() {
                            anyhow::bail!("artifact-server logServices url required");
                        }
                        if !seen_log_services.insert((
                            log_service.type_.clone(),
                            log_service.url.trim_end_matches('/'),
                        )) {
                            anyhow::bail!("duplicate artifact-server logServices entry");
                        }
                    }
                }
                TransparencyServiceConfig::RekorV1 {
                    log_url, log_index, ..
                } => {
                    if log_url.is_empty() {
                        anyhow::bail!("rekor-v1 logUrl required");
                    }
                    if *log_index < 0 {
                        anyhow::bail!("rekor-v1 logIndex must be >= 0");
                    }
                }
            }
        }

        // A rekor-v1 primary is the entry's only service: it has no fallback
        // and the renderer uses `services[0]` as the primary.
        if !artifact_server && self.services.len() != 1 {
            anyhow::bail!("services must contain exactly one rekor-v1 service");
        }

        match (
            self.fallback_services.as_ref(),
            self.fallback_published_measurements.as_ref(),
        ) {
            (None, Some(_)) => {
                anyhow::bail!("fallbackPublishedMeasurements requires fallbackServices");
            }
            (None, None) => Ok(()),
            (Some(fallback_services), _) => {
                if !artifact_server {
                    anyhow::bail!(
                        "fallbackServices is only supported with an artifact-server primary"
                    );
                }
                if fallback_services.is_empty() {
                    anyhow::bail!("fallbackServices must be non-empty");
                }
                for service in fallback_services {
                    match service {
                        TransparencyServiceConfig::RekorV1 {
                            log_url, log_index, ..
                        } => {
                            if log_url.is_empty() {
                                anyhow::bail!("fallbackServices logUrl required");
                            }
                            if *log_index < 0 {
                                anyhow::bail!("fallbackServices logIndex >= 0");
                            }
                        }
                        _ => anyhow::bail!("fallbackServices must be rekor-v1"),
                    }
                }
                if let Some(fallback_measurements) = &self.fallback_published_measurements {
                    if fallback_measurements.is_empty() {
                        anyhow::bail!("fallbackPublishedMeasurements non-empty");
                    }
                    let primary_types: std::collections::HashSet<&String> =
                        self.published_measurements.iter().collect();
                    for fallback_type in fallback_measurements {
                        if !primary_types.contains(fallback_type) {
                            anyhow::bail!(
                                "fallbackPublishedMeasurements type {fallback_type} not in publishedMeasurements"
                            );
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

/// One entry in a `modules` attestation-policy group. `type` selects the
/// module family; it is parsed once into a canonical entry-type enum at load
/// time, so a canonical `com.alibabacloud.` spelling and its permanent
/// unprefixed alias resolve to the same family. `value` is a measurement
/// string for the measurement families (`tdx.*`,
/// `com.alibabacloud.container.image.*`, `com.alibabacloud.ai.model.*`, with
/// the unprefixed `container.image.*` and `ai.model.*` spellings as
/// aliases), a posture object for the posture families (`tdx`, `nvidia`,
/// `com.alibabacloud.gpu`; the last takes an empty object), and a
/// `TransparencyLogEntryConfig` object for `transparency_log`, whose trusted
/// baseline is a transparency-logged manifest rather than an inlined digest.
/// The `value` shape is validated against the parsed family at load time; an
/// unrecognized type, a malformed value, or a name-segment charset violation
/// is a configuration error rejected before any appraisal runs, never silently
/// ignored.
///
/// A `container.image.<repo>` type may repeat within one group: the entries'
/// values merge into the expected digest set for that repo, and evidence must
/// report exactly that set. Every other type (including `ai.model.*` and
/// `tdx.*`) may appear at most once per group.
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    use crate::tee::coco::converter::builtin::converter::BuiltinCocoConverter;
    use crate::tee::coco::converter::builtin::policies::modules::{parse_module_groups, Module};
    use crate::tee::coco::converter::builtin::test_fixtures::{
        artifact_entry_value, rekor_entry_value, transparency_entry,
        SECURE_PROXY_ARTIFACT_SERVER_CONFIG_JSON,
    };

    use super::*;
    use reference_value_provider_service::rv_list::{
        ReferenceValueListItem, ReferenceValueProvenanceInfo, ReferenceValueProvenanceSource,
    };
    use serde_json::{json, Value};

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

    fn valid_rekor_entry() -> serde_json::Value {
        json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{
                "type": "rekor-v1",
                "logUrl": "https://rekor.example.com",
                "logIndex": 1,
            }],
        })
    }

    #[test]
    fn transparency_log_entry_config_validates_on_deserialize() {
        let cfg: TransparencyLogEntryConfig =
            serde_json::from_value(valid_rekor_entry()).expect("valid entry parses");
        // The schema version default still applies and the wire shape is
        // unchanged.
        assert_eq!(cfg.schema_version, "1.0.0");
        let serialized = serde_json::to_value(&cfg).expect("serialize entry");
        assert_eq!(serialized["schemaVersion"], "1.0.0");
        assert!(serialized.get("fallbackServices").is_some());

        // Structural invariants are rejected where the value is created, with
        // no hand-built location strings.
        for (value, message) in [
            (
                json!({"publishedMeasurements": [], "services": valid_rekor_entry()["services"]}),
                "publishedMeasurements must be non-empty",
            ),
            (
                json!({
                    "publishedMeasurements": ["tdx.uki"],
                    "services": valid_rekor_entry()["services"],
                }),
                "unsupported publishedMeasurements type",
            ),
            (
                json!({
                    "publishedMeasurements": ["tdx.td-shim"],
                    "services": [],
                }),
                "services must be non-empty",
            ),
            (
                json!({
                    "publishedMeasurements": ["tdx.td-shim"],
                    "services": [{
                        "type": "rekor-v1",
                        "logUrl": "https://rekor.example.com",
                        "logIndex": -1,
                    }],
                }),
                "rekor-v1 logIndex must be >= 0",
            ),
            (
                json!({
                    "publishedMeasurements": ["tdx.td-shim"],
                    "services": valid_rekor_entry()["services"],
                    "fallbackPublishedMeasurements": ["tdx.td-shim"],
                }),
                "fallbackPublishedMeasurements requires fallbackServices",
            ),
        ] {
            let error =
                serde_json::from_value::<TransparencyLogEntryConfig>(value).expect_err(message);
            assert!(error.to_string().contains(message), "{error}");
        }

        // The programmatic constructor applies the same check.
        let error = TransparencyLogEntryConfig::try_new(
            vec![],
            "1.0.0".to_string(),
            serde_json::from_value(valid_rekor_entry()["services"].clone())
                .expect("services parse"),
            None,
            None,
        )
        .expect_err("empty publishedMeasurements must be rejected");
        assert!(error
            .to_string()
            .contains("publishedMeasurements must be non-empty"));
    }

    #[test]
    fn policy_config_accepts_reference_values_only_for_user_content() {
        for policy in [
            PolicyConfig::HardwareOnly,
            PolicyConfig::HardwareOnlyStrict,
            PolicyConfig::TrustAll,
            PolicyConfig::Modules {
                modules: ModuleGroupsConfig::default(),
            },
        ] {
            assert!(
                !policy.accepts_reference_values(),
                "{policy:?} must reject external reference values"
            );
        }
        assert!(PolicyConfig::Inline {
            content: String::new(),
        }
        .accepts_reference_values());
        #[cfg(not(wasm))]
        assert!(PolicyConfig::Path {
            path: String::new(),
        }
        .accepts_reference_values());
    }

    #[test]
    fn policy_capabilities_match_the_compiled_variants() {
        let caps = PolicyConfig::capabilities();

        #[cfg(not(wasm))]
        let expected_types = [
            "hardware_only",
            "hardware_only_strict",
            "modules",
            "trust_all",
            "inline",
            "path",
        ];
        #[cfg(wasm)]
        let expected_types = [
            "hardware_only",
            "hardware_only_strict",
            "modules",
            "trust_all",
            "inline",
        ];

        let types: Vec<_> = caps.iter().map(|c| c.policy_type).collect();
        assert_eq!(types, expected_types);
        assert!(caps.iter().all(|c| !c.name.is_empty()));

        // Exactly one default, and it is hardware_only.
        let defaults: Vec<_> = caps.iter().filter(|c| c.is_default).collect();
        assert_eq!(defaults.len(), 1);
        assert_eq!(defaults[0].policy_type, "hardware_only");

        // Accepting external reference values is the same rule the constructor
        // enforces: only user-supplied content does.
        let accepting: Vec<_> = caps
            .iter()
            .filter(|c| c.accepts_reference_values)
            .map(|c| c.policy_type)
            .collect();
        #[cfg(not(wasm))]
        assert_eq!(accepting, ["inline", "path"]);
        #[cfg(wasm)]
        assert_eq!(accepting, ["inline"]);

        let with_content: Vec<_> = caps
            .iter()
            .filter(|c| c.has_content)
            .map(|c| c.policy_type)
            .collect();
        assert_eq!(with_content, ["inline"]);
    }

    #[test]
    fn transparency_log_entry_parses_flat_and_nested() {
        let value = rekor_entry_value(&["tdx.td-shim"], 7);

        // Flat list: one group.
        let flat: ModuleGroupsConfig =
            serde_json::from_value(json!([transparency_entry(value.clone())])).expect("parse");
        let groups = parse_module_groups(&flat).expect("validate");
        assert_eq!(groups.len(), 1);
        match &groups[0][0] {
            Module::TransparencyLog {
                config: cfg,
                resolved,
            } => {
                assert!(resolved.is_none(), "parse does not resolve rekor data");
                assert_eq!(cfg.published_measurements, vec!["tdx.td-shim".to_string()]);
                assert_eq!(cfg.schema_version, "1.0.0");
                assert_eq!(cfg.services.len(), 1);
                match &cfg.services[0] {
                    TransparencyServiceConfig::RekorV1 {
                        log_url, log_index, ..
                    } => {
                        assert_eq!(log_url, "https://rekor.example.com");
                        assert_eq!(*log_index, 7);
                    }
                    other => panic!("expected RekorV1, got {other:?}"),
                }
            }
            other => panic!("expected TransparencyLog, got {other:?}"),
        }

        // Nested list: one transparency entry per group.
        let nested: ModuleGroupsConfig = serde_json::from_value(json!([
            [transparency_entry(value.clone())],
            [transparency_entry(rekor_entry_value(&["tdx.kernel"], 8))],
        ]))
        .expect("parse");
        let groups = parse_module_groups(&nested).expect("validate");
        assert_eq!(groups.len(), 2);
        assert!(matches!(groups[0][0], Module::TransparencyLog { .. }));
        assert!(matches!(groups[1][0], Module::TransparencyLog { .. }));
    }

    #[test]
    fn transparency_log_entry_defaults_and_publisher_key() {
        // `schemaVersion` defaults to 1.0.0; an optional publisher key parses.
        let value = json!({
            "publishedMeasurements": ["container.image.cmaas-runtime"],
            "services": [{
                "type": "rekor-v1",
                "logUrl": "https://rekor.example.com",
                "logIndex": 1,
                "publisherPublicKeyPem": "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
            }],
        });
        let cfg: ModuleGroupsConfig =
            serde_json::from_value(json!([transparency_entry(value)])).expect("parse");
        let groups = parse_module_groups(&cfg).expect("validate");
        let Module::TransparencyLog { config: entry, .. } = &groups[0][0] else {
            panic!("expected TransparencyLog");
        };
        assert_eq!(entry.schema_version, "1.0.0");
        assert!(matches!(
            &entry.services[0],
            TransparencyServiceConfig::RekorV1 {
                publisher_public_key_pem: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn transparency_log_entry_validation_rejects() {
        fn entry_error(value: Value) -> String {
            let cfg: ModuleGroupsConfig =
                serde_json::from_value(json!([transparency_entry(value)])).expect("modules parse");
            format!("{:#}", parse_module_groups(&cfg).unwrap_err())
        }

        let rekor = json!({"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1});
        let artifact = json!({
            "type": "artifact-server",
            "url": "https://as",
            "logServices": [{"type": "rekor-v1", "url": "https://r"}],
        });

        // Value shape.
        assert!(entry_error(json!("not-an-object")).contains("expects an object value"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [rekor.clone()],
            "bogus": true,
        }))
        .contains("unknown field"));
        assert!(entry_error(json!({"services": [rekor.clone()]}))
            .contains("missing field `publishedMeasurements`"));

        // publishedMeasurements.
        assert!(
            entry_error(json!({"publishedMeasurements": [], "services": [rekor]}))
                .contains("publishedMeasurements must be non-empty")
        );
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.uki"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
        }))
        .contains("unsupported publishedMeasurements type"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim", "tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
        }))
        .contains("duplicate publishedMeasurements type"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["container.image.busybox", "container.image.busybox"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
        }))
        .contains("duplicate publishedMeasurements type"));

        // Any single-segment container image repository is accepted, as is the
        // rootfs measurement type.
        let accepted = json!({
            "publishedMeasurements": ["tdx.td-shim", "rootfs.cc", "container.image.busybox"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
        });
        let cfg: ModuleGroupsConfig =
            serde_json::from_value(json!([transparency_entry(accepted)])).expect("modules parse");
        assert!(parse_module_groups(&cfg).is_ok());

        for measurement_type in [
            "container.image.",
            "container.image.foo/bar",
            "container.image.foo@sha256",
            "container.image.foo:tag",
        ] {
            let error = entry_error(json!({
                "publishedMeasurements": [measurement_type],
                "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
            }));
            assert!(
                error.contains("invalid container image repository"),
                "{measurement_type}: {error}"
            );
        }

        assert!(entry_error(json!({
            "publishedMeasurements": ["com.alibabacloud.container.image.busybox"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
        }))
        .contains("unsupported publishedMeasurements type"));

        assert!(entry_error(json!({
            "publishedMeasurements": ["com.alibabacloud.rootfs.cc"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
        }))
        .contains("unsupported publishedMeasurements type"));

        let accepted_fallback = json!({
            "publishedMeasurements": ["tdx.td-shim", "container.image.busybox"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r2", "logIndex": 2}],
            "fallbackPublishedMeasurements": ["container.image.busybox"],
        });
        let cfg: ModuleGroupsConfig =
            serde_json::from_value(json!([transparency_entry(accepted_fallback)]))
                .expect("modules parse");
        assert!(parse_module_groups(&cfg).is_ok());

        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim", "container.image.busybox"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r2", "logIndex": 2}],
            "fallbackPublishedMeasurements": ["container.image.nginx"],
        }))
        .contains("not in publishedMeasurements"));

        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim", "container.image.busybox"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r2", "logIndex": 2}],
            "fallbackPublishedMeasurements": [],
        }))
        .contains("fallbackPublishedMeasurements non-empty"));

        // services.
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [],
        }))
        .contains("services must be non-empty"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [
                {"type": "artifact-server", "url": "https://as",
                 "logServices": [{"type": "rekor-v1", "url": "https://r"}]},
                {"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1},
            ],
        }))
        .contains("artifact-server must be the only primary service"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [
                {"type": "rekor-v1", "logUrl": "https://r1", "logIndex": 1},
                {"type": "rekor-v1", "logUrl": "https://r2", "logIndex": 2},
            ],
        }))
        .contains("exactly one rekor-v1 service"));

        // artifact-server field constraints.
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
        }))
        .contains("url is required"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as", "logServices": []}],
        }))
        .contains("logServices non-empty"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v2", "url": "https://r"}]}],
        }))
        .contains("type must be rekor-v1"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": ""}]}],
        }))
        .contains("url required"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [
                              {"type": "rekor-v1", "url": "https://r"},
                              {"type": "rekor-v1", "url": "https://r/"},
                          ]}],
        }))
        .contains("duplicate"));

        // rekor-v1 field constraints.
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "", "logIndex": 1}],
        }))
        .contains("logUrl required"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": -1}],
        }))
        .contains("logIndex must be >= 0"));

        // fallback pairing.
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("fallbackPublishedMeasurements requires fallbackServices"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 2}],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("only supported with an artifact-server primary"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [artifact.clone()],
            "fallbackServices": [],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("fallbackServices must be non-empty"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [
                {"type": "artifact-server", "url": "https://as2",
                 "logServices": [{"type": "rekor-v1", "url": "https://r2"}]},
            ],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("must be rekor-v1"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
            "fallbackPublishedMeasurements": ["tdx.kernel"],
        }))
        .contains("not in publishedMeasurements"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "", "logIndex": 1}],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("fallbackServices logUrl required"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": -1}],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("fallbackServices logIndex >= 0"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1}],
            "fallbackPublishedMeasurements": [],
        }))
        .contains("fallbackPublishedMeasurements non-empty"));

        // Unknown fields nested inside a service entry are rejected at load,
        // so a mistyped key cannot silently fall back to the built-in key.
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1,
                          "publisherPublicKeyPemX": "x"}],
        }))
        .contains("unknown field"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1,
                          "rekorPublicKeyPemX": "x"}],
        }))
        .contains("unknown field"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}],
                          "publisherPublicKeyPemX": "x"}],
        }))
        .contains("unknown field"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r", "urlX": "x"}]}],
        }))
        .contains("unknown field"));
        assert!(entry_error(json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}]}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1,
                                  "logUrlX": "x"}],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        }))
        .contains("unknown field"));

        // A fully specified valid configuration still parses: the strictness
        // must not reject known fields.
        let valid_rekor_entry = json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "rekor-v1", "logUrl": "https://r", "logIndex": 1,
                          "rekorPublicKeyPem": "pem", "publisherPublicKeyPem": "pem"}],
        });
        let cfg: ModuleGroupsConfig =
            serde_json::from_value(json!([transparency_entry(valid_rekor_entry)]))
                .expect("modules parse");
        assert!(parse_module_groups(&cfg).is_ok());

        let valid_artifact_entry = json!({
            "publishedMeasurements": ["tdx.td-shim"],
            "services": [{"type": "artifact-server", "url": "https://as",
                          "logServices": [{"type": "rekor-v1", "url": "https://r"}],
                          "publisherPublicKeyPem": "pem"}],
            "fallbackServices": [{"type": "rekor-v1", "logUrl": "https://r2", "logIndex": 2}],
            "fallbackPublishedMeasurements": ["tdx.td-shim"],
        });
        let cfg: ModuleGroupsConfig =
            serde_json::from_value(json!([transparency_entry(valid_artifact_entry)]))
                .expect("modules parse");
        assert!(parse_module_groups(&cfg).is_ok());
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn secure_proxy_readme_json_round_trips() {
        let json = SECURE_PROXY_ARTIFACT_SERVER_CONFIG_JSON;
        let policy: PolicyConfig = serde_json::from_str(json).expect("parse into PolicyConfig");
        let PolicyConfig::Modules { modules } = &policy else {
            panic!("fixture must be a modules policy");
        };
        parse_module_groups(modules).expect("artifact-server + fallback entry validates");
        let round = serde_json::to_string(&policy).expect("serialize");
        let reparsed: PolicyConfig = serde_json::from_str(&round).expect("re-parse");
        assert_eq!(
            serde_json::to_value(&policy).unwrap(),
            serde_json::to_value(&reparsed).unwrap(),
            "PolicyConfig must round-trip"
        );
    }

    /// A rekor-v1 primary that names more than one service is a configuration
    /// error, caught by validation before any network access.
    #[test]
    fn load_policy_rejects_multiple_rekor_v1_services() {
        let cfg_json = json!({
            "type": "modules",
            "modules": [transparency_entry(json!({
                "publishedMeasurements": ["tdx.td-shim"],
                "schemaVersion": "1.0.0",
                "services": [
                    {"type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 1},
                    {"type": "rekor-v1", "logUrl": "https://rekor.sigstore.dev", "logIndex": 2},
                ],
            }))],
        });
        let cfg: PolicyConfig = serde_json::from_value(cfg_json).unwrap();
        let PolicyConfig::Modules { modules } = &cfg else {
            panic!("expected Modules");
        };
        let err = parse_module_groups(modules).unwrap_err();
        assert!(
            format!("{err:?}").contains("exactly one rekor-v1 service"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn modules_with_transparency_rejects_reference_values() {
        let policy = PolicyConfig::Modules {
            modules: serde_json::from_value(json!([transparency_entry(artifact_entry_value(
                "https://attest.example.com",
                "https://rekor.sigstore.dev",
                None,
            ))]))
            .expect("modules config"),
        };
        let mut rvs = std::collections::HashMap::new();
        rvs.insert("measurement.tdx.ovmf".to_string(), json!(["x"]));
        let reference = ReferenceValueConfig::Sample {
            payload: SampleProvenancePayloadConfig::Inline {
                content: Provenance { rvs },
            },
        };
        let err = match BuiltinCocoConverter::new(&policy, std::slice::from_ref(&reference)).await {
            Ok(_) => panic!("external reference_values must be rejected"),
            Err(e) => e,
        };
        assert!(
            format!("{err:?}").contains("does not accept external reference_values"),
            "{err:?}"
        );
    }
}
