//! Shared builtin-AS configuration types.
//!
//! These enums are compiled for both the native trustee-backed builtin-AS
//! (`__builtin-as` feature) and the wasm pure-Rust builtin-AS (`__builtin-as-wasm`
//! feature). Inline payloads are typed as `serde_json::Value` (not as trustee types
//! like `Provenance`) so the wasm path — which cannot depend on
//! `reference-value-provider-service` — can still parse the same config surface.
//!
//! The native `builtin.rs` converts the `serde_json::Value` payloads back into the
//! concrete trustee types (`Provenance` / `ReferenceValueListPayload`) at the
//! attestation-service call site via `serde_json::from_value`.

use serde::{Deserialize, Serialize};

/// Configuration for policy loading.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyConfig {
    /// Use the attestation-service default policy (the trustee
    /// `ear_default_policy_cpu.rego`): a comprehensive appraisal that checks
    /// hardware, boot measurements, configuration and filesystem against
    /// configured reference values. Suited to deployments where those
    /// reference values are available and mandatory.
    /// See: https://github.com/openanolis/trustee/blob/7a6a7b8a2554295bcd296963d353761eaf4f70eb/attestation-service/src/token/ear_default_policy_cpu.rego
    ///
    /// On the wasm builtin-AS this degrades to `HardwareOnly` (no regorus policy
    /// engine is compiled for wasm).
    HardwareWithReferenceValues,
    /// tng-bundled template: only hardware TEE recognition is enforced; the
    /// other three trustworthiness dimensions are affirming by default and
    /// `data.reference` is ignored. This is the default policy, suited to
    /// general-purpose deployments that only need to assert the hardware TEE.
    /// On wasm this degrades to TrustAll (no TEE verifier is compiled for wasm).
    #[default]
    #[serde(alias = "default")]
    HardwareOnly,
    /// tng-bundled template: every trustworthiness dimension is affirming
    /// regardless of input. **For development and testing only.**
    TrustAll,
    /// Base64 encoded policy content (native only — needs regorus policy engine).
    Inline { content: String },
    /// Path to policy file (native only — needs a filesystem).
    Path { path: String },
}

/// Inline reference-value payload (a JSON `Value` so it parses on wasm too).
///
/// The native `builtin.rs` converts the `content` `Value` into the concrete
/// trustee type (`Provenance` / `ReferenceValueListPayload`) via
/// `serde_json::from_value` before calling the attestation-service API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReferenceValuePayloadConfig {
    /// Inline JSON content
    Inline { content: serde_json::Value },
    /// Path to payload file (native only — needs a filesystem)
    Path { path: String },
}

/// Configuration for reference values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReferenceValueConfig {
    /// Sample reference values (inline or from file)
    Sample {
        payload: ReferenceValuePayloadConfig,
    },
    /// SLSA-based reference values from Rekor
    Slsa {
        payload: ReferenceValuePayloadConfig,
    },
    /// RV release manifest-based reference values
    ReleaseManifest {
        payload: ReferenceValuePayloadConfig,
    },
}
