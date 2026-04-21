use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Context as _, Result};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::TngError;
#[cfg(unix)]
use crate::tunnel::utils::maybe_cached::RefreshStrategy;

// ---------------------------------------------------------------------------
// Custom Deserialize on RaArgsUnchecked
// ---------------------------------------------------------------------------
// The JSON config format mixes an optional `model` tag with provider-specific
// keys (`aa_provider`, `as_provider`, `aa_type`, `as_type`) in one flat object.
// Serde has no built-in "default variant when tag is missing", so we inject
// defaults (`model`, provider tags, sub-type tags) into the raw JSON here
// before delegating to the serde-derived `AttestArgs` / `VerifyArgs`.
//
// Compared with the previous MaybeTagged-style split (tagged + untagged
// wrapper structs with TryFrom):
// 1. Provider enums (`AttesterArgs`, `ConverterArgs`, …) use plain serde
//    derives — no field duplication across extra layers.
// 2. `AttestArgs` / `VerifyArgs` are also serde-derived (`#[serde(tag, flatten)]`)
//    — no manual Serialize/Deserialize, so the structure is self-documenting.
// 3. Default injection lives in one place (here), keeping the downstream
//    types unaware of backward-compat defaulting.

/// Remote Attestation configuration parameters
#[derive(Debug, Clone, Serialize)]
pub struct RaArgsUnchecked {
    /// Whether to disable Remote Attestation functionality
    #[serde(default = "bool::default")]
    pub no_ra: bool,

    /// Attestation parameters configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attest: Option<AttestArgs>,

    /// Verification parameters configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyArgs>,
}

impl<'de> Deserialize<'de> for RaArgsUnchecked {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        /// Mirrors `RaArgsUnchecked` but keeps `attest`/`verify` as raw JSON
        /// so we can inject tag defaults before parsing.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            no_ra: bool,
            attest: Option<serde_json::Value>,
            verify: Option<serde_json::Value>,
        }

        let raw = Raw::deserialize(deserializer)?;

        let attest = raw
            .attest
            .map(|mut v| {
                if let Some(obj) = v.as_object_mut() {
                    inject_tag_defaults(obj);
                }
                serde_json::from_value::<AttestArgs>(v)
            })
            .transpose()
            .map_err(serde::de::Error::custom)?;

        let verify = raw
            .verify
            .map(|mut v| {
                if let Some(obj) = v.as_object_mut() {
                    inject_tag_defaults(obj);
                }
                serde_json::from_value::<VerifyArgs>(v)
            })
            .transpose()
            .map_err(serde::de::Error::custom)?;

        Ok(RaArgsUnchecked {
            no_ra: raw.no_ra,
            attest,
            verify,
        })
    }
}

#[derive(Debug, Clone)]
pub enum RaArgs {
    #[cfg(unix)]
    AttestOnly(AttestArgs),
    VerifyOnly(VerifyArgs),
    #[cfg(unix)]
    AttestAndVerify(AttestArgs, VerifyArgs),
    NoRa,
}

impl RaArgsUnchecked {
    pub fn into_checked(self) -> Result<RaArgs, TngError> {
        let ra_args = if self.no_ra {
            // Sanity check
            if self.verify.is_some() {
                return Err(TngError::InvalidParameter(anyhow!(
                    "The 'no_ra: true' flag should not be used with 'verify' field"
                )));
            }

            if self.attest.is_some() {
                return Err(TngError::InvalidParameter(anyhow!(
                    "The 'no_ra: true' flag should not be used with 'attest' field"
                )));
            }

            tracing::warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment");

            RaArgs::NoRa
        } else {
            match (self.attest, self.verify) {
                (None, None) => {
                    return Err(TngError::InvalidParameter(anyhow!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_egress'")));
                }
                (None, Some(verify)) => RaArgs::VerifyOnly(verify),
                #[cfg(unix)]
                (Some(attest), None) => RaArgs::AttestOnly(attest),
                #[cfg(unix)]
                (Some(attest), Some(verify)) => RaArgs::AttestAndVerify(attest, verify),
                #[cfg(wasm)]
                (Some(..), _) => {
                    return Err(TngError::InvalidParameter(anyhow!("`attest` option is not supported since attestation is not supported on this platform.")));
                }
            }
        };

        // Sanity check for the attest_args.
        #[cfg(unix)]
        if let RaArgs::AttestOnly(attest_args) | RaArgs::AttestAndVerify(attest_args, _) = &ra_args
        {
            match &attest_args {
                AttestArgs::Passport { attester, .. }
                | AttestArgs::BackgroundCheck { attester, .. } => match attester {
                    AttesterArgs::Coco(coco_attester) => match coco_attester {
                        CocoAttesterArgs::Uds { aa_addr } => {
                            let aa_sock_file = aa_addr
                                .strip_prefix("unix:///")
                                .context("AA address must start with unix:///")
                                .map_err(TngError::InvalidParameter)?;
                            let aa_sock_file = Path::new("/").join(aa_sock_file);
                            if !Path::new(&aa_sock_file).exists() {
                                return Err(TngError::InvalidParameter(anyhow!(
                                    "AA socket file {aa_sock_file:?} not found"
                                )));
                            }
                        }
                        // Builtin AA doesn't need socket file check
                        CocoAttesterArgs::Builtin => {
                            // TODO: Builtin AA not implemented yet
                        }
                    },
                    AttesterArgs::Ita(ita) => {
                        let aa_sock_file = ita
                            .aa_addr
                            .strip_prefix("unix:///")
                            .context("AA address must start with unix:///")
                            .map_err(TngError::InvalidParameter)?;
                        let aa_sock_file = Path::new("/").join(aa_sock_file);
                        if !Path::new(&aa_sock_file).exists() {
                            return Err(TngError::InvalidParameter(anyhow!(
                                "AA socket file {aa_sock_file:?} not found"
                            )));
                        }
                    }
                },
            };
        }

        // Sanity check for the verify_args.
        {
            let verify_args = match &ra_args {
                RaArgs::VerifyOnly(verify_args) => verify_args,
                #[cfg(unix)]
                RaArgs::AttestAndVerify(_, verify_args) => verify_args,
                _ => return Ok(ra_args),
            };

            // Check token_verify
            match verify_args {
                VerifyArgs::Passport { verifier }
                | VerifyArgs::BackgroundCheck { verifier, .. } => {
                    match verifier {
                        VerifierArgs::Coco(coco_verifier) => match coco_verifier {
                            CocoVerifierArgs::Restful {
                                as_addr,
                                as_headers,
                                trusted_certs_paths,
                                ..
                            }
                            | CocoVerifierArgs::Grpc {
                                as_addr,
                                as_headers,
                                trusted_certs_paths,
                                ..
                            } => {
                                if as_addr.is_none() && !as_headers.is_empty() {
                                    return Err(TngError::InvalidParameter(anyhow!(
                                        "'as_headers' cannot be set without 'as_addr'"
                                    )));
                                }

                                // Additional checks for Passport mode
                                if matches!(verify_args, VerifyArgs::Passport { .. })
                                    && as_addr.is_none()
                                    && trusted_certs_paths.is_none()
                                {
                                    return Err(TngError::InvalidParameter(anyhow!("At least one of 'as_addr' or 'trusted_certs_paths' must be set to verify attestation token")));
                                }

                                if let Some(paths) = trusted_certs_paths {
                                    for path in paths {
                                        if !Path::new(path).exists() {
                                            return Err(TngError::InvalidParameter(anyhow!("Attestation service trusted certificate path does not exist: {}", path)));
                                        }
                                    }
                                }
                            }
                            #[cfg(feature = "__builtin-as")]
                            CocoVerifierArgs::Builtin => {}
                        },
                        VerifierArgs::Ita(_) => {
                            // ITA verifier fetches JWKS from the portal URL; no additional checks needed here
                        }
                    }
                }
            };

            // Check if as_addr is a valid URL (for Restful/Grpc types)
            // or validate builtin configuration
            if let VerifyArgs::BackgroundCheck { converter, .. } = verify_args {
                match converter {
                    ConverterArgs::Coco(coco_converter) => match coco_converter {
                        CocoConverterArgs::Restful { as_addr, .. }
                        | CocoConverterArgs::Grpc { as_addr, .. } => {
                            Url::parse(as_addr)
                                .with_context(|| {
                                    format!("Invalid attestation service address: {}", as_addr)
                                })
                                .map_err(TngError::InvalidParameter)?;
                        }
                        // Validate builtin configuration
                        #[cfg(feature = "__builtin-as")]
                        CocoConverterArgs::Builtin {
                            policy,
                            reference_values,
                        } => {
                            use rats_cert::cert::verify::{
                                PolicyConfig, ReferenceValueConfig, SampleProvenancePayloadConfig,
                            };
                            // Check policy path exists if using Path variant
                            if let PolicyConfig::Path { path } = policy {
                                if !Path::new(path).exists() {
                                    return Err(TngError::InvalidParameter(anyhow!(
                                        "Policy file path does not exist: {}",
                                        path
                                    )));
                                }
                            }

                            // Check reference value payload paths
                            for rv in reference_values {
                                if let ReferenceValueConfig::Sample {
                                    payload: SampleProvenancePayloadConfig::Path { path },
                                } = rv
                                {
                                    if !Path::new(path).exists() {
                                        return Err(TngError::InvalidParameter(anyhow!(
                                            "Reference value payload file path does not exist: {}",
                                            path
                                        )));
                                    }
                                }
                            }
                        }
                    },
                    ConverterArgs::Ita(ita) => {
                        Url::parse(&ita.as_addr)
                            .with_context(|| format!("Invalid ITA API address: {}", ita.as_addr))
                            .map_err(TngError::InvalidParameter)?;
                        if ita.api_key.is_none() {
                            return Err(TngError::InvalidParameter(anyhow!(
                                "ITA api_key is required: set it in config or via ${} env var",
                                ITA_API_KEY_ENV
                            )));
                        }
                    }
                }
            }
        }
        Ok(ra_args)
    }
}

// ---------------------------------------------------------------------------
// Provider-tagged config enums (serde-derived)
// ---------------------------------------------------------------------------

/// Provider-tagged attester config. Serde reads "aa_provider" from flat JSON.
/// Separate from as_provider because in Passport mode the attester and
/// converter can use different providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "aa_provider", rename_all = "snake_case")]
pub enum AttesterArgs {
    Coco(CocoAttesterArgs),
    Ita(ItaAttesterArgs),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItaAttesterArgs {
    /// Attestation agent address (unix socket path). ITA reuses CoCo AA via ttrpc.
    pub aa_addr: String,
}

#[cfg(unix)]
impl ItaAttesterArgs {
    pub fn to_attester(&self) -> anyhow::Result<rats_cert::tee::ita::ItaAttester> {
        rats_cert::tee::ita::ItaAttester::new(&self.aa_addr).map_err(Into::into)
    }
}

/// CoCo-internal attester variants. Serde reads "aa_type" from flat JSON.
/// Default is Uds when aa_type is omitted (injected by custom Deserialize).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "aa_type", rename_all = "snake_case")]
pub enum CocoAttesterArgs {
    /// Unix Domain Socket
    Uds {
        /// Attestation agent address (unix socket path)
        aa_addr: String,
    },
    /// Builtin AA (embedded) - not implemented yet
    Builtin,
}

const DEFAULT_ITA_API_URL: &str = "https://api.trustauthority.intel.com";
const DEFAULT_ITA_PORTAL_URL: &str = "https://portal.trustauthority.intel.com";
const ITA_API_KEY_ENV: &str = "ITA_API_KEY";

fn default_ita_api_url() -> String {
    DEFAULT_ITA_API_URL.to_string()
}

fn default_ita_portal_url() -> String {
    DEFAULT_ITA_PORTAL_URL.to_string()
}

/// Provider-tagged converter config. Serde reads "as_provider" from flat JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "as_provider", rename_all = "snake_case")]
pub enum ConverterArgs {
    Coco(CocoConverterArgs),
    Ita(ItaConverterArgs),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ItaConverterArgs {
    #[serde(default = "default_ita_api_url")]
    pub as_addr: String,
    /// Optional in config JSON -- if absent, `inject_ita_api_key_default()` fills
    /// it from the `$ITA_API_KEY` env var during deserialization.
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub policy_ids: Vec<String>,
}

/// Manual impl to redact `api_key` from debug/log output.
impl std::fmt::Debug for ItaConverterArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItaConverterArgs")
            .field("as_addr", &self.as_addr)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("policy_ids", &self.policy_ids)
            .finish()
    }
}

impl ItaConverterArgs {
    pub fn to_converter(&self) -> anyhow::Result<rats_cert::tee::ita::ItaConverter> {
        let api_key = self
            .api_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("ITA api_key is required but not set"))?;
        rats_cert::tee::ita::ItaConverter::new(api_key, &self.as_addr, &self.policy_ids)
            .map_err(Into::into)
    }
}

/// CoCo-internal converter variants. Serde reads "as_type" from flat JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "as_type", rename_all = "snake_case")]
pub enum CocoConverterArgs {
    /// Restful API
    Restful {
        /// Attestation service address
        as_addr: String,
        /// Policy ID list
        #[serde(default)]
        policy_ids: Vec<String>,
        /// Custom headers to be sent with attestation service requests
        #[serde(default)]
        as_headers: HashMap<String, String>,
    },
    /// gRPC API
    Grpc {
        /// Attestation service address
        as_addr: String,
        /// Policy ID list
        #[serde(default)]
        policy_ids: Vec<String>,
        /// Custom headers to be sent with attestation service requests
        #[serde(default)]
        as_headers: HashMap<String, String>,
    },
    /// Builtin AS (embedded)
    #[cfg(feature = "__builtin-as")]
    Builtin {
        /// OPA policy configuration
        policy: rats_cert::cert::verify::PolicyConfig,
        /// Reference value configurations
        #[serde(default)]
        reference_values: Vec<rats_cert::cert::verify::ReferenceValueConfig>,
    },
}

/// Provider-tagged verifier config. Serde reads "as_provider" from flat JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "as_provider", rename_all = "snake_case")]
pub enum VerifierArgs {
    Coco(CocoVerifierArgs),
    Ita(ItaVerifierArgs),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItaVerifierArgs {
    #[serde(default = "default_ita_portal_url")]
    pub ita_jwks_addr: String,
    #[serde(default)]
    pub policy_ids: Vec<String>,
}

impl ItaVerifierArgs {
    pub fn to_verifier(&self) -> anyhow::Result<rats_cert::tee::ita::ItaVerifier> {
        rats_cert::tee::ita::ItaVerifier::new(&self.ita_jwks_addr, &self.policy_ids)
            .map_err(Into::into)
    }
}

/// CoCo-internal verifier variants. Serde reads "as_type" from flat JSON.
/// Mirrors CocoConverterArgs structure. as_addr is Optional because verifier
/// can work with just trusted_certs_paths (local cert trust) without AS.
/// Invariant: if as_addr is None, as_headers must be empty (checked in into_checked).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "as_type", rename_all = "snake_case")]
pub enum CocoVerifierArgs {
    /// Restful API
    Restful {
        /// Attestation service address, used for fetching AS certificate (optional)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        as_addr: Option<String>,
        /// Policy ID list
        policy_ids: Vec<String>,
        /// Custom headers to be sent with attestation service requests
        #[serde(default)]
        as_headers: HashMap<String, String>,
        /// Trusted certificate paths list (optional)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_certs_paths: Option<Vec<String>>,
    },
    /// gRPC API
    Grpc {
        /// Attestation service address, used for fetching AS certificate (optional)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        as_addr: Option<String>,
        /// Policy ID list
        policy_ids: Vec<String>,
        /// Custom headers to be sent with attestation service requests
        #[serde(default)]
        as_headers: HashMap<String, String>,
        /// Trusted certificate paths list (optional)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_certs_paths: Option<Vec<String>>,
    },
    /// Builtin AS (embedded)
    #[cfg(feature = "__builtin-as")]
    Builtin,
}

// ---------------------------------------------------------------------------
// AttestArgs / VerifyArgs (serde-derived)
// ---------------------------------------------------------------------------

#[cfg(unix)]
const EVIDENCE_REFRESH_INTERVAL_SECOND: u64 = 10 * 60; // 10 minutes

/// Attestation parameters configuration enum.
/// Note: refresh_interval lives here at the model level for consistency with
/// ConverterArgs/VerifierArgs (all plain enums). If desired, it could be moved
/// into AttesterArgs via a struct wrapper at the cost of one more level of
/// indirection and inconsistency with the ConverterArgs/VerifierArgs enums.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "model", rename_all = "snake_case")]
pub enum AttestArgs {
    /// Passport mode attestation parameters
    Passport {
        #[serde(flatten)]
        attester: AttesterArgs,
        #[serde(flatten)]
        converter: ConverterArgs,
        /// Evidence refresh interval (seconds), optional
        refresh_interval: Option<u64>,
    },
    /// Background check mode attestation parameters
    BackgroundCheck {
        #[serde(flatten)]
        attester: AttesterArgs,
        /// Evidence refresh interval (seconds), optional
        refresh_interval: Option<u64>,
    },
}

#[cfg(unix)]
impl AttestArgs {
    pub fn refresh_strategy(&self) -> RefreshStrategy {
        let interval = match self {
            Self::Passport {
                refresh_interval, ..
            }
            | Self::BackgroundCheck {
                refresh_interval, ..
            } => refresh_interval.unwrap_or(EVIDENCE_REFRESH_INTERVAL_SECOND),
        };
        if interval == 0 {
            RefreshStrategy::Always
        } else {
            RefreshStrategy::Periodically { interval }
        }
    }
}

/// Verification parameters configuration enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "model", rename_all = "snake_case")]
pub enum VerifyArgs {
    /// Passport mode verification parameters
    Passport {
        #[serde(flatten)]
        verifier: VerifierArgs,
    },
    /// Background check mode verification parameters
    BackgroundCheck {
        #[serde(flatten)]
        converter: ConverterArgs,
        #[serde(flatten)]
        verifier: VerifierArgs,
    },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Inject default tag values into raw JSON before delegation to serde-derived
/// deserializers. Covers the `model` discriminator, provider tags
/// (`aa_provider`/`as_provider`), and CoCo-specific sub-type tags
/// (`aa_type`/`as_type`) so that omitting any of them gives
/// backward-compatible defaults.
fn inject_tag_defaults(obj: &mut serde_json::Map<String, serde_json::Value>) {
    obj.entry("model").or_insert("background_check".into());
    obj.entry("aa_provider").or_insert("coco".into());
    obj.entry("as_provider").or_insert("coco".into());

    // CoCo-specific sub-type defaults
    if obj.get("aa_provider").and_then(|v| v.as_str()) == Some("coco") {
        obj.entry("aa_type").or_insert("uds".into());
    }
    if obj.get("as_provider").and_then(|v| v.as_str()) == Some("coco") {
        obj.entry("as_type").or_insert("restful".into());
    }

    // ITA: inject api_key from environment variable if not present in config
    if obj.get("as_provider").and_then(|v| v.as_str()) == Some("ita") {
        inject_ita_api_key_default(obj);
    }
}

/// Fill `api_key` from `$ITA_API_KEY` env var if it's absent or null in the config.
fn inject_ita_api_key_default(obj: &mut serde_json::Map<String, serde_json::Value>) {
    let has_key = obj
        .get("api_key")
        .map(|v| !v.is_null() && v.as_str() != Some(""))
        .unwrap_or(false);
    if !has_key {
        if let Ok(env_key) = std::env::var(ITA_API_KEY_ENV) {
            if !env_key.is_empty() {
                obj.insert("api_key".into(), serde_json::Value::String(env_key));
            }
        }
    }
}

// ============================================================================
// Builtin AS/AA Configuration Types
// ============================================================================

// Re-export config types from rats-cert to ensure consistency
#[cfg(feature = "__builtin-as")]
pub use rats_cert::cert::verify::{
    PolicyConfig, ReferenceValueConfig, SampleProvenancePayloadConfig,
    SlsaReferenceValuePayloadConfig,
};

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_background_check_attest_without_model() {
        let json = json!(
            {
                "attest": {
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
            }) => {
                match attester {
                    AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }) => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Coco/Uds variant"),
                }
                assert_eq!(*refresh_interval, Some(3600));
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""aa_type":"uds""#));
        assert!(serialized.contains(r#""aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock""#));
        assert!(serialized.contains(r#""refresh_interval":3600"#));
    }

    #[test]
    fn test_background_check_attest_with_model() {
        let json = json!(
            {
                "attest": {
                    "model": "background_check",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
            }) => {
                match attester {
                    AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }) => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Coco/Uds variant"),
                }
                assert_eq!(*refresh_interval, Some(3600));
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_attest() {
        let json = json!(
            {
                "attest": {
                    "model": "passport",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600,
                    "as_addr": "localhost:8081",
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::Passport {
                attester,
                converter,
                refresh_interval,
            }) => {
                match attester {
                    AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }) => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Coco/Uds variant"),
                }
                assert_eq!(*refresh_interval, Some(3600));
                match converter {
                    ConverterArgs::Coco(CocoConverterArgs::Restful {
                        as_addr,
                        policy_ids,
                        ..
                    }) => {
                        assert_eq!(as_addr, "localhost:8081");
                        assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
                    }
                    _ => panic!("Expected Coco/Restful converter"),
                }
            }
            _ => panic!("Expected Passport variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"passport""#));
        assert!(serialized.contains(r#""aa_type":"uds""#));
        assert!(serialized.contains(r#""aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock""#));
        assert!(serialized.contains(r#""as_type":"restful""#));
        assert!(serialized.contains(r#""as_addr":"localhost:8081""#));
        assert!(serialized.contains(r#""policy_ids":["policy1","policy2"]"#));
    }

    #[test]
    #[should_panic]
    fn test_attest_bad_model() {
        let json = json!(
            {
                "attest": {
                    "model": "foobar",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_passport_attest_missing_fields() {
        let json = json!(
            {
                "attest": {
                    "model": "passport",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_verify_bad_model() {
        let json = json!(
            {
                "verify": {
                    "model": "foobar",
                    "as_addr": "localhost:8081",
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_passport_verify_missing_fields() {
        let json = json!(
            {
                "verify": {
                    "model": "passport",
                    "as_addr": "localhost:8081"
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }
    #[test]
    fn test_background_check_verify_without_model() {
        let json = json!(
            {
                "verify": {
                    "as_addr": "localhost:8081",
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Restful {
                    as_addr,
                    policy_ids,
                    ..
                }) => {
                    assert_eq!(as_addr, "localhost:8081");
                    assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
                }
                _ => panic!("Expected Coco/Restful converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_background_check_verify_with_model() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "localhost:8081",
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Restful {
                    as_addr,
                    policy_ids,
                    ..
                }) => {
                    assert_eq!(as_addr, "localhost:8081");
                    assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
                }
                _ => panic!("Expected Coco/Restful converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_verify() {
        let json = json!(
            {
                "verify": {
                    "model": "passport",
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::Passport { verifier }) => match verifier {
                VerifierArgs::Coco(CocoVerifierArgs::Restful { policy_ids, .. }) => {
                    assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
                }
                _ => panic!("Expected Coco/Restful verifier"),
            },
            _ => panic!("Expected Passport variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"passport""#));
        assert!(serialized.contains(r#""policy_ids":["policy1","policy2"]"#));
    }

    #[test]
    fn test_passport_verify_with_invalid_cert_path() {
        let json = json!(
            {
                "verify": {
                    "model": "passport",
                    "policy_ids": ["policy1"],
                    "trusted_certs_paths": ["/path/that/does/not/exist/cert.pem"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            format!("{error:?}").contains("trusted certificate path does not exist"),
            "{error:?}"
        );
    }

    #[test]
    fn test_background_check_verify_with_invalid_cert_path() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "http://localhost:8080",
                    "policy_ids": ["policy1"],
                    "trusted_certs_paths": ["/path/that/does/not/exist/cert.pem"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            format!("{error:?}").contains("trusted certificate path does not exist"),
            "{error:?}"
        );
    }

    #[test]
    fn test_background_check_verify_with_invalid_as_addr() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "not-a-valid-url",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            format!("{error:?}").contains("Invalid attestation service address"),
            "{error:?}"
        );
    }

    #[test]
    fn test_background_check_verify_with_valid_as_addr() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "<should-be-a-url>:<should-be-a-port-number>",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value::<RaArgsUnchecked>(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            format!("{error:?}").contains("Invalid attestation service address"),
            "{error:?}"
        );
    }

    // =====================================================================
    // Builtin mode tests
    // =====================================================================

    #[cfg(feature = "__builtin-as")]
    #[test]
    fn test_builtin_verify_with_inline_policy() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_type": "builtin",
                    "policy": {
                        "type": "inline",
                        "content": "cGFja2FnZSBwb2xpY3kKZGVmYXVsdCBhbGxvdyA9IHRydWU="
                    },
                    "reference_values": []
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Builtin {
                    policy,
                    reference_values,
                }) => {
                    match policy {
                        PolicyConfig::Inline { content } => {
                            assert_eq!(content, "cGFja2FnZSBwb2xpY3kKZGVmYXVsdCBhbGxvdyA9IHRydWU=");
                        }
                        _ => panic!("Expected Inline policy"),
                    }
                    assert!(reference_values.is_empty());
                }
                _ => panic!("Expected Coco/Builtin converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"background_check""#));
        assert!(serialized.contains(r#""as_type":"builtin""#));
    }

    #[cfg(feature = "__builtin-as")]
    #[test]
    fn test_builtin_verify_with_path_policy() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_type": "builtin",
                    "policy": {
                        "type": "path",
                        "path": "/path/to/policy.rego"
                    },
                    "reference_values": []
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Builtin { policy, .. }) => match policy {
                    PolicyConfig::Path { path } => {
                        assert_eq!(path, "/path/to/policy.rego");
                    }
                    _ => panic!("Expected Path policy"),
                },
                _ => panic!("Expected Coco/Builtin converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[cfg(feature = "__builtin-as")]
    #[test]
    fn test_builtin_verify_with_sample_reference() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_type": "builtin",
                    "policy": {
                        "type": "inline",
                        "content": "cGFja2FnZQ=="
                    },
                    "reference_values": [
                        {
                            "type": "sample",
                            "payload": {
                                "type": "path",
                                "path": "/path/to/payload.json"
                            }
                        }
                    ]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Builtin {
                    reference_values, ..
                }) => {
                    assert_eq!(reference_values.len(), 1);
                    match &reference_values[0] {
                        ReferenceValueConfig::Sample { payload } => match payload {
                            SampleProvenancePayloadConfig::Path { path } => {
                                assert_eq!(path, "/path/to/payload.json");
                            }
                            _ => panic!("Expected Path payload"),
                        },
                        _ => panic!("Expected Sample reference value"),
                    }
                }
                _ => panic!("Expected Coco/Builtin converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[cfg(feature = "__builtin-as")]
    #[test]
    fn test_builtin_verify_with_slsa_reference() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_type": "builtin",
                    "policy": {
                        "type": "inline",
                        "content": "cGFja2FnZQ=="
                    },
                    "reference_values": [
                        {
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
                        }
                    ]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Builtin {
                    reference_values, ..
                }) => {
                    assert_eq!(reference_values.len(), 1);
                    match &reference_values[0] {
                        ReferenceValueConfig::Slsa { payload } => {
                            // Verify payload is inline with ReferenceValueListPayload content
                            match payload {
                                SlsaReferenceValuePayloadConfig::Inline { content } => {
                                    assert_eq!(content.rv_list.len(), 1);
                                    let rv = &content.rv_list[0];
                                    assert_eq!(rv.id, "test-artifact");
                                    assert_eq!(rv.version, "1.0.0");
                                    assert_eq!(rv.rv_type, "binary");
                                    assert_eq!(
                                        rv.provenance_info.provenance_type,
                                        "slsa-intoto-statements"
                                    );
                                    assert_eq!(
                                        rv.provenance_info.rekor_url,
                                        "https://log2025-1.rekor.sigstore.dev"
                                    );
                                    assert_eq!(rv.provenance_info.rekor_api_version, Some(2));
                                    assert!(rv.provenance_source.is_some());
                                    let ps = rv.provenance_source.as_ref().unwrap();
                                    assert_eq!(ps.protocol, "oci");
                                    assert_eq!(
                                        ps.uri,
                                        "oci://127.0.0.1:5000/trustee/provenance:test-artifact-1.0.0"
                                    );
                                    assert_eq!(ps.artifact, Some("bundle".to_string()));
                                }
                                _ => panic!("Expected Inline payload"),
                            }
                        }
                        _ => panic!("Expected Slsa reference value"),
                    }
                }
                _ => panic!("Expected Coco/Builtin converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[cfg(feature = "__builtin-as")]
    #[test]
    fn test_attest_passport_builtin() {
        let json = json!(
            {
                "attest": {
                    "model": "passport",
                    "aa_type": "builtin",
                    "refresh_interval": 600,
                    "as_type": "restful",
                    "as_addr": "http://as-server:8080",
                    "policy_ids": ["default"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::Passport {
                attester,
                converter,
                refresh_interval,
            }) => {
                assert!(matches!(
                    attester,
                    AttesterArgs::Coco(CocoAttesterArgs::Builtin)
                ));
                assert_eq!(*refresh_interval, Some(600));
                match converter {
                    ConverterArgs::Coco(CocoConverterArgs::Restful { as_addr, .. }) => {
                        assert_eq!(as_addr, "http://as-server:8080");
                    }
                    _ => panic!("Expected Coco/Restful converter"),
                }
            }
            _ => panic!("Expected Passport variant with builtin AA"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"passport""#));
        assert!(serialized.contains(r#""aa_type":"builtin""#));
    }

    #[cfg(feature = "__builtin-as")]
    #[test]
    fn test_attest_builtin() {
        let json = json!(
            {
                "attest": {
                    "model": "background_check",
                    "aa_type": "builtin",
                    "refresh_interval": 300
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
            }) => {
                assert!(matches!(
                    attester,
                    AttesterArgs::Coco(CocoAttesterArgs::Builtin)
                ));
                assert_eq!(*refresh_interval, Some(300));
            }
            _ => panic!("Expected BackgroundCheck variant with builtin AA"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"background_check""#));
        assert!(serialized.contains(r#""aa_type":"builtin""#));
    }

    #[test]
    fn test_new_format_attest_with_aa_type_uds() {
        // New format: explicit aa_type="uds"
        let json = json!(
            {
                "attest": {
                    "aa_type": "uds",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
            }) => {
                match attester {
                    AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }) => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Coco/Uds variant"),
                }
                assert_eq!(*refresh_interval, Some(3600));
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""aa_type":"uds""#));
    }

    #[test]
    fn test_new_format_verify_with_as_type_restful() {
        // New format: explicit as_type="restful"
        let json = json!(
            {
                "verify": {
                    "as_type": "restful",
                    "as_addr": "http://localhost:8080",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Restful {
                    as_addr,
                    policy_ids,
                    ..
                }) => {
                    assert_eq!(as_addr, "http://localhost:8080");
                    assert_eq!(policy_ids, &vec!["policy1"]);
                }
                _ => panic!("Expected Coco/Restful converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""as_type":"restful""#));
    }

    #[test]
    fn test_new_format_verify_with_as_type_grpc() {
        // New format: explicit as_type="grpc"
        let json = json!(
            {
                "verify": {
                    "as_type": "grpc",
                    "as_addr": "http://localhost:5000",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Grpc { as_addr, .. }) => {
                    assert_eq!(as_addr, "http://localhost:5000");
                }
                _ => panic!("Expected Coco/Grpc converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""as_type":"grpc""#));
    }

    #[cfg(feature = "__builtin-as")]
    #[test]
    fn test_new_format_verify_with_as_type_builtin() {
        // New format: explicit as_type="builtin"
        let json = json!(
            {
                "verify": {
                    "as_type": "builtin",
                    "policy": {
                        "type": "default"
                    },
                    "reference_values": [],
                    "policy_ids": ["default"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Builtin {
                    policy,
                    reference_values,
                }) => {
                    assert!(matches!(policy, PolicyConfig::Default));
                    assert!(reference_values.is_empty());
                }
                _ => panic!("Expected Coco/Builtin converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""as_type":"builtin""#));
    }

    // =====================================================================
    // ITA mode tests
    // =====================================================================

    #[test]
    fn test_ita_attest_config_passport() {
        let aa_addr = "unix:///tmp/ita-aa.sock";
        let as_addr = "https://api.trustauthority.intel.com";
        let api_key = "test-key";
        let json = json!({
            "attest": {
                "model": "passport",
                "aa_provider": "ita",
                "aa_addr": aa_addr,
                "as_provider": "ita",
                "as_addr": as_addr,
                "api_key": api_key
            }
        });

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::Passport {
                attester,
                converter,
                ..
            }) => {
                match attester {
                    AttesterArgs::Ita(ita) => {
                        assert_eq!(ita.aa_addr, aa_addr);
                    }
                    _ => panic!("Expected Ita attester"),
                }
                match converter {
                    ConverterArgs::Ita(ita) => {
                        assert_eq!(ita.as_addr, as_addr);
                        assert_eq!(ita.api_key, Some(api_key.to_string()));
                    }
                    _ => panic!("Expected Ita converter"),
                }
            }
            _ => panic!("Expected Passport attest variant"),
        }
    }

    #[test]
    fn test_ita_attest_config_background_check() {
        let aa_addr = "unix:///tmp/ita-aa.sock";
        let json = json!({
            "attest": {
                "aa_provider": "ita",
                "aa_addr": aa_addr
            }
        });

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck { attester, .. }) => match attester {
                AttesterArgs::Ita(ita) => {
                    assert_eq!(ita.aa_addr, aa_addr);
                }
                _ => panic!("Expected Ita attester"),
            },
            _ => panic!("Expected BackgroundCheck attest variant"),
        }
    }

    #[test]
    fn test_ita_background_check_verify_config() {
        let as_addr = "https://api.trustauthority.intel.com";
        let api_key = "test-key-123";
        let policy_ids = vec!["policy-1"];
        let json = json!({
            "verify": {
                "model": "background_check",
                "as_provider": "ita",
                "as_addr": as_addr,
                "api_key": api_key,
                "policy_ids": policy_ids
            }
        });

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck {
                converter,
                verifier,
            }) => {
                match converter {
                    ConverterArgs::Ita(ita) => {
                        assert_eq!(ita.as_addr, as_addr);
                        assert_eq!(ita.api_key, Some(api_key.to_string()));
                        assert_eq!(ita.policy_ids, policy_ids);
                    }
                    _ => panic!("Expected Ita converter"),
                }
                match verifier {
                    VerifierArgs::Ita(ita) => {
                        assert_eq!(ita.ita_jwks_addr, DEFAULT_ITA_PORTAL_URL);
                        assert_eq!(ita.policy_ids, policy_ids);
                    }
                    _ => panic!("Expected Ita verifier"),
                }
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_ita_passport_verify_config() {
        let jwks_addr = "https://portal.custom.intel.com";
        let policy_ids = vec!["my-policy"];
        let json = json!({
            "verify": {
                "model": "passport",
                "as_provider": "ita",
                "ita_jwks_addr": jwks_addr,
                "policy_ids": policy_ids
            }
        });

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::Passport { verifier }) => match verifier {
                VerifierArgs::Ita(ita) => {
                    assert_eq!(ita.ita_jwks_addr, jwks_addr);
                    assert_eq!(ita.policy_ids, policy_ids);
                }
                _ => panic!("Expected Ita verifier"),
            },
            _ => panic!("Expected Passport variant"),
        }
    }

    #[test]
    fn test_ita_api_key_defaults_from_env() {
        let env_key = "env-key-456";
        let json = json!({
            "verify": {
                "model": "background_check",
                "as_provider": "ita"
            }
        });

        std::env::set_var(ITA_API_KEY_ENV, env_key);
        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        std::env::remove_var(ITA_API_KEY_ENV);

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Ita(ita) => {
                    assert_eq!(ita.as_addr, DEFAULT_ITA_API_URL);
                    assert_eq!(ita.api_key, Some(env_key.to_string()));
                }
                _ => panic!("Expected Ita converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_ita_config_serde_round_trip() {
        let as_addr = "https://api.trustauthority.intel.com";
        let api_key = "test-key";
        let policy_ids = vec!["p1"];
        let json = json!({
            "verify": {
                "model": "background_check",
                "as_provider": "ita",
                "as_addr": as_addr,
                "api_key": api_key,
                "policy_ids": policy_ids
            }
        });

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        let back: RaArgsUnchecked =
            serde_json::from_str(&serialized).expect("Failed to re-deserialize");

        match &back.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Ita(ita) => {
                    assert_eq!(ita.as_addr, as_addr);
                    assert_eq!(ita.api_key, Some(api_key.to_string()));
                    assert_eq!(ita.policy_ids, policy_ids);
                }
                _ => panic!("Expected Ita converter after round-trip"),
            },
            _ => panic!("Expected BackgroundCheck after round-trip"),
        }
    }

    #[test]
    fn test_ita_verify_into_checked_rejects_missing_api_key() {
        std::env::remove_var(ITA_API_KEY_ENV);
        let json = json!({
            "verify": {
                "model": "background_check",
                "as_provider": "ita"
            }
        });
        let ra: RaArgsUnchecked = serde_json::from_value(json).unwrap();
        ra.into_checked()
            .expect_err("should reject missing api_key");
    }

    #[test]
    fn test_ita_verify_into_checked_rejects_invalid_as_addr() {
        let json = json!({
            "verify": {
                "model": "background_check",
                "as_provider": "ita",
                "as_addr": "not a url",
                "api_key": "key"
            }
        });
        let ra: RaArgsUnchecked = serde_json::from_value(json).unwrap();
        assert!(ra.into_checked().is_err());
    }
}
