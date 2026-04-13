use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Context as _, Result};
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::TngError;
#[cfg(unix)]
use crate::tunnel::utils::maybe_cached::RefreshStrategy;

/// Remote Attestation configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        if let RaArgs::AttestOnly(attest_args) | RaArgs::AttestAndVerify(attest_args, _) =
            &ra_args
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
                VerifyArgs::Passport { verifier } | VerifyArgs::BackgroundCheck { verifier, .. } => {
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
                                if as_addr.is_none() && trusted_certs_paths.is_none() {
                                    return Err(TngError::InvalidParameter(anyhow!(
                                        "At least one of 'as_addr' or 'trusted_certs_paths' must be set to verify attestation token"
                                    )));
                                }

                                // Check if trusted certificate paths exist
                                if let Some(paths) = trusted_certs_paths {
                                    for path in paths {
                                        if !Path::new(path).exists() {
                                            return Err(TngError::InvalidParameter(anyhow!(
                                                "Attestation service trusted certificate path does not exist: {}",
                                                path
                                            )));
                                        }
                                    }
                                }
                            }
                            #[cfg(feature = "__builtin-as")]
                            CocoVerifierArgs::Builtin => {}
                        },
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
/// converter can use different providers (e.g., aa_provider: "ita_asr" + as_provider: "ita").
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "aa_provider", rename_all = "snake_case")]
pub enum AttesterArgs {
    Coco(CocoAttesterArgs),
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

/// Provider-tagged converter config. Serde reads "as_provider" from flat JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "as_provider", rename_all = "snake_case")]
pub enum ConverterArgs {
    Coco(CocoConverterArgs),
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
// AttestArgs / VerifyArgs -- model-level enums with custom (De)Serialize
// ---------------------------------------------------------------------------

const EVIDENCE_REFRESH_INTERVAL_SECOND: u64 = 10 * 60; // 10 minutes

/// Attestation parameters configuration enum.
/// Note: refresh_interval lives here at the model level for consistency with
/// ConverterArgs/VerifierArgs (all plain enums). If desired, it could be moved
/// into AttesterArgs via a struct wrapper at the cost of one more level of
/// indirection and inconsistency with the other *Args enums.
#[derive(Debug, Clone)]
pub enum AttestArgs {
    /// Passport mode attestation parameters
    Passport {
        attester: AttesterArgs,
        converter: ConverterArgs,
        /// Evidence refresh interval (seconds), optional
        refresh_interval: Option<u64>,
    },
    /// Background check mode attestation parameters
    BackgroundCheck {
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

impl<'de> Deserialize<'de> for AttestArgs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut value = serde_json::Value::deserialize(deserializer)?;
        if let Some(obj) = value.as_object_mut() {
            inject_provider_defaults(obj);
        }
        let model = value
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("background_check");
        match model {
            "passport" => {
                let attester: AttesterArgs =
                    serde_json::from_value(value.clone()).map_err(serde::de::Error::custom)?;
                let converter: ConverterArgs =
                    serde_json::from_value(value.clone()).map_err(serde::de::Error::custom)?;
                let refresh_interval = value.get("refresh_interval").and_then(|v| v.as_u64());
                Ok(AttestArgs::Passport {
                    attester,
                    converter,
                    refresh_interval,
                })
            }
            "background_check" => {
                let attester: AttesterArgs =
                    serde_json::from_value(value.clone()).map_err(serde::de::Error::custom)?;
                let refresh_interval = value.get("refresh_interval").and_then(|v| v.as_u64());
                Ok(AttestArgs::BackgroundCheck {
                    attester,
                    refresh_interval,
                })
            }
            other => Err(serde::de::Error::custom(format!(
                r#"unsupported value for "model": "{other}", should be one of ["background_check", "passport"]"#
            ))),
        }
    }
}

impl Serialize for AttestArgs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut obj = serde_json::Map::new();
        match self {
            AttestArgs::Passport {
                attester,
                converter,
                refresh_interval,
            } => {
                obj.insert("model".into(), "passport".into());
                merge_into(
                    &mut obj,
                    &serde_json::to_value(attester).map_err(serde::ser::Error::custom)?,
                );
                merge_into(
                    &mut obj,
                    &serde_json::to_value(converter).map_err(serde::ser::Error::custom)?,
                );
                if let Some(ri) = refresh_interval {
                    obj.insert("refresh_interval".into(), (*ri).into());
                }
            }
            AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
            } => {
                obj.insert("model".into(), "background_check".into());
                merge_into(
                    &mut obj,
                    &serde_json::to_value(attester).map_err(serde::ser::Error::custom)?,
                );
                if let Some(ri) = refresh_interval {
                    obj.insert("refresh_interval".into(), (*ri).into());
                }
            }
        }
        serde_json::Value::Object(obj).serialize(serializer)
    }
}

/// Verification parameters configuration enum.
#[derive(Debug, Clone)]
pub enum VerifyArgs {
    /// Passport mode verification parameters
    Passport { verifier: VerifierArgs },
    /// Background check mode verification parameters
    BackgroundCheck {
        converter: ConverterArgs,
        verifier: VerifierArgs,
    },
}

impl<'de> Deserialize<'de> for VerifyArgs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut value = serde_json::Value::deserialize(deserializer)?;
        if let Some(obj) = value.as_object_mut() {
            inject_provider_defaults(obj);
        }
        let model = value
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("background_check");
        match model {
            "passport" => {
                let verifier: VerifierArgs =
                    serde_json::from_value(value.clone()).map_err(serde::de::Error::custom)?;
                Ok(VerifyArgs::Passport { verifier })
            }
            "background_check" => {
                let converter: ConverterArgs =
                    serde_json::from_value(value.clone()).map_err(serde::de::Error::custom)?;
                let verifier: VerifierArgs =
                    serde_json::from_value(value.clone()).map_err(serde::de::Error::custom)?;
                Ok(VerifyArgs::BackgroundCheck {
                    converter,
                    verifier,
                })
            }
            other => Err(serde::de::Error::custom(format!(
                r#"unsupported value for "model": "{other}", should be one of ["background_check", "passport"]"#
            ))),
        }
    }
}

impl Serialize for VerifyArgs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut obj = serde_json::Map::new();
        match self {
            VerifyArgs::Passport { verifier } => {
                obj.insert("model".into(), "passport".into());
                merge_into(
                    &mut obj,
                    &serde_json::to_value(verifier).map_err(serde::ser::Error::custom)?,
                );
            }
            VerifyArgs::BackgroundCheck {
                converter,
                verifier,
            } => {
                obj.insert("model".into(), "background_check".into());
                merge_into(
                    &mut obj,
                    &serde_json::to_value(converter).map_err(serde::ser::Error::custom)?,
                );
                merge_into(
                    &mut obj,
                    &serde_json::to_value(verifier).map_err(serde::ser::Error::custom)?,
                );
            }
        }
        serde_json::Value::Object(obj).serialize(serializer)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Inject default provider tags and CoCo-specific sub-type defaults into the
/// raw JSON before delegation to derived serde. This avoids field duplication
/// that serde's MaybeTagged/try_from workarounds require, since serde has no
/// built-in "default variant when tag is missing".
fn inject_provider_defaults(obj: &mut serde_json::Map<String, serde_json::Value>) {
    obj.entry("aa_provider").or_insert("coco".into());
    obj.entry("as_provider").or_insert("coco".into());

    // Backward compat: translate as_is_grpc -> as_type for old configs
    if !obj.contains_key("as_type") {
        if obj.get("as_is_grpc").and_then(|v| v.as_bool()) == Some(true) {
            obj.insert("as_type".into(), "grpc".into());
        }
    }

    // CoCo-specific sub-type defaults
    if obj.get("aa_provider").and_then(|v| v.as_str()) == Some("coco") {
        obj.entry("aa_type").or_insert("uds".into());
    }
    if obj.get("as_provider").and_then(|v| v.as_str()) == Some("coco") {
        obj.entry("as_type").or_insert("restful".into());
    }
}

/// Merge a serde_json::Value (expected to be an Object) into a Map.
fn merge_into(target: &mut serde_json::Map<String, serde_json::Value>, source: &serde_json::Value) {
    if let serde_json::Value::Object(src) = source {
        for (k, v) in src {
            if !v.is_null() {
                target.insert(k.clone(), v.clone());
            }
        }
    }
}

// ============================================================================
// Builtin AS/AA Configuration Types
// ============================================================================

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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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
        assert!(serialized.contains(r#""as_type":"restful""#));
        assert!(serialized.contains(r#""as_addr":"localhost:8081""#));
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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");
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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");
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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");
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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Builtin {
                    policy,
                    reference_values,
                }) => {
                    match policy {
                        PolicyConfig::Inline { content } => {
                            assert_eq!(
                                content,
                                "cGFja2FnZSBwb2xpY3kKZGVmYXVsdCBhbGxvdyA9IHRydWU="
                            );
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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Builtin {
                    reference_values, ..
                }) => {
                    assert_eq!(reference_values.len(), 1);
                    match &reference_values[0] {
                        // Verify payload is inline with ReferenceValueListPayload content
                        ReferenceValueConfig::Slsa { payload } => match payload {
                            SlsaReferenceValuePayloadConfig::Inline { content } => {
                                assert_eq!(content.rv_list.len(), 1);
                                let rv = &content.rv_list[0];
                                assert_eq!(rv.id, "test-artifact");
                                assert_eq!(rv.version, "1.0.0");
                                assert_eq!(rv.rv_type, "binary");
                            }
                            _ => panic!("Expected Inline payload"),
                        },
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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::Passport {
                attester,
                converter,
                refresh_interval,
            }) => {
                assert!(matches!(attester, AttesterArgs::Coco(CocoAttesterArgs::Builtin)));
                assert_eq!(*refresh_interval, Some(600));
                match converter {
                    ConverterArgs::Coco(CocoConverterArgs::Restful {
                        as_addr,
                        policy_ids,
                        ..
                    }) => {
                        assert_eq!(as_addr, "http://as-server:8080");
                        assert_eq!(policy_ids, &vec!["default"]);
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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
            }) => {
                assert!(matches!(attester, AttesterArgs::Coco(CocoAttesterArgs::Builtin)));
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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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

        let ra_args: RaArgsUnchecked =
            serde_json::from_value(json).expect("Failed to deserialize");

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
}
