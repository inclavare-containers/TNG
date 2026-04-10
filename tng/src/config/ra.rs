use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Context as _, Result};
use rats_cert::cert::verify::AttestationServiceAddrArgs;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{error::TngError, tunnel::utils::maybe_cached::RefreshStrategy};

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
        if let RaArgs::AttestOnly(attest_args) | RaArgs::AttestAndVerify(attest_args, _) = &ra_args
        {
            match &attest_args {
                AttestArgs::Passport {
                    aa_args: AttestationAgentArgs { aa_type, .. },
                    ..
                }
                | AttestArgs::BackgroundCheck {
                    aa_args: AttestationAgentArgs { aa_type, .. },
                } => {
                    match aa_type {
                        AttestationAgentType::Uds { aa_addr } => {
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
                        AttestationAgentType::Builtin => {
                            // TODO: Builtin AA not implemented yet
                        }
                    }
                }
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
                VerifyArgs::Passport {
                    token_verify:
                        AttestationServiceTokenVerifyArgs {
                            trusted_certs_paths,
                            ..
                        },
                }
                | VerifyArgs::BackgroundCheck {
                    token_verify:
                        AttestationServiceTokenVerifyAdditionalArgs {
                            trusted_certs_paths,
                            ..
                        },
                    ..
                } => {
                    // Additional checks for Passport mode
                    let has_as_addr = if let VerifyArgs::Passport {
                        token_verify: AttestationServiceTokenVerifyArgs { as_addr_config, .. },
                    } = verify_args
                    {
                        as_addr_config.is_some()
                    } else {
                        true
                    };

                    if !has_as_addr && trusted_certs_paths.is_none() {
                        return Err(TngError::InvalidParameter(anyhow!("At least one of 'as_addr' or 'trusted_certs_paths' must be set to verify attestation token")));
                    }

                    // Check if trusted certificate paths exist
                    if let Some(paths) = &trusted_certs_paths {
                        for path in paths {
                            if !Path::new(path).exists() {
                                return Err(TngError::InvalidParameter(anyhow!("Attestation service trusted certificate path does not exist: {}", path)));
                            }
                        }
                    }
                }
            };

            // Check if as_addr is a valid URL (for Restful/Grpc types)
            // or validate builtin configuration
            if let VerifyArgs::BackgroundCheck { as_args, .. } = verify_args {
                match &as_args.as_type {
                    AttestationServiceType::Restful { as_addr, .. }
                    | AttestationServiceType::Grpc { as_addr, .. } => {
                        Url::parse(as_addr)
                            .with_context(|| {
                                format!("Invalid attestation service address: {}", as_addr)
                            })
                            .map_err(TngError::InvalidParameter)?;
                    }
                    #[cfg(feature = "__builtin-as")]
                    AttestationServiceType::Builtin {
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
                }
            }
        }
        Ok(ra_args)
    }
}

/// Attestation parameters configuration enum
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "model")]
#[serde(try_from = "maybe_tagged_attest_args::MaybeTaggedAttestArgs")]
pub enum AttestArgs {
    /// Passport mode attestation parameters
    Passport {
        #[serde(flatten)]
        aa_args: AttestationAgentArgs,

        #[serde(flatten)]
        as_args: AttestationServiceArgs,
    },

    /// Background check mode attestation parameters
    BackgroundCheck {
        #[serde(flatten)]
        aa_args: AttestationAgentArgs,
    },
}

/// This is a workaround for a missing feature in serde where it doesn't support deserializing
/// untagged enums. See https://github.com/serde-rs/serde/issues/1799#issuecomment-624978919
mod maybe_tagged_attest_args {
    use std::collections::HashMap;

    use anyhow::bail;
    use serde::{Deserialize, Serialize};

    use super::{AttestArgs, AttestationAgentArgs, AttestationServiceArgs};

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum MaybeTaggedAttestArgs {
        Tagged(TaggedAttestArgs),
        Untagged {
            #[serde(flatten)]
            aa_args: AttestationAgentArgs,

            #[serde(flatten)]
            other: HashMap<String, serde_json::Value>,
        },
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case", tag = "model")]
    pub enum TaggedAttestArgs {
        Passport {
            #[serde(flatten)]
            aa_args: AttestationAgentArgs,

            #[serde(flatten)]
            as_args: AttestationServiceArgs,
        },

        BackgroundCheck {
            #[serde(flatten)]
            aa_args: AttestationAgentArgs,
        },

        #[serde(other)]
        Unknown,
    }

    impl TryFrom<MaybeTaggedAttestArgs> for AttestArgs {
        type Error = anyhow::Error;
        fn try_from(args: MaybeTaggedAttestArgs) -> Result<AttestArgs, Self::Error> {
            Ok(match args {
                MaybeTaggedAttestArgs::Tagged(TaggedAttestArgs::BackgroundCheck { aa_args }) => {
                    AttestArgs::BackgroundCheck { aa_args }
                }
                MaybeTaggedAttestArgs::Untagged { aa_args, other } => {
                    if let Some(v) = other.get("model") {
                        bail!(r#"missing field for "model": {v}"#);
                    }
                    AttestArgs::BackgroundCheck { aa_args }
                }
                MaybeTaggedAttestArgs::Tagged(TaggedAttestArgs::Passport { aa_args, as_args }) => {
                    AttestArgs::Passport { aa_args, as_args }
                }
                MaybeTaggedAttestArgs::Tagged(TaggedAttestArgs::Unknown) => {
                    bail!(
                        r#"unsupported value for "model" field, should be one of ["background_check", "passport"]"#
                    )
                }
            })
        }
    }
}

/// Attestation agent type enum
///
/// Default is `Uds` if `aa_type` is not specified.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "aa_type", rename_all = "snake_case")]
#[serde(try_from = "maybe_tagged_aa_type::MaybeTaggedAttestationAgentType")]
pub enum AttestationAgentType {
    /// Unix Domain Socket
    Uds {
        /// Attestation agent address (unix socket path)
        aa_addr: String,
    },
    /// Builtin AA (embedded) - not implemented yet
    Builtin,
}

/// Attestation agent parameters configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationAgentArgs {
    /// Attestation agent type and configuration
    #[serde(flatten)]
    pub aa_type: AttestationAgentType,

    /// Evidence refresh interval (seconds), optional
    pub refresh_interval: Option<u64>,
}

/// This is a workaround for a missing feature in serde where it doesn't support deserializing
/// untagged enums. This allows backward compatibility for configs that only have `aa_addr`
/// without explicit `aa_type` field.
mod maybe_tagged_aa_type {
    use std::collections::HashMap;

    use anyhow::bail;
    use serde::{Deserialize, Serialize};

    use super::AttestationAgentType;

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum MaybeTaggedAttestationAgentType {
        Tagged(TaggedAttestationAgentType),
        Untagged {
            aa_addr: String,
            #[serde(flatten)]
            other: HashMap<String, serde_json::Value>,
        },
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case", tag = "aa_type")]
    pub enum TaggedAttestationAgentType {
        Uds {
            aa_addr: String,
        },
        Builtin,
        #[serde(other)]
        Unknown,
    }

    impl TryFrom<MaybeTaggedAttestationAgentType> for AttestationAgentType {
        type Error = anyhow::Error;
        fn try_from(args: MaybeTaggedAttestationAgentType) -> Result<Self, Self::Error> {
            Ok(match args {
                MaybeTaggedAttestationAgentType::Tagged(TaggedAttestationAgentType::Uds {
                    aa_addr,
                }) => AttestationAgentType::Uds { aa_addr },
                MaybeTaggedAttestationAgentType::Tagged(TaggedAttestationAgentType::Builtin) => {
                    AttestationAgentType::Builtin
                }
                MaybeTaggedAttestationAgentType::Tagged(TaggedAttestationAgentType::Unknown) => {
                    bail!(
                        r#"unsupported value for "aa_type" field, should be one of ["uds", "builtin"]"#
                    )
                }
                MaybeTaggedAttestationAgentType::Untagged { aa_addr, other } => {
                    if let Some(v) = other.get("aa_type") {
                        bail!(r#"missing field for "aa_type": {v}"#);
                    }
                    // Default to Uds for backward compatibility
                    AttestationAgentType::Uds { aa_addr }
                }
            })
        }
    }
}

const EVIDENCE_REFRESH_INTERVAL_SECOND: u64 = 10 * 60; // 10 minutes

impl AttestationAgentArgs {
    pub fn refresh_strategy(&self) -> RefreshStrategy {
        let refresh_interval = self
            .refresh_interval
            .unwrap_or(EVIDENCE_REFRESH_INTERVAL_SECOND);

        if refresh_interval == 0 {
            RefreshStrategy::Always
        } else {
            RefreshStrategy::Periodically {
                interval: refresh_interval,
            }
        }
    }
}

/// Verification parameters configuration enum
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "model")]
#[serde(try_from = "maybe_tagged_verify_args::MaybeTaggedVerifyArgs")]
pub enum VerifyArgs {
    /// Passport mode verification parameters
    Passport {
        #[serde(flatten)]
        token_verify: AttestationServiceTokenVerifyArgs,
    },

    /// Background check mode verification parameters
    BackgroundCheck {
        #[serde(flatten)]
        as_args: AttestationServiceArgs,

        #[serde(flatten)]
        token_verify: AttestationServiceTokenVerifyAdditionalArgs,
    },
}

/// This is a workaround for a missing feature in serde where it doesn't support deserializing
/// untagged enums. See https://github.com/serde-rs/serde/issues/1799#issuecomment-624978919
mod maybe_tagged_verify_args {
    use std::collections::HashMap;

    use anyhow::bail;
    use serde::{Deserialize, Serialize};

    use crate::config::ra::AttestationServiceTokenVerifyAdditionalArgs;

    use super::{AttestationServiceArgs, AttestationServiceTokenVerifyArgs, VerifyArgs};

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum MaybeTaggedVerifyArgs {
        Tagged(TaggedVerifyArgs),
        Untagged {
            #[serde(flatten)]
            as_args: AttestationServiceArgs,

            #[serde(flatten)]
            token_verify: AttestationServiceTokenVerifyAdditionalArgs,

            #[serde(flatten)]
            other: HashMap<String, serde_json::Value>,
        },
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case", tag = "model")]
    pub enum TaggedVerifyArgs {
        Passport {
            #[serde(flatten)]
            token_verify: AttestationServiceTokenVerifyArgs,
        },

        BackgroundCheck {
            #[serde(flatten)]
            as_args: AttestationServiceArgs,

            #[serde(flatten)]
            token_verify: AttestationServiceTokenVerifyAdditionalArgs,
        },

        #[serde(other)]
        Unknown,
    }

    impl TryFrom<MaybeTaggedVerifyArgs> for VerifyArgs {
        type Error = anyhow::Error;
        fn try_from(args: MaybeTaggedVerifyArgs) -> Result<VerifyArgs, Self::Error> {
            Ok(match args {
                MaybeTaggedVerifyArgs::Tagged(TaggedVerifyArgs::BackgroundCheck {
                    as_args,
                    token_verify,
                }) => VerifyArgs::BackgroundCheck {
                    as_args,
                    token_verify,
                },
                MaybeTaggedVerifyArgs::Untagged {
                    as_args,
                    token_verify,
                    other,
                } => {
                    if let Some(v) = other.get("model") {
                        bail!(r#"missing field for "model": {v}"#);
                    }
                    VerifyArgs::BackgroundCheck {
                        as_args,
                        token_verify,
                    }
                }
                MaybeTaggedVerifyArgs::Tagged(TaggedVerifyArgs::Passport { token_verify }) => {
                    VerifyArgs::Passport { token_verify }
                }
                MaybeTaggedVerifyArgs::Tagged(TaggedVerifyArgs::Unknown) => {
                    bail!(
                        r#"unsupported value for "model" field, should be one of ["background_check", "passport"]"#
                    )
                }
            })
        }
    }
}

/// Attestation service parameters configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationServiceArgs {
    /// Attestation service type and configuration
    #[serde(flatten)]
    pub as_type: AttestationServiceType,

    /// Policy ID list
    #[serde(default)]
    pub policy_ids: Vec<String>,
}

/// Attestation service type enum
///
/// This enum uses the "fat enum" pattern where each variant contains its own
/// configuration fields, rather than having shared fields flattened from outside.
/// This provides better type safety and clearer configuration structure.
///
/// Default is `Restful` if `as_type` is not specified.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "as_type", rename_all = "snake_case")]
#[serde(try_from = "maybe_tagged_as_type::MaybeTaggedAttestationServiceType")]
pub enum AttestationServiceType {
    /// Restful API
    Restful {
        /// Attestation service address
        as_addr: String,
        /// Custom headers to be sent with attestation service requests
        #[serde(default)]
        as_headers: HashMap<String, String>,
    },
    /// gRPC API
    Grpc {
        /// Attestation service address
        as_addr: String,
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

/// This is a workaround for a missing feature in serde where it doesn't support deserializing
/// untagged enums. This allows backward compatibility for configs that only have `as_addr`
/// without explicit `as_type` field.
mod maybe_tagged_as_type {
    use std::collections::HashMap;

    use anyhow::bail;
    use serde::{Deserialize, Serialize};

    use super::AttestationServiceType;

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum MaybeTaggedAttestationServiceType {
        Tagged(TaggedAttestationServiceType),
        Untagged {
            as_addr: String,
            #[serde(default)]
            as_headers: HashMap<String, String>,
            #[serde(flatten)]
            other: HashMap<String, serde_json::Value>,
        },
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case", tag = "as_type")]
    pub enum TaggedAttestationServiceType {
        Restful {
            as_addr: String,
            #[serde(default)]
            as_headers: HashMap<String, String>,
        },
        Grpc {
            as_addr: String,
            #[serde(default)]
            as_headers: HashMap<String, String>,
        },
        #[cfg(feature = "__builtin-as")]
        Builtin {
            policy: rats_cert::cert::verify::PolicyConfig,
            #[serde(default)]
            reference_values: Vec<rats_cert::cert::verify::ReferenceValueConfig>,
        },
        #[serde(other)]
        Unknown,
    }

    impl TryFrom<MaybeTaggedAttestationServiceType> for AttestationServiceType {
        type Error = anyhow::Error;
        fn try_from(args: MaybeTaggedAttestationServiceType) -> Result<Self, Self::Error> {
            Ok(match args {
                MaybeTaggedAttestationServiceType::Untagged {
                    as_addr,
                    as_headers,
                    other,
                } => {
                    if let Some(v) = other.get("as_type") {
                        bail!(r#"missing field for "as_type": {v}"#);
                    }
                    // Default to Restful for backward compatibility
                    AttestationServiceType::Restful {
                        as_addr,
                        as_headers,
                    }
                }
                MaybeTaggedAttestationServiceType::Tagged(
                    TaggedAttestationServiceType::Restful {
                        as_addr,
                        as_headers,
                    },
                ) => AttestationServiceType::Restful {
                    as_addr,
                    as_headers,
                },
                MaybeTaggedAttestationServiceType::Tagged(TaggedAttestationServiceType::Grpc {
                    as_addr,
                    as_headers,
                }) => AttestationServiceType::Grpc {
                    as_addr,
                    as_headers,
                },

                #[cfg(feature = "__builtin-as")]
                MaybeTaggedAttestationServiceType::Tagged(
                    TaggedAttestationServiceType::Builtin {
                        policy,
                        reference_values,
                    },
                ) => AttestationServiceType::Builtin {
                    policy,
                    reference_values,
                },
                MaybeTaggedAttestationServiceType::Tagged(
                    TaggedAttestationServiceType::Unknown,
                ) => {
                    bail!(
                        r#"unsupported value for "as_type" field, should be one of ["restful", "grpc", "builtin"]"#
                    )
                }
            })
        }
    }
}

/// Attestation service token verification parameters configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationServiceTokenVerifyArgs {
    /// Policy ID list
    pub policy_ids: Vec<String>,

    /// Trusted certificate paths list, optional
    #[serde(default = "Default::default")]
    pub trusted_certs_paths: Option<Vec<String>>,

    /// Attestation service address configuration, used for fetching attestation service certificate, optional
    #[serde(flatten)]
    pub as_addr_config: Option<AttestationServiceAddrArgs>,
}

/// Attestation service token verification parameters additional configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationServiceTokenVerifyAdditionalArgs {
    /// Trusted certificate paths list, optional
    #[serde(default = "Default::default")]
    pub trusted_certs_paths: Option<Vec<String>>,
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
            Some(AttestArgs::BackgroundCheck { aa_args }) => {
                match &aa_args.aa_type {
                    AttestationAgentType::Uds { aa_addr } => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Uds variant"),
                }
                assert_eq!(aa_args.refresh_interval, Some(3600));
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
            Some(AttestArgs::BackgroundCheck { aa_args }) => {
                match &aa_args.aa_type {
                    AttestationAgentType::Uds { aa_addr } => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Uds variant"),
                }
                assert_eq!(aa_args.refresh_interval, Some(3600));
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
                    "as_is_grpc": false,
                    "policy_ids": ["policy1", "policy2"],
                    "trusted_certs_paths": null
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::Passport { aa_args, as_args }) => {
                match &aa_args.aa_type {
                    AttestationAgentType::Uds { aa_addr } => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Uds variant"),
                }
                assert_eq!(aa_args.refresh_interval, Some(3600));
                match &as_args.as_type {
                    AttestationServiceType::Restful { as_addr, .. } => {
                        assert_eq!(as_addr, "localhost:8081");
                    }
                    _ => panic!("Expected Restful type"),
                }
                assert_eq!(as_args.policy_ids, vec!["policy1", "policy2"]);
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
                    "as_is_grpc": false,
                    "policy_ids": ["policy1", "policy2"],
                    "trusted_certs_paths": null
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
                    "as_is_grpc": false,
                    "policy_ids": ["policy1", "policy2"],
                    "trusted_certs_paths": null
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { as_args, .. }) => {
                match &as_args.as_type {
                    AttestationServiceType::Restful { as_addr, .. } => {
                        assert_eq!(as_addr, "localhost:8081");
                    }
                    _ => panic!("Expected Restful type"),
                }
                assert_eq!(as_args.policy_ids, vec!["policy1", "policy2"]);
            }
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
                    "as_is_grpc": false,
                    "policy_ids": ["policy1", "policy2"],
                    "trusted_certs_paths": null
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { as_args, .. }) => {
                match &as_args.as_type {
                    AttestationServiceType::Restful { as_addr, .. } => {
                        assert_eq!(as_addr, "localhost:8081");
                    }
                    _ => panic!("Expected Restful type"),
                }
                assert_eq!(as_args.policy_ids, vec!["policy1", "policy2"]);
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_verify() {
        let json = json!(
                {
                "verify": {
                    "model": "passport",
                    "policy_ids": ["policy1", "policy2"],
                    "trusted_certs_paths": null
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::Passport { token_verify }) => {
                assert_eq!(token_verify.policy_ids, vec!["policy1", "policy2"]);
            }
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
    fn test_attestation_service_args_with_restful() {
        let json = json!(
            {
                "as_type": "restful",
                "as_addr": "http://localhost:8080",
                "policy_ids": ["policy1"]
            }
        );

        serde_json::from_value::<AttestationServiceArgs>(json).expect("Failed to deserialize");
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
            Some(VerifyArgs::BackgroundCheck { as_args, .. }) => match &as_args.as_type {
                AttestationServiceType::Builtin {
                    policy,
                    reference_values,
                } => {
                    match policy {
                        PolicyConfig::Inline { content } => {
                            assert_eq!(content, "cGFja2FnZSBwb2xpY3kKZGVmYXVsdCBhbGxvdyA9IHRydWU=");
                        }
                        _ => panic!("Expected Inline policy"),
                    }
                    assert!(reference_values.is_empty());
                }
                _ => panic!("Expected Builtin AS type"),
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
            Some(VerifyArgs::BackgroundCheck { as_args, .. }) => match &as_args.as_type {
                AttestationServiceType::Builtin { policy, .. } => match policy {
                    PolicyConfig::Path { path } => {
                        assert_eq!(path, "/path/to/policy.rego");
                    }
                    _ => panic!("Expected Path policy"),
                },
                _ => panic!("Expected Builtin AS type"),
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
            Some(VerifyArgs::BackgroundCheck { as_args, .. }) => match &as_args.as_type {
                AttestationServiceType::Builtin {
                    reference_values, ..
                } => {
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
                _ => panic!("Expected Builtin AS type"),
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
            Some(VerifyArgs::BackgroundCheck { as_args, .. }) => {
                match &as_args.as_type {
                    AttestationServiceType::Builtin {
                        reference_values, ..
                    } => {
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
                    _ => panic!("Expected Builtin AS type"),
                }
            }
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
            Some(AttestArgs::Passport { aa_args, as_args }) => {
                match &aa_args.aa_type {
                    AttestationAgentType::Builtin => {}
                    _ => panic!("Expected Builtin variant"),
                }
                assert_eq!(aa_args.refresh_interval, Some(600));
                match &as_args.as_type {
                    AttestationServiceType::Restful { as_addr, .. } => {
                        assert_eq!(as_addr, "http://as-server:8080");
                    }
                    _ => panic!("Expected Restful type"),
                }
                assert_eq!(as_args.policy_ids, vec!["default"]);
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
            Some(AttestArgs::BackgroundCheck { aa_args }) => {
                match &aa_args.aa_type {
                    AttestationAgentType::Builtin => {}
                    _ => panic!("Expected Builtin variant"),
                }
                assert_eq!(aa_args.refresh_interval, Some(300));
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
            Some(AttestArgs::BackgroundCheck { aa_args }) => {
                match &aa_args.aa_type {
                    AttestationAgentType::Uds { aa_addr } => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Uds variant"),
                }
                assert_eq!(aa_args.refresh_interval, Some(3600));
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
            Some(VerifyArgs::BackgroundCheck { as_args, .. }) => {
                match &as_args.as_type {
                    AttestationServiceType::Restful { as_addr, .. } => {
                        assert_eq!(as_addr, "http://localhost:8080");
                    }
                    _ => panic!("Expected Restful variant"),
                }
                assert_eq!(as_args.policy_ids, vec!["policy1"]);
            }
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
            Some(VerifyArgs::BackgroundCheck { as_args, .. }) => match &as_args.as_type {
                AttestationServiceType::Grpc { as_addr, .. } => {
                    assert_eq!(as_addr, "http://localhost:5000");
                }
                _ => panic!("Expected Grpc variant"),
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
            Some(VerifyArgs::BackgroundCheck { as_args, .. }) => match &as_args.as_type {
                AttestationServiceType::Builtin {
                    policy,
                    reference_values,
                } => {
                    match policy {
                        PolicyConfig::Default => {}
                        _ => panic!("Expected Default policy"),
                    }
                    assert!(reference_values.is_empty());
                }
                _ => panic!("Expected Builtin variant"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""as_type":"builtin""#));
    }
}
