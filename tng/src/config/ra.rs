use std::{collections::HashMap, path::Path};

use anyhow::{anyhow, Context as _, Result};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    error::TngError,
    tunnel::{provider::ProviderType, utils::maybe_cached::RefreshStrategy},
};

/// Remote Attestation configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
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
                    aa_args: AttestationAgentArgs { aa_addr, .. },
                    ..
                }
                | AttestArgs::BackgroundCheck {
                    aa_args: AttestationAgentArgs { aa_addr, .. },
                    ..
                } => {
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
                    ..
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
                        ..
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

            // Check if as_addr is a valid URL
            if let VerifyArgs::BackgroundCheck { as_args, .. } = verify_args {
                Url::parse(&as_args.as_addr_config.as_addr)
                    .with_context(|| {
                        format!(
                            "Invalid attestation service address: {}",
                            &as_args.as_addr_config.as_addr
                        )
                    })
                    .map_err(TngError::InvalidParameter)?;
            }
        }

        // Cross-provider compatibility checks
        #[cfg(unix)]
        if let RaArgs::AttestAndVerify(attest_args, verify_args) = &ra_args {
            if attest_args.provider() != verify_args.provider() {
                tracing::warn!(
                    attest_provider = %attest_args.provider(),
                    verify_provider = %verify_args.provider(),
                    "attest and verify use different providers; cross-provider compatibility depends on TranslateTo support"
                );
            }
            if let Some(converter_provider) = attest_args.converter_provider() {
                if converter_provider != verify_args.provider() {
                    tracing::warn!(
                        converter_provider = %converter_provider,
                        verify_provider = %verify_args.provider(),
                        "converter override uses a different provider than verify; the token format may be incompatible"
                    );
                }
            }
        }

        Ok(ra_args)
    }
}

/// Attestation parameters configuration enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "model")]
#[serde(try_from = "maybe_tagged_attest_args::MaybeProviderTaggedAttestArgs")]
pub enum AttestArgs {
    /// Passport mode attestation parameters
    Passport {
        provider: ProviderType,

        #[serde(flatten)]
        aa_args: AttestationAgentArgs,

        #[serde(flatten)]
        as_args: AttestationServiceArgs,

        #[serde(skip_serializing_if = "Option::is_none")]
        converter: Option<ConverterOverride>,
    },

    /// Background check mode attestation parameters
    BackgroundCheck {
        provider: ProviderType,

        #[serde(flatten)]
        aa_args: AttestationAgentArgs,
    },
}

impl AttestArgs {
    pub fn provider(&self) -> ProviderType {
        match self {
            Self::Passport { provider, .. } | Self::BackgroundCheck { provider, .. } => *provider,
        }
    }

    pub fn converter_provider(&self) -> Option<ProviderType> {
        match self {
            Self::Passport {
                converter: Some(c), ..
            } => Some(c.provider()),
            _ => None,
        }
    }
}

/// This is a workaround for a missing feature in serde where it doesn't support deserializing
/// untagged enums. See https://github.com/serde-rs/serde/issues/1799#issuecomment-624978919
mod maybe_tagged_attest_args {
    use std::collections::HashMap;

    use anyhow::bail;
    use serde::{Deserialize, Serialize};

    use super::{
        AttestArgs, AttestationAgentArgs, AttestationServiceArgs, ConverterOverride, ProviderType,
    };

    /// Outer layer: backward compat for optional "provider" field.
    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum MaybeProviderTaggedAttestArgs {
        WithProvider(ProviderTaggedAttestArgs),
        Legacy(MaybeTaggedAttestArgs),
    }

    /// Provider dispatch layer: routes on "provider" field.
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "provider")]
    pub enum ProviderTaggedAttestArgs {
        #[serde(rename = "coco")]
        Coco(MaybeTaggedAttestArgs),
        #[serde(other)]
        Unknown,
    }

    /// Model dispatch layer: routes on "model" field with untagged fallback.
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

            #[serde(default)]
            converter: Option<ConverterOverride>,
        },

        BackgroundCheck {
            #[serde(flatten)]
            aa_args: AttestationAgentArgs,
        },

        #[serde(other)]
        Unknown,
    }

    fn attest_args_from_model(
        args: MaybeTaggedAttestArgs,
        provider: ProviderType,
    ) -> Result<AttestArgs, anyhow::Error> {
        match args {
            MaybeTaggedAttestArgs::Tagged(TaggedAttestArgs::Passport {
                aa_args,
                as_args,
                converter,
            }) => Ok(AttestArgs::Passport {
                provider,
                aa_args,
                as_args,
                converter,
            }),
            MaybeTaggedAttestArgs::Tagged(TaggedAttestArgs::BackgroundCheck { aa_args }) => {
                Ok(AttestArgs::BackgroundCheck { provider, aa_args })
            }
            MaybeTaggedAttestArgs::Untagged { aa_args, other } => {
                if let Some(v) = other.get("model") {
                    bail!(r#"missing field for "model": {v}"#);
                }
                Ok(AttestArgs::BackgroundCheck { provider, aa_args })
            }
            MaybeTaggedAttestArgs::Tagged(TaggedAttestArgs::Unknown) => {
                bail!(
                    r#"unsupported value for "model" field, should be one of ["background_check", "passport"]"#
                )
            }
        }
    }

    impl TryFrom<MaybeProviderTaggedAttestArgs> for AttestArgs {
        type Error = anyhow::Error;
        fn try_from(args: MaybeProviderTaggedAttestArgs) -> Result<AttestArgs, Self::Error> {
            let (provider, model_args) = match args {
                MaybeProviderTaggedAttestArgs::WithProvider(tagged) => match tagged {
                    ProviderTaggedAttestArgs::Coco(m) => (ProviderType::Coco, m),
                    ProviderTaggedAttestArgs::Unknown => {
                        bail!(r#"unsupported value for "provider" field"#)
                    }
                },
                MaybeProviderTaggedAttestArgs::Legacy(m) => (ProviderType::Coco, m),
            };
            attest_args_from_model(model_args, provider)
        }
    }
}

/// Attestation agent parameters configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationAgentArgs {
    /// Attestation agent address
    pub aa_addr: String,

    /// Evidence refresh interval (seconds), optional
    pub refresh_interval: Option<u64>,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "model")]
#[serde(try_from = "maybe_tagged_verify_args::MaybeProviderTaggedVerifyArgs")]
pub enum VerifyArgs {
    /// Passport mode verification parameters
    Passport {
        provider: ProviderType,

        #[serde(flatten)]
        token_verify: AttestationServiceTokenVerifyArgs,
    },

    /// Background check mode verification parameters
    BackgroundCheck {
        provider: ProviderType,

        #[serde(flatten)]
        as_args: AttestationServiceArgs,

        #[serde(flatten)]
        token_verify: AttestationServiceTokenVerifyAdditionalArgs,
    },
}

impl VerifyArgs {
    pub fn provider(&self) -> ProviderType {
        match self {
            Self::Passport { provider, .. } | Self::BackgroundCheck { provider, .. } => *provider,
        }
    }
}

/// This is a workaround for a missing feature in serde where it doesn't support deserializing
/// untagged enums. See https://github.com/serde-rs/serde/issues/1799#issuecomment-624978919
mod maybe_tagged_verify_args {
    use std::collections::HashMap;

    use anyhow::bail;
    use serde::{Deserialize, Serialize};

    use crate::config::ra::AttestationServiceTokenVerifyAdditionalArgs;

    use super::{
        AttestationServiceArgs, AttestationServiceTokenVerifyArgs, ProviderType, VerifyArgs,
    };

    /// Outer layer: backward compat for optional "provider" field.
    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum MaybeProviderTaggedVerifyArgs {
        WithProvider(ProviderTaggedVerifyArgs),
        Legacy(MaybeTaggedVerifyArgs),
    }

    /// Provider dispatch layer: routes on "provider" field.
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "provider")]
    pub enum ProviderTaggedVerifyArgs {
        #[serde(rename = "coco")]
        Coco(MaybeTaggedVerifyArgs),
        #[serde(other)]
        Unknown,
    }

    /// Model dispatch layer: routes on "model" field with untagged fallback.
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

    fn verify_args_from_model(
        args: MaybeTaggedVerifyArgs,
        provider: ProviderType,
    ) -> Result<VerifyArgs, anyhow::Error> {
        match args {
            MaybeTaggedVerifyArgs::Tagged(TaggedVerifyArgs::BackgroundCheck {
                as_args,
                token_verify,
            }) => Ok(VerifyArgs::BackgroundCheck {
                provider,
                as_args,
                token_verify,
            }),
            MaybeTaggedVerifyArgs::Untagged {
                as_args,
                token_verify,
                other,
            } => {
                if let Some(v) = other.get("model") {
                    bail!(r#"missing field for "model": {v}"#);
                }
                Ok(VerifyArgs::BackgroundCheck {
                    provider,
                    as_args,
                    token_verify,
                })
            }
            MaybeTaggedVerifyArgs::Tagged(TaggedVerifyArgs::Passport { token_verify }) => {
                Ok(VerifyArgs::Passport {
                    provider,
                    token_verify,
                })
            }
            MaybeTaggedVerifyArgs::Tagged(TaggedVerifyArgs::Unknown) => {
                bail!(
                    r#"unsupported value for "model" field, should be one of ["background_check", "passport"]"#
                )
            }
        }
    }

    impl TryFrom<MaybeProviderTaggedVerifyArgs> for VerifyArgs {
        type Error = anyhow::Error;
        fn try_from(args: MaybeProviderTaggedVerifyArgs) -> Result<VerifyArgs, Self::Error> {
            let (provider, model_args) = match args {
                MaybeProviderTaggedVerifyArgs::WithProvider(tagged) => match tagged {
                    ProviderTaggedVerifyArgs::Coco(m) => (ProviderType::Coco, m),
                    ProviderTaggedVerifyArgs::Unknown => {
                        bail!(r#"unsupported value for "provider" field"#)
                    }
                },
                MaybeProviderTaggedVerifyArgs::Legacy(m) => (ProviderType::Coco, m),
            };
            verify_args_from_model(model_args, provider)
        }
    }
}

/// Attestation service address configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationServiceAddrArgs {
    /// Attestation service address
    pub as_addr: String,

    /// Whether attestation service uses gRPC protocol, default is false (using REST API)
    #[serde(default = "bool::default")]
    pub as_is_grpc: bool,

    /// Custom headers to be sent with attestation service requests
    #[serde(default = "Default::default")]
    pub as_headers: HashMap<String, String>,
}

/// Attestation service parameters configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationServiceArgs {
    #[serde(flatten)]
    pub as_addr_config: AttestationServiceAddrArgs,

    /// Policy ID list
    pub policy_ids: Vec<String>,
}

/// Attestation service token verification parameters configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationServiceTokenVerifyAdditionalArgs {
    /// Trusted certificate paths list, optional
    #[serde(default = "Default::default")]
    pub trusted_certs_paths: Option<Vec<String>>,
}

/// Optional converter provider override for passport mode.
/// When present, the converter uses this provider instead of the top-level attest provider.
/// This allows e.g. CoCo attester with ITA converter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "provider")]
pub enum ConverterOverride {
    #[serde(rename = "coco")]
    Coco {
        #[serde(flatten)]
        as_args: AttestationServiceArgs,
    },
}

impl ConverterOverride {
    pub fn provider(&self) -> ProviderType {
        match self {
            Self::Coco { .. } => ProviderType::Coco,
        }
    }
}

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
            Some(AttestArgs::BackgroundCheck { aa_args, .. }) => {
                assert_eq!(
                    aa_args.aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
                assert_eq!(aa_args.refresh_interval, Some(3600));
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
        assert_eq!(ra_args.attest.as_ref().unwrap().provider(), ProviderType::Coco);

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock""#));
        assert!(serialized.contains(r#""refresh_interval":3600"#));
        assert!(serialized.contains(r#""provider":"coco""#));
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
            Some(AttestArgs::BackgroundCheck { aa_args, .. }) => {
                assert_eq!(
                    aa_args.aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
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
            Some(AttestArgs::Passport { aa_args, as_args, .. }) => {
                assert_eq!(
                    aa_args.aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
                assert_eq!(aa_args.refresh_interval, Some(3600));
                assert_eq!(as_args.as_addr_config.as_addr, "localhost:8081");
                assert!(!as_args.as_addr_config.as_is_grpc);
                assert_eq!(as_args.policy_ids, vec!["policy1", "policy2"]);
            }
            _ => panic!("Expected Passport variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"passport""#));
        assert!(serialized.contains(r#""provider":"coco""#));
        assert!(serialized.contains(r#""aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock""#));
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
                assert_eq!(as_args.as_addr_config.as_addr, "localhost:8081");
                assert!(!as_args.as_addr_config.as_is_grpc);
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
                assert_eq!(as_args.as_addr_config.as_addr, "localhost:8081");
                assert!(!as_args.as_addr_config.as_is_grpc);
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
            Some(VerifyArgs::Passport { token_verify, .. }) => {
                assert_eq!(token_verify.policy_ids, vec!["policy1", "policy2"]);
            }
            _ => panic!("Expected Passport variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"passport""#));
        assert!(serialized.contains(r#""provider":"coco""#));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("trusted certificate path does not exist"));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("trusted certificate path does not exist"));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid attestation service address"));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid attestation service address"));
    }

    // --- Provider-tagged config tests ---

    #[test]
    fn test_background_check_attest_with_provider() {
        let json = json!(
            {
                "attest": {
                    "provider": "coco",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck { provider, aa_args, .. }) => {
                assert_eq!(*provider, ProviderType::Coco);
                assert_eq!(
                    aa_args.aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_attest_with_provider() {
        let json = json!(
            {
                "attest": {
                    "provider": "coco",
                    "model": "passport",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600,
                    "as_addr": "localhost:8081",
                    "as_is_grpc": false,
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        match &ra_args.attest {
            Some(AttestArgs::Passport { provider, aa_args, as_args, .. }) => {
                assert_eq!(*provider, ProviderType::Coco);
                assert_eq!(
                    aa_args.aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
                assert_eq!(as_args.as_addr_config.as_addr, "localhost:8081");
            }
            _ => panic!("Expected Passport variant"),
        }
    }

    #[test]
    fn test_background_check_verify_with_provider() {
        let json = json!(
            {
                "verify": {
                    "provider": "coco",
                    "model": "background_check",
                    "as_addr": "http://localhost:8081",
                    "as_is_grpc": false,
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { provider, as_args, .. }) => {
                assert_eq!(*provider, ProviderType::Coco);
                assert_eq!(as_args.as_addr_config.as_addr, "http://localhost:8081");
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_verify_with_provider() {
        let json = json!(
            {
                "verify": {
                    "provider": "coco",
                    "model": "passport",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        match &ra_args.verify {
            Some(VerifyArgs::Passport { provider, token_verify, .. }) => {
                assert_eq!(*provider, ProviderType::Coco);
                assert_eq!(token_verify.policy_ids, vec!["policy1"]);
            }
            _ => panic!("Expected Passport variant"),
        }
    }

    #[test]
    fn test_attest_bad_provider() {
        let json = json!(
            {
                "attest": {
                    "provider": "unknown_provider",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        );

        let result = serde_json::from_value::<RaArgsUnchecked>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_bad_provider() {
        let json = json!(
            {
                "verify": {
                    "provider": "unknown_provider",
                    "model": "background_check",
                    "as_addr": "http://localhost:8081",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let result = serde_json::from_value::<RaArgsUnchecked>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_passport_attest_with_converter_override() {
        let json = json!(
            {
                "attest": {
                    "provider": "coco",
                    "model": "passport",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "as_addr": "localhost:8081",
                    "as_is_grpc": false,
                    "policy_ids": ["policy1"],
                    "converter": {
                        "provider": "coco",
                        "as_addr": "localhost:9090",
                        "as_is_grpc": true,
                        "policy_ids": ["converter_policy"]
                    }
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        match &ra_args.attest {
            Some(AttestArgs::Passport { provider, converter, .. }) => {
                assert_eq!(*provider, ProviderType::Coco);
                let converter = converter.as_ref().expect("Expected converter override");
                assert_eq!(converter.provider(), ProviderType::Coco);
                match converter {
                    ConverterOverride::Coco { as_args } => {
                        assert_eq!(as_args.as_addr_config.as_addr, "localhost:9090");
                        assert!(as_args.as_addr_config.as_is_grpc);
                        assert_eq!(as_args.policy_ids, vec!["converter_policy"]);
                    }
                }
            }
            _ => panic!("Expected Passport variant"),
        }
    }

    #[test]
    fn test_passport_attest_without_converter_override() {
        let json = json!(
            {
                "attest": {
                    "provider": "coco",
                    "model": "passport",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "as_addr": "localhost:8081",
                    "as_is_grpc": false,
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        match &ra_args.attest {
            Some(AttestArgs::Passport { converter, .. }) => {
                assert!(converter.is_none());
            }
            _ => panic!("Expected Passport variant"),
        }
    }

    #[test]
    fn test_legacy_config_defaults_to_coco_provider() {
        let attest_json = json!(
            {
                "attest": {
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        );
        let ra_args: RaArgsUnchecked = serde_json::from_value(attest_json).expect("Failed to deserialize");
        assert_eq!(ra_args.attest.as_ref().unwrap().provider(), ProviderType::Coco);

        let verify_json = json!(
            {
                "verify": {
                    "as_addr": "http://localhost:8081",
                    "policy_ids": ["policy1"]
                }
            }
        );
        let ra_args: RaArgsUnchecked = serde_json::from_value(verify_json).expect("Failed to deserialize");
        assert_eq!(ra_args.verify.as_ref().unwrap().provider(), ProviderType::Coco);
    }
}
