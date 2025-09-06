use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

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
    AttestOnly(AttestArgs),
    VerifyOnly(VerifyArgs),
    AttestAndVerify(AttestArgs, VerifyArgs),
    NoRa,
}

impl RaArgsUnchecked {
    pub fn into_checked(self) -> Result<RaArgs> {
        Ok(if self.no_ra {
            // Sanity check
            if self.verify.is_some() {
                bail!("The 'no_ra: true' flag should not be used with 'verify' field");
            }

            if self.attest.is_some() {
                bail!("The 'no_ra: true' flag should not be used with 'attest' field");
            }

            tracing::warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment");

            RaArgs::NoRa
        } else {
            match (self.attest, self.verify) {
                (None, None) => {
                    bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_egress'");
                }
                (None, Some(verify)) => RaArgs::VerifyOnly(verify),
                (Some(attest), None) => RaArgs::AttestOnly(attest),
                (Some(attest), Some(verify)) => RaArgs::AttestAndVerify(attest, verify),
            }
        })
    }
}

/// Attestation parameters configuration enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// Attestation agent parameters configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationAgentArgs {
    /// Attestation agent address
    pub aa_addr: String,

    /// Evidence refresh interval (seconds), optional
    pub refresh_interval: Option<u64>,
}

/// Verification parameters configuration enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    },
}

/// This is a workaround for a missing feature in serde where it doesn't support deserializing
/// untagged enums. See https://github.com/serde-rs/serde/issues/1799#issuecomment-624978919
mod maybe_tagged_verify_args {
    use std::collections::HashMap;

    use anyhow::bail;
    use serde::{Deserialize, Serialize};

    use super::{AttestationServiceArgs, AttestationServiceTokenVerifyArgs, VerifyArgs};

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum MaybeTaggedVerifyArgs {
        Tagged(TaggedVerifyArgs),
        Untagged {
            #[serde(flatten)]
            as_args: AttestationServiceArgs,

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
        },

        #[serde(other)]
        Unknown,
    }

    impl TryFrom<MaybeTaggedVerifyArgs> for VerifyArgs {
        type Error = anyhow::Error;
        fn try_from(args: MaybeTaggedVerifyArgs) -> Result<VerifyArgs, Self::Error> {
            Ok(match args {
                MaybeTaggedVerifyArgs::Tagged(TaggedVerifyArgs::BackgroundCheck { as_args }) => {
                    VerifyArgs::BackgroundCheck { as_args }
                }
                MaybeTaggedVerifyArgs::Untagged { as_args, other } => {
                    if let Some(v) = other.get("model") {
                        bail!(r#"missing field for "model": {v}"#);
                    }
                    VerifyArgs::BackgroundCheck { as_args }
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationServiceArgs {
    /// Attestation service address
    pub as_addr: String,

    /// Whether attestation service uses gRPC protocol, default is false (using REST API)
    #[serde(default = "bool::default")]
    pub as_is_grpc: bool,

    /// Attestation service token verification parameters
    #[serde(flatten)]
    pub token_verify: AttestationServiceTokenVerifyArgs,
}

/// Attestation service token verification parameters configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationServiceTokenVerifyArgs {
    /// Policy ID list
    pub policy_ids: Vec<String>,

    /// Trusted certificate paths list, optional
    #[serde(default = "Default::default")]
    pub trusted_certs_paths: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_background_check_attest_without_model() {
        let json = r#"
        {
            "attest": {
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                "refresh_interval": 3600
            }
        }
        "#;

        let ra_args: RaArgsUnchecked = serde_json::from_str(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck { aa_args }) => {
                assert_eq!(
                    aa_args.aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
                assert_eq!(aa_args.refresh_interval, Some(3600));
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock""#));
        assert!(serialized.contains(r#""refresh_interval":3600"#));
    }

    #[test]
    fn test_background_check_attest_with_model() {
        let json = r#"
        {
            "attest": {
                "model": "background_check",
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                "refresh_interval": 3600
            }
        }
        "#;

        let ra_args: RaArgsUnchecked = serde_json::from_str(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck { aa_args }) => {
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
        let json = r#"
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
        "#;

        let ra_args: RaArgsUnchecked = serde_json::from_str(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::Passport { aa_args, as_args }) => {
                assert_eq!(
                    aa_args.aa_addr,
                    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                );
                assert_eq!(aa_args.refresh_interval, Some(3600));
                assert_eq!(as_args.as_addr, "localhost:8081");
                assert_eq!(as_args.as_is_grpc, false);
                assert_eq!(as_args.token_verify.policy_ids, vec!["policy1", "policy2"]);
            }
            _ => panic!("Expected Passport variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"passport""#));
        assert!(serialized.contains(r#""aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock""#));
        assert!(serialized.contains(r#""as_addr":"localhost:8081""#));
        assert!(serialized.contains(r#""policy_ids":["policy1","policy2"]"#));
    }

    #[test]
    #[should_panic]
    fn test_attest_bad_model() {
        let json = r#"
        {
            "attest": {
                "model": "foobar",
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
        "#;

        serde_json::from_str::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_passport_attest_missing_fields() {
        let json = r#"
        {
            "attest": {
                "model": "passport",
                "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
            }
        }
        "#;

        serde_json::from_str::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_verify_bad_model() {
        let json = r#"
        {
            "verify": {
                "model": "foobar",
                "as_addr": "localhost:8081",
                "as_is_grpc": false,
                "policy_ids": ["policy1", "policy2"],
                "trusted_certs_paths": null
            }
        }
        "#;

        serde_json::from_str::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_passport_verify_missing_fields() {
        let json = r#"
        {
            "verify": {
                "model": "passport",
                "as_addr": "localhost:8081"
            }
        }
        "#;

        serde_json::from_str::<RaArgsUnchecked>(json).unwrap();
    }
    #[test]
    fn test_background_check_verify_without_model() {
        let json = r#"
        {
            "verify": {
                "as_addr": "localhost:8081",
                "as_is_grpc": false,
                "policy_ids": ["policy1", "policy2"],
                "trusted_certs_paths": null
            }
        }
        "#;

        let ra_args: RaArgsUnchecked = serde_json::from_str(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { as_args }) => {
                assert_eq!(as_args.as_addr, "localhost:8081");
                assert_eq!(as_args.as_is_grpc, false);
                assert_eq!(as_args.token_verify.policy_ids, vec!["policy1", "policy2"]);
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_background_check_verify_with_model() {
        let json = r#"
        {
            "verify": {
                "model": "background_check",
                "as_addr": "localhost:8081",
                "as_is_grpc": false,
                "policy_ids": ["policy1", "policy2"],
                "trusted_certs_paths": null
            }
        }
        "#;

        let ra_args: RaArgsUnchecked = serde_json::from_str(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { as_args }) => {
                assert_eq!(as_args.as_addr, "localhost:8081");
                assert_eq!(as_args.as_is_grpc, false);
                assert_eq!(as_args.token_verify.policy_ids, vec!["policy1", "policy2"]);
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_verify() {
        let json = r#"
        {
            "verify": {
                "model": "passport",
                "policy_ids": ["policy1", "policy2"],
                "trusted_certs_paths": null
            }
        }
        "#;

        let ra_args: RaArgsUnchecked = serde_json::from_str(json).expect("Failed to deserialize");

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
}
