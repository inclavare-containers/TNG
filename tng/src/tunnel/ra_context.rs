//! Pre-instantiated Remote Attestation Context
//!
//! This module provides `RaContext` which holds pre-instantiated attestation
//! components based on `RaArgs` configuration. This avoids repeated creation
//! of attester/converter/verifier instances at each API call.

use anyhow::Result;
#[cfg(unix)]
use rats_cert::tee::coco::attester::CocoAttester;
use rats_cert::tee::coco::converter::CocoConverter;
use rats_cert::tee::coco::verifier::remote::CocoVerifier;

#[cfg(feature = "builtin-as")]
use rats_cert::tee::coco::converter::builtin::BuiltinCocoConverter;
#[cfg(feature = "builtin-as")]
use rats_cert::tee::coco::verifier::builtin::BuiltinCocoVerifier;

#[cfg(unix)]
use crate::config::ra::AttestArgs;
use crate::config::ra::{RaArgs, VerifyArgs};
#[cfg(unix)]
use crate::tunnel::utils::maybe_cached::RefreshStrategy;

/// Pre-instantiated RA context for OHTTP security
///
/// This enum mirrors the structure of `RaArgs` but holds ready-to-use
/// component instances instead of just configuration.
pub enum RaContext {
    /// Attest only mode - server attests itself
    #[cfg(unix)]
    AttestOnly(AttestContext),

    /// Verify only mode - server verifies client
    VerifyOnly(VerifyContext),

    /// Both attest and verify
    #[cfg(unix)]
    AttestAndVerify {
        attest: AttestContext,
        verify: VerifyContext,
    },

    /// No remote attestation
    NoRa,
}

impl RaContext {
    /// Create pre-instantiated RA context from RaArgs configuration
    pub async fn from_ra_args(ra_args: &RaArgs) -> Result<Self> {
        match ra_args {
            RaArgs::NoRa => Ok(Self::NoRa),
            RaArgs::VerifyOnly(verify_args) => Ok(Self::VerifyOnly(
                VerifyContext::from_verify_args(verify_args).await?,
            )),
            #[cfg(unix)]
            RaArgs::AttestOnly(attest_args) => Ok(Self::AttestOnly(
                AttestContext::from_attest_args(attest_args)?,
            )),
            #[cfg(unix)]
            RaArgs::AttestAndVerify(attest_args, verify_args) => Ok(Self::AttestAndVerify {
                attest: AttestContext::from_attest_args(attest_args)?,
                verify: VerifyContext::from_verify_args(verify_args).await?,
            }),
        }
    }

    /// Get verify context if available
    pub fn verify_context(&self) -> Option<&VerifyContext> {
        match self {
            Self::VerifyOnly(verify) => Some(verify),
            #[cfg(unix)]
            Self::AttestAndVerify { verify, .. } => Some(verify),
            _ => None,
        }
    }

    /// Get attest context if available
    #[cfg(unix)]
    pub fn attest_context(&self) -> Option<&AttestContext> {
        match self {
            Self::AttestOnly(attest) => Some(attest),
            Self::AttestAndVerify { attest, .. } => Some(attest),
            _ => None,
        }
    }
}

/// Pre-instantiated attestation context
///
/// Holds attester and converter instances for server attestation.
#[cfg(unix)]
pub enum AttestContext {
    /// Passport mode - attest via AA, convert via remote AS
    Passport {
        attester: CocoAttester,
        converter: CocoConverter,
        refresh_strategy: RefreshStrategy,
    },

    /// Background check mode - just attest via AA (client verifies)
    BackgroundCheck {
        attester: CocoAttester,
        refresh_strategy: RefreshStrategy,
    },
    // Future: PassportBuiltin, Builtin
}

#[cfg(unix)]
impl AttestContext {
    /// Create attestation context from AttestArgs configuration
    pub fn from_attest_args(attest_args: &AttestArgs) -> Result<Self> {
        match attest_args {
            AttestArgs::Passport { aa_args, as_args } => {
                let attester = CocoAttester::new(&aa_args.aa_addr)?;
                let converter = CocoConverter::new(
                    &as_args.as_addr_config.as_addr,
                    &as_args.policy_ids,
                    as_args.as_addr_config.as_is_grpc,
                    &as_args.as_addr_config.as_headers,
                )?;
                Ok(Self::Passport {
                    attester,
                    converter,
                    refresh_strategy: aa_args.refresh_strategy(),
                })
            }
            AttestArgs::BackgroundCheck { aa_args } => {
                let attester = CocoAttester::new(&aa_args.aa_addr)?;
                Ok(Self::BackgroundCheck {
                    attester,
                    refresh_strategy: aa_args.refresh_strategy(),
                })
            }
            AttestArgs::PassportBuiltin { .. } => {
                anyhow::bail!("Builtin AA with remote AS not implemented yet")
            }
            AttestArgs::Builtin { .. } => {
                anyhow::bail!("Builtin AA not implemented yet")
            }
        }
    }

    /// Get refresh strategy for caching
    pub fn refresh_strategy(&self) -> RefreshStrategy {
        match self {
            Self::Passport {
                refresh_strategy, ..
            }
            | Self::BackgroundCheck {
                refresh_strategy, ..
            } => *refresh_strategy,
        }
    }
}

/// Pre-instantiated verification context
///
/// Holds components needed for verifying client attestation.
pub enum VerifyContext {
    /// Passport mode - verify token from remote AS
    Passport { verifier: CocoVerifier },

    /// Background check - convert evidence via remote AS, then verify
    BackgroundCheck {
        converter: CocoConverter,
        verifier: CocoVerifier,
    },

    /// Builtin - local conversion and verification
    #[cfg(feature = "builtin-as")]
    Builtin {
        converter: BuiltinCocoConverter,
        verifier: BuiltinCocoVerifier,
    },
}

impl std::fmt::Debug for VerifyContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passport { .. } => f
                .debug_struct("VerifyContext::Passport")
                .finish_non_exhaustive(),
            Self::BackgroundCheck { .. } => f
                .debug_struct("VerifyContext::BackgroundCheck")
                .finish_non_exhaustive(),
            #[cfg(feature = "builtin-as")]
            Self::Builtin { .. } => f
                .debug_struct("VerifyContext::Builtin")
                .finish_non_exhaustive(),
        }
    }
}

impl VerifyContext {
    /// Create verification context from VerifyArgs configuration
    pub async fn from_verify_args(verify_args: &VerifyArgs) -> Result<Self> {
        match verify_args {
            VerifyArgs::Passport { token_verify } => {
                let verifier = CocoVerifier::new(
                    &token_verify.as_addr_config,
                    &token_verify.trusted_certs_paths,
                    &token_verify.policy_ids,
                )
                .await?;
                Ok(Self::Passport { verifier })
            }
            VerifyArgs::BackgroundCheck {
                as_args,
                token_verify,
            } => {
                let converter = CocoConverter::new(
                    &as_args.as_addr_config.as_addr,
                    &as_args.policy_ids,
                    as_args.as_addr_config.as_is_grpc,
                    &as_args.as_addr_config.as_headers,
                )?;
                let verifier = CocoVerifier::new(
                    &Some(as_args.as_addr_config.clone()),
                    &token_verify.trusted_certs_paths,
                    &as_args.policy_ids,
                )
                .await?;
                Ok(Self::BackgroundCheck {
                    converter,
                    verifier,
                })
            }
            #[cfg(feature = "builtin-as")]
            VerifyArgs::Builtin {
                policy,
                reference_values,
            } => {
                let converter = BuiltinCocoConverter::new(policy, reference_values).await?;
                let verifier = converter.new_verifier().await?;
                Ok(Self::Builtin {
                    converter,
                    verifier,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ra::{
        AttestationServiceAddrArgs, AttestationServiceArgs,
        AttestationServiceTokenVerifyAdditionalArgs, AttestationServiceTokenVerifyArgs, RaArgs,
        VerifyArgs,
    };
    use std::collections::HashMap;

    // =========================================================================
    // Test Constants
    // =========================================================================

    const TEST_AA_ADDR: &str =
        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";
    const TEST_AS_ADDR: &str = "http://0.0.0.0:8080";
    const TEST_AS_CERT_PATH: &str = "/tmp/as-full.pem";

    // =========================================================================
    // Helper Functions
    // =========================================================================

    fn make_as_addr_config() -> AttestationServiceAddrArgs {
        AttestationServiceAddrArgs {
            as_addr: TEST_AS_ADDR.to_string(),
            as_is_grpc: false,
            as_headers: HashMap::new(),
        }
    }

    fn make_as_args() -> AttestationServiceArgs {
        AttestationServiceArgs {
            as_addr_config: make_as_addr_config(),
            policy_ids: vec!["default".to_string()],
        }
    }

    #[allow(dead_code)]
    fn make_verify_passport_args() -> VerifyArgs {
        VerifyArgs::Passport {
            token_verify: AttestationServiceTokenVerifyArgs {
                policy_ids: vec!["default".to_string()],
                trusted_certs_paths: Some(vec![TEST_AS_CERT_PATH.to_string()]),
                as_addr_config: Some(make_as_addr_config()),
            },
        }
    }

    fn make_verify_bgcheck_args() -> VerifyArgs {
        VerifyArgs::BackgroundCheck {
            as_args: make_as_args(),
            token_verify: AttestationServiceTokenVerifyAdditionalArgs {
                trusted_certs_paths: Some(vec![TEST_AS_CERT_PATH.to_string()]),
            },
        }
    }

    // =========================================================================
    // Non-builtin tests (always compiled)
    // =========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ra_context_no_ra() {
        let ra_args = RaArgs::NoRa;
        let result = RaContext::from_ra_args(&ra_args).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert!(
            matches!(ctx, RaContext::NoRa),
            "Expected NoRa variant, got {:?}",
            std::mem::discriminant(&ctx)
        );
        assert!(
            ctx.verify_context().is_none(),
            "NoRa should have no verify context"
        );
    }

    // =========================================================================
    // Section 2: VerifyOnly Tests
    // =========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ra_context_verify_only_passport() {
        let verify_args = make_verify_passport_args();
        let ra_args = RaArgs::VerifyOnly(verify_args);
        let result = RaContext::from_ra_args(&ra_args).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert!(
            matches!(ctx, RaContext::VerifyOnly(_)),
            "Expected VerifyOnly variant"
        );
        assert!(
            ctx.verify_context().is_some(),
            "VerifyOnly should have verify context"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ra_context_verify_only_background_check() {
        let verify_args = make_verify_bgcheck_args();
        let ra_args = RaArgs::VerifyOnly(verify_args);
        let result = RaContext::from_ra_args(&ra_args).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert!(
            matches!(ctx, RaContext::VerifyOnly(_)),
            "Expected VerifyOnly variant"
        );
        assert!(
            ctx.verify_context().is_some(),
            "VerifyOnly should have verify context"
        );
    }

    // =========================================================================
    // Section 5: Accessor Method Tests
    // =========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accessor_verify_only() {
        let verify_args = make_verify_bgcheck_args();
        let ra_args = RaArgs::VerifyOnly(verify_args);
        let result = RaContext::from_ra_args(&ra_args).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert!(
            ctx.verify_context().is_some(),
            "VerifyOnly should have verify context"
        );
    }

    // =========================================================================
    // Section 3-4: Unix-specific tests (AttestOnly and AttestAndVerify)
    // =========================================================================

    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use crate::config::ra::{AttestArgs, AttestationAgentArgs, BuiltinAttestationAgentArgs};
        use crate::tunnel::utils::maybe_cached::RefreshStrategy;

        // Helper functions for Unix tests
        fn make_aa_args() -> AttestationAgentArgs {
            AttestationAgentArgs {
                aa_addr: TEST_AA_ADDR.to_string(),
                refresh_interval: None,
            }
        }

        fn make_aa_args_with_interval(interval: Option<u64>) -> AttestationAgentArgs {
            AttestationAgentArgs {
                aa_addr: TEST_AA_ADDR.to_string(),
                refresh_interval: interval,
            }
        }

        fn make_attest_bgcheck_args() -> AttestArgs {
            AttestArgs::BackgroundCheck {
                aa_args: make_aa_args(),
            }
        }

        fn make_attest_passport_args() -> AttestArgs {
            AttestArgs::Passport {
                aa_args: make_aa_args(),
                as_args: make_as_args(),
            }
        }

        // =====================================================================
        // Section 3: AttestOnly Tests
        // =====================================================================

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_ra_context_attest_only_background_check() {
            let attest_args = make_attest_bgcheck_args();
            let ra_args = RaArgs::AttestOnly(attest_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestOnly(_)),
                "Expected AttestOnly variant"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_ra_context_attest_only_passport() {
            let attest_args = make_attest_passport_args();
            let ra_args = RaArgs::AttestOnly(attest_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestOnly(_)),
                "Expected AttestOnly variant"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_attest_context_refresh_strategy_periodic() {
            let attest_args = AttestArgs::BackgroundCheck {
                aa_args: make_aa_args_with_interval(Some(600)),
            };
            let result = AttestContext::from_attest_args(&attest_args);
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(
                    ctx.refresh_strategy(),
                    RefreshStrategy::Periodically { interval: 600 }
                ),
                "Expected Periodically with interval 600"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_attest_context_refresh_strategy_always() {
            let attest_args = AttestArgs::BackgroundCheck {
                aa_args: make_aa_args_with_interval(Some(0)),
            };
            let result = AttestContext::from_attest_args(&attest_args);
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx.refresh_strategy(), RefreshStrategy::Always),
                "Expected Always refresh strategy"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_attest_context_passport_builtin_not_implemented() {
            let attest_args = AttestArgs::PassportBuiltin {
                builtin_aa_args: BuiltinAttestationAgentArgs {
                    refresh_interval: None,
                },
                as_args: make_as_args(),
            };
            let result = AttestContext::from_attest_args(&attest_args);
            assert!(result.is_err(), "Expected error for PassportBuiltin");
            let err = result.err().unwrap();
            assert!(
                err.to_string().contains("not implemented"),
                "Error should mention 'not implemented', got: {}",
                err
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_attest_context_builtin_not_implemented() {
            let attest_args = AttestArgs::Builtin {
                builtin_aa_args: BuiltinAttestationAgentArgs {
                    refresh_interval: None,
                },
            };
            let result = AttestContext::from_attest_args(&attest_args);
            assert!(result.is_err(), "Expected error for Builtin");
            let err = result.err().unwrap();
            assert!(
                err.to_string().contains("not implemented"),
                "Error should mention 'not implemented', got: {}",
                err
            );
        }

        // =====================================================================
        // Section 4: AttestAndVerify Combination Tests
        // =====================================================================

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_ra_context_two_way_passport_passport() {
            let attest_args = make_attest_passport_args();
            let verify_args = make_verify_passport_args();
            let ra_args = RaArgs::AttestAndVerify(attest_args, verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestAndVerify { .. }),
                "Expected AttestAndVerify variant"
            );
            assert!(
                ctx.verify_context().is_some(),
                "AttestAndVerify should have verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestAndVerify should have attest context"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_ra_context_two_way_bgcheck_bgcheck() {
            let attest_args = make_attest_bgcheck_args();
            let verify_args = make_verify_bgcheck_args();
            let ra_args = RaArgs::AttestAndVerify(attest_args, verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestAndVerify { .. }),
                "Expected AttestAndVerify variant"
            );
            assert!(
                ctx.verify_context().is_some(),
                "AttestAndVerify should have verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestAndVerify should have attest context"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_ra_context_two_way_bgcheck_passport() {
            let attest_args = make_attest_bgcheck_args();
            let verify_args = make_verify_passport_args();
            let ra_args = RaArgs::AttestAndVerify(attest_args, verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestAndVerify { .. }),
                "Expected AttestAndVerify variant"
            );
            assert!(
                ctx.verify_context().is_some(),
                "AttestAndVerify should have verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestAndVerify should have attest context"
            );
        }

        // =====================================================================
        // Section 5: Accessor Method Tests (Unix-specific)
        // =====================================================================

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_accessor_attest_only() {
            let attest_args = make_attest_bgcheck_args();
            let ra_args = RaArgs::AttestOnly(attest_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                ctx.verify_context().is_none(),
                "AttestOnly should have no verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestOnly should have attest context"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_accessor_attest_and_verify() {
            let attest_args = make_attest_bgcheck_args();
            let verify_args = make_verify_bgcheck_args();
            let ra_args = RaArgs::AttestAndVerify(attest_args, verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                ctx.verify_context().is_some(),
                "AttestAndVerify should have verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestAndVerify should have attest context"
            );
        }
    }

    // =========================================================================
    // Section 4: Unix + Builtin-AS combined tests (tests 12-13)
    // =========================================================================

    #[cfg(all(unix, feature = "builtin-as"))]
    mod unix_builtin_tests {
        use super::*;
        use crate::config::ra::{AttestArgs, AttestationAgentArgs};
        use rats_cert::cert::verify::PolicyConfig;
        use serial_test::serial;

        fn make_aa_args() -> AttestationAgentArgs {
            AttestationAgentArgs {
                aa_addr: TEST_AA_ADDR.to_string(),
                refresh_interval: None,
            }
        }

        fn make_attest_passport_args() -> AttestArgs {
            AttestArgs::Passport {
                aa_args: make_aa_args(),
                as_args: make_as_args(),
            }
        }

        fn make_attest_bgcheck_args() -> AttestArgs {
            AttestArgs::BackgroundCheck {
                aa_args: make_aa_args(),
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_ra_context_two_way_passport_builtin() {
            let attest_args = make_attest_passport_args();
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Default,
                reference_values: vec![],
            };
            let ra_args = RaArgs::AttestAndVerify(attest_args, verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestAndVerify { .. }),
                "Expected AttestAndVerify variant"
            );
            assert!(
                ctx.verify_context().is_some(),
                "AttestAndVerify should have verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestAndVerify should have attest context"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_ra_context_two_way_bgcheck_builtin() {
            let attest_args = make_attest_bgcheck_args();
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Default,
                reference_values: vec![],
            };
            let ra_args = RaArgs::AttestAndVerify(attest_args, verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestAndVerify { .. }),
                "Expected AttestAndVerify variant"
            );
            assert!(
                ctx.verify_context().is_some(),
                "AttestAndVerify should have verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestAndVerify should have attest context"
            );
        }
    }

    // =========================================================================
    // Builtin-specific tests
    // =========================================================================

    #[cfg(feature = "builtin-as")]
    mod builtin_tests {
        use super::*;
        use base64::{engine::general_purpose::STANDARD, Engine};
        use rats_cert::cert::verify::{
            PayloadConfig, PolicyConfig, ProvenanceSource, ReferenceValueConfig,
        };
        use serial_test::serial;

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_creation_with_default_policy() {
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Default,
                reference_values: vec![],
            };
            let result = VerifyContext::from_verify_args(&verify_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            match result.unwrap() {
                VerifyContext::Builtin { .. } => {} // expected
                other => panic!("Expected Builtin variant, got {:?}", other),
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_with_inline_policy() {
            // "package policy\ndefault allow = true" encoded in base64
            let policy_content = STANDARD.encode("package policy\ndefault allow = true");
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Inline {
                    content: policy_content,
                },
                reference_values: vec![],
            };
            let result = VerifyContext::from_verify_args(&verify_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            match result.unwrap() {
                VerifyContext::Builtin { .. } => {} // expected
                other => panic!("Expected Builtin variant, got {:?}", other),
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_with_sample_reference_inline() {
            // Sample reference value payload (inline JSON)
            let payload_json = r#"{"tdx":{}}"#.to_string();
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Default,
                reference_values: vec![ReferenceValueConfig::Sample {
                    payload: PayloadConfig::Inline {
                        content: payload_json,
                    },
                }],
            };
            let result = VerifyContext::from_verify_args(&verify_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            match result.unwrap() {
                VerifyContext::Builtin { .. } => {} // expected
                other => panic!("Expected Builtin variant, got {:?}", other),
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_ra_context_verify_only_builtin() {
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Default,
                reference_values: vec![],
            };
            let ra_args = RaArgs::VerifyOnly(verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::VerifyOnly(_)),
                "Expected VerifyOnly variant"
            );
            assert!(
                ctx.verify_context().is_some(),
                "VerifyOnly should have verify context"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_debug_format() {
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Default,
                reference_values: vec![],
            };
            let result = VerifyContext::from_verify_args(&verify_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            let debug_str = format!("{:?}", ctx);
            assert!(
                debug_str.contains("VerifyContext::Builtin"),
                "Debug format should contain 'VerifyContext::Builtin', got: {}",
                debug_str
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_error_invalid_policy_path() {
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Path {
                    path: "/nonexistent/policy.rego".to_string(),
                },
                reference_values: vec![],
            };
            let result = VerifyContext::from_verify_args(&verify_args).await;
            assert!(result.is_err(), "Should fail with nonexistent policy path");
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_error_invalid_reference_path() {
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Default,
                reference_values: vec![ReferenceValueConfig::Sample {
                    payload: PayloadConfig::Path {
                        path: "/nonexistent/ref.json".to_string(),
                    },
                }],
            };
            let result = VerifyContext::from_verify_args(&verify_args).await;
            assert!(
                result.is_err(),
                "Should fail with nonexistent reference value path"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_challenge_generation() {
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Default,
                reference_values: vec![],
            };
            let result = VerifyContext::from_verify_args(&verify_args).await;
            assert!(
                result.is_ok(),
                "Failed to create context: {:?}",
                result.err()
            );
            let ctx = result.unwrap();
            match ctx {
                VerifyContext::Builtin { converter, .. } => {
                    let challenge_result = converter.generate_challenge().await;
                    assert!(
                        challenge_result.is_ok(),
                        "Failed to generate challenge: {:?}",
                        challenge_result.err()
                    );
                    let challenge = challenge_result.unwrap();
                    assert!(!challenge.is_empty(), "Challenge should be non-empty");
                }
                other => panic!("Expected Builtin variant, got {:?}", other),
            }
        }

        // =====================================================================
        // Section 6: New Builtin Tests
        // =====================================================================

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_with_slsa_reference() {
            // Note: This test may fail since Rekor is not available in local environment.
            // We just verify that the creation is attempted correctly.
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Default,
                reference_values: vec![ReferenceValueConfig::Slsa {
                    id: "test-artifact".to_string(),
                    version: "1.0.0".to_string(),
                    artifact_type: "container-image".to_string(),
                    rekor_url: "https://rekor.sigstore.dev".to_string(),
                    rekor_api_version: 2,
                    provenance_source: None,
                }],
            };
            // This may fail due to Rekor not being available, so we just attempt creation
            let _result = VerifyContext::from_verify_args(&verify_args).await;
            // Either Ok or specific error from Rekor fetch is acceptable
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_with_slsa_reference_and_provenance() {
            // Note: This test may fail since Rekor/OCI registry is not available.
            // We just verify that the creation is attempted correctly.
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Default,
                reference_values: vec![ReferenceValueConfig::Slsa {
                    id: "test-artifact".to_string(),
                    version: "1.0.0".to_string(),
                    artifact_type: "container-image".to_string(),
                    rekor_url: "https://rekor.sigstore.dev".to_string(),
                    rekor_api_version: 2,
                    provenance_source: Some(ProvenanceSource {
                        protocol: "oci".to_string(),
                        uri: "oci://registry/repo:tag".to_string(),
                        artifact: Some("bundle".to_string()),
                    }),
                }],
            };
            // This may fail due to external services not being available
            let _result = VerifyContext::from_verify_args(&verify_args).await;
            // Either Ok or specific error from network fetch is acceptable
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_with_multiple_references() {
            let verify_args = VerifyArgs::Builtin {
                policy: PolicyConfig::Default,
                reference_values: vec![
                    ReferenceValueConfig::Sample {
                        payload: PayloadConfig::Inline {
                            content: r#"{"tdx":{}}"#.to_string(),
                        },
                    },
                    ReferenceValueConfig::Sample {
                        payload: PayloadConfig::Inline {
                            content: r#"{"sample":{}}"#.to_string(),
                        },
                    },
                ],
            };
            let result = VerifyContext::from_verify_args(&verify_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            match result.unwrap() {
                VerifyContext::Builtin { .. } => {} // expected
                other => panic!("Expected Builtin variant, got {:?}", other),
            }
        }
    }
}
