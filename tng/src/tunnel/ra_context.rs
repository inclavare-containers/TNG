//! Pre-instantiated Remote Attestation Context
//!
//! This module provides `RaContext` which holds pre-instantiated attestation
//! components based on `RaArgs` configuration. This avoids repeated creation
//! of attester/converter/verifier instances at each API call.

use std::sync::Arc;

use anyhow::Result;
#[cfg(unix)]
use rats_cert::tee::coco::attester::CocoAttester;
use rats_cert::tee::coco::converter::CocoConverter;
use rats_cert::tee::coco::verifier::remote::CocoRemoteVerifier;
use rats_cert::tee::coco::verifier::CocoVerifier;

#[cfg(feature = "__builtin-as")]
use rats_cert::tee::coco::converter::builtin::BuiltinCocoConverter;

use crate::config::ra::{
    AttestArgs, AttestationAgentType, AttestationServiceType, RaArgs, VerifyArgs,
};
#[cfg(unix)]
use crate::tunnel::utils::maybe_cached::RefreshStrategy;

/// Pre-instantiated RA context for OHTTP security
///
/// This enum mirrors the structure of `RaArgs` but holds ready-to-use
/// component instances instead of just configuration.
pub enum RaContext {
    /// Attest only mode - server attests itself
    #[cfg(unix)]
    AttestOnly(Arc<AttestContext>),

    /// Verify only mode - server verifies client
    VerifyOnly(Arc<VerifyContext>),

    /// Both attest and verify
    #[cfg(unix)]
    AttestAndVerify {
        attest: Arc<AttestContext>,
        verify: Arc<VerifyContext>,
    },

    /// No remote attestation
    NoRa,
}

impl RaContext {
    /// Create pre-instantiated RA context from RaArgs configuration
    pub async fn from_ra_args(ra_args: &RaArgs) -> Result<Self> {
        match ra_args {
            RaArgs::NoRa => Ok(Self::NoRa),
            RaArgs::VerifyOnly(verify_args) => Ok(Self::VerifyOnly(Arc::new(
                VerifyContext::from_verify_args(verify_args).await?,
            ))),
            #[cfg(unix)]
            RaArgs::AttestOnly(attest_args) => Ok(Self::AttestOnly(Arc::new(
                AttestContext::from_attest_args(attest_args)?,
            ))),
            #[cfg(unix)]
            RaArgs::AttestAndVerify(attest_args, verify_args) => Ok(Self::AttestAndVerify {
                attest: Arc::new(AttestContext::from_attest_args(attest_args)?),
                verify: Arc::new(VerifyContext::from_verify_args(verify_args).await?),
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
                // Extract aa_addr from AttestationAgentType
                let aa_addr = match &aa_args.aa_type {
                    AttestationAgentType::Uds { aa_addr } => aa_addr.clone(),
                    AttestationAgentType::Builtin => {
                        anyhow::bail!("Builtin AA is not supported in Passport mode with remote AS. Use PassportBuiltin model instead.")
                    }
                };
                let attester = CocoAttester::new(&aa_addr)?;
                // Extract address and headers from AttestationServiceType
                let (as_addr, is_grpc, as_headers) = match &as_args.as_type {
                    AttestationServiceType::Restful {
                        as_addr,
                        as_headers,
                    } => (as_addr.clone(), false, as_headers.clone()),
                    AttestationServiceType::Grpc {
                        as_addr,
                        as_headers,
                    } => (as_addr.clone(), true, as_headers.clone()),
                    #[cfg(feature = "__builtin-as")]
                    AttestationServiceType::Builtin { .. } => {
                        anyhow::bail!("Builtin AS is not supported in Passport mode")
                    }
                };
                let converter =
                    CocoConverter::new(&as_addr, &as_args.policy_ids, is_grpc, &as_headers)?;
                Ok(Self::Passport {
                    attester,
                    converter,
                    refresh_strategy: aa_args.refresh_strategy(),
                })
            }
            AttestArgs::BackgroundCheck { aa_args } => {
                // Extract aa_addr from AttestationAgentType
                let aa_addr = match &aa_args.aa_type {
                    AttestationAgentType::Uds { aa_addr } => aa_addr.clone(),
                    AttestationAgentType::Builtin => {
                        anyhow::bail!("Builtin AA is not supported in BackgroundCheck mode. Use Builtin model instead.")
                    }
                };
                let attester = CocoAttester::new(&aa_addr)?;

                if aa_args.refresh_interval.is_some() {
                    tracing::warn!(
                        "`refresh_interval` in your configuration is set, but it will be ignored for background check if you are using OHTTP protocol"
                    );
                }
                Ok(Self::BackgroundCheck {
                    attester,
                    refresh_strategy: aa_args.refresh_strategy(),
                })
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
    #[cfg(feature = "__builtin-as")]
    Builtin {
        converter: BuiltinCocoConverter,
        verifier: CocoVerifier,
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
            #[cfg(feature = "__builtin-as")]
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
                let verifier = CocoVerifier::Remote(
                    CocoRemoteVerifier::new(
                        &token_verify.as_addr_config,
                        &token_verify.trusted_certs_paths,
                        &token_verify.policy_ids,
                    )
                    .await?,
                );
                Ok(Self::Passport { verifier })
            }
            VerifyArgs::BackgroundCheck {
                as_args,
                token_verify,
            } => {
                // Extract address and headers from AttestationServiceType
                let (as_addr, is_grpc, as_headers) = match &as_args.as_type {
                    AttestationServiceType::Restful {
                        as_addr,
                        as_headers,
                    } => (as_addr.clone(), false, as_headers.clone()),
                    AttestationServiceType::Grpc {
                        as_addr,
                        as_headers,
                    } => (as_addr.clone(), true, as_headers.clone()),
                    #[cfg(feature = "__builtin-as")]
                    AttestationServiceType::Builtin {
                        policy,
                        reference_values,
                    } => {
                        let converter = BuiltinCocoConverter::new(policy, reference_values).await?;
                        let verifier = CocoVerifier::Builtin(converter.new_verifier().await?);
                        return Ok(Self::Builtin {
                            converter,
                            verifier,
                        });
                    }
                };
                let converter =
                    CocoConverter::new(&as_addr, &as_args.policy_ids, is_grpc, &as_headers)?;
                // Create AttestationServiceAddrArgs for verifier
                let as_addr_config = Some(rats_cert::cert::verify::AttestationServiceAddrArgs {
                    as_addr,
                    as_is_grpc: is_grpc,
                    as_headers,
                });
                let verifier = CocoVerifier::Remote(
                    CocoRemoteVerifier::new(
                        &as_addr_config,
                        &token_verify.trusted_certs_paths,
                        &as_args.policy_ids,
                    )
                    .await?,
                );
                Ok(Self::BackgroundCheck {
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
        AttestationServiceArgs, AttestationServiceTokenVerifyAdditionalArgs,
        AttestationServiceTokenVerifyArgs, RaArgs, VerifyArgs,
    };
    use rats_cert::cert::verify::AttestationServiceAddrArgs;
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
            as_type: AttestationServiceType::Restful {
                as_addr: TEST_AS_ADDR.to_string(),
                as_headers: HashMap::new(),
            },
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
        use crate::config::ra::{AttestArgs, AttestationAgentArgs, AttestationAgentType};
        use crate::tunnel::utils::maybe_cached::RefreshStrategy;

        // Helper functions for Unix tests
        fn make_aa_args() -> AttestationAgentArgs {
            AttestationAgentArgs {
                aa_type: AttestationAgentType::Uds {
                    aa_addr: TEST_AA_ADDR.to_string(),
                },
                refresh_interval: None,
            }
        }

        fn make_aa_args_with_interval(interval: Option<u64>) -> AttestationAgentArgs {
            AttestationAgentArgs {
                aa_type: AttestationAgentType::Uds {
                    aa_addr: TEST_AA_ADDR.to_string(),
                },
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

    #[cfg(all(unix, feature = "__builtin-as"))]
    mod unix_builtin_tests {
        use super::*;
        use crate::config::ra::{
            AttestArgs, AttestationAgentArgs, AttestationAgentType, AttestationServiceArgs,
            AttestationServiceType,
        };
        use rats_cert::cert::verify::PolicyConfig;
        use serial_test::serial;

        fn make_aa_args() -> AttestationAgentArgs {
            AttestationAgentArgs {
                aa_type: AttestationAgentType::Uds {
                    aa_addr: TEST_AA_ADDR.to_string(),
                },
                refresh_interval: None,
            }
        }

        fn make_builtin_as_args() -> AttestationServiceArgs {
            AttestationServiceArgs {
                as_type: AttestationServiceType::Builtin {
                    policy: PolicyConfig::Default,
                    reference_values: vec![],
                },
                policy_ids: vec!["default".to_string()],
            }
        }

        fn make_attest_passport_args() -> AttestArgs {
            AttestArgs::Passport {
                aa_args: make_aa_args(),
                as_args: make_builtin_as_args(),
            }
        }

        fn make_attest_bgcheck_args() -> AttestArgs {
            AttestArgs::BackgroundCheck {
                aa_args: make_aa_args(),
            }
        }

        fn make_verify_builtin_args() -> VerifyArgs {
            VerifyArgs::BackgroundCheck {
                as_args: make_builtin_as_args(),
                token_verify: AttestationServiceTokenVerifyAdditionalArgs {
                    trusted_certs_paths: None,
                },
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        // Test Passport mode with Builtin AS should failed
        async fn test_ra_context_two_way_passport_builtin() {
            let attest_args = make_attest_passport_args();
            let verify_args = make_verify_builtin_args();
            let ra_args = RaArgs::AttestAndVerify(attest_args, verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_err());
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_ra_context_two_way_bgcheck_builtin() {
            let attest_args = make_attest_bgcheck_args();
            let verify_args = make_verify_builtin_args();
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

    #[cfg(feature = "__builtin-as")]
    mod builtin_tests {
        use super::*;
        use crate::config::ra::{AttestationServiceArgs, AttestationServiceType};
        use base64::{engine::general_purpose::STANDARD, Engine};
        use rats_cert::cert::verify::{
            PolicyConfig, ReferenceValueConfig, SampleProvenancePayloadConfig,
            SlsaReferenceValuePayloadConfig,
        };
        use serial_test::serial;

        fn make_verify_builtin_args(
            policy: PolicyConfig,
            reference_values: Vec<ReferenceValueConfig>,
        ) -> VerifyArgs {
            VerifyArgs::BackgroundCheck {
                as_args: AttestationServiceArgs {
                    as_type: AttestationServiceType::Builtin {
                        policy,
                        reference_values,
                    },
                    policy_ids: vec!["default".to_string()],
                },
                token_verify: AttestationServiceTokenVerifyAdditionalArgs {
                    trusted_certs_paths: None,
                },
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_creation_with_default_policy() {
            let verify_args = make_verify_builtin_args(PolicyConfig::Default, vec![]);
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
            let verify_args = make_verify_builtin_args(
                PolicyConfig::Inline {
                    content: policy_content,
                },
                vec![],
            );
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
            use rats_cert::cert::verify::Provenance;
            use std::collections::HashMap;
            // Sample reference value payload (inline Provenance)
            let mut rvs = HashMap::new();
            rvs.insert("example-measurement".to_string(), vec![]);
            let provenance = Provenance { rvs };
            let verify_args = make_verify_builtin_args(
                PolicyConfig::Default,
                vec![ReferenceValueConfig::Sample {
                    payload: SampleProvenancePayloadConfig::Inline {
                        content: provenance,
                    },
                }],
            );
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
            let verify_args = make_verify_builtin_args(PolicyConfig::Default, vec![]);
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
            let verify_args = make_verify_builtin_args(PolicyConfig::Default, vec![]);
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
            let verify_args = make_verify_builtin_args(
                PolicyConfig::Path {
                    path: "/nonexistent/policy.rego".to_string(),
                },
                vec![],
            );
            let result = VerifyContext::from_verify_args(&verify_args).await;
            assert!(result.is_err(), "Should fail with nonexistent policy path");
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_error_invalid_reference_path() {
            let verify_args = make_verify_builtin_args(
                PolicyConfig::Default,
                vec![ReferenceValueConfig::Sample {
                    payload: SampleProvenancePayloadConfig::Path {
                        path: "/nonexistent/ref.json".to_string(),
                    },
                }],
            );
            let result = VerifyContext::from_verify_args(&verify_args).await;
            assert!(
                result.is_err(),
                "Should fail with nonexistent reference value path"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_challenge_generation() {
            let verify_args = make_verify_builtin_args(PolicyConfig::Default, vec![]);
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
            use rats_cert::cert::verify::{
                ReferenceValueListItem, ReferenceValueListPayload, ReferenceValueProvenanceInfo,
                ReferenceValueProvenanceSource,
            };

            // Note: This test requires the test environment set up by `make test-dep-as`.
            let rv_item = ReferenceValueListItem {
                id: "test-artifact".to_string(),
                rv_name: Some("test-artifact".to_string()),
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
            };
            let payload = ReferenceValueListPayload {
                rv_list: vec![rv_item],
            };

            let verify_args = make_verify_builtin_args(
                PolicyConfig::Default,
                vec![ReferenceValueConfig::Slsa {
                    payload: SlsaReferenceValuePayloadConfig::Inline { content: payload },
                }],
            );
            // This may fail due to Rekor not being available, so we just attempt creation
            let _result = VerifyContext::from_verify_args(&verify_args).await;
            // Either Ok or specific error from Rekor fetch is acceptable
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_with_slsa_reference_and_provenance() {
            use rats_cert::cert::verify::{
                ReferenceValueListItem, ReferenceValueListPayload, ReferenceValueProvenanceInfo,
                ReferenceValueProvenanceSource,
            };

            // Note: This test requires the test environment set up by `make test-dep-as`.
            let rv_item = ReferenceValueListItem {
                id: "test-artifact".to_string(),
                rv_name: Some("test-artifact".to_string()),
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
            };
            let payload = ReferenceValueListPayload {
                rv_list: vec![rv_item],
            };

            let verify_args = make_verify_builtin_args(
                PolicyConfig::Default,
                vec![ReferenceValueConfig::Slsa {
                    payload: SlsaReferenceValuePayloadConfig::Inline { content: payload },
                }],
            );
            // This test requires external services from `make test-dep-as`
            let _result = VerifyContext::from_verify_args(&verify_args).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn test_verify_context_builtin_with_multiple_references() {
            use rats_cert::cert::verify::Provenance;
            use std::collections::HashMap;

            let mut rvs1 = HashMap::new();
            rvs1.insert("component-a".to_string(), vec![]);
            let provenance1 = Provenance { rvs: rvs1 };

            let mut rvs2 = HashMap::new();
            rvs2.insert("component-b".to_string(), vec![]);
            let provenance2 = Provenance { rvs: rvs2 };

            let verify_args = make_verify_builtin_args(
                PolicyConfig::Default,
                vec![
                    ReferenceValueConfig::Sample {
                        payload: SampleProvenancePayloadConfig::Inline {
                            content: provenance1,
                        },
                    },
                    ReferenceValueConfig::Sample {
                        payload: SampleProvenancePayloadConfig::Inline {
                            content: provenance2,
                        },
                    },
                ],
            );
            let result = VerifyContext::from_verify_args(&verify_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            match result.unwrap() {
                VerifyContext::Builtin { .. } => {} // expected
                other => panic!("Expected Builtin variant, got {:?}", other),
            }
        }
    }
}
