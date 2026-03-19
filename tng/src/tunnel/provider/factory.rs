use anyhow::{bail, Result};
use rats_cert::cert::verify::{AttestationServiceConfig, CocoVerifyMode, CocoVerifyPolicy};
use rats_cert::tee::coco::attester::CocoAttester;
use rats_cert::tee::coco::converter::CocoConverter;
use rats_cert::tee::coco::verifier::CocoVerifier;

use crate::config::ra::{
    AttestArgs, AttestationServiceArgs, VerifyArgs,
};

use super::attester::TngAttester;
use super::converter::TngConverter;
use super::verifier::TngVerifier;
use super::verify_policy::TngVerifyPolicy;

/// Create an attester from the current config.
/// Pass `timeout_nano` to override the provider's default timeout.
pub fn create_attester(
    attest_args: &AttestArgs,
    timeout_nano: Option<i64>,
) -> Result<TngAttester> {
    let aa_args = match attest_args {
        AttestArgs::Passport { aa_args, .. } => aa_args,
        AttestArgs::BackgroundCheck { aa_args } => aa_args,
    };
    let attester = match timeout_nano {
        Some(t) => CocoAttester::new_with_timeout_nano(&aa_args.aa_addr, t)?,
        None => CocoAttester::new(&aa_args.aa_addr)?,
    };
    Ok(TngAttester::Coco(attester))
}

/// Create a converter from the current config. Only valid in passport mode.
/// When provider dispatching is added (Phase 2), this will match on converter_provider.
pub fn create_converter(attest_args: &AttestArgs) -> Result<TngConverter> {
    let as_args = match attest_args {
        AttestArgs::Passport { as_args, .. } => as_args,
        AttestArgs::BackgroundCheck { .. } => {
            bail!("converter not available in background check attest mode")
        }
    };
    Ok(TngConverter::Coco(CocoConverter::new(
        &as_args.as_addr_config.as_addr,
        &as_args.policy_ids,
        as_args.as_addr_config.as_is_grpc,
        &as_args.as_addr_config.as_headers,
    )?))
}

// TODO: Consolidate into a single create_converter taking ConverterConfig once Phase 2 config restructuring is done.
/// Create a converter from explicit AS args (used on the verify side in background check mode).
pub fn create_converter_from_as_args(as_args: &AttestationServiceArgs) -> Result<TngConverter> {
    Ok(TngConverter::Coco(CocoConverter::new(
        &as_args.as_addr_config.as_addr,
        &as_args.policy_ids,
        as_args.as_addr_config.as_is_grpc,
        &as_args.as_addr_config.as_headers,
    )?))
}

/// Create a verifier from the current config.
/// When provider dispatching is added (Phase 2), this will match on provider type.
pub async fn create_verifier(verify_args: &VerifyArgs) -> Result<TngVerifier> {
    match verify_args {
        VerifyArgs::Passport { token_verify } => {
            let as_addr_config = token_verify.as_addr_config.as_ref().map(|a| {
                AttestationServiceConfig {
                    as_addr: a.as_addr.clone(),
                    as_is_grpc: a.as_is_grpc,
                    as_headers: a.as_headers.clone(),
                }
            });
            Ok(TngVerifier::Coco(
                CocoVerifier::new(
                    as_addr_config,
                    &token_verify.trusted_certs_paths,
                    &token_verify.policy_ids,
                )
                .await?,
            ))
        }
        VerifyArgs::BackgroundCheck {
            as_args,
            token_verify,
        } => {
            let as_addr_config = AttestationServiceConfig {
                as_addr: as_args.as_addr_config.as_addr.clone(),
                as_is_grpc: as_args.as_addr_config.as_is_grpc,
                as_headers: as_args.as_addr_config.as_headers.clone(),
            };
            Ok(TngVerifier::Coco(
                CocoVerifier::new(
                    Some(as_addr_config),
                    &token_verify.trusted_certs_paths,
                    &as_args.policy_ids,
                )
                .await?,
            ))
        }
    }
}

/// Create a verify policy from the current config. Used in the RATS-TLS cert verification path.
/// When provider dispatching is added (Phase 2), this will match on provider type.
pub fn create_verify_policy(verify_args: &VerifyArgs) -> TngVerifyPolicy {
    match verify_args {
        VerifyArgs::Passport { token_verify } => {
            TngVerifyPolicy::Coco(CocoVerifyPolicy {
                verify_mode: CocoVerifyMode::Token,
                policy_ids: token_verify.policy_ids.clone(),
                trusted_certs_paths: token_verify.trusted_certs_paths.clone(),
                as_addr_config: token_verify.as_addr_config.as_ref().map(|a| {
                    AttestationServiceConfig {
                        as_addr: a.as_addr.clone(),
                        as_is_grpc: a.as_is_grpc,
                        as_headers: a.as_headers.clone(),
                    }
                }),
            })
        }
        VerifyArgs::BackgroundCheck {
            as_args,
            token_verify,
        } => {
            let as_config = AttestationServiceConfig {
                as_addr: as_args.as_addr_config.as_addr.clone(),
                as_is_grpc: as_args.as_addr_config.as_is_grpc,
                as_headers: as_args.as_addr_config.as_headers.clone(),
            };
            TngVerifyPolicy::Coco(CocoVerifyPolicy {
                verify_mode: CocoVerifyMode::Evidence(as_config.clone()),
                policy_ids: as_args.policy_ids.clone(),
                trusted_certs_paths: token_verify.trusted_certs_paths.clone(),
                as_addr_config: Some(as_config),
            })
        }
    }
}
