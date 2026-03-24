use anyhow::Result;
use rats_cert::cert::verify::{AttestationServiceConfig, CocoVerifyMode, CocoVerifyPolicy};
use rats_cert::tee::coco::attester::CocoAttester;
use rats_cert::tee::coco::converter::CocoConverter;
use rats_cert::tee::coco::verifier::CocoVerifier;

use crate::config::ra::{AsAddrConfig, AttesterConfig, ConverterConfig, VerifierConfig, VerifyArgs};

use super::attester::TngAttester;
use super::converter::TngConverter;
use super::verifier::TngVerifier;
use super::verify_policy::TngVerifyPolicy;

/// Create an attester from the provider-specific config.
pub fn create_attester(
    config: &AttesterConfig,
    timeout_nano: Option<i64>,
) -> Result<TngAttester> {
    match config {
        AttesterConfig::Coco { aa_addr } => {
            let attester = match timeout_nano {
                Some(t) => CocoAttester::new_with_timeout_nano(aa_addr, t)?,
                None => CocoAttester::new(aa_addr)?,
            };
            Ok(TngAttester::Coco(attester))
        }
    }
}

/// Create a converter from the provider-specific config.
pub fn create_converter(config: &ConverterConfig) -> Result<TngConverter> {
    match config {
        ConverterConfig::Coco {
            as_addr_config,
            policy_ids,
        } => Ok(TngConverter::Coco(CocoConverter::new(
            &as_addr_config.as_addr,
            policy_ids,
            as_addr_config.as_is_grpc,
            &as_addr_config.as_headers,
        )?)),
    }
}

/// Create a verifier from the provider-specific config.
pub async fn create_verifier(config: &VerifierConfig) -> Result<TngVerifier> {
    match config {
        VerifierConfig::Coco {
            policy_ids,
            trusted_certs_paths,
            as_addr_config,
        } => {
            let as_config = as_addr_config.as_ref().map(as_addr_to_service_config);
            Ok(TngVerifier::Coco(
                CocoVerifier::new(as_config, trusted_certs_paths, policy_ids).await?,
            ))
        }
    }
}

/// Create a verify policy from the current config. Used in the RATS-TLS cert verification path.
pub fn create_verify_policy(verify_args: &VerifyArgs) -> TngVerifyPolicy {
    match verify_args {
        VerifyArgs::Passport { verifier } => match verifier {
            VerifierConfig::Coco {
                policy_ids,
                trusted_certs_paths,
                as_addr_config,
            } => TngVerifyPolicy::Coco(CocoVerifyPolicy {
                verify_mode: CocoVerifyMode::Token,
                policy_ids: policy_ids.clone(),
                trusted_certs_paths: trusted_certs_paths.clone(),
                as_addr_config: as_addr_config.as_ref().map(as_addr_to_service_config),
            }),
        },
        VerifyArgs::BackgroundCheck {
            converter,
            verifier,
        } => match (converter, verifier) {
            (
                ConverterConfig::Coco {
                    as_addr_config, ..
                },
                VerifierConfig::Coco {
                    policy_ids,
                    trusted_certs_paths,
                    ..
                },
            ) => {
                let as_config = as_addr_to_service_config(as_addr_config);
                TngVerifyPolicy::Coco(CocoVerifyPolicy {
                    verify_mode: CocoVerifyMode::Evidence(as_config.clone()),
                    policy_ids: policy_ids.clone(),
                    trusted_certs_paths: trusted_certs_paths.clone(),
                    as_addr_config: Some(as_config),
                })
            }
        },
    }
}

fn as_addr_to_service_config(addr: &AsAddrConfig) -> AttestationServiceConfig {
    AttestationServiceConfig {
        as_addr: addr.as_addr.clone(),
        as_is_grpc: addr.as_is_grpc,
        as_headers: addr.as_headers.clone(),
    }
}
