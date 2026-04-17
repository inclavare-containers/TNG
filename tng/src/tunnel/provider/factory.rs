use anyhow::Result;
#[cfg(unix)]
use rats_cert::tee::coco::attester::CocoAttester;
use rats_cert::tee::coco::converter::grpc::CocoGrpcConverter;
use rats_cert::tee::coco::converter::restful::CocoRestfulConverter;
use rats_cert::tee::coco::converter::CocoConverter;
use rats_cert::tee::coco::verifier::remote::CocoRemoteVerifier;
use rats_cert::tee::coco::verifier::CocoVerifier;

#[cfg(unix)]
use crate::config::ra::{AttesterArgs, CocoAttesterArgs};
use crate::config::ra::{CocoConverterArgs, CocoVerifierArgs, ConverterArgs, VerifierArgs};

#[cfg(unix)]
use super::attester::TngAttester;
use super::converter::TngConverter;
use super::verifier::TngVerifier;

/// Instantiate a `TngAttester` from config. Dispatches on provider, then sub-type.
#[cfg(unix)]
pub fn create_attester(config: &AttesterArgs) -> Result<TngAttester> {
    match config {
        AttesterArgs::Coco(coco) => match coco {
            CocoAttesterArgs::Uds { aa_addr } => Ok(TngAttester::Coco(CocoAttester::new(aa_addr)?)),
            CocoAttesterArgs::Builtin => {
                anyhow::bail!("Builtin AA is not yet implemented")
            }
        },
    }
}

/// Instantiate a `TngConverter` from config. Dispatches on provider, then sub-type.
/// Note: Builtin AS converter creation via factory is not supported.
pub fn create_converter(config: &ConverterArgs) -> Result<TngConverter> {
    match config {
        ConverterArgs::Coco(coco) => match coco {
            CocoConverterArgs::Restful {
                as_addr,
                policy_ids,
                as_headers,
            } => Ok(TngConverter::Coco(CocoConverter::Restful(
                CocoRestfulConverter::new(as_addr, policy_ids, as_headers)?,
            ))),
            CocoConverterArgs::Grpc {
                as_addr,
                policy_ids,
                as_headers,
            } => Ok(TngConverter::Coco(CocoConverter::Grpc(
                CocoGrpcConverter::new(as_addr, policy_ids, as_headers)?,
            ))),
            #[cfg(feature = "__builtin-as")]
            CocoConverterArgs::Builtin { .. } => {
                anyhow::bail!("Builtin AS converter creation via factory is not supported")
            }
        },
    }
}

/// Instantiate a `TngVerifier` from config. Dispatches on provider, then sub-type.
/// Note: Builtin AS verifier creation via factory is not supported.
pub async fn create_verifier(config: &VerifierArgs) -> Result<TngVerifier> {
    match config {
        VerifierArgs::Coco(coco) => match coco {
            CocoVerifierArgs::Restful {
                as_addr,
                policy_ids,
                as_headers,
                trusted_certs_paths,
            } => {
                let as_addr_config = as_addr.as_ref().map(|addr| {
                    rats_cert::cert::verify::AttestationServiceAddrArgs {
                        as_addr: addr.clone(),
                        as_is_grpc: false,
                        as_headers: as_headers.clone(),
                    }
                });
                Ok(TngVerifier::Coco(CocoVerifier::Remote(
                    CocoRemoteVerifier::new(&as_addr_config, trusted_certs_paths, policy_ids)
                        .await?,
                )))
            }
            CocoVerifierArgs::Grpc {
                as_addr,
                policy_ids,
                as_headers,
                trusted_certs_paths,
            } => {
                let as_addr_config = as_addr.as_ref().map(|addr| {
                    rats_cert::cert::verify::AttestationServiceAddrArgs {
                        as_addr: addr.clone(),
                        as_is_grpc: true,
                        as_headers: as_headers.clone(),
                    }
                });
                Ok(TngVerifier::Coco(CocoVerifier::Remote(
                    CocoRemoteVerifier::new(&as_addr_config, trusted_certs_paths, policy_ids)
                        .await?,
                )))
            }
            #[cfg(feature = "__builtin-as")]
            CocoVerifierArgs::Builtin => {
                anyhow::bail!("Builtin AS verifier creation via factory is not supported")
            }
        },
    }
}
