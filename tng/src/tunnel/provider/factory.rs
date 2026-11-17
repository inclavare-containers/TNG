use anyhow::Result;
#[cfg(unix)]
use rats_cert::tee::coco::attester::CocoAttester;
#[cfg(feature = "__builtin-as")]
use rats_cert::tee::coco::converter::builtin::BuiltinCocoConverter;
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
pub async fn create_attester(config: &AttesterArgs) -> Result<TngAttester> {
    match config {
        AttesterArgs::Coco(coco) => match coco {
            CocoAttesterArgs::Uds {
                aa_addr,
                tdx_carry_collateral,
            } => Ok(TngAttester::Coco(
                CocoAttester::new(aa_addr)?.with_tdx_carry_collateral(*tdx_carry_collateral),
            )),
            CocoAttesterArgs::Builtin => {
                anyhow::bail!("Builtin AA is not yet implemented")
            }
        },
        AttesterArgs::Ita(args) => Ok(TngAttester::Ita(args.to_attester()?)),
        AttesterArgs::CocoAsr(args) => Ok(TngAttester::CocoAsr(args.to_attester().await?)),
        AttesterArgs::ItaAsr(args) => Ok(TngAttester::ItaAsr(args.to_attester().await?)),
    }
}

/// Instantiate a `TngConverter` from config. Dispatches on provider, then sub-type.
///
/// Every config variant is constructible here, including the in-process
/// builtin AS. A builtin verifier must be paired with the converter that owns
/// the signer chain; use [`create_verifier_for_converter`] for that.
pub async fn create_converter(config: &ConverterArgs) -> Result<TngConverter> {
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
            CocoConverterArgs::Builtin {
                attestation_policy,
                reference_values,
            } => Ok(TngConverter::Coco(CocoConverter::Builtin(
                BuiltinCocoConverter::new(attestation_policy, reference_values).await?,
            ))),
        },
        ConverterArgs::Ita(args) => Ok(TngConverter::Ita(args.to_converter()?)),
    }
}

/// Instantiate a `TngVerifier` that does not depend on a converter.
///
/// The builtin verifier cannot be built this way: it must trust the
/// self-signed chain of the in-process AS that signs the converter's tokens.
/// Background-check verification builds it through
/// [`create_verifier_for_converter`] instead.
pub async fn create_verifier(config: &VerifierArgs) -> Result<TngVerifier> {
    match config {
        VerifierArgs::Coco(coco) => match coco {
            CocoVerifierArgs::Restful {
                as_addr,
                policy_ids,
                as_headers,
                #[cfg(not(wasm))]
                trusted_certs_paths,
                verify_signer_transparency,
                skip_as_token_cert_verify,
            } => {
                let as_addr_config = as_addr.as_ref().map(|addr| {
                    rats_cert::cert::verify::AttestationServiceAddrArgs {
                        as_addr: addr.clone(),
                        as_is_grpc: false,
                        as_headers: as_headers.clone(),
                    }
                });
                Ok(TngVerifier::Coco(CocoVerifier::Remote(
                    CocoRemoteVerifier::new(
                        &as_addr_config,
                        #[cfg(not(wasm))]
                        trusted_certs_paths,
                        policy_ids,
                        *verify_signer_transparency,
                        *skip_as_token_cert_verify,
                    )
                    .await?,
                )))
            }
            CocoVerifierArgs::Grpc {
                as_addr,
                policy_ids,
                as_headers,
                #[cfg(not(wasm))]
                trusted_certs_paths,
                verify_signer_transparency,
                skip_as_token_cert_verify,
            } => {
                let as_addr_config = as_addr.as_ref().map(|addr| {
                    rats_cert::cert::verify::AttestationServiceAddrArgs {
                        as_addr: addr.clone(),
                        as_is_grpc: true,
                        as_headers: as_headers.clone(),
                    }
                });
                Ok(TngVerifier::Coco(CocoVerifier::Remote(
                    CocoRemoteVerifier::new(
                        &as_addr_config,
                        #[cfg(not(wasm))]
                        trusted_certs_paths,
                        policy_ids,
                        *verify_signer_transparency,
                        *skip_as_token_cert_verify,
                    )
                    .await?,
                )))
            }
            #[cfg(feature = "__builtin-as")]
            CocoVerifierArgs::Builtin => {
                anyhow::bail!(
                    "Builtin AS verifier must be built from the builtin converter; use create_verifier_for_converter"
                )
            }
        },
        VerifierArgs::Ita(args) => Ok(TngVerifier::Ita(args.to_verifier()?)),
    }
}

/// Instantiate a `TngVerifier` paired with an already-constructed converter.
///
/// Only the builtin verifier depends on the converter. It trusts the
/// self-signed chain that the in-process AS signs its tokens with, so building
/// it from that same converter instance keeps the pair consistent and avoids
/// standing up a second in-process AS. Remote verifiers ignore the converter
/// and delegate to [`create_verifier`].
pub async fn create_verifier_for_converter(
    converter: &TngConverter,
    config: &VerifierArgs,
) -> Result<TngVerifier> {
    #[cfg(feature = "__builtin-as")]
    if matches!(config, VerifierArgs::Coco(CocoVerifierArgs::Builtin)) {
        return match converter {
            TngConverter::Coco(CocoConverter::Builtin(builtin)) => Ok(TngVerifier::Coco(
                CocoVerifier::Builtin(builtin.new_verifier().await?),
            )),
            other => anyhow::bail!(
                "Builtin AS verifier requires the builtin converter, got provider {}",
                other.provider_type()
            ),
        };
    }

    create_verifier(config).await
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rats_cert::tee::coco::converter::CocoConverter;
    use rats_cert::tee::coco::verifier::CocoVerifier;

    use super::*;
    use crate::config::ra::ItaConverterArgs;
    use crate::tunnel::provider::ProviderType;

    fn restful_converter_args() -> ConverterArgs {
        ConverterArgs::Coco(CocoConverterArgs::Restful {
            as_addr: "http://127.0.0.1:8080".to_string(),
            policy_ids: vec!["default".to_string()],
            as_headers: HashMap::new(),
        })
    }

    fn grpc_converter_args() -> ConverterArgs {
        ConverterArgs::Coco(CocoConverterArgs::Grpc {
            as_addr: "http://127.0.0.1:5000".to_string(),
            policy_ids: vec!["default".to_string()],
            as_headers: HashMap::new(),
        })
    }

    fn ita_converter_args() -> ConverterArgs {
        ConverterArgs::Ita(ItaConverterArgs {
            as_addr: "https://api.trustauthority.example.com".to_string(),
            api_key: Some("test-key".to_string()),
            policy_ids: vec!["default".to_string()],
        })
    }

    #[cfg(feature = "__builtin-as")]
    fn builtin_converter_args() -> ConverterArgs {
        ConverterArgs::Coco(CocoConverterArgs::Builtin {
            attestation_policy: crate::config::ra::PolicyConfig::HardwareOnly,
            reference_values: vec![],
        })
    }

    #[cfg(feature = "__builtin-as")]
    fn builtin_verifier_args() -> VerifierArgs {
        VerifierArgs::Coco(CocoVerifierArgs::Builtin)
    }

    #[tokio::test]
    async fn create_converter_constructs_remote_variants() {
        let restful = create_converter(&restful_converter_args())
            .await
            .expect("restful converter constructs");
        assert_eq!(restful.provider_type(), ProviderType::Coco);

        let grpc = create_converter(&grpc_converter_args())
            .await
            .expect("grpc converter constructs");
        assert_eq!(grpc.provider_type(), ProviderType::Coco);

        let ita = create_converter(&ita_converter_args())
            .await
            .expect("ita converter constructs");
        assert_eq!(ita.provider_type(), ProviderType::Ita);
    }

    #[cfg(feature = "__builtin-as")]
    #[tokio::test]
    #[serial_test::serial]
    async fn builtin_converter_constructs() {
        let converter = create_converter(&builtin_converter_args())
            .await
            .expect("builtin converter constructs");
        assert!(
            matches!(converter, TngConverter::Coco(CocoConverter::Builtin(_))),
            "expected the builtin adapter"
        );
    }

    #[cfg(feature = "__builtin-as")]
    #[tokio::test]
    #[serial_test::serial]
    async fn builtin_verifier_is_built_from_the_builtin_converter() {
        let converter = create_converter(&builtin_converter_args()).await.unwrap();
        assert!(
            matches!(converter, TngConverter::Coco(CocoConverter::Builtin(_))),
            "expected the builtin adapter"
        );

        let verifier = create_verifier_for_converter(&converter, &builtin_verifier_args())
            .await
            .expect("builtin verifier is built from the converter");
        assert!(
            matches!(verifier, TngVerifier::Coco(CocoVerifier::Builtin(_))),
            "expected the builtin verifier"
        );
    }

    #[cfg(feature = "__builtin-as")]
    #[tokio::test]
    #[serial_test::serial]
    async fn builtin_verifier_rejects_standalone_and_unpaired_construction() {
        assert!(
            create_verifier(&builtin_verifier_args()).await.is_err(),
            "a builtin verifier cannot be built without its converter"
        );

        let restful = create_converter(&restful_converter_args()).await.unwrap();
        assert!(
            create_verifier_for_converter(&restful, &builtin_verifier_args())
                .await
                .is_err(),
            "a builtin verifier cannot pair with a remote converter"
        );
    }
}
