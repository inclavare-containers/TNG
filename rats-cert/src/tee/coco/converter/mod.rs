use std::collections::HashMap;

use grpc::CocoGrpcConverter;
use kbs_types::Tee;
use restful::CocoRestfulConverter;

use super::evidence::{AttestationServiceHashAlgo, CocoAsToken, CocoEvidence};
use crate::errors::*;
#[cfg(feature = "__builtin-as")]
use crate::tee::coco::converter::builtin::BuiltinCocoConverter;
use crate::tee::{ConverterCapabilities, GenericConverter};

#[cfg(feature = "__builtin-as")]
pub mod builtin;
pub mod grpc;
pub mod restful;

pub enum CocoConverter {
    Grpc(CocoGrpcConverter),
    Restful(CocoRestfulConverter),
    #[cfg(feature = "__builtin-as")]
    Builtin(BuiltinCocoConverter),
}

impl CocoConverter {
    /// The attestation-service address this converter targets (for error context).
    pub fn as_addr(&self) -> &str {
        match self {
            CocoConverter::Restful(c) => c.as_addr(),
            CocoConverter::Grpc(c) => c.as_addr(),
            #[cfg(feature = "__builtin-as")]
            CocoConverter::Builtin(c) => c.as_addr(),
        }
    }

    /// The observable behavior of the selected adapter.
    pub fn capabilities(&self) -> ConverterCapabilities {
        match self {
            CocoConverter::Restful(c) => c.capabilities(),
            CocoConverter::Grpc(c) => c.capabilities(),
            #[cfg(feature = "__builtin-as")]
            CocoConverter::Builtin(c) => c.capabilities(),
        }
    }
}

#[cfg_attr(wasm, async_trait::async_trait(?Send))]
#[cfg_attr(not(wasm), async_trait::async_trait)]

impl GenericConverter for CocoConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;
    type Nonce = String;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        match self {
            CocoConverter::Grpc(converter) => converter.convert(in_evidence).await,
            CocoConverter::Restful(converter) => converter.convert(in_evidence).await,
            #[cfg(feature = "__builtin-as")]
            CocoConverter::Builtin(converter) => converter.convert(in_evidence).await,
        }
    }

    async fn get_nonce(&self) -> Result<Self::Nonce> {
        match self {
            CocoConverter::Grpc(converter) => converter.get_nonce().await,
            CocoConverter::Restful(converter) => converter.get_nonce().await,
            #[cfg(feature = "__builtin-as")]
            CocoConverter::Builtin(converter) => converter.get_nonce().await,
        }
    }
}

pub(crate) fn convert_additional_evidence(
    in_evidence: &CocoEvidence,
) -> Result<Vec<(Tee, serde_json::Value)>> {
    if let Some(json_bytes) = in_evidence.aa_additional_evidence_ref() {
        let additional_evidence_map: HashMap<Tee, serde_json::Value> =
            serde_json::from_slice(json_bytes).map_err(Error::ParseAdditionalEvidenceJsonFailed)?;

        Ok(additional_evidence_map.into_iter().collect())
    } else {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::{FallbackCapability, NonceCapability};
    use std::collections::HashMap;

    #[test]
    fn restful_capabilities_match_its_fallback_and_nonce_behavior() {
        let converter =
            CocoRestfulConverter::new("http://127.0.0.1:8080", &Vec::new(), &HashMap::new())
                .expect("restful converter builds without a connection");
        assert_eq!(
            converter.capabilities(),
            ConverterCapabilities {
                nonce: NonceCapability::SignedOrDummy,
                fallback: FallbackCapability::OnSpecificError,
                policy_ids: true,
                additional_evidence: true,
            }
        );
    }

    #[test]
    fn grpc_capabilities_match_its_fallback_and_nonce_behavior() {
        let converter =
            CocoGrpcConverter::new("http://127.0.0.1:5000", &Vec::new(), &HashMap::new())
                .expect("grpc converter builds without a connection");
        assert_eq!(
            converter.capabilities(),
            ConverterCapabilities {
                nonce: NonceCapability::Dummy,
                fallback: FallbackCapability::OnAnyError,
                policy_ids: true,
                additional_evidence: false,
            }
        );
    }

    #[cfg(feature = "__builtin-as")]
    #[tokio::test]
    async fn builtin_capabilities_match_its_in_process_behavior() {
        use crate::tee::coco::converter::builtin::{BuiltinCocoConverter, PolicyConfig};

        let converter = BuiltinCocoConverter::new(&PolicyConfig::HardwareOnly, &[])
            .await
            .expect("builtin converter builds");
        assert_eq!(
            converter.capabilities(),
            ConverterCapabilities {
                nonce: NonceCapability::Signed,
                fallback: FallbackCapability::None,
                policy_ids: false,
                additional_evidence: true,
            }
        );
    }

    #[cfg(feature = "__builtin-as")]
    #[tokio::test]
    async fn builtin_converter_and_its_verifier_share_the_signer_chain() {
        use crate::tee::coco::converter::builtin::{BuiltinCocoConverter, PolicyConfig};

        let converter = BuiltinCocoConverter::new(&PolicyConfig::HardwareOnly, &[])
            .await
            .expect("builtin converter builds");
        let verifier = converter
            .new_verifier()
            .await
            .expect("builtin verifier builds from the converter");
        assert_eq!(verifier.trusted_certs(), converter.signer_cert_chain());

        // Each converter generates a fresh self-signed identity, so a verifier
        // built from a different converter does not share this chain.
        let other = BuiltinCocoConverter::new(&PolicyConfig::HardwareOnly, &[])
            .await
            .expect("second builtin converter builds");
        assert_ne!(other.signer_cert_chain(), converter.signer_cert_chain());
    }
}
