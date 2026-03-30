use std::collections::HashMap;

use grpc::CocoGrpcConverter;
use restful::CocoRestfulConverter;
use serde::{Deserialize, Serialize};

use super::evidence::{CocoAsToken, CocoEvidence};
use crate::errors::*;
#[cfg(feature = "builtin-as")]
use crate::tee::coco::converter::builtin::BuiltinCocoConverter;
use crate::tee::coco::evidence::AaTeeType;
use crate::{
    crypto::HashAlgo,
    tee::{GenericConverter, TeeType},
};

#[cfg(feature = "builtin-as")]
pub mod builtin;
pub mod grpc;
pub mod restful;

#[derive(Serialize, Deserialize)]
pub enum AttestationServiceHashAlgo {
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "sha384")]
    Sha384,
    #[serde(rename = "sha512")]
    Sha512,
}

impl AttestationServiceHashAlgo {
    pub fn str_id(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
}

impl From<HashAlgo> for AttestationServiceHashAlgo {
    fn from(hash_algo: HashAlgo) -> Self {
        match hash_algo {
            HashAlgo::Sha256 => Self::Sha256,
            HashAlgo::Sha384 => Self::Sha384,
            HashAlgo::Sha512 => Self::Sha512,
        }
    }
}

impl From<AttestationServiceHashAlgo> for HashAlgo {
    fn from(as_hash_algo: AttestationServiceHashAlgo) -> Self {
        match as_hash_algo {
            AttestationServiceHashAlgo::Sha256 => Self::Sha256,
            AttestationServiceHashAlgo::Sha384 => Self::Sha384,
            AttestationServiceHashAlgo::Sha512 => Self::Sha512,
        }
    }
}

pub enum CocoConverter {
    Grpc(CocoGrpcConverter),
    Restful(CocoRestfulConverter),
    #[cfg(feature = "builtin-as")]
    Builtin(BuiltinCocoConverter),
}

impl CocoConverter {
    pub fn new(
        as_addr: &str,
        policy_ids: &Vec<String>,
        as_is_grpc: bool,
        as_headers: &HashMap<String, String>,
    ) -> Result<Self> {
        Ok(if as_is_grpc {
            Self::Grpc(CocoGrpcConverter::new(as_addr, policy_ids, as_headers)?)
        } else {
            Self::Restful(CocoRestfulConverter::new(as_addr, policy_ids, as_headers)?)
        })
    }

    pub async fn get_nonce(&self) -> Result<CoCoNonce> {
        match self {
            CocoConverter::Grpc(converter) => converter.get_nonce().await,
            CocoConverter::Restful(converter) => converter.get_nonce().await,
            #[cfg(feature = "builtin-as")]
            CocoConverter::Builtin(converter) => {
                let challenge = converter.generate_challenge().await?;
                Ok(CoCoNonce::Jwt(challenge))
            }
        }
    }
}

pub enum CoCoNonce {
    Jwt(String),
}

#[async_trait::async_trait]

impl GenericConverter for CocoConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        match self {
            CocoConverter::Grpc(converter) => converter.convert(in_evidence).await,
            CocoConverter::Restful(converter) => converter.convert(in_evidence).await,
            #[cfg(feature = "builtin-as")]
            CocoConverter::Builtin(converter) => converter.convert(in_evidence).await,
        }
    }
}

pub(crate) fn convert_additional_evidence(
    in_evidence: &CocoEvidence,
) -> Result<Vec<(AaTeeType, serde_json::Value)>> {
    if let Some(json_bytes) = in_evidence.aa_additional_evidence_ref() {
        let additional_evidence_map: HashMap<String, serde_json::Value> =
            serde_json::from_slice(json_bytes)
                .context("Failed to parse JSON from additional evidence")?;

        let additional_evidence_map = additional_evidence_map
            .into_iter()
            .map(|(k, v)| (AaTeeType::from_attestation_agent_str_id(&k), v))
            .collect::<Vec<(AaTeeType, serde_json::Value)>>();

        Ok(additional_evidence_map)
    } else {
        Ok(Vec::new())
    }
}
