use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::json;

use super::super::evidence::{
    tee_to_string, AttestationServiceHashAlgo, CocoAsToken, CocoEvidence,
};
use crate::errors::*;
use crate::tee::coco::converter::{convert_additional_evidence, CoCoNonce};
use crate::tee::GenericConverter;

mod as_api {
    pub mod v1_5_2 {
        include!(concat!(
            env!("OUT_DIR"),
            "/attestation-service/v1_5_2/attestation.rs"
        ));
    }

    pub mod v1_6_0 {
        include!(concat!(
            env!("OUT_DIR"),
            "/attestation-service/v1_6_0/attestation.rs"
        ));
    }
}

#[derive(Debug, Clone, Copy)]
pub enum GrpcAsVersion {
    V1_5_2,
    V1_6_0,
}

pub struct CocoGrpcConverter {
    as_addr: String,
    policy_ids: Vec<String>,
    request_metadata: tonic::metadata::MetadataMap,
}

impl CocoGrpcConverter {
    pub fn new(
        as_addr: &str,
        policy_ids: &Vec<String>,
        as_headers: &HashMap<String, String>,
    ) -> Result<Self> {
        let mut request_metadata = tonic::metadata::MetadataMap::new();
        for (key, value) in as_headers {
            request_metadata.insert(
                    <tonic::metadata::MetadataKey::<tonic::metadata::Ascii> as std::str::FromStr>::from_str(key.as_str())
                        .map_err(Error::InvalidGrpcMetadataKey)?,
                    <tonic::metadata::MetadataValue::<tonic::metadata::Ascii> as std::str::FromStr>::from_str(value.as_str())
                        .map_err(Error::InvalidGrpcMetadataValue)?,
                );
        }

        Ok(Self {
            as_addr: as_addr.to_string(),
            policy_ids: policy_ids.to_owned(),
            request_metadata,
        })
    }

    pub async fn get_nonce(&self) -> Result<CoCoNonce> {
        // grpc-as does not support the /challenge api, so we return a dummy nonce here
        tracing::warn!(
            "Connected to an grpc-as instance that does not support challenge token retrieval; falling back to dummy nonce. This may compromise freshness guarantees of evidence."
        );
        Ok(CoCoNonce::Jwt("dummy nonce".to_string()))
    }
}

#[async_trait::async_trait]
impl GenericConverter for CocoGrpcConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        tracing::debug!(
            "Convert CoCo evidence to CoCo AS token via grpc-as with policy ids: {:?}",
            self.policy_ids
        );

        match self.convert_v1_6_0(in_evidence).await {
            Ok(v) => Ok(v),
            Err(error) => {
                tracing::warn!(?error, "Failed to convert CoCo evidence to CoCo AS token via grpc-as, try to convert with old grpc-as version");
                self.convert_v1_5_2(in_evidence).await
            }
        }
    }
}

impl CocoGrpcConverter {
    async fn convert_v1_6_0(&self, in_evidence: &CocoEvidence) -> Result<CocoAsToken> {
        tracing::debug!("Connect to grpc-as with protobuf version 1.6.0");

        let runtime_data_hash_algorithm =
            AttestationServiceHashAlgo::from(in_evidence.get_aa_runtime_data_hash_algo()).str_id();

        let request = tonic::Request::from_parts(
            self.request_metadata.clone(),
            tonic::Extensions::new(),
    as_api::v1_6_0::AttestationRequest {
            verification_requests: std::iter::once(Ok(as_api::v1_6_0::IndividualAttestationRequest {
                tee: tee_to_string(*in_evidence.get_tee_type())?,
                evidence: URL_SAFE_NO_PAD.encode(in_evidence.aa_evidence_ref()),
                runtime_data: Some(
                    as_api::v1_6_0::individual_attestation_request::RuntimeData::StructuredRuntimeData(
                        in_evidence.aa_runtime_data_ref().into(),
                    ),
                ),
                init_data: None, // TODO: add support for init_data when support on AA is ready
                runtime_data_hash_algorithm: runtime_data_hash_algorithm.into(),
            })).chain(
                convert_additional_evidence(in_evidence)?
                    .iter()
                    .map(|(tee_type, evidence)| {
                        Ok(as_api::v1_6_0::IndividualAttestationRequest {
                            tee: tee_to_string(*tee_type)?,
                            evidence: URL_SAFE_NO_PAD.encode(evidence.to_string()),
                            init_data: None,
                            runtime_data: None, // Always None for additional evidence
                            runtime_data_hash_algorithm: "".to_owned(),
                        })
                    }),
            )
            .collect::<Result<Vec<_>>>()?,
            policy_ids: self.policy_ids.clone(),
        });

        let mut client =
            {
                #[cfg(not(all(
                    target_arch = "wasm32",
                    target_vendor = "unknown",
                    target_os = "unknown"
                )))]
                {
                    let endpoint = tonic::transport::Endpoint::new(self.as_addr.to_string())
                        .map_err(|e| Error::GrpcEndpointCreateFailed {
                            as_addr: self.as_addr.clone(),
                            source: e,
                        })?;
                    as_api::v1_6_0::attestation_service_client::AttestationServiceClient::new(
                        endpoint
                            .connect()
                            .await
                            .map_err(|e| Error::GrpcConnectFailed {
                                as_addr: self.as_addr.clone(),
                                source: e,
                            })?,
                    )
                }
                #[cfg(all(
                    target_arch = "wasm32",
                    target_vendor = "unknown",
                    target_os = "unknown"
                ))]
                as_api::v1_6_0::attestation_service_client::AttestationServiceClient::new(
                    tonic_web_wasm_client::Client::new(self.as_addr.to_string()),
                )
            };

        let fut = async move {
            let response: as_api::v1_6_0::AttestationResponse = client
                .attestation_evaluate(request)
                .await
                .map_err(|e| {
                    Error::AttestationServiceGrpcAttestationEvaluateFailed(GrpcAsVersion::V1_6_0, e)
                })?
                .into_inner();
            Ok::<_, Error>(response)
        };

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        // In wasm32 (web), the tonic Response future is not `Send` but #[async_trait::async_trait] requires the function body to be Sen. So we have to spawn it with tokio_with_wasm::task::spawn and await for it.
        let response = tokio_with_wasm::task::spawn(fut)
            .await
            .map_err(Error::TaskSpawnFailed)??;
        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let response = fut.await?;

        let attestation_token = response.attestation_token;

        CocoAsToken::new(attestation_token)
    }

    async fn convert_v1_5_2(&self, in_evidence: &CocoEvidence) -> Result<CocoAsToken> {
        tracing::debug!("Connect to grpc-as with protobuf version 1.5.2");

        if in_evidence.aa_additional_evidence_ref().is_some() {
            tracing::warn!("Additional evidence is not supported in grpc-as <= 1.5.2");
        }

        let runtime_data_hash_algorithm =
            AttestationServiceHashAlgo::from(in_evidence.get_aa_runtime_data_hash_algo()).str_id();

        let request = tonic::Request::from_parts(
            self.request_metadata.clone(),
            tonic::Extensions::new(),
            as_api::v1_5_2::AttestationRequest {
                tee: tee_to_string(*in_evidence.get_tee_type())?,
                evidence: URL_SAFE_NO_PAD.encode(in_evidence.aa_evidence_ref()),
                init_data: None, // TODO: add support for init_data when support on AA is ready
                init_data_hash_algorithm: "".into(),
                policy_ids: self.policy_ids.clone(),
                runtime_data: Some(
                    as_api::v1_5_2::attestation_request::RuntimeData::StructuredRuntimeData(
                        in_evidence.aa_runtime_data_ref().into(),
                    ),
                ),
                runtime_data_hash_algorithm: runtime_data_hash_algorithm.into(),
            },
        );

        let mut client =
            {
                #[cfg(not(all(
                    target_arch = "wasm32",
                    target_vendor = "unknown",
                    target_os = "unknown"
                )))]
                {
                    let endpoint = tonic::transport::Endpoint::new(self.as_addr.to_string())
                        .map_err(|e| Error::GrpcEndpointCreateFailed {
                            as_addr: self.as_addr.clone(),
                            source: e,
                        })?;
                    as_api::v1_5_2::attestation_service_client::AttestationServiceClient::new(
                        endpoint
                            .connect()
                            .await
                            .map_err(|e| Error::GrpcConnectFailed {
                                as_addr: self.as_addr.clone(),
                                source: e,
                            })?,
                    )
                }
                #[cfg(all(
                    target_arch = "wasm32",
                    target_vendor = "unknown",
                    target_os = "unknown"
                ))]
                as_api::v1_5_2::attestation_service_client::AttestationServiceClient::new(
                    tonic_web_wasm_client::Client::new(self.as_addr.to_string()),
                )
            };

        let fut = async move {
            let response: as_api::v1_5_2::AttestationResponse = client
                .attestation_evaluate(request)
                .await
                .map_err(|e| {
                    Error::AttestationServiceGrpcAttestationEvaluateFailed(GrpcAsVersion::V1_5_2, e)
                })?
                .into_inner();
            Ok::<_, Error>(response)
        };

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        // In wasm32 (web), the tonic Response future is not `Send` but #[async_trait::async_trait] requires the function body to be Sen. So we have to spawn it with tokio_with_wasm::task::spawn and await for it.
        let response = tokio_with_wasm::task::spawn(fut)
            .await
            .map_err(Error::TaskSpawnFailed)??;
        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let response = fut.await?;

        let attestation_token = response.attestation_token;

        CocoAsToken::new(attestation_token)
    }
}
