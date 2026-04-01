use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use kbs_types::Tee;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;

use super::super::evidence::{AttestationServiceHashAlgo, CocoAsToken, CocoEvidence};
use crate::errors::*;
use crate::tee::coco::converter::convert_additional_evidence;
use crate::tee::coco::converter::CoCoNonce;
use crate::tee::GenericConverter;

#[derive(Debug, Clone, Copy)]
pub enum RestfulAsApiVersion {
    V1_5_2,
    V1_6_0,
}

#[cfg(unix)]
pub const RESTFUL_AS_CONNECT_TIMEOUT_DEFAULT: u64 = 5;

pub struct CocoRestfulConverter {
    as_addr: String,
    policy_ids: Vec<String>,
    client: Client,
}

impl CocoRestfulConverter {
    pub fn new(
        as_addr: &str,
        policy_ids: &Vec<String>,
        as_headers: &HashMap<String, String>,
    ) -> Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        for (k, v) in as_headers {
            headers.insert(
                reqwest::header::HeaderName::from_str(k)
                    .map_err(Error::InvalidAttestationServiceHeaderName)?,
                v.parse()
                    .map_err(Error::InvalidAttestationServiceHeaderValue)?,
            );
        }

        let client = {
            let mut builder = reqwest::Client::builder()
                .user_agent(format!("rats-rs/{}", env!("CARGO_PKG_VERSION")));
            builder = builder.default_headers(headers);
            #[cfg(unix)]
            let builder =
                builder.connect_timeout(Duration::from_secs(RESTFUL_AS_CONNECT_TIMEOUT_DEFAULT));
            builder
                .build()
                .map_err(Error::AttestationServiceHttpClientBuildFailed)?
        };

        Ok(Self {
            as_addr: as_addr.trim_end_matches('/').to_owned(),
            client,
            policy_ids: policy_ids.to_owned(),
        })
    }

    pub async fn get_nonce(&self) -> Result<CoCoNonce> {
        tracing::debug!("Connect to restful-as with protobuf version 1.6.0");

        let url = format!("{}/challenge", self.as_addr);

        let client = self.client.clone();

        let fut = async move {
            let response = client
                .post(url)
                .json(&json!({}))
                .send()
                .await
                .map_err(|e| {
                    Error::AttestationServiceChallengeHttpRequestSendFailed(
                        RestfulAsApiVersion::V1_6_0,
                        e,
                    )
                })?;

            let status = response.status();
            let text = response.text().await.map_err(|e| {
                Error::AttestationServiceChallengeHttpResponseReadFailed(
                    RestfulAsApiVersion::V1_6_0,
                    e,
                )
            })?;

            Ok::<_, Error>((status, text))
        };

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        // In wasm32 (web), the reqwest Response future is not `Send` but #[async_trait::async_trait] requires the function body to be Send. So we have to spawn it with tokio_with_wasm::task::spawn and await for it.
        let (status, text) = tokio_with_wasm::task::spawn(fut)
            .await
            .map_err(|e| Error::TaskSpawnFailed(e))??;
        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let (status, text) = fut.await?;

        let body_text = match status {
            reqwest::StatusCode::OK => text,
            _ => {
                // Add compatibility with older trustee versions which does not support /challenge api
                if text.contains("Failed to get inner tee") {
                    tracing::warn!(
                        "Connected to an older version of restful-as that does not support challenge token retrieval; falling back to dummy nonce. This may compromise freshness guarantees of evidence."
                    );
                    return Ok(CoCoNonce::Jwt("dummy nonce".to_string()));
                }

                return Err(Error::AttestationServiceChallengeHttpResponseError {
                    api_version: RestfulAsApiVersion::V1_6_0,
                    status_code: status.as_u16(),
                    response_body: text,
                });
            }
        };

        let challenge_response = serde_json::from_str::<GetChallengeResponse>(&body_text)
            .map_err(Error::ParseChallengeResponseFailed)?;

        Ok(CoCoNonce::Jwt(challenge_response.extra_params.jwt))
    }
}

mod as_api {
    pub mod v1_5_2 {
        use super::super::*;

        // Copy from https://github.com/confidential-containers/trustee/blob/7dbd42f0baeb3d26d75d43ab73b29a168d584472/attestation-service/attestation-service/src/bin/restful/mod.rs#L36-L45
        #[derive(Debug, Serialize, Deserialize)]
        pub struct AttestationRequest {
            pub tee: Tee,
            pub evidence: String,
            pub runtime_data: Option<Data>,
            pub init_data: Option<Data>,
            pub runtime_data_hash_algorithm: Option<String>,
            pub init_data_hash_algorithm: Option<String>,
            pub policy_ids: Vec<String>,
        }

        // Copy from https://github.com/confidential-containers/trustee/blob/7dbd42f0baeb3d26d75d43ab73b29a168d584472/attestation-service/attestation-service/src/bin/restful/mod.rs#L55-L60
        #[derive(Debug, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum Data {
            Raw(String),
            Structured(Value),
        }
    }

    pub mod v1_6_0 {
        use super::super::*;

        #[derive(Debug, Serialize, Deserialize)]
        pub struct AttestationRequest {
            pub verification_requests: Vec<IndividualAttestationRequest>,
            pub policy_ids: Vec<String>,
        }

        #[derive(Debug, Serialize, Deserialize)]
        pub struct IndividualAttestationRequest {
            pub tee: Tee,
            pub evidence: String,
            pub runtime_data: Option<RuntimeData>,
            pub init_data: Option<InitDataInput>,
            pub runtime_data_hash_algorithm: Option<String>,
        }

        #[derive(Debug, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum RuntimeData {
            Raw(String),
            Structured(Value),
        }

        #[derive(Debug, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum InitDataInput {
            InitDataDigest(String),
            InitDataToml(String),
        }
    }
}

#[async_trait::async_trait]
impl GenericConverter for CocoRestfulConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        tracing::debug!(
            "Convert CoCo evidence to CoCo AS token via restful-as with policy ids: {:?}",
            self.policy_ids
        );

        self.convert_v1_6_0_or_fallback(in_evidence).await
    }
}

impl CocoRestfulConverter {
    async fn convert_v1_6_0_or_fallback(&self, in_evidence: &CocoEvidence) -> Result<CocoAsToken> {
        tracing::debug!("Connect to restful-as with protobuf version 1.6.0");

        let runtime_data_hash_algorithm =
            AttestationServiceHashAlgo::from(in_evidence.get_aa_runtime_data_hash_algo()).str_id();

        let url = format!("{}/attestation", self.as_addr);
        let body = as_api::v1_6_0::AttestationRequest {
            verification_requests: std::iter::once(as_api::v1_6_0::IndividualAttestationRequest {
                tee: *in_evidence.get_tee_type(),
                evidence: URL_SAFE_NO_PAD.encode(in_evidence.aa_evidence_ref()),
                init_data: None, // TODO: add support for init_data when support on AA is ready
                runtime_data: Some(as_api::v1_6_0::RuntimeData::Structured(
                    serde_json::from_str(in_evidence.aa_runtime_data_ref())
                        .map_err(Error::ParseRuntimeDataJsonFailed)?,
                )),
                runtime_data_hash_algorithm: Some(runtime_data_hash_algorithm.into()),
            })
            .chain(
                convert_additional_evidence(in_evidence)?
                    .iter()
                    .map(|(tee_type, evidence)| {
                        as_api::v1_6_0::IndividualAttestationRequest {
                            tee: *tee_type,
                            evidence: URL_SAFE_NO_PAD.encode(evidence.to_string()),
                            init_data: None,
                            runtime_data: None, // Always None for additional evidence
                            runtime_data_hash_algorithm: None,
                        }
                    }),
            )
            .collect::<Vec<_>>(),
            policy_ids: self.policy_ids.clone(),
        };
        let client = self.client.clone();

        let fut = async move {
            let response = client.post(url).json(&body).send().await.map_err(|e| {
                Error::AttestationServiceAttestationHttpRequestSendFailed(
                    RestfulAsApiVersion::V1_6_0,
                    e,
                )
            })?;

            let status = response.status();
            let text = response.text().await.map_err(|e| {
                Error::AttestationServiceAttestationHttpResponseReadFailed(
                    RestfulAsApiVersion::V1_6_0,
                    e,
                )
            })?;
            Ok::<_, Error>((status, text))
        };

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        // In wasm32 (web), the reqwest Response future is not `Send` but #[async_trait::async_trait] requires the function body to be Send. So we have to spawn it with tokio_with_wasm::task::spawn and await for it.
        let (status, text) = tokio_with_wasm::task::spawn(fut)
            .await
            .map_err(|e| Error::TaskSpawnFailed(e))??;
        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let (status, text) = fut.await?;

        let attestation_token = match status {
            reqwest::StatusCode::OK => text,
            _ => {
                // Add compatibility with older trustee versions which use different request parameters
                if text.contains("missing field `tee`") {
                    tracing::warn!(
                        "Connected to an older version of restful-as <= 1.5.2, fallback to use old request parameters and try again"
                    );
                    return self.convert_v1_5_2(in_evidence).await;
                }

                return Err(Error::AttestationServiceAttestationHttpResponseError {
                    api_version: RestfulAsApiVersion::V1_6_0,
                    status_code: status.as_u16(),
                    response_body: text,
                });
            }
        };

        CocoAsToken::new(attestation_token)
    }

    async fn convert_v1_5_2(&self, in_evidence: &CocoEvidence) -> Result<CocoAsToken> {
        tracing::debug!("Connect to restful-as with protobuf version 1.5.2");

        if in_evidence.aa_additional_evidence_ref().is_some() {
            tracing::warn!("Additional evidence is not supported in restful-as <= 1.5.2");
        }

        let runtime_data_hash_algorithm =
            AttestationServiceHashAlgo::from(in_evidence.get_aa_runtime_data_hash_algo()).str_id();

        let url = format!("{}/attestation", self.as_addr);
        let body = as_api::v1_5_2::AttestationRequest {
            tee: *in_evidence.get_tee_type(),
            evidence: URL_SAFE_NO_PAD.encode(in_evidence.aa_evidence_ref()),
            init_data: None, // TODO: add support for init_data when support on AA is ready
            init_data_hash_algorithm: None,
            policy_ids: self.policy_ids.clone(),
            runtime_data: Some(as_api::v1_5_2::Data::Structured(
                serde_json::from_str(in_evidence.aa_runtime_data_ref())
                    .map_err(Error::ParseRuntimeDataJsonFailed)?,
            )),
            runtime_data_hash_algorithm: Some(runtime_data_hash_algorithm.into()),
        };
        let client = self.client.clone();

        let fut = async move {
            let response = client.post(url).json(&body).send().await.map_err(|e| {
                Error::AttestationServiceAttestationHttpRequestSendFailed(
                    RestfulAsApiVersion::V1_5_2,
                    e,
                )
            })?;

            let status = response.status();
            let text = response.text().await.map_err(|e| {
                Error::AttestationServiceAttestationHttpResponseReadFailed(
                    RestfulAsApiVersion::V1_5_2,
                    e,
                )
            })?;
            Ok::<_, Error>((status, text))
        };

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        // In wasm32 (web), the reqwest Response future is not `Send` but #[async_trait::async_trait] requires the function body to be Sen. So we have to spawn it with tokio_with_wasm::task::spawn and await for it.
        let (status, text) = tokio_with_wasm::task::spawn(fut)
            .await
            .map_err(|e| Error::TaskSpawnFailed(e))??;
        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let (status, text) = fut.await?;

        let attestation_token = match status {
            reqwest::StatusCode::OK => text,
            _ => {
                return Err(Error::AttestationServiceAttestationHttpResponseError {
                    api_version: RestfulAsApiVersion::V1_5_2,
                    status_code: status.as_u16(),
                    response_body: text,
                });
            }
        };

        CocoAsToken::new(attestation_token)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetChallengeResponse {
    pub nonce: String,
    #[serde(rename = "extra_params")]
    #[serde(alias = "extra-params")]
    pub extra_params: ExtraParams,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExtraParams {
    pub jwt: String,
}
