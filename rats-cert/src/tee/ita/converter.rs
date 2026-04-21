use std::time::Duration;

use again::RetryPolicy;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::errors::*;
use crate::tee::GenericConverter;

use super::evidence::{ItaEvidence, ItaNonce};
use super::token::ItaToken;

/// ITA delegates GPU evidence verification to NVIDIA's Remote Attestation Service
/// (NRAS), which may transiently fail. Intel recommends client-side retry logic for
/// GPU attestation requests.
/// See: https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html#:~:text=recommended%20to%20include-,retry%20logic,-in%20the%20client
const ITA_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(100);
const ITA_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);
const ITA_MAX_RETRIES: usize = 4;

const ITA_NONCE_PATH: &str = "/appraisal/v2/nonce";
const ITA_ATTEST_PATH: &str = "/appraisal/v2/attest";

// ---------------------------------------------------------------------------
// ITA API request/response types (private)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ItaAttestRequest {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policy_ids: Vec<String>,
    token_signing_alg: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    policy_must_match: bool,
    tdx: TdxEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    nvgpu: Option<NvgpuEvidence>,
}

#[derive(Serialize)]
struct TdxEvidence {
    quote: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_nonce: Option<ItaNonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_data: Option<String>,
}

#[derive(Serialize)]
struct NvgpuEvidence {
    evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_nonce: Option<ItaNonce>,
    gpu_nonce: String,
    certificate: String,
    arch: String,
}

#[derive(Deserialize)]
struct ItaAttestResponse {
    token: String,
}

// ---------------------------------------------------------------------------
// ItaConverter
// ---------------------------------------------------------------------------

pub struct ItaConverter {
    http: Client,
    api_key: String,
    base_url: String,
    policy_ids: Vec<String>,
}

impl ItaConverter {
    pub fn new(api_key: &str, base_url: &str, policy_ids: &[String]) -> Result<Self> {
        Ok(Self {
            http: Client::new(),
            api_key: api_key.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            policy_ids: policy_ids.to_vec(),
        })
    }

    fn is_retryable_error(status: reqwest::StatusCode, body: &str) -> bool {
        status.is_server_error()
            || (status == reqwest::StatusCode::BAD_REQUEST
                && body.contains("Failed to verify GPU evidence"))
    }

    /// Send an HTTP request to ITA with retry logic, returning the response body
    /// on success.
    async fn ita_request(&self, request: reqwest::RequestBuilder, label: &str) -> Result<String> {
        let label = label.to_string();

        let fut = async move {
            let policy = RetryPolicy::exponential(ITA_RETRY_INITIAL_DELAY)
                .with_max_delay(ITA_RETRY_MAX_DELAY)
                .with_max_retries(ITA_MAX_RETRIES);

            let (status, body) = policy
                .retry(|| async {
                    let resp = request
                        .try_clone()
                        .expect("request must be cloneable")
                        .send()
                        .await
                        .map_err(|e| Error::ItaHttpRequestFailed {
                            endpoint: label.clone(),
                            source: e,
                        })?;
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    if Self::is_retryable_error(status, &body) {
                        tracing::warn!(%status, body = %body, "{label} failed (retrying)");
                        return Err(Error::ItaHttpResponseError {
                            endpoint: label.clone(),
                            status_code: status.as_u16(),
                            response_body: body,
                        });
                    }
                    Ok((status, body))
                })
                .await?;

            if !status.is_success() {
                return Err(Error::ItaHttpResponseError {
                    endpoint: label,
                    status_code: status.as_u16(),
                    response_body: body,
                });
            }

            Ok(body)
        };

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        let result = tokio_with_wasm::task::spawn(fut)
            .await
            .map_err(|e| Error::ItaError(format!("Failed to spawn ITA request task: {e}")))
            .and_then(|e| e);
        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let result = fut.await;

        result
    }
}

#[async_trait::async_trait]
impl GenericConverter for ItaConverter {
    type InEvidence = ItaEvidence;
    type OutEvidence = ItaToken;
    type Nonce = String;

    async fn get_nonce(&self) -> Result<String> {
        let url = format!("{}{}", self.base_url, ITA_NONCE_PATH);
        tracing::debug!(url = %url, "Fetching ITA nonce");

        let req = self
            .http
            .get(&url)
            .header("x-api-key", &self.api_key)
            .header("Accept", "application/json");

        let resp_body = self.ita_request(req, &url).await?;

        let nonce: ItaNonce =
            serde_json::from_str(&resp_body).map_err(Error::ParseChallengeResponseFailed)?;
        let nonce_str = serde_json::to_string(&nonce).map_err(Error::SerializeJsonFailed)?;
        tracing::debug!(nonce = %nonce_str, "ITA nonce request succeeded");
        Ok(nonce_str)
    }

    async fn convert(&self, in_evidence: &ItaEvidence) -> Result<ItaToken> {
        let quote_b64 = BASE64.encode(&in_evidence.tdx_quote);
        let runtime_data_b64 = BASE64.encode(&in_evidence.runtime_data);

        let tdx = TdxEvidence {
            quote: quote_b64,
            verifier_nonce: in_evidence.nonce.clone(),
            runtime_data: Some(runtime_data_b64),
        };

        let nvgpu = in_evidence
            .nvgpu_evidence
            .as_ref()
            .map(|gpu| NvgpuEvidence {
                evidence: gpu.evidence.clone(),
                verifier_nonce: in_evidence.nonce.clone(),
                gpu_nonce: hex::encode(gpu.runtime_data_hash),
                certificate: gpu.certificate.clone(),
                arch: gpu.arch.clone(),
            });

        let body = ItaAttestRequest {
            policy_ids: self.policy_ids.clone(),
            token_signing_alg: "PS384".to_string(),
            policy_must_match: !self.policy_ids.is_empty(),
            tdx,
            nvgpu,
        };

        let url = format!("{}{}", self.base_url, ITA_ATTEST_PATH);

        tracing::debug!(
            url = %url,
            body = %serde_json::to_string(&body).unwrap_or_default(),
            "Sending ITA attest request"
        );

        let req = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);

        let resp_body = self.ita_request(req, &url).await?;
        let attest_resp: ItaAttestResponse = serde_json::from_str(&resp_body)
            .map_err(|e| Error::ItaError(format!("Failed to parse ITA attest response: {e}")))?;

        tracing::debug!(token = %attest_resp.token, "ITA attest request succeeded");
        ItaToken::new(attest_resp.token)
    }
}
