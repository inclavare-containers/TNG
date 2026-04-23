use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use reqwest::Client;

use crate::errors::*;

/// HTTP response from `GET /info` on the CoCo API Server Rest (ASR).
#[derive(serde::Deserialize)]
struct AsrInfoResponse {
    tee: String,
}

/// HTTP client for the CoCo API Server Rest (ASR).
///
/// Mirrors the [`AaClient`] interface but communicates over HTTP instead of
/// ttrpc, enabling TNG instances running in containers (without direct access
/// to the AA Unix socket) to collect attestation evidence through the ASR proxy.
///
/// Conforms to the ASR interface defined in
/// <https://github.com/cohere-ai/guest-components/pull/2>.
pub(crate) struct AsrClient {
    http: Client,
    base_url: String,
}

impl AsrClient {
    pub fn new(asr_addr: &str) -> Result<Self> {
        Ok(Self {
            http: Client::new(),
            base_url: asr_addr.trim_end_matches('/').to_string(),
        })
    }

    /// Request a TEE evidence quote from the ASR with the given runtime_data_hash bytes.
    pub async fn get_evidence(&self, runtime_data_hash_value: Vec<u8>) -> Result<Vec<u8>> {
        let runtime_data_b64 = BASE64.encode(&runtime_data_hash_value);
        let url = format!("{}/aa/evidence", self.base_url);

        let resp = self
            .http
            .get(&url)
            .query(&[
                ("runtime_data", &runtime_data_b64),
                ("encoding", &"base64".to_string()),
            ])
            .send()
            .await
            .map_err(|e| Error::AsrHttpRequestFailed {
                endpoint: url.clone(),
                source: e,
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::AsrHttpResponseError {
                endpoint: url,
                status_code: status,
                response_body: body,
            });
        }

        Ok(resp
            .bytes()
            .await
            .map_err(|e| Error::AsrHttpRequestFailed {
                endpoint: url,
                source: e,
            })?
            .to_vec())
    }

    /// Query the TEE type string from the ASR via `GET /info` (e.g. "tdx", "snp").
    pub async fn get_tee_type(&self) -> Result<String> {
        let url = format!("{}/info", self.base_url);

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::AsrHttpRequestFailed {
                endpoint: url.clone(),
                source: e,
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::AsrHttpResponseError {
                endpoint: url,
                status_code: status,
                response_body: body,
            });
        }

        let info: AsrInfoResponse = resp.json().await.map_err(|e| Error::AsrHttpRequestFailed {
            endpoint: url,
            source: e,
        })?;
        Ok(info.tee)
    }

    /// Request additional device evidence (e.g. GPU attestation) from the ASR.
    ///
    /// Returns `Ok(None)` when the ASR does not support additional evidence,
    /// the endpoint returns non-success, or the response is empty.
    pub async fn get_additional_evidence(
        &self,
        runtime_data_hash_value: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let runtime_data_b64 = BASE64.encode(&runtime_data_hash_value);
        let url = format!("{}/aa/additional_evidence", self.base_url);

        let resp = match self
            .http
            .get(&url)
            .query(&[
                ("runtime_data", &runtime_data_b64),
                ("encoding", &"base64".to_string()),
            ])
            .send()
            .await
        {
            Ok(r) => r,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "GetAdditionalEvidence request to ASR failed, proceeding without additional evidence"
                );
                return None;
            }
        };

        if !resp.status().is_success() {
            tracing::warn!(
                status = %resp.status(),
                "ASR additional_evidence returned non-success, proceeding without additional evidence"
            );
            return None;
        }

        match resp.bytes().await {
            Ok(bytes) if !bytes.is_empty() => Some(bytes.to_vec()),
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "Failed to read additional evidence response body from ASR"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn get_evidence_returns_response_bytes() {
        let server = MockServer::start().await;
        let expected_evidence = b"fake-tdx-quote-bytes";

        Mock::given(method("GET"))
            .and(path("/aa/evidence"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(expected_evidence.to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let client = AsrClient::new(&server.uri()).unwrap();
        let evidence = client.get_evidence(b"test-hash".to_vec()).await.unwrap();
        assert_eq!(evidence, expected_evidence);
    }

    #[tokio::test]
    async fn get_evidence_returns_error_on_non_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/aa/evidence"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .expect(1)
            .mount(&server)
            .await;

        let client = AsrClient::new(&server.uri()).unwrap();
        let err = client
            .get_evidence(b"test-hash".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::AsrHttpResponseError {
                status_code: 500,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn get_tee_type_parses_info_response() {
        let server = MockServer::start().await;
        let tee_type = "tdx";

        Mock::given(method("GET"))
            .and(path("/info"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"tee": tee_type})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = AsrClient::new(&server.uri()).unwrap();
        assert_eq!(client.get_tee_type().await.unwrap(), tee_type);
    }

    #[tokio::test]
    async fn get_additional_evidence_returns_none_on_failure() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/aa/additional_evidence"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let client = AsrClient::new(&server.uri()).unwrap();
        assert!(client.get_additional_evidence(vec![]).await.is_none());
    }

    #[tokio::test]
    async fn get_additional_evidence_returns_bytes_on_success() {
        let server = MockServer::start().await;
        let expected = b"gpu-evidence-blob";

        Mock::given(method("GET"))
            .and(path("/aa/additional_evidence"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(expected.to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let client = AsrClient::new(&server.uri()).unwrap();
        let result = client.get_additional_evidence(vec![]).await;
        assert_eq!(result.unwrap(), expected);
    }
}
