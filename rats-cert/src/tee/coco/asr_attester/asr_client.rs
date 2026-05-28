use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
/// <https://github.com/inclavare-containers/guest-components/pull/91>.
pub(crate) struct AsrClient {
    http: Client,
    base_url: String,
    /// TEE type obtained from `/info` at construction time.
    cached_tee_type: String,
}

impl AsrClient {
    /// Create a new AsrClient.
    ///
    /// Fetches the TEE type from `GET /info`. Returns an error if the
    /// endpoint is unavailable or does not return a TEE type.
    pub async fn new(asr_addr: &str) -> Result<Self> {
        let base_url = asr_addr.trim_end_matches('/').to_string();
        let http = Client::new();

        let resp = http
            .get(format!("{}/info", base_url))
            .send()
            .await
            .map_err(|e| Error::AsrHttpRequestFailed {
                endpoint: format!("{}/info", base_url),
                source: e,
            })?;
        if !resp.status().is_success() {
            return Err(Error::AsrHttpResponseError {
                endpoint: format!("{}/info", base_url),
                status_code: resp.status().as_u16(),
                response_body: resp.text().await.unwrap_or_default(),
            });
        }
        let info: AsrInfoResponse = resp.json().await.map_err(|e| Error::AsrHttpRequestFailed {
            endpoint: format!("{}/info", base_url),
            source: e,
        })?;

        tracing::info!(tee = %info.tee, "ASR reported TEE type via /info");

        Ok(Self {
            http,
            base_url,
            cached_tee_type: info.tee,
        })
    }

    /// Request a TEE evidence quote from the ASR with the given runtime_data_hash bytes.
    ///
    /// Uses URL-safe base64-no-pad encoding (`encoding=base64`), matching the
    /// inclavare-containers community ASR.
    pub async fn get_evidence(&self, runtime_data_hash_value: Vec<u8>) -> Result<Vec<u8>> {
        let url = format!("{}/aa/evidence", self.base_url);
        let runtime_data_b64 = URL_SAFE_NO_PAD.encode(&runtime_data_hash_value);

        let resp = self
            .http
            .get(&url)
            .query(&[
                ("runtime_data", runtime_data_b64.as_str()),
                ("encoding", "base64"),
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

    /// Query the TEE type string from the ASR (fetched at construction time).
    pub fn get_tee_type(&self) -> &str {
        &self.cached_tee_type
    }

    /// Request additional device evidence (e.g. GPU attestation) from the ASR.
    ///
    /// Returns `Ok(None)` when the endpoint returns non-success or the response is empty.
    pub async fn get_additional_evidence(
        &self,
        runtime_data_hash_value: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let runtime_data_b64 = URL_SAFE_NO_PAD.encode(&runtime_data_hash_value);
        let url = format!("{}/aa/additional-evidence", self.base_url);

        let resp = match self
            .http
            .get(&url)
            .query(&[
                ("runtime_data", runtime_data_b64.as_str()),
                ("encoding", "base64"),
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
            .and(path("/info"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"tee": "tdx"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/aa/evidence"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(expected_evidence.to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let client = AsrClient::new(&server.uri()).await.unwrap();
        let evidence = client.get_evidence(b"test-hash".to_vec()).await.unwrap();
        assert_eq!(evidence, expected_evidence);
    }

    #[tokio::test]
    async fn get_evidence_returns_error_on_non_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/info"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"tee": "tdx"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/aa/evidence"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .expect(1)
            .mount(&server)
            .await;

        let client = AsrClient::new(&server.uri()).await.unwrap();
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
    async fn new_parses_info_response() {
        let server = MockServer::start().await;
        let tee_type = "tdx";

        Mock::given(method("GET"))
            .and(path("/info"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"tee": tee_type})),
            )
            .expect(1..)
            .mount(&server)
            .await;

        let client = AsrClient::new(&server.uri()).await.unwrap();
        assert_eq!(client.get_tee_type(), "tdx");
    }

    #[tokio::test]
    async fn new_fails_when_info_unavailable() {
        let server = MockServer::start().await;

        match AsrClient::new(&server.uri()).await {
            Ok(_) => panic!("expected error"),
            Err(Error::AsrHttpResponseError { status_code, .. }) => {
                assert_eq!(status_code, 404);
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn get_additional_evidence_returns_none_on_failure() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/info"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"tee": "tdx"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/aa/additional-evidence"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let client = AsrClient::new(&server.uri()).await.unwrap();
        assert!(client.get_additional_evidence(vec![]).await.is_none());
    }

    #[tokio::test]
    async fn get_additional_evidence_returns_bytes_on_success() {
        let server = MockServer::start().await;
        let expected = b"gpu-evidence-blob";

        Mock::given(method("GET"))
            .and(path("/info"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"tee": "tdx"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/aa/additional-evidence"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(expected.to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let client = AsrClient::new(&server.uri()).await.unwrap();
        let result = client.get_additional_evidence(vec![]).await;
        assert_eq!(result.unwrap(), expected);
    }
}
