use anyhow::Context as _;
use async_trait::async_trait;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Custom error type
#[derive(Error, Debug)]
pub enum TngError {
    #[error("Internal server error")]
    InternalError,

    #[error("System time error: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    #[error("OHTTP error: {0}")]
    OhttpError(#[from] ohttp::Error),

    #[error("BHTTP error: {0}")]
    BhttpError(#[from] bhttp::Error),

    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Failed to read metadata: {0}")]
    MetadataReadError(#[source] std::io::Error),

    #[error("The metadata is too long")]
    MetadataTooLong,

    #[error("Failed to decode metadata: {0}")]
    MetadataDecodeError(#[source] prost::DecodeError),

    #[error("Failed to encode metadata: {0}")]
    MetadataEncodeError(#[source] prost::EncodeError),

    #[error("Failed to validate metadata: {0}")]
    MetadataValidateError(#[source] anyhow::Error),

    #[error("Not a valid http request")]
    InvalidHttpRequest,

    #[error("Not a valid http response")]
    InvalidHttpResponse,

    #[error("Http error during forwarding HTTP plain text to upstream: {0}")]
    HttpPlainTextForwardError(#[source] hyper::Error),

    #[error("Http error during forwarding HTTP cyper text to upstream: {0}")]
    HttpCyperTextForwardError(#[source] reqwest::Error),

    #[error("Failed to get attestation challenge from server: {0}")]
    ClientGetAttestationChallengeFaild(#[source] anyhow::Error),

    #[error("Failed to get client background check result from server: {0}")]
    ClientGetBackgroundCheckResultFaild(#[source] anyhow::Error),

    #[error("Failed to verify client evidence: {0}")]
    ServerVerifyClientEvidenceFailed(#[source] anyhow::Error),

    #[error("Failed to request key config froam ohttp server: {0}")]
    RequestKeyConfigFailed(#[source] anyhow::Error),

    #[error("Failed to connect to upstream")]
    ConnectUpstreamFailed,

    #[error("Failed to construct http response: {0}")]
    ConstructHttpResponseFailed(#[source] http::Error),

    #[error("Failed to select a hpke configutation: {0}")]
    ServerHpkeConfigurationSelectFailed(#[source] anyhow::Error),

    #[error("Failed to generate hpke configuration: {0}")]
    GenServerHpkeConfigurationFailed(#[source] anyhow::Error),

    #[error("Not a valid OHTTP request: {0}")]
    InvalidOHttpRequest(#[source] anyhow::Error),

    #[error("Not a valid OHTTP request: {0}")]
    InvalidOHttpResponse(#[source] anyhow::Error),
}

/// Error response structure
#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    /// Human-readable error description
    pub message: String,
}

impl IntoResponse for TngError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            message: self.to_string(),
        });

        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

#[async_trait]
pub trait CheckErrorResponse: Sized {
    async fn check_error_response(self) -> Result<Self, anyhow::Error>;
}

#[async_trait]
impl CheckErrorResponse for reqwest::Response {
    async fn check_error_response(self) -> Result<Self, anyhow::Error> {
        if let Err(error) = self.error_for_status_ref() {
            if self.status() == StatusCode::INTERNAL_SERVER_ERROR {
                let text = self.text().await?;
                if let Ok(ErrorResponse { message }) = serde_json::from_str(&text) {
                    Err(error).context(format!("server error message: {message}"))?
                } else {
                    Err(error).context(format!("full response: {text}"))?
                }
            } else {
                Err(error)?
            }
        } else {
            Ok(self)
        }
    }
}
