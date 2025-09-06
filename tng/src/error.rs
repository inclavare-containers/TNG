use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
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

    #[error("Not a valid http request")]
    InvalidHttpRequest,

    #[error("Not a valid http response")]
    InvalidHttpResponse,

    #[error("Http error during forwarding HTTP plain text to upstream: {0}")]
    HttpPlainTextForwardError(#[source] hyper::Error),

    #[error("Http error during forwarding HTTP cyper text to upstream: {0}")]
    HttpCyperTextForwardError(#[source] reqwest::Error),

    #[error("Failed to get attestation challenge from server: {0}")]
    ClientGetAttestationChallengeFaild(#[source] reqwest::Error),

    #[error("Failed during background check from server: {0}")]
    ClientBackgroundCheckFaild(#[source] reqwest::Error),

    #[error("Failed to request key config froam ohttp server: {0}")]
    RequestKeyConfigFailed(#[source] reqwest::Error),

    #[error("Failed to connect to upstream")]
    ConnectUpstreamFailed,

    #[error("Failed to construct http response: {0}")]
    ConstructHttpResponseFailed(#[source] http::Error),

    #[error("Failed to get hpke configuration: {0}")]
    GetServerHpkeConfigurationFailed(#[source] anyhow::Error),

    #[error("Failed to select a hpke configutation: {0}")]
    ServerHpkeConfigurationSelectFailed(#[source] anyhow::Error),

    #[error("Failed to generate hpke configuration: {0}")]
    GenServerHpkeConfigurationFailed(#[source] anyhow::Error),
}

/// Error response structure
#[derive(Serialize, Debug)]
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
