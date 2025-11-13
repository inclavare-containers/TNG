use std::path::PathBuf;

use anyhow::Context as _;
use async_trait::async_trait;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use strum_macros::AsRefStr;
use thiserror::Error;

/// Custom error type
#[derive(Error, Debug, AsRefStr)]
pub enum TngError {
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

    #[error("Http error during forwarding HTTP cipher text to upstream: {0}")]
    HttpCipherTextForwardError(#[source] reqwest::Error),

    #[error("Got bad response during forwarding HTTP cipher text to upstream: {0}")]
    HttpCipherTextBadResponse(#[source] anyhow::Error),

    #[error("Failed to get attestation challenge from server: {0}")]
    ClientGetAttestationChallengeFaild(#[source] anyhow::Error),

    #[error("Failed to get client background check result from server: {0}")]
    ClientGetBackgroundCheckResultFaild(#[source] anyhow::Error),

    #[error("Failed to get challenge token for client: {0}")]
    ServerVerifyClientGetChallengeTokenFailed(#[source] anyhow::Error),

    #[error("Failed to verify client evidence: {0}")]
    ServerVerifyClientEvidenceFailed(#[source] anyhow::Error),

    #[error("Failed to request key config from ohttp server: {0}")]
    RequestKeyConfigFailed(#[source] anyhow::Error),

    #[error("Failed to connect to upstream")]
    ConnectUpstreamFailed,

    #[error("Failed to construct http response: {0}")]
    ConstructHttpResponseFailed(#[source] http::Error),

    #[error("Failed to select a hpke configuration: {0}")]
    ClientSelectHpkeConfigurationFailed(#[source] anyhow::Error),

    #[error("Failed to generate hpke configuration response: {0}")]
    GenServerHpkeConfigurationResponseFailed(#[source] anyhow::Error),

    #[error("Not a valid OHTTP request: {0}")]
    InvalidOHttpRequest(#[source] anyhow::Error),

    #[error("Not a valid OHTTP response: {0}")]
    InvalidOHttpResponse(#[source] anyhow::Error),

    #[error("Failed to create OHTTP client: {0}")]
    CreateOHttpClientFailed(#[source] anyhow::Error),

    #[error("Access to this service requires a TNG-secured connection. Ensure your client connects via TNG. To bypass, update the direct_forward rules in the TNG server side configuration.")]
    RejectNonTngRequest,

    #[error("Invalid request payload: {0}")]
    InvalidRequestPayload(#[from] axum::extract::rejection::JsonRejection),

    #[error("Invalid x-tng-ohttp-api value")]
    InvalidOhttpApiHeaderValue,

    #[error("The key does not exist: {key_id}")]
    ServerKeyConfigNotFound { key_id: u8 },

    #[error("The server has no active key")]
    NoActiveKey,

    #[error("Failed to load private key {0}: {1}")]
    LoadPrivateKeyFailed(PathBuf, #[source] anyhow::Error),
}

/// Error response structure
#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    /// Machine-readable error code
    pub code: String,
    /// Human-readable error description
    pub message: String,
}

impl IntoResponse for TngError {
    fn into_response(self) -> Response {
        let status = match &self {
            // Client errors (4xx)
            TngError::InvalidRequestPayload(..) => StatusCode::BAD_REQUEST,
            TngError::RejectNonTngRequest => StatusCode::FORBIDDEN,
            TngError::InvalidOhttpApiHeaderValue => StatusCode::BAD_REQUEST,
            TngError::InvalidHttpRequest => StatusCode::BAD_REQUEST,
            TngError::InvalidHttpResponse => StatusCode::BAD_REQUEST,
            TngError::InvalidOHttpRequest(..) => StatusCode::BAD_REQUEST,
            TngError::InvalidOHttpResponse(..) => StatusCode::BAD_REQUEST,

            // Validation / Decode errors → 400 Bad Request
            TngError::Base64DecodeError(..) => StatusCode::BAD_REQUEST,
            TngError::MetadataDecodeError(..) => StatusCode::BAD_REQUEST,
            TngError::MetadataEncodeError(..) => StatusCode::INTERNAL_SERVER_ERROR,
            TngError::ConstructHttpResponseFailed(..) => StatusCode::INTERNAL_SERVER_ERROR,

            // Not Found / Upstream issues
            TngError::ConnectUpstreamFailed => StatusCode::BAD_GATEWAY,

            // Timeouts / Network failures
            TngError::HttpPlainTextForwardError(..) => StatusCode::BAD_GATEWAY,
            TngError::HttpCipherTextForwardError(e) => {
                #[cfg(unix)]
                let is_timeout = e.is_connect() || e.is_timeout();
                #[cfg(wasm)]
                let is_timeout = e.is_timeout();
                if is_timeout {
                    StatusCode::GATEWAY_TIMEOUT
                } else if e
                    .status()
                    .map(|s| s == StatusCode::TOO_MANY_REQUESTS)
                    .unwrap_or(false)
                {
                    StatusCode::TOO_MANY_REQUESTS
                } else {
                    StatusCode::BAD_GATEWAY
                }
            }
            TngError::HttpCipherTextBadResponse(..) => StatusCode::BAD_GATEWAY,

            // Metadata I/O errors
            TngError::MetadataReadError(..) => StatusCode::BAD_REQUEST,

            // Metadata size limit → 413 Payload Too Large
            TngError::MetadataTooLong => StatusCode::PAYLOAD_TOO_LARGE,

            // 500 for all other internal errors
            TngError::SystemTimeError(..)
            | TngError::OhttpError(..)
            | TngError::BhttpError(..)
            | TngError::MetadataValidateError(..)
            | TngError::ClientGetAttestationChallengeFaild(..)
            | TngError::ClientGetBackgroundCheckResultFaild(..)
            | TngError::ServerVerifyClientGetChallengeTokenFailed(..)
            | TngError::ServerVerifyClientEvidenceFailed(..)
            | TngError::RequestKeyConfigFailed(..)
            | TngError::ClientSelectHpkeConfigurationFailed(..)
            | TngError::GenServerHpkeConfigurationResponseFailed(..)
            | TngError::CreateOHttpClientFailed(..)
            | TngError::LoadPrivateKeyFailed(..) => StatusCode::INTERNAL_SERVER_ERROR,

            // See the RFC 9458 section 6.4. Key Management
            TngError::ServerKeyConfigNotFound { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            TngError::NoActiveKey => StatusCode::UNPROCESSABLE_ENTITY,
        };

        (
            status,
            Json(ErrorResponse {
                code: self.as_ref().to_owned(),
                message: self.to_string(),
            }),
        )
            .into_response()
    }
}

#[cfg(unix)]
#[async_trait]
pub trait CheckErrorResponse: Sized {
    async fn check_error_response(self) -> Result<Self, anyhow::Error>;
}

#[cfg(unix)]
#[async_trait]
impl CheckErrorResponse for reqwest::Response {
    async fn check_error_response(self) -> Result<Self, anyhow::Error> {
        check_error_response(self).await
    }
}

#[cfg(wasm)]
#[async_trait(?Send)]
pub trait CheckErrorResponse: Sized {
    async fn check_error_response(self) -> Result<Self, anyhow::Error>;
}

#[cfg(wasm)]
#[async_trait(?Send)]
impl CheckErrorResponse for reqwest::Response {
    async fn check_error_response(self) -> Result<Self, anyhow::Error> {
        check_error_response(self).await
    }
}

async fn check_error_response(
    response: reqwest::Response,
) -> Result<reqwest::Response, anyhow::Error> {
    if let Err(error) = response.error_for_status_ref() {
        let text = response.text().await?;
        // Try to parse the error response as TNG error response
        if let Ok(ErrorResponse { code, message }) = serde_json::from_str(&text) {
            Err(error).context(format!("server error code: {code} message: {message}"))?
        } else {
            Err(error).context(format!("full response: {text}"))?
        }
    } else {
        Ok(response)
    }
}
