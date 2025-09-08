use anyhow::{anyhow, bail, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use bhttp::http_compat::{
    decode::{BhttpDecoder, HttpMessage},
    encode::BhttpEncoder,
};
use bytes::{BufMut, BytesMut};
use futures::{AsyncWriteExt as _, StreamExt, TryStreamExt as _};
use http::header::HeaderValue;
use ohttp::KeyConfig;
use prost::Message;
use rats_cert::tee::{
    coco::{evidence::CocoAsToken, verifier::CocoVerifier},
    GenericEvidence as _, GenericVerifier as _,
};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::AsyncReadExt,
    sync::{OnceCell, RwLock},
};
use tokio_util::{
    compat::{
        FuturesAsyncReadCompatExt as _, FuturesAsyncWriteCompatExt as _,
        TokioAsyncReadCompatExt as _,
    },
    io::{ReaderStream, StreamReader},
};

use crate::{
    config::ra::{AttestationServiceArgs, AttestationServiceTokenVerifyArgs, VerifyArgs},
    tunnel::{
        endpoint::TngEndpoint,
        ingress::protocol::ohttp::security::path_rewrite::PathRewriteGroup,
        ohttp::protocol::{
            metadata::{
                metadata::MetadataType, EncryptedWithoutClientAuth, Metadata, METADATA_MAX_LEN,
            },
            AttestationChallengeResponse, AttestationRequest, AttestationResultJwt,
            AttestationVerifyRequest, AttestationVerifyResponse, HpkeKeyConfig, KeyConfigRequest,
            KeyConfigResponse, ServerAttestationInfo,
        },
    },
    HTTP_REQUEST_USER_AGENT_HEADER,
};
use crate::{
    config::{ingress::OHttpArgs, ra::RaArgs},
    error::TngError,
    AttestationResult, TokioRuntime,
};

pub struct OHttpClient {
    runtime: TokioRuntime,
    ra_args: RaArgs,
    http_client: reqwest::Client,
    // TODO: setup a updater for updating hpke config in key_store
    key_store: RwLock<HashMap<TngEndpoint, Arc<OnceCell<Arc<KeyStoreValue>>>>>,

    path_rewrite_group: PathRewriteGroup,
}

struct KeyStoreValue {
    metadata: Metadata,
    private_key: (), // TODO
    server_key_config_parsed: ServerHpkeKeyConfigParsed,
    /// Server attestation information. This is only represented if the server attestation is required.
    server_attestation_result: Option<AttestationResult>,
}

struct ServerHpkeKeyConfigParsed {
    /// Expiration timestamp for this configuration
    pub expire_timestamp: u64,

    /// A base64 encoded list of key configurations, each entry is a Individual key configuration entry. Defined in Section 3.1 of RFC 9458.
    pub key_config_list: Vec<KeyConfig>,
}

impl OHttpClient {
    pub fn new(runtime: TokioRuntime, ra_args: RaArgs, ohttp_args: &OHttpArgs) -> Result<Self> {
        // TODO: add check for ra_args

        let http_client = reqwest::Client::builder()
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    http::header::USER_AGENT,
                    HeaderValue::from_static(HTTP_REQUEST_USER_AGENT_HEADER),
                );
                headers
            })
            .build()?;
        Ok(Self {
            runtime,
            ra_args,
            http_client,
            key_store: Default::default(),
            path_rewrite_group: PathRewriteGroup::new(&ohttp_args.path_rewrites)?,
        })
    }

    pub async fn forward_request(
        &self,
        endpoint: &TngEndpoint,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>), TngError> {
        let value = self
            .get_key_store_value(&endpoint)
            .await
            .map_err(TngError::GenServerHpkeConfigurationFailed)?;

        let response = self
            .send_encrypted_request(
                &value.server_key_config_parsed,
                &value.metadata,
                &endpoint,
                request,
            )
            .await?;

        Ok((response, value.server_attestation_result.clone()))
    }

    async fn verify_token(
        server_key_config: &HpkeKeyConfig,
        attestation_result: &AttestationResultJwt,
        token_verify: &AttestationServiceTokenVerifyArgs,
    ) -> Result<AttestationResult> {
        let token = CocoAsToken::new(attestation_result.0.to_owned())?;
        let verifier =
            CocoVerifier::new(&token_verify.trusted_certs_paths, &token_verify.policy_ids)?;
        verifier
            .verify_evidence(
                &token,
                serde_json::to_string(&server_key_config)?.as_bytes(),
            )
            .await?;
        Ok(AttestationResult::from_claims(token.get_claims()?))
    }

    async fn verify_evidence(
        evidence: &str,
        as_args: &AttestationServiceArgs,
    ) -> Result<AttestationResult> {
        unimplemented!("server attestation with background check model is not supported yet")
    }

    async fn get_key_store_value(&self, endpoint: &TngEndpoint) -> Result<Arc<KeyStoreValue>> {
        // Try to read the key store entry.
        let cell = {
            let read = self.key_store.read().await;
            read.get(&endpoint).map(|v| v.clone())
        };

        // If no entry exists, create one with uninitialized value.
        let cell = match cell {
            Some(cell) => cell,
            _ => self
                .key_store
                .write()
                .await
                .entry(endpoint.clone())
                .or_default()
                .clone(),
        };

        // read from the cell
        cell.get_or_try_init(|| async {
            // Handle metatdata for self
            let metadata = match &self.ra_args {
                RaArgs::AttestOnly(..) | RaArgs::AttestAndVerify(..) => {
                    unimplemented!("Client side attestation is not supported yet.")
                }
                RaArgs::VerifyOnly(..) | RaArgs::NoRa => {
                    // Not required
                    Metadata{
                        metadata_type: Some(MetadataType::EncryptedWithoutClientAuth(EncryptedWithoutClientAuth{}))
                    }
                }
            };

            let key_config_request = self.prepare_key_config_request(&endpoint).await?;

            // Handle hpke configuration for server
            let response = self.get_hpke_configuration(&endpoint, key_config_request).await?;

            let server_key_config = response.hpke_key_config;
            let server_attestation_result = match &self.ra_args {
                RaArgs::VerifyOnly(verify) | RaArgs::AttestAndVerify(.., verify) => {
                    match (response.attestation_info, verify) {
                        (
                            Some(ServerAttestationInfo::Passport { attestation_result }),
                            VerifyArgs::Passport { token_verify },
                        ) => {
                            Some(Self::verify_token(&server_key_config, &attestation_result, token_verify).await?)
                        },
                        (
                            Some(ServerAttestationInfo::BackgroundCheck { evidence }),
                            VerifyArgs::BackgroundCheck { as_args },
                        ) => {
                            Some(Self::verify_evidence(&evidence, as_args).await?)
                        },
                        (
                            Some(ServerAttestationInfo::Passport { .. }),
                            VerifyArgs::BackgroundCheck { .. },
                        ) => bail!(
                            "Background check model is expected but got passport attestation from server"
                        ),
                        (
                            Some(ServerAttestationInfo::BackgroundCheck { .. }),
                            VerifyArgs::Passport { .. },
                        ) => bail!(
                            "Passport model is expected but got background check attestation from server"
                        ),
                        (None, _) => bail!("Missing attestation info from server"),
                    }
                }
                RaArgs::AttestOnly(..) | RaArgs::NoRa => {
                    // Not required
                    None
                }
            };

            let server_key_config_parsed = {
                let key_config_list = KeyConfig::decode_list(BASE64_STANDARD.decode(server_key_config.encoded_key_config_list)?.as_ref())?;

                ServerHpkeKeyConfigParsed{
                    expire_timestamp: server_key_config.expire_timestamp,
                    key_config_list,
                }
            };

           Ok(Arc::new(KeyStoreValue{
                metadata,
                private_key: (),
                server_key_config_parsed,
                server_attestation_result,
            }))
        })
        .await
        .cloned()
    }

    /// Prepare a key configuration request
    async fn prepare_key_config_request(&self, endpoint: &TngEndpoint) -> Result<KeyConfigRequest> {
        let key_config_request = match &self.ra_args {
            RaArgs::VerifyOnly(verify) | RaArgs::AttestAndVerify(.., verify) => match verify {
                VerifyArgs::Passport { token_verify } => KeyConfigRequest {
                    attestation_request: Some(AttestationRequest::Passport),
                },
                VerifyArgs::BackgroundCheck { as_args } => KeyConfigRequest {
                    attestation_request: Some(AttestationRequest::BackgroundCheck {
                        // TODO: use kbs protocol to get real challenge token
                        challenge_token: "dummy".to_string(),
                    }),
                },
            },
            RaArgs::AttestOnly(..) | RaArgs::NoRa => KeyConfigRequest {
                attestation_request: None,
            },
        };

        Ok(key_config_request)
    }

    /// Interface 1: Get HPKE Configuration
    /// POST /tng/key-config
    ///
    /// This method is used by TNG Clients to obtain the public key configuration needed
    /// to establish an encrypted channel and verify the server's identity.
    async fn get_hpke_configuration(
        &self,
        endpoint: &TngEndpoint,
        key_config_request: KeyConfigRequest,
    ) -> Result<KeyConfigResponse, TngError> {
        let url = format!(
            "http://{}:{}/tng/key-config",
            endpoint.host(),
            endpoint.port()
        );

        tracing::info!(
            url,
            ?key_config_request,
            "Getting HPKE configuration upstream"
        );

        let response = self
            .http_client
            .post(&url)
            .json(&key_config_request)
            .send()
            .await
            .map_err(|error| TngError::RequestKeyConfigFailed(error.into()))?;

        if let Err(e) = response.error_for_status_ref() {
            if let Ok(text) = response.text().await {
                return Err(e)
                    .with_context(|| format!("Server response: {text}"))
                    .map_err(|error| TngError::RequestKeyConfigFailed(error.into()));
            } else {
                return Err(e).map_err(|error| TngError::RequestKeyConfigFailed(error.into()));
            }
        }

        let result: KeyConfigResponse = response
            .json()
            .await
            .map_err(|error| TngError::RequestKeyConfigFailed(error.into()))?;

        Ok(result)
    }

    /// Clients use the hpke_key_config obtained from Interface 1 to encrypt a standard HTTP request,
    /// and send the encrypted ciphertext as the request body to the server.
    async fn send_encrypted_request(
        &self,
        server_key_config_parsed: &ServerHpkeKeyConfigParsed,
        metadata: &Metadata,
        endpoint: &TngEndpoint,
        request: axum::extract::Request,
    ) -> Result<axum::response::Response, TngError> {
        let old_uri = request.uri().clone();

        // Encode the request to bhttp message
        let bhttp_encoder = BhttpEncoder::from_request(request);

        // Encrypt to get the ohttp message
        let mut key_config = server_key_config_parsed
            .key_config_list
            .first()
            .context("No key config found")
            .map_err(TngError::ServerHpkeConfigurationSelectFailed)?
            .clone();
        let client = ohttp::ClientRequest::from_config(&mut key_config)?;

        let (encrypted_request, client_response_decapsulator) = {
            let (response_read, response_write) = tokio::io::duplex(4096);
            let client_request = client.encapsulate_stream(response_write.compat())?;
            let client_response_decapsulator = client_request.response_decapsulator()?;

            self.runtime.spawn_supervised_task_current_span(async {
                let mut client_request = client_request.compat_write();
                tokio::io::copy(
                    &mut bhttp_encoder
                        .map_err(std::io::Error::other)
                        .into_async_read()
                        .compat(),
                    &mut client_request,
                )
                .await?;
                let mut client_request = client_request.into_inner();
                client_request.close().await?; // Remember to close the response stream

                Ok::<_, anyhow::Error>(())
            });

            (response_read, client_response_decapsulator)
        };

        let ohttp_request_body = {
            let metadata_buf = {
                let metadata_len = metadata.encoded_len();
                if metadata_len > METADATA_MAX_LEN {
                    return Err(TngError::MetadataTooLong);
                }
                let mut metadata_buf = BytesMut::new();
                metadata_buf
                    .put_u32(u32::try_from(metadata_len).map_err(|_| TngError::MetadataTooLong)?); // big-endian
                metadata_buf.reserve(metadata_len); // to prevent reallocations during encoding
                metadata
                    .encode(&mut metadata_buf)
                    .map_err(TngError::MetadataEncodeError)?;
                metadata_buf
            };

            let body = std::io::Cursor::new(metadata_buf).chain(encrypted_request);
            reqwest::Body::wrap_stream(ReaderStream::new(body))
        };

        // Forward the request to the upstream server
        let url = {
            let original_path = old_uri.path();
            let mut rewrited_path = self
                .path_rewrite_group
                .rewrite(original_path)
                .unwrap_or_else(|| "/tng/tunnel".to_string());

            if !rewrited_path.starts_with("/") {
                rewrited_path = format!("/{}", rewrited_path);
            }

            tracing::debug!(original_path, rewrited_path, "path is rewrited");

            let url = format!(
                "http://{}:{}{rewrited_path}",
                endpoint.host(),
                endpoint.port()
            );
            url
        };

        tracing::debug!(url, "Sending OHTTP request to upstream server");

        let response = self
            .http_client
            .post(&url)
            .header(http::header::CONTENT_TYPE, "message/ohttp-chunked-req")
            .body(ohttp_request_body)
            .send()
            .await
            .map_err(TngError::HttpCyperTextForwardError)?;

        tracing::debug!(
            status = ?response.status(),
            version = ?response.version(),
            "Received OHTTP response from upstream server"
        );

        // Check content-type
        match response.headers().get(http::header::CONTENT_TYPE) {
            Some(value) => {
                if value != "message/ohttp-chunked-res" {
                    return Err(TngError::InvalidOHttpResponse(anyhow!(
                        "Wrong content-type header"
                    )));
                }
            }
            None => {
                return Err(TngError::InvalidOHttpResponse(anyhow!(
                    "Wrong content-type header"
                )));
            }
        }

        // Check the response status code
        let response = response
            .error_for_status()
            .map_err(TngError::HttpCyperTextForwardError)?;

        let response_body = response.bytes_stream();

        // Decrypt the ohttp response message
        let decrypted_response = client_response_decapsulator.decapsulate_response(
            StreamReader::new(response_body.map(|result| {
                result.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
            }))
            .compat(),
        )?;
        // Decode the bhttp binary message
        let decode_result = BhttpDecoder::new(decrypted_response)
            .decode_message()
            .await?;

        let HttpMessage::Response(response) = decode_result.into_full_message()? else {
            return Err(TngError::InvalidHttpResponse);
        };

        Ok(axum::response::IntoResponse::into_response(response))
    }

    /// Interface 3: Attestation Forward - Get Challenge
    /// GET /tng/background-check/challenge
    ///
    /// This method is a forwarder for the AS (Attestation Service) challenge endpoint.
    /// It is used specifically in the "Server verification Client + background check model" scenario.
    pub async fn background_check_attestation_challenge(
        &self,
        endpoint: &TngEndpoint,
    ) -> Result<AttestationChallengeResponse, TngError> {
        let client = reqwest::Client::new();
        let url = format!(
            "http://{}:{}/tng/background-check/challenge",
            endpoint.host(),
            endpoint.port()
        );

        let result: AttestationChallengeResponse = client
            .get(&url)
            .send()
            .await
            .map_err(TngError::ClientGetAttestationChallengeFaild)?
            .json()
            .await
            .map_err(TngError::ClientGetAttestationChallengeFaild)?;

        Ok(result)
    }

    /// Interface 3: Attestation Forward - Verify Evidence
    /// POST /tng/background-check/verify
    ///
    /// This method is a forwarder for the AS (Attestation Service) verification endpoint.
    /// It is used specifically in the "Server verification Client + background check model" scenario.
    pub async fn background_check_verify_attestation(
        &self,
        endpoint: &TngEndpoint,
        challenge_token: String,
        evidence: String,
    ) -> Result<AttestationVerifyResponse, TngError> {
        let client = reqwest::Client::new();
        let url = format!(
            "http://{}:{}/tng/background-check/verify",
            endpoint.host(),
            endpoint.port()
        );

        let payload = AttestationVerifyRequest {
            challenge_token,
            evidence,
        };

        let result: AttestationVerifyResponse = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(TngError::ClientBackgroundCheckFaild)?
            .json()
            .await
            .map_err(TngError::ClientBackgroundCheckFaild)?;

        Ok(result)
    }
}
