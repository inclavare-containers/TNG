use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use bhttp::http_compat::{
    decode::{BhttpDecoder, HttpMessage},
    encode::BhttpEncoder,
};
use bytes::{BufMut, BytesMut};
use futures::{AsyncWriteExt as _, StreamExt, TryStreamExt as _};
#[cfg(unix)]
use hpke::Serializable;
use hpke::{kem::X25519HkdfSha256, Kem};
use http::StatusCode;
use ohttp::KeyConfig;
use prost::Message;
#[cfg(unix)]
use rand::SeedableRng as _;
#[cfg(unix)]
use rand_chacha::ChaCha12Rng;
#[cfg(unix)]
use rats_cert::tee::AttesterPipeline;
#[cfg(unix)]
use rats_cert::tee::GenericAttester as _;
use rats_cert::tee::ReportData;
use rats_cert::tee::{GenericConverter, GenericVerifier as _};
use serde::Serialize;
// tokio_with_wasm::task::spawn does not propagate the current tracing span,
// so we must explicitly .instrument() the spawned future.
#[cfg(wasm)]
use tracing::Instrument;

use crate::tunnel::provider::{ProviderType, TngEvidence, TngToken};
#[cfg(not(wasm))]
use tokio::io::AsyncReadExt;
use tokio_util::{
    compat::{
        FuturesAsyncReadCompatExt as _, FuturesAsyncWriteCompatExt as _,
        TokioAsyncReadCompatExt as _,
    },
    io::StreamReader,
};
use url::Url;

use std::{pin::Pin, sync::Arc};

#[cfg(unix)]
use crate::tunnel::ohttp::protocol::metadata::AttestedPublicKey;
#[cfg(unix)]
use crate::tunnel::ohttp::protocol::userdata::ClientUserData;
#[cfg(unix)]
use crate::tunnel::ra_context::AttestContext;
use crate::{
    error::CheckErrorResponse as _,
    tunnel::{
        ohttp::protocol::{
            metadata::{metadata::ClientAuth, Metadata, NoAuth, METADATA_MAX_LEN},
            userdata::ServerUserData,
            AttestationChallengeResponse, AttestationRequest, AttestationVerifyRequest,
            AttestationVerifyResponse, KeyConfigRequest, KeyConfigResponse, ServerAttestationInfo,
        },
        utils::maybe_cached::{Expire, MaybeCached, RefreshStrategy},
    },
};
use crate::{
    error::TngError,
    tunnel::{
        ohttp::{
            key_config::KeyConfigExtend,
            protocol::{
                header::{
                    OhttpApi, OHTTP_CHUNKED_REQUEST_CONTENT_TYPE,
                    OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE,
                },
                metadata::ServerKeyConfigHint,
            },
        },
        ra_context::{RaContext, VerifyContext},
    },
    AttestationResult, TokioRuntime,
};

const DEFAULT_KEY_CONFIG_REFRESH_SECOND: u64 = 5 * 60; // 5 minutes

pub struct OHttpClient {
    inner: Arc<OHttpClientInner>,
    key_store_value: MaybeCached<KeyStoreValue, TngError>,
}

pub struct OHttpClientInner {
    ra_context: Arc<RaContext>,
    http_client: Arc<reqwest::Client>,
    #[cfg(unix)]
    rng: tokio::sync::Mutex<ChaCha12Rng>,
    base_url: Url,
    #[allow(unused)]
    runtime: TokioRuntime,
    /// Headers to copy from downstream requests to the outer OHTTP POST.
    #[allow(unused)]
    passthrough_request_headers: Arc<Vec<String>>,
}

struct KeyStoreValue {
    client_auth: ClientAuth,

    #[allow(unused)]
    client_key: Option<(
        <X25519HkdfSha256 as Kem>::PrivateKey,
        <X25519HkdfSha256 as Kem>::PublicKey,
    )>,

    /// A base64 encoded list of key configurations, each entry is a Individual key configuration entry. Defined in Section 3.1 of RFC 9458.
    server_key_config_list: Vec<KeyConfig>,

    /// Server attestation information. This is only represented if the server attestation is required.
    server_attestation_result: Option<AttestationResult>,
}

/// A single entry in the status API response for an upstream OHTTP server.
///
/// Contains the server URL, optional HPKE public key in hex format,
/// and optional server attestation result as a raw JWT string.
#[derive(Serialize)]
pub struct ServerStatusEntry {
    pub(crate) url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) server_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) server_attestation: Option<String>,
}

impl OHttpClient {
    /// Return server status info for the status API.
    pub async fn server_status(&self) -> Option<ServerStatusEntry> {
        let ksv = self.key_store_value.get_latest().await.ok()?;
        Some(ServerStatusEntry {
            url: self.inner.base_url.to_string(),
            server_public_key: ksv
                .server_key_config_list
                .first()
                .and_then(|kc| kc.public_key().ok().map(|pk| hex::encode(pk.as_ref()))),
            server_attestation: ksv
                .server_attestation_result
                .as_ref()
                .map(|ar| ar.token_str().to_string()),
        })
    }

    pub async fn new(
        ra_context: Arc<RaContext>,
        http_client: Arc<reqwest::Client>,
        base_url: Url,
        runtime: TokioRuntime,
        passthrough_request_headers: Arc<Vec<String>>,
    ) -> Result<Self> {
        let refresh_strategy = {
            #[cfg(unix)]
            if let Some(attest_ctx) = ra_context.attest_context() {
                attest_ctx.refresh_strategy()
            } else {
                RefreshStrategy::Periodically {
                    interval: DEFAULT_KEY_CONFIG_REFRESH_SECOND,
                    min_fallback_interval: 1,
                }
            }
            #[cfg(not(unix))]
            {
                RefreshStrategy::Periodically {
                    interval: DEFAULT_KEY_CONFIG_REFRESH_SECOND,
                    min_fallback_interval: 1,
                }
            }
        };

        let inner = Arc::new(OHttpClientInner {
            ra_context,
            #[cfg(unix)]
            rng: tokio::sync::Mutex::new(ChaCha12Rng::from_os_rng()),
            http_client,
            base_url,
            runtime: runtime.clone(),
            passthrough_request_headers,
        });

        let key_store_value = MaybeCached::new(runtime.clone(), refresh_strategy, {
            let inner = inner.clone();
            move || {
                let inner = inner.clone();
                Box::pin(async move { inner.create_key_store_value().await }) as Pin<Box<_>>
            }
        })
        .await?;

        Ok(Self {
            inner,
            key_store_value,
        })
    }
}

impl OHttpClient {
    pub async fn forward_request(
        &self,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>), TngError> {
        let key_store_value = self.key_store_value.get_latest().await?;

        match self
            .inner
            .send_encrypted_request(
                &key_store_value.server_key_config_list,
                &key_store_value.client_auth,
                request,
            )
            .await
        {
            Ok(response) => Ok((response, key_store_value.server_attestation_result.clone())),
            Err(error) => {
                // When the key config is expired, we should invalidate the key config cache. So that the next request will get the new key config.
                if matches!(
                    error,
                    TngError::ShouldRequestNewKeyConfigFromServerError(..)
                ) {
                    self.key_store_value.invalidate();
                }
                Err(error)
            }
        }
    }
}

impl OHttpClientInner {
    async fn create_key_store_value(&self) -> Result<(KeyStoreValue, Expire), TngError> {
        // Handle metatdata for self
        let (client_key, client_auth, mut expire) = self
            .create_attested_client_key()
            .await
            .map_err(TngError::ClientGenerateClientKeyFailed)?;

        let (server_key_config, token) = {
            let verify_context = self.ra_context.verify_context();

            match verify_context {
                Some(VerifyContext::Passport { verifier }) => {
                    // Request hpke configuration for server
                    let response = self
                        .get_hpke_configuration(KeyConfigRequest {
                            attestation_request: Some(AttestationRequest::Passport),
                        })
                        .await?;

                    let token = match &response.attestation_info {
                        Some(ServerAttestationInfo::Passport {
                            attestation_result,
                            as_provider,
                        }) => {
                            let token = TngToken::from_wire(
                                ProviderType::from_optional_wire(*as_provider),
                                attestation_result.clone(),
                            )
                            .map_err(TngError::TngTokenDecodeError)?;

                            let userdata = ServerUserData {
                                // The challenge_token is not required to be check here, since it is already checked by attestation service. So that we skip the comparesion of challenge_token here.
                                challenge_token: None,
                                hpke_key_config: response.hpke_key_config.clone(),
                            }
                            .to_claims()
                            .map_err(TngError::ClaimsEncodeError)?;

                            verifier
                                .verify_evidence(&token, &ReportData::Claims(userdata))
                                .await
                                .map_err(TngError::EvidenceVerifyError)?;
                            token
                        }
                        Some(ServerAttestationInfo::BackgroundCheck { .. }) => {
                            Err(TngError::ClientRequestKeyConfigFailed(anyhow!("Passport model is expected but got background check attestation from server")))?
                        }
                        None => Err(TngError::ClientRequestKeyConfigFailed(anyhow!("Missing attestation info from server")))?,
                    };

                    (response.hpke_key_config, Some(token))
                }
                Some(VerifyContext::BackgroundCheck {
                    converter,
                    verifier,
                }) => {
                    // fetch a challenge token from attestation service
                    let challenge_token = converter
                        .get_nonce()
                        .await
                        .map_err(|e| TngError::ClientRequestKeyConfigFailed(e.into()))?;

                    // Request hpke configuration for server
                    let response = self
                        .get_hpke_configuration(KeyConfigRequest {
                            attestation_request: Some(AttestationRequest::BackgroundCheck {
                                challenge_token: challenge_token.clone(),
                            }),
                        })
                        .await?;

                    let token = match response.attestation_info {
                        Some(ServerAttestationInfo::BackgroundCheck {
                            evidence,
                            aa_provider,
                        }) => {
                            let evidence = TngEvidence::deserialize_from_json(
                                ProviderType::from_optional_wire(aa_provider),
                                evidence,
                            )
                            .map_err(TngError::TngEvidenceDecodeError)?;
                            let token = converter.convert(&evidence).await
                                .map_err(TngError::EvidenceVerifyError)?;

                            let userdata = ServerUserData {
                                challenge_token: Some(challenge_token),
                                hpke_key_config: response.hpke_key_config.clone(),
                            }
                            .to_claims()
                            .map_err(TngError::ClaimsEncodeError)?;

                            verifier
                                .verify_evidence(&token, &ReportData::Claims(userdata))
                                .await
                                .map_err(TngError::EvidenceVerifyError)?;
                            token
                        }
                        Some(ServerAttestationInfo::Passport { .. }) => {
                            Err(TngError::ClientRequestKeyConfigFailed(anyhow!("Background check model is expected but got passport attestation from server")))?
                        },
                        None => Err(TngError::ClientRequestKeyConfigFailed(anyhow!("Missing attestation info from server")))?,
                    };

                    (response.hpke_key_config, Some(token))
                }
                // No verification required
                None => {
                    // Request hpke configuration for server
                    let response = self
                        .get_hpke_configuration(KeyConfigRequest {
                            attestation_request: None,
                        })
                        .await?;
                    (response.hpke_key_config, None)
                }
            }
        };

        expire = std::cmp::min(
            expire,
            Expire::from_timestamp(server_key_config.expire_timestamp)?,
        );

        let server_attestation_result = match token {
            Some(token) => {
                expire = std::cmp::min(
                    expire,
                    Expire::from_timestamp(
                        token
                            .exp()
                            .map_err(TngError::ClientRequestKeyConfigFailed)?,
                    )?,
                );
                Some(AttestationResult::from_token(token))
            }
            None => None,
        };

        let server_key_config_list = KeyConfig::decode_list(
            BASE64_STANDARD
                .decode(server_key_config.encoded_key_config_list)?
                .as_ref(),
        )?;

        Ok((
            KeyStoreValue {
                client_auth,
                client_key, // TODO: ohttp hpke setup with the client key
                server_key_config_list,
                server_attestation_result,
            },
            expire,
        ))
    }

    async fn create_attested_client_key(
        &self,
    ) -> Result<(
        Option<(
            <X25519HkdfSha256 as Kem>::PrivateKey,
            <X25519HkdfSha256 as Kem>::PublicKey,
        )>,
        ClientAuth,
        Expire,
    )> {
        #[cfg(not(unix))]
        {
            Ok((None, ClientAuth::NoAuth(NoAuth {}), Expire::NoExpire))
        }

        #[cfg(unix)]
        Ok(match self.ra_context.attest_context() {
            Some(attest_ctx) => {
                let client_key = X25519HkdfSha256::gen_keypair(&mut self.rng.lock().await);
                let pk_s = client_key.1.to_bytes().to_vec();

                let token = match attest_ctx {
                    AttestContext::Passport {
                        attester,
                        converter,
                        ..
                    } => {
                        // fetch a challenge token from attestation service
                        let challenge_token = converter.get_nonce().await?;

                        let attester_pipeline = AttesterPipeline::new(attester, converter);

                        let userdata = ClientUserData {
                            challenge_token: Some(challenge_token),
                            pk_s: BASE64_STANDARD.encode(pk_s.as_slice()),
                        }
                        .to_claims()?;

                        attester_pipeline
                            .get_evidence(&ReportData::Claims(userdata))
                            .await?
                    }
                    AttestContext::BackgroundCheck { attester, .. } => {
                        let AttestationChallengeResponse { challenge_token } =
                            self.background_check_attestation_challenge().await?;

                        let userdata = ClientUserData {
                            challenge_token: Some(challenge_token),
                            pk_s: BASE64_STANDARD.encode(pk_s.as_slice()),
                        }
                        .to_claims()?;

                        let evidence = attester.get_evidence(&ReportData::Claims(userdata)).await?;

                        let AttestationVerifyResponse {
                            attestation_result,
                            as_provider,
                        } = self.background_check_verify_attestation(evidence).await?;
                        TngToken::from_wire(
                            ProviderType::from_optional_wire(as_provider),
                            attestation_result,
                        )?
                    }
                };

                let token_expire = Expire::from_timestamp(token.exp()?)?;

                (
                    Some(client_key),
                    ClientAuth::AttestedPublicKey(AttestedPublicKey {
                        attestation_result: token.serialize_to_wire_str()?,
                        pk_s,
                        as_provider: token.provider_type().as_str().to_string(),
                    }),
                    token_expire,
                )
            }
            None => {
                // Not required
                (None, ClientAuth::NoAuth(NoAuth {}), Expire::NoExpire)
            }
        })
    }

    /// Interface 1: Get HPKE Configuration
    /// x-tng-ohttp-api: /tng/key-config
    ///
    /// This method is used by TNG Clients to obtain the public key configuration needed
    /// to establish an encrypted channel and verify the server's identity.
    async fn get_hpke_configuration(
        &self,
        key_config_request: KeyConfigRequest,
    ) -> Result<KeyConfigResponse, TngError> {
        let url = self.base_url.clone();

        tracing::info!(
            ?url,
            ?key_config_request,
            "Getting HPKE configuration upstream"
        );

        let response = self
            .http_client
            .post(url)
            .header(OhttpApi::HEADER_NAME, OhttpApi::KEY_CONFIG)
            .json(&key_config_request)
            .send()
            .await
            .map_err(|error| TngError::ClientRequestKeyConfigFailed(error.into()))?
            .check_error_response()
            .await
            .map_err(TngError::ClientRequestKeyConfigFailed)?;

        let response: KeyConfigResponse = response
            .json()
            .await
            .map_err(|error| TngError::ClientRequestKeyConfigFailed(error.into()))?;

        tracing::debug!(?response, "Received HPKE key configuration");

        Ok(response)
    }

    /// Clients use the hpke_key_config obtained from Interface 1 to encrypt a standard HTTP request,
    /// and send the encrypted ciphertext as the request body to the server.
    async fn send_encrypted_request(
        &self,
        server_key_config_list: &[KeyConfig],
        client_auth: &ClientAuth,
        request: axum::extract::Request,
    ) -> Result<axum::response::Response, TngError> {
        // Encode the request to bhttp message
        let bhttp_encoder = BhttpEncoder::from_request(request);

        // Encrypt to get the ohttp message
        let mut key_config = server_key_config_list
            .first()
            .context("No key config found")
            .map_err(TngError::ClientSelectHpkeConfigurationFailed)?
            .clone();

        tracing::debug!(
            public_key = ?key_config.public_key(),
            "Encrypting request with HPKE key"
        );

        let client = ohttp::ClientRequest::from_config(&mut key_config)?;

        let (encrypted_request, client_response_decapsulator) = {
            #[cfg(wasm)]
            let mut encrypted_request = Vec::new();
            #[cfg(wasm)]
            let client_request =
                client.encapsulate_stream(futures::io::Cursor::new(&mut encrypted_request))?;

            #[cfg(not(wasm))]
            let (encrypted_request, request_write) = tokio::io::duplex(4096);
            #[cfg(not(wasm))]
            let client_request = client.encapsulate_stream(request_write.compat())?;

            let client_response_decapsulator = client_request.response_decapsulator()?;

            let encryption_task = async {
                async {
                    let mut client_request = client_request.compat_write();
                    let bytes_copied = tokio::io::copy(
                        &mut bhttp_encoder
                            .map_err(std::io::Error::other)
                            .into_async_read()
                            .compat(),
                        &mut client_request,
                    )
                    .await?;
                    tracing::debug!(bytes_copied, "BHTTP request encoded and encrypted");
                    let mut client_request = client_request.into_inner();
                    client_request.close().await?; // Remember to close the response stream

                    Ok::<_, anyhow::Error>(())
                }
                .await
                .unwrap_or_else(|error| tracing::error!(?error, "Error when encrypting request"))
            };

            // We have to avoid using spawn_supervised_task_current_span(), since it may randomly not got executed on wasm (web) and currently we have no idea why.
            //  streaming request is not supported, so we can just wait for the encryption task to finish here.
            #[cfg(wasm)]
            let _: () = encryption_task.await;

            #[cfg(not(wasm))]
            self.runtime
                .spawn_supervised_task_current_span(encryption_task);

            (encrypted_request, client_response_decapsulator)
        };

        let ohttp_request_body = {
            let metadata_buf = {
                let metadata = Metadata {
                    client_auth: Some(client_auth.clone()), // TODO: optimize this clone
                    key_config_hint: Some(ServerKeyConfigHint {
                        public_key: key_config.public_key()?.into_vec(),
                    }),
                };

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
                tracing::trace!(metadata_length = metadata_buf.len(), "metadata length");
                metadata_buf
            };

            #[cfg(wasm)]
            {
                let mut body_bytes = metadata_buf;
                body_bytes.extend_from_slice(&encrypted_request);
                tracing::debug!(
                    body_length = body_bytes.len(),
                    "Encrypted request body length"
                );
                reqwest::Body::from(body_bytes.freeze())
            }
            #[cfg(not(wasm))]
            {
                let body = std::io::Cursor::new(metadata_buf).chain(encrypted_request);
                reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(body))
            }
        };

        // Forward the request to the upstream server
        let url = self.base_url.clone();

        tracing::debug!(?url, "Sending OHTTP request to upstream server");

        let response = self
            .http_client
            .post(url)
            .header(OhttpApi::HEADER_NAME, OhttpApi::TUNNEL)
            .header(
                http::header::CONTENT_TYPE,
                OHTTP_CHUNKED_REQUEST_CONTENT_TYPE,
            )
            .body(ohttp_request_body)
            .send()
            .await
            .map_err(TngError::HttpCipherTextForwardError)?;

        #[cfg(unix)]
        tracing::debug!(
            status = ?response.status(),
            version = ?response.version(),
            "Received OHTTP response from upstream server"
        );
        #[cfg(wasm)]
        tracing::debug!(
            status = ?response.status(),
            "Received OHTTP response from upstream server"
        );

        // Check the response status code
        let status_code = response.status();
        #[cfg(unix)]
        let content_len = {
            let headers = response.headers().clone();
            headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
        };
        #[cfg(unix)]
        tracing::debug!(
            status = ?status_code,
            ?content_len,
            "OHTTP response content length before decapsulation"
        );
        let response = response.check_error_response().await.map_err(|error| {
            if status_code == StatusCode::UNPROCESSABLE_ENTITY {
                TngError::ShouldRequestNewKeyConfigFromServerError(error)
            } else {
                TngError::HttpCipherTextBadResponse(error)
            }
        })?;

        // Check content-type
        match response.headers().get(http::header::CONTENT_TYPE) {
            Some(value) => {
                if value != OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE {
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

        #[cfg(unix)]
        let content_len = response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());
        #[cfg(unix)]
        tracing::debug!(
            content_length = ?content_len,
            "OHTTP response body stream ready for decapsulation"
        );

        let response_body = response.bytes_stream();

        #[cfg(wasm)]
        // Create a new stream wrapper here since reqwest::Response is not Send, which is required by BhttpDecoder.
        // TODO: maybe we can check Send requirements in BhttpDecoder can be removed ?
        let response_body = {
            use futures::SinkExt;

            let (mut sender, receiver) = futures::channel::mpsc::unbounded();
            let parent_span = tracing::Span::current();
            tokio_with_wasm::task::spawn(
                async move {
                    let stream = response_body;
                    sender.send_all(&mut stream.map(|item| Ok(item))).await
                }
                .instrument(parent_span),
            );
            receiver
        };

        // Decrypt the ohttp response message
        let decrypted_response = client_response_decapsulator.decapsulate_response(
            StreamReader::new(response_body.map(|result| result.map_err(std::io::Error::other)))
                .compat(),
        ).map_err(|e| {
            tracing::error!(
                error = ?e,
                "OHTTP response decapsulation failed (likely server returned malformed ciphertext)"
            );
            e
        })?;
        // Decode the bhttp binary message
        let decode_result = BhttpDecoder::new(decrypted_response)
            .decode_message()
            .await
            .map_err(|e| {
                tracing::error!(
                    error = ?e,
                    "BHTTP decoding of decrypted response failed"
                );
                e
            })?;

        let HttpMessage::Response(response) = decode_result.into_full_message()? else {
            return Err(TngError::InvalidHttpResponse);
        };

        let response = {
            let (head, body) = response.into_parts();
            tracing::debug!(response = ?head, "Decrypted response head from upstream server");
            http::Response::from_parts(head, body)
        };

        Ok(axum::response::IntoResponse::into_response(response))
    }

    /// Interface 3: Attestation Forward - Get Challenge
    /// x-tng-ohttp-api: /tng/background-check/challenge
    ///
    /// This method is a forwarder for the AS (Attestation Service) challenge endpoint.
    /// It is used specifically in the "Server verification Client + background check model" scenario.
    pub async fn background_check_attestation_challenge(
        &self,
    ) -> Result<AttestationChallengeResponse, TngError> {
        let url = self.base_url.clone();

        let result: AttestationChallengeResponse = self
            .http_client
            .get(url)
            .header(OhttpApi::HEADER_NAME, OhttpApi::BACKGROUND_CHECK_CHALLENGE)
            .send()
            .await
            .map_err(|e| TngError::ClientGetAttestationChallengeFaild(e.into()))?
            .check_error_response()
            .await
            .map_err(TngError::ClientGetAttestationChallengeFaild)?
            .json()
            .await
            .map_err(|e| TngError::ClientGetAttestationChallengeFaild(e.into()))?;

        Ok(result)
    }

    /// Interface 3: Attestation Forward - Verify Evidence
    /// x-tng-ohttp-api: /tng/background-check/verify
    ///
    /// This method is a forwarder for the AS (Attestation Service) verification endpoint.
    /// It is used specifically in the "Server verification Client + background check model" scenario.
    pub async fn background_check_verify_attestation(
        &self,
        evidence: TngEvidence,
    ) -> Result<AttestationVerifyResponse, TngError> {
        let url = self.base_url.clone();

        let payload = AttestationVerifyRequest {
            evidence: evidence
                .serialize_to_json()
                .map_err(|e| TngError::ClientGetBackgroundCheckResultFaild(e.into()))?,
            aa_provider: Some(evidence.provider_type()),
        };

        let result: AttestationVerifyResponse = self
            .http_client
            .post(url)
            .header(OhttpApi::HEADER_NAME, OhttpApi::BACKGROUND_CHECK_VERIFY)
            .json(&payload)
            .send()
            .await
            .map_err(|e| TngError::ClientGetBackgroundCheckResultFaild(e.into()))?
            .check_error_response()
            .await
            .map_err(TngError::ClientGetBackgroundCheckResultFaild)?
            .json()
            .await
            .map_err(|e| TngError::ClientGetBackgroundCheckResultFaild(e.into()))?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_status_entry_full() {
        let entry = ServerStatusEntry {
            url: "http://10.0.0.1:8080/path".to_string(),
            server_public_key: Some("a1b2c3d4".to_string()),
            server_attestation: Some("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig".to_string()),
        };
        let value = serde_json::to_value(&entry).unwrap();
        assert_eq!(value["url"], "http://10.0.0.1:8080/path");
        assert_eq!(value["server_public_key"], "a1b2c3d4");
        assert_eq!(
            value["server_attestation"],
            "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig"
        );
    }

    #[test]
    fn test_server_status_entry_partial() {
        let entry = ServerStatusEntry {
            url: "http://10.0.0.2:9090/".to_string(),
            server_public_key: None,
            server_attestation: None,
        };
        let value = serde_json::to_value(&entry).unwrap();
        assert_eq!(value["url"], "http://10.0.0.2:9090/");
        assert!(
            value.get("server_public_key").is_none(),
            "server_public_key should be omitted when None"
        );
        assert!(
            value.get("server_attestation").is_none(),
            "server_attestation should be omitted when None"
        );
    }
}
