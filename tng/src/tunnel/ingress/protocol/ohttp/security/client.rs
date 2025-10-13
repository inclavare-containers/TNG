use anyhow::{anyhow, bail, Context, Result};
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
use ohttp::KeyConfig;
use prost::Message;
use rand::{RngCore, SeedableRng as _};
use rand_chacha::ChaCha12Rng;
#[cfg(unix)]
use rats_cert::tee::coco::attester::CocoAttester;
#[cfg(unix)]
use rats_cert::tee::AttesterPipeline;
#[cfg(unix)]
use rats_cert::tee::GenericAttester as _;
use rats_cert::{
    cert::dice::cbor::OCBR_TAG_EVIDENCE_COCO_EVIDENCE,
    tee::{
        coco::{
            converter::CocoConverter,
            evidence::{CocoAsToken, CocoEvidence},
            verifier::CocoVerifier,
        },
        GenericConverter, GenericEvidence as _, GenericVerifier as _,
    },
};
use tokio::{io::AsyncReadExt, sync::Mutex};
use tokio_util::{
    compat::{
        FuturesAsyncReadCompatExt as _, FuturesAsyncWriteCompatExt as _,
        TokioAsyncReadCompatExt as _,
    },
    io::{ReaderStream, StreamReader},
};
use url::Url;

use std::{pin::Pin, sync::Arc};

#[cfg(unix)]
use crate::config::ra::AttestArgs;
#[cfg(unix)]
use crate::tunnel::ohttp::protocol::metadata::EncryptedWithClientAuthAsymmetricKey;
#[cfg(unix)]
use crate::tunnel::ohttp::protocol::userdata::ClientUserData;
use crate::{
    config::ra::RaArgs,
    error::TngError,
    tunnel::ohttp::protocol::header::{
        OhttpApi, OHTTP_CHUNKED_REQUEST_CONTENT_TYPE, OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE,
    },
    AttestationResult, TokioRuntime,
};
use crate::{
    config::ra::{AttestationServiceArgs, AttestationServiceTokenVerifyArgs, VerifyArgs},
    error::CheckErrorResponse as _,
    tunnel::{
        ohttp::protocol::{
            metadata::{
                metadata::MetadataType, EncryptedWithoutClientAuth, Metadata, METADATA_MAX_LEN,
            },
            userdata::ServerUserData,
            AttestationChallengeResponse, AttestationRequest, AttestationResultJwt,
            AttestationVerifyRequest, AttestationVerifyResponse, HpkeKeyConfig, KeyConfigRequest,
            KeyConfigResponse, ServerAttestationInfo,
        },
        utils::maybe_cached::{Expire, MaybeCached, RefreshStrategy},
    },
};

const DEFAULT_KEY_CONFIG_REFRESH_SECOND: u64 = 5 * 60; // 5 minutes

pub struct OHttpClient {
    inner: Arc<OHttpClientInner>,
    key_store_value: MaybeCached<KeyStoreValue, TngError>,
}

pub struct OHttpClientInner {
    ra_args: RaArgs,
    http_client: Arc<reqwest::Client>,
    rng: Mutex<ChaCha12Rng>,
    base_url: Url,
    runtime: TokioRuntime,
}

struct KeyStoreValue {
    metadata: Metadata,

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

impl OHttpClient {
    pub async fn new(
        ra_args: RaArgs,
        http_client: Arc<reqwest::Client>,
        base_url: Url,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let refresh_strategy = match &ra_args {
            #[cfg(unix)]
            RaArgs::AttestOnly(attest) | RaArgs::AttestAndVerify(attest, ..) => match &attest {
                AttestArgs::Passport { aa_args, .. } | AttestArgs::BackgroundCheck { aa_args } => {
                    aa_args.refresh_strategy()
                }
            },
            RaArgs::VerifyOnly(..) | RaArgs::NoRa => RefreshStrategy::Periodically {
                interval: DEFAULT_KEY_CONFIG_REFRESH_SECOND,
            },
        };

        let inner = Arc::new(OHttpClientInner {
            ra_args,
            rng: Mutex::new(ChaCha12Rng::from_os_rng()),
            http_client,
            base_url,
            runtime: runtime.clone(),
        });

        let key_store_value = MaybeCached::new(runtime.clone(), refresh_strategy, {
            let inner = inner.clone();
            move || {
                let inner = inner.clone();
                Box::pin(async move {
                    inner
                        .create_key_store_value()
                        .await
                        .map_err(TngError::GenServerHpkeConfigurationFailed)
                }) as Pin<Box<_>>
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

        let response = self
            .inner
            .send_encrypted_request(
                &key_store_value.server_key_config_list,
                &key_store_value.metadata,
                request,
            )
            .await?;

        Ok((response, key_store_value.server_attestation_result.clone()))
    }
}

impl OHttpClientInner {
    async fn verify_token(
        server_key_config: &HpkeKeyConfig,
        attestation_result: &AttestationResultJwt,
        token_verify: &AttestationServiceTokenVerifyArgs,
    ) -> Result<CocoAsToken> {
        let token = CocoAsToken::new(attestation_result.0.to_owned())?;
        let verifier =
            CocoVerifier::new(&token_verify.trusted_certs_paths, &token_verify.policy_ids)?;

        let userdata = ServerUserData {
            challenge_token: "".to_string(),
            hpke_key_config: server_key_config.clone(),
        };

        verifier
            .verify_evidence(&token, serde_json::to_string(&userdata)?.as_bytes())
            .await?;
        Ok(token)
    }

    async fn verify_evidence(
        server_key_config: &HpkeKeyConfig,
        challenge_token: &str,
        evidence: &str,
        as_args: &AttestationServiceArgs,
    ) -> Result<CocoAsToken> {
        let raw_evidence = BASE64_STANDARD.decode(evidence)?;

        let coco_evidence = std::result::Result::<_, rats_cert::errors::Error>::from(
            CocoEvidence::create_evidence_from_dice(OCBR_TAG_EVIDENCE_COCO_EVIDENCE, &raw_evidence),
        )?;
        let coco_converter = CocoConverter::new(
            &as_args.as_addr,
            &as_args.token_verify.policy_ids,
            as_args.as_is_grpc,
        )?;
        let token = coco_converter.convert(&coco_evidence).await?;

        let verifier = CocoVerifier::new(
            &as_args.token_verify.trusted_certs_paths,
            &as_args.token_verify.policy_ids,
        )?;

        let userdata = ServerUserData {
            challenge_token: challenge_token.to_owned(),
            hpke_key_config: server_key_config.clone(),
        };

        verifier
            .verify_evidence(&token, serde_json::to_string(&userdata)?.as_bytes())
            .await?;
        Ok(token)
    }

    async fn create_key_store_value(&self) -> Result<(KeyStoreValue, Expire)> {
        // Handle metatdata for self
        let (client_key, metadata, mut expire) = self.create_attested_client_key().await?;

        // TODO: use kbs protocol to get challenge token from trustee
        let challenge_token = self.rng.lock().await.next_u64().to_string();
        let key_config_request = self.prepare_key_config_request(&challenge_token).await?;

        // Handle hpke configuration for server
        let response = self.get_hpke_configuration(key_config_request).await?;

        let token = self
            .check_key_config_response(&response, &challenge_token)
            .await?;

        expire = std::cmp::min(
            expire,
            Expire::from_timestamp(response.hpke_key_config.expire_timestamp)?,
        );

        let server_attestation_result = match token {
            Some(token) => {
                expire = std::cmp::min(expire, Expire::from_timestamp(token.exp()?)?);
                Some(AttestationResult::from_claims(token.get_claims()?))
            }
            None => None,
        };

        let server_key_config_list = KeyConfig::decode_list(
            BASE64_STANDARD
                .decode(response.hpke_key_config.encoded_key_config_list)?
                .as_ref(),
        )?;

        Ok((
            KeyStoreValue {
                metadata,
                client_key, // TODO: ohttp hpke setup with the client key
                server_key_config_list,
                server_attestation_result,
            },
            expire,
        ))
    }

    async fn check_key_config_response(
        &self,
        response: &KeyConfigResponse,
        challenge_token: &str,
    ) -> Result<Option<CocoAsToken>, anyhow::Error> {
        let verify = match &self.ra_args {
            RaArgs::VerifyOnly(verify) => verify,
            #[cfg(unix)]
            RaArgs::AttestAndVerify(.., verify) => verify,
            #[cfg(unix)]
            RaArgs::AttestOnly(..) => {
                // Not required
                return Ok(None);
            }
            RaArgs::NoRa => {
                // Not required
                return Ok(None);
            }
        };

        let server_key_config = &response.hpke_key_config;

        Ok(match (&response.attestation_info, verify) {
            (
                Some(ServerAttestationInfo::Passport { attestation_result }),
                VerifyArgs::Passport { token_verify },
            ) => {
                Some(Self::verify_token(server_key_config, attestation_result, token_verify).await?)
            }
            (
                Some(ServerAttestationInfo::BackgroundCheck { evidence }),
                VerifyArgs::BackgroundCheck { as_args },
            ) => Some(
                Self::verify_evidence(server_key_config, &challenge_token, evidence, as_args)
                    .await?,
            ),
            (Some(ServerAttestationInfo::Passport { .. }), VerifyArgs::BackgroundCheck { .. }) => {
                bail!("Background check model is expected but got passport attestation from server")
            }
            (Some(ServerAttestationInfo::BackgroundCheck { .. }), VerifyArgs::Passport { .. }) => {
                bail!("Passport model is expected but got background check attestation from server")
            }
            (None, _) => bail!("Missing attestation info from server"),
        })
    }

    async fn create_attested_client_key(
        &self,
    ) -> Result<(
        Option<(
            <X25519HkdfSha256 as Kem>::PrivateKey,
            <X25519HkdfSha256 as Kem>::PublicKey,
        )>,
        Metadata,
        Expire,
    )> {
        Ok(match &self.ra_args {
            #[cfg(unix)]
            RaArgs::AttestOnly(attest) | RaArgs::AttestAndVerify(attest, ..) => {
                let client_key = X25519HkdfSha256::gen_keypair(&mut self.rng.lock().await);
                let pk_s = client_key.1.to_bytes().to_vec();

                let token = match attest {
                    AttestArgs::Passport { aa_args, as_args } => {
                        let coco_attester = CocoAttester::new(&aa_args.aa_addr)?;
                        let coco_converter = CocoConverter::new(
                            &as_args.as_addr,
                            &as_args.token_verify.policy_ids,
                            as_args.as_is_grpc,
                        )?;
                        let attester_pipeline =
                            AttesterPipeline::new(coco_attester, coco_converter);

                        let userdata = ClientUserData {
                            // TODO: should get challenge from attestation service
                            challenge_token: "".to_string(),
                            pk_s: BASE64_STANDARD.encode(pk_s.as_slice()),
                        };

                        attester_pipeline
                            .get_evidence(serde_json::to_string(&userdata)?.as_bytes())
                            .await?
                    }
                    AttestArgs::BackgroundCheck { aa_args } => {
                        let AttestationChallengeResponse { challenge_token } =
                            self.background_check_attestation_challenge().await?;

                        let coco_attester = CocoAttester::new(&aa_args.aa_addr)?;

                        let userdata = ClientUserData {
                            challenge_token: challenge_token.clone(),
                            pk_s: BASE64_STANDARD.encode(pk_s.as_slice()),
                        };

                        let evidence = coco_attester
                            .get_evidence(serde_json::to_string(&userdata)?.as_bytes())
                            .await?;

                        let AttestationVerifyResponse {
                            attestation_result: token,
                        } = self
                            .background_check_verify_attestation(
                                challenge_token,
                                BASE64_STANDARD.encode(evidence.get_dice_raw_evidence()?),
                            )
                            .await?;
                        CocoAsToken::new(token)?
                    }
                };

                let token_expire = Expire::from_timestamp(token.exp()?)?;

                (
                    Some(client_key),
                    Metadata {
                        metadata_type: Some(MetadataType::EncryptedWithClientAuthAsymmetricKey(
                            EncryptedWithClientAuthAsymmetricKey {
                                attestation_result: token.into_str(),
                                pk_s,
                            },
                        )),
                    },
                    token_expire,
                )
            }
            RaArgs::VerifyOnly(..) | RaArgs::NoRa => {
                // Not required
                (
                    None,
                    Metadata {
                        metadata_type: Some(MetadataType::EncryptedWithoutClientAuth(
                            EncryptedWithoutClientAuth {},
                        )),
                    },
                    Expire::NoExpire,
                )
            }
        })
    }

    /// Prepare a key configuration request
    async fn prepare_key_config_request(&self, challenge_token: &str) -> Result<KeyConfigRequest> {
        let verify = match &self.ra_args {
            RaArgs::VerifyOnly(verify) => verify,
            #[cfg(unix)]
            RaArgs::AttestAndVerify(.., verify) => verify,
            #[cfg(unix)]
            RaArgs::AttestOnly(..) => {
                return Ok(KeyConfigRequest {
                    attestation_request: None,
                });
            }
            RaArgs::NoRa => {
                return Ok(KeyConfigRequest {
                    attestation_request: None,
                });
            }
        };

        Ok(match verify {
            VerifyArgs::Passport { .. } => KeyConfigRequest {
                attestation_request: Some(AttestationRequest::Passport),
            },
            VerifyArgs::BackgroundCheck { .. } => KeyConfigRequest {
                attestation_request: Some(AttestationRequest::BackgroundCheck {
                    challenge_token: challenge_token.to_owned(),
                }),
            },
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

        let response: KeyConfigResponse = response
            .json()
            .await
            .map_err(|error| TngError::RequestKeyConfigFailed(error.into()))?;

        tracing::debug!(?response, "Received HPKE key configuration");

        Ok(response)
    }

    /// Clients use the hpke_key_config obtained from Interface 1 to encrypt a standard HTTP request,
    /// and send the encrypted ciphertext as the request body to the server.
    async fn send_encrypted_request(
        &self,
        server_key_config_list: &Vec<KeyConfig>,
        metadata: &Metadata,
        request: axum::extract::Request,
    ) -> Result<axum::response::Response, TngError> {
        // Encode the request to bhttp message
        let bhttp_encoder = BhttpEncoder::from_request(request);

        // Encrypt to get the ohttp message
        let mut key_config = server_key_config_list
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
        let response = response
            .error_for_status()
            .map_err(TngError::HttpCipherTextForwardError)?;

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

        let response_body = response.bytes_stream();

        #[cfg(wasm)]
        // Create a new stream wrapper here since reqwest::Response is not Send, which is required by BhttpDecoder.
        // TODO: maybe we can check Send requirements in BhttpDecoder can be removed ?
        let response_body = {
            use futures::SinkExt;

            let (mut sender, receiver) = futures::channel::mpsc::unbounded();
            tokio_with_wasm::task::spawn(async move {
                let stream = response_body;
                sender.send_all(&mut stream.map(|item| Ok(item))).await
            });
            receiver
        };

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
        challenge_token: String,
        evidence: String,
    ) -> Result<AttestationVerifyResponse, TngError> {
        let url = self.base_url.clone();

        let payload = AttestationVerifyRequest {
            challenge_token,
            evidence,
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
