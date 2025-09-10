use anyhow::{anyhow, bail, Result};
use axum::Json;
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use bhttp::http_compat::decode::{BhttpDecoder, HttpMessage};
use bhttp::http_compat::encode::BhttpEncoder;
use bytes::BytesMut;
use futures::{AsyncWriteExt, StreamExt as _, TryStreamExt as _};
use ohttp::KeyConfig;
use prost::Message as _;
use rats_cert::cert::dice::cbor::OCBR_TAG_EVIDENCE_COCO_EVIDENCE;
use rats_cert::tee::coco::attester::CocoAttester;
use rats_cert::tee::coco::converter::CocoConverter;
use rats_cert::tee::coco::evidence::{CocoAsToken, CocoEvidence};
use rats_cert::tee::coco::verifier::CocoVerifier;
use rats_cert::tee::{
    AttesterPipeline, GenericAttester as _, GenericConverter, GenericEvidence, GenericVerifier as _,
};
use tokio::io::AsyncReadExt;
use tokio_util::compat::FuturesAsyncReadCompatExt as _;
use tokio_util::compat::FuturesAsyncWriteCompatExt as _;
use tokio_util::compat::TokioAsyncReadCompatExt as _;
use tokio_util::io::ReaderStream;

use crate::config::ra::{AttestArgs, AttestationServiceArgs, RaArgs, VerifyArgs};
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::state::OhttpServerState;
use crate::tunnel::ohttp::protocol::metadata::metadata::MetadataType;
use crate::tunnel::ohttp::protocol::metadata::{
    EncryptedWithClientAuthAsymmetricKey, EncryptedWithoutClientAuth, Metadata, METADATA_MAX_LEN,
};
use crate::tunnel::ohttp::protocol::userdata::{ClientUserData, ServerUserData};
use crate::tunnel::ohttp::protocol::{
    AttestationChallengeResponse, AttestationRequest, AttestationResultJwt,
    AttestationVerifyRequest, AttestationVerifyResponse, HpkeKeyConfig, KeyConfigRequest,
    KeyConfigResponse, ServerAttestationInfo,
};

/// Server-side key store for managing cryptographic keys and attestation data
#[derive(Debug, Clone)]
pub struct ServerKeyStore {
    /// Remote Attestation arguments
    ra_args: RaArgs,
    /// OHTTP key configurations
    ohttp: ohttp::Server,
    /// Expiration timestamp for the key configurations
    expire_timestamp: u64,
}

impl ServerKeyStore {
    /// Create a new ServerKeyStore with OHTTP key configurations
    ///
    /// This function generates OHTTP key configurations with the following algorithms:
    /// - KEM: X25519Sha256
    /// - Symmetric Algorithms:
    ///   - KDF: HkdfSha256
    ///   - AEAD: ChaCha20Poly1305, Aes256Gcm, Aes128Gcm
    pub fn new(ra_args: RaArgs) -> Result<Self, TngError> {
        // TODO: support multiple key config and select key config based on key id

        // Create key config with X25519Sha256 KEM and multiple symmetric algorithms, this will generate all the keys randomly
        let config = ohttp::KeyConfig::new(
            0, // key_id
            ohttp::hpke::Kem::X25519Sha256,
            vec![
                ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                ),
                ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::Aes256Gcm,
                ),
                ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::Aes128Gcm,
                ),
            ],
        )
        .map_err(TngError::from)?;

        // Initialize the ohttp server
        let ohttp = ohttp::Server::new(config).map_err(TngError::from)?;

        // TODO: set a background task to refresh the keyconfig
        // Set expiration timestamp to 1 hour from now
        let expire_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(TngError::from)?
            .as_secs()
            + 3600;

        Ok(ServerKeyStore {
            ra_args,
            ohttp,
            expire_timestamp,
        })
    }

    /// Interface 1: Get HPKE Configuration
    /// POST /tng/key-config
    ///
    /// This endpoint is used by TNG Clients to obtain the public key configuration needed
    /// to establish an encrypted channel and verify the server's identity.
    ///
    /// The client accesses this path before connecting to the TNG Server to obtain the
    /// server's public key and Evidence or Attestation Result (if needed).
    ///
    /// This endpoint only needs to be accessed once. Before config_expire_timestamp or
    /// attestation_result expiration, the configuration needs to be refreshed in the background.
    pub async fn get_hpke_configuration(
        &self,
        payload: Option<Json<KeyConfigRequest>>,
    ) -> Result<Json<KeyConfigResponse>, TngError> {
        let key_config_list = vec![self.ohttp.config()];

        let encoded_key_config_list = BASE64_STANDARD
            .encode(KeyConfig::encode_list(&key_config_list).map_err(TngError::from)?);

        let key_config = HpkeKeyConfig {
            expire_timestamp: self.expire_timestamp,
            encoded_key_config_list,
        };

        let attestation_request = payload
            .map(|Json(payload)| payload.attestation_request)
            .flatten();

        let response = async {
            Ok(match &self.ra_args {
                RaArgs::AttestOnly(attest) | RaArgs::AttestAndVerify(attest, ..) => {
                    match (attestation_request, attest) {
                        (
                            Some(AttestationRequest::Passport),
                            AttestArgs::Passport { aa_args, as_args },
                        ) => {
                            // TODO: aa_args.refresh_interval
                            let coco_attester = CocoAttester::new(&aa_args.aa_addr)?;
                            let coco_converter = CocoConverter::new(
                                &as_args.as_addr,
                                &as_args.token_verify.policy_ids,
                                as_args.as_is_grpc,
                            )?;
                            let attester_pipeline =
                                AttesterPipeline::new(coco_attester, coco_converter);

                            let userdata = ServerUserData {
                                challenge_token: "".to_string(),
                                hpke_key_config: key_config,
                            };

                            let token = attester_pipeline
                                .get_evidence(serde_json::to_string(&userdata)?.as_bytes())
                                .await?;
                            KeyConfigResponse {
                                hpke_key_config: userdata.hpke_key_config,
                                attestation_info: Some(ServerAttestationInfo::Passport {
                                    attestation_result: AttestationResultJwt(
                                        token.as_str().to_owned(),
                                    ),
                                }),
                            }
                        }
                        (
                            Some(AttestationRequest::BackgroundCheck { challenge_token }),
                            AttestArgs::BackgroundCheck { aa_args },
                        ) => {
                            // TODO: aa_args.refresh_interval
                            let coco_attester = CocoAttester::new(&aa_args.aa_addr)?;

                            let userdata = ServerUserData {
                                challenge_token,
                                hpke_key_config: key_config,
                            };

                            let evidence = coco_attester
                                .get_evidence(serde_json::to_string(&userdata)?.as_bytes())
                                .await?;

                            let evidence =
                                BASE64_STANDARD.encode(evidence.get_dice_raw_evidence()?);

                            KeyConfigResponse {
                                hpke_key_config: userdata.hpke_key_config,
                                attestation_info: Some(ServerAttestationInfo::BackgroundCheck {
                                    evidence,
                                }),
                            }
                        }
                        (
                            Some(AttestationRequest::Passport { .. }),
                            AttestArgs::BackgroundCheck { .. },
                        ) => bail!(
                        "Background check model is expected but passport attestation is requested"
                    ),
                        (
                            Some(AttestationRequest::BackgroundCheck { .. }),
                            AttestArgs::Passport { .. },
                        ) => bail!(
                        "Passport model is expected but background check attestation is requested"
                    ),
                        (None, _) => bail!("Missing attestation request from client"),
                    }
                }
                RaArgs::VerifyOnly(..) | RaArgs::NoRa => {
                    // No remote attestaion
                    KeyConfigResponse {
                        hpke_key_config: key_config,
                        attestation_info: None,
                    }
                }
            })
        }
        .await
        .map_err(TngError::GenServerHpkeConfigurationFailed)?;

        Ok(Json(response))
    }

    /// Interface 2: Process Encrypted Request
    /// POST /tng/tunnel (or user specified path via path_rewrites)
    ///
    /// Clients use the hpke_key_config obtained from Interface 1 to encrypt a standard HTTP request,
    /// and send the encrypted ciphertext as the request body to the server. The server decrypts and processes
    /// the request, then encrypts the HTTP response and returns it.
    pub async fn process_encrypted_request(
        &self,
        payload: axum::extract::Request,
        state: OhttpServerState,
    ) -> Result<axum::response::Response, TngError> {
        // Check content-type
        match payload.headers().get(http::header::CONTENT_TYPE) {
            Some(value) => {
                if value != "message/ohttp-chunked-req" {
                    return Err(TngError::InvalidOHttpRequest(anyhow!(
                        "Wrong content-type header"
                    )));
                }
            }
            None => {
                return Err(TngError::InvalidOHttpRequest(anyhow!(
                    "Wrong content-type header"
                )));
            }
        }

        // TODO: check version of tng protocol
        let mut reader =
            tokio_util::io::StreamReader::new(payload.into_body().into_data_stream().map(
                |result| result.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err)),
            ));

        // Read and decode matadata
        let metadata = {
            let metadata_len = reader
                .read_u32() // big-endian
                .await
                .map_err(TngError::MetadataReadError)?;

            let metadata_len =
                usize::try_from(metadata_len).map_err(|_| TngError::MetadataTooLong)?;

            if metadata_len > METADATA_MAX_LEN {
                return Err(TngError::MetadataTooLong);
            }

            let mut buf = BytesMut::with_capacity(metadata_len as usize);

            while buf.len() < metadata_len as usize {
                reader
                    .read_buf(&mut buf)
                    .await
                    .map_err(TngError::MetadataReadError)?;
            }

            Metadata::decode(buf.as_ref()).map_err(TngError::MetadataDecodeError)?
        };

        tracing::debug!(?metadata, "Received OHTTP request");

        // Check metadata
        self.validata_metadata(metadata)
            .await
            .map_err(TngError::MetadataValidateError)?;

        // Decrypt the ohttp message
        let plain_text = self.ohttp.decapsulate_stream(reader.compat());
        // Decode the bhttp binary message
        let decode_result = BhttpDecoder::new(plain_text).decode_message().await?;
        let server_response_encapsulator = decode_result.reader_ref().response_encapsulator()?;

        let HttpMessage::Request(request) = decode_result.into_full_message()? else {
            return Err(TngError::InvalidHttpRequest);
        };

        tracing::debug!(
            method = ?request.method(),
            version = ?request.version(),
            uri = ?request.uri(),
            "Forwarding request to upstream server"
        );

        // Forward the request to the upstream server
        let response = state.forward_request(request, None).await?;

        tracing::debug!(
            status = ?response.status(),
            version = ?response.version(),
            "Received response from upstream server"
        );

        // Encode the response to bhttp message
        let bhttp_encoder = BhttpEncoder::from_response(response);
        // Encrypt to get the ohttp message
        let encrypted_response = {
            let (response_read, response_write) = tokio::io::duplex(4096);
            let server_response =
                server_response_encapsulator.encapsulate_response(response_write.compat())?;
            state.runtime.spawn_supervised_task_current_span(async {
                let mut server_response = server_response.compat_write();
                tokio::io::copy(
                    &mut bhttp_encoder
                        .map_err(std::io::Error::other)
                        .into_async_read()
                        .compat(),
                    &mut server_response,
                )
                .await?;
                let mut server_response = server_response.into_inner();
                server_response.close().await?; // Remember to close the response stream

                Ok::<_, anyhow::Error>(())
            });

            response_read
        };

        // Return the response
        let response = http::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "message/ohttp-chunked-res")
            .body(axum::body::Body::from_stream(ReaderStream::new(
                encrypted_response,
            )))
            .map_err(TngError::ConstructHttpResponseFailed)?;

        Ok(response)
    }

    async fn validata_metadata(&self, metadata: Metadata) -> Result<()> {
        match (metadata.metadata_type, &self.ra_args) {
            (
                Some(MetadataType::EncryptedWithClientAuthAsymmetricKey(
                    EncryptedWithClientAuthAsymmetricKey {
                        attestation_result,
                        pk_s,
                    },
                )),
                RaArgs::VerifyOnly(verify) | RaArgs::AttestAndVerify(.., verify),
            ) => match verify {
                VerifyArgs::Passport { token_verify }
                | VerifyArgs::BackgroundCheck {
                    as_args: AttestationServiceArgs { token_verify, .. },
                } => {
                    let token = CocoAsToken::new(attestation_result)?;
                    let verifier = CocoVerifier::new(
                        &token_verify.trusted_certs_paths,
                        &token_verify.policy_ids,
                    )?;

                    let userdata = ClientUserData {
                        // TODO: the challenge_token is not required to be check here, since it is already checked by attestation service. One way to slove it in rats-rs is to make report_data field of CocoVerifier::verify_evidence() to be Option<&[u8]>. So that we can skip the comparesion of user data.
                        challenge_token: "".to_string(),
                        pk_s: BASE64_STANDARD.encode(&pk_s),
                    };

                    verifier
                        .verify_evidence(&token, serde_json::to_string(&userdata)?.as_bytes())
                        .await?;
                }
            },
            (
                Some(MetadataType::EncryptedWithoutClientAuth(EncryptedWithoutClientAuth {})),
                RaArgs::AttestOnly(..) | RaArgs::NoRa,
            ) => {
                // Peace and love
            }
            (
                Some(MetadataType::EncryptedWithoutClientAuth(EncryptedWithoutClientAuth {})),
                RaArgs::VerifyOnly(..) | RaArgs::AttestAndVerify(..),
            ) => {
                bail!(
                    "client attestation is required but no attestation info was provided by client"
                )
            }
            (
                Some(MetadataType::EncryptedWithClientAuthAsymmetricKey(..)),
                RaArgs::AttestOnly(..) | RaArgs::NoRa,
            ) => {
                bail!("client attestation is not required but some attestation info ware provided by client")
            }
            (None, _) => {
                bail!("metadata_type is empty")
            }
        }

        Ok(())
    }

    /// Interface 3: Attestation Forward - Get Challenge
    /// GET /tng/background-check/challenge
    ///
    /// This endpoint is a forwarder for the AS (Attestation Service) challenge endpoint.
    /// It is used specifically in the "Server verification Client + background check model" scenario.
    pub async fn get_attestation_challenge(
        &self,
    ) -> Result<Json<AttestationChallengeResponse>, TngError> {
        // TODO: Forward the request to the actual AS challenge endpoint. Return the challenge token received from the AS
        let response = AttestationChallengeResponse {
            challenge_token: "".to_string(),
        };

        Ok(Json(response))
    }

    /// Interface 3: Attestation Forward - Verify Evidence
    /// POST /tng/background-check/verify
    ///
    /// This endpoint is a forwarder for the AS (Attestation Service) verification endpoint.
    /// It is used specifically in the "Server verification Client + background check model" scenario.
    pub async fn verify_attestation(
        &self,
        Json(payload): Json<AttestationVerifyRequest>,
    ) -> Result<Json<AttestationVerifyResponse>, TngError> {
        async {
            match &self.ra_args {
                RaArgs::VerifyOnly(verify) | RaArgs::AttestAndVerify(.., verify) => match verify {
                    VerifyArgs::Passport { token_verify: _ } => {
                        bail!("Passport model is expected but got background check attestation from client")
                    }
                    VerifyArgs::BackgroundCheck {
                        as_args,
                    } => {

                        // TODO: pass payload.challenge_token to attestation server
                        let _challenge_token = payload.challenge_token;

                        let coco_evidence = std::result::Result::<_, rats_cert::errors::Error>::from(
                            CocoEvidence::create_evidence_from_dice(OCBR_TAG_EVIDENCE_COCO_EVIDENCE, BASE64_STANDARD.decode(payload.evidence)?.as_ref()),
                        )?;

                        let coco_converter = CocoConverter::new(
                            &as_args.as_addr,
                            &as_args.token_verify.policy_ids,
                            as_args.as_is_grpc,
                        )?;

                        let token  = coco_converter.convert(&coco_evidence).await?;

                        let response = AttestationVerifyResponse {
                            attestation_result: token.as_str().to_string(),
                        };
                        Ok(Json(response))

                    }
                },
                RaArgs::AttestOnly(..) | RaArgs::NoRa => {
                    bail!("client attestation is not required")
                }
            }
        }
        .await
        .map_err(TngError::ServerVerifyClientEvidenceFailed)
    }
}
