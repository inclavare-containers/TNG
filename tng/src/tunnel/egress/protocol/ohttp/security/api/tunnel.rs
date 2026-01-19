use anyhow::{anyhow, bail, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use bhttp::http_compat::decode::{BhttpDecoder, HttpMessage};
use bhttp::http_compat::encode::BhttpEncoder;
use bytes::BytesMut;
use futures::{AsyncWriteExt, StreamExt as _, TryStreamExt as _};
use prost::Message as _;
use rats_cert::tee::coco::evidence::CocoAsToken;
use rats_cert::tee::coco::verifier::CocoVerifier;
use rats_cert::tee::{GenericVerifier as _, ReportData};
use tokio::io::AsyncReadExt;
use tokio_util::compat::FuturesAsyncReadCompatExt as _;
use tokio_util::compat::FuturesAsyncWriteCompatExt as _;
use tokio_util::compat::TokioAsyncReadCompatExt as _;
use tokio_util::io::ReaderStream;

use crate::config::ra::{
    AttestationServiceArgs, AttestationServiceTokenVerifyAdditionalArgs,
    AttestationServiceTokenVerifyArgs, RaArgs, VerifyArgs,
};
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::egress::protocol::ohttp::security::context::TngStreamContext;
use crate::tunnel::ohttp::key_config::PublicKeyData;
use crate::tunnel::ohttp::protocol::header::{
    OHTTP_CHUNKED_REQUEST_CONTENT_TYPE, OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE,
};
use crate::tunnel::ohttp::protocol::metadata::metadata::ClientAuth;
use crate::tunnel::ohttp::protocol::metadata::{
    AttestedPublicKey, Metadata, NoAuth, METADATA_MAX_LEN,
};
use crate::tunnel::ohttp::protocol::userdata::ClientUserData;

impl OhttpServerApi {
    /// Interface 2: Process Encrypted Request
    /// x-tng-ohttp-api: /tng/tunnel (or user specified path via path_rewrites)
    ///
    /// Clients use the hpke_key_config obtained from Interface 1 to encrypt a standard HTTP request,
    /// and send the encrypted ciphertext as the request body to the server. The server decrypts and processes
    /// the request, then encrypts the HTTP response and returns it.
    pub async fn process_encrypted_request(
        &self,
        payload: axum::extract::Request,
        context: TngStreamContext,
    ) -> Result<axum::response::Response, TngError> {
        // Check content-type
        match payload.headers().get(http::header::CONTENT_TYPE) {
            Some(value) => {
                if value != OHTTP_CHUNKED_REQUEST_CONTENT_TYPE {
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

        let mut reader = tokio_util::io::StreamReader::new(
            payload
                .into_body()
                .into_data_stream()
                .map(|result| result.map_err(std::io::Error::other)),
        );

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

            let mut buf = BytesMut::with_capacity(metadata_len);

            while buf.len() < metadata_len {
                reader
                    .read_buf(&mut buf)
                    .await
                    .map_err(TngError::MetadataReadError)?;
            }

            Metadata::decode(buf.as_ref()).map_err(TngError::MetadataDecodeError)?
        };

        let header_decoded = ohttp::Server::decode_header(reader.compat()).await?;

        tracing::debug!(
            ?metadata,
            key_id = header_decoded.key_id(),
            "Received OHTTP request"
        );

        // Check metadata
        self.validate_client_attestation_consistency(metadata.client_auth)
            .await
            .map_err(TngError::MetadataValidateError)?;

        let key_info = if let Some(hint) = metadata.key_config_hint {
            // Get key by hint
            self.key_manager
                .get_key_by_public_key_data(&PublicKeyData::new(hint.public_key))
                .await?
        } else {
            // Check key id, this make it compatible with old tng clients versions
            self.key_manager
                .get_fist_key_by_key_id(header_decoded.key_id())
                .await?
        };

        // Decrypt the ohttp message
        let plain_text = header_decoded.into_server_request(key_info.key_config);

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
        let response = context.forward_request(request, None).await?;

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
            context.runtime.spawn_supervised_task_current_span(async {
                async {
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
                }
                .await
                .unwrap_or_else(|error| tracing::error!(?error, "Error when encrypting response"))
            });

            response_read
        };

        // Return the response
        let response = http::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(
                http::header::CONTENT_TYPE,
                OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE,
            )
            .body(axum::body::Body::from_stream(ReaderStream::new(
                encrypted_response,
            )))
            .map_err(TngError::ConstructHttpResponseFailed)?;

        Ok(response)
    }

    /// Validates that the provided client metadata type is consistent with the server's
    /// remote attestation (RA) configuration.
    async fn validate_client_attestation_consistency(
        &self,
        client_auth: Option<ClientAuth>,
    ) -> Result<()> {
        match (client_auth, self.ra_args.as_ref()) {
            (
                Some(ClientAuth::AttestedPublicKey(AttestedPublicKey {
                    attestation_result,
                    pk_s,
                })),
                RaArgs::VerifyOnly(verify) | RaArgs::AttestAndVerify(.., verify),
            ) => {
                let verifier = match verify {
                    VerifyArgs::Passport {
                        token_verify:
                            AttestationServiceTokenVerifyArgs {
                                policy_ids,
                                trusted_certs_paths,
                                as_addr,
                            },
                    } => CocoVerifier::new(as_addr, trusted_certs_paths, policy_ids).await?,
                    VerifyArgs::BackgroundCheck {
                        as_args:
                            AttestationServiceArgs {
                                as_addr,
                                policy_ids,
                                ..
                            },
                        token_verify:
                            AttestationServiceTokenVerifyAdditionalArgs {
                                trusted_certs_paths,
                            },
                    } => {
                        CocoVerifier::new(&Some(as_addr.clone()), trusted_certs_paths, policy_ids)
                            .await?
                    }
                };

                let token = CocoAsToken::new(attestation_result)?;

                let userdata = ClientUserData {
                    // The challenge_token is not required to be check here, since it is already checked by attestation service. So that we skip the comparesion of challenge_token here.
                    challenge_token: None,
                    pk_s: BASE64_STANDARD.encode(&pk_s),
                }
                .to_claims()?;

                verifier
                    .verify_evidence(&token, &ReportData::Claims(userdata))
                    .await?;
            }
            (Some(ClientAuth::NoAuth(NoAuth {})), RaArgs::AttestOnly(..) | RaArgs::NoRa) => {
                // Peace and love
            }
            (
                Some(ClientAuth::NoAuth(NoAuth {})),
                RaArgs::VerifyOnly(..) | RaArgs::AttestAndVerify(..),
            ) => {
                bail!(
                    "client attestation is required but no attestation info was provided by client"
                )
            }
            (Some(ClientAuth::AttestedPublicKey(..)), RaArgs::AttestOnly(..) | RaArgs::NoRa) => {
                bail!("client attestation is not required but some attestation info ware provided by client")
            }
            (None, _) => {
                bail!("client_auth is empty")
            }
        }

        Ok(())
    }
}
