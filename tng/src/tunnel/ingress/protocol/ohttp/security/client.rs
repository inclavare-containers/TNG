use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use bhttp::http_compat::{
    decode::{BhttpDecoder, HttpMessage},
    encode::BhttpEncoder,
};
use bytes::{BufMut, Bytes, BytesMut};
#[cfg(wasm)]
use futures::AsyncWriteExt as _;
use futures::{Stream, StreamExt, TryStreamExt as _};
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
#[cfg(wasm)]
use tokio_util::compat::{FuturesAsyncReadCompatExt as _, FuturesAsyncWriteCompatExt as _};
use tokio_util::{compat::TokioAsyncReadCompatExt as _, io::StreamReader};
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
    /// Headers to copy from the inner (plaintext) request to the outer OHTTP POST.
    #[allow(unused)]
    passthrough_request_headers: Arc<crate::config::header_passthrough::HeaderPassthroughSpec>,
    /// Headers to copy from the outer OHTTP response to the inner (plaintext) response.
    #[allow(unused)]
    passthrough_response_headers: Arc<crate::config::header_passthrough::HeaderPassthroughSpec>,
}

struct KeyStoreValue {
    /// The outer-POST metadata frame (big-endian length + prost-encoded
    /// Metadata) for this key generation. Both of its inputs - `client_auth`
    /// and the selected (first) server key config's public key - are fixed
    /// per store generation, so the frame is built once here instead of per
    /// request. `None` when the server returned an empty key-config list:
    /// the request path then reports the same
    /// `ClientSelectHpkeConfigurationFailed` as before.
    outer_metadata: Option<Bytes>,

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
        base_url: String,
        runtime: TokioRuntime,
        passthrough_request_headers: Arc<crate::config::header_passthrough::HeaderPassthroughSpec>,
        passthrough_response_headers: Arc<crate::config::header_passthrough::HeaderPassthroughSpec>,
    ) -> Result<Self> {
        // Parsed once per client, not per forwarded request. The error keeps
        // the context text the per-request parse produced before; the caller
        // in `security/mod.rs` maps it to `CreateOHttpClientFailed` as always.
        let base_url =
            url::Url::parse(&base_url).with_context(|| format!("Not a valid URL: {base_url}"))?;

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
            passthrough_response_headers,
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
                key_store_value.outer_metadata.as_ref(),
                key_store_value.client_key.as_ref(),
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

        let (server_key_config, server_attestation_result) = match self.ra_context.verify_context()
        {
            Some(verify_ctx @ VerifyContext::Passport { .. }) => {
                // Request hpke configuration for server
                let response = self
                    .get_hpke_configuration(KeyConfigRequest {
                        attestation_request: Some(AttestationRequest::Passport),
                    })
                    .await?;
                // Passport tokens are self-contained, so no AS challenge token is bound.
                let result = verify_keyconfig_attestation(&response, verify_ctx, None).await?;
                (response.hpke_key_config, Some(result))
            }
            Some(verify_ctx @ VerifyContext::BackgroundCheck { converter, .. }) => {
                // fetch a challenge token from attestation service
                let challenge_token = converter
                    .get_nonce()
                    .await
                    .with_context(|| {
                        format!(
                            "requesting challenge token from AS at {}",
                            converter.as_addr()
                        )
                    })
                    .map_err(TngError::ClientRequestKeyConfigFailed)?;

                // Request hpke configuration for server
                let response = self
                    .get_hpke_configuration(KeyConfigRequest {
                        attestation_request: Some(AttestationRequest::BackgroundCheck {
                            challenge_token: challenge_token.clone(),
                        }),
                    })
                    .await?;
                // Bind the freshly-fetched challenge token to prove freshness.
                let result =
                    verify_keyconfig_attestation(&response, verify_ctx, Some(challenge_token))
                        .await?;
                (response.hpke_key_config, Some(result))
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
        };

        expire = std::cmp::min(
            expire,
            Expire::from_timestamp(server_key_config.expire_timestamp)?,
        );

        let server_attestation_result = match server_attestation_result {
            Some(result) => {
                expire = std::cmp::min(
                    expire,
                    Expire::from_timestamp(
                        result
                            .exp()
                            .map_err(TngError::ClientRequestKeyConfigFailed)?,
                    )?,
                );
                Some(result)
            }
            None => None,
        };

        let server_key_config_list = KeyConfig::decode_list(
            BASE64_STANDARD
                .decode(server_key_config.encoded_key_config_list)?
                .as_ref(),
        )?;

        // Fixed inputs (client auth + the selected first key config's public
        // key), so the outer-POST metadata frame is built once per generation
        // rather than re-encoded per request. An empty list keeps the
        // request-time `ClientSelectHpkeConfigurationFailed` behavior.
        let outer_metadata = match server_key_config_list.first() {
            Some(key_config) => Some(Self::build_metadata_block(&client_auth, key_config)?),
            None => None,
        };

        Ok((
            KeyStoreValue {
                outer_metadata,
                client_key,
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
            .with_context(|| format!("POST key-config request to {}", self.base_url))
            .map_err(TngError::ClientRequestKeyConfigFailed)?
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

    /// Copy passthrough headers from the downstream request to the outer POST builder.
    /// Protocol headers (protected set, incl. content-type, x-tng-ohttp-api) are never copied.
    fn passthrough_headers<'a>(
        &'a self,
        request: &'a axum::extract::Request,
    ) -> Vec<(http::HeaderName, http::HeaderValue)> {
        let protected = crate::config::header_passthrough::protected_ohttp_headers();
        self.passthrough_request_headers
            .collect_passthrough_headers(request.headers(), protected)
    }

    /// Clients use the hpke_key_config obtained from Interface 1 to encrypt a standard HTTP request,
    /// and send the encrypted ciphertext as the request body to the server.
    ///
    /// Pipeline: select the HPKE encapsulator, seal the bhttp-encoded inner
    /// request into the outer POST body, send it, validate the outer
    /// response, then decapsulate and bhttp-decode the reply into the inner
    /// response.
    async fn send_encrypted_request(
        &self,
        server_key_config_list: &[KeyConfig],
        outer_metadata: Option<&Bytes>,
        client_key: Option<&(
            <X25519HkdfSha256 as Kem>::PrivateKey,
            <X25519HkdfSha256 as Kem>::PublicKey,
        )>,
        request: axum::extract::Request,
    ) -> Result<axum::response::Response, TngError> {
        // Extract passthrough headers before the request is consumed by BHttp encoding
        let passthrough_headers = self.passthrough_headers(&request);

        // Encode the request to bhttp message
        let bhttp_encoder = BhttpEncoder::from_request(request);

        // Select the server key config and build the HPKE request encapsulator
        let client = Self::build_request_encapsulator(server_key_config_list, client_key)?;

        // Seal stage: encrypt the bhttp stream into the ohttp envelope that
        // becomes the outer body, with a per-platform strategy because the
        // HTTP clients behave differently:
        //   wasm: `reqwest` on top of the browser `fetch` cannot stream a
        //     request body and task spawn is unreliable on the web, so the
        //     sealed request is fully buffered here and sent as one body.
        //   native: the seal runs inline in the outer body stream's poll: an
        //     always-ready sink keeps every seal write non-blocking, and
        //     sealed frames are pumped as reqwest pulls the body.
        // The ohttp seal writer and the response decapsulator are types from
        // ohttp's private stream module, so the decapsulator is created and
        // consumed within this scope.
        #[cfg(wasm)]
        let (client_response_decapsulator, ohttp_request_body) = {
            let mut encrypted_request = Vec::new();
            let client_request =
                client.encapsulate_stream(futures::io::Cursor::new(&mut encrypted_request))?;
            let client_response_decapsulator = client_request.response_decapsulator()?;

            // We have to avoid using spawn_supervised_task_current_span(), since it may randomly not got executed on wasm (web) and currently we have no idea why.
            //  streaming request is not supported, so we can just wait for the encryption to finish here.
            seal_request_into_buffer(client_request, bhttp_encoder)
                .await
                .unwrap_or_else(|error| tracing::error!(?error, "Error when encrypting request"));

            let metadata_buf = outer_metadata.cloned().ok_or_else(|| {
                TngError::ClientSelectHpkeConfigurationFailed(anyhow!("No key config found"))
            })?;
            let mut body_bytes = BytesMut::from(&metadata_buf[..]);
            body_bytes.extend_from_slice(&encrypted_request);
            tracing::debug!(
                body_length = body_bytes.len(),
                "Encrypted request body length"
            );
            (
                client_response_decapsulator,
                reqwest::Body::from(body_bytes.freeze()),
            )
        };
        #[cfg(not(wasm))]
        let (client_response_decapsulator, ohttp_request_body) = {
            // The seal runs synchronously inside the outer body stream's
            // poll (no task, no duplex): the always-ready sink keeps every
            // seal write non-blocking.
            let sink = crate::tunnel::ohttp::seal_stream::SealedBytesSink::new();
            let client_request = client.encapsulate_stream(sink.clone())?;
            let client_response_decapsulator = client_request.response_decapsulator()?;
            let metadata_buf = outer_metadata.cloned().ok_or_else(|| {
                TngError::ClientSelectHpkeConfigurationFailed(anyhow!("No key config found"))
            })?;
            let reader = bhttp_encoder
                .map_err(std::io::Error::other)
                .into_async_read();
            let body = crate::tunnel::ohttp::seal_stream::sealed_request_body(
                metadata_buf,
                reader,
                client_request,
                sink,
            );
            (
                client_response_decapsulator,
                reqwest::Body::wrap_stream(body),
            )
        };

        // Forward the sealed request to the upstream server
        let response = self
            .post_sealed_request(ohttp_request_body, passthrough_headers)
            .await?;

        // Validate the outer response and take the sealed body stream
        let (outer_passthrough, response_body) = self.validate_outer_response(response).await?;

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

        self.decode_inner_response(decrypted_response, outer_passthrough)
            .await
    }

    /// Select the server's first advertised key config and build the HPKE
    /// request encapsulator. (The metadata hint for the selected config is
    /// precomputed per key generation in `create_key_store_value`.)
    ///
    /// With an attested client key (native RA mode) the seal runs in HPKE
    /// Auth mode using that key, so the envelope's sender matches the `pk_s`
    /// advertised in the metadata and the egress can authenticate it.
    /// Without one -- and always on wasm, where the client has no attester --
    /// HPKE Base mode generates an ephemeral sender key.
    fn build_request_encapsulator(
        server_key_config_list: &[KeyConfig],
        client_key: Option<&(
            <X25519HkdfSha256 as Kem>::PrivateKey,
            <X25519HkdfSha256 as Kem>::PublicKey,
        )>,
    ) -> Result<ohttp::ClientRequest, TngError> {
        let mut key_config = server_key_config_list
            .first()
            .context("No key config found")
            .map_err(TngError::ClientSelectHpkeConfigurationFailed)?
            .clone();

        tracing::debug!(
            public_key = ?key_config.public_key(),
            "Encrypting request with HPKE key"
        );

        #[cfg(unix)]
        let client = match client_key {
            Some((sk, _pk)) => {
                let sk_bytes = hpke::Serializable::to_bytes(sk);
                ohttp::ClientRequest::from_config_with_client_key_bytes(
                    &mut key_config,
                    sk_bytes.as_ref(),
                )?
            }
            None => ohttp::ClientRequest::from_config(&mut key_config)?,
        };
        #[cfg(not(unix))]
        let client = {
            let _ = client_key; // unused on wasm
            ohttp::ClientRequest::from_config(&mut key_config)?
        };

        Ok(client)
    }

    /// Encode the metadata block that precedes the sealed request body: a
    /// big-endian `u32` prost length followed by that many prost bytes. The
    /// egress parses the same block in its `read_metadata_block`.
    ///
    /// Both inputs are fixed per key-store generation, so `create_key_store_value`
    /// encodes this once and each request only refcount-clones the result.
    fn build_metadata_block(
        client_auth: &ClientAuth,
        key_config: &KeyConfig,
    ) -> Result<Bytes, TngError> {
        let metadata = Metadata {
            client_auth: Some(client_auth.clone()),
            key_config_hint: Some(ServerKeyConfigHint {
                public_key: key_config.public_key()?.into_vec(),
            }),
        };

        let metadata_len = metadata.encoded_len();
        if metadata_len > METADATA_MAX_LEN {
            return Err(TngError::MetadataTooLong);
        }
        let mut metadata_buf = BytesMut::new();
        metadata_buf.put_u32(u32::try_from(metadata_len).map_err(|_| TngError::MetadataTooLong)?); // big-endian
        metadata_buf.reserve(metadata_len); // to prevent reallocations during encoding
        metadata
            .encode(&mut metadata_buf)
            .map_err(TngError::MetadataEncodeError)?;
        tracing::trace!(metadata_length = metadata_buf.len(), "metadata length");
        Ok(metadata_buf.freeze())
    }

    /// Validate the outer POST response and hand back what the decapsulate
    /// stage needs: the configured passthrough pairs selected from the outer
    /// response headers (collected by reference before the body is taken) and
    /// the outer body stream of sealed bytes.
    /// A `422` maps to `ShouldRequestNewKeyConfigFromServerError` so the
    /// caller invalidates the cached key config and refetches on the next
    /// request.
    async fn validate_outer_response(
        &self,
        response: reqwest::Response,
    ) -> Result<
        (
            Vec<(http::HeaderName, http::HeaderValue)>,
            impl Stream<Item = Result<Bytes, reqwest::Error>>,
        ),
        TngError,
    > {
        // Check the response status code
        let status_code = response.status();
        #[cfg(unix)]
        let content_len = response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());
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

        // Select the configured outer response headers (outer -> inner) before
        // bytes_stream() consumes the reqwest::Response. Only the chosen pairs
        // are taken; the whole-HeaderMap clone existed just to outlive the
        // stream handoff.
        let outer_passthrough = self
            .passthrough_response_headers
            .collect_passthrough_headers(
                response.headers(),
                crate::config::header_passthrough::protected_ohttp_headers(),
            );

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

        Ok((outer_passthrough, response_body))
    }

    /// Decode stage: bhttp-decode the decrypted inner response, copy the
    /// configured passthrough headers (outer -> inner, collected by
    /// `validate_outer_response`) onto it, and hand it to the downstream
    /// caller.
    async fn decode_inner_response<R>(
        &self,
        decrypted_body: R,
        outer_passthrough: Vec<(http::HeaderName, http::HeaderValue)>,
    ) -> Result<axum::response::Response, TngError>
    where
        R: futures::AsyncRead + Unpin + Send + 'static,
    {
        let decode_result = BhttpDecoder::new(decrypted_body)
            .decode_message()
            .await
            .map_err(|e| {
                tracing::error!(
                    error = ?e,
                    "BHTTP decoding of decrypted response failed"
                );
                e
            })?;

        let HttpMessage::Response(mut response) = decode_result.into_full_message()? else {
            return Err(TngError::InvalidHttpResponse);
        };

        // Copy the configured outer response headers (outer -> inner),
        // collected by `validate_outer_response` before the body stream was
        // taken, onto the decrypted response returned to the caller.
        let inner_headers = response.headers_mut();
        for (name, value) in outer_passthrough {
            inner_headers.insert(name, value);
        }

        let response = {
            let (head, body) = response.into_parts();
            // Log only the status; the full head carries upstream response headers
            // (e.g. Set-Cookie, Authorization) which are plaintext application data.
            tracing::debug!(
                status = %head.status,
                "Decrypted response from upstream server"
            );
            http::Response::from_parts(head, body)
        };

        Ok(axum::response::IntoResponse::into_response(response))
    }

    /// Send stage: POST the sealed envelope to the egress. The outer request
    /// carries the tunnel API header, the streaming ohttp request content
    /// type, and the passthrough headers collected from the inner request.
    async fn post_sealed_request(
        &self,
        ohttp_request_body: reqwest::Body,
        passthrough_headers: Vec<(http::HeaderName, http::HeaderValue)>,
    ) -> Result<reqwest::Response, TngError> {
        let url = self.base_url.clone();

        tracing::debug!(?url, "Sending OHTTP request to upstream server");

        let mut request_builder = self
            .http_client
            .post(url)
            .header(OhttpApi::HEADER_NAME, OhttpApi::TUNNEL)
            .header(
                http::header::CONTENT_TYPE,
                OHTTP_CHUNKED_REQUEST_CONTENT_TYPE,
            );

        for (name, value) in passthrough_headers {
            request_builder = request_builder.header(name, value);
        }

        let response = request_builder
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

        Ok(response)
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

/// wasm seal strategy: drive the bhttp-encoded inner request through the
/// seal writer (an ohttp stream encapsulator over the caller's buffer) until
/// EOF, then close the seal so it emits its final chunk. The caller awaits
/// this inline: web task spawn is unreliable and `fetch` cannot stream a
/// request body, so the whole sealed request must be in the buffer before
/// the POST goes out.
#[cfg(wasm)]
async fn seal_request_into_buffer<W>(
    seal: W,
    bhttp_encoder: BhttpEncoder<axum::body::Body>,
) -> Result<(), anyhow::Error>
where
    W: futures::AsyncWrite + Unpin,
{
    let mut client_request = seal.compat_write();
    // BufReader at the protocol's 16 KiB max chunk + copy_buf
    // so each seal write carries up to one full AEAD chunk and
    // skips copy's intermediate 8 KiB buffer copy;
    // tokio::io::copy would cap chunks at 8 KiB.
    let mut bhttp_reader = tokio::io::BufReader::with_capacity(
        crate::tunnel::ohttp::SEAL_CHUNK_SIZE,
        bhttp_encoder
            .map_err(std::io::Error::other)
            .into_async_read()
            .compat(),
    );
    let bytes_copied = tokio::io::copy_buf(&mut bhttp_reader, &mut client_request).await?;
    tracing::debug!(bytes_copied, "BHTTP request encoded and encrypted");
    let mut client_request = client_request.into_inner();
    client_request.close().await?; // Remember to close the response stream

    Ok(())
}

/// Verify the attestation bound to an ohttp `KeyConfigResponse` against a
/// pre-built `VerifyContext`. This is the single shared attestation-verification
/// half for the ohttp key config: the live ingress client
/// ([`OHttpClientInner::create_key_store_value`]) and the `ohttp verify`
/// operator tool both call it on an already-fetched `KeyConfigResponse`
/// (the ingress path on a live fetch, the tool on a dumped JSON file) so the
/// `ServerAttestationInfo` dispatch + `verify_evidence`/`convert` calls live in
/// exactly one place.
///
/// `resp.hpke_key_config` is bound into the report_data claims, so a token
/// whose runtime_data does not cover the server's HPKE key config is rejected
/// (subset check inside the verifier). `challenge_token` is the AS challenge
/// token to bind into those claims: the live ingress path passes the token it
/// just obtained from the AS to prove freshness (`Some` for the background-check
/// model; `None` for passport, whose token is self-contained), while the verify
/// tool passes `None` because a dumped file carries no such token. The
/// verifier's report_data check is subset-based, so omitting `challenge_token`
/// still validates the hpke_key_config binding, which is the meaningful check
/// for a dumped artifact.
pub(crate) async fn verify_keyconfig_attestation(
    resp: &KeyConfigResponse,
    verify_ctx: &VerifyContext,
    challenge_token: Option<String>,
) -> Result<AttestationResult, TngError> {
    let info = resp.attestation_info.as_ref().ok_or_else(|| {
        TngError::ClientRequestKeyConfigFailed(anyhow!("ohttp key config has no attestation_info"))
    })?;

    let token = match verify_ctx {
        VerifyContext::Passport { verifier } => {
            let ServerAttestationInfo::Passport {
                attestation_result,
                as_provider,
            } = info
            else {
                return Err(TngError::ClientRequestKeyConfigFailed(anyhow!(
                    "Passport model is expected but got background check attestation from server"
                )));
            };
            let token = TngToken::from_wire(
                ProviderType::from_optional_wire(*as_provider),
                attestation_result.clone(),
            )
            .map_err(TngError::TngTokenDecodeError)?;
            // The challenge_token is not checked here; it is already checked by
            // the attestation service, so it is omitted from the claims.
            let userdata = ServerUserData {
                challenge_token: None,
                hpke_key_config: resp.hpke_key_config.clone(),
            }
            .to_claims()
            .map_err(TngError::ClaimsEncodeError)?;
            verifier
                .verify_evidence(&token, &ReportData::Claims(userdata))
                .await
                .map_err(TngError::EvidenceVerifyError)?;
            token
        }
        VerifyContext::BackgroundCheck {
            converter,
            verifier,
        } => {
            let ServerAttestationInfo::BackgroundCheck {
                evidence,
                aa_provider,
            } = info
            else {
                return Err(TngError::ClientRequestKeyConfigFailed(anyhow!(
                    "Background check model is expected but got passport attestation from server"
                )));
            };
            let userdata = ServerUserData {
                challenge_token,
                hpke_key_config: resp.hpke_key_config.clone(),
            }
            .to_claims()
            .map_err(TngError::ClaimsEncodeError)?;
            let evidence = TngEvidence::deserialize_from_json(
                ProviderType::from_optional_wire(*aa_provider),
                evidence.clone(),
            )
            .map_err(TngError::TngEvidenceDecodeError)?;
            let token = converter
                .convert(&evidence)
                .await
                .map_err(TngError::EvidenceVerifyError)?;
            verifier
                .verify_evidence(&token, &ReportData::Claims(userdata))
                .await
                .map_err(TngError::EvidenceVerifyError)?;
            token
        }
    };

    Ok(AttestationResult::from_token(token))
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

    /// A dumped key config with no `attestation_info` (e.g. a no_ra dump) must
    /// be rejected up front, before the `VerifyContext` is touched. Uses a
    /// Passport verifier built with `skip_as_token_cert_verify` so no AS/cert
    /// file is contacted to construct the context.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_keyconfig_attestation_errors_when_no_attestation_info() {
        use crate::config::ra::{CocoVerifierArgs, VerifierArgs, VerifyArgs};
        use crate::tunnel::ohttp::protocol::HpkeKeyConfig;
        use std::collections::HashMap;

        let verify_args = VerifyArgs::Passport {
            verifier: VerifierArgs::Coco(CocoVerifierArgs::Restful {
                as_addr: None,
                policy_ids: vec!["default".to_string()],
                as_headers: HashMap::new(),
                #[cfg(not(wasm))]
                trusted_certs_paths: None,
                verify_signer_transparency: false,
                skip_as_token_cert_verify: true,
            }),
        };
        let verify_ctx = VerifyContext::from_verify_args(&verify_args)
            .await
            .expect("build skip-verify Passport context without AS");

        let resp = KeyConfigResponse {
            hpke_key_config: HpkeKeyConfig {
                expire_timestamp: 0,
                encoded_key_config_list: String::new(),
            },
            attestation_info: None,
        };

        let err = verify_keyconfig_attestation(&resp, &verify_ctx, None)
            .await
            .expect_err("no-attestation_info response should error");
        // The helper returns a typed TngError; format its full source chain
        // (variant message + cause) the same way IntoResponse does, so the
        // attestation_info-missing reason is visible in the assertion text.
        let msg = format!("{:#}", anyhow::Error::new(err));
        assert!(
            msg.contains("no attestation_info"),
            "expected 'no attestation_info' error, got: {msg}"
        );
    }
}
