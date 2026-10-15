use anyhow::{anyhow, bail, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use bhttp::http_compat::decode::{BhttpDecoder, HttpMessage};
use bhttp::http_compat::encode::BhttpEncoder;
use bytes::{Bytes, BytesMut};
use futures::{AsyncRead, AsyncWrite, Stream, StreamExt as _, TryStreamExt as _};
use prost::Message as _;
use rats_cert::tee::{GenericVerifier as _, ReportData};

use crate::tunnel::provider::{ProviderType, TngToken};
use tokio::io::AsyncReadExt;
use tokio_util::compat::TokioAsyncReadCompatExt as _;

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
use crate::tunnel::ra_context::VerifyContext;

impl OhttpServerApi {
    /// Interface 2: Process Encrypted Request
    /// x-tng-ohttp-api: /tng/tunnel (or user specified path via path_rewrites)
    ///
    /// Clients use the hpke_key_config obtained from Interface 1 to encrypt a standard HTTP request,
    /// and send the encrypted ciphertext as the request body to the server. The server decrypts and processes
    /// the request, then encrypts the HTTP response and returns it.
    ///
    /// Pipeline: parse the metadata block, decapsulate the sealed inner
    /// request, rewrite its headers, forward it to the backend, then seal
    /// the backend response into the outer ohttp body.
    pub async fn process_encrypted_request(
        &self,
        payload: axum::extract::Request,
        context: TngStreamContext,
    ) -> Result<axum::response::Response, TngError> {
        check_request_content_type(payload.headers())?;

        // Capture outer request headers (e.g. the browser's `Origin`) before the
        // body is consumed. These are copied onto the decrypted inner request so
        // the upstream backend can make its own CORS decision. `Origin` is a
        // forbidden header set by the browser on the outer fetch; only the egress
        // server (which terminates the outer HTTP) can see it.
        let outer_request_headers = payload.headers().clone();

        let mut reader = tokio_util::io::StreamReader::new(
            payload
                .into_body()
                .into_data_stream()
                .map(|result| result.map_err(std::io::Error::other)),
        );

        // Parse stage: read and decode metadata
        let metadata = read_metadata_block(&mut reader).await?;

        // Decapsulate stage: open the sealed inner request and open the
        // response seal bound to this request's HPKE context.
        let (mut request, response_seal, sealed_sink) =
            self.decapsulate_request(reader.compat(), metadata).await?;

        // Rewrite stage: copy the configured outer request headers onto the
        // inner request and annotate it with the relay peer's client IP.
        self.rewrite_inner_request_headers(&mut request, &outer_request_headers, context.peer_addr);

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

        // Collect passthrough headers before the response is consumed by BhttpEncoder.
        // Uses the unified HeaderPassthroughSpec (`"all"` or allowlist) and the
        // shared protected set. Inner (backend) response → outer (browser) response.
        let protected = crate::config::header_passthrough::protected_ohttp_headers();
        let passthrough_headers = self
            .passthrough_response_headers
            .collect_passthrough_headers(response.headers(), protected);

        // Seal stage: encrypt the bhttp-encoded response into the outer body.
        let encrypted_response = seal_bhttp_response(response, response_seal, sealed_sink);

        // Return the response
        let mut response_builder = http::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(
                http::header::CONTENT_TYPE,
                OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE,
            );

        for (name, value) in passthrough_headers {
            response_builder = response_builder.header(name, value);
        }

        let response = response_builder
            .body(axum::body::Body::from_stream(encrypted_response))
            .map_err(TngError::ConstructHttpResponseFailed)?;

        Ok(response)
    }

    /// Decapsulate stage: decode the ohttp request header, check the client
    /// attestation carried in the metadata against this server's RA config,
    /// open the envelope with the hinted HPKE key, and bhttp-decode the
    /// plaintext into the inner request. It also opens the response seal:
    /// the ohttp response must encrypt under the same HPKE context the
    /// request opened, so this returns the inner request, its seal writer,
    /// and the sink that collects the sealed response bytes.
    ///
    /// The plaintext reader (`ServerRequest`) and the response seal
    /// (`ServerResponse`) are types in ohttp's private stream module, so
    /// they leave this function only as opaque `impl Trait` values: they are
    /// handed to the bhttp decoder and the seal pump, which accept them
    /// generically. Nothing that cannot be named here crosses the boundary.
    async fn decapsulate_request<S>(
        &self,
        sealed_body: S,
        metadata: Metadata,
    ) -> Result<
        (
            http::Request<
                impl http_body::Body<Data = Bytes, Error = bhttp::Error> + Send + 'static,
            >,
            impl AsyncWrite + Send + 'static,
            crate::tunnel::ohttp::seal_stream::SealedBytesSink,
        ),
        TngError,
    >
    where
        S: AsyncRead + Unpin + Send + 'static,
    {
        let header_decoded = ohttp::Server::decode_header(sealed_body)
            .await
            .map_err(|e| {
                tracing::error!(
                    ?e,
                    "OHTTP decode_header failed (client ciphertext may be malformed or truncated)"
                );
                e
            })?;

        tracing::debug!(
            ?metadata,
            key_id = header_decoded.key_id(),
            "Received OHTTP request"
        );

        // Extract client public key before validation moves client_auth
        let client_pk_bytes = match &metadata.client_auth {
            Some(ClientAuth::AttestedPublicKey(AttestedPublicKey { pk_s, .. })) => {
                Some(pk_s.clone())
            }
            _ => None,
        };

        // Check metadata
        self.validate_client_attestation_consistency(metadata.client_auth)
            .await
            .map_err(TngError::MetadataValidateError)?;

        let key_info = if let Some(hint) = metadata.key_config_hint {
            // Get key by hint
            self.key_manager
                .get_key_by_public_key(&PublicKeyData::new(hint.public_key))
                .await?
        } else {
            return Err(TngError::ServerKeyConfigHintNotSpecified);
        };

        // Decrypt the ohttp message
        let plain_text = match client_pk_bytes {
            Some(pk_s) => {
                // Use Auth mode: server verifies client identity via HPKE Auth
                let client_pk = ohttp::PublicKey::from_x25519_bytes(&pk_s).map_err(|e| {
                    TngError::ClientRequestKeyConfigFailed(
                        anyhow::Error::from(e).context("Failed to construct client public key"),
                    )
                })?;
                header_decoded.into_server_request_with_client_pk(key_info.key_config, client_pk)
            }
            None => {
                // Base mode: no client authentication
                header_decoded.into_server_request(key_info.key_config)
            }
        };

        // Decode the bhttp binary message
        let decode_result = BhttpDecoder::new(plain_text).decode_message().await?;
        let server_response_encapsulator = decode_result.reader_ref().response_encapsulator()?;
        let HttpMessage::Request(request) = decode_result.into_full_message()? else {
            return Err(TngError::InvalidHttpRequest);
        };

        let sink = crate::tunnel::ohttp::seal_stream::SealedBytesSink::new();
        let response_seal = server_response_encapsulator.encapsulate_response(sink.clone())?;

        Ok((request, response_seal, sink))
    }

    /// Rewrite stage: copy the configured passthrough headers from the outer
    /// request onto the decrypted inner request and inject the
    /// forwarded-client-IP headers, before the request goes to the backend.
    fn rewrite_inner_request_headers<B>(
        &self,
        request: &mut http::Request<B>,
        outer_request_headers: &http::HeaderMap,
        peer_addr: Option<std::net::SocketAddr>,
    ) {
        let protected = crate::config::header_passthrough::protected_ohttp_headers();
        let outer_passthrough = self
            .passthrough_request_headers
            .collect_passthrough_headers(outer_request_headers, protected);
        let inner_headers = request.headers_mut();
        for (name, value) in outer_passthrough {
            // `insert` replaces any existing inner value; protected headers are
            // already excluded by `collect_passthrough_headers`.
            inner_headers.insert(name, value);
        }

        // The direct TCP peer (the relay) is reported so the upstream
        // backend can see which relay forwarded this request. No-op when
        // disabled or peer unknown.
        inject_forwarded_client_ip(request.headers_mut(), peer_addr, self.forward_client_ip);
    }

    /// Validates that the provided client metadata type is consistent with the server's
    /// remote attestation (RA) configuration.
    async fn validate_client_attestation_consistency(
        &self,
        client_auth: Option<ClientAuth>,
    ) -> Result<()> {
        match (client_auth, self.ra_context.verify_context()) {
            (
                Some(ClientAuth::AttestedPublicKey(AttestedPublicKey {
                    attestation_result,
                    pk_s,
                    as_provider,
                })),
                Some(verify_ctx),
            ) => {
                match verify_ctx {
                    VerifyContext::Passport { verifier }
                    | VerifyContext::BackgroundCheck { verifier, .. } => {
                        let provider = ProviderType::from_optional_wire_str(&as_provider)?;
                        let token =
                            TngToken::deserialize_from_wire_str(provider, &attestation_result)?;

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
                }
            }
            (Some(ClientAuth::NoAuth(NoAuth {})), None) => {
                // Peace and love - no attestation required and client didn't provide any
            }
            (Some(ClientAuth::NoAuth(NoAuth {})), Some(_)) => {
                bail!(
                    "client attestation is required but no attestation info was provided by client"
                )
            }
            (Some(ClientAuth::AttestedPublicKey(..)), None) => {
                bail!("client attestation is not required but some attestation info ware provided by client")
            }
            (None, _) => {
                bail!("client_auth is empty")
            }
        }

        Ok(())
    }
}

/// Front gate: the outer POST must carry the streaming ohttp request
/// content type, matching what the ingress `post_sealed_request` sends.
fn check_request_content_type(headers: &http::HeaderMap) -> Result<(), TngError> {
    match headers.get(http::header::CONTENT_TYPE) {
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
    Ok(())
}

/// Parse stage: read the metadata block that prefixes the sealed body: a
/// big-endian `u32` prost length followed by that many prost bytes, the
/// mirror of the ingress `build_metadata_block`. `METADATA_MAX_LEN` caps the
/// client-supplied length before the read buffer is reserved.
async fn read_metadata_block<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Metadata, TngError> {
    let metadata_len = reader
        .read_u32() // big-endian
        .await
        .map_err(TngError::MetadataReadError)?;

    let metadata_len = usize::try_from(metadata_len).map_err(|_| TngError::MetadataTooLong)?;

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

    Metadata::decode(buf.as_ref()).map_err(TngError::MetadataDecodeError)
}

/// Seal stage: bhttp-encode the backend response and pump it through the
/// request's ohttp seal (`response_seal` writing into `sink`) into the
/// sealed outer response body. The seal runs synchronously inside the
/// response body stream's poll (no task, no pipe): the always-ready sink
/// keeps the seal's writes non-blocking, so bhttp-encode and seal happen per
/// frame on the serving worker.
fn seal_bhttp_response<W: AsyncWrite + Send + 'static>(
    response: axum::response::Response,
    response_seal: W,
    sink: crate::tunnel::ohttp::seal_stream::SealedBytesSink,
) -> impl Stream<Item = std::io::Result<Bytes>> + Send + 'static {
    let bhttp_reader = BhttpEncoder::from_response(response)
        .map_err(std::io::Error::other)
        .into_async_read();
    crate::tunnel::ohttp::seal_stream::sealed_response_body(bhttp_reader, response_seal, sink)
}

/// Inject nginx-standard forwarded-client-IP headers onto the decrypted
/// inner request headers, using the egress's direct TCP peer. `X-Real-IP`
/// is set/overwritten; `X-Forwarded-For` appends the peer to any existing
/// chain (nginx `$proxy_add_x_forwarded_for`). No-op when disabled or when
/// the peer is unknown (e.g. unix socket).
fn inject_forwarded_client_ip(
    headers: &mut http::HeaderMap,
    peer: Option<std::net::SocketAddr>,
    enabled: bool,
) {
    if !enabled {
        return;
    }
    let Some(peer) = peer else {
        return;
    };
    let peer_ip = peer.ip().to_string();

    if let Ok(v) = http::HeaderValue::from_str(&peer_ip) {
        headers.insert(http::HeaderName::from_static("x-real-ip"), v);
    }
    let new_xff = match headers.get("x-forwarded-for") {
        Some(existing) => match existing.to_str() {
            Ok(s) => format!("{s}, {peer_ip}"),
            Err(_) => peer_ip.clone(),
        },
        None => peer_ip,
    };
    if let Ok(v) = http::HeaderValue::from_str(&new_xff) {
        headers.insert(http::HeaderName::from_static("x-forwarded-for"), v);
    }
}

#[cfg(test)]
mod forwarded_client_ip_tests {
    use super::inject_forwarded_client_ip;
    use http::HeaderMap;
    use std::net::{Ipv4Addr, SocketAddr};

    fn peer() -> Option<SocketAddr> {
        Some(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443)))
    }

    #[test]
    fn disabled_is_noop() {
        let mut h = HeaderMap::new();
        inject_forwarded_client_ip(&mut h, peer(), false);
        assert!(h.get("x-real-ip").is_none());
        assert!(h.get("x-forwarded-for").is_none());
    }

    #[test]
    fn no_peer_is_noop() {
        let mut h = HeaderMap::new();
        inject_forwarded_client_ip(&mut h, None, true);
        assert!(h.get("x-real-ip").is_none());
        assert!(h.get("x-forwarded-for").is_none());
    }

    #[test]
    fn sets_real_ip_and_xff_when_absent() {
        let mut h = HeaderMap::new();
        inject_forwarded_client_ip(&mut h, peer(), true);
        assert_eq!(h.get("x-real-ip").unwrap().to_str().unwrap(), "203.0.113.7");
        assert_eq!(
            h.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "203.0.113.7"
        );
    }

    #[test]
    fn appends_to_existing_xff() {
        let mut h = HeaderMap::new();
        h.insert(
            http::HeaderName::from_static("x-forwarded-for"),
            http::HeaderValue::from_static("198.51.100.1"),
        );
        inject_forwarded_client_ip(&mut h, peer(), true);
        assert_eq!(
            h.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "198.51.100.1, 203.0.113.7"
        );
        assert_eq!(h.get("x-real-ip").unwrap().to_str().unwrap(), "203.0.113.7");
    }
}
