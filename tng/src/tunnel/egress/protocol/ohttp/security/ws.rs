use std::sync::Arc;

use anyhow::{anyhow, Context as _, Result};
use async_tungstenite::tungstenite::protocol::Role;
use async_tungstenite::tungstenite::Message;
use async_tungstenite::{tokio::TokioAdapter, WebSocketStream};
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::{SinkExt, StreamExt};
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadHalf, WriteHalf,
};
use tokio_util::sync::CancellationToken;

use crate::error::{ErrorResponse, TngError};
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::egress::protocol::ohttp::security::context::TngStreamContext;
use crate::tunnel::ohttp::protocol::header::is_websocket_upgrade;
use crate::tunnel::ohttp::protocol::ws::{
    has_tng_marker, strip_tng_marker, ws_relay_request_headers, ws_relay_response_headers,
    TNG_WS_NEGOTIATION_TIMEOUT,
};
use crate::TokioRuntime;

/// Ingress-side hop of the middle relay (the TNG-to-TNG WebSocket). The 101
/// answered here is the backend's, so the connection is adopted post-handshake:
/// hyper hands the io over as `Upgraded`, and TokioIo/TokioAdapter re-skin it
/// into the traits async-tungstenite drives. Binary messages carry one sealed
/// chunk record each.
type IngressHop = WebSocketStream<TokioAdapter<TokioIo<hyper::upgrade::Upgraded>>>;

/// Backend frame pipe: the raw upgraded connection the egress hands the backend
/// after relaying the handshake. The WebSocket frames the app and backend
/// exchange are opaque bytes to TNG, so this hop is a plain byte pipe, never a
/// frame parser. It arrives split into tokio read/write halves.
type BackendRead = ReadHalf<TokioIo<hyper::upgrade::Upgraded>>;
type BackendWrite = WriteHalf<TokioIo<hyper::upgrade::Upgraded>>;

/// True when the request is a TNG ws tunnel upgrade: a WebSocket upgrade
/// whose subprotocol offer carries the marker. The marker is the tunnel's
/// single dispatch signal (checked in `server.rs` ahead of the
/// `x-tng-ohttp-api` dispatch) because a browser in the client role cannot
/// set custom handshake headers; the native ingress adds the marker when it
/// relays, so both client-role forms share one path.
pub fn is_ws_tunnel_upgrade<B>(req: &http::Request<B>) -> bool {
    is_websocket_upgrade(req)
        && req
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .map(has_tng_marker)
            .unwrap_or(false)
}

/// Serve a WebSocket upgrade as an encrypted tunnel to the backend the ingress
/// connection dials (the capture-mode mapped out address, never the request's
/// `Host`). The handshake is a relay: the ingress's key and version flow on to
/// the backend and the backend's 101 comes back verbatim. Until the protocol
/// switches every failure is a plain HTTP error; afterwards the session runs in
/// its own task and only logs.
pub async fn handle_ws_tunnel(
    api: Arc<OhttpServerApi>,
    context: TngStreamContext,
    req: Request,
) -> Response {
    // Dispatch already matched these; re-check the cheap parts so the
    // handler cannot be driven into a malformed relay by a future caller.
    if !is_websocket_upgrade(&req) {
        return reject(StatusCode::BAD_REQUEST, TngError::InvalidHttpRequest);
    }
    // The relayed key and version must exist for the backend to answer a
    // handshake the app can verify (and so the request line is well formed).
    for required in [header::SEC_WEBSOCKET_KEY, header::SEC_WEBSOCKET_VERSION] {
        if !req.headers().contains_key(required) {
            return reject(StatusCode::BAD_REQUEST, TngError::InvalidHttpRequest);
        }
    }
    // Strip the dispatch marker before the backend sees the offer list; a list
    // that was only the marker becomes no offer at all.
    let relayed_protocols = req
        .headers()
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(strip_tng_marker);

    // Build the backend handshake request while the relayed request is still a
    // plain borrow: its body type is not Sync, so a reference to the whole
    // Request must not exist across the dial below's await points. The request
    // line and `Host` are preserved as data (the backend vhosts on them); the
    // backend itself is reached through the connection's UpstreamConnector.
    let handshake_request = match build_backend_request(&req, relayed_protocols) {
        Ok(request) => request,
        Err(err) => return err.into_response(),
    };

    // Take the upgrade future before the request is consumed any further;
    // hyper delivers the raw ingress connection once the 101 below goes out.
    let mut req = req;
    let upgraded = hyper::upgrade::on(&mut req);

    let runtime = context.runtime.clone();
    let (backend_io, handshake) = match connect_backend(context, &runtime, handshake_request).await
    {
        Ok(pair) => pair,
        Err(err) => return err.into_response(),
    };

    let response = match relay_upgrade_response(&handshake) {
        Ok(response) => response,
        Err(err) => return err.into_response(),
    };

    let session_runtime = runtime.clone();
    let (backend_read, backend_write) = tokio::io::split(TokioIo::new(backend_io));
    let session = async move {
        if let Err(err) =
            ws_session_relay(api, session_runtime, upgraded, backend_read, backend_write).await
        {
            tracing::warn!(?err, "ws tunnel session ended with error");
        }
    };
    runtime.spawn_supervised_task_current_span(session);
    response
}

/// Plain HTTP rejection before the protocol switches. The JSON shape matches
/// `TngError::into_response`; only the status is overridden here because
/// client-caused ws rejects deserve 4xx codes.
fn reject(status: StatusCode, error: TngError) -> Response {
    let code = error.as_ref().to_owned();
    (
        status,
        Json(ErrorResponse {
            code,
            message: format!("{:#}", anyhow::Error::new(error)),
        }),
    )
        .into_response()
}

/// Build the backend handshake request as a relay of the ingress's request:
/// method, version, request-target, `Host` and the RFC 6455 handshake headers
/// stay the ones the app sent (its key flows end to end, so the backend's
/// accept verifies at every hop and nobody recomputes anything). The relayed
/// `Host`/URI is data only: the connection was already resolved by the
/// capture-mode mapped out address before this request is sent. Hop-owned
/// headers are rewritten: the extension offer now travels (app and backend
/// negotiate end to end, TNG relays the frames opaquely), the dispatch marker
/// is dropped, and the `x-tng-ohttp-api` header must never reach the backend.
///
/// The empty body keeps this a plain GET; the response is a 101 upgrade that
/// hands the connection over to the byte relay.
fn build_backend_request(
    incoming: &Request,
    relayed_protocols: Option<HeaderValue>,
) -> Result<http::Request<BodyT>, TngError> {
    let mut headers = ws_relay_request_headers(incoming.headers(), relayed_protocols);
    // Preserve the app's authority as the `Host` the backend sees. The
    // request already arrived with it (or with an absolute URI whose authority
    // hyper folded into `Host`), so carry the value through verbatim.
    if let Some(host) = incoming.headers().get(header::HOST) {
        headers.insert(header::HOST, host.clone());
    }
    // Parts are set directly rather than through the builder: a whole relayed
    // `HeaderMap` replaces the request's headers, which the builder's
    // append-style API cannot express.
    let mut parts = http::Request::new(empty_body()).into_parts().0;
    parts.method = http::Method::GET;
    // Origin-form target: hyper serializes `path-and-query` and relies on the
    // `Host` header for the authority, the same relay the ingress sent.
    parts.uri = incoming.uri().clone();
    parts.version = incoming.version();
    parts.headers = headers;
    Ok(http::Request::from_parts(parts, empty_body()))
}

/// The body type a one-shot upgrade request is sent with: an empty body, so
/// `SendRequest` can hand the connection to the upgrade once the backend
/// answers the 101.
type BodyT = Empty<Bytes>;

fn empty_body() -> BodyT {
    Empty::<Bytes>::new()
}

/// Open the backend hop through the connection's shared dial path and finish
/// the WebSocket handshake on top of it.
///
/// The dial goes through the connection's `UpstreamConnector` like every other
/// protocol: it resolves the capture-mode mapped out address (never the
/// relayed request's `Host`), keeps the access log and connection accounting
/// current, and settles them by ownership when the upgraded socket drops. The
/// HTTP/1.1 upgrade exchange (send the relayed GET, read the 101, take the
/// upgraded io) runs on that socket directly and is bounded by the negotiation
/// budget so a black-holed or non-upgrading backend fails the upgrade promptly
/// rather than hanging the ingress hop.
async fn connect_backend(
    context: TngStreamContext,
    runtime: &TokioRuntime,
    handshake_request: http::Request<BodyT>,
) -> Result<
    (
        hyper::upgrade::Upgraded,
        http::Response<hyper::body::Incoming>,
    ),
    TngError,
> {
    let connected = context
        .connector
        .connect(true, false)
        .await
        .map_err(TngError::ConnectUpstreamFailed)?;
    // Same byte accounting the ordinary backend leg carries; the counter
    // wrapper travels inside the upgrade, so totals stay on this service.
    let backend = context.connector.metrics().wrap_stream(
        connected,
        crate::tunnel::service_metrics::ByteCountOrientation::Backend,
    );

    let exchange = async {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(backend))
            .await
            .map_err(|err| {
                TngError::WsUpgradeFailed(
                    anyhow::Error::new(err).context("backend http handshake failed"),
                )
            })?;
        // The connection driver must run for the request to reach the backend;
        // driving the upgradeable future is also what fulfills the 101 upgrade
        // (it hands the socket to hyper::upgrade::on below) instead of closing
        // the connection when the protocol switches.
        runtime.spawn_supervised_task_current_span(async move {
            if let Err(err) = conn.with_upgrades().await {
                tracing::debug!(?err, "backend http connection ended");
            }
        });
        let mut response = sender
            .send_request(handshake_request)
            .await
            .map_err(|err| {
                TngError::WsUpgradeFailed(
                    anyhow::Error::new(err).context("backend ws handshake request failed"),
                )
            })?;
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(TngError::WsUpgradeFailed(anyhow!(
                "backend returned {} instead of switching protocols",
                response.status()
            )));
        }
        let upgraded = hyper::upgrade::on(&mut response).await.map_err(|err| {
            TngError::WsUpgradeFailed(
                anyhow::Error::new(err).context("backend ws upgrade did not complete"),
            )
        })?;
        Ok::<_, TngError>((upgraded, response))
    };
    tokio::time::timeout(TNG_WS_NEGOTIATION_TIMEOUT, exchange)
        .await
        .map_err(|_| TngError::WsUpgradeFailed(anyhow!("backend ws handshake timed out")))?
}

/// The 101 to hand back up the chain: the backend's status and headers relayed
/// verbatim (minus connection-owned response headers). Nothing is synthesized
/// at this hop, so the accept the app verifies is the backend's own.
fn relay_upgrade_response(
    handshake: &http::Response<hyper::body::Incoming>,
) -> Result<Response, TngError> {
    let mut parts = http::Response::new(axum::body::Body::empty())
        .into_parts()
        .0;
    parts.status = handshake.status();
    parts.headers = ws_relay_response_headers(handshake.headers());
    Ok(http::Response::from_parts(parts, axum::body::Body::empty()))
}

/// One session, from adopted upgrade through in-stream negotiation to the chunk
/// relay. The backend is already connected and handshaked; the ingress hop is
/// adopted here and the two directions then run as their own relay tasks.
async fn ws_session_relay(
    api: Arc<OhttpServerApi>,
    runtime: TokioRuntime,
    upgraded: hyper::upgrade::OnUpgrade,
    backend_read: BackendRead,
    backend_write: BackendWrite,
) -> Result<()> {
    let upgraded = upgraded.await.context("ws upgrade never completed")?;
    let ingress: IngressHop = WebSocketStream::from_raw_socket(
        TokioAdapter::new(TokioIo::new(upgraded)),
        Role::Server,
        None,
    )
    .await;

    let (in_sink, in_stream) = ingress.split();
    ws_relay_adopted(
        api,
        runtime,
        in_sink,
        in_stream,
        backend_read,
        backend_write,
        TNG_WS_NEGOTIATION_TIMEOUT,
    )
    .await
}

/// The adopted-hop half of a session: in-stream negotiation, then one relay
/// task per direction. The ingress hop arrives as generic split halves and the
/// backend as a raw byte pipe so a duplex test can drive either end;
/// `negotiation_timeout` bounds the wait for the control message (production
/// passes the standard budget). Any exit drops both hops here because they are
/// owned here.
#[allow(clippy::too_many_arguments)]
async fn ws_relay_adopted<ISink, IStream, BRead, BWrite>(
    api: Arc<OhttpServerApi>,
    runtime: TokioRuntime,
    mut in_sink: ISink,
    mut in_stream: IStream,
    backend_read: BRead,
    backend_write: BWrite,
    negotiation_timeout: std::time::Duration,
) -> Result<()>
where
    ISink: futures::Sink<Message, Error = async_tungstenite::tungstenite::Error>
        + Unpin
        + Send
        + 'static,
    IStream: futures::Stream<Item = std::result::Result<Message, async_tungstenite::tungstenite::Error>>
        + Unpin
        + Send
        + 'static,
    BRead: AsyncRead + Unpin + Send + 'static,
    BWrite: AsyncWrite + Unpin + Send + 'static,
{
    // The first frame must be the binary control message carrying metadata +
    // ohttp header. A missing or mis-typed one ends the session before any
    // key material is derived.
    let control = tokio::time::timeout(negotiation_timeout, in_stream.next())
        .await
        .map_err(|_| anyhow!("ws negotiation timed out before the control message"))?
        .ok_or_else(|| anyhow!("ingress closed before ws negotiation"))?
        .context("failed to read ws control message")?;
    let Message::Binary(control) = control else {
        return Err(anyhow!(
            "ws negotiation violation: first message must be a binary control message"
        ));
    };

    let (c2s_opener, s2c_sealer, key_id) = api
        .accept_ws_session(&control)
        .await
        .context("ws session negotiation failed")?;

    // The nonce must land before any S2C data: the ingress derives its S2C
    // opener from it, and the s2c relay only starts after this send.
    in_sink
        .send(Message::Binary(s2c_sealer.response_nonce().to_vec()))
        .await
        .context("failed to send ws response nonce")?;
    tracing::info!(key_id, "ws tunnel session established");

    // Each direction owns its sequence number, so each relay task owns its
    // own record context.
    let token = CancellationToken::new();

    let c2s = runtime.spawn_supervised_task_current_span(c2s_relay(
        in_stream,
        backend_write,
        c2s_opener,
        token.clone(),
    ));
    let s2c = runtime.spawn_supervised_task_current_span(s2c_relay(
        in_sink,
        backend_read,
        s2c_sealer,
        token,
    ));
    let (c2s, s2c) = tokio::join!(c2s, s2c);
    c2s.context("c2s relay task join failed")?
        .assume_finished()?
        .context("c2s relay ended with error")?;
    s2c.context("s2c relay task join failed")?
        .assume_finished()?
        .context("s2c relay ended with error")?;

    tracing::info!("ws tunnel session ended");
    Ok(())
}

/// Ingress to backend: open chunk records and emit the recovered frame bytes on
/// the backend byte pipe. The session is over once this direction ends (the
/// stream terminated or the peer died), so the peer direction is cancelled.
async fn c2s_relay<IStream, BWrite>(
    mut stream: IStream,
    mut backend: BWrite,
    mut opener: ohttp::chunk::ServerOpener,
    token: CancellationToken,
) -> Result<()>
where
    IStream: futures::Stream<Item = std::result::Result<Message, async_tungstenite::tungstenite::Error>>
        + Unpin,
    BWrite: AsyncWrite + Unpin,
{
    let outcome = relay_c2s(&mut stream, &mut backend, &mut opener, &token).await;
    // Whichever way this direction ends, the tunnel cannot run half-open
    // upward: pull the peer down too.
    token.cancel();
    outcome
}

async fn relay_c2s<IStream, BWrite>(
    stream: &mut IStream,
    backend: &mut BWrite,
    opener: &mut ohttp::chunk::ServerOpener,
    token: &CancellationToken,
) -> Result<()>
where
    IStream: futures::Stream<Item = std::result::Result<Message, async_tungstenite::tungstenite::Error>>
        + Unpin,
    BWrite: AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Binary(record))) => match opener.open(&record)? {
                    Some(frame_bytes) => {
                        backend.write_all(&frame_bytes).await
                            .context("failed to forward ws frame bytes to backend")?;
                        backend.flush().await.context("failed to flush to backend")?;
                    }
                    // The client's C2S stream ended: half-close the backend so
                    // the close it is owed can propagate.
                    None => {
                        tracing::debug!("c2s stream terminated, half-closing the backend");
                        let _ = backend.shutdown().await;
                        break;
                    }
                },
                Some(Ok(Message::Close(_))) | None => {
                    // Ingress hop gone without a terminating chunk: the session
                    // is over, take it down.
                    tracing::debug!("ingress hop ended before the c2s stream terminated");
                    break;
                }
                Some(Ok(other)) => {
                    return Err(anyhow!(
                        "ws protocol violation: only binary chunk records expected, got {other:?}"
                    ));
                }
                Some(Err(err)) => return Err(anyhow::Error::from(err).context("ingress ws read failed")),
            }
        }
    }
    Ok(())
}

/// Backend to ingress: read the opaque frame bytes off the backend pipe and
/// seal them as chunk records. On backend EOF the terminating chunk is emitted
/// so the ingress closes its app side.
async fn s2c_relay<ISink, BRead>(
    mut sink: ISink,
    mut backend: BRead,
    mut sealer: ohttp::chunk::ServerSealer,
    token: CancellationToken,
) -> Result<()>
where
    ISink: futures::Sink<Message, Error = async_tungstenite::tungstenite::Error> + Unpin,
    BRead: AsyncRead + Unpin,
{
    let outcome = relay_s2c(&mut sink, &mut backend, &mut sealer, &token).await;
    token.cancel();
    outcome
}

async fn relay_s2c<ISink, BRead>(
    sink: &mut ISink,
    backend: &mut BRead,
    sealer: &mut ohttp::chunk::ServerSealer,
    token: &CancellationToken,
) -> Result<()>
where
    ISink: futures::Sink<Message, Error = async_tungstenite::tungstenite::Error> + Unpin,
    BRead: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; ohttp::chunk::MAX_CHUNK];
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            read = backend.read(&mut buf) => {
                let read = read.context("backend ws read failed")?;
                if read == 0 {
                    // Backend EOF: emit the terminating chunk and let the
                    // ingress see its stream end.
                    let final_record = sealer.seal_final().context("s2c final seal failed")?;
                    if sink.send(Message::Binary(final_record)).await.is_err() {
                        tracing::debug!("ingress hop died before the s2c final chunk");
                    }
                    break;
                }
                let record = sealer.seal(&buf[..read]).context("s2c chunk seal failed")?;
                sink.send(Message::Binary(record))
                    .await
                    .context("failed to forward chunk record to ingress")?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use crate::tunnel::ohttp::protocol::header::OhttpApi;
    use crate::tunnel::ohttp::protocol::ws::TNG_WS_MARKER;
    use async_tungstenite::tungstenite::Error as WsError;
    use tokio::io::DuplexStream;

    /// A matching set of egress- and client-side chunk streamers, plus the
    /// client S2C opener the ingress would derive after seeing the nonce.
    fn e2e_pair() -> (
        ohttp::chunk::ServerOpener,
        ohttp::chunk::ServerSealer,
        ohttp::chunk::ClientSealer,
        ohttp::chunk::ClientOpener,
    ) {
        let key_config = ohttp::KeyConfig::new(
            1,
            ohttp::hpke::Kem::X25519Sha256,
            vec![ohttp::SymmetricSuite::new(
                ohttp::hpke::Kdf::HkdfSha256,
                ohttp::hpke::Aead::ChaCha20Poly1305,
            )],
        )
        .unwrap();
        let hpke = key_config.select(key_config.symmetric()[0]).unwrap();
        let pk = ohttp::PublicKey::from_x25519_bytes(&key_config.pk_data().unwrap()).unwrap();
        let (header, c2s_sealer, pending) =
            ohttp::ClientRequest::start_without_body(hpke, key_config.key_id(), &pk).unwrap();
        let (c2s_opener, s2c_sealer) = ohttp::Server::decode_header_from_slice(&header)
            .unwrap()
            .into_chunk_parts(key_config)
            .unwrap();
        let s2c_opener = pending
            .with_response_nonce(s2c_sealer.response_nonce())
            .unwrap();
        (c2s_opener, s2c_sealer, c2s_sealer, s2c_opener)
    }

    /// A connected client/server WebSocket pair over an in-memory duplex.
    async fn ws_pair() -> (
        WebSocketStream<TokioAdapter<DuplexStream>>,
        WebSocketStream<TokioAdapter<DuplexStream>>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client =
            WebSocketStream::from_raw_socket(TokioAdapter::new(client_io), Role::Client, None)
                .await;
        let server =
            WebSocketStream::from_raw_socket(TokioAdapter::new(server_io), Role::Server, None)
                .await;
        (client, server)
    }

    /// The C2S relay opens chunk records from the ingress hop and writes the
    /// recovered frame bytes verbatim to the backend pipe; the terminating
    /// chunk half-closes the backend and ends the direction.
    #[tokio::test]
    async fn c2s_relay_reassembles_frames_and_ends_on_final() {
        let (mut opener, _sealer, mut c2s, _s2c_opener) = e2e_pair();
        let (mut fake_ingress, relay_ws) = ws_pair().await;
        let (_relay_sink, mut relay_stream) = relay_ws.split();
        let (mut backend, mut backend_probe) = tokio::io::duplex(64 * 1024);

        let r1 = c2s.seal(b"GET /x HTTP/1.1\r\n").unwrap();
        let r2 = c2s.seal(b"\r\n").unwrap();
        let rf = c2s.seal_final().unwrap();

        let driver = async {
            fake_ingress.send(Message::Binary(r1)).await.unwrap();
            fake_ingress.send(Message::Binary(r2)).await.unwrap();
            fake_ingress.send(Message::Binary(rf)).await.unwrap();
        };
        let token = CancellationToken::new();
        let relay = async { relay_c2s(&mut relay_stream, &mut backend, &mut opener, &token).await };

        let relay_out = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            futures::future::join(driver, relay),
        )
        .await
        .expect("relay must finish")
        .1;
        relay_out.expect("c2s relay ok");

        // The two chunks arrive reassembled; the terminator closed the backend.
        let mut got = Vec::new();
        backend_probe.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"GET /x HTTP/1.1\r\n\r\n");
    }

    /// The S2C relay seals backend frame bytes into chunk records and emits the
    /// terminating record when the backend pipe reaches EOF.
    #[tokio::test]
    async fn s2c_relay_seals_and_terminates_on_eof() {
        let (_opener, mut sealer, _c2s, mut s2c_opener) = e2e_pair();
        let (mut fake_ingress, relay_ws) = ws_pair().await;
        let (mut relay_sink, _relay_stream) = relay_ws.split();
        let (mut backend, mut fake_backend) = tokio::io::duplex(64 * 1024);

        let token = CancellationToken::new();
        let relay = async { relay_s2c(&mut relay_sink, &mut backend, &mut sealer, &token).await };

        let feeder = async {
            fake_backend.write_all(b"opaque frame bytes").await.unwrap();
            fake_backend.flush().await.unwrap();
            // Dropping the backend write half gives the relay EOF; it must
            // then emit the final chunk and end.
            drop(fake_backend);
        };

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            futures::future::join(feeder, relay),
        )
        .await
        .expect("relay must finish")
        .1
        .expect("s2c relay ok");

        let mut seen = Vec::new();
        let mut got_final = false;
        while let Some(Ok(Message::Binary(record))) = fake_ingress.next().await {
            match s2c_opener.open(&record).unwrap() {
                Some(pt) => seen.extend_from_slice(&pt),
                None => {
                    got_final = true;
                    break;
                }
            }
        }
        assert_eq!(seen, b"opaque frame bytes");
        assert!(got_final, "the final chunk must reach the ingress");
    }

    /// A tampered record must fail the open rather than be skipped or
    /// resynchronised, and the C2S relay surfaces it as a session error.
    #[tokio::test]
    async fn tampered_record_fails_open_and_ends_relay() {
        let (mut opener, _sealer, mut c2s, _s2c_opener) = e2e_pair();
        let mut record = c2s.seal(b"payload").unwrap();
        let last = record.len() - 1;
        record[last] ^= 0x01;
        assert!(
            opener.open(&record).is_err(),
            "a tampered record must fail the open"
        );

        // Fresh pair: feed the tampered record through the relay and expect an
        // error, not a silent skip.
        let (mut opener2, _s2, mut c2s2, _o) = e2e_pair();
        let mut rec2 = c2s2.seal(b"payload").unwrap();
        let last = rec2.len() - 1;
        rec2[last] ^= 0x01;
        let bad = Message::Binary(rec2);
        let mut bad_stream = futures::stream::iter(vec![Ok::<_, WsError>(bad)]);
        let (mut backend, backend_probe) = tokio::io::duplex(128);
        // Keep the probe (reader half) alive so a write never blocks on a full
        // duplex while the relay fails on the bad record.
        let _probe = backend_probe;
        let token = CancellationToken::new();
        let relay = relay_c2s(&mut bad_stream, &mut backend, &mut opener2, &token);
        tokio::pin!(relay);
        tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("relay must not hang")
            .expect_err("a tampered record must end the relay with an error");
    }

    #[test]
    fn build_backend_request_relays_the_handshake_verbatim() {
        let incoming = ingress_upgrade_request();
        let relayed_protocols = incoming
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(strip_tng_marker);
        let request = build_backend_request(&incoming, relayed_protocols).unwrap();

        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.version(), http::Version::HTTP_11);
        assert_eq!(request.uri(), incoming.uri());
        let headers = request.headers();
        // The app's identity flows on untouched.
        assert_eq!(headers.get(header::SEC_WEBSOCKET_KEY).unwrap(), APP_KEY);
        assert_eq!(headers.get(header::SEC_WEBSOCKET_VERSION).unwrap(), "13");
        assert_eq!(
            headers.get(header::HOST).unwrap(),
            incoming.headers().get(header::HOST).unwrap()
        );
        // The extension offer now travels (it is no longer stripped).
        assert_eq!(
            headers[header::SEC_WEBSOCKET_EXTENSIONS],
            "permessage-deflate"
        );
        assert_eq!(headers["x-app-meta"], "keep-me");
        // The marker and the api header must never reach the backend.
        let protocols = headers[header::SEC_WEBSOCKET_PROTOCOL]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(protocols, "chat.v2");
        assert!(
            !protocols.contains(TNG_WS_MARKER),
            "marker leaked: {protocols}"
        );
        assert!(!headers.contains_key(OhttpApi::HEADER_NAME));
    }

    /// The app's key, relayed by the ingress unchanged and expected to reach
    /// the backend verbatim.
    const APP_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn ingress_upgrade_request() -> Request {
        Request::builder()
            .method(http::Method::GET)
            .uri("/tng/ws-tunnel?room=1")
            .version(http::Version::HTTP_11)
            .header(header::HOST, "backend.example:9443")
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, APP_KEY)
            .header(header::SEC_WEBSOCKET_PROTOCOL, "tng-ohttp-ws, chat.v2")
            .header(header::SEC_WEBSOCKET_EXTENSIONS, "permessage-deflate")
            .header(OhttpApi::HEADER_NAME, OhttpApi::TUNNEL)
            .header("x-app-meta", "keep-me")
            .body(axum::body::Body::empty())
            .unwrap()
    }
}
