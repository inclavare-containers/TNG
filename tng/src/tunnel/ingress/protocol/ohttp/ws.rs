use std::sync::Arc;

use anyhow::{anyhow, Context as _, Result};
use async_tungstenite::tokio::TokioAdapter;
use async_tungstenite::tungstenite::{self, Message};
use async_tungstenite::WebSocketStream;
use axum::response::{IntoResponse as _, Response};
use futures::{SinkExt, StreamExt};
use http::header::{HOST, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION};
use http::{HeaderMap, HeaderValue, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::error::TngError;
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::ingress::protocol::ohttp::security::client::WsSessionMaterial;
use crate::tunnel::ingress::protocol::ohttp::security::{OHttpSecurityLayer, WsEgressHop};
use crate::tunnel::ohttp::protocol::ws::{
    backend_target, ws_relay_request_headers, ws_relay_response_headers, TNG_WS_MARKER,
    TNG_WS_NEGOTIATION_TIMEOUT,
};
use crate::TokioRuntime;

/// Egress-side hop. Plain TCP and TLS-wrapped TCP are folded into one enum so
/// both branches share a single stream type; the websocket handshake itself
/// runs in async-tungstenite over whichever variant comes in.
enum EgressHopIo {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl tokio::io::AsyncRead for EgressHopIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(&mut **stream).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for EgressHopIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(&mut **stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }
}

type EgressHop = WebSocketStream<TokioAdapter<EgressHopIo>>;

type EgressHandshake = async_tungstenite::tungstenite::handshake::client::Response;

/// Serve an app websocket upgrade by tunneling it to the egress. All failures
/// before the protocol switch are plain HTTP errors; afterwards the session
/// runs in its own supervised task and only logs.
pub async fn handle_ws_upgrade(
    request: http::Request<hyper::body::Incoming>,
    endpoint: &TngEndpoint,
    security_layer: &Arc<OHttpSecurityLayer>,
    runtime: TokioRuntime,
) -> Response {
    match try_handle_ws_upgrade(request, endpoint, security_layer, runtime).await {
        Ok(response) => response,
        Err(error) => {
            tracing::debug!(?error, "ingress websocket upgrade rejected");
            error.into_response()
        }
    }
}

async fn try_handle_ws_upgrade(
    request: http::Request<hyper::body::Incoming>,
    endpoint: &TngEndpoint,
    security_layer: &Arc<OHttpSecurityLayer>,
    runtime: TokioRuntime,
) -> Result<Response, TngError> {
    // The handshake is relayed end to end, so the app's key and version must
    // exist for the backend's accept to be verifiable on every hop.
    for required in [SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION] {
        if !request.headers().contains_key(required) {
            return Err(TngError::InvalidHttpRequest);
        }
    }
    // Backend target follows proxy semantics like ordinary ohttp inner
    // requests: an absolute-form URI carries its own authority, an
    // origin-form one relies on the Host header.
    let (backend_authority, _) = backend_target(request.uri(), request.headers())?;

    let mut request = request.map(axum::body::Body::new);
    // Take the upgrade future before the request is consumed any further;
    // hyper delivers the raw connection once the 101 below goes on the wire.
    let upgraded = hyper::upgrade::on(&mut request);

    // The relayed path goes through the same `path_rewrites`/`path_default`
    // rule as the outer POST path; the app's query is carried over intact.
    let rewritten_path = security_layer.ws_relay_path(&request);
    let backend_path = match request.uri().query() {
        Some(query) => format!("{rewritten_path}?{query}"),
        None => rewritten_path.into_owned(),
    };

    let hop = security_layer.forward_ws_upgrade(endpoint).await?;
    let WsEgressHop {
        material,
        tcp,
        tls_connector,
    } = hop;

    let (egress_ws, handshake) = timeout(
        TNG_WS_NEGOTIATION_TIMEOUT,
        open_egress_hop(
            tcp,
            tls_connector,
            &material,
            request.headers(),
            &backend_authority,
            &backend_path,
        ),
    )
    .await
    .map_err(|_| TngError::WsUpgradeFailed(anyhow!("egress ws handshake timed out")))??;
    if handshake.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(TngError::WsUpgradeFailed(anyhow!(
            "egress returned {} instead of switching protocols",
            handshake.status()
        )));
    }

    // Relay the egress hop's 101 verbatim: its `Sec-WebSocket-Accept` is the
    // backend's (computed over the app's own key) and its negotiated
    // subprotocol is the backend's. Nothing is synthesized for the app here.
    let mut parts = http::Response::new(axum::body::Body::empty())
        .into_parts()
        .0;
    parts.status = StatusCode::SWITCHING_PROTOCOLS;
    parts.headers = ws_relay_response_headers(handshake.headers());
    let response = http::Response::from_parts(parts, axum::body::Body::empty());

    tracing::info!(
        backend = %backend_authority,
        egress = %material.egress_base,
        "ws tunnel session established"
    );

    let session_runtime = runtime.clone();
    let session = async move {
        if let Err(error) = ws_half_open_relay(
            session_runtime,
            upgraded,
            egress_ws,
            backend_authority,
            material,
        )
        .await
        {
            tracing::warn!(?error, "ws tunnel session ended with error");
        }
    };
    runtime.spawn_supervised_task_current_span(session);
    Ok(response)
}

/// Offer list for the egress hop: the app's subprotocols plus the TNG marker
/// (the marker is the tunnel's dispatch signal on the egress; a browser in
/// the client role offers it itself, so the native relay offers the same
/// thing). A non-utf8 app offer cannot be re-serialized here, so only the
/// marker survives; the egress relays whatever subprotocol the backend picks.
fn offered_subprotocols(app_protocols: Option<&HeaderValue>) -> String {
    match app_protocols {
        Some(value) => format!("{}, {}", value.to_str().unwrap_or_default(), TNG_WS_MARKER),
        None => TNG_WS_MARKER.to_string(),
    }
}

/// Strip the scheme from the egress origin, leaving `host:port`.
fn egress_authority(egress_base: &str) -> Result<&str, TngError> {
    egress_base
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| {
            TngError::WsUpgradeFailed(anyhow!("malformed egress base url {egress_base}"))
        })
}

/// Authority without the port: the TLS SNI/server-name value.
fn server_name_host(authority: &str) -> &str {
    authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority)
}

/// Run the client websocket handshake to the egress over the dialled tcp
/// (wrapped in TLS only when `ohttp.tls` is on). TLS itself is fully
/// delegated: the pre-built rustls connector performs the handshake and the
/// resulting stream is handed to async-tungstenite like the plain one.
///
/// The request is a relay of the app's upgrade (the app's key and version
/// flow through untouched), with the marker appended to the subprotocol
/// offer, the backend target as the request authority (`Host`, since
/// tungstenite serializes an origin-form request line), and hop-owned
/// headers rewritten. async-tungstenite's `client_async` forwards a prebuilt
/// `http::Request` unchanged, and tungstenite refuses to send a request
/// missing any of Host, Connection, Upgrade, Sec-WebSocket-Version or
/// Sec-WebSocket-Key, so those come from the validated app request.
async fn open_egress_hop(
    tcp: tokio::net::TcpStream,
    tls_connector: Option<Arc<tokio_rustls::TlsConnector>>,
    material: &WsSessionMaterial,
    app_headers: &HeaderMap,
    backend_authority: &str,
    backend_path: &str,
) -> Result<(EgressHop, EgressHandshake), TngError> {
    let authority = egress_authority(&material.egress_base)?;
    let protocol = HeaderValue::from_str(&offered_subprotocols(
        app_headers.get(SEC_WEBSOCKET_PROTOCOL),
    ))
    .map_err(|error| {
        TngError::WsUpgradeFailed(anyhow::Error::new(error).context("invalid subprotocol offer"))
    })?;
    let mut headers = ws_relay_request_headers(app_headers, Some(protocol));
    let host = HeaderValue::from_str(backend_authority).map_err(|error| {
        TngError::WsUpgradeFailed(
            anyhow::Error::new(error)
                .context(format!("invalid backend target {backend_authority}")),
        )
    })?;
    headers.insert(HOST, host);
    // The relayed request is built through parts: the whole copied header
    // map replaces the request's headers, which the builder's append-style
    // API cannot express. The scheme mirrors the egress hop's TLS flag
    // (tungstenite only accepts ws/wss), and the URI authority names the
    // backend for the egress while the TCP connection goes to the egress
    // itself.
    let mut parts = http::Request::new(()).into_parts().0;
    parts.method = http::Method::GET;
    parts.uri = format!(
        "{}://{backend_authority}{backend_path}",
        if material.scheme_tls { "wss" } else { "ws" }
    )
    .parse()
    .map_err(|error| {
        TngError::WsUpgradeFailed(
            anyhow::Error::new(error)
                .context(format!("invalid relay uri for backend {backend_authority}")),
        )
    })?;
    parts.version = http::Version::HTTP_11;
    parts.headers = headers;
    let request = http::Request::from_parts(parts, ());

    let io = match tls_connector {
        Some(connector) => {
            let server_name =
                rustls::pki_types::ServerName::try_from(server_name_host(authority).to_owned())
                    .map_err(|error| {
                        TngError::WsUpgradeFailed(anyhow::Error::new(error).context(format!(
                            "egress host {authority} is not a valid TLS server name"
                        )))
                    })?;
            EgressHopIo::Tls(Box::new(
                connector.connect(server_name, tcp).await.map_err(|error| {
                    TngError::WsUpgradeFailed(
                        anyhow::Error::new(error).context("egress tls handshake failed"),
                    )
                })?,
            ))
        }
        None => EgressHopIo::Plain(tcp),
    };

    async_tungstenite::tokio::client_async(request, io)
        .await
        .map_err(|error| {
            TngError::WsUpgradeFailed(
                anyhow::Error::from(error)
                    .context(format!("egress ws handshake to {authority} failed")),
            )
        })
}

/// One session, from adopted upgrade through in-stream negotiation to the chunk
/// relay. The app hop is a raw byte pipe (the app's frames are opaque to TNG);
/// the egress hop is the middle-hop WebSocket whose binary messages each carry
/// one sealed chunk record. The control message goes out first, then each
/// direction runs as its own task: C2S seals and forwards immediately, S2C
/// waits for the nonce.
async fn ws_half_open_relay(
    runtime: TokioRuntime,
    upgraded: hyper::upgrade::OnUpgrade,
    egress_ws: EgressHop,
    backend_authority: String,
    material: WsSessionMaterial,
) -> Result<()> {
    let upgraded = upgraded.await.context("ws upgrade never completed")?;
    let (app_read, app_write) = tokio::io::split(TokioIo::new(upgraded));

    let WsSessionMaterial {
        outer_metadata,
        header,
        c2s_sealer,
        s2c_pending,
        ..
    } = material;

    // In-stream control message: [metadata block][ohttp header], one binary
    // frame, exactly what the egress's `accept_ws_session` parses.
    let control: Vec<u8> = [&outer_metadata[..], &header].concat();
    let (mut eg_sink, eg_stream) = egress_ws.split();
    eg_sink
        .send(Message::Binary(control))
        .await
        .context("failed to send ws control message")?;

    // The C2S sealer runs immediately; the S2C opener stays keyed only once
    // the egress's nonce arrives. No shared state: the half-open window is why
    // the uplink can run before the downlink is ready.
    let token = CancellationToken::new();

    let c2s = runtime.spawn_supervised_task_current_span(c2s_relay(
        app_read,
        eg_sink,
        c2s_sealer,
        token.clone(),
    ));
    let s2c = runtime.spawn_supervised_task_current_span(s2c_relay(
        app_write,
        eg_stream,
        s2c_pending,
        token,
    ));
    let (c2s, s2c) = tokio::join!(c2s, s2c);
    c2s.context("c2s relay task join failed")?
        .assume_finished()?
        .context("c2s relay ended with error")?;
    s2c.context("s2c relay task join failed")?
        .assume_finished()?
        .context("s2c relay ended with error")?;

    tracing::info!(backend = %backend_authority, "ws tunnel session ended");
    Ok(())
}

/// App to egress: read the app's opaque frame bytes, seal them as chunk records,
/// and send one record per egress message. The session is over once this
/// direction ends, so the peer direction is cancelled.
async fn c2s_relay<R, Sink>(
    mut app: R,
    mut sink: Sink,
    mut sealer: ohttp::chunk::ClientSealer,
    token: CancellationToken,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    Sink: futures::Sink<Message, Error = tungstenite::Error> + Unpin,
{
    let outcome = relay_c2s(&mut app, &mut sink, &mut sealer, &token).await;
    // The tunnel cannot run half-open upward once the uplink stream ended or
    // broke: pull the downlink down too.
    token.cancel();
    outcome
}

async fn relay_c2s<R, Sink>(
    app: &mut R,
    sink: &mut Sink,
    sealer: &mut ohttp::chunk::ClientSealer,
    token: &CancellationToken,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    Sink: futures::Sink<Message, Error = tungstenite::Error> + Unpin,
{
    let mut buf = vec![0u8; ohttp::chunk::MAX_CHUNK];
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            read = app.read(&mut buf) => {
                let read = read.context("app byte read failed")?;
                if read == 0 {
                    // App EOF: the byte stream ended, emit the terminating
                    // chunk so the egress closes the backend.
                    let final_record = sealer.seal_final().context("c2s final seal failed")?;
                    if sink.send(Message::Binary(final_record)).await.is_err() {
                        tracing::debug!("egress hop died before the c2s final chunk");
                    }
                    break;
                }
                let record = sealer.seal(&buf[..read]).context("c2s chunk seal failed")?;
                sink.send(Message::Binary(record))
                    .await
                    .context("failed to forward chunk record to egress")?;
            }
        }
    }
    Ok(())
}

/// Egress to app: wait for the response nonce, key the S2C opener from it, then
/// open chunk records and write the recovered frame bytes on the app byte pipe.
async fn s2c_relay<W, Stream>(
    mut app: W,
    mut stream: Stream,
    pending: ohttp::chunk::PendingClientOpener,
    token: CancellationToken,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    Stream: futures::Stream<Item = std::result::Result<Message, tungstenite::Error>> + Unpin,
{
    let outcome = match derive_s2c_opener(&mut stream, pending).await {
        Ok(mut opener) => relay_s2c(&mut app, &mut stream, &mut opener, &token).await,
        Err(error) => Err(error),
    };
    token.cancel();
    outcome
}

/// The first egress message after our control message must be the binary
/// response nonce; anything else is a negotiation violation.
async fn derive_s2c_opener<Stream>(
    stream: &mut Stream,
    pending: ohttp::chunk::PendingClientOpener,
) -> Result<ohttp::chunk::ClientOpener>
where
    Stream: futures::Stream<Item = std::result::Result<Message, tungstenite::Error>> + Unpin,
{
    let first = timeout(TNG_WS_NEGOTIATION_TIMEOUT, stream.next())
        .await
        .map_err(|_| anyhow!("ws negotiation timed out waiting for the response nonce"))?
        .ok_or_else(|| anyhow!("egress closed before the ws response nonce"))?
        .context("failed to read ws response nonce")?;
    let Message::Binary(nonce) = first else {
        return Err(anyhow!(
            "ws negotiation violation: first egress message is not a binary response nonce"
        ));
    };
    pending
        .with_response_nonce(&nonce)
        .context("failed to derive the s2c opener from the response nonce")
}

async fn relay_s2c<W, Stream>(
    app: &mut W,
    stream: &mut Stream,
    opener: &mut ohttp::chunk::ClientOpener,
    token: &CancellationToken,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    Stream: futures::Stream<Item = std::result::Result<Message, tungstenite::Error>> + Unpin,
{
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Binary(record))) => {
                    // A failed open means this hop is out of sync with the
                    // egress; tear down rather than resynchronize.
                    match opener.open(&record).context("s2c chunk open failed")? {
                        Some(frame_bytes) => {
                            app.write_all(&frame_bytes)
                                .await
                                .context("failed to write frame bytes to app")?;
                            app.flush().await.context("failed to flush to app")?;
                        }
                        // The terminating chunk: close the app byte pipe.
                        None => {
                            tracing::debug!("s2c stream terminated, closing the app side");
                            let _ = app.shutdown().await;
                            break;
                        }
                    }
                }
                Some(Ok(Message::Close(_))) | None => {
                    // Hop EOF/close without a terminating chunk: nothing can
                    // answer the app anymore, so end the session.
                    tracing::debug!("egress hop ended before the s2c stream terminated");
                    break;
                }
                Some(Ok(other)) => {
                    return Err(anyhow!(
                        "ws protocol violation: only binary chunk records expected from egress, got {other:?}"
                    ));
                }
                Some(Err(error)) => {
                    return Err(anyhow::Error::from(error).context("egress ws read failed"))
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use async_tungstenite::tungstenite::protocol::Role;
    use std::time::Duration;
    use tokio::io::DuplexStream;

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

    /// A matching key set: the client's C2S sealer and pending S2C opener, the
    /// server's C2S opener and S2C sealer, and the server nonce the client
    /// would receive in-stream.
    fn e2e_pair() -> (
        ohttp::chunk::ClientSealer,
        ohttp::chunk::PendingClientOpener,
        ohttp::chunk::ServerOpener,
        ohttp::chunk::ServerSealer,
        Vec<u8>,
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
        let (header, c2s_sealer, s2c_pending) =
            ohttp::ClientRequest::start_without_body(hpke, key_config.key_id(), &pk).unwrap();
        let (c2s_opener, s2c_sealer) = ohttp::Server::decode_header_from_slice(&header)
            .unwrap()
            .into_chunk_parts(key_config)
            .unwrap();
        let nonce = s2c_sealer.response_nonce().to_vec();
        (c2s_sealer, s2c_pending, c2s_opener, s2c_sealer, nonce)
    }

    /// The app's raw frame bytes must reach the egress as sealed chunk records
    /// (opaque: no type byte, no re-framing), and app EOF must emit the
    /// terminating record.
    #[tokio::test]
    async fn c2s_relay_seals_bytes_and_terminates_on_eof() {
        let (mut sealer, _pending, mut server_c2s, _s2c, _nonce) = e2e_pair();
        let (mut app_writer, mut app_reader) = tokio::io::duplex(64 * 1024);
        let (relay_ws, mut egress_probe) = ws_pair().await;
        let (mut relay_sink, _relay_stream) = relay_ws.split();

        let token = CancellationToken::new();
        let relay =
            async { relay_c2s(&mut app_reader, &mut relay_sink, &mut sealer, &token).await };

        let driver = async {
            app_writer.write_all(b"frame part one ").await.unwrap();
            app_writer.write_all(b"part two").await.unwrap();
            // EOF: drop the writer so the relay seals the terminating chunk.
            drop(app_writer);
        };

        let relay_out =
            tokio::time::timeout(Duration::from_secs(5), futures::future::join(driver, relay))
                .await
                .expect("relay must finish")
                .1;
        relay_out.expect("c2s relay ok");

        // Reassemble on the server side: records carry the byte stream, the
        // last is the terminator.
        let mut got = Vec::new();
        let mut saw_final = false;
        while let Some(Ok(Message::Binary(record))) = egress_probe.next().await {
            match server_c2s.open(&record).unwrap() {
                Some(pt) => got.extend_from_slice(&pt),
                None => {
                    saw_final = true;
                    break;
                }
            }
        }
        assert_eq!(got, b"frame part one part two");
        assert!(saw_final, "the terminating chunk must reach the egress");
    }

    /// The s2c relay keys the opener from the binary nonce, then turns sealed
    /// chunk records back into the app's raw frame bytes; the terminating
    /// record ends the app side.
    #[tokio::test]
    async fn s2c_relay_opens_after_nonce_and_writes_bytes() {
        let (_sealer, pending, _server_c2s, mut s2c_sealer, nonce) = e2e_pair();
        let (mut app_writer, mut app_reader) = tokio::io::duplex(64 * 1024);
        let (relay_ws, egress_side) = ws_pair().await;
        let (_relay_sink, mut relay_stream) = relay_ws.split();
        let (mut egress_sink, _egress_stream) = egress_side.split();

        // The fake egress sends nonce then two sealed records then the final.
        let r1 = s2c_sealer.seal(b"hello ").unwrap();
        let r2 = s2c_sealer.seal(b"backend").unwrap();
        let rf = s2c_sealer.seal_final().unwrap();
        let token = CancellationToken::new();

        let feeder = async {
            egress_sink.send(Message::Binary(nonce)).await.unwrap();
            egress_sink.send(Message::Binary(r1)).await.unwrap();
            egress_sink.send(Message::Binary(r2)).await.unwrap();
            egress_sink.send(Message::Binary(rf)).await.unwrap();
        };

        let relay = async {
            let mut opener = derive_s2c_opener(&mut relay_stream, pending)
                .await
                .expect("nonce must key the s2c opener");
            relay_s2c(&mut app_writer, &mut relay_stream, &mut opener, &token).await
        };

        tokio::time::timeout(Duration::from_secs(5), futures::future::join(feeder, relay))
            .await
            .expect("relay must finish")
            .1
            .expect("s2c relay ok");

        // The app receives the reassembled frame bytes, then EOF (the relay
        // shut down the write half).
        let mut got = Vec::new();
        app_reader.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello backend");
    }

    /// A non-binary first message before the nonce is a negotiation violation:
    /// the relay must return the error and cancel the token, so the c2s side
    /// never keeps sealing into a tunnel that cannot answer.
    #[tokio::test]
    async fn s2c_relay_tears_down_on_non_nonce_first_message() {
        let (_sealer, pending, _server_c2s, _s2c, _nonce) = e2e_pair();
        let (mut app_writer, _app_reader) = tokio::io::duplex(64 * 1024);
        let (relay_ws, egress_side) = ws_pair().await;
        let (_relay_sink, relay_stream) = relay_ws.split();
        let (mut egress_sink, _egress_stream) = egress_side.split();

        let token = CancellationToken::new();
        let mut relay_stream = relay_stream;
        let feeder = async {
            egress_sink
                .send(Message::Text("not the nonce".to_string()))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        };
        tokio::pin!(feeder);

        let relay =
            async { s2c_relay(&mut app_writer, &mut relay_stream, pending, token.clone()).await };

        let violation = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::select! {
                _ = &mut feeder => unreachable!("the feeder parks after sending"),
                result = relay => result,
            }
        })
        .await
        .expect("the violation must be detected without waiting out the negotiation timeout")
        .expect_err("the relay must return the negotiation error");
        assert!(
            violation
                .to_string()
                .contains("first egress message is not a binary response nonce"),
            "unexpected error: {violation:?}"
        );
        assert!(token.is_cancelled(), "a failed nonce must cancel the token");
    }

    /// A tampered record must fail the open and end the relay with an error.
    #[tokio::test]
    async fn s2c_relay_fails_on_tampered_record() {
        let (_sealer, pending, _server_c2s, mut s2c_sealer, nonce) = e2e_pair();
        let (mut app_writer, _app_reader) = tokio::io::duplex(64 * 1024);
        let (relay_ws, egress_side) = ws_pair().await;
        let (_relay_sink, relay_stream) = relay_ws.split();
        let (mut egress_sink, _egress_stream) = egress_side.split();

        let mut record = s2c_sealer.seal(b"payload").unwrap();
        let last = record.len() - 1;
        record[last] ^= 0x01;

        let nonce_msg = Message::Binary(nonce);
        let bad = Message::Binary(record);
        let mut relay_stream = relay_stream;
        let feeder = async {
            egress_sink.send(nonce_msg).await.unwrap();
            egress_sink.send(bad).await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        };
        tokio::pin!(feeder);

        let token = CancellationToken::new();
        // Drive the wrapper (not the inner loop): the wrapper owns the
        // teardown cancellation this test asserts on.
        let relay = s2c_relay(&mut app_writer, &mut relay_stream, pending, token.clone());

        let result = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::select! {
                _ = &mut feeder => unreachable!("the feeder parks after sending"),
                result = relay => result,
            }
        })
        .await
        .expect("tampered record must be detected, not hang");
        result.expect_err("a tampered record must end the relay");
        assert!(token.is_cancelled());
    }

    #[test]
    fn offered_subprotocols_always_carries_marker() {
        assert_eq!(offered_subprotocols(None), TNG_WS_MARKER);
        let offered = HeaderValue::from_static("chat.v2, json");
        assert_eq!(
            offered_subprotocols(Some(&offered)),
            "chat.v2, json, tng-ohttp-ws"
        );
    }

    #[test]
    fn server_name_host_strips_port() {
        assert_eq!(server_name_host("10.0.0.1:8080"), "10.0.0.1");
        assert_eq!(server_name_host("egress.example"), "egress.example");
        assert_eq!(server_name_host("egress.example:443"), "egress.example");
    }
}
