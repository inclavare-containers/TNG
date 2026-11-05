use std::time::Duration;

use anyhow::{bail, Result};
use async_tungstenite::tokio::{client_async, TokioAdapter};
use async_tungstenite::tungstenite::client::IntoClientRequest;
use async_tungstenite::tungstenite::Message;
use async_tungstenite::WebSocketStream;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const WS_TEST_MESSAGE: &str = "ws-tng-test";

type WsStream = WebSocketStream<TokioAdapter<TcpStream>>;

/// Which side of the close handshake the client exercises, and what it must
/// observe to call the run green.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WsCloseMode {
    /// Echo round trip only; no close assertions.
    None,
    /// The server closes after the greeting; require that Close frame.
    ExpectServerClose,
    /// Send a Close after the echo round trip and require a Close frame back:
    /// an abrupt end without one is a broken tunnel close handshake (what a
    /// browser would report as 1006 instead of 1000).
    InitiateAndRequireEcho,
}

/// Dial `ws://{host}:{port}/tng/ws-tunnel`. With a `proxy` ("ip:port") the
/// TCP connection goes to the proxy while the handshake request keeps the
/// backend authority, which is how an app addresses its backend through the
/// TNG ingress. Without one the socket connects to the backend directly.
/// `subprotocol` is offered in the handshake; when set, the backend that
/// echoes it back (see `ws_server`) makes the greeting carry its name.
async fn dial_backend_ws(
    host: &str,
    port: u16,
    proxy: Option<&str>,
    subprotocol: Option<&str>,
) -> Result<WsStream> {
    let url = format!("ws://{host}:{port}/tng/ws-tunnel");
    let connect_addr = match proxy {
        Some(proxy) => proxy.to_owned(),
        None => format!("{host}:{port}"),
    };
    tracing::info!("WS client connecting to {url} (tcp: {connect_addr})");

    let tcp = TcpStream::connect(&connect_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect TCP to {connect_addr} for {url}: {e}"))?;
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("Failed to build WS request for {url}: {e}"))?;
    if let Some(subprotocol) = subprotocol {
        // `into_client_request` never sets a subprotocol, so this inserts
        // the offer rather than replacing one.
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", subprotocol.parse()?);
    }
    let (ws, _response) = client_async(request, tcp)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to handshake WS to {url} via {connect_addr}: {e}"))?;

    tracing::info!("WS client connected");
    Ok(ws)
}

/// The server greets every connection with `WS_TEST_MESSAGE`, extended with
/// the negotiated subprotocol name when one was offered; anything else
/// before the echo fails the run.
async fn expect_greeting(ws: &mut WsStream, expected: &str) -> Result<()> {
    match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
        Ok(Some(Ok(msg))) => {
            if let Message::Text(text) = msg {
                if text != expected {
                    bail!("Expected WS test message '{expected}', got '{text}'");
                }
                tracing::info!("WS client received expected test message: {text}");
                Ok(())
            } else {
                bail!("Expected Text message, got {msg:?}");
            }
        }
        Ok(Some(Err(e))) => bail!("WS error: {e}"),
        Ok(None) => bail!("WS connection closed before receiving test message"),
        Err(_) => bail!("Timeout waiting for WS test message"),
    }
}

/// Send the echo message and require it back verbatim.
async fn echo_round_trip(ws: &mut WsStream) -> Result<()> {
    let echo_msg = "echo-from-client";
    ws.send(Message::Text(echo_msg.to_owned())).await?;
    tracing::info!("WS client sent echo message: {echo_msg}");

    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(msg))) => {
            if let Message::Text(text) = msg {
                if text != echo_msg {
                    bail!("Expected echo '{echo_msg}', got '{text}'");
                }
                tracing::info!("WS client received correct echo: {text}");
                Ok(())
            } else {
                bail!("Expected echo Text message, got {msg:?}");
            }
        }
        Ok(Some(Err(e))) => bail!("WS error waiting for echo: {e}"),
        Ok(None) => bail!("WS connection closed before receiving echo"),
        Err(_) => bail!("Timeout waiting for echo response"),
    }
}

/// Require a Close frame (not an abrupt end) within the timeout.
async fn expect_close_frame(ws: &mut WsStream, context: &str) -> Result<()> {
    match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
        Ok(Some(Ok(Message::Close(_)))) => {
            tracing::info!("WS client received the {context} close");
            Ok(())
        }
        Ok(Some(Ok(msg))) => bail!("Expected Close message, got {msg:?}"),
        Ok(Some(Err(e))) => bail!("WS error waiting for close: {e}"),
        Ok(None) => bail!("WS connection ended without a Close frame"),
        Err(_) => bail!("Timeout waiting for {context} close"),
    }
}

pub async fn launch_ws_client(
    token: CancellationToken,
    host: &str,
    port: u16,
    proxy: Option<String>,
    subprotocol: Option<&'static str>,
    close_mode: WsCloseMode,
) -> Result<JoinHandle<Result<()>>> {
    let host = host.to_owned();

    Ok(tokio::task::spawn(async move {
        let _drop_guard = token.drop_guard();

        let mut ws = dial_backend_ws(&host, port, proxy.as_deref(), subprotocol).await?;
        // The backend echoes an offered subprotocol in its greeting (see
        // `ws_server`), so the expected text grows with the offer.
        let expected_greeting = match subprotocol {
            Some(subprotocol) => format!("{WS_TEST_MESSAGE} {subprotocol}"),
            None => WS_TEST_MESSAGE.to_owned(),
        };
        expect_greeting(&mut ws, &expected_greeting).await?;

        match close_mode {
            WsCloseMode::None => {
                echo_round_trip(&mut ws).await?;
            }
            WsCloseMode::ExpectServerClose => {
                expect_close_frame(&mut ws, "backend").await?;
            }
            WsCloseMode::InitiateAndRequireEcho => {
                echo_round_trip(&mut ws).await?;
                // Start the close handshake; the tunnel must finish it with
                // a Close frame on the way back.
                ws.send(Message::Close(None)).await?;
                tracing::info!("WS client sent close");
                expect_close_frame(&mut ws, "close echo").await?;
            }
        }

        tracing::info!("WS client test passed ({close_mode:?})");
        Ok(())
    }))
}
