use std::net::SocketAddr;

use anyhow::Result;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    http::{header, HeaderMap},
    routing::get,
    Router,
};
use futures::{SinkExt as _, StreamExt};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;

const WS_TEST_MESSAGE: &str = "ws-tng-test";

/// Tokens offered in `Sec-WebSocket-Protocol` lists, in order.
fn offered_subprotocols(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

pub async fn launch_ws_server(
    token: CancellationToken,
    port: u16,
    close_after_greeting: bool,
) -> Result<JoinHandle<Result<()>>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("WS test server listening on 0.0.0.0:{port}");

    Ok(tokio::task::spawn(async move {
        let close = close_after_greeting;
        let app = Router::new()
            .route(
                "/tng/ws-tunnel",
                get(move |headers: HeaderMap, ws: WebSocketUpgrade| async move {
                    // Negotiate (echo) whatever the client offered so a tunnel
                    // can be proven to relay the subprotocol end to end, and
                    // show the negotiated name in the greeting.
                    let offered = offered_subprotocols(&headers);
                    let ws = if offered.is_empty() {
                        ws
                    } else {
                        ws.protocols(offered)
                    };
                    ws.on_upgrade(move |socket| handle_socket(socket, close))
                }),
            )
            // The e2e topology points the egress mapping's out at this single
            // app (ws dials go through the connector like every other
            // protocol), so the plain-HTTP regression shares it: the ws
            // listener also answers ordinary requests.
            .fallback(|| async { super::HTTP_RESPONSE_BODY });

        let server = axum::serve(listener, app);

        tokio::select! {
            _ = token.cancelled() => {}
            res = server => { res?; }
        }

        tracing::info!("The WS test server task normally exited");
        Ok(())
    }))
}

async fn handle_socket(mut socket: WebSocket, close_after_greeting: bool) {
    // Greet with the test token; when a subprotocol was negotiated, its
    // name is appended so the client can see it crossed the tunnel intact.
    let greeting = match socket.protocol() {
        Some(protocol) => format!(
            "{WS_TEST_MESSAGE} {}",
            protocol.to_str().unwrap_or_default()
        ),
        None => WS_TEST_MESSAGE.to_owned(),
    };
    if let Ok(()) = socket.send(Message::Text(greeting.clone().into())).await {
        tracing::info!("WS server sent test message: {greeting}");
    }

    if close_after_greeting {
        // Close mode for the tunnel teardown case: the Close frame must
        // propagate backend -> egress -> ingress -> app.
        let _ = socket.send(Message::Close(None)).await;
        tracing::info!("WS server closed the connection after the greeting");
        return;
    }

    // Echo any messages back
    while let Some(Ok(msg)) = socket.next().await {
        match msg {
            Message::Text(text) => {
                tracing::info!("WS server received text: {text}");
                if socket.send(Message::Text(text)).await.is_err() {
                    break;
                }
            }
            Message::Binary(data) => {
                tracing::info!("WS server received binary data ({} bytes)", data.len());
                if socket.send(Message::Binary(data)).await.is_err() {
                    break;
                }
            }
            Message::Ping(data) => {
                if socket.send(Message::Pong(data)).await.is_err() {
                    break;
                }
            }
            Message::Pong(_) => {}
            Message::Close(_) => {
                // Echo the Close so the app's close handshake completes
                // through the tunnel; a bare break would let the reply
                // depend on tungstenite's auto-close flush timing. The send
                // may fail (SendAfterClosing: the reply is already queued
                // from the read), so the flush is what delivers it.
                let _ = socket.send(Message::Close(None)).await;
                let _ = socket.flush().await;
                break;
            }
        }
    }

    tracing::info!("WS server connection ended");
}
