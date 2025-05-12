use std::pin::Pin;

use crate::{
    config::egress::DecapFromHttp, observability::trace::shutdown_guard_ext::ShutdownGuardExt,
    tunnel::utils::h2_stream::H2Stream,
};

use anyhow::{bail, Context as _, Result};
use futures::Stream;
use http::{HeaderValue, Response, StatusCode};
use pin_project::pin_project;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

pub struct TransportLayerDecoder {
    decap_from_http: Option<DecapFromHttp>,
}

impl TransportLayerDecoder {
    pub fn new(decap_from_http: Option<DecapFromHttp>) -> Self {
        Self { decap_from_http }
    }
}

impl TransportLayerDecoder {
    pub async fn decode(
        &self,
        in_stream: TcpStream,
        shutdown_guard: ShutdownGuard,
    ) -> Result<impl Stream<Item = Result<TransportLayerStream>> + '_> {
        let span = tracing::info_span!("transport", type={if self.decap_from_http.is_some() {"h2"} else {"tcp"}});

        async {
            let span = span.clone();

            tracing::debug!("Decode the underlying connection from downstream");
            let state = match &self.decap_from_http {
                Some(decap_from_http) => {
                    let connection = h2::server::handshake(in_stream).await?;
                    DecodeStreamState::Http(
                        H2ConnectionGracefulShutdown::new(connection, shutdown_guard, span.clone()),
                        decap_from_http.clone(),
                    )
                }
                None => DecodeStreamState::Tcp(in_stream),
            };

            let next_stream = futures::stream::unfold(Some(state), move |state| {
                async move {
                    match state {
                        Some(DecodeStreamState::Tcp(tcp_stream)) => {
                            tracing::debug!("New tcp stream established with downstream");
                            Some((Ok(TransportLayerStream::Tcp(tcp_stream)), None))
                        }
                        Some(DecodeStreamState::Http(mut connection, decap_from_http)) => {
                            let Some(h2_connection) = connection.h2_connection_mut() else {
                                // The connection object is dropped
                                return None;
                            };

                            // Accept all inbound HTTP/2 streams sent over the connection.
                            match h2_connection.accept().await {
                                Some(Ok((request, mut send_response))) => {
                                    let result = async {
                                        let (parts, recv_stream) = request.into_parts();
                                        tracing::trace!("Accepted h2 request: {:?}", parts);

                                        if !parts.headers.contains_key("tng") {
                                            bail!("TNG protocol error: invalid request")
                                        }

                                        // Send a response back to the client
                                        let send_stream = send_response.send_response(
                                            Response::builder()
                                                .status(StatusCode::OK)
                                                .header(
                                                    http::header::SERVER,
                                                    HeaderValue::from_static("tng"),
                                                )
                                                .body(())?,
                                            false,
                                        )?;

                                        tracing::debug!(
                                            "New h2 stream established with downstream"
                                        );

                                        Ok(TransportLayerStream::Http(H2Stream::new(
                                            send_stream,
                                            recv_stream,
                                            Span::current(),
                                        )))
                                    }
                                    .await
                                    .context("failed to handle h2 request");

                                    let next_state =
                                        Some(DecodeStreamState::Http(connection, decap_from_http));
                                    Some((result, next_state))
                                }
                                Some(Err(err)) => {
                                    // Note that once we got an error from accept(), we should not accept more h2 streams

                                    if err.is_go_away() {
                                        // The h2 connection is in goaway state, so we should stop on this connection.
                                        tracing::debug!(
                                            "The h2 connection is closed, stop decoding"
                                        );
                                        None
                                    } else if err
                                        .get_io()
                                        .map(|io_error| {
                                            io_error.kind() == std::io::ErrorKind::NotConnected
                                        })
                                        .unwrap_or(false)
                                    {
                                        // The underlaying io is closed by remote peer, we just print it and stop.
                                        tracing::debug!(
                                            "The underlaying io is closed by remote, stop decoding"
                                        );
                                        None
                                    } else {
                                        // On other not well known errors, report to the caller
                                        Some((
                                            Err(err).context(
                                                "Failed to accept request in h2 transport layer",
                                            ),
                                            None,
                                        ))
                                    }
                                }
                                None => {
                                    // The .accept() function reports that no more streams will be generated
                                    None
                                }
                            }
                        }
                        None => {
                            // The state is consumed and no more streams will be generated
                            None
                        }
                    }
                }
                .instrument(span.clone())
            });

            Ok(Box::pin(next_stream))
        }
        .instrument(span.clone())
        .await
    }
}

enum DecodeStreamState {
    Tcp(TcpStream),
    Http(
        H2ConnectionGracefulShutdown<TcpStream, bytes::Bytes>,
        DecapFromHttp,
    ),
}

/// This is a wrapper of h2::server::Connection, which is used to gracefully shutdown the connection.
///
/// Once the connection is dropped, the graceful shutdown will be triggered. First, it will send GOAWAY frame to the client, and then handle all the remaining streams until the h2 connection is fully closed.
struct H2ConnectionGracefulShutdown<
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    B: bytes::Buf + Send + 'static,
> {
    conn: Option<h2::server::Connection<T, B>>,
    shutdown_guard: ShutdownGuard,
    span: Span,
}

impl<
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        B: bytes::Buf + Send + 'static,
    > H2ConnectionGracefulShutdown<T, B>
{
    pub fn new(
        conn: h2::server::Connection<T, B>,
        shutdown_guard: ShutdownGuard,
        span: Span,
    ) -> Self {
        Self {
            conn: Some(conn),
            shutdown_guard,
            span,
        }
    }

    pub fn h2_connection_mut(&mut self) -> Option<&mut h2::server::Connection<T, B>> {
        self.conn.as_mut()
    }
}

impl<
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
        B: bytes::Buf + Send + 'static,
    > Drop for H2ConnectionGracefulShutdown<T, B>
{
    fn drop(&mut self) {
        let Some(mut conn) = self.conn.take() else {
            return;
        };

        self.shutdown_guard
            .spawn_task_with_span(self.span.clone(), async move {
                conn.graceful_shutdown();

                if let Err(error) = core::future::poll_fn(|cx| conn.poll_closed(cx)).await {
                    tracing::debug!(?error, "Failed to gracefully shutdown h2 connection");
                };
            });
    }
}

#[pin_project(project = TransportLayerStreamProj)]
pub enum TransportLayerStream {
    Tcp(#[pin] TcpStream),
    Http(#[pin] H2Stream),
}

impl tokio::io::AsyncWrite for TransportLayerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        match self.project() {
            TransportLayerStreamProj::Tcp(tcp_stream) => {
                tokio::io::AsyncWrite::poll_write(tcp_stream, cx, buf)
            }
            TransportLayerStreamProj::Http(duplex_stream) => {
                tokio::io::AsyncWrite::poll_write(duplex_stream, cx, buf)
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        match self.project() {
            TransportLayerStreamProj::Tcp(tcp_stream) => {
                tokio::io::AsyncWrite::poll_flush(tcp_stream, cx)
            }
            TransportLayerStreamProj::Http(duplex_stream) => {
                tokio::io::AsyncWrite::poll_flush(duplex_stream, cx)
            }
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        match self.project() {
            TransportLayerStreamProj::Tcp(tcp_stream) => {
                tokio::io::AsyncWrite::poll_shutdown(tcp_stream, cx)
            }
            TransportLayerStreamProj::Http(duplex_stream) => {
                tokio::io::AsyncWrite::poll_shutdown(duplex_stream, cx)
            }
        }
    }
}

impl tokio::io::AsyncRead for TransportLayerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.project() {
            TransportLayerStreamProj::Tcp(tcp_stream) => {
                tokio::io::AsyncRead::poll_read(tcp_stream, cx, buf)
            }
            TransportLayerStreamProj::Http(duplex_stream) => {
                tokio::io::AsyncRead::poll_read(duplex_stream, cx, buf)
            }
        }
    }
}
