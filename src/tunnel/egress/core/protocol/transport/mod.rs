use std::pin::Pin;

use crate::{
    config::egress::DecapFromHttp, observability::trace::shutdown_guard_ext::ShutdownGuardExt,
    tunnel::utils::{h2_stream::H2Stream, http_inspector::{HttpRequestInspector, InspectionResult, RequestInfo}},
};

use anyhow::{bail, Context as _, Result};
use futures::Stream;
use http::{HeaderValue, Response, StatusCode};
use non_tng_traffic::DirectlyForwardTrafficDetector;
use pin_project::pin_project;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

mod non_tng_traffic;
mod direct_response;


pub enum TransportLayer {
    Tcp,
    Http(DirectlyForwardTrafficDetector),
}

impl TransportLayer {
    pub fn new(decap_from_http: Option<DecapFromHttp>) -> Result<Self> {
        Ok(match decap_from_http {
            Some(decap_from_http) => {
                TransportLayer::Http(DirectlyForwardTrafficDetector::new(&decap_from_http)?)
            }
            None => TransportLayer::Tcp,
        })
    }
}

impl TransportLayer {
    pub async fn decode(
        &self,
        in_stream: TcpStream,
        shutdown_guard: ShutdownGuard,
    ) -> Result<impl Stream<Item = Result<DecodeResult<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>>> + '_> {
        let span = tracing::info_span!("transport", type={match self {
            TransportLayer::Tcp => "tcp",
            TransportLayer::Http(..) => "h2",
        }});

        async {
            let span = span.clone();

            tracing::debug!("Decode the underlying connection from downstream");
            let state = match self {
                TransportLayer::Tcp => DecodeStreamState::Tcp(in_stream),
                TransportLayer::Http(directly_forward_traffic_detector) => {
                    // First, we need to detect if it is a HTTP connection or a HTTP/2 connection.
                    let InspectionResult {
                        unmodified_stream,
                        result,
                    } = HttpRequestInspector::inspect_stream(in_stream).await;
                    let request_info =
                        result.context("Failed to inspect http request from downstream, maybe not a valid tng traffic")?;
    
                    match request_info {
                        RequestInfo::Http1 {  path, .. } => { // It must not be a tng traffic, since tng traffic must be HTTP/2.
                            if directly_forward_traffic_detector.should_forward_directly(&path) {
                                // Bypass the security layer and wrapping layer, forward the stream to upstream directly.
                                DecodeStreamState::DirectlyForward(unmodified_stream)
                            }else{
                                // Send a notice message as response to downstream
                                direct_response::send_http1_response_to_non_tng_client(shutdown_guard, unmodified_stream).await?;
                                DecodeStreamState::NoMoreStreams
                            }
                        },
                        RequestInfo::Http2 {  path, ..  } => {
                            // It may be a tng traffic, but we still need to check if it with NonTngTrafficDetector
                            if directly_forward_traffic_detector.should_forward_directly(&path) {
                                // Though it is a HTTP2, we have to bypass the security layer and wrapping layer, forward the stream to upstream directly.
                                DecodeStreamState::DirectlyForward(unmodified_stream)
                            }else{
                                // Treat it as a valid tng traffic and try to decode from it.
                                let connection = h2::server::handshake(unmodified_stream).await?;
                                DecodeStreamState::Http(
                                    H2ConnectionGracefulShutdown::new(connection, shutdown_guard, span.clone()),
                                )
                            }
                        },
                    }
                }
            };

            let next_stream = futures::stream::unfold(state, move |state| {
                async move {
                    match state {
                        DecodeStreamState::Tcp(tcp_stream) => {
                            tracing::debug!("New tcp stream established with downstream");
                            Some((Ok(DecodeResult::ContinueAsTngTraffic(TransportLayerStream::Tcp(tcp_stream))), DecodeStreamState::NoMoreStreams))
                        }
                        DecodeStreamState::Http(mut connection) => {
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

                                        Ok(DecodeResult::ContinueAsTngTraffic(TransportLayerStream::Http(H2Stream::new(
                                            send_stream,
                                            recv_stream,
                                            Span::current(),
                                        ))))
                                    }
                                    .await
                                    .context("failed to handle h2 request");

                                    let next_state = DecodeStreamState::Http(
                                        connection,
                                    );
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
                                            DecodeStreamState::NoMoreStreams,
                                        ))
                                    }
                                }
                                None => {
                                    // The .accept() function reports that no more streams will be generated
                                    None
                                }
                            }
                        }
                        DecodeStreamState::DirectlyForward(stream) => {
                            Some((Ok(DecodeResult::DirectlyForward(stream)), DecodeStreamState::NoMoreStreams))
                        },
                        DecodeStreamState::NoMoreStreams => {
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

enum DecodeStreamState<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> {
    Tcp(TcpStream),
    Http(
        H2ConnectionGracefulShutdown<T, bytes::Bytes>
    ),
    DirectlyForward(T),
    NoMoreStreams,
}

pub enum DecodeResult<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>{
    ContinueAsTngTraffic(TransportLayerStream),
    DirectlyForward(T)
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
