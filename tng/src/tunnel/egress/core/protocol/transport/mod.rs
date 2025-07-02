use std::{pin::Pin, time::Duration};

use crate::{
    config::egress::{DecapFromHttp, DirectForwardRules},
    observability::trace::shutdown_guard_ext::ShutdownGuardExt,
    tunnel::{
        stream::CommonStreamTrait,
        utils::{
            h2_stream::H2Stream,
            http_inspector::{HttpRequestInspector, InspectionResult, RequestInfo},
        },
    },
};

use anyhow::{bail, Context as _, Result};
use direct_forward::DirectForwardTrafficDetector;
use futures::Stream;
use http::{HeaderValue, Response, StatusCode};
use pin_project::pin_project;
use std::task::{Context, Poll};
use timeout::FirstByteReadTimeoutStream;
use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

mod direct_forward;
mod direct_response;
mod timeout;

/// Timeout before we receive first byte from peer, This is essential to make it fasts fail quickly when a none tng client is connected to tng server unexpectedly.
const TRANSPORT_LAYER_READ_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TransportLayer {
    typ: TransportLayerType,
    direct_forward_traffic_detector: Option<DirectForwardTrafficDetector>,
}

pub enum TransportLayerType {
    Tcp,
    Http,
}

impl TransportLayer {
    pub fn new(
        direct_forward: Option<DirectForwardRules>,
        decap_from_http: Option<DecapFromHttp>,
    ) -> Result<Self> {
        let typ = match &decap_from_http {
            Some(_) => TransportLayerType::Http,
            None => TransportLayerType::Tcp,
        };

        // For compatibility with older versions
        let direct_forward = if let Some(decap_from_http) = decap_from_http {
            match (
                direct_forward,
                decap_from_http.allow_non_tng_traffic_regexes,
            ) {
                (Some(_), Some(_)) => {
                    bail!("Cannot specify both `direct_forward` and `decap_from_http.allow_non_tng_traffic_regexes`. The later is deprecated, please use `direct_forward` instead.");
                }
                (None, Some(allow_non_tng_traffic_regexes)) => {
                    tracing::warn!("`allow_non_tng_traffic_regexes` is deprecated, please use `direct_forward` instead.");
                    Some(DirectForwardRules::from(allow_non_tng_traffic_regexes))
                }
                (direct_forward, None) => direct_forward,
            }
        } else {
            direct_forward
        };

        let direct_forward_traffic_detector = match direct_forward {
            Some(direct_forward) => Some(DirectForwardTrafficDetector::new(direct_forward)?),
            None => None,
        };

        Ok(Self {
            typ,
            direct_forward_traffic_detector,
        })
    }
}

impl TransportLayer {
    pub async fn decode(
        &self,
        in_stream: Box<dyn CommonStreamTrait>,
        shutdown_guard: ShutdownGuard,
    ) -> Result<impl Stream<Item = Result<DecodeResult>> + '_> {
        let span = tracing::info_span!("transport", type={match self.typ {
            TransportLayerType::Tcp => "tcp",
            TransportLayerType::Http => "h2",
        }});

        // Set timeout for underly tcp stream
        let in_stream = {
            Box::pin(FirstByteReadTimeoutStream::new(
                in_stream,
                TRANSPORT_LAYER_READ_FIRST_BYTE_TIMEOUT,
            ))
        };

        async {
            let span = span.clone();

            tracing::debug!(
                direct_forward_detect_enabled = self.direct_forward_traffic_detector.is_some(),
                "Decoding the underlying connection from downstream"
            );

            let state = if let Some(direct_forward_traffic_detector) =
                &self.direct_forward_traffic_detector
            {
                // First, we need to detect if it is a HTTP connection or a HTTP/2 connection.
                let InspectionResult {
                    unmodified_stream,
                    result,
                } = HttpRequestInspector::inspect_stream(in_stream).await;
                let request_info =
                    result.context("Failed during inspecting http request from downstream")?;

                let unmodified_stream = Box::new(unmodified_stream) as Box<dyn CommonStreamTrait>;

                // If it should be forwarded directly, we just do that.
                if direct_forward_traffic_detector.should_forward_directly(&request_info) {
                    // Bypass the security layer and wrapping layer, forward the stream to upstream directly.
                    tracing::debug!("Forwarding directly");
                    DecodeStreamState::DirectlyForward(unmodified_stream)
                } else {
                    tracing::debug!("Try to decode as TNG traffic");
                    // If not, we try to treat it as tng traffic, it is determined by the configuration of transport layer.
                    match self.typ {
                        // If the transport layer is configured to tcp, we just use it.
                        TransportLayerType::Tcp => DecodeStreamState::Tcp(unmodified_stream),
                        // If the transport layer is configured to h2, we need to check the http request.
                        TransportLayerType::Http => {
                            match request_info {
                                RequestInfo::Http1 { .. } => {
                                    // It must not be a tng traffic, since tng traffic must be HTTP/2 when the transport layer is configured to h2. Here we send a notice message as response to downstream
                                    direct_response::send_http1_response_to_non_tng_client(
                                        shutdown_guard,
                                        unmodified_stream,
                                    )
                                    .await?;
                                    DecodeStreamState::NoMoreStreams
                                }
                                RequestInfo::Http2 { .. } => {
                                    // It may be a tng traffic, so we treat it as a valid tng traffic and try to decode from it.
                                    let connection =
                                        h2::server::handshake(unmodified_stream).await?;
                                    DecodeStreamState::Http(H2ConnectionGracefulShutdown::new(
                                        connection,
                                        shutdown_guard,
                                        span.clone(),
                                    ))
                                }
                                RequestInfo::UnknownProtocol => {
                                    // The transport layer is configured to h2 but it is a UnknownProtocol.
                                    bail!("Not valid TNG protocol")
                                }
                            }
                        }
                    }
                }
            } else {
                let in_stream = Box::new(in_stream) as Box<dyn CommonStreamTrait>;

                match self.typ {
                    TransportLayerType::Tcp => DecodeStreamState::Tcp(in_stream),
                    TransportLayerType::Http => {
                        // Treat it as a valid tng traffic and try to decode from it.
                        let connection = h2::server::handshake(in_stream).await?;
                        DecodeStreamState::Http(H2ConnectionGracefulShutdown::new(
                            connection,
                            shutdown_guard,
                            span.clone(),
                        ))
                    }
                }
            };

            let next_stream = futures::stream::unfold(state, move |state| {
                async move {
                    match state {
                        DecodeStreamState::Tcp(tcp_stream) => {
                            tracing::debug!("New tcp stream established with downstream");
                            Some((
                                Ok(DecodeResult::ContinueAsTngTraffic(
                                    TransportLayerStream::Tcp(tcp_stream),
                                )),
                                DecodeStreamState::NoMoreStreams,
                            ))
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

                                        Ok(DecodeResult::ContinueAsTngTraffic(
                                            TransportLayerStream::Http(H2Stream::new(
                                                send_stream,
                                                recv_stream,
                                                Span::current(),
                                            )),
                                        ))
                                    }
                                    .await
                                    .context("failed to handle h2 request");

                                    let next_state = DecodeStreamState::Http(connection);
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
                        DecodeStreamState::DirectlyForward(stream) => Some((
                            Ok(DecodeResult::DirectlyForward(stream)),
                            DecodeStreamState::NoMoreStreams,
                        )),
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

enum DecodeStreamState {
    Tcp(Box<dyn CommonStreamTrait>),
    Http(H2ConnectionGracefulShutdown<Box<dyn CommonStreamTrait>, bytes::Bytes>),
    DirectlyForward(Box<dyn CommonStreamTrait>),
    NoMoreStreams,
}

pub enum DecodeResult {
    ContinueAsTngTraffic(TransportLayerStream),
    DirectlyForward(Box<dyn CommonStreamTrait>),
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
            .spawn_supervised_task_with_span(self.span.clone(), async move {
                conn.graceful_shutdown();

                if let Err(error) = core::future::poll_fn(|cx| conn.poll_closed(cx)).await {
                    tracing::debug!(?error, "Failed to gracefully shutdown h2 connection");
                };
            });
    }
}

#[pin_project(project = TransportLayerStreamProj)]
pub enum TransportLayerStream {
    Tcp(#[pin] Box<dyn CommonStreamTrait>),
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
