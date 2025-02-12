use std::pin::Pin;

use crate::{config::egress::DecapFromHttp, tunnel::utils::h2_stream::H2Stream};

use anyhow::{bail, Context as _, Result};
use futures::Stream;
use http::{HeaderValue, Response, StatusCode};
use pin_project::pin_project;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
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
    ) -> Result<impl Stream<Item = Result<TransportLayerStream>> + '_> {
        let span = tracing::info_span!("transport", type={if self.decap_from_http.is_some() {"h2"} else {"tcp"}});
        async {
            let span = span.clone();

            tracing::debug!("Decode the underlying connection from downstream");
            let state = match &self.decap_from_http {
                Some(decap_from_http) => {
                    let connection = h2::server::handshake(in_stream).await?;
                    DecodeStreamState::Http(connection, decap_from_http.clone())
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
                            // Accept all inbound HTTP/2 streams sent over the connection.
                            if let Some(request) = connection.accept().await {
                                let result = async {
                                    let (request, mut send_response) =
                                        request.context("Failed to accept request")?;

                                    let (parts, recv_stream) = request.into_parts();
                                    tracing::trace!("Accepted http request: {:?}", parts);

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

                                    tracing::debug!("New h2 stream established with downstream");

                                    Ok(TransportLayerStream::Http(H2Stream::new(
                                        send_stream,
                                        recv_stream,
                                        Span::current(),
                                    )))
                                }
                                .await
                                .context("Error in transport layer");

                                let next_state =
                                    Some(DecodeStreamState::Http(connection, decap_from_http));

                                Some((result, next_state))
                            } else {
                                None
                            }
                        }
                        None => return None,
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
        h2::server::Connection<TcpStream, bytes::Bytes>,
        DecapFromHttp,
    ),
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
