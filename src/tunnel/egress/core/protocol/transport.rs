use std::pin::Pin;

use crate::{config::egress::DecapFromHttp, tunnel::utils::h2_stream::H2Stream};

use anyhow::{Context as _, Result};
use futures::Stream;
use http::{HeaderValue, Response, StatusCode};
use pin_project::pin_project;
use std::task::{Context, Poll};
use tokio::{io::DuplexStream, net::TcpStream};

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
    ) -> Result<impl Stream<Item = Result<TransportLayerStream>>> {
        let state = match &self.decap_from_http {
            Some(decap_from_http) => {
                let connection = h2::server::handshake(in_stream).await?;
                DecodeStreamState::Http(connection, decap_from_http.clone())
            }
            None => DecodeStreamState::Tcp(in_stream),
        };

        let next_stream = futures::stream::unfold(Some(state), |state| async move {
            match state {
                Some(DecodeStreamState::Tcp(tcp_stream)) => {
                    Some((Ok(TransportLayerStream::Tcp(tcp_stream)), None))
                }
                Some(DecodeStreamState::Http(mut connection, decap_from_http)) => {
                    // Accept all inbound HTTP/2 streams sent over the connection.
                    if let Some(request) = connection.accept().await {
                        let result = async {
                            let (request, mut send_response) =
                                request.context("Failed to accept request")?;

                            let (parts, recv_stream) = request.into_parts();
                            tracing::debug!("Accepted request: {:?}", parts);

                            // Send a response back to the client
                            let send_stream = send_response.send_response(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(http::header::SERVER, HeaderValue::from_static("tng"))
                                    .body(())?,
                                false,
                            )?;

                            let local = H2Stream::work_on(send_stream, recv_stream).await?;

                            Ok(TransportLayerStream::Http(local))
                        }
                        .await;

                        let next_state = Some(DecodeStreamState::Http(connection, decap_from_http));

                        Some((result, next_state))
                    } else {
                        None
                    }
                }
                None => return None,
            }
        });

        Ok(Box::pin(next_stream))
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
    Http(#[pin] DuplexStream),
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
