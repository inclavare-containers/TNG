use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{bail, Context as _, Result};
use http::{Request, Uri};
use hyper_util::rt::TokioIo;
use pin_project::pin_project;
use tokio::net::TcpStream;
use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

use crate::{
    config::ingress::EncapInHttp,
    tunnel::{ingress::core::TngEndpoint, utils::h2_stream::H2Stream},
};

pub struct TransportLayerCreator {
    encap_in_http: Option<EncapInHttp>,
    shutdown_guard: ShutdownGuard,
}

impl TransportLayerCreator {
    pub fn new(encap_in_http: Option<EncapInHttp>, shutdown_guard: ShutdownGuard) -> Self {
        Self {
            encap_in_http,
            shutdown_guard,
        }
    }

    pub fn create(&self, dst: &TngEndpoint) -> TransportLayerConnector {
        match &self.encap_in_http {
            Some(encap_in_http) => TransportLayerConnector::Http(HttpTransportLayer {
                dst: dst.clone(),
                _encap_in_http: encap_in_http.clone(),
                shutdown_guard: self.shutdown_guard.clone(),
            }),
            None => TransportLayerConnector::Tcp(TcpTransportLayer { dst: dst.clone() }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpTransportLayer {
    dst: TngEndpoint,
}

impl<Req> tower::Service<Req> for TcpTransportLayer {
    type Response = TokioIo<TransportLayerStream>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, _: Req) -> Self::Future {
        let endpoint_owned = self.dst.to_owned();
        let fut = async move {
            tracing::debug!("Establish the underlying tcp connection with upstream");

            let tcp_stream = TcpStream::connect((endpoint_owned.host(), endpoint_owned.port()))
                .await
                .context("Failed to establish the underlying tcp connection for rats-tls")?;

            Ok(TokioIo::new(TransportLayerStream::Tcp(tcp_stream)))
        }
        .instrument(tracing::info_span!("transport", type = "tcp"));

        Box::pin(fut)
    }
}

#[derive(Debug, Clone)]
pub struct HttpTransportLayer {
    dst: TngEndpoint,
    _encap_in_http: EncapInHttp,
    shutdown_guard: ShutdownGuard,
}

impl HttpTransportLayer {
    async fn create_internal(
        dst: TngEndpoint,
        shutdown_guard: ShutdownGuard,
    ) -> Result<TokioIo<TransportLayerStream>> {
        // TODO: reuse the same tcp stream for all the h2 streams
        let tcp_stream = TcpStream::connect((dst.host(), dst.port())).await?;

        let (mut sender, conn) = h2::client::handshake(tcp_stream).await?;
        {
            let span = tracing::info_span!("http2_conn");
            shutdown_guard.spawn_task(
                async move {
                    if let Err(e) = conn.await {
                        tracing::warn!(?e, "The H2 connection is broken");
                    }
                }
                .instrument(span),
            );
        }

        // TODO: we need to support path rewrites instead of hard encode the path as '/'
        let req = Request::builder()
            .uri(
                Uri::builder()
                    .scheme("http")
                    .authority(format!("{}:{}", dst.host(), dst.port()))
                    .path_and_query("/")
                    .build()?,
            )
            .method("POST")
            .header("tng", "{}")
            .body(())?;

        let (response, send_stream) = sender.send_request(req, false)?;

        let response = response.await?;

        if response.status() != hyper::StatusCode::OK {
            bail!("unexpected status code: {}", response.status());
        }

        let recv_stream = response.into_body();

        return Ok(TokioIo::new(TransportLayerStream::Http(H2Stream::new(
            send_stream,
            recv_stream,
            Span::current(),
        ))));
    }
}

impl<Req> tower::Service<Req> for HttpTransportLayer {
    type Response = TokioIo<TransportLayerStream>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, _: Req) -> Self::Future {
        let endpoint_owned = self.dst.to_owned();
        let shutdown_guard = self.shutdown_guard.to_owned();

        let fut = async {
            tracing::debug!("Establish the underlying h2 stream with upstream");
            Self::create_internal(endpoint_owned, shutdown_guard).await
        }
        .instrument(tracing::info_span!("transport", type = "h2"));

        Box::pin(fut)
    }
}

#[derive(Debug, Clone)]
pub enum TransportLayerConnector {
    Tcp(TcpTransportLayer),
    Http(HttpTransportLayer),
}

// TODO: The connector will be cloned each time when we clone the hyper http client. Maybe we can replace it with std::borrow::Cow to save memory.

impl<Req> tower::Service<Req> for TransportLayerConnector {
    type Response = TokioIo<TransportLayerStream>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            TransportLayerConnector::Tcp(tcp_transport_layer) => {
                <TcpTransportLayer as tower::Service<Req>>::poll_ready(tcp_transport_layer, context)
            }
            TransportLayerConnector::Http(http_transport_layer) => {
                <HttpTransportLayer as tower::Service<Req>>::poll_ready(
                    http_transport_layer,
                    context,
                )
            }
        }
    }

    fn call(&mut self, req: Req) -> Self::Future {
        match self {
            TransportLayerConnector::Tcp(tcp_transport_layer) => tcp_transport_layer.call(req),
            TransportLayerConnector::Http(http_transport_layer) => http_transport_layer.call(req),
        }
    }
}

#[pin_project(project = TransportLayerStreamProj)]
pub enum TransportLayerStream {
    Tcp(#[pin] TcpStream),
    Http(#[pin] H2Stream),
}

impl hyper_util::client::legacy::connect::Connection for TransportLayerStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        match self {
            TransportLayerStream::Tcp(tcp_stream) => tcp_stream.connected(),
            TransportLayerStream::Http(_duplex_stream) => {
                hyper_util::client::legacy::connect::Connected::new()
            }
        }
    }
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
