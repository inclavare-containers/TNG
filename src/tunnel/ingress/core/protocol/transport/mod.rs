use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::Result;
use http::HttpTransportLayer;
use hyper_util::rt::TokioIo;
use pin_project::pin_project;
use tcp::TcpTransportLayer;
use tokio::net::TcpStream;
use tokio_graceful::ShutdownGuard;
use tracing::Span;

use crate::{
    config::ingress::EncapInHttp,
    tunnel::{ingress::core::TngEndpoint, utils::h2_stream::H2Stream},
};

mod http;
mod tcp;

pub struct TransportLayerCreator {
    so_mark: u32,
    encap_in_http: Option<EncapInHttp>,
}

impl TransportLayerCreator {
    pub fn new(so_mark: u32, encap_in_http: Option<EncapInHttp>) -> Self {
        Self {
            so_mark,
            encap_in_http,
        }
    }

    pub fn create(
        &self,
        dst: &TngEndpoint,
        shutdown_guard: ShutdownGuard,
        parent_span: Span,
    ) -> TransportLayerConnector {
        match &self.encap_in_http {
            Some(encap_in_http) => TransportLayerConnector::Http(HttpTransportLayer {
                dst: dst.clone(),
                so_mark: self.so_mark,
                _encap_in_http: encap_in_http.clone(),
                shutdown_guard,
                transport_layer_span: tracing::info_span!(parent: parent_span, "transport", type = "h2"),
            }),
            None => TransportLayerConnector::Tcp(TcpTransportLayer {
                dst: dst.clone(),
                so_mark: self.so_mark,
                transport_layer_span: tracing::info_span!(parent: parent_span, "transport", type = "tcp"),
            }),
        }
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
