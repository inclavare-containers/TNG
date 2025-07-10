use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::Result;
use extra_data::PoolKeyExtraDataInserter;
use http::{HttpTransportLayer, HttpTransportLayerCreator};
use pin_project::pin_project;
#[cfg(feature = "unix")]
use tcp::{TcpTransportLayer, TcpTransportLayerCreator};
use tokio_graceful::ShutdownGuard;
use tracing::Span;

use crate::{
    config::ingress::EncapInHttp,
    tunnel::{
        stream::CommonStreamTrait,
        utils::{http_inspector::RequestInfo, tokio::TokioIo},
    },
};

use super::security::pool::PoolKey;

pub mod extra_data;
mod http;
#[cfg(feature = "unix")]
mod tcp;

pub trait TransportLayerCreatorTrait: PoolKeyExtraDataInserter {
    type TransportLayerConnector;

    fn create(
        &self,
        pool_key: &PoolKey,
        shutdown_guard: ShutdownGuard,
        parent_span: Span,
    ) -> Result<Self::TransportLayerConnector>;
}

/// The transport layer creator is used to create the transport layer.
///
/// This struct is just a enum wrapper of the real implementation of transport layer creator. By design, each transport layer creator should implement the TransportLayerCreatorTrait.
pub enum TransportLayerCreator {
    #[cfg(feature = "unix")]
    Tcp(TcpTransportLayerCreator),
    Http(HttpTransportLayerCreator),
}

impl TransportLayerCreator {
    pub fn new(so_mark: Option<u32>, encap_in_http: Option<EncapInHttp>) -> Result<Self> {
        Ok(match encap_in_http {
            Some(encap_in_http) => {
                Self::Http(HttpTransportLayerCreator::new(so_mark, encap_in_http)?)
            }
            None => {
                #[cfg(feature = "unix")]
                {
                    Self::Tcp(TcpTransportLayerCreator::new(so_mark))
                }

                #[cfg(not(feature = "unix"))]
                {
                    use anyhow::bail;
                    bail!("Tcp transport layer is not supported on this platform.")
                }
            }
        })
    }
}

impl TransportLayerCreatorTrait for TransportLayerCreator {
    type TransportLayerConnector = TransportLayerConnector;
    fn create(
        &self,
        pool_key: &PoolKey,
        shutdown_guard: ShutdownGuard,
        parent_span: Span,
    ) -> Result<TransportLayerConnector> {
        Ok(match self {
            #[cfg(feature = "unix")]
            TransportLayerCreator::Tcp(creater) => TransportLayerConnector::Tcp(creater.create(
                pool_key,
                shutdown_guard,
                parent_span,
            )?),
            TransportLayerCreator::Http(creater) => TransportLayerConnector::Http(creater.create(
                pool_key,
                shutdown_guard,
                parent_span,
            )?),
        })
    }
}

impl PoolKeyExtraDataInserter for TransportLayerCreator {
    fn need_to_insert_extra_data(&self) -> bool {
        match self {
            #[cfg(feature = "unix")]
            TransportLayerCreator::Tcp(creater) => creater.need_to_insert_extra_data(),
            TransportLayerCreator::Http(creater) => creater.need_to_insert_extra_data(),
        }
    }

    fn insert_extra_data_to_pool_key(
        &self,
        request_info: &RequestInfo,
        target_pool_key: &mut PoolKey,
    ) -> Result<()> {
        match self {
            #[cfg(feature = "unix")]
            TransportLayerCreator::Tcp(creater) => {
                creater.insert_extra_data_to_pool_key(request_info, target_pool_key)
            }
            TransportLayerCreator::Http(creater) => {
                creater.insert_extra_data_to_pool_key(request_info, target_pool_key)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum TransportLayerConnector {
    #[cfg(feature = "unix")]
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
            #[cfg(feature = "unix")]
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
            #[cfg(feature = "unix")]
            TransportLayerConnector::Tcp(tcp_transport_layer) => tcp_transport_layer.call(req),
            TransportLayerConnector::Http(http_transport_layer) => http_transport_layer.call(req),
        }
    }
}

#[pin_project(project = TransportLayerStreamProj)]
pub enum TransportLayerStream {
    #[cfg(feature = "unix")]
    Tcp(#[pin] tokio::net::TcpStream),
    Http(#[pin] Box<dyn CommonStreamTrait>),
}

impl hyper_util::client::legacy::connect::Connection for TransportLayerStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        match self {
            #[cfg(feature = "unix")]
            TransportLayerStream::Tcp(tcp_stream) => tcp_stream.connected(),
            TransportLayerStream::Http(_h2_stream) => {
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
            #[cfg(feature = "unix")]
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
            #[cfg(feature = "unix")]
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
            #[cfg(feature = "unix")]
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
            #[cfg(feature = "unix")]
            TransportLayerStreamProj::Tcp(tcp_stream) => {
                tokio::io::AsyncRead::poll_read(tcp_stream, cx, buf)
            }
            TransportLayerStreamProj::Http(duplex_stream) => {
                tokio::io::AsyncRead::poll_read(duplex_stream, cx, buf)
            }
        }
    }
}
