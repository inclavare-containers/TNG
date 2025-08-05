use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{Context as _, Result};
use tracing::{Instrument, Span};

use super::security::pool::PoolKey;
use crate::tunnel::utils::{socket::tcp_connect_with_so_mark, tokio::TokioIo};

/// The transport layer creator is used to create the transport layer.
pub struct TcpTransportLayerCreator {
    so_mark: Option<u32>,
}

impl TcpTransportLayerCreator {
    pub fn new(so_mark: Option<u32>) -> Self {
        Self { so_mark }
    }
}

impl TcpTransportLayerCreator {
    pub fn create(
        &self,
        pool_key: &PoolKey,
        parent_span: Span,
    ) -> Result<TcpTransportLayerConnector> {
        Ok(TcpTransportLayerConnector {
            pool_key: pool_key.clone(),
            so_mark: self.so_mark,
            transport_layer_span: tracing::info_span!(parent: parent_span, "transport", type = "tcp"),
        })
    }
}

// TODO: The connector will be cloned each time when we clone the hyper http client. Maybe we can replace it with std::borrow::Cow to save memory.
#[derive(Debug, Clone)]
pub struct TcpTransportLayerConnector {
    pub pool_key: PoolKey,
    pub so_mark: Option<u32>,
    pub transport_layer_span: Span,
}

pub type TcpTransportLayerStream = tokio::net::TcpStream;

impl<Req> tower::Service<Req> for TcpTransportLayerConnector {
    type Response = TokioIo<TcpTransportLayerStream>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, _: Req) -> Self::Future {
        let so_mark = self.so_mark;
        let dst = self.pool_key.get_endpoint().to_owned();

        let fut = async move {
            tracing::debug!("Establishing the underlying tcp connection with upstream");

            let tcp_stream = tcp_connect_with_so_mark((dst.host(), dst.port()), so_mark)
                .await
                .context("Failed to establish the underlying tcp connection for rats-tls")?;

            Ok(TokioIo::new(tcp_stream))
        }
        .instrument(self.transport_layer_span.clone());

        Box::pin(fut)
    }
}
