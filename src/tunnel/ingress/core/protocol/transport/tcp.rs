use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{bail, Context as _, Result};
use hyper_util::rt::TokioIo;
use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

use crate::tunnel::{
    ingress::core::protocol::security::pool::PoolKey,
    utils::{http_inspector::RequestInfo, socket::tcp_connect_with_so_mark},
};

use super::{
    extra_data::PoolKeyExtraDataInserter, TransportLayerCreatorTrait, TransportLayerStream,
};

pub struct TcpTransportLayerCreator {
    so_mark: u32,
}

impl TcpTransportLayerCreator {
    pub fn new(so_mark: u32) -> Self {
        Self { so_mark }
    }
}

impl TransportLayerCreatorTrait for TcpTransportLayerCreator {
    type TransportLayerConnector = TcpTransportLayer;

    fn create(
        &self,
        pool_key: &PoolKey,
        _shutdown_guard: ShutdownGuard,
        parent_span: Span,
    ) -> Result<TcpTransportLayer> {
        Ok(TcpTransportLayer {
            pool_key: pool_key.clone(),
            so_mark: self.so_mark,
            transport_layer_span: tracing::info_span!(parent: parent_span, "transport", type = "tcp"),
        })
    }
}

impl PoolKeyExtraDataInserter for TcpTransportLayerCreator {
    fn need_to_insert_extra_data(&self) -> bool {
        false
    }

    fn insert_extra_data_to_pool_key(
        &self,
        _request_info: &RequestInfo,
        _target_pool_key: &mut PoolKey,
    ) -> Result<()> {
        bail!("TCP Transport layer creator does not need to insert extra data to the pool key.")
    }
}

#[derive(Debug, Clone)]
pub struct TcpTransportLayer {
    pub pool_key: PoolKey,
    pub so_mark: u32,
    pub transport_layer_span: Span,
}

impl<Req> tower::Service<Req> for TcpTransportLayer {
    type Response = TokioIo<TransportLayerStream>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, _: Req) -> Self::Future {
        let so_mark = self.so_mark;
        let dst = self.pool_key.get_endpoint().to_owned();

        let fut = async move {
            tracing::debug!("Establish the underlying tcp connection with upstream");

            let tcp_stream = tcp_connect_with_so_mark((dst.host(), dst.port()), so_mark)
                .await
                .context("Failed to establish the underlying tcp connection for rats-tls")?;

            Ok(TokioIo::new(TransportLayerStream::Tcp(tcp_stream)))
        }
        .instrument(self.transport_layer_span.clone());

        Box::pin(fut)
    }
}
