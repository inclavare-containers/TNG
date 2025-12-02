use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{Context as _, Result};
use tracing::{Instrument, Span};

use super::security::pool::PoolKey;
use crate::tunnel::utils::{socket::tcp_connect, tokio::TokioIo};

/// The transport layer creator is used to create the transport layer.
pub struct RatsTlsTransportLayerCreator {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    so_mark: Option<u32>,
}

impl RatsTlsTransportLayerCreator {
    pub fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        so_mark: Option<u32>,
    ) -> Self {
        Self {
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            so_mark,
        }
    }
}

impl RatsTlsTransportLayerCreator {
    pub fn create(
        &self,
        pool_key: &PoolKey,
        parent_span: Span,
    ) -> Result<RatsTlsTransportLayerConnector> {
        Ok(RatsTlsTransportLayerConnector {
            pool_key: pool_key.clone(),
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            so_mark: self.so_mark,
            transport_layer_span: tracing::info_span!(parent: parent_span, "transport", type = "rats-tls"),
        })
    }
}

// TODO: The connector will be cloned each time when we clone the hyper http client. Maybe we can replace it with std::borrow::Cow to save memory.
#[derive(Debug, Clone)]
pub struct RatsTlsTransportLayerConnector {
    pub pool_key: PoolKey,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub so_mark: Option<u32>,
    pub transport_layer_span: Span,
}

impl<Req> tower::Service<Req> for RatsTlsTransportLayerConnector {
    type Response = TokioIo<tokio::net::TcpStream>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, _: Req) -> Self::Future {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        let so_mark = self.so_mark;
        let dst = self.pool_key.get_endpoint().to_owned();

        let fut = async move {
            tracing::debug!("Establishing the underlying tcp connection with upstream");

            let tcp_stream = tcp_connect(
                (dst.host(), dst.port()),
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                so_mark,
            )
            .await
            .context("Failed to establish the underlying tcp connection for rats-tls")?;

            Ok(TokioIo::new(tcp_stream))
        }
        .instrument(self.transport_layer_span.clone());

        Box::pin(fut)
    }
}
