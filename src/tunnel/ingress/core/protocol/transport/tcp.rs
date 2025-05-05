use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{anyhow, Context as _, Result};
use hyper_util::rt::TokioIo;
use socket2::{Domain, Socket, Type};
use tokio::net::TcpSocket;
use tracing::{Instrument, Span};

use crate::tunnel::ingress::core::TngEndpoint;

use super::TransportLayerStream;

#[derive(Debug, Clone)]
pub struct TcpTransportLayer {
    pub dst: TngEndpoint,
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
        let dst = self.dst.to_owned();

        let fut = async move {
            tracing::debug!("Establish the underlying tcp connection with upstream");

            let tcp_stream = async {
                let addrs = tokio::net::lookup_host((dst.host(), dst.port())).await?;

                let mut last_result = None;
                for addr in addrs {
                    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
                    socket.set_nonblocking(true)?;
                    #[cfg(not(target_os = "macos"))]
                    socket.set_mark(so_mark)?; // Prevent from been redirected by iptables
                    let socket = TcpSocket::from_std_stream(socket.into());

                    let result = socket.connect(addr).await.map_err(anyhow::Error::from);
                    if result.is_ok() {
                        last_result = Some(result);
                        break;
                    }
                    last_result = Some(result);
                }

                last_result.unwrap_or_else(|| Err(anyhow!("No address resolved")))
            }
            .await
            .context("Failed to establish the underlying tcp connection for rats-tls")?;

            Ok(TokioIo::new(TransportLayerStream::Tcp(tcp_stream)))
        }
        .instrument(self.transport_layer_span.clone());

        Box::pin(fut)
    }
}
