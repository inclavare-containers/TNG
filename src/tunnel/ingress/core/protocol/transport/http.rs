use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{anyhow, bail, Context as _, Result};
use http::{Request, Uri};
use hyper_util::rt::TokioIo;
use socket2::{Domain, Socket, Type};
use tokio::net::TcpSocket;
use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

use crate::{
    config::ingress::EncapInHttp,
    observability::trace::ShutdownGuardExt,
    tunnel::{ingress::core::TngEndpoint, utils::h2_stream::H2Stream},
};

use super::TransportLayerStream;

#[derive(Debug, Clone)]
pub struct HttpTransportLayer {
    pub dst: TngEndpoint,
    pub so_mark: u32,
    pub _encap_in_http: EncapInHttp,
    pub shutdown_guard: ShutdownGuard,
    pub transport_layer_span: Span,
}

impl<Req> tower::Service<Req> for HttpTransportLayer {
    type Response = TokioIo<TransportLayerStream>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, _: Req) -> Self::Future {
        let so_mark = self.so_mark;
        let dst = self.dst.to_owned();
        let shutdown_guard = self.shutdown_guard.clone();

        let fut = async move {
            tracing::debug!("Establish the underlying h2 stream with upstream");

            // TODO: reuse the same tcp stream for all the h2 streams
            let (recv_stream, send_stream) = async {
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

                let tcp_stream =
                    last_result.unwrap_or_else(|| Err(anyhow!("No address resolved")))?;

                let (mut sender, conn) = h2::client::handshake(tcp_stream).await?;
                {
                    shutdown_guard.spawn_task_current_span(async move {
                        if let Err(e) = conn.await {
                            tracing::error!(?e, "The H2 connection is broken");
                        }
                    });
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

                Ok((response.into_body(), send_stream))
            }
            .await
            .context("Failed to establish the underlying http connection for rats-tls")?;

            return Ok(TokioIo::new(TransportLayerStream::Http(H2Stream::new(
                send_stream,
                recv_stream,
                Span::current(),
            ))));
        }
        .instrument(self.transport_layer_span.clone());

        Box::pin(fut)
    }
}
