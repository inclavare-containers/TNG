use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{bail, Context as _, Result};
use extra_data::HttpPoolKeyExtraData;
use http::{Request, Uri};
use hyper_util::rt::TokioIo;
use path_rewrite::PathRewriteGroup;
use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

use crate::{
    config::ingress::EncapInHttp,
    observability::trace::shutdown_guard_ext::ShutdownGuardExt,
    tunnel::{
        ingress::core::{protocol::security::pool::PoolKey, TngEndpoint},
        utils::{h2_stream::H2Stream, socket::tcp_connect_with_so_mark},
    },
};

use super::{TransportLayerCreatorTrait, TransportLayerStream};

mod extra_data;
mod path_rewrite;

pub struct HttpTransportLayerCreator {
    so_mark: u32,
    path_rewrite_group: PathRewriteGroup,
}

impl HttpTransportLayerCreator {
    pub fn new(so_mark: u32, encap_in_http: EncapInHttp) -> Result<Self> {
        Ok(Self {
            so_mark,
            path_rewrite_group: PathRewriteGroup::new(encap_in_http.path_rewrites)?,
        })
    }
}

impl TransportLayerCreatorTrait for HttpTransportLayerCreator {
    type TransportLayerConnector = HttpTransportLayer;

    fn create(
        &self,
        pool_key: &PoolKey,
        shutdown_guard: ShutdownGuard,
        parent_span: Span,
    ) -> Result<HttpTransportLayer> {
        Ok(HttpTransportLayer {
            dst: pool_key.get_endpoint().clone(),
            extra_data: pool_key
                .get_extra_data::<HttpPoolKeyExtraData>()
                .context("Failed to get the extra data from the pool key")?
                .clone(),
            so_mark: self.so_mark,
            shutdown_guard,
            transport_layer_span: tracing::info_span!(parent: parent_span, "transport", type = "h2"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct HttpTransportLayer {
    dst: TngEndpoint,
    extra_data: HttpPoolKeyExtraData,
    so_mark: u32,
    shutdown_guard: ShutdownGuard,
    transport_layer_span: Span,
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
        let dst = self.dst.clone();
        let extra_data = self.extra_data.clone();
        let shutdown_guard = self.shutdown_guard.clone();

        let fut = async move {
            tracing::debug!("Establish the underlying h2 stream with upstream");

            // TODO: reuse the same tcp stream for all the h2 streams
            let (recv_stream, send_stream) = async {
                let tcp_stream =
                    tcp_connect_with_so_mark((dst.host(), dst.port()), so_mark).await?;

                let (mut sender, conn) = h2::client::handshake(tcp_stream).await?;
                {
                    shutdown_guard.spawn_task_current_span(async move {
                        if let Err(e) = conn.await {
                            tracing::error!(?e, "The H2 connection is broken");
                        }
                    });
                }

                let req = Request::builder()
                    .uri(
                        Uri::builder()
                            .scheme("http")
                            .authority(extra_data.authority)
                            .path_and_query(extra_data.path)
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
