use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{Context as _, Result};
use extra_data::HttpPoolKeyExtraData;
use path_rewrite::PathRewriteGroup;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{Instrument, Span};

use crate::{
    config::ingress::EncapInHttp,
    tunnel::{
        endpoint::TngEndpoint,
        ingress::core::protocol::security::pool::PoolKey,
        utils::{runtime::TokioRuntime, tokio::TokioIo},
    },
};

use super::{TransportLayerCreatorTrait, TransportLayerStream};

mod extra_data;
mod path_rewrite;

pub struct HttpTransportLayerCreator {
    so_mark: Option<u32>,
    path_rewrite_group: PathRewriteGroup,
    runtime: TokioRuntime,
}

impl HttpTransportLayerCreator {
    pub fn new(
        so_mark: Option<u32>,
        encap_in_http: EncapInHttp,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        Ok(Self {
            so_mark,
            path_rewrite_group: PathRewriteGroup::new(encap_in_http.path_rewrites)?,
            runtime,
        })
    }
}

impl TransportLayerCreatorTrait for HttpTransportLayerCreator {
    type TransportLayerConnector = HttpTransportLayer;

    fn create(&self, pool_key: &PoolKey, parent_span: Span) -> Result<HttpTransportLayer> {
        Ok(HttpTransportLayer {
            dst: pool_key.get_endpoint().clone(),
            extra_data: pool_key
                .get_extra_data::<HttpPoolKeyExtraData>()
                .context("Failed to get the extra data from the pool key")?
                .clone(),
            so_mark: self.so_mark,
            runtime: self.runtime.clone(),
            transport_layer_span: tracing::info_span!(parent: parent_span, "transport", type = "h2"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct HttpTransportLayer {
    #[allow(unused)]
    dst: TngEndpoint,
    extra_data: HttpPoolKeyExtraData,
    #[allow(unused)]
    so_mark: Option<u32>,
    #[allow(unused)]
    runtime: TokioRuntime,
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
        #[cfg(unix)]
        let so_mark = self.so_mark;
        #[cfg(unix)]
        let dst = self.dst.clone();
        #[cfg(wasm)]
        let runtime = self.runtime.clone();

        let url = format!("ws://{}{}", self.extra_data.authority, self.extra_data.path);

        let fut = async move {
            tracing::debug!("Establishing the underly http stream with upstream");

            let stream = async {
                #[cfg(unix)]
                {
                    use tokio_util::compat::TokioAsyncReadCompatExt;

                    let tcp_stream = crate::tunnel::utils::socket::tcp_connect_with_so_mark(
                        (dst.host(), dst.port()),
                        so_mark,
                    )
                    .await?;

                    let (ws, _http_response) =
                        async_tungstenite::client_async(&url, tcp_stream.compat())
                            .await
                            .with_context(|| {
                                format!("Failed to create the websocket connection to {url}")
                            })?;

                    let ws_stream = ws_stream_tungstenite::WsStream::new(ws).compat();

                    Ok::<_, anyhow::Error>(ws_stream)
                }
                #[cfg(wasm)]
                {
                    let ws_stream = {
                        // Since web_sys::features::gen_CloseEvent::CloseEvent is not Send
                        // Here we have to spawn a local task to run in background, which will pipe data with duplexstream
                        let (s1, mut s2) = tokio::io::duplex(1024);
                        runtime.spawn_supervised_wasm_local_task_with_span(
                            Span::current(),
                            async move {
                                let fut = async {
                                    tracing::debug!("Connecting to {url}");

                                    let (_ws, wsio) = ws_stream_wasm::WsMeta::connect(&url, None)
                                        .await
                                        .with_context(|| {
                                            format!(
                                            "Failed to create the websocket connection to {url}"
                                        )
                                        })?;

                                    tracing::debug!(
                                      state=?wsio.ready_state(),
                                      "websocket connection to {url} created successfully"
                                    );

                                    let mut ws_stream = wsio.into_io().compat();

                                    scopeguard::defer!(
                                        tracing::debug!("Ws connection droped");
                                    );

                                    Ok::<_, anyhow::Error>(
                                        tokio::io::copy_bidirectional(&mut ws_stream, &mut s2)
                                            .await?,
                                    )
                                };
                                if let Err(error) = fut.await {
                                    tracing::error!(
                                        ?error,
                                        "Failed to read/write data from websocket"
                                    );
                                }
                            },
                        );
                        s1
                    };

                    Ok::<_, anyhow::Error>(ws_stream)
                }
            }
            .await
            .context("Failed to establish the underlying http connection for rats-tls")?;

            tracing::debug!("The underlying http connection is established");

            Ok(TokioIo::new(TransportLayerStream::Http(Box::new(stream))))
        }
        .instrument(self.transport_layer_span.clone());

        Box::pin(fut)
    }
}
