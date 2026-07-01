use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_stream::stream;
use async_trait::async_trait;
use futures::StreamExt;
use indexmap::IndexMap;
use tokio::net::TcpListener;

use crate::config::ingress::IngressHookArgs;
use crate::tunnel::access_log::IngressAccessMode;
use crate::tunnel::ingress::flow::stream_router::StreamRouter;
use crate::tunnel::ingress::flow::{Incomming, IngressTrait};
use crate::tunnel::utils::endpoint_matcher::EndpointMatcher;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::socket::SetListenerSockOpts;

use super::http_proxy::serve_http_proxy_no_throw_error;

/// Ingress mode for LD_PRELOAD-based hook interception.
///
/// The listener is bound eagerly in `new()` (unlike some other ingress types
/// that bind lazily in `accept()`), which ensures the port is ready before
/// `IngressFlow::serve()` signals readiness. This is required for the exec
/// readiness signal in hook mode.
pub struct HookIngress {
    id: usize,
    listen_addr: String,
    listen_port: u16,
    listener: TcpListener,
    listener_addr: SocketAddr,
    stream_router: Arc<StreamRouter>,
}

impl HookIngress {
    pub async fn new(id: usize, hook_args: &IngressHookArgs) -> Result<Self> {
        let listen_addr = hook_args
            .proxy_listen
            .as_deref()
            .unwrap_or("127.0.0.1")
            .to_owned();
        let listen_port = hook_args
            .proxy_port
            .ok_or_else(|| anyhow::anyhow!("Ingress hook mode requires proxy_port to be set. This should be populated by tng exec"))?;

        // Build an endpoint matcher from the capture_dst rules converted to
        // EndpointFilter format. The hook already filtered at the connect()
        // level via LD_PRELOAD, but we still need domain/port matching for
        // the HTTP CONNECT authority.
        let dst_filters: Vec<_> = hook_args
            .capture_dst
            .iter()
            .map(|capture| crate::config::ingress::EndpointFilter {
                domain: Some("*".to_owned()),
                domain_regex: None,
                port: Some(capture.port),
                port_end: capture.port_end,
            })
            .collect();

        let stream_router = Arc::new(StreamRouter::with_endpoint_matcher(EndpointMatcher::new(
            &dst_filters,
        )?));

        // Eager binding: the listener is bound here in the constructor,
        // before IngressFlow::serve() calls accept(). This is required for
        // the exec readiness signal — the child process must not connect
        // before the listener is ready.
        let listen_addr_full = format!("{}:{}", listen_addr, listen_port);
        tracing::debug!(%listen_addr_full, "Add TCP listener for hook ingress");
        let listener = TcpListener::bind(&listen_addr_full)
            .await
            .with_context(|| {
                format!("Failed to bind hook ingress listener on {listen_addr_full}")
            })?;
        listener.set_listener_common_sock_opts()?;
        let listener_addr = listener.local_addr()?;

        Ok(Self {
            id,
            listen_addr,
            listen_port,
            listener,
            listener_addr,
            stream_router,
        })
    }
}

#[async_trait]
impl IngressTrait for HookIngress {
    /// ingress_type=hook,ingress_id={id},ingress_proxy_listen={proxy_listen}:{port}
    fn metric_attributes(&self) -> IndexMap<String, String> {
        [
            ("ingress_type".to_owned(), "hook".to_owned()),
            ("ingress_id".to_owned(), self.id.to_string()),
            (
                "ingress_proxy_listen".to_owned(),
                format!("{}:{}", self.listen_addr, self.listen_port),
            ),
        ]
        .into()
    }

    fn ingress_mode(&self) -> IngressAccessMode {
        IngressAccessMode::Hook
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn transport_so_mark(&self) -> Option<u32> {
        None
    }

    async fn accept(&self, runtime: TokioRuntime) -> Result<Incomming> {
        let listener_addr = self.listener_addr;
        let stream_router = self.stream_router.clone();
        let mode = self.ingress_mode();

        Ok(Box::pin(
            stream! {
                loop {
                    yield self.listener.accept_with_common_sock_opts().await
                }
            }
            .flat_map_unordered(
                None, // Unlimited concurrency for hook proxy sessions
                move |res| {
                    let runtime = runtime.clone();
                    let stream_router = stream_router.clone();

                    Box::pin(stream! {
                        match res {
                            Ok((stream, peer_addr)) => {
                                let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

                                runtime.spawn_supervised_task_fn_current_span(move |runtime| async move {
                                    serve_http_proxy_no_throw_error(
                                        stream,
                                        stream_router,
                                        runtime,
                                        peer_addr,
                                        sender,
                                        listener_addr,
                                        mode,
                                    )
                                    .await
                                });

                                while let Some(accepted_stream) = receiver.recv().await {
                                    yield Ok(accepted_stream)
                                }
                            }
                            Err(e) => Err(anyhow::anyhow!(e))?,
                        }
                    })
                }
            )
        ))
    }
}
