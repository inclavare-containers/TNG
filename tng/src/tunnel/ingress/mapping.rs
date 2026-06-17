use std::sync::Arc;

use anyhow::anyhow;
use anyhow::{Context, Result};
use async_trait::async_trait;
use indexmap::IndexMap;
use tokio::net::TcpListener;

use crate::config::ingress::IngressMappingArgs;
use crate::tunnel::access_log::IngressMode;
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::ingress::flow::AcceptedStream;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::socket::SetListenerSockOpts;

use super::flow::{Incomming, IngressTrait};

/// Config for a single listener (without the TcpListener itself).
struct ListenerConfig {
    bind_addr: String,
    listen_addr: String,
    listen_port: u16,
    upstream: TngEndpoint,
}

pub struct MappingIngress {
    id: usize,
    configs: Vec<ListenerConfig>,
}

impl MappingIngress {
    pub async fn new(id: usize, mapping_args: &IngressMappingArgs) -> Result<Self> {
        if mapping_args.rules.is_empty() {
            anyhow::bail!("at least one mapping rule is required");
        }

        let mut configs = Vec::new();

        for rule in &mapping_args.rules {
            let listen_addr = rule
                .r#in
                .host
                .clone()
                .unwrap_or_else(|| "0.0.0.0".to_owned());
            let upstream_addr = rule
                .out
                .host
                .as_ref()
                .context("'host' of 'out' field must be set")?
                .clone();

            if let Some(port_end) = rule.r#in.port_end {
                let offset_base = rule.out.port;
                for port in rule.r#in.port..=port_end {
                    let offset = port - rule.r#in.port;
                    let out_port = offset_base + offset;
                    let bind_addr = format!("{}:{}", listen_addr, port);

                    configs.push(ListenerConfig {
                        bind_addr,
                        listen_addr: listen_addr.clone(),
                        listen_port: port,
                        upstream: TngEndpoint::new(upstream_addr.clone(), out_port),
                    });
                }
            } else {
                let listen_port = rule.r#in.port;
                let bind_addr = format!("{}:{}", listen_addr, listen_port);
                let upstream_port = rule.out.port;

                configs.push(ListenerConfig {
                    bind_addr,
                    listen_addr,
                    listen_port,
                    upstream: TngEndpoint::new(upstream_addr, upstream_port),
                });
            }
        }

        Ok(Self { id, configs })
    }
}

#[async_trait]
impl IngressTrait for MappingIngress {
    /// ingress_type=mapping,ingress_id={id},ingress_in={in.host}:{in.port},ingress_out={out.host}:{out.port}
    fn metric_attributes(&self) -> IndexMap<String, String> {
        // Use the first listener's addresses for metric attributes (single-rule compatible)
        let first = &self.configs[0];
        [
            ("ingress_type".to_owned(), "mapping".to_owned()),
            ("ingress_id".to_owned(), self.id.to_string()),
            (
                "ingress_in".to_owned(),
                format!("{}:{}", first.listen_addr, first.listen_port),
            ),
            (
                "ingress_out".to_owned(),
                format!("{}:{}", first.upstream.host(), first.upstream.port()),
            ),
        ]
        .into()
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn transport_so_mark(&self) -> Option<u32> {
        None
    }

    async fn accept(&self, runtime: TokioRuntime) -> Result<Incomming> {
        // Create all listeners and spawn a task for each.
        // Results are merged via a shared mpsc channel (multi-listener select_all pattern).
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<AcceptedStream>>(32);

        for cfg in &self.configs {
            tracing::debug!(bind_addr = %cfg.bind_addr, "Add TCP listener");

            let listener = TcpListener::bind(&cfg.bind_addr).await?;
            listener.set_listener_common_sock_opts()?;

            let listener_addr = listener.local_addr()?;
            let upstream = Arc::new(cfg.upstream.clone());
            let tx = tx.clone();

            runtime.spawn_supervised_task_fn_current_span(move |_rt| async move {
                loop {
                    let result = match listener.accept_with_common_sock_opts().await {
                        Ok((stream, peer_addr)) => Ok(AcceptedStream {
                            stream: Box::new(crate::ContextualStream::new(
                                stream,
                                "ingress-mapping",
                            )),
                            src: peer_addr,
                            dst: upstream.clone(),
                            via_tunnel: true,
                            listener_addr,
                            ingress_mode: IngressMode::Mapping,
                        }),
                        Err(e) => Err(anyhow!(e)),
                    };
                    if tx.send(result).await.is_err() {
                        break; // Channel closed, exit
                    }
                }
            });
        }

        // Drop the original sender so the channel closes when all tasks exit.
        drop(tx);

        Ok(Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        })))
    }
}
