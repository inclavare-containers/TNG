use anyhow::{anyhow, Context, Result};
use async_stream::stream;
use async_trait::async_trait;
use futures::stream::select_all;
use indexmap::IndexMap;
use tokio::net::TcpListener;

use crate::{
    config::egress::EgressMappingArgs,
    tunnel::access_log::{AccessAccepted, EgressAccessMode},
    tunnel::{
        egress::flow::AcceptedStream, endpoint::TngEndpoint, utils::runtime::TokioRuntime,
        utils::socket::SetListenerSockOpts,
    },
};

use super::flow::{EgressTrait, Incomming};

use std::net::SocketAddr;
use std::sync::Arc;

pub struct MappingEgress {
    id: usize,
    rules: Vec<crate::config::mapping_rule::MappingRule>,
}

impl MappingEgress {
    pub async fn new(id: usize, mapping_args: &EgressMappingArgs) -> Result<Self> {
        if mapping_args.rules.is_empty() {
            anyhow::bail!("egress mapping: no rules defined");
        }

        Ok(Self {
            id,
            rules: mapping_args.rules.clone(),
        })
    }
}

#[async_trait]
impl EgressTrait for MappingEgress {
    fn metric_attributes(&self) -> IndexMap<String, String> {
        let first = self.rules.first();
        let in_desc = first.map_or("".to_owned(), |rule| {
            format!(
                "{}:{}",
                rule.r#in.host.as_deref().unwrap_or("0.0.0.0"),
                rule.r#in.port
            )
        });
        let out_desc = first.map_or("".to_owned(), |rule| {
            format!(
                "{}:{}",
                rule.out.host.as_deref().unwrap_or(""),
                rule.out.port
            )
        });

        [
            ("egress_type".to_owned(), "mapping".to_owned()),
            ("egress_id".to_owned(), self.id.to_string()),
            ("egress_in".to_owned(), in_desc),
            ("egress_out".to_owned(), out_desc),
        ]
        .into()
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn transport_so_mark(&self) -> Option<u32> {
        None
    }

    async fn accept(&self, _runtime: TokioRuntime) -> Result<Incomming> {
        struct ListenerTarget {
            listener: TcpListener,
            local_addr: SocketAddr,
            out_ep: Arc<TngEndpoint>,
        }

        let mut targets: Vec<ListenerTarget> = Vec::new();

        for rule in &self.rules {
            let host = rule.r#in.host.as_deref().unwrap_or("0.0.0.0");
            let out_host = rule.out.host.as_deref().context("out.host is required")?;

            if let Some(port_end) = rule.r#in.port_end {
                let offset_base = rule.out.port;
                for port in rule.r#in.port..=port_end {
                    let offset = port - rule.r#in.port;
                    let out_port = offset_base + offset;
                    let addr = format!("{host}:{port}");
                    tracing::debug!(%addr, "Add TCP listener");

                    let listener = TcpListener::bind(&addr).await.with_context(|| {
                        format!("Failed to bind mapping egress listener on {addr}")
                    })?;
                    listener.set_listener_common_sock_opts()?;
                    let local_addr = listener.local_addr()?;
                    let out_ep = Arc::new(TngEndpoint::new(out_host.to_owned(), out_port));

                    targets.push(ListenerTarget {
                        listener,
                        local_addr,
                        out_ep,
                    });
                }
            } else {
                let addr = format!("{host}:{}", rule.r#in.port);
                tracing::debug!(%addr, "Add TCP listener");

                let listener = TcpListener::bind(&addr)
                    .await
                    .with_context(|| format!("Failed to bind mapping egress listener on {addr}"))?;
                listener.set_listener_common_sock_opts()?;
                let local_addr = listener.local_addr()?;
                let out_ep = Arc::new(TngEndpoint::new(out_host.to_owned(), rule.out.port));

                targets.push(ListenerTarget {
                    listener,
                    local_addr,
                    out_ep,
                });
            }
        }

        let streams: Vec<_> = targets
            .into_iter()
            .map(|target| {
                Box::pin(stream! {
                    loop {
                        match target.listener.accept_with_common_sock_opts().await {
                            Ok((stream, peer_addr)) => {
                                let access_accepted = AccessAccepted::new_egress(
                                    peer_addr,
                                    target.local_addr,
                                    EgressAccessMode::Mapping,
                                );
                                yield Ok(AcceptedStream {
                                    stream: Box::new(crate::ContextualStream::new(stream, "egress-mapping")),
                                    src: peer_addr,
                                    dst: Arc::clone(&target.out_ep),
                                    listener_addr: target.local_addr,
                                    egress_mode: EgressAccessMode::Mapping,
                                    access_accepted,
                                    encrypted: true,
                                })
                            }
                            Err(e) => yield Err(anyhow!(e)),
                        }
                    }
                })
            })
            .collect();

        Ok(Box::new(select_all(streams)))
    }
}
