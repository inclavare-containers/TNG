use std::{net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Result};
use async_stream::stream;
use async_trait::async_trait;
use futures::stream::select_all;
use indexmap::IndexMap;
use tokio::net::TcpListener;

use crate::config::EgressHookMappingEntry;
use crate::tunnel::access_log::{AccessAccepted, EgressAccessMode};
use crate::tunnel::egress::flow::AcceptedStream;
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::socket::SetListenerSockOpts;

use super::flow::{EgressTrait, Incomming};

/// Hook-based egress that listens on origin ports and forwards
/// to real ports on localhost.
///
/// Each HookEgress instance handles a list of origin->real port mappings
/// (expanded from capture_listen entries by `tng exec`).
pub struct HookEgress {
    id: usize,
    entries: Vec<EgressHookMappingEntry>,
}

impl HookEgress {
    /// Create a new HookEgress from resolved mapping entries.
    pub fn new(id: usize, entries: &[EgressHookMappingEntry]) -> Self {
        Self {
            id,
            entries: entries.to_vec(),
        }
    }
}

#[async_trait]
impl EgressTrait for HookEgress {
    /// egress_type=hook,egress_id={id},egress_in={listen_addr}:{origin_port},egress_out=127.0.0.1:{real_port}
    fn metric_attributes(&self) -> IndexMap<String, String> {
        let first = self.entries.first();
        let in_desc = first.map_or("".to_owned(), |e| {
            let host = if e.host.is_unspecified() {
                "0.0.0.0"
            } else {
                ""
            };
            format!("{}:{}", host, e.origin_port)
        });
        let out_desc = first.map_or("".to_owned(), |e| format!("127.0.0.1:{}", e.real_port));

        [
            ("egress_type".to_owned(), "hook".to_owned()),
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
        struct ListenerInfo {
            listener: TcpListener,
            local_addr: SocketAddr,
            real_port: u16,
        }

        let mut listeners: Vec<ListenerInfo> = Vec::new();

        for entry in &self.entries {
            let host = if entry.host.is_unspecified() {
                "0.0.0.0".to_owned()
            } else {
                entry.host.to_string()
            };
            let addr = format!("{}:{}", host, entry.origin_port);
            tracing::debug!(%addr, real_port = entry.real_port, "Hook egress: Add TCP listener on origin port");

            let listener = TcpListener::bind(&addr).await?;
            listener.set_listener_common_sock_opts()?;
            let local_addr = listener.local_addr()?;

            listeners.push(ListenerInfo {
                listener,
                local_addr,
                real_port: entry.real_port,
            });
        }

        let streams: Vec<_> = listeners
            .into_iter()
            .map(|info| {
                Box::pin(stream! {
                    loop {
                        match info.listener.accept_with_common_sock_opts().await {
                            Ok((stream, peer_addr)) => {
                                // Derive the upstream host from the accepted connection's
                                // local address (the actual IP the connection arrived on).
                                // The hook only changes the port, not the IP, so we must
                                // connect back to the same host on the real port.
                                let local = stream.local_addr().unwrap_or(info.local_addr);
                                let upstream_host = if local.ip().is_unspecified() {
                                    "127.0.0.1".to_owned()
                                } else {
                                    local.ip().to_string()
                                };
                                let dst = Arc::new(TngEndpoint::new(upstream_host, info.real_port));

                                let access_accepted = AccessAccepted::new_egress(
                                    peer_addr,
                                    info.local_addr,
                                    EgressAccessMode::Hook,
                                );
                                yield Ok(AcceptedStream {
                                    stream: Box::new(crate::ContextualStream::new(stream, "egress-hook")),
                                    src: peer_addr,
                                    dst,
                                    listener_addr: info.local_addr,
                                    egress_mode: EgressAccessMode::Hook,
                                    access_accepted,
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
