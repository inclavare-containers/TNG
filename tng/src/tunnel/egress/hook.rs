use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_stream::stream;
use async_trait::async_trait;
use futures::stream::select_all;
use indexmap::IndexMap;
use tokio::net::TcpListener;

use crate::config::egress_hook::EgressHookArgs;
use crate::config::egress_hook::EgressHookHostFilterRule;
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
///
/// Host CIDR filtering happens at accept time: connections whose local_addr
/// matches a configured CIDR go through encryption; others are forwarded directly.
pub struct HookEgress {
    id: usize,
    /// Port-only mapping entries (origin_port -> real_port) for metric attributes
    /// and getsockname lookup reference.
    entries: Vec<EgressHookMappingEntry>,
    /// Host filter rules for accept-time CIDR matching.
    /// A connection is encrypted only if its local_addr.ip() matches
    /// one of these CIDRs AND the port is in range.
    /// When empty, all traffic is encrypted (default behavior).
    host_filters: Vec<EgressHookHostFilterRule>,
}

impl HookEgress {
    /// Create a new HookEgress from hook args.
    ///
    /// Expands `resolved_entries` into port-only mapping entries for
    /// metric attributes and getsockname lookup, and builds host filter
    /// rules for accept-time CIDR matching.
    pub fn new(id: usize, hook_args: &EgressHookArgs) -> Self {
        let mut entries: Vec<EgressHookMappingEntry> = Vec::new();
        let mut host_filters: Vec<EgressHookHostFilterRule> = Vec::new();

        for entry in &hook_args.resolved_entries {
            entries.push(EgressHookMappingEntry {
                origin_port: entry.origin_port,
                real_port: entry.real_port,
            });
            if let Some(rule) = entry.host_filter_rule() {
                host_filters.push(rule);
            }
        }

        Self {
            id,
            entries,
            host_filters,
        }
    }

    /// Check whether a connection arriving at local_addr should go through
    /// the encryption/decryption path.
    ///
    /// Returns true if local_addr.ip() matches any configured host CIDR
    /// and the port is within the configured range. When no filters are
    /// configured, all traffic is encrypted (backward compatible default).
    pub fn encrypted(&self, local_addr: SocketAddr) -> bool {
        if self.host_filters.is_empty() {
            return true;
        }

        let ip = match local_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return false,
        };

        let port = local_addr.port();

        self.host_filters
            .iter()
            .any(|rule| rule.host_cidr.contains(&ip) && rule.port_range.contains(&port))
    }
}

#[async_trait]
impl EgressTrait for HookEgress {
    /// egress_type=hook,egress_id={id},egress_in=0.0.0.0:{origin_port},egress_out=127.0.0.1:{real_port}
    fn metric_attributes(&self) -> IndexMap<String, String> {
        let first = self.entries.first();
        let in_desc = first.map_or("".to_owned(), |e| format!("0.0.0.0:{}", e.origin_port));
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
            let addr = format!("0.0.0.0:{}", entry.origin_port);
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
                                //
                                // This is necessary: using local_addr() as the forwarding
                                // target ensures we only reach the interface the listener
                                // was bound to, avoiding accidentally exposing a
                                // localhost-bound listener to the external network.
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
                                let encrypted = self.encrypted(local);

                                yield Ok(AcceptedStream {
                                    stream: Box::new(crate::ContextualStream::new(stream, "egress-hook")),
                                    src: peer_addr,
                                    dst,
                                    listener_addr: info.local_addr,
                                    egress_mode: EgressAccessMode::Hook,
                                    access_accepted,
                                    encrypted,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::egress_hook::TngEgressHookMappingEntry;
    use cidr::Ipv4Cidr;
    use std::net::Ipv4Addr;

    fn make_args(entries: Vec<TngEgressHookMappingEntry>) -> EgressHookArgs {
        EgressHookArgs {
            capture_listen: vec![],
            resolved_entries: entries,
        }
    }

    #[test]
    fn test_should_encrypt_empty_filters_returns_true() {
        let egress = HookEgress::new(0, &make_args(vec![]));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5600);
        assert!(egress.encrypted(addr));
    }

    #[test]
    fn test_should_encrypt_matches_cidr_and_port() {
        let entry = TngEgressHookMappingEntry {
            host_cidr: Ipv4Cidr::new(Ipv4Addr::new(172, 17, 80, 0), 20).unwrap(),
            origin_port: 5600,
            real_port: 9600,
        };
        let egress = HookEgress::new(0, &make_args(vec![entry]));

        // In range
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 17, 80, 5)), 5600);
        assert!(egress.encrypted(addr));

        // Out of CIDR
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5600);
        assert!(!egress.encrypted(addr));

        // Out of port range
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 17, 80, 5)), 5601);
        assert!(!egress.encrypted(addr));
    }

    #[test]
    fn test_should_encrypt_ipv6_returns_false() {
        let entry = TngEgressHookMappingEntry {
            host_cidr: Ipv4Cidr::new(Ipv4Addr::new(172, 17, 80, 0), 20).unwrap(),
            origin_port: 5600,
            real_port: 9600,
        };
        let egress = HookEgress::new(0, &make_args(vec![entry]));

        let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 5600);
        assert!(!egress.encrypted(addr));
    }

    #[test]
    fn test_should_encrypt_port_range() {
        // Each TngEgressHookMappingEntry creates a single-port host filter rule.
        // Include entries only for 8000, 8005, 8010 — 8011 should return false.
        let entry = TngEgressHookMappingEntry {
            host_cidr: Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            origin_port: 8000,
            real_port: 9000,
        };
        let entry2 = TngEgressHookMappingEntry {
            host_cidr: Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            origin_port: 8005,
            real_port: 9005,
        };
        let entry3 = TngEgressHookMappingEntry {
            host_cidr: Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            origin_port: 8010,
            real_port: 9010,
        };
        let egress = HookEgress::new(0, &make_args(vec![entry, entry2, entry3]));

        // Port at start of range
        assert!(egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8000
        )));
        // Port in middle
        assert!(egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8005
        )));
        // Port at end of range
        assert!(egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8010
        )));
        // Port just outside range
        assert!(!egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8011
        )));
    }
}
