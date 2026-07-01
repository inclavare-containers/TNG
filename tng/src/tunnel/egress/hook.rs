use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_stream::stream;
use async_trait::async_trait;
use futures::stream::select_all;
use indexmap::IndexMap;
use tokio::net::TcpListener;

use crate::tunnel::access_log::{AccessAccepted, EgressAccessMode};
use crate::tunnel::egress::flow::AcceptedStream;
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::socket::SetListenerSockOpts;

use super::flow::{EgressTrait, Incomming};

/// Pre-resolved entry: port mapping + resolved ifname IPs.
///
/// Built from config entries during HookEgress::new(),
/// with ifname resolved to actual IPs via list_afinet_netifas().
pub struct ResolvedEgressEntry {
    /// The port the app thinks it's binding to
    pub origin_port: u16,
    /// The actual port the app binds to (redirected by hook)
    pub real_port: u16,
    /// Host IP to match (0.0.0.0 = wildcard, match all)
    pub host: Ipv4Addr,
    /// Resolved IPs of the configured ifname.
    /// None = no ifname was configured (pass-through).
    /// Some(empty) = ifname configured but interface has no IPs (nothing matches).
    /// Some(set) = ifname configured with IPs (check membership).
    pub resolved_ifname_ips: Option<HashSet<Ipv4Addr>>,
}

/// Hook-based egress that listens on origin ports and forwards
/// to real ports on localhost.
///
/// Each HookEgress instance handles a list of origin->real port mappings
/// (expanded from capture_listen entries by `tng exec`).
///
/// Host/ifname filtering happens at accept time: connections are checked
/// against the resolved host IP and ifname IP set.
pub struct HookEgress {
    id: usize,
    entries: Vec<ResolvedEgressEntry>,
}

impl HookEgress {
    /// Create a new HookEgress from hook args.
    ///
    /// Expands `resolved_entries` into resolved entries, resolving
    /// ifname -> IPs via list_afinet_netifas() once at startup.
    pub fn new(id: usize, hook_args: &crate::config::egress_hook::EgressHookArgs) -> Self {
        let mut entries: Vec<ResolvedEgressEntry> = Vec::new();

        for entry in &hook_args.resolved_entries {
            let resolved_ifname_ips = entry.ifname.as_ref().map(|name| resolve_ifname_ips(name));

            entries.push(ResolvedEgressEntry {
                origin_port: entry.origin_port,
                real_port: entry.real_port,
                host: entry.host,
                resolved_ifname_ips,
            });
        }

        // Diagnose missing ifname interfaces at startup so users know why
        // all connections are being blocked.
        for entry in &entries {
            if let Some(ips) = &entry.resolved_ifname_ips {
                if ips.is_empty() {
                    let ifname = hook_args
                        .resolved_entries
                        .iter()
                        .find(|r| {
                            r.origin_port == entry.origin_port && r.real_port == entry.real_port
                        })
                        .and_then(|r| r.ifname.as_deref())
                        .unwrap_or("?");
                    tracing::warn!(
                        %ifname,
                        origin_port = entry.origin_port,
                        real_port = entry.real_port,
                        "ifname configured but interface not found or has no IPv4 addresses — connections will bypass tunnel"
                    );
                }
            }
        }

        Self { id, entries }
    }

    /// Check whether a connection arriving at local_addr should go through
    /// the encryption/decryption path.
    ///
    /// Returns true if:
    /// - local_addr.ip() matches the configured host (0.0.0.0 = wildcard), AND
    /// - if ifname was configured (Some), local_addr.ip() is in the resolved ifname IP set
    /// - if ifname was not configured (None), skip the ifname check
    /// - IPv6 connections always return false
    /// - No entries -> default to encrypted (backward compatible)
    pub fn encrypted(&self, local_addr: SocketAddr) -> bool {
        // No entries configured -> default to encrypted (backward compatible)
        if self.entries.is_empty() {
            return true;
        }

        let ip = match local_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return false,
        };

        for entry in &self.entries {
            // Host check: 0.0.0.0 matches all, otherwise exact match
            if !entry.host.is_unspecified() && entry.host != ip {
                continue;
            }

            // Ifname check: None = no filter (pass-through),
            // Some(empty) = nothing matches, Some(set) = must contain IP
            match &entry.resolved_ifname_ips {
                None => {} // no ifname configured -> pass-through
                Some(set) if set.is_empty() => continue,
                Some(set) if !set.contains(&ip) => continue,
                Some(_) => {}
            }

            // Found a matching entry
            return true;
        }

        // Entries exist but none matched
        false
    }
}

/// Resolve a network interface name to its IPv4 addresses.
///
/// Called once at HookEgress startup. Uses netlink on Linux
/// (via local-ip-address crate). Returns empty set if the
/// interface doesn't exist or has no IPv4 addresses.
fn resolve_ifname_ips(ifname: &str) -> HashSet<Ipv4Addr> {
    match local_ip_address::list_afinet_netifas() {
        Ok(interfaces) => interfaces
            .into_iter()
            .filter_map(|(name, ip)| {
                if name == ifname {
                    match ip {
                        IpAddr::V4(addr) => Some(addr),
                        IpAddr::V6(_) => None,
                    }
                } else {
                    None
                }
            })
            .collect(),
        Err(error) => {
            tracing::warn!(?error, %ifname, "Failed to resolve interface IPs");
            HashSet::new()
        }
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

    fn make_egress(entries: Vec<ResolvedEgressEntry>) -> HookEgress {
        HookEgress { id: 0, entries }
    }

    fn make_entry(
        host: Ipv4Addr,
        ifname_ips: Option<HashSet<Ipv4Addr>>,
        origin_port: u16,
        real_port: u16,
    ) -> ResolvedEgressEntry {
        ResolvedEgressEntry {
            origin_port,
            real_port,
            host,
            resolved_ifname_ips: ifname_ips,
        }
    }

    #[test]
    fn test_encrypted_empty_entries_returns_true() {
        let egress = make_egress(vec![]);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5600);
        assert!(egress.encrypted(addr));
    }

    #[test]
    fn test_encrypted_wildcard_host_matches_all() {
        // host = 0.0.0.0, no ifname -> always true
        let entry = make_entry(Ipv4Addr::UNSPECIFIED, None, 5600, 9600);
        let egress = make_egress(vec![entry]);

        // Any IP should match
        assert!(egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            5600
        )));
        assert!(egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            5600
        )));
        assert!(egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5600
        )));
    }

    #[test]
    fn test_encrypted_specific_host_matches() {
        let entry = make_entry(Ipv4Addr::new(172, 17, 80, 1), None, 5600, 9600);
        let egress = make_egress(vec![entry]);

        // Exact match
        assert!(egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 17, 80, 1)),
            5600
        )));

        // Different IP -> fail
        assert!(!egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            5600
        )));
    }

    #[test]
    fn test_encrypted_ifname_filter() {
        // host = 0.0.0.0, ifname resolved to specific IPs
        let mut ips = HashSet::new();
        ips.insert(Ipv4Addr::new(172, 17, 80, 1));
        ips.insert(Ipv4Addr::new(172, 17, 80, 2));

        let entry = make_entry(Ipv4Addr::UNSPECIFIED, Some(ips), 5600, 9600);
        let egress = make_egress(vec![entry]);

        // IP in the resolved set -> match
        assert!(egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 17, 80, 1)),
            5600
        )));

        // IP not in the set -> no match
        assert!(!egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            5600
        )));
    }

    #[test]
    fn test_encrypted_host_and_ifname_and() {
        // host = 172.17.80.1 AND ifname_ips contains 172.17.80.1
        let mut ips = HashSet::new();
        ips.insert(Ipv4Addr::new(172, 17, 80, 1));

        let entry = make_entry(Ipv4Addr::new(172, 17, 80, 1), Some(ips.clone()), 5600, 9600);
        let egress = make_egress(vec![entry]);

        // Both match -> true
        assert!(egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 17, 80, 1)),
            5600
        )));

        // IP matches neither host nor ifname -> false
        assert!(!egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 17, 80, 2)),
            5600
        )));

        // IP matches ifname but not host (different entry) -> false
        let entry2 = make_entry(Ipv4Addr::new(10, 0, 0, 1), Some(ips), 5601, 9601);
        let egress2 = make_egress(vec![entry2]);
        assert!(!egress2.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 17, 80, 1)),
            5601
        )));
    }

    #[test]
    fn test_encrypted_ipv6_returns_false() {
        let entry = make_entry(Ipv4Addr::UNSPECIFIED, None, 5600, 9600);
        let egress = make_egress(vec![entry]);

        let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 5600);
        assert!(!egress.encrypted(addr));
    }

    #[test]
    fn test_encrypted_ifname_no_ips_blocks_all() {
        // ifname configured but interface has no IPs -> empty Some -> nothing matches
        let entry = make_entry(Ipv4Addr::UNSPECIFIED, Some(HashSet::new()), 5600, 9600);
        let egress = make_egress(vec![entry]);
        // No IPs to match -> nothing is encrypted
        assert!(!egress.encrypted(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5600
        )));
    }
}
