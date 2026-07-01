use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
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
    /// Whether to capture traffic where the peer IP is a local interface
    /// address. When false, local-traffic is excluded from the tunnel.
    capture_local_traffic: bool,
    /// Cached set of local interface IPs.
    local_ips: HashSet<Ipv4Addr>,
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

        // Collect local interface IPs for capture_local_traffic filtering.
        let mut local_ips = HashSet::new();
        if let Ok(ifaces) = local_ip_address::list_afinet_netifas() {
            for (_, addr) in ifaces {
                if let IpAddr::V4(v4) = addr {
                    if !v4.is_loopback() {
                        local_ips.insert(v4);
                    }
                }
            }
        }

        Self {
            id,
            entries,
            capture_local_traffic: hook_args.capture_local_traffic,
            local_ips,
        }
    }

    /// Check whether a connection arriving at local_addr should go through
    /// the encryption/decryption path.
    ///
    /// Returns true if local_addr matches any entry's host AND ifname filter.
    /// When no entries are configured, defaults to encrypted (backward compatible).
    /// IPv6 connections always return false.
    pub fn encrypted(&self, peer_addr: SocketAddr, local_addr: SocketAddr) -> bool {
        if self.entries.is_empty() {
            return true;
        }

        let peer_ip = match peer_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return false,
        };
        let ip = match local_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return false,
        };

        // When capture_local_traffic is false, skip only if the connection
        // is purely local — source is also a local address. An external
        // source connecting to a local destination must still be encrypted.
        let peer_is_local = peer_ip.is_loopback() || self.local_ips.contains(&peer_ip);
        if !self.capture_local_traffic && peer_is_local {
            return false;
        }

        for entry in &self.entries {
            let host_match = entry.host.is_unspecified() || entry.host == ip;
            let ifname_match = match &entry.resolved_ifname_ips {
                None => true,                   // no ifname configured
                Some(set) => set.contains(&ip), // empty set → false (no IPs)
            };

            if host_match && ifname_match {
                return true;
            }
        }

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

            let listener = TcpListener::bind(&addr)
                .await
                .with_context(|| format!("Failed to bind hook egress listener on {addr}"))?;
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
                                let encrypted = self.encrypted(peer_addr, local);

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

    // ── helpers ──────────────────────────────────────────────────────────────

    fn make_egress(entries: Vec<ResolvedEgressEntry>) -> HookEgress {
        HookEgress {
            id: 0,
            entries,
            // Default to true so host/ifname matching tests aren't affected
            // by the local-traffic filter.
            capture_local_traffic: true,
            local_ips: HashSet::new(),
        }
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

    // Well-known IPs used across tests for clarity.
    const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const EXT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 99); // "external" non-local
    const IFACE1: Ipv4Addr = Ipv4Addr::new(172, 17, 89, 111); // simulated interface IP
    const IFACE2: Ipv4Addr = Ipv4Addr::new(172, 17, 89, 112); // another interface IP

    fn peer(ip: Ipv4Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip), 12345)
    }

    fn dest(ip: Ipv4Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip), 5600)
    }

    // ── host / ifname matching (capture_local_traffic = true, local_ips empty)
    // These tests isolate the host/ifname filter without the local-traffic
    // shortcut.

    #[test]
    fn test_encrypted_empty_entries_returns_true() {
        let egress = make_egress(vec![]);
        assert!(egress.encrypted(peer(EXT), dest(LOOPBACK)));
    }

    #[test]
    fn test_encrypted_wildcard_host_matches_all() {
        let entry = make_entry(Ipv4Addr::UNSPECIFIED, None, 5600, 9600);
        let egress = make_egress(vec![entry]);

        assert!(egress.encrypted(peer(EXT), dest(LOOPBACK)));
        assert!(egress.encrypted(peer(EXT), dest(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(egress.encrypted(peer(EXT), dest(EXT)));
    }

    #[test]
    fn test_encrypted_specific_host_matches() {
        let entry = make_entry(Ipv4Addr::new(172, 17, 80, 1), None, 5600, 9600);
        let egress = make_egress(vec![entry]);

        assert!(egress.encrypted(peer(EXT), dest(Ipv4Addr::new(172, 17, 80, 1))));
        assert!(!egress.encrypted(peer(EXT), dest(LOOPBACK)));
    }

    #[test]
    fn test_encrypted_ifname_filter() {
        let mut ips = HashSet::new();
        ips.insert(Ipv4Addr::new(172, 17, 80, 1));
        ips.insert(Ipv4Addr::new(172, 17, 80, 2));

        let entry = make_entry(Ipv4Addr::UNSPECIFIED, Some(ips), 5600, 9600);
        let egress = make_egress(vec![entry]);

        assert!(egress.encrypted(peer(EXT), dest(Ipv4Addr::new(172, 17, 80, 1))));
        assert!(!egress.encrypted(peer(EXT), dest(LOOPBACK)));
    }

    #[test]
    fn test_encrypted_host_and_ifname_and() {
        let mut ips = HashSet::new();
        ips.insert(Ipv4Addr::new(172, 17, 80, 1));

        let entry = make_entry(Ipv4Addr::new(172, 17, 80, 1), Some(ips.clone()), 5600, 9600);
        let egress = make_egress(vec![entry]);

        // Both match
        assert!(egress.encrypted(peer(EXT), dest(Ipv4Addr::new(172, 17, 80, 1))));
        // Neither matches
        assert!(!egress.encrypted(peer(EXT), dest(Ipv4Addr::new(172, 17, 80, 2))));

        // IP matches ifname but not host (separate entry)
        let entry2 = make_entry(Ipv4Addr::new(10, 0, 0, 1), Some(ips), 5601, 9601);
        let egress2 = make_egress(vec![entry2]);
        assert!(!egress2.encrypted(peer(EXT), dest(Ipv4Addr::new(172, 17, 80, 1))));
    }

    #[test]
    fn test_encrypted_ifname_no_ips_blocks_all() {
        let entry = make_entry(Ipv4Addr::UNSPECIFIED, Some(HashSet::new()), 5600, 9600);
        let egress = make_egress(vec![entry]);
        assert!(!egress.encrypted(peer(EXT), dest(EXT)));
    }

    #[test]
    fn test_encrypted_ipv6_returns_false() {
        let entry = make_entry(Ipv4Addr::UNSPECIFIED, None, 5600, 9600);
        let egress = make_egress(vec![entry]);

        let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 5600);
        assert!(!egress.encrypted(peer(EXT), addr));
    }

    // ── capture_local_traffic = false: peer locality is the gatekeeper ───────
    //
    // When false, the only question for the local-traffic shortcut is:
    // "is the peer local?"  If yes → skip encryption.  If no → proceed to
    // host/ifname matching normally.

    fn egress_no_capture(local_ips: HashSet<Ipv4Addr>) -> HookEgress {
        let entry = make_entry(Ipv4Addr::UNSPECIFIED, None, 5600, 9600);
        HookEgress {
            id: 0,
            entries: vec![entry],
            capture_local_traffic: false,
            local_ips,
        }
    }

    #[test]
    fn test_no_capture_loopback_peer_always_skipped() {
        // Loopback peer is always local (is_loopback()), regardless of dest
        // or local_ips contents.
        let mut ips = HashSet::new();
        ips.insert(IFACE1);
        let egress = egress_no_capture(ips);

        // Loopback peer → loopback dest
        assert!(!egress.encrypted(peer(LOOPBACK), dest(LOOPBACK)));
        // Loopback peer → interface dest
        assert!(!egress.encrypted(peer(LOOPBACK), dest(IFACE1)));
        // Loopback peer → external dest
        assert!(!egress.encrypted(peer(LOOPBACK), dest(EXT)));
    }

    #[test]
    fn test_no_capture_interface_peer_always_skipped() {
        // Peer is a known interface IP → local → skip, regardless of dest.
        let mut ips = HashSet::new();
        ips.insert(IFACE1);
        ips.insert(IFACE2);
        let egress = egress_no_capture(ips);

        // Interface peer → interface dest
        assert!(!egress.encrypted(peer(IFACE1), dest(IFACE2)));
        // Interface peer → loopback dest
        assert!(!egress.encrypted(peer(IFACE1), dest(LOOPBACK)));
        // Interface peer → external dest (the bug scenario: external-looking
        // dest but local peer → must skip)
        assert!(!egress.encrypted(peer(IFACE1), dest(EXT)));
    }

    #[test]
    fn test_no_capture_external_peer_to_local_dest_is_encrypted() {
        // The bug fix: external peer → local dest must be encrypted.
        let mut ips = HashSet::new();
        ips.insert(IFACE1);
        let egress = egress_no_capture(ips);

        // External → interface dest: encrypted
        assert!(egress.encrypted(peer(EXT), dest(IFACE1)));
        // External → loopback dest: encrypted
        assert!(egress.encrypted(peer(EXT), dest(LOOPBACK)));
        // External → external dest: encrypted
        assert!(egress.encrypted(peer(EXT), dest(EXT)));
    }

    #[test]
    fn test_no_capture_empty_local_ips_only_loopback_is_local() {
        // With no interface IPs in local_ips, only loopback peers are local.
        let egress = egress_no_capture(HashSet::new());

        // Loopback peer → skipped
        assert!(!egress.encrypted(peer(LOOPBACK), dest(LOOPBACK)));
        // Any non-loopback peer → encrypted (wildcard entry always matches)
        assert!(egress.encrypted(peer(EXT), dest(LOOPBACK)));
        assert!(egress.encrypted(peer(IFACE1), dest(IFACE1)));
    }

    #[test]
    fn test_no_capture_loopback_range_coverage() {
        // is_loopback() covers all of 127.0.0.0/8, not just 127.0.0.1.
        let egress = egress_no_capture(HashSet::new());

        assert!(!egress.encrypted(peer(Ipv4Addr::new(127, 0, 0, 1)), dest(EXT)));
        assert!(!egress.encrypted(peer(Ipv4Addr::new(127, 0, 0, 2)), dest(EXT)));
        assert!(!egress.encrypted(peer(Ipv4Addr::new(127, 1, 2, 3)), dest(EXT)));
    }

    #[test]
    fn test_no_capture_external_peer_host_mismatch_still_false() {
        // External peer passes the local-traffic gate, but host/ifname
        // matching can still reject the connection.
        let mut ips = HashSet::new();
        ips.insert(IFACE1);
        let entry = make_entry(Ipv4Addr::new(10, 10, 10, 10), None, 5600, 9600);
        let egress = HookEgress {
            id: 0,
            entries: vec![entry],
            capture_local_traffic: false,
            local_ips: ips,
        };

        // External peer passes gate, but dest doesn't match host → false
        assert!(!egress.encrypted(peer(EXT), dest(IFACE1)));
        // External peer passes gate, dest matches host → true
        assert!(egress.encrypted(peer(EXT), dest(Ipv4Addr::new(10, 10, 10, 10))));
    }

    // ── capture_local_traffic = true: local-traffic shortcut is disabled ─────
    //
    // All connections proceed to host/ifname matching, regardless of peer
    // locality.

    fn egress_capture_local(local_ips: HashSet<Ipv4Addr>) -> HookEgress {
        let entry = make_entry(Ipv4Addr::UNSPECIFIED, None, 5600, 9600);
        HookEgress {
            id: 0,
            entries: vec![entry],
            capture_local_traffic: true,
            local_ips,
        }
    }

    #[test]
    fn test_capture_local_loopback_peer_encrypted() {
        let mut ips = HashSet::new();
        ips.insert(IFACE1);
        let egress = egress_capture_local(ips);

        // Loopback peer → any dest: still encrypted (wildcard entry)
        assert!(egress.encrypted(peer(LOOPBACK), dest(LOOPBACK)));
        assert!(egress.encrypted(peer(LOOPBACK), dest(IFACE1)));
        assert!(egress.encrypted(peer(LOOPBACK), dest(EXT)));
    }

    #[test]
    fn test_capture_local_interface_peer_encrypted() {
        let mut ips = HashSet::new();
        ips.insert(IFACE1);
        ips.insert(IFACE2);
        let egress = egress_capture_local(ips);

        // Interface peer → any dest: still encrypted
        assert!(egress.encrypted(peer(IFACE1), dest(IFACE2)));
        assert!(egress.encrypted(peer(IFACE1), dest(LOOPBACK)));
        assert!(egress.encrypted(peer(IFACE1), dest(EXT)));
    }

    #[test]
    fn test_capture_local_external_peer_encrypted() {
        let mut ips = HashSet::new();
        ips.insert(IFACE1);
        let egress = egress_capture_local(ips);

        assert!(egress.encrypted(peer(EXT), dest(IFACE1)));
        assert!(egress.encrypted(peer(EXT), dest(LOOPBACK)));
    }

    #[test]
    fn test_capture_local_host_mismatch_still_rejects() {
        // Even with capture_local_traffic = true, host/ifname matching still
        // applies.
        let mut ips = HashSet::new();
        ips.insert(IFACE1);
        let entry = make_entry(Ipv4Addr::new(10, 10, 10, 10), None, 5600, 9600);
        let egress = HookEgress {
            id: 0,
            entries: vec![entry],
            capture_local_traffic: true,
            local_ips: ips,
        };

        // Dest doesn't match host → false (even though peer is external)
        assert!(!egress.encrypted(peer(EXT), dest(IFACE1)));
        // Dest matches host → true
        assert!(egress.encrypted(peer(EXT), dest(Ipv4Addr::new(10, 10, 10, 10))));
    }
}
