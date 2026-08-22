use std::path::Path;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use crate::{
    config::egress::EgressNetfilterCaptureDst,
    tunnel::utils::iptables::{
        format_dport, IptablesRuleGenerator, NETFILTER_UDP_EGRESS_FW_MARK_BASE,
        NETFILTER_UDP_EGRESS_ROUTE_TABLE_BASE,
    },
};

use super::NetfilterUdpEgress;

fn is_cgroup_v2() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

#[async_trait]
impl IptablesRuleGenerator for NetfilterUdpEgress {
    async fn gen_script(&self) -> Result<(String, String)> {
        which::which("iptables")
            .context("The external tool \"iptables\" is not found, please install it")?;
        which::which("ip").context("The external tool \"ip\" is not found, please install it")?;

        let id = self.id;
        let fw_mark = NETFILTER_UDP_EGRESS_FW_MARK_BASE + id as u32;
        let route_table = NETFILTER_UDP_EGRESS_ROUTE_TABLE_BASE + id as u32;
        let listen_port = self.listen_port;

        if self.capture_dst.is_empty() {
            tracing::info!("capture_dst is empty, will capture all UDP traffic");

            if self.capture_local_traffic {
                tracing::warn!(
                    "netfilter_udp egress: capture_dst is empty and \
                     capture_local_traffic is true — the backend's reply packets \
                     may not be delivered to the downstream client; please specify \
                     concrete capture rules instead of capture-all"
                );
            }
        }

        let mut invoke_script = "".to_owned();
        let mut revoke_script = "".to_owned();

        let clean_up = format!(
            "\
            iptables -t mangle -D PREROUTING -p udp -j TNG_EGRESS_UDP_{id} 2>/dev/null || true ; \
            iptables -t mangle -F TNG_EGRESS_UDP_{id} 2>/dev/null || true ; \
            iptables -t mangle -X TNG_EGRESS_UDP_{id} 2>/dev/null || true ; \
            iptables -t mangle -F TNG_EGRESS_UDP_{id}_CGROUP 2>/dev/null || true ; \
            iptables -t mangle -X TNG_EGRESS_UDP_{id}_CGROUP 2>/dev/null || true ; \
            ip route flush table {route_table} 2>/dev/null || true ; \
            ip rule del table {route_table} 2>/dev/null || true ; \
            "
        );

        invoke_script += &clean_up;
        invoke_script += &format!("iptables -t mangle -N TNG_EGRESS_UDP_{id} ; ");

        // Bypass our own backend-forward traffic. The egress forwards each
        // QUIC datagram to the backend via a connected UDP socket carrying
        // SO_MARK = so_mark. When the backend address equals a capture_dst
        // host that is local to this node (the common case: capture_dst is one
        // of this machine's own IPs), that locally-generated forward packet is
        // looped back through `lo` and re-traverses PREROUTING — so without an
        // escape it would be TPROXY'd right back into our own QUIC listener
        // and never reach the real backend. This `--mark so_mark -j RETURN`
        // rule (placed first in the chain) lets the marked forward fall through
        // to normal local delivery.
        //
        // This does NOT exempt the ingress's QUIC tunnel packets: those carry
        // the *ingress* side's so_mark on the client node, but a packet mark
        // (skb->mark) is per-skb and is NOT propagated across the bridge/wire
        // — the server receives the ingress tunnel with mark 0, so it does not
        // match here and is still intercepted. (Mirrors the TCP `netfilter`
        // egress and the ingress `out1_chain` escape rule.)
        invoke_script += &format!(
            "iptables -t mangle -A TNG_EGRESS_UDP_{id} -m mark --mark {} -j RETURN ;",
            self.so_mark
        );

        // Handle cgroup filtering
        if !self.capture_cgroup.is_empty() {
            if !is_cgroup_v2() {
                bail!("It seems that you are not running in cgroup v2, but `capture_cgroup` and `nocapture_cgroup` are supported on cgroup v2 only")
            }

            invoke_script += &format!("iptables -t mangle -N TNG_EGRESS_UDP_{id}_CGROUP ; ");

            for cgroup in &self.nocapture_cgroup {
                invoke_script += &format!(
                    "iptables -t mangle -A TNG_EGRESS_UDP_{id}_CGROUP -m cgroup --path {cgroup} -j RETURN ;"
                );
            }

            Self::append_capture_rules(
                &mut invoke_script,
                &format!("TNG_EGRESS_UDP_{id}_CGROUP"),
                &self.capture_dst,
                &self.capture_local_traffic,
                listen_port,
                fw_mark,
            );

            for cgroup in &self.capture_cgroup {
                invoke_script += &format!(
                    "iptables -t mangle -A TNG_EGRESS_UDP_{id} -m cgroup --path {cgroup} -j TNG_EGRESS_UDP_{id}_CGROUP ;"
                );
            }
            invoke_script += "iptables -t mangle -A TNG_EGRESS_UDP_{id} -j RETURN ; ";
        } else {
            for cgroup in &self.nocapture_cgroup {
                invoke_script += &format!(
                    "iptables -t mangle -A TNG_EGRESS_UDP_{id} -m cgroup --path {cgroup} -j RETURN ;"
                );
            }

            Self::append_capture_rules(
                &mut invoke_script,
                &format!("TNG_EGRESS_UDP_{id}"),
                &self.capture_dst,
                &self.capture_local_traffic,
                listen_port,
                fw_mark,
            );
        }

        // Add routing rules for TPROXY
        invoke_script += &format!(
            "ip route add local default dev lo table {route_table} ; \
             ip rule add fwmark {fw_mark}/0xffffff table {route_table} ; "
        );

        // NOTE: unlike the TCP `netfilter` egress, the UDP egress hooks only
        // PREROUTING (not OUTPUT) because TPROXY is a PREROUTING-only target.
        // There is intentionally NO trailing catch-all `-p udp -j TPROXY` here:
        // `append_capture_rules` already emits a catch-all when `capture_dst`
        // is empty. Adding another unconditional one would also TPROXY the
        // backend's *reply* (UdpServer -> our backend socket, destined to an
        // ephemeral port that no specific capture rule matches), sinking the
        // echo before it reaches the backend socket and breaking the
        // round-trip. The TCP egress avoids this via conntrack (nat REDIRECT
        // only applies to the first packet of a connection); UDP has no such
        // established-connection bypass, so we must not over-capture.

        // Insert into PREROUTING chain
        invoke_script +=
            &format!("iptables -t mangle -I PREROUTING 1 -p udp -j TNG_EGRESS_UDP_{id} ; ");

        revoke_script += &clean_up;

        Ok((invoke_script, revoke_script))
    }
}

impl NetfilterUdpEgress {
    fn append_capture_rules(
        script: &mut String,
        chain: &str,
        capture_dst: &[EgressNetfilterCaptureDst],
        capture_local_traffic: &bool,
        listen_port: u16,
        fw_mark: u32,
    ) {
        let src_check = if !*capture_local_traffic {
            "-m addrtype ! --src-type LOCAL "
        } else {
            ""
        };

        if capture_dst.is_empty() {
            *script += &format!(
                "iptables -t mangle -A {chain} -p udp {src_check}-j TPROXY --on-ip 0.0.0.0 --on-port {listen_port} --tproxy-mark {fw_mark}/0xffffff ; ",
            );
        } else {
            for cap in capture_dst {
                match cap {
                    EgressNetfilterCaptureDst::HostOnly { host } => {
                        *script += &format!(
                            "iptables -t mangle -A {chain} -p udp {src_check}--dst {}/{} -j TPROXY --on-ip 0.0.0.0 --on-port {listen_port} --tproxy-mark {fw_mark}/0xffffff ; ",
                            host.first_address(), host.network_length()
                        );
                    }
                    EgressNetfilterCaptureDst::IpSetOnly { ipset } => {
                        *script += &format!(
                            "iptables -t mangle -A {chain} -p udp {src_check}-m set --match-set {ipset} dst -j TPROXY --on-ip 0.0.0.0 --on-port {listen_port} --tproxy-mark {fw_mark}/0xffffff ; "
                        );
                    }
                    EgressNetfilterCaptureDst::PortOnly { port, port_end } => {
                        let dport = format_dport(*port, port_end.as_ref());
                        *script += &format!(
                            "iptables -t mangle -A {chain} -p udp {src_check}--dport {dport} -j TPROXY --on-ip 0.0.0.0 --on-port {listen_port} --tproxy-mark {fw_mark}/0xffffff ; "
                        );
                    }
                    EgressNetfilterCaptureDst::HostAndPort {
                        host,
                        port,
                        port_end,
                    } => {
                        let dport = format_dport(*port, port_end.as_ref());
                        *script += &format!(
                            "iptables -t mangle -A {chain} -p udp {src_check}--dst {}/{} --dport {dport} -j TPROXY --on-ip 0.0.0.0 --on-port {listen_port} --tproxy-mark {fw_mark}/0xffffff ; ",
                            host.first_address(), host.network_length()
                        );
                    }
                    EgressNetfilterCaptureDst::IpSetAndPort {
                        ipset,
                        port,
                        port_end,
                    } => {
                        let dport = format_dport(*port, port_end.as_ref());
                        *script += &format!(
                            "iptables -t mangle -A {chain} -p udp {src_check}--dport {dport} -m set --match-set {ipset} dst -j TPROXY --on-ip 0.0.0.0 --on-port {listen_port} --tproxy-mark {fw_mark}/0xffffff ; "
                        );
                    }
                }
            }
        }
    }
}
