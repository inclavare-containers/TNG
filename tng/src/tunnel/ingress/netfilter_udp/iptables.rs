use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use crate::{
    config::ingress::IngressNetfilterCaptureDst,
    tunnel::utils::iptables::{
        format_dport, IptablesRuleGenerator, NETFILTER_UDP_INGRESS_FW_MARK_BASE,
        NETFILTER_UDP_INGRESS_ROUTE_TABLE_BASE,
    },
};

use super::NetfilterUdpIngress;

fn is_cgroup_v2() -> bool {
    std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

#[async_trait]
impl IptablesRuleGenerator for NetfilterUdpIngress {
    async fn gen_script(&self) -> Result<(String, String)> {
        which::which("iptables")
            .context("The external tool \"iptables\" is not found, please install it")?;
        which::which("ip").context("The external tool \"ip\" is not found, please install it")?;

        let id = self.id;
        let fw_mark = NETFILTER_UDP_INGRESS_FW_MARK_BASE + id as u32;
        let route_table = NETFILTER_UDP_INGRESS_ROUTE_TABLE_BASE + id as u32;
        let listen_port = self.listen_port;

        if self.capture_dst.is_empty() {
            tracing::info!("capture_dst is empty, will capture all UDP traffic")
        }

        let mut invoke_script = "".to_owned();
        let mut revoke_script = "".to_owned();

        // Short chain names that still fit iptables nftables' 28-char limit
        // (e.g. `TNG_INGRESS_UDP_255_OUT1` is 24 chars). Each netfilter_udp
        // ingress instance owns its own chain set keyed by `id`.
        let pre_chain = format!("TNG_INGRESS_UDP_{id}_PRE");
        let out1_chain = format!("TNG_INGRESS_UDP_{id}_OUT1");
        let out2_chain = format!("TNG_INGRESS_UDP_{id}_OUT2");

        let clean_up = format!(
            "\
            iptables -t mangle -D PREROUTING -p udp -j {pre_chain} 2>/dev/null || true ; \
            iptables -t mangle -D OUTPUT -p udp -j {out1_chain} 2>/dev/null || true ; \
            iptables -t mangle -F {pre_chain} 2>/dev/null || true ; \
            iptables -t mangle -X {pre_chain} 2>/dev/null || true ; \
            iptables -t mangle -F {out1_chain} 2>/dev/null || true ; \
            iptables -t mangle -X {out1_chain} 2>/dev/null || true ; \
            iptables -t mangle -F {out2_chain} 2>/dev/null || true ; \
            iptables -t mangle -X {out2_chain} 2>/dev/null || true ; \
            ip route flush table {route_table} 2>/dev/null || true ; \
            ip rule del table {route_table} 2>/dev/null || true ; \
            "
        );

        invoke_script += &clean_up;
        invoke_script += &format!("iptables -t mangle -N {pre_chain} ; ");

        // Skip: local dst, non-unicast dst, non-local src
        invoke_script += &format!(
            "\
            iptables -t mangle -A {pre_chain} -m addrtype --dst-type LOCAL -j RETURN ; \
            iptables -t mangle -A {pre_chain} -m addrtype ! --dst-type UNICAST -j RETURN ; \
            iptables -t mangle -A {pre_chain} -m addrtype ! --src-type LOCAL -j RETURN ; \
            "
        );

        invoke_script += &format!(
            "iptables -t mangle -A {pre_chain} -p udp -j TPROXY --on-ip 127.0.0.1 --on-port {listen_port} --tproxy-mark {fw_mark}/0xffffff ;"
        );
        invoke_script += &format!("iptables -t mangle -I PREROUTING 1 -p udp -j {pre_chain} ;");

        // OUTPUT chain (local process traffic)
        invoke_script += &format!(
            "\
            ip route add local default dev lo table {route_table} ; \
            ip rule add fwmark {fw_mark}/0xffffff table {route_table} ; \
            iptables -t mangle -N {out1_chain} ; \
            iptables -t mangle -N {out2_chain} ; \
            "
        );

        invoke_script += &format!(
            "\
            iptables -t mangle -A {out1_chain} -m addrtype --dst-type LOCAL -j RETURN ; \
            iptables -t mangle -A {out1_chain} -m addrtype ! --dst-type UNICAST -j RETURN ; \
            iptables -t mangle -A {out1_chain} -m addrtype ! --src-type LOCAL -j RETURN ; \
            iptables -t mangle -A {out1_chain} -p udp -m mark --mark {} -j RETURN ; \
            ",
            self.so_mark
        );

        // cgroup handling
        if (!is_cgroup_v2())
            && (!self.capture_cgroup.is_empty() || !self.nocapture_cgroup.is_empty())
        {
            bail!("It seems that you are not running in cgroup v2, but `capture_cgroup` and `nocapture_cgroup` are supported on cgroup v2 only")
        } else {
            if self.capture_cgroup.is_empty() {
                invoke_script += &format!("iptables -t mangle -A {out1_chain} -j {out2_chain} ;");
            } else {
                for cgroup in &self.capture_cgroup {
                    invoke_script += &format!(
                        "iptables -t mangle -A {out1_chain} -m cgroup --path {cgroup} -j {out2_chain} ;"
                    );
                }
            }
            for cgroup in &self.nocapture_cgroup {
                invoke_script += &format!(
                    "iptables -t mangle -A {out2_chain} -m cgroup --path {cgroup} -j RETURN ;"
                );
            }
        }

        // capture_dst rules
        if self.capture_dst.is_empty() {
            invoke_script += &format!(
                "iptables -t mangle -A {out2_chain} -p udp -j MARK --set-mark {fw_mark}/0xffffff ;"
            );
        } else {
            for cap in &self.capture_dst {
                match cap {
                    IngressNetfilterCaptureDst::HostOnly { host } => {
                        invoke_script += &format!(
                            "iptables -t mangle -A {out2_chain} -p udp --dst {}/{} -j MARK --set-mark {fw_mark}/0xffffff ;",
                            host.first_address(), host.network_length()
                        );
                    }
                    IngressNetfilterCaptureDst::IpSetOnly { ipset } => {
                        invoke_script += &format!(
                            "iptables -t mangle -A {out2_chain} -p udp -m set --match-set {ipset} dst -j MARK --set-mark {fw_mark}/0xffffff ;"
                        );
                    }
                    IngressNetfilterCaptureDst::PortOnly { port, port_end } => {
                        let dport = format_dport(*port, port_end.as_ref());
                        invoke_script += &format!(
                            "iptables -t mangle -A {out2_chain} -p udp --dport {dport} -j MARK --set-mark {fw_mark}/0xffffff ;"
                        );
                    }
                    IngressNetfilterCaptureDst::HostAndPort {
                        host,
                        port,
                        port_end,
                    } => {
                        let dport = format_dport(*port, port_end.as_ref());
                        invoke_script += &format!(
                            "iptables -t mangle -A {out2_chain} -p udp --dst {}/{} --dport {dport} -j MARK --set-mark {fw_mark}/0xffffff ;",
                            host.first_address(), host.network_length()
                        );
                    }
                    IngressNetfilterCaptureDst::IpSetAndPort {
                        ipset,
                        port,
                        port_end,
                    } => {
                        let dport = format_dport(*port, port_end.as_ref());
                        invoke_script += &format!(
                            "iptables -t mangle -A {out2_chain} -p udp --dport {dport} -m set --match-set {ipset} dst -j MARK --set-mark {fw_mark}/0xffffff ;"
                        );
                    }
                }
            }
        }

        invoke_script += &format!("iptables -t mangle -I OUTPUT 1 -p udp -j {out1_chain} ;");

        revoke_script += &clean_up;

        Ok((invoke_script, revoke_script))
    }
}
