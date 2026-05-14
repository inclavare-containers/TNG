use std::path::Path;

use crate::{
    config::egress::EgressNetfilterCaptureDst,
    tunnel::utils::iptables::{format_dport, IptablesRuleGenerator},
};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use super::NetfilterEgress;

fn is_cgroup_v2() -> bool {
    // https://rootlesscontaine.rs/getting-started/common/cgroup2/#checking-whether-cgroup-v2-is-already-enabled
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

#[async_trait]
impl IptablesRuleGenerator for NetfilterEgress {
    /// Generates iptables rules for egress traffic interception using REDIRECT.
    ///
    /// Both OUTPUT and PREROUTING chains are hooked into the nat table.
    async fn gen_script(&self) -> Result<(String, String)> {
        which::which("iptables")
            .context("The external tool \"iptables\" is not found, please install it")?;

        let id = self.id;
        let listen_port = self.listen_port;

        if self.capture_dst.is_empty() {
            tracing::info!("capture_dst is empty, will capture all TCP traffic")
        }

        let mut invoke_script = "".to_owned();
        let mut revoke_script = "".to_owned();

        let clean_up_iptables_script = format!(
            "\
            iptables -t nat -D PREROUTING -p tcp -j TNG_EGRESS_{id} 2>/dev/null || true ; \
            iptables -t nat -D OUTPUT -p tcp -j TNG_EGRESS_{id} 2>/dev/null || true ; \
            iptables -t nat -F TNG_EGRESS_{id} 2>/dev/null || true ; \
            iptables -t nat -X TNG_EGRESS_{id} 2>/dev/null || true ; \
            ",
        );

        invoke_script += &clean_up_iptables_script;
        invoke_script += &format!("iptables -t nat -N TNG_EGRESS_{id} ; ");

        // Ignore packets with SO_MARK set to {self.so_mark} (to prevent loopback)
        invoke_script += &format!(
            "iptables -t nat -A TNG_EGRESS_{id} -p tcp -m mark --mark {} -j RETURN ; ",
            self.so_mark
        );

        // Handle cgroup filtering
        if !self.capture_cgroup.is_empty() {
            if !is_cgroup_v2() {
                bail!("It seems that you are not running in cgroup v2, but `capture_cgroup` and `nocapture_cgroup` are supported on cgroup v2 only")
            }

            // Create a separate chain for cgroup-matched traffic
            invoke_script += &format!("iptables -t nat -N TNG_EGRESS_{id}_CGROUP ; ");

            // Apply nocapture_cgroup rules (return to skip capture)
            for cgroup in &self.nocapture_cgroup {
                invoke_script += &format!(
                    "iptables -t nat -A TNG_EGRESS_{id}_CGROUP -m cgroup --path {cgroup} -j RETURN ;"
                );
            }

            // Apply capture rules for cgroup-matched traffic
            Self::append_capture_rules(
                &mut invoke_script,
                &format!("TNG_EGRESS_{id}_CGROUP"),
                &self.capture_dst,
                &self.capture_local_traffic,
                listen_port,
            );

            // Jump to cgroup chain for matching capture_cgroups
            for cgroup in &self.capture_cgroup {
                invoke_script += &format!(
                    "iptables -t nat -A TNG_EGRESS_{id} -m cgroup --path {cgroup} -j TNG_EGRESS_{id}_CGROUP ;"
                );
            }
            // For non-matching cgroups, return (no capture)
            invoke_script += "iptables -t nat -A TNG_EGRESS_{id} -j RETURN ; ";
        } else {
            // No capture_cgroup: apply nocapture_cgroup exclusions in main chain
            for cgroup in &self.nocapture_cgroup {
                invoke_script += &format!(
                    "iptables -t nat -A TNG_EGRESS_{id} -m cgroup --path {cgroup} -j RETURN ;"
                );
            }

            // Apply capture rules in main chain
            Self::append_capture_rules(
                &mut invoke_script,
                &format!("TNG_EGRESS_{id}"),
                &self.capture_dst,
                &self.capture_local_traffic,
                listen_port,
            );
        }

        // Insert into PREROUTING and OUTPUT chains
        invoke_script += &format!(
            "iptables -t nat -I PREROUTING 1 -p tcp -j TNG_EGRESS_{id} ; \
            iptables -t nat -I OUTPUT 1 -p tcp -j TNG_EGRESS_{id} ; "
        );

        revoke_script += &clean_up_iptables_script;

        Ok((invoke_script, revoke_script))
    }
}

impl NetfilterEgress {
    /// Generate REDIRECT rules matching all capture_dst entries.
    ///
    /// When `capture_local_traffic` is false, adds `! --src-type LOCAL`
    /// to avoid intercepting traffic from local processes (handled by OUTPUT chain).
    fn append_capture_rules(
        script: &mut String,
        chain: &str,
        capture_dst: &[EgressNetfilterCaptureDst],
        capture_local_traffic: &bool,
        listen_port: u16,
    ) {
        let src_check = if !*capture_local_traffic {
            "-m addrtype ! --src-type LOCAL "
        } else {
            ""
        };

        if capture_dst.is_empty() {
            *script += &format!(
                "iptables -t nat -A {chain} -p tcp {src_check}-j REDIRECT --to-ports {listen_port} ; ",
            );
        } else {
            for cap in capture_dst {
                match cap {
                    EgressNetfilterCaptureDst::HostOnly { host } => {
                        *script += &format!(
                            "iptables -t nat -A {chain} -p tcp {src_check}--dst {}/{} -j REDIRECT --to-ports {listen_port} ; ",
                            host.first_address(), host.network_length()
                        );
                    }
                    EgressNetfilterCaptureDst::IpSetOnly { ipset } => {
                        *script += &format!(
                            "iptables -t nat -A {chain} -p tcp {src_check}-m set --match-set {ipset} dst -j REDIRECT --to-ports {listen_port} ; "
                        );
                    }
                    EgressNetfilterCaptureDst::PortOnly { port, port_end } => {
                        let dport = format_dport(*port, port_end.as_ref());
                        *script += &format!(
                            "iptables -t nat -A {chain} -p tcp {src_check}--dport {dport} -j REDIRECT --to-ports {listen_port} ; "
                        );
                    }
                    EgressNetfilterCaptureDst::HostAndPort {
                        host,
                        port,
                        port_end,
                    } => {
                        let dport = format_dport(*port, port_end.as_ref());
                        *script += &format!(
                            "iptables -t nat -A {chain} -p tcp {src_check}--dst {}/{} --dport {dport} -j REDIRECT --to-ports {listen_port} ; ",
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
                            "iptables -t nat -A {chain} -p tcp {src_check}--dport {dport} -m set --match-set {ipset} dst -j REDIRECT --to-ports {listen_port} ; "
                        );
                    }
                }
            }
        }
    }
}
