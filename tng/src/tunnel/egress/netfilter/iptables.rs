use crate::tunnel::utils::iptables::IptablesRuleGenerator;

use anyhow::{Context, Result};
use async_trait::async_trait;

use super::NetfilterEgress;

#[async_trait]
impl IptablesRuleGenerator for NetfilterEgress {
    ///
    /// Example output:
    ///
    /// ```sh
    /// # invoke_script
    /// iptables -t nat -N TNG_EGRESS_0
    /// iptables -t nat -A TNG_EGRESS_0 -p tcp -m mark --mark 565 -j RETURN
    /// iptables -t nat -A TNG_EGRESS_0 -p tcp -m addrtype --dst-type LOCAL --dport 30001 -j REDIRECT --to-ports 30000
    /// iptables -t nat -A PREROUTING -p tcp -j TNG_EGRESS_0
    /// iptables -t nat -A OUTPUT -p tcp -j TNG_EGRESS_0
    ///
    /// # revoke_script
    /// iptables -t nat -D PREROUTING -p tcp -j TNG_EGRESS_0
    /// iptables -t nat -D OUTPUT -p tcp -j TNG_EGRESS_0
    /// iptables -t nat -F TNG_EGRESS_0
    /// iptables -t nat -X TNG_EGRESS_0
    /// ```
    ///
    async fn gen_script(&self) -> Result<(String, String)> {
        // Detect required external tools
        which::which("iptables")
            .context("The external tool \"iptables\" is not found, please install it")?;

        let mut invoke_script = "".to_owned();
        let mut revoke_script = "".to_owned();

        let mut redirect_invoke_script = "".to_owned();

        let id = self.id;

        let clean_up_iptables_script = format!(
            "\
            iptables -t nat -D PREROUTING -p tcp -j TNG_EGRESS_{id} 2>/dev/null || true ; \
            iptables -t nat -D OUTPUT -p tcp -j TNG_EGRESS_{id} 2>/dev/null || true ; \
            iptables -t nat -F TNG_EGRESS_{id} 2>/dev/null || true ; \
            iptables -t nat -X TNG_EGRESS_{id} 2>/dev/null || true ; \
            ",
        );

        redirect_invoke_script += &clean_up_iptables_script;
        redirect_invoke_script += &format!("iptables -t nat -N TNG_EGRESS_{id} ; ");

        redirect_invoke_script += &format!(
            "iptables -t nat -A TNG_EGRESS_{id} -p tcp -m mark --mark {} -j RETURN ; ", // Ignore packets with SO_MARK set to {self.so_mark}
            self.so_mark
        );

        if let Some(addr) = &self.capture_dst.host {
            if self.capture_local_traffic {
                redirect_invoke_script += &format!(
                    "iptables -t nat -A TNG_EGRESS_{id} -p tcp --dst {addr}/32 --dport {} -j REDIRECT --to-ports {} ; ", self.capture_dst.port, self.listen_port
                );
            } else {
                redirect_invoke_script += &format!(
                    "iptables -t nat -A TNG_EGRESS_{id} -p tcp -m addrtype ! --src-type LOCAL --dst {addr}/32 --dport {} -j REDIRECT --to-ports {} ; ", self.capture_dst.port, self.listen_port
                );
            }
        } else if self.capture_local_traffic {
            redirect_invoke_script += &format!(
                "iptables -t nat -A TNG_EGRESS_{id} -p tcp -m addrtype --dst-type LOCAL --dport {} -j REDIRECT --to-ports {} ; ", self.capture_dst.port, self.listen_port
            );
        } else {
            redirect_invoke_script += &format!(
                "iptables -t nat -A TNG_EGRESS_{id} -p tcp -m addrtype ! --src-type LOCAL --dst-type LOCAL --dport {} -j REDIRECT --to-ports {} ; ", self.capture_dst.port, self.listen_port
            );
        }

        redirect_invoke_script += &format!(
            "\
            iptables -t nat -A PREROUTING -p tcp -j TNG_EGRESS_{id} ; \
            iptables -t nat -A OUTPUT -p tcp -j TNG_EGRESS_{id} ; \
            "
        );

        invoke_script += &redirect_invoke_script;
        revoke_script += &clean_up_iptables_script;

        Ok((invoke_script, revoke_script))
    }
}
