use std::{
    mem::forget,
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixListener},
    },
};

use anyhow::{Context, Result};
use itertools::Itertools;

use crate::config::Endpoint;

pub enum IpTablesAction {
    Redirect {
        capture_dst: Endpoint,
        listen_port: u16,
        so_mark: u32,
    },
}

pub struct IpTablesActions {
    pub actions: Vec<IpTablesAction>,
}

impl IpTablesActions {
    pub fn new(actions: Vec<IpTablesAction>) -> Self {
        Self { actions }
    }

    ///
    /// Example output:
    ///
    /// ```sh
    /// # invoke_script
    /// iptables -t nat -N TNG_ENGRESS
    /// iptables -t nat -A TNG_ENGRESS -p tcp -m mark --mark 565 -j RETURN
    /// iptables -t nat -A TNG_ENGRESS -p tcp -m addrtype --dst-type LOCAL --dport 30001 -j REDIRECT --to-ports 30000
    /// iptables -t nat -A PREROUTING -p tcp -j TNG_ENGRESS
    /// iptables -t nat -A OUTPUT -p tcp -j TNG_ENGRESS
    ///
    /// # revoke_script
    /// iptables -t nat -D PREROUTING -p tcp -j TNG_ENGRESS
    /// iptables -t nat -D OUTPUT -p tcp -j TNG_ENGRESS
    /// iptables -t nat -F TNG_ENGRESS
    /// iptables -t nat -X TNG_ENGRESS
    /// ```
    ///
    pub fn gen_script(&self) -> Result<(String, String)> {
        let mut invoke_script = "".to_owned();
        let mut revoke_script = "".to_owned();

        if !self.actions.is_empty() {
            // Check if there is annother TNG instance running in same network namespace.
            let listener = UnixListener::bind_addr(&SocketAddr::from_abstract_name(b"tng")?).context("Running more than 1 TNG instances concurrently in same network namespace which need iptables rules is not supported in current TNG version")?;
            forget(listener);

            // Handle 'Redirect' case
            let mut redirect_invoke_script = "".to_owned();

            let clean_up_iptables_script = "\
                iptables -t nat -D PREROUTING -p tcp -j TNG_ENGRESS 2>/dev/null || true ; \
                iptables -t nat -D OUTPUT -p tcp -j TNG_ENGRESS 2>/dev/null || true ; \
                iptables -t nat -F TNG_ENGRESS 2>/dev/null || true ; \
                iptables -t nat -X TNG_ENGRESS 2>/dev/null || true ; \
            ";

            redirect_invoke_script += clean_up_iptables_script;
            redirect_invoke_script += "iptables -t nat -N TNG_ENGRESS ; ";

            for so_mark in self
                .actions
                .iter()
                .filter_map(|action| match action {
                    IpTablesAction::Redirect {
                        capture_dst: _,
                        listen_port: _,
                        so_mark,
                    } => Some(so_mark),
                })
                .unique()
            {
                redirect_invoke_script += &format!(
                    "iptables -t nat -A TNG_ENGRESS -p tcp -m mark --mark {so_mark} -j RETURN ; "
                )
            }

            for action in &self.actions {
                match action {
                    IpTablesAction::Redirect {
                        capture_dst,
                        listen_port,
                        so_mark: _,
                    } => {
                        if let Some(addr) = &capture_dst.host {
                            redirect_invoke_script += &format!(
                                "iptables -t nat -A TNG_ENGRESS -p tcp --dst {addr}/32 --dport {} -j REDIRECT --to-ports {listen_port} ; ",capture_dst.port
                            );
                        } else {
                            redirect_invoke_script += &format!(
                                "iptables -t nat -A TNG_ENGRESS -p tcp -m addrtype --dst-type LOCAL --dport {} -j REDIRECT --to-ports {listen_port} ; ",capture_dst.port
                            );
                        }
                    }
                }
            }

            redirect_invoke_script += "iptables -t nat -A PREROUTING -p tcp -j TNG_ENGRESS ; ";
            redirect_invoke_script += "iptables -t nat -A OUTPUT -p tcp -j TNG_ENGRESS ; ";

            invoke_script += &redirect_invoke_script;
            revoke_script += clean_up_iptables_script;
        }
        Ok((invoke_script, revoke_script))
    }
}
