use std::{
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixListener},
    },
    process::Command,
};

use anyhow::{bail, Context, Result};
use itertools::Itertools;
use log::{debug, error, info};

use crate::config::Endpoint;

pub enum IpTablesAction {
    Redirect {
        capture_dst: Endpoint,
        capture_local_traffic: bool,
        listen_port: u16,
        so_mark: u32,
    },
}

pub type IpTablesActions = Vec<IpTablesAction>;

pub struct IPTablesGuard {
    iptables_revoke_script: String,
    _unix_listener: UnixListener,
}

impl IPTablesGuard {
    pub fn setup_from_actions(actions: IpTablesActions) -> Result<Option<Self>> {
        if actions.len() == 0 {
            return Ok(None);
        }

        info!("Setting up iptables rule");

        // Check if there is annother TNG instance running in same network namespace.
        let unix_listener = UnixListener::bind_addr(&SocketAddr::from_abstract_name(b"tng")?).context("Running more than 1 TNG instances concurrently in same network namespace which need iptables rules is not supported in current TNG version")?;

        let (iptables_invoke_script, iptables_revoke_script) = IPTablesGuard::gen_script(&actions)?;

        Self::execute_script(&iptables_invoke_script)?;

        Ok(Some(Self {
            iptables_revoke_script,
            _unix_listener: unix_listener,
        }))
    }

    fn execute_script(script: &str) -> Result<()> {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(&format!("set -e ; true ; {}", script));
        let output = cmd.output();

        match output {
            Ok(output) => {
                debug!(
                    "iptable executor: script:\n{cmd:?}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );

                if !output.status.success() {
                    bail!(
                        "failed to execute iptables script, stderr: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
            Err(e) => {
                bail!("Failed to execute command: {e}");
            }
        }
        Ok(())
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
    pub fn gen_script(actions: &IpTablesActions) -> Result<(String, String)> {
        let mut invoke_script = "".to_owned();
        let mut revoke_script = "".to_owned();

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

        for so_mark in actions
            .iter()
            .filter_map(|action| match action {
                IpTablesAction::Redirect {
                    capture_dst: _,
                    listen_port: _,
                    capture_local_traffic: _,
                    so_mark,
                } => Some(so_mark),
            })
            .unique()
        {
            redirect_invoke_script += &format!(
                "iptables -t nat -A TNG_ENGRESS -p tcp -m mark --mark {so_mark} -j RETURN ; "
            )
        }

        for action in actions {
            match action {
                IpTablesAction::Redirect {
                    capture_dst,
                    listen_port,
                    capture_local_traffic,
                    so_mark: _,
                } => {
                    if let Some(addr) = &capture_dst.host {
                        if *capture_local_traffic {
                            redirect_invoke_script += &format!(
                                    "iptables -t nat -A TNG_ENGRESS -p tcp --dst {addr}/32 --dport {} -j REDIRECT --to-ports {listen_port} ; ",capture_dst.port
                                );
                        } else {
                            redirect_invoke_script += &format!(
                                    "iptables -t nat -A TNG_ENGRESS -p tcp -m addrtype ! --src-type LOCAL --dst {addr}/32 --dport {} -j REDIRECT --to-ports {listen_port} ; ",capture_dst.port
                                );
                        }
                    } else {
                        if *capture_local_traffic {
                            redirect_invoke_script += &format!(
                                    "iptables -t nat -A TNG_ENGRESS -p tcp -m addrtype --dst-type LOCAL --dport {} -j REDIRECT --to-ports {listen_port} ; ",capture_dst.port
                                );
                        } else {
                            redirect_invoke_script += &format!(
                                    "iptables -t nat -A TNG_ENGRESS -p tcp -m addrtype ! --src-type LOCAL --dst-type LOCAL --dport {} -j REDIRECT --to-ports {listen_port} ; ",capture_dst.port
                                );
                        }
                    }
                }
            }
        }

        redirect_invoke_script += "iptables -t nat -A PREROUTING -p tcp -j TNG_ENGRESS ; ";
        redirect_invoke_script += "iptables -t nat -A OUTPUT -p tcp -j TNG_ENGRESS ; ";

        invoke_script += &redirect_invoke_script;
        revoke_script += clean_up_iptables_script;

        Ok((invoke_script, revoke_script))
    }
}

impl Drop for IPTablesGuard {
    fn drop(&mut self) {
        if let Err(e) = Self::execute_script(&self.iptables_revoke_script) {
            error!("Failed to revoke iptables rules: {e:#}");
        }
    }
}
