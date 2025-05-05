use std::{
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixListener},
    },
    process::Command,
};

use anyhow::{bail, Context, Result};

pub trait IptablesRuleGenerator {
    fn gen_script(&self) -> Result<(String, String)>;
}

pub struct IptablesExecutor {}

pub struct IptablesGuard {
    iptables_revoke_script: String,
    _unix_listener: UnixListener,
}

impl IptablesExecutor {
    pub fn setup(rule_generator: &impl IptablesRuleGenerator) -> Result<IptablesGuard> {
        tracing::info!("Setting up iptables rule");

        // Check if there is annother TNG instance running in same network namespace.
        let unix_listener = UnixListener::bind_addr(&SocketAddr::from_abstract_name(b"tng")?).context("Running more than 1 TNG instances concurrently in same network namespace which need iptables rules is not supported in current TNG version")?;

        let (iptables_invoke_script, iptables_revoke_script) = rule_generator.gen_script()?;

        let guard = IptablesGuard {
            iptables_revoke_script,
            _unix_listener: unix_listener,
        };

        IptablesExecutor::execute_script(&iptables_invoke_script)?;

        Ok(guard)
    }

    fn execute_script(script: &str) -> Result<()> {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(&format!("set -e ; true ; {}", script));
        let output = cmd.output();

        match output {
            Ok(output) => {
                tracing::debug!(
                    "execute iptable script:\n{cmd:?}\nstdout:\n{}\nstderr:\n{}",
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
}

impl Drop for IptablesGuard {
    fn drop(&mut self) {
        if let Err(e) = IptablesExecutor::execute_script(&self.iptables_revoke_script) {
            tracing::error!("Failed to revoke iptables rules: {e:#}");
        }
    }
}
