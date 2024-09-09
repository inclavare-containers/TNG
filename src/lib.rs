use generator::RuntimeData;
use std::process::{Child, Command, ExitStatus};

use anyhow::{bail, Context as _, Result};
use config::TngConfig;
use log::{error, info, warn};
use nix::{
    libc::pid_t,
    sys::signal::{self, Signal},
    unistd::Pid,
};
use rand::Rng as _;

pub mod config;
mod generator;

pub struct TngBuilder {
    config: TngConfig,
}

pub struct TngInstance {
    envoy_cmd: Command,
    envoy_process: Child,
    runtime_data: RuntimeData,
}

impl TngBuilder {
    pub fn new(config: TngConfig) -> Self {
        Self { config }
    }

    pub fn launch(self) -> Result<TngInstance> {
        let runtime_data = RuntimeData::new(self.config)?;
        let _envoy_config = runtime_data.envoy_config();
        let envoy_config_file = runtime_data.envoy_config_file();

        info!("Generated Envoy config written to: {envoy_config_file:?}");

        // Setup Iptables
        info!("Setting up iptables rule (if needed)");
        if let Err(e) = runtime_data.iptable_setup() {
            let msg = format!("Failed setting up iptables rule: {e}");
            error!("{msg}");
            if let Err(e) = runtime_data.iptable_clean_up() {
                warn!("Failed cleaning up iptables rule: {}", e);
            };
            bail!("{msg}");
        }

        // Start Envoy
        info!("Starting Envoy now");
        let mut cmd = Command::new("envoy-static");
        cmd.arg("-c")
            .arg(envoy_config_file)
            .arg("-l")
            .arg("info")
            .arg("--component-log-level")
            .arg("rats_tls:debug")
            .arg("--base-id")
            .arg(rand::thread_rng().gen::<u32>().to_string()); // Use pid of tng process as base-id of envoy to avoid conflicts
        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to start Envoy with cmd: {cmd:?}"))?;
        info!("Envoy started with PID: {}", child.id());

        Ok(TngInstance {
            envoy_cmd: cmd,
            envoy_process: child,
            runtime_data,
        })
    }
}

impl TngInstance {
    pub fn stopper(&mut self) -> TngInstanceStopper {
        TngInstanceStopper {
            envoy_process_pid: self.envoy_process.id(),
        }
    }

    pub fn wait(&mut self) -> Result<ExitStatus> {
        let exit_status = self
            .envoy_process
            .wait()
            .context("Failed to wait for Envoy process")?;
        Ok(exit_status)
    }

    pub fn clean_up(&mut self) -> Result<()> {
        match self
            .envoy_process
            .try_wait()
            .context("Failed to query envoy process status")?
        {
            Some(_) => {
                // Already exited
            }
            None => {
                // Not exited
                signal::kill(
                    Pid::from_raw(self.envoy_process.id() as pid_t),
                    Signal::SIGTERM,
                )
                .context("Failed to terminate envoy process before cleaning up")?;
            }
        }

        let exit_status = self
            .envoy_process
            .wait()
            .context("Failed to wait for Envoy process during clean up")?;
        info!("Envoy exited with status {exit_status}");

        info!("Cleaning up iptables rule (if needed)");
        if let Err(e) = self.runtime_data.iptable_clean_up() {
            warn!("Failed cleaning up iptables rule: {}", e);
        };

        if exit_status.success() {
            self.runtime_data.envoy_clean_up();

            info!("TNG now exit gracefully");
        } else {
            bail!(
                "Envoy exited with unexpected status {exit_status}, cmd: {:?}",
                self.envoy_cmd
            )
        }

        Ok(())
    }
}

pub struct TngInstanceStopper {
    pub(crate) envoy_process_pid: u32,
}

impl TngInstanceStopper {
    pub fn stop(&self) -> Result<()> {
        signal::kill(
            Pid::from_raw(self.envoy_process_pid as pid_t),
            Signal::SIGTERM,
        )
        .context("Failed to terminate envoy process")?;
        Ok(())
    }
}
