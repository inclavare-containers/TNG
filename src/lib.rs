use executor::{envoy::EnvoyExecutor, iptables::IpTablesExecutor};
use observability::collector::envoy::MetricCollectorHandle;
use std::process::ExitStatus;

use anyhow::{bail, Context as _, Result};
use config::TngConfig;
use log::{error, info, warn};
use nix::{
    libc::pid_t,
    sys::signal::{self, Signal},
    unistd::Pid,
};

pub mod config;
mod executor;
mod observability;

pub struct TngBuilder {
    config: TngConfig,
}

impl TngBuilder {
    pub fn new(config: TngConfig) -> Self {
        Self { config }
    }

    pub fn launch(self) -> Result<TngInstance> {
        let blueprint = executor::handle_config(self.config)?;

        let iptables_executor = IpTablesExecutor::new_from_actions(&blueprint.iptables_actions)?;

        // Setup Iptables
        if let Some(iptables_executor) = &iptables_executor {
            info!("Setting up iptables rule");
            if let Err(e) = iptables_executor.setup() {
                let msg = format!("Failed setting up iptables rule: {e}");
                error!("{msg}");
                if let Err(e) = iptables_executor.clean_up() {
                    warn!("Failed cleaning up iptables rule: {}", e);
                };
                bail!("{msg}");
            }
        }

        // Start Envoy
        let envoy_executor = EnvoyExecutor::launch(&blueprint.envoy_config)?;

        Ok(TngInstance {
            envoy_executor,
            _metric_collector_handle: blueprint.metric_collector.launch(),
            iptables_executor,
        })
    }
}

pub struct TngInstance {
    envoy_executor: EnvoyExecutor,
    _metric_collector_handle: MetricCollectorHandle,
    iptables_executor: Option<IpTablesExecutor>,
}

impl TngInstance {
    pub fn stopper(&mut self) -> TngInstanceStopper {
        TngInstanceStopper {
            envoy_process_pid: self.envoy_executor.pid(),
        }
    }

    pub fn wait(&mut self) -> Result<ExitStatus> {
        self.envoy_executor.wait()
    }

    pub fn clean_up(&mut self) -> Result<()> {
        let exit_status = self.envoy_executor.clean_up()?;

        if let Some(iptables_executor) = &self.iptables_executor {
            info!("Cleaning up iptables rule (if needed)");
            if let Err(e) = iptables_executor.clean_up() {
                warn!("Failed cleaning up iptables rule: {}", e);
            };
        }

        if exit_status.success() {
            info!("TNG now exit gracefully");
        } else {
            bail!("Envoy exited with unexpected status {exit_status}")
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
