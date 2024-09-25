use executor::{envoy::EnvoyExecutor, iptables::IpTablesExecutor};
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
pub mod tunnel;

pub struct TngBuilder {
    config: TngConfig,
}

impl TngBuilder {
    pub fn new(config: TngConfig) -> Self {
        Self { config }
    }

    pub fn launch(self) -> Result<TngInstance> {
        let (envoy_config, iptables_actions) = executor::handle_config(self.config.clone())?;

        let iptables_executor = IpTablesExecutor::new_from_actions(iptables_actions)?;

        // Setup Iptables
        if let Some(iptables_executor) = &iptables_executor {
            info!("Setting up iptables rule");
            if let Err(e) = iptables_executor.setup() {
                let msg = format!("Failed setting up iptables rule: {e}");
                error!("{msg}");
                if let Err(e) = iptables_executor.clean_up() {
                    warn!("Failed cleaning up iptables rule: {e:#}");
                };
                bail!("{msg}");
            }
        }

        // Start Envoy
        let envoy_executor = EnvoyExecutor::launch(&envoy_config)?;

        // Start native part
        info!("Starting native part");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to init tokio runtime for tng native part")?;

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(());

        rt.spawn(async { self::tunnel::run_native_part(stop_rx, self.config).await });

        Ok(TngInstance {
            envoy_executor,
            iptables_executor,
            rt,
            stop_tx,
        })
    }
}

pub struct TngInstance {
    envoy_executor: EnvoyExecutor,
    iptables_executor: Option<IpTablesExecutor>,
    rt: tokio::runtime::Runtime,
    stop_tx: tokio::sync::watch::Sender<()>,
}

impl TngInstance {
    pub fn stopper(&mut self) -> TngInstanceStopper {
        TngInstanceStopper {
            envoy_process_pid: self.envoy_executor.pid(),
            rt_handle: self.rt.handle().clone(),
            stop_tx: self.stop_tx.clone(),
        }
    }

    pub fn wait(&mut self) -> Result<ExitStatus> {
        self.envoy_executor.wait()

        // self.rt.shutdown_timeout(Duration::from_millis(1000));
    }

    pub fn clean_up(&mut self) -> Result<()> {
        let exit_status = self.envoy_executor.clean_up()?;

        if let Some(iptables_executor) = &self.iptables_executor {
            info!("Cleaning up iptables rule (if needed)");
            if let Err(e) = iptables_executor.clean_up() {
                warn!("Failed cleaning up iptables rule: {e:#}");
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
    rt_handle: tokio::runtime::Handle,
    stop_tx: tokio::sync::watch::Sender<()>,
}

impl TngInstanceStopper {
    pub fn stop(&self) -> Result<()> {
        signal::kill(
            Pid::from_raw(self.envoy_process_pid as pid_t),
            Signal::SIGTERM,
        )
        .context("Failed to terminate envoy process")?;

        let stop_tx = self.stop_tx.clone();
        self.rt_handle.spawn(async move {
            if let Err(e) = stop_tx.send(()) {
                panic!("Failed to send STOP to TNG native part: {e:#}");
            }
        });

        Ok(())
    }
}
