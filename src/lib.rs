use executor::iptables::IpTablesExecutor;
use tunnel::TngRuntime;

use anyhow::{bail, Context as _, Result};
use config::TngConfig;

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
        // Start native part
        tracing::info!("Starting native part");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to init tokio runtime for tng native part")?;

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(());

        let (runtime, iptables_actions) = TngRuntime::launch_from_config(stop_rx, self.config)
            .context("Failed to launch envoy executor")?;

        // Setup Iptables
        let iptables_executor = IpTablesExecutor::new_from_actions(iptables_actions)?;
        if let Some(iptables_executor) = &iptables_executor {
            tracing::info!("Setting up iptables rule");
            if let Err(e) = iptables_executor.setup() {
                let msg = format!("Failed setting up iptables rule: {e}");
                tracing::error!("{msg}");
                if let Err(e) = iptables_executor.clean_up() {
                    tracing::warn!("Failed cleaning up iptables rule: {e:#}");
                };
                bail!("{msg}");
            }
        }

        rt.spawn(async { runtime.serve().await });

        Ok(TngInstance {
            iptables_executor,
            rt,
            stop_tx,
        })
    }
}

pub struct TngInstance {
    iptables_executor: Option<IpTablesExecutor>,
    rt: tokio::runtime::Runtime,
    stop_tx: tokio::sync::watch::Sender<()>,
}

impl TngInstance {
    pub fn stopper(&mut self) -> TngInstanceStopper {
        TngInstanceStopper {
            rt_handle: self.rt.handle().clone(),
            stop_tx: self.stop_tx.clone(),
        }
    }

    pub fn wait(&mut self) -> Result<()> {
        // TODO: optimize this
        // self.rt.shutdown_timeout(Duration::from_millis(1000));
        Ok(())
    }

    pub fn clean_up(&mut self) -> Result<()> {
        if let Some(iptables_executor) = &self.iptables_executor {
            tracing::info!("Cleaning up iptables rule (if needed)");
            if let Err(e) = iptables_executor.clean_up() {
                tracing::warn!("Failed cleaning up iptables rule: {e:#}");
            };
        }

        Ok(())
    }
}

pub struct TngInstanceStopper {
    rt_handle: tokio::runtime::Handle,
    stop_tx: tokio::sync::watch::Sender<()>,
}

impl TngInstanceStopper {
    pub fn stop(&self) -> Result<()> {
        let stop_tx = self.stop_tx.clone();
        self.rt_handle.spawn(async move {
            if let Err(e) = stop_tx.send(()) {
                panic!("Failed to send STOP to TNG native part: {e:#}");
            }
        });

        Ok(())
    }
}
