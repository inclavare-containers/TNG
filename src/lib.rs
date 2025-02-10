use executor::{envoy::EnvoyExecutor, iptables::IPTablesGuard};
use scopeguard::defer;
use tokio_util::sync::CancellationToken;

use anyhow::{Context as _, Result};
use config::TngConfig;
use log::info;

pub mod config;
mod executor;
mod observability;

pub struct TngBuilder {
    config: TngConfig,
}

impl TngBuilder {
    pub fn from_config(config: TngConfig) -> Self {
        Self { config }
    }

    pub async fn serve_forever(self) -> Result<()> {
        self.serve_with_cancel(CancellationToken::new()).await
    }

    pub async fn serve_with_cancel(self, task_exit: CancellationToken) -> Result<()> {
        // Handle tng config
        let blueprint = executor::handle_config(self.config)?;

        // Setup Iptables
        let _iptables_guard = IPTablesGuard::setup_from_actions(blueprint.iptables_actions)?;

        let for_cancel_safity = task_exit.clone();
        defer! {
            // Cancel-Safity: exit tng in case of the future of this function is dropped
            for_cancel_safity.cancel();
        }

        let shutdown = {
            let task_exit = task_exit.clone();
            tokio_graceful::Shutdown::builder()
                .with_signal(async move {
                    tokio::select! {
                        _ = task_exit.cancelled() => {}
                        _ = tokio_graceful::default_signal() => {}
                    }
                })
                .with_overwrite_fn(tokio::signal::ctrl_c)
                .build()
        };

        let metric_collector = blueprint.metric_collector;
        shutdown.spawn_task_fn(|shutdown_guard| async move {
            // TODO: wait until the envoy process is ready
            // Starting Metric Collector
            metric_collector
                .serve(shutdown_guard)
                .await
                .context("Failed to launch metric collector")
        });

        shutdown.spawn_task_fn(move |shutdown_guard| async move {
            // Starting Envoy process
            EnvoyExecutor::serve(&blueprint.envoy_config, shutdown_guard, task_exit)
                .await
                .context("Failed to launch envoy executor")
        });

        shutdown.shutdown().await;

        info!("Tng instance shutdown complete");

        Ok(())
    }
}
