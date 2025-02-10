use executor::iptables::IPTablesGuard;
use scopeguard::defer;
use tokio_util::sync::CancellationToken;
use tunnel::TngRuntime;

use anyhow::{Context as _, Result};
use config::TngConfig;

pub mod config;
mod executor;
pub mod tunnel;

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
        // Start native part
        tracing::info!("Starting all components now");

        let (runtime, iptables_actions) = TngRuntime::launch_from_config(self.config)
            .context("Failed to launch envoy executor")?;

        // Setup Iptables
        let _iptables_guard = IPTablesGuard::setup_from_actions(iptables_actions)?;

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

        shutdown.spawn_task_fn(|shutdown_guard| runtime.serve(shutdown_guard, task_exit));

        shutdown.shutdown().await;

        tracing::debug!("All components shutdown complete");

        Ok(())
    }
}
