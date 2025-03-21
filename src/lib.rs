use control_interface::ControlInterface;
use executor::{
    envoy::{admin_interface::EnvoyAdminInterface, EnvoyExecutor},
    iptables::IPTablesGuard,
};
use scopeguard::defer;
use tokio::select;
use tokio_util::sync::CancellationToken;

use anyhow::{Context as _, Result};
use config::TngConfig;
use log::info;

pub mod config;
mod control_interface;
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
        self.serve_with_cancel(CancellationToken::new(), tokio::sync::oneshot::channel().0)
            .await
    }

    pub async fn serve_with_cancel(
        self,
        task_exit: CancellationToken,
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> Result<()> {
        // Handle tng config
        let blueprint = executor::handle_config(&self.config)?;

        // Setup Iptables
        let _iptables_guard = IPTablesGuard::setup_from_actions(blueprint.iptables_actions)?;

        let for_cancel_safity = task_exit.clone();
        defer! {
            // Cancel-Safity: exit tng in case of the future of this function is dropped
            for_cancel_safity.cancel();
        }

        // Prepare for graceful shutdown
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

        // Channel to receive envoy process ready signal
        let (admin_instance_ready_send, admin_instance_ready_recv) =
            tokio::sync::oneshot::channel();

        // Launch Metric Collector
        let metric_collector = blueprint.metric_collector;
        shutdown.spawn_task_fn(|shutdown_guard| async move {
            select! {
                _ = shutdown_guard.cancelled() => { return Ok(()) /* exit here */ }
                res = admin_instance_ready_recv =>{
                    if res != Ok(()) {
                        return Ok(())// if we got error when waiting for envoy process ready, then exit
                    }
                }
            };

            // Starting Metric Collector
            metric_collector
                .serve(shutdown_guard)
                .await
                .context("Failed to launch metric collector")
        });

        let envoy_admin_interface = EnvoyAdminInterface::new(blueprint.envoy_admin_endpoint);

        // Launch Control Interface
        if let Some(control_interface) = self.config.control_interface {
            ControlInterface::launch(
                control_interface,
                envoy_admin_interface.clone(),
                shutdown.guard(),
            )
            .await
            .context("Failed to launch control interface")?
        }

        let envoy_executor = EnvoyExecutor::new(blueprint.envoy_config, envoy_admin_interface);
        shutdown.spawn_task_fn(move |shutdown_guard| async move {
            // Starting Envoy process
            envoy_executor
                .serve(shutdown_guard, task_exit, admin_instance_ready_send, ready)
                .await
                .context("Failed to launch envoy executor")
        });

        shutdown.shutdown().await;

        info!("Tng instance shutdown complete");

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[cfg(test)]
    #[ctor::ctor]
    fn init() {
        let env = env_logger::Env::default()
            .filter_or("TNG_LOG_LEVEL", "none,tng=trace")
            .write_style_or("TNG_LOG_STYLE", "always"); // enable color
        env_logger::Builder::from_env(env).init();
    }

    use serde_json::json;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_exit_on_cancel() -> Result<()> {
        let config: TngConfig = serde_json::from_value(json!(
            {
                "metric": {
                    "exporters": [{
                        "type": "stdout",
                        "step": 1
                    }]
                },
                "add_ingress": [
                    {
                        "mapping": {
                            "in": {
                                "port": 10001
                            },
                            "out": {
                                "host": "127.0.0.1",
                                "port": 30001
                            }
                        },
                        "no_ra": true
                    }
                ]
            }
        ))?;

        let cancel_token = CancellationToken::new();
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();

        let cancel_token_clone = cancel_token.clone();
        let join_handle = tokio::task::spawn(async move {
            TngBuilder::from_config(config)
                .serve_with_cancel(cancel_token_clone, ready_sender)
                .await
        });

        ready_receiver.await?;
        // tng is ready now, so we cancel it

        cancel_token.cancel();

        select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                defer! {
                    std::process::exit(1);
                }
                panic!("Wait for tng exit timeout")
            }
            _ = join_handle => {}
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_exit_on_envoy_error() -> Result<()> {
        let config: TngConfig = serde_json::from_value(json!(
            {
                "metric": {
                    "exporters": [{
                        "type": "stdout",
                        "step": 1
                    }]
                },
                "add_ingress": [
                    {
                        "mapping": {
                            "in": {
                                "port": 10001
                            },
                            "out": {
                                "host": "127.0.0.1",
                                "port": 30001
                            }
                        },
                        "attest": {
                            "aa_addr": "unix:///a/not/exist/path"
                        }
                    }
                ]
            }
        ))?;

        let cancel_token = CancellationToken::new();
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();

        let cancel_token_clone = cancel_token.clone();
        let join_handle = tokio::task::spawn(async move {
            TngBuilder::from_config(config)
                .serve_with_cancel(cancel_token_clone, ready_sender)
                .await
        });

        select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                defer! {
                    std::process::exit(1);
                }
                panic!("Wait for tng exit timeout")
            }
            res = ready_receiver => {
                if !res.is_err(){
                    defer! {
                        std::process::exit(1);
                    }
                    panic!("the tng should exit before it is ready");
                }
            }
        }

        select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                defer! {
                    std::process::exit(1);
                }
                panic!("Wait for tng exit timeout")
            }
            _ = join_handle => {}
        }

        Ok(())
    }
}
