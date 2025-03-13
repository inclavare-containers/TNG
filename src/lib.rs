use executor::{envoy::EnvoyExecutor, iptables::IPTablesGuard};
use scopeguard::defer;
use tokio::select;
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
        self.serve_with_cancel(CancellationToken::new(), tokio::sync::oneshot::channel().0)
            .await
    }

    pub async fn serve_with_cancel(
        self,
        task_exit: CancellationToken,
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> Result<()> {
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

        let (admin_instance_ready_send, admin_instance_ready_recv) =
            tokio::sync::oneshot::channel();

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

        let envoy_executor =
            EnvoyExecutor::new(blueprint.envoy_config, blueprint.envoy_admin_endpoint);
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

    use axum::{routing::get, Router};
    use http::StatusCode;
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;

    pub async fn launch_fake_falcon_server(port: u16) {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            async fn handler() -> Result<(StatusCode, std::string::String), ()> {
                Ok((StatusCode::OK, "".into()))
            }
            let app = Router::new().route("/{*path}", get(handler));
            let server = axum::serve(listener, app);
            server.await
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_exit_on_cancel() -> Result<()> {
        let port = portpicker::pick_unused_port().unwrap();

        launch_fake_falcon_server(port).await;

        let config: TngConfig = serde_json::from_value(json!(
            {
                "metric": {
                    "exporters": [{
                        "type": "falcon",
                        "server_url": format!("http://127.0.0.1:{port}"),
                        "endpoint": "master-node",
                        "tags": {
                            "namespace": "ns1",
                            "app": "tng-client"
                        },
                        "step": 60
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
        let port = portpicker::pick_unused_port().unwrap();

        launch_fake_falcon_server(port).await;

        let config: TngConfig = serde_json::from_value(json!(
            {
                "metric": {
                    "exporters": [{
                        "type": "falcon",
                        "server_url": format!("http://127.0.0.1:{port}"),
                        "endpoint": "master-node",
                        "tags": {
                            "namespace": "ns1",
                            "app": "tng-client"
                        },
                        "step": 60
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
