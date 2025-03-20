use scopeguard::defer;
use tokio_util::sync::CancellationToken;
use tunnel::TngRuntime;

use anyhow::{Context as _, Result};
use config::TngConfig;

pub mod config;
mod control_interface;
mod executor;
mod observability;
pub mod tunnel;

pub struct TngBuilder {
    config: TngConfig,
}

impl TngBuilder {
    pub fn from_config(mut config: TngConfig) -> Self {
        if config.admin_bind.is_some() {
            tracing::warn!("The field `admin_bind` in configuration is ignored, since envoy admin interface is deprecated");
            config.admin_bind = None;
        }
        Self { config }
    }

    pub async fn serve_forever(self) -> Result<()> {
        self.serve_with_cancel(CancellationToken::new(), tokio::sync::oneshot::channel().0)
            .await
    }

    pub async fn serve_with_cancel(
        self,
        cancel_by_caller: CancellationToken, // This is a canell token which can be called from the caller to cancel the task. Note that this funnction will not call the cancel() function on this.
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> Result<()> {
        // Start native part
        tracing::info!("Starting all service now");

        let runtime = TngRuntime::new_from_config(self.config)
            .await
            .context("Failed to launch envoy executor")?;

        let cancel_before_func_return = CancellationToken::new();
        let for_cancel_safity = cancel_before_func_return.clone();
        defer! {
            // Cancel-Safity: exit tng in case of the future of this function is dropped
            for_cancel_safity.cancel();
        }

        // Prepare for graceful shutdown
        let shutdown = {
            let cancel_before_func_return = cancel_before_func_return.clone();
            tokio_graceful::Shutdown::builder()
                .with_signal(async move {
                    tokio::select! {
                        _ = cancel_by_caller.cancelled() => {}
                        _ = cancel_before_func_return.cancelled() => {}
                        _ = tokio_graceful::default_signal() => {}
                    }
                })
                .with_overwrite_fn(tokio::signal::ctrl_c)
                .build()
        };

        // Watch the ready signal from the tng runtime state object.
        {
            let mut receiver = runtime.state().ready.0.subscribe();
            shutdown.spawn_task_fn(move |shutdown_guard| {
                async move {
                    loop {
                        tokio::select! {
                            _ = receiver.changed() => {
                                if *receiver.borrow_and_update() {
                                    let _ = ready.send(());// Ignore any error occuring during send
                                    break;
                                }
                            }
                            _ = shutdown_guard.cancelled() => {}
                        }
                    }
                }
            });
        }

        // Wait for the runtime to finish serving.
        runtime.serve(shutdown.guard()).await?;
        // Trigger the shutdown guard to gracefully shutdown all the tokio tasks.
        cancel_before_func_return.cancel();
        // Wait for the shutdown guard to complete.
        shutdown.shutdown().await;

        tracing::debug!("All service shutdown complete");
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use serde_json::json;
    use tokio::select;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    use super::*;

    #[cfg(test)]
    #[ctor::ctor]
    fn init() {
        // Initialize log tracing
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "none,tng=info".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

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
                    panic!("The tng should report the error and exit, before it be ready status");
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
