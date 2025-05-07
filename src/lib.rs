use shadow_rs::shadow;

pub mod config;
mod control_interface;
mod executor;
mod observability;
pub mod runtime;
mod service;
mod state;
mod tunnel;

shadow!(build);

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use once_cell::sync::OnceCell;
    use scopeguard::defer;
    use serde_json::json;
    use tokio::select;
    use tokio_util::sync::CancellationToken;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

    use crate::{
        config::TngConfig,
        runtime::{TngRuntime, TracingReloadHandle},
    };

    pub static RELOAD_HANDLE: OnceCell<TracingReloadHandle> = OnceCell::new();

    #[ctor::ctor]
    fn init() {
        // Initialize rustls crypto provider
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");

        // Initialize log tracing
        let pending_tracing_layers = vec![];
        let (pending_tracing_layers, reload_handle) =
            tracing_subscriber::reload::Layer::new(pending_tracing_layers);
        tracing_subscriber::registry()
            .with(
                pending_tracing_layers.with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info,tokio_graceful=off,tng=trace".into()),
                ),
            )
            .with(
                tracing_subscriber::fmt::layer().with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info,tokio_graceful=off,tng=debug".into()),
                ),
            )
            .init();
        // Set the reload handle to the global static variable so that we can use it in tests
        if RELOAD_HANDLE.set(reload_handle).is_err() {
            panic!("Failed to set reload handle to global static variable")
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_exit_on_cancel() -> Result<()> {
        let config: TngConfig = serde_json::from_value(json!(
            {
                "add_ingress": [
                    {
                        "mapping": {
                            "in": {
                                "port": portpicker::pick_unused_port().unwrap()
                            },
                            "out": {
                                "host": "127.0.0.1",
                                "port": portpicker::pick_unused_port().unwrap()
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
            TngRuntime::from_config(config)
                .await?
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
                "add_ingress": [
                    {
                        "mapping": {
                            "in": {
                                "port": portpicker::pick_unused_port().unwrap()
                            },
                            "out": {
                                "host": "127.0.0.1",
                                "port": portpicker::pick_unused_port().unwrap()
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
            TngRuntime::from_config(config)
                .await?
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
