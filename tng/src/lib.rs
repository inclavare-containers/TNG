#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use shadow_rs::shadow;

pub mod config;
#[cfg(unix)]
mod control_interface;
pub mod error;
mod observability;
#[cfg(unix)]
pub mod runtime;
#[cfg(unix)]
mod service;
#[cfg(unix)]
mod state;
pub mod tunnel;

shadow!(build);

pub(crate) const HTTP_REQUEST_USER_AGENT_HEADER: &str =
    const_format::concatcp!("tng/", crate::build::PKG_VERSION);

#[cfg(unix)]
pub(crate) const HTTP_RESPONSE_SERVER_HEADER: &str =
    const_format::concatcp!("tng/", crate::build::PKG_VERSION);

pub use crate::tunnel::attestation_result::AttestationResult;
pub use crate::tunnel::stream::CommonStreamTrait;
pub use crate::tunnel::utils::runtime::TokioRuntime;
pub use crate::tunnel::utils::tokio::TokioIo;

#[cfg(test)]
mod tests {

    use std::future::Future;

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
        TokioRuntime,
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
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        "info,tokio_graceful=off,rats_cert=trace,tng=trace".into()
                    }),
                ),
            )
            .with(
                tracing_subscriber::fmt::layer().with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        "info,tokio_graceful=off,rats_cert=debug,tng=debug".into()
                    }),
                ),
            )
            .init();
        // Set the reload handle to the global static variable so that we can use it in tests
        if RELOAD_HANDLE.set(reload_handle).is_err() {
            panic!("Failed to set reload handle to global static variable")
        }
    }

    pub async fn run_test_with_tokio_runtime<F, T>(f: F) -> Result<()>
    where
        F: FnOnce(TokioRuntime) -> T,
        T: Future<Output = Result<()>>,
    {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        defer! {
            cancel_clone.cancel();
        }
        let cancel_clone = cancel.clone();
        let shutdown = tokio_graceful::Shutdown::new(async move { cancel_clone.cancelled().await });

        let res = async { f(TokioRuntime::current(shutdown.guard())?).await }.await;

        cancel.cancel();
        shutdown.shutdown().await;

        res
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

        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();

        let tng_runtime = TngRuntime::from_config(config).await?;
        let canceller = tng_runtime.canceller();

        let join_handle =
            tokio::task::spawn(async move { tng_runtime.serve_with_ready(ready_sender).await });

        ready_receiver.await?;
        // tng is ready now, so we cancel it
        canceller.cancel();

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
    async fn test_exit_on_config_error() -> Result<()> {
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

        assert!(TngRuntime::from_config(config).await.is_err());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_exit_on_serve_error() -> Result<()> {
        let port = portpicker::pick_unused_port().unwrap();

        let config: TngConfig = serde_json::from_value(json!(
            {
                "add_ingress": [
                    {
                        "mapping": {
                            "in": {
                                "port": port
                            },
                            "out": {
                                "host": "127.0.0.1",
                                "port": portpicker::pick_unused_port().unwrap()
                            }
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    },
                    {
                        "mapping": {
                            "in": {
                                "port": port
                            },
                            "out": {
                                "host": "127.0.0.1",
                                "port": portpicker::pick_unused_port().unwrap()
                            }
                        },
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
        ))?;

        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();

        let tng_runtime = TngRuntime::from_config(config).await?;
        let join_handle =
            tokio::task::spawn(async move { tng_runtime.serve_with_ready(ready_sender).await });

        select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                defer! {
                    std::process::exit(1);
                }
                panic!("Wait for tng exit timeout")
            }
            res = ready_receiver => {
                if res.is_ok(){
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
