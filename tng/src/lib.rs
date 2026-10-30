#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use shadow_rs::shadow;

pub mod config;
#[cfg(not(wasm))]
mod control_interface;
pub mod error;
#[cfg(not(wasm))]
pub mod exec;
#[cfg(target_os = "linux")]
pub mod hook_log_collector;
#[cfg(not(wasm))]
mod observability;
pub mod rolling;
#[cfg(not(wasm))]
pub mod runtime;
#[cfg(not(wasm))]
mod service;
#[cfg(not(wasm))]
mod state;
#[cfg(not(wasm))]
pub(crate) mod status;
#[cfg(feature = "tools")]
pub mod tools;
pub mod tunnel;

shadow!(build);

pub(crate) const HTTP_REQUEST_USER_AGENT_HEADER: &str =
    const_format::concatcp!("tng/", crate::build::PKG_VERSION);

#[cfg(not(wasm))]
pub(crate) const HTTP_RESPONSE_SERVER_HEADER: &str =
    const_format::concatcp!("tng/", crate::build::PKG_VERSION);

pub use crate::tunnel::attestation_result::{AttestationResult, AttestationState};
pub use crate::tunnel::ra_context::RaContext;
pub use crate::tunnel::stream::{CommonStreamTrait, ContextualStream};
pub use crate::tunnel::utils::drain::DrainRegistry;
pub use crate::tunnel::utils::runtime::TokioRuntime;
pub use crate::tunnel::utils::tokio::TokioIo;

pub fn show_banner(mode: &str) {
    #[cfg(not(wasm))]
    let mode = format_args!("(mode: {}, pid: {})", mode, std::process::id());
    #[cfg(wasm)]
    let mode = format_args!("(mode: {})", mode);

    tracing::info!(
        r#"
  _______   ________
 /_  __/ | / / ____/
  / / /  |/ / / __
 / / / /|  / /_/ /  Welcome to the Trusted Network Gateway! {}
/_/ /_/ |_/\____/   version: v{}  commit: {}  buildtime: {}"#,
        mode,
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );
}

#[cfg(test)]
pub(crate) mod tests {

    use std::future::Future;

    use anyhow::{anyhow, Result};
    use once_cell::sync::OnceCell;
    use scopeguard::defer;
    use serde_json::json;
    use tokio::select;
    use tokio_util::sync::CancellationToken;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

    use crate::{
        config::TngConfig,
        runtime::{TngRuntime, TracingReloadHandle},
        DrainRegistry, TokioRuntime,
    };

    pub static RELOAD_HANDLE: OnceCell<TracingReloadHandle> = OnceCell::new();

    #[ctor::ctor]
    fn init() {
        // Initialize rustls crypto provider
        #[cfg(not(wasm))]
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        #[cfg(wasm)]
        let provider = rustls::crypto::ring::default_provider();
        provider
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
                tracing_subscriber::fmt::layer()
                    .with_ansi(atty::is(atty::Stream::Stdout))
                    .with_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(
                            |_| "info,tokio_graceful=off,rats_cert=debug,tng=debug".into(),
                        ),
                    ),
            )
            .init();
        // Set the reload handle to the global static variable so that we can use it in tests
        if RELOAD_HANDLE.set(reload_handle).is_err() {
            panic!("Failed to set reload handle to global static variable")
        }
    }

    // Serf cluster teardown can legitimately take seconds under CI CPU
    // contention; 30s is far past that, so a longer wait means a supervised
    // task is wedged, not merely slow.
    const DEFAULT_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    pub async fn run_test_with_tokio_runtime<F, T>(f: F) -> Result<()>
    where
        F: FnOnce(TokioRuntime) -> T,
        T: Future<Output = Result<()>>,
    {
        run_test_with_tokio_runtime_with_shutdown_timeout(f, DEFAULT_SHUTDOWN_TIMEOUT).await
    }

    async fn run_test_with_tokio_runtime_with_shutdown_timeout<F, T>(
        f: F,
        shutdown_timeout: std::time::Duration,
    ) -> Result<()>
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

        let res = async {
            f(TokioRuntime::current(
                shutdown.guard(),
                DrainRegistry::new_shared(),
            )?)
            .await
        }
        .await;

        cancel.cancel();
        if tokio::time::timeout(shutdown_timeout, shutdown.shutdown())
            .await
            .is_err()
        {
            tracing::error!(
                ?shutdown_timeout,
                "Supervised tasks did not drain before the shutdown timeout; a task is leaking its shutdown guard"
            );
            // The test's own failure takes precedence; the leak is already logged.
            if res.is_ok() {
                return Err(anyhow!(
                    "supervised tasks did not finish within {shutdown_timeout:?} of test shutdown"
                ));
            }
        }

        res
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_run_test_with_tokio_runtime_shutdown_timeout_on_leaked_guard() -> Result<()> {
        let outer = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            run_test_with_tokio_runtime_with_shutdown_timeout(
                |runtime| async move {
                    runtime.spawn_supervised_task_with_span(
                        tracing::info_span!("leaked_supervised_task"),
                        std::future::pending::<()>(),
                    );
                    // A wedged supervised task holds a strong guard past its
                    // own cancellation. Leak one synchronously in the body so
                    // the blocked drain does not depend on when the spawned
                    // task is first polled; otherwise shutdown can complete
                    // before the task ever runs.
                    let guard = runtime.shutdown_guard().clone();
                    std::mem::forget(guard);
                    Ok(())
                },
                std::time::Duration::from_secs(1),
            ),
        )
        .await;

        let res = match outer {
            Err(_elapsed) => {
                return Err(anyhow!(
                    "run_test_with_tokio_runtime_with_shutdown_timeout hung despite the bounded shutdown wait"
                ));
            }
            Ok(res) => res,
        };
        let err = match res {
            Ok(()) => {
                return Err(anyhow!(
                    "wrapper returned Ok although a supervised task leaked its shutdown guard"
                ));
            }
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("did not finish within"),
            "unexpected error message: {msg}"
        );
        assert!(
            msg.contains("1s"),
            "error message should name the shutdown timeout: {msg}"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_run_test_with_tokio_runtime_waits_for_supervised_task() -> Result<()> {
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            run_test_with_tokio_runtime_with_shutdown_timeout(
                |runtime| async move {
                    runtime.spawn_supervised_task(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    });
                    Ok(())
                },
                std::time::Duration::from_secs(5),
            ),
        )
        .await
        .map_err(|_| anyhow!("wrapper did not return within its outer bound"))?;

        assert!(
            res.is_ok(),
            "wrapper should return Ok when supervised tasks drain: {res:?}"
        );
        Ok(())
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

        #[allow(clippy::disallowed_methods)]
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
        #[allow(clippy::disallowed_methods)]
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

    /// A service that fails before reporting ready must not produce a ready
    /// signal: with the ingress port already held by an outside listener, the
    /// runtime exits on the bind error and the ready channel closes without
    /// ever sending. Guards the readiness loop against treating the ready
    /// channel closing (every sender dropped by failing services) as if all
    /// services had reported ready.
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_no_ready_when_all_services_fail() -> Result<()> {
        use tokio::net::TcpListener;

        // Pick a port and grab it in one step; retry if another process
        // raced us to it between portpicker's probe and our bind.
        let (holder, port) = loop {
            let port = portpicker::pick_unused_port().unwrap();
            match TcpListener::bind(("0.0.0.0", port)).await {
                Ok(listener) => break (listener, port),
                Err(_) => continue,
            }
        };

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
                        "no_ra": true
                    }
                ]
            }
        ))?;

        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();

        let tng_runtime = TngRuntime::from_config(config).await?;
        #[allow(clippy::disallowed_methods)]
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
                if res.is_ok() {
                    defer! {
                        std::process::exit(1);
                    }
                    panic!("tng reported ready although the only service failed to serve");
                }
            }
        }

        // The runtime must exit on the bind error, whether it surfaces the
        // error as a return value or only in the logs: what matters for this
        // regression is that it never signaled ready on the way out.
        select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                defer! {
                    std::process::exit(1);
                }
                panic!("Wait for tng exit timeout")
            }
            _ = join_handle => {}
        }

        drop(holder);
        Ok(())
    }
}
