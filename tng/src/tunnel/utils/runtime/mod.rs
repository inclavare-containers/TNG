#![allow(unexpected_cfgs)]

use std::sync::Arc;

use anyhow::Result;
use tokio_graceful::ShutdownGuard;
#[cfg(wasm)]
use tokio_with_wasm::alias as tokio;

use crate::tunnel::utils::runtime::future::TokioRuntimeSupportedFuture;

pub mod future;
pub mod hyper;
pub mod supervised_task;

/// This is a wrapper around tokio::runtime::Runtime, to make it easier to manage the shutdown of the task.
///
/// It enables fine-grained control over how tasks behave during shutdown of the tng instance:
///
/// - A **supervised task** is tied to the lifetime of this runtime wrapper. It will be cancelled
///   immediately when the shutdown guard is dropped. This allows the entire instance to shut down
///   quickly and cleanly.
///
/// - An **unsupervised task**, in contrast, is spawned independently (e.g., via `tokio::spawn` on
///   a long-lived handle) and may continue running even after shutdown has begun. Such tasks can
///   prevent the tng instance from exiting until they complete on their own.
///
/// By ensuring most work is done in supervised contexts, we minimize graceful shutdown time and
/// avoid lingering tasks. Critical background operations that must finish can remain unsupervised,
/// at the cost of longer shutdown latency.
#[derive(Debug, Clone)]
pub struct TokioRuntime {
    inner: Arc<TokioRuntimeInner>,
    #[allow(unused)]
    shutdown_guard: ShutdownGuard,
}

#[derive(Debug)]
enum TokioRuntimeInner {
    #[cfg(unix)]
    Owned {
        rt: Option<tokio::runtime::Runtime>,
        rt_handle: tokio::runtime::Handle,
    },
    #[cfg(unix)]
    Reference { rt_handle: tokio::runtime::Handle },
    #[cfg(wasm)]
    WasmMainThread,
}

impl TokioRuntime {
    #[cfg(unix)]
    #[allow(dead_code)]
    pub fn new_multi_thread(shutdown_guard: ShutdownGuard) -> Result<Self> {
        use anyhow::Context;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?;
        let rt_handle = rt.handle().clone();
        Ok(Self {
            inner: Arc::new(TokioRuntimeInner::Owned {
                rt: Some(rt),
                rt_handle,
            }),
            shutdown_guard,
        })
    }

    #[cfg(unix)]
    #[allow(dead_code)]
    pub fn current(shutdown_guard: ShutdownGuard) -> Result<Self> {
        let rt_handle = tokio::runtime::Handle::try_current()?;
        Ok(Self {
            inner: Arc::new(TokioRuntimeInner::Reference { rt_handle }),
            shutdown_guard,
        })
    }

    #[cfg(wasm)]
    #[allow(dead_code)]
    pub fn wasm_main_thread(shutdown_guard: ShutdownGuard) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(TokioRuntimeInner::WasmMainThread),
            shutdown_guard,
        })
    }

    #[allow(dead_code)]
    pub fn shutdown_guard(&self) -> &ShutdownGuard {
        &self.shutdown_guard
    }
}

/// Core funstions to spawn new task.
impl TokioRuntime {
    #[inline]
    #[track_caller]
    fn spawn_task_named<T, O>(&self, name: &str, task: T) -> tokio::task::JoinHandle<O>
    where
        T: TokioRuntimeSupportedFuture<O>,
        O: Send + 'static,
    {
        let this = self.clone();
        let handle = match self.inner.as_ref() {
            #[cfg(unix)]
            TokioRuntimeInner::Owned { rt: _, rt_handle }
            | TokioRuntimeInner::Reference { rt_handle } => {
                // Spawn a task with a name is a unstable feature
                #[cfg(tokio_unstable)]
                let handle = tokio::task::Builder::new()
                    .name(name)
                    .spawn_on(
                        async move {
                            let output = task.await;
                            drop(this);
                            output
                        },
                        rt_handle,
                    )
                    .expect("Bug detected");

                #[cfg(not(tokio_unstable))]
                let handle = {
                    let _ = name;
                    rt_handle.spawn(async move {
                        let output = task.await;
                        drop(this);
                        output
                    })
                };

                handle
            }
            #[cfg(wasm)]
            TokioRuntimeInner::WasmMainThread => {
                let _ = name;
                tokio::spawn(async move {
                    let output = task.await;
                    drop(this);
                    output
                })
            }
        };

        handle
    }
}

impl Drop for TokioRuntimeInner {
    /// Safely drops the owned runtime by handling the complexities of async context restrictions.
    ///
    /// # The Problem
    ///
    /// Directly dropping a `tokio::runtime::Runtime` from within an asynchronous context (e.g., inside
    /// another spawned task or future) causes a panic:
    ///
    /// ```text
    /// thread 'tokio-runtime-worker' panicked at ...:
    /// Cannot drop a runtime in a context where blocking is not allowed. This happens when a runtime is dropped from within an asynchronous context.
    /// ```
    ///
    /// This happens because the runtime may need to perform blocking operations during shutdown,
    /// which are disallowed in non-blocking contexts.
    ///
    /// # Previous Solution: `shutdown_background()`
    ///
    /// We previously used `rt.shutdown_background()` to avoid this panic. However, that approach
    /// does **not wait** for ongoing work to finish — it detaches the runtime abruptly, increasing
    /// the risk of resource leaks or incomplete cleanup.
    ///
    /// # Current Solution: `spawn_blocking`
    ///
    /// To ensure safe and clean shutdown:
    ///
    /// - If we're currently on a Tokio runtime (`try_current()` succeeds), we use `spawn_blocking`
    ///   to move the actual drop of the `Runtime` into a blocking context where it's allowed.
    /// - Otherwise, we drop the runtime directly (e.g., in a sync context or during program teardown).
    ///
    /// This approach avoids the panic *and* allows proper finalization of any remaining work,
    /// making it safer than `shutdown_background()`.
    ///
    /// Note: Only the `Owned` variant holds a `Runtime`; other variants require no special handling.
    fn drop(&mut self) {
        match self {
            #[cfg(unix)]
            TokioRuntimeInner::Owned { rt, rt_handle: _ } => {
                if let Some(rt_to_drop) = rt.take() {
                    match tokio::runtime::Handle::try_current() {
                        Ok(rt_in_drop_context) => {
                            rt_in_drop_context.spawn_blocking(|| drop(rt_to_drop));
                        }
                        Err(_) => {
                            drop(rt_to_drop);
                        }
                    }
                }
            }
            _ => { /* nothing to do */ }
        }
    }
}
