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
/// A supervised task is a task that will be cancelled immediately when the shutdown guard is
/// cancelled. In this case, all the tasks can be cancelled quickly and cleanly when the tng instance
/// is shutting down.
///
/// # Drop
/// It us shutdown_background() to make prevent the following error:
///
/// ```text
/// thread 'tokio-runtime-worker' panicked at /root/.cargo/registry/src/mirrors.ustc.edu.cn-4affec411d11e50f/tokio-1.45.1/src/runtime/blocking/shutdown.rs:51:21:
/// Cannot drop a runtime in a context where blocking is not allowed. This happens when a runtime is dropped from within an asynchronous context.
/// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
/// ```
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
        let guard = self.shutdown_guard.clone();
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
                            drop(guard);
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
                        drop(guard);
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
                    drop(guard);
                    output
                })
            }
        };

        handle
    }
}

impl Drop for TokioRuntimeInner {
    fn drop(&mut self) {
        match self {
            #[cfg(unix)]
            TokioRuntimeInner::Owned { rt, rt_handle: _ } => {
                if let Some(rt) = rt.take() {
                    rt.shutdown_background();
                }
            }
            _ => { /* nothing to do */ }
        }
    }
}
