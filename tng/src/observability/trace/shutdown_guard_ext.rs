use std::{future::Future, sync::Arc};

use anyhow::{bail, Result};
use tokio_graceful::ShutdownGuard;
use tokio_with_wasm::alias as tokio;
use tracing::{Instrument, Span};

use crate::tunnel::utils::runtime::TokioRuntime;

#[derive(Debug)]
pub enum SupervisedTaskResult<O> {
    /// The task finished successfully.
    Finished(O),
    /// The task was cancelled.
    Cancelled,
}

impl<O> SupervisedTaskResult<O> {
    #[allow(dead_code)]
    pub fn assume_finished(self) -> Result<O> {
        match self {
            Self::Finished(o) => Ok(o),
            Self::Cancelled => bail!("task was cancelled"),
        }
    }
}

/// This trait is used to spawn supervised tasks with a shutdown guard.
///
/// A supervised task is a task that will be cancelled immediately when the shutdown guard is
/// cancelled. In this case, all the tasks can be cancelled quickly and cleanly when the tng instance
/// is shutting down.
#[allow(dead_code)]
pub trait ShutdownGuardExt {
    #[inline]
    fn as_hyper_executor(self, rt: Arc<TokioRuntime>) -> ShutdownGuardHyperExecutor<Self>
    where
        Self: Sized,
    {
        ShutdownGuardHyperExecutor { inner: self, rt }
    }

    #[inline]
    #[track_caller]
    fn spawn_supervised_task_fn_current_span<F, T, O: std::marker::Send + 'static>(
        &self,
        task: F,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = O> + Send + 'static,
    {
        let span = Span::current();
        self.spawn_supervised_task_fn_with_span(span, task)
    }

    #[inline]
    #[track_caller]
    fn spawn_supervised_task_current_span<T, O: std::marker::Send + 'static>(
        &self,
        task: T,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        T: std::future::Future<Output = O> + Send + 'static,
    {
        let span = Span::current();
        self.spawn_supervised_task_with_span(span, task)
    }

    #[track_caller]
    fn spawn_supervised_task_fn_with_span<F, T, O: std::marker::Send + 'static>(
        &self,
        span: Span,
        task: F,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = O> + Send + 'static;

    #[track_caller]
    fn spawn_supervised_task_with_span<T, O: std::marker::Send + 'static>(
        &self,
        span: Span,
        task: T,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        T: std::future::Future<Output = O> + Send + 'static;

    #[track_caller]
    fn spawn_supervised_task_fn<F, T, O: std::marker::Send + 'static>(
        &self,
        task: F,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = O> + Send + 'static;

    #[track_caller]
    fn spawn_supervised_task<T, O: std::marker::Send + 'static>(
        &self,
        task: T,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        T: std::future::Future<Output = O> + Send + 'static;

    #[cfg(feature = "wasm")]
    #[track_caller]
    fn spawn_supervised_wasm_local_task_with_span<T>(&self, span: Span, task: T)
    where
        T: std::future::Future<Output = ()> + 'static;
}

impl ShutdownGuardExt for ShutdownGuard {
    #[inline]
    #[track_caller]
    fn spawn_supervised_task_fn_with_span<F, T, O: std::marker::Send + 'static>(
        &self,
        span: Span,
        task: F,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = O> + Send + 'static,
    {
        let guard = self.clone();
        self.spawn_supervised_task_with_span(span, async move { task(guard).await })
    }

    #[inline]
    #[track_caller]
    fn spawn_supervised_task_with_span<T, O: std::marker::Send + 'static>(
        &self,
        span: Span,
        task: T,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        T: std::future::Future<Output = O> + Send + 'static,
    {
        let guard_cloned = self.clone();

        spawn_task_named(self, &format!("{span:?}"), async move {
            tokio::select! {
                _ = guard_cloned.cancelled() => {
                    /* cancelled, so we just exit here and drop the another future */
                    SupervisedTaskResult::Cancelled
                }
                output = task.instrument(span) => {
                    /* finished */
                    SupervisedTaskResult::Finished(output)
                }
            }
        })
    }

    #[inline]
    #[track_caller]
    fn spawn_supervised_task_fn<F, T, O: std::marker::Send + 'static>(
        &self,
        task: F,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = O> + Send + 'static,
    {
        let guard = self.clone();
        self.spawn_supervised_task(async move { task(guard).await })
    }

    #[inline]
    #[track_caller]
    fn spawn_supervised_task<T, O: std::marker::Send + 'static>(
        &self,
        task: T,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        T: std::future::Future<Output = O> + Send + 'static,
    {
        let guard_cloned = self.clone();

        spawn_task_named(self, "unnamed", async move {
            tokio::select! {
                _ = guard_cloned.cancelled() => {
                    /* cancelled, so we just exit here and drop the another future */
                    SupervisedTaskResult::Cancelled
                }
                output = task => {
                    /* finished */
                    SupervisedTaskResult::Finished(output)
                }
            }
        })
    }

    #[cfg(feature = "wasm")]
    #[track_caller]
    fn spawn_supervised_wasm_local_task_with_span<T>(&self, span: Span, task: T)
    where
        T: std::future::Future<Output = ()> + 'static,
    {
        let guard_cloned = self.clone();

        wasm_bindgen_futures::spawn_local(async move {
            task.instrument(span).await;
            drop(guard_cloned);
        })
    }
}

#[track_caller]
fn spawn_task_named<T>(
    guard: &ShutdownGuard,
    name: &str,
    task: T,
) -> tokio::task::JoinHandle<T::Output>
where
    T: std::future::Future + Send + 'static,
    T::Output: Send + 'static,
{
    let guard = guard.clone();

    // Spawn a task with a name is a unstable feature
    #[cfg(tokio_unstable)]
    let handle = tokio::task::Builder::new()
        .name(name)
        .spawn(async move {
            let output = task.await;
            drop(guard);
            output
        })
        .expect("Bug detected");

    #[cfg(not(tokio_unstable))]
    let handle = {
        let _ = name;
        tokio::spawn(async move {
            let output = task.await;
            drop(guard);
            output
        })
    };

    handle
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ShutdownGuardHyperExecutor<T: ShutdownGuardExt> {
    inner: T,
    rt: Arc<TokioRuntime>,
}

impl<Fut, T: ShutdownGuardExt> hyper::rt::Executor<Fut> for ShutdownGuardHyperExecutor<T>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    #[inline(always)]
    #[track_caller]
    fn execute(&self, fut: Fut) {
        #[cfg(feature = "unix")]
        let _guard = self.rt.tokio_rt_handle().enter();
        self.inner.spawn_supervised_task_current_span(fut);
    }
}
