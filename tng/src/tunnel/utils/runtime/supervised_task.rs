use anyhow::{bail, Result};
#[cfg(wasm)]
use tokio_with_wasm::alias as tokio;
use tracing::{Instrument, Span};

use crate::tunnel::utils::runtime::future::TokioRuntimeSupportedFuture;

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

/// Methods for spawning supervised tasks
impl super::TokioRuntime {
    #[inline]
    #[track_caller]
    pub fn spawn_supervised_task_fn_current_span<F, T, O: std::marker::Send + 'static>(
        &self,
        task: F,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        F: FnOnce(super::TokioRuntime) -> T + Send + 'static,
        T: TokioRuntimeSupportedFuture<O>,
    {
        let span = Span::current();
        self.spawn_supervised_task_fn_with_span(span, task)
    }

    #[inline]
    #[track_caller]
    pub fn spawn_supervised_task_current_span<T, O: std::marker::Send + 'static>(
        &self,
        task: T,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        T: TokioRuntimeSupportedFuture<O>,
    {
        let span = Span::current();
        self.spawn_supervised_task_with_span(span, task)
    }

    #[inline]
    #[track_caller]
    pub fn spawn_supervised_task_fn_with_span<F, T, O: std::marker::Send + 'static>(
        &self,
        span: Span,
        task: F,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        F: FnOnce(super::TokioRuntime) -> T + Send + 'static,
        T: TokioRuntimeSupportedFuture<O>,
    {
        let runtime_cloned: super::TokioRuntime = self.clone();
        self.spawn_supervised_task_with_span(span, async move { task(runtime_cloned).await })
    }

    #[inline]
    #[track_caller]
    pub fn spawn_supervised_task_with_span<T, O: std::marker::Send + 'static>(
        &self,
        span: Span,
        task: T,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        T: TokioRuntimeSupportedFuture<O>,
    {
        let guard_cloned = self.shutdown_guard.clone();

        self.spawn_task_named(&format!("{span:?}"), async move {
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
    pub fn spawn_supervised_task_fn<F, T, O: std::marker::Send + 'static>(
        &self,
        task: F,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        F: FnOnce(super::TokioRuntime) -> T + Send + 'static,
        T: TokioRuntimeSupportedFuture<O>,
    {
        let runtime_cloned: super::TokioRuntime = self.clone();
        self.spawn_supervised_task(async move { task(runtime_cloned).await })
    }

    #[inline]
    #[track_caller]
    pub fn spawn_supervised_task<T, O: std::marker::Send + 'static>(
        &self,
        task: T,
    ) -> tokio::task::JoinHandle<SupervisedTaskResult<O>>
    where
        T: TokioRuntimeSupportedFuture<O>,
    {
        let guard_cloned = self.shutdown_guard.clone();

        self.spawn_task_named("unnamed", async move {
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
}
