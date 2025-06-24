use std::future::Future;

use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

/// This trait is used to spawn supervised tasks with a shutdown guard.
///
/// A supervised task is a task that will be cancelled immediately when the shutdown guard is
/// cancelled. In this case, all the tasks can be cancelled quickly and cleanly when the tng instance
/// is shutting down.
#[allow(dead_code)]
pub trait ShutdownGuardExt {
    #[inline]
    fn as_hyper_executor(
        self,
        rt_handle: tokio::runtime::Handle,
    ) -> ShutdownGuardHyperExecutor<Self>
    where
        Self: Sized,
    {
        ShutdownGuardHyperExecutor {
            inner: self,
            rt_handle,
        }
    }

    #[inline]
    #[track_caller]
    fn spawn_supervised_task_fn_current_span<F, T>(&self, task: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        let span = Span::current();
        self.spawn_supervised_task_fn_with_span(span, task)
    }

    #[inline]
    #[track_caller]
    fn spawn_supervised_task_current_span<T>(&self, task: T) -> tokio::task::JoinHandle<()>
    where
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        let span = Span::current();
        self.spawn_supervised_task_with_span(span, task)
    }

    #[track_caller]
    fn spawn_supervised_task_fn_with_span<F, T>(
        &self,
        span: Span,
        task: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = ()> + Send + 'static;

    #[track_caller]
    fn spawn_supervised_task_with_span<T>(
        &self,
        span: Span,
        task: T,
    ) -> tokio::task::JoinHandle<()>
    where
        T: std::future::Future<Output = ()> + Send + 'static;

    #[track_caller]
    fn spawn_supervised_task_fn<F, T>(&self, task: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = ()> + Send + 'static;

    #[track_caller]
    fn spawn_supervised_task<T>(&self, task: T) -> tokio::task::JoinHandle<()>
    where
        T: std::future::Future<Output = ()> + Send + 'static;
}

impl ShutdownGuardExt for ShutdownGuard {
    #[inline]
    #[track_caller]
    fn spawn_supervised_task_fn_with_span<F, T>(
        &self,
        span: Span,
        task: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        let guard = self.clone();
        self.spawn_supervised_task_with_span(span, async move { task(guard).await })
    }

    #[inline]
    #[track_caller]
    fn spawn_supervised_task_with_span<T>(&self, span: Span, task: T) -> tokio::task::JoinHandle<()>
    where
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        let guard_cloned = self.clone();

        spawn_task_named(self, &format!("{span:?}"), async move {
            tokio::select! {
                _ = guard_cloned.cancelled() => {/* cancelled, so we just exit here and drop the another future */}
                () = task.instrument(span) => {/* finished */}
            };
        })
    }

    #[inline]
    #[track_caller]
    fn spawn_supervised_task_fn<F, T>(&self, task: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        let guard = self.clone();
        self.spawn_supervised_task(async move { task(guard).await })
    }

    #[inline]
    #[track_caller]
    fn spawn_supervised_task<T>(&self, task: T) -> tokio::task::JoinHandle<()>
    where
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        let guard_cloned = self.clone();

        spawn_task_named(self, "unnamed", async move {
            tokio::select! {
                _ = guard_cloned.cancelled() => {/* cancelled, so we just exit here and drop the another future */}
                () = task => {/* finished */}
            };
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
    rt_handle: tokio::runtime::Handle,
}

impl<Fut, T: ShutdownGuardExt> hyper::rt::Executor<Fut> for ShutdownGuardHyperExecutor<T>
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    #[inline(always)]
    #[track_caller]
    fn execute(&self, fut: Fut) {
        let _guard = self.rt_handle.enter();
        self.inner.spawn_supervised_task_current_span(async {
            fut.await;
        });
    }
}
