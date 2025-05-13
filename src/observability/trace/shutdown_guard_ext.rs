use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

/// This trait is used to spawn supervised tasks with a shutdown guard.
///
/// A supervised task is a task that will be cancelled immediately when the shutdown guard is
/// cancelled. In this case, all the tasks can be cancelled quickly and cleanly when the tng instance
/// is shutting down.
pub trait ShutdownGuardExt {
    #[inline]
    fn spawn_supervised_task_fn_current_span<F, T>(&self, task: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        let span = Span::current();
        self.spawn_supervised_task_fn_with_span(span, task)
    }

    #[inline]
    fn spawn_supervised_task_current_span<T>(&self, task: T) -> tokio::task::JoinHandle<()>
    where
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        let span = Span::current();
        self.spawn_supervised_task_with_span(span, task)
    }

    fn spawn_supervised_task_fn_with_span<F, T>(
        &self,
        span: Span,
        task: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = ()> + Send + 'static;

    fn spawn_supervised_task_with_span<T>(
        &self,
        span: Span,
        task: T,
    ) -> tokio::task::JoinHandle<()>
    where
        T: std::future::Future<Output = ()> + Send + 'static;

    fn spawn_supervised_task_fn<F, T>(&self, task: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = ()> + Send + 'static;

    fn spawn_supervised_task<T>(&self, task: T) -> tokio::task::JoinHandle<()>
    where
        T: std::future::Future<Output = ()> + Send + 'static;
}

impl ShutdownGuardExt for ShutdownGuard {
    #[inline]
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
    fn spawn_supervised_task_with_span<T>(&self, span: Span, task: T) -> tokio::task::JoinHandle<()>
    where
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        let guard_cloned = self.clone();

        self.spawn_task(
            async move {
                tokio::select! {
                    _ = guard_cloned.cancelled() => {/* cancelled, so we just exit here and drop the another future */}
                    () = task.instrument(span) => {/* finished */}
                };
            }
        )
    }

    #[inline]
    fn spawn_supervised_task_fn<F, T>(&self, task: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        let guard = self.clone();
        self.spawn_supervised_task(async move { task(guard).await })
    }

    #[inline]
    fn spawn_supervised_task<T>(&self, task: T) -> tokio::task::JoinHandle<()>
    where
        T: std::future::Future<Output = ()> + Send + 'static,
    {
        let guard_cloned = self.clone();

        self.spawn_task(
            async move {
                tokio::select! {
                    _ = guard_cloned.cancelled() => {/* cancelled, so we just exit here and drop the another future */}
                    () = task => {/* finished */}
                };
            }
        )
    }
}
