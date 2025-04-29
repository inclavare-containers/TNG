use tokio_graceful::ShutdownGuard;
use tracing::{Instrument, Span};

pub trait ShutdownGuardExt {
    fn spawn_task_fn_current_span<F, T>(&self, task: F) -> tokio::task::JoinHandle<T::Output>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future + Send + 'static,
        T::Output: Send + 'static,
    {
        let span = Span::current();
        self.spawn_task_fn_with_span(span, task)
    }

    fn spawn_task_current_span<T>(&self, task: T) -> tokio::task::JoinHandle<T::Output>
    where
        T: std::future::Future + Send + 'static,
        T::Output: Send + 'static,
    {
        let span = Span::current();
        self.spawn_task_with_span(span, task)
    }

    fn spawn_task_fn_with_span<F, T>(
        &self,
        span: Span,
        task: F,
    ) -> tokio::task::JoinHandle<T::Output>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future + Send + 'static,
        T::Output: Send + 'static;

    fn spawn_task_with_span<T>(&self, span: Span, task: T) -> tokio::task::JoinHandle<T::Output>
    where
        T: std::future::Future + Send + 'static,
        T::Output: Send + 'static;
}

impl ShutdownGuardExt for ShutdownGuard {
    fn spawn_task_fn_with_span<F, T>(
        &self,
        span: Span,
        task: F,
    ) -> tokio::task::JoinHandle<T::Output>
    where
        F: FnOnce(tokio_graceful::ShutdownGuard) -> T + Send + 'static,
        T: std::future::Future + Send + 'static,
        T::Output: Send + 'static,
    {
        self.spawn_task_fn(|guard| async move { task(guard).instrument(span).await })
    }

    fn spawn_task_with_span<T>(&self, span: Span, task: T) -> tokio::task::JoinHandle<T::Output>
    where
        T: std::future::Future + Send + 'static,
        T::Output: Send + 'static,
    {
        self.spawn_task(task.instrument(span))
    }
}
