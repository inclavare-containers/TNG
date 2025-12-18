use std::{future::Future, marker::PhantomData};

use serf::agnostic::Yielder;
use tracing::Instrument;
use tracing::Span;

/// A runtime wrapper that instruments spawned tasks with the current tracing span.
///
/// This type wraps any runtime implementing `serf::agnostic::Runtime` and ensures
/// that all spawned tasks (via associated spawners) automatically inherit the current
/// [`tracing::Span`], enabling seamless distributed tracing and structured logging
/// across asynchronous task boundaries.
///
/// Note: This is a zero-sized type that uses `PhantomData` to carry the inner runtime type.
/// It does not own an instance of `R`, but relies on `R`'s static methods.
#[derive(Clone, Copy)]
pub struct InstrumentedRuntime<R: serf::agnostic::Runtime>(PhantomData<R>);

impl<R: serf::agnostic::Runtime> serf::agnostic::Runtime for InstrumentedRuntime<R> {
    type Net = <R as serf::agnostic::Runtime>::Net;

    type Quinn = <R as serf::agnostic::Runtime>::Quinn;

    #[inline]
    fn quinn() -> Self::Quinn {
        R::quinn()
    }
}

impl<R: serf::agnostic::Runtime> serf::agnostic::RuntimeLite for InstrumentedRuntime<R> {
    type Spawner = InstrumentedSpawner<<R as serf::agnostic::RuntimeLite>::Spawner>;
    type LocalSpawner = InstrumentedLocalSpawner<<R as serf::agnostic::RuntimeLite>::LocalSpawner>;
    type BlockingSpawner =
        InstrumentedBlockingSpawner<<R as serf::agnostic::RuntimeLite>::BlockingSpawner>;
    type Instant = <R as serf::agnostic::RuntimeLite>::Instant;
    type AfterSpawner = InstrumentedAfterSpawner<<R as serf::agnostic::RuntimeLite>::AfterSpawner>;
    type Interval = <R as serf::agnostic::RuntimeLite>::Interval;
    type LocalInterval = <R as serf::agnostic::RuntimeLite>::LocalInterval;
    type Sleep = <R as serf::agnostic::RuntimeLite>::Sleep;
    type LocalSleep = <R as serf::agnostic::RuntimeLite>::LocalSleep;

    type Delay<F>
        = <R as serf::agnostic::RuntimeLite>::Delay<F>
    where
        F: Future + Send;

    type LocalDelay<F>
        = <R as serf::agnostic::RuntimeLite>::LocalDelay<F>
    where
        F: Future;

    type Timeout<F>
        = <R as serf::agnostic::RuntimeLite>::Timeout<F>
    where
        F: Future + Send;

    type LocalTimeout<F>
        = <R as serf::agnostic::RuntimeLite>::LocalTimeout<F>
    where
        F: Future;

    #[inline]
    fn new() -> Self {
        let _ = R::new();
        Self(PhantomData)
    }

    #[inline]
    fn name() -> &'static str {
        R::name()
    }

    #[inline]
    fn fqname() -> &'static str {
        R::fqname()
    }

    #[inline]
    fn block_on<F: Future>(f: F) -> F::Output {
        R::block_on(f)
    }

    #[inline]
    fn yield_now() -> impl Future<Output = ()> + Send {
        R::yield_now()
    }

    #[inline]
    fn interval(interval: core::time::Duration) -> Self::Interval {
        R::interval(interval)
    }

    #[inline]
    fn interval_at(start: Self::Instant, period: core::time::Duration) -> Self::Interval {
        R::interval_at(start, period)
    }

    #[inline]
    fn interval_local(interval: core::time::Duration) -> Self::LocalInterval {
        R::interval_local(interval)
    }

    #[inline]
    fn interval_local_at(
        start: Self::Instant,
        period: core::time::Duration,
    ) -> Self::LocalInterval {
        R::interval_local_at(start, period)
    }

    #[inline]
    fn sleep(duration: core::time::Duration) -> Self::Sleep {
        R::sleep(duration)
    }

    #[inline]
    fn sleep_until(instant: Self::Instant) -> Self::Sleep {
        R::sleep_until(instant)
    }

    #[inline]
    fn sleep_local(duration: core::time::Duration) -> Self::LocalSleep {
        R::sleep_local(duration)
    }

    #[inline]
    fn sleep_local_until(instant: Self::Instant) -> Self::LocalSleep {
        R::sleep_local_until(instant)
    }

    #[inline]
    fn delay<F>(duration: core::time::Duration, fut: F) -> Self::Delay<F>
    where
        F: Future + Send,
    {
        R::delay(duration, fut)
    }

    #[inline]
    fn delay_local<F>(duration: core::time::Duration, fut: F) -> Self::LocalDelay<F>
    where
        F: Future,
    {
        R::delay_local(duration, fut)
    }

    #[inline]
    fn delay_at<F>(deadline: Self::Instant, fut: F) -> Self::Delay<F>
    where
        F: Future + Send,
    {
        R::delay_at(deadline, fut)
    }

    #[inline]
    fn delay_local_at<F>(deadline: Self::Instant, fut: F) -> Self::LocalDelay<F>
    where
        F: Future,
    {
        R::delay_local_at(deadline, fut)
    }

    #[inline]
    fn timeout<F>(duration: core::time::Duration, future: F) -> Self::Timeout<F>
    where
        F: Future + Send,
    {
        R::timeout(duration, future)
    }

    #[inline]
    fn timeout_at<F>(deadline: Self::Instant, future: F) -> Self::Timeout<F>
    where
        F: Future + Send,
    {
        R::timeout_at(deadline, future)
    }

    #[inline]
    fn timeout_local<F>(duration: core::time::Duration, future: F) -> Self::LocalTimeout<F>
    where
        F: Future,
    {
        R::timeout_local(duration, future)
    }

    #[inline]
    fn timeout_local_at<F>(deadline: Self::Instant, future: F) -> Self::LocalTimeout<F>
    where
        F: Future,
    {
        R::timeout_local_at(deadline, future)
    }
}

/// A spawner wrapper that automatically instruments spawned futures with the current tracing span.
///
/// When [`spawn`](serf::agnostic::AsyncSpawner::spawn) is called, the current
/// [`tracing::Span`] is captured and applied to the given future using `.instrument()`,
/// ensuring that all logs and events inside the task are associated with the correct context.
///
/// This is particularly useful for maintaining trace continuity across asynchronous boundaries.
#[derive(Clone, Copy)]
pub struct InstrumentedSpawner<S: serf::agnostic::AsyncSpawner>(PhantomData<S>);

impl<S: serf::agnostic::AsyncSpawner> serf::agnostic::AsyncSpawner for InstrumentedSpawner<S> {
    type JoinHandle<R>
        = <S as serf::agnostic::AsyncSpawner>::JoinHandle<R>
    where
        R: Send + 'static;

    #[inline]
    fn spawn<F>(future: F) -> Self::JoinHandle<F::Output>
    where
        F::Output: Send + 'static,
        F: Future + Send + 'static,
    {
        S::spawn(future.instrument(Span::current()))
    }
}

impl<S: serf::agnostic::AsyncSpawner> Yielder for InstrumentedSpawner<S> {
    #[inline]
    fn yield_now() -> impl Future<Output = ()> + Send {
        S::yield_now()
    }

    #[inline]
    fn yield_now_local() -> impl Future<Output = ()> {
        S::yield_now_local()
    }
}

/// A local spawner wrapper that instruments `!Send` tasks with the current tracing span.
///
/// Similar to [`InstrumentedSpawner`], but for futures that are not `Send` and must be spawned
/// on the same thread. The current [`tracing::Span`] is captured and attached to the future,
/// preserving context even in `!Send` task boundaries.
#[derive(Clone, Copy)]
pub struct InstrumentedLocalSpawner<S: serf::agnostic::AsyncLocalSpawner>(PhantomData<S>);

impl<S: serf::agnostic::AsyncLocalSpawner> serf::agnostic::AsyncLocalSpawner
    for InstrumentedLocalSpawner<S>
{
    type JoinHandle<R>
        = <S as serf::agnostic::AsyncLocalSpawner>::JoinHandle<R>
    where
        R: 'static;

    #[inline]
    fn spawn_local<F>(future: F) -> Self::JoinHandle<F::Output>
    where
        F::Output: 'static,
        F: Future + 'static,
    {
        S::spawn_local(future.instrument(Span::current()))
    }
}

impl<S: serf::agnostic::AsyncLocalSpawner> Yielder for InstrumentedLocalSpawner<S> {
    #[inline]
    fn yield_now() -> impl Future<Output = ()> + Send {
        S::yield_now()
    }

    #[inline]
    fn yield_now_local() -> impl Future<Output = ()> {
        S::yield_now_local()
    }
}

/// A blocking spawner wrapper that propagates the current tracing span into blocking tasks.
///
/// When spawning a blocking function, the current [`tracing::Span`] is captured and re-entered
/// when the function executes. This ensures that logs and metrics emitted inside the blocking
/// context are correctly associated with the originating trace.
///
/// Note: Since blocking tasks don't return futures, instrumentation is done via span entering
/// rather than `.instrument()`.
#[derive(Clone, Copy)]
pub struct InstrumentedBlockingSpawner<S: serf::agnostic::AsyncBlockingSpawner>(PhantomData<S>);

impl<S: serf::agnostic::AsyncBlockingSpawner> serf::agnostic::AsyncBlockingSpawner
    for InstrumentedBlockingSpawner<S>
{
    type JoinHandle<R>
        = <S as serf::agnostic::AsyncBlockingSpawner>::JoinHandle<R>
    where
        R: Send + 'static;

    #[inline]
    fn spawn_blocking<F, R>(f: F) -> Self::JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let span = Span::current();
        let instrumented_fn = move || {
            let _guard = span.enter();
            f()
        };
        S::spawn_blocking(instrumented_fn)
    }
}

impl<S: serf::agnostic::AsyncBlockingSpawner> Yielder for InstrumentedBlockingSpawner<S> {
    #[inline]
    fn yield_now() -> impl Future<Output = ()> + Send {
        S::yield_now()
    }

    #[inline]
    fn yield_now_local() -> impl Future<Output = ()> {
        S::yield_now_local()
    }
}

/// A delayed spawner wrapper that instruments futures spawned after a duration or at a specific time.
///
/// Tasks spawned via [`spawn_after`](serf::agnostic::AsyncAfterSpawner::spawn_after)
/// or [`spawn_after_at`](serf::agnostic::AsyncAfterSpawner::spawn_at) are automatically
/// instrumented with the current [`tracing::Span`], preserving context even across delayed execution.
///
/// This ensures that timed or deferred tasks remain part of the original tracing flow.
#[derive(Clone, Copy)]
pub struct InstrumentedAfterSpawner<S: serf::agnostic::AsyncAfterSpawner>(PhantomData<S>);

impl<S: serf::agnostic::AsyncAfterSpawner> serf::agnostic::AsyncAfterSpawner
    for InstrumentedAfterSpawner<S>
{
    type Instant = <S as serf::agnostic::AsyncAfterSpawner>::Instant;

    type JoinHandle<F>
        = <S as serf::agnostic::AsyncAfterSpawner>::JoinHandle<F>
    where
        F: Send + 'static;

    #[inline]
    fn spawn_after<F>(duration: std::time::Duration, future: F) -> Self::JoinHandle<F::Output>
    where
        F::Output: Send + 'static,
        F: Future + Send + 'static,
    {
        S::spawn_after(duration, future.instrument(Span::current()))
    }

    #[inline]
    fn spawn_after_at<F>(instant: Self::Instant, future: F) -> Self::JoinHandle<F::Output>
    where
        F::Output: Send + 'static,
        F: Future + Send + 'static,
    {
        S::spawn_after_at(instant, future.instrument(Span::current()))
    }
}
