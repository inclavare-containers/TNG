use anyhow::{anyhow, Context, Result};
use futures::FutureExt as _;
use std::cmp::{Ord, Ordering, PartialOrd};
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::select;

#[cfg(unix)]
use tokio::task::JoinHandle;
#[cfg(wasm)]
use tokio_with_wasm::alias::task::JoinHandle;

#[cfg(unix)]
use tokio::time as tokio_time;
#[cfg(wasm)]
use tokio_with_wasm::alias::time as tokio_time;

#[cfg(unix)]
use std::time::SystemTime;
#[cfg(wasm)]
use web_time::SystemTime;

use crate::tunnel::utils::runtime::{
    future::TokioRuntimeSupportedFuture, supervised_task::SupervisedTaskResult, TokioRuntime,
};

/// Represents an optional expiration time.
/// - `NoExpire`: Never expires (treated as infinite future).
/// - `ExpireAt(time)`: Expires at a specific system time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expire {
    NoExpire,
    ExpireAt(SystemTime),
}

impl PartialOrd for Expire {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Expire {
    /// Compare two `Expire` values:
    /// - `NoExpire` is considered greater than any `ExpireAt` (i.e., it expires later).
    /// - Two `ExpireAt` times are compared using `SystemTime`.
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Expire::NoExpire, Expire::NoExpire) => Ordering::Equal,
            (Expire::NoExpire, Expire::ExpireAt(_)) => Ordering::Greater, // Never expire > finite time
            (Expire::ExpireAt(_), Expire::NoExpire) => Ordering::Less, // Finite time < never expire
            (Expire::ExpireAt(a), Expire::ExpireAt(b)) => a.cmp(b),    // Compare actual timestamps
        }
    }
}

impl Expire {
    pub fn from_timestamp(timestamp_seconds: u64) -> Result<Self> {
        let input_system_time = SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(timestamp_seconds))
            .with_context(|| {
                format!(
                    "the timestamp is too far in the future to be represented: {timestamp_seconds}"
                )
            })?;

        // Sanity check
        let now = SystemTime::now();
        let _duration = input_system_time.duration_since(now).with_context(|| {
            format!("the timestamp is earlier than current time: {input_system_time:?} < {now:?}")
        })?;

        Ok(Expire::ExpireAt(input_system_time))
    }
}

type MaybeCachedUpdateFunc<T, E> = Arc<
    dyn Fn() -> Pin<Box<dyn TokioRuntimeSupportedFuture<Result<(T, Expire), E>>>>
        + Send
        + Sync
        + 'static,
>;

pub enum MaybeCached<
    T: std::marker::Send + std::marker::Sync + 'static,
    E: Into<anyhow::Error> + std::marker::Send + std::marker::Sync + 'static,
> {
    UpdatePeriodically {
        #[allow(unused)]
        interval: u64,
        latest: (
            tokio::sync::watch::Sender<Arc<T>>,
            tokio::sync::watch::Receiver<Arc<T>>,
        ),
        #[allow(unused)]
        refresh_task: RefreshTask,
        #[allow(unused)]
        invalidator_tx: tokio::sync::watch::Sender<()>,
        #[allow(unused)]
        f: MaybeCachedUpdateFunc<T, E>,
    },
    NoCache {
        f: MaybeCachedUpdateFunc<T, E>,
    },
}

impl<
        T: std::marker::Send + std::marker::Sync + 'static,
        E: Into<anyhow::Error> + std::marker::Send + std::marker::Sync + 'static,
    > MaybeCached<T, E>
{
    pub async fn new<F>(
        runtime: TokioRuntime,
        refresh_strategy: RefreshStrategy,
        f: F,
    ) -> Result<Self, E>
    where
        F: Fn() -> Pin<Box<dyn TokioRuntimeSupportedFuture<Result<(T, Expire), E>>>>
            + Send
            + Sync
            + 'static,
    {
        match refresh_strategy {
            RefreshStrategy::Periodically { interval } => {
                // Fetch the value first time
                let (init_value, init_expire) = f().await?;

                let latest = tokio::sync::watch::channel(Arc::new(init_value));

                let (invalidator_tx, mut invalidator_rx) = tokio::sync::watch::channel(());

                let f = Arc::new(f);
                let refresh_task = {
                    let f = f.clone();
                    let latest = latest.clone();

                    let join_handle = runtime.spawn_supervised_task_current_span(async move {
                        let mut expire = init_expire;

                        loop {
                            // Update certs in loop
                            let fut = async {
                                let expire_fut = match expire {
                                    Expire::NoExpire => {
                                        let fut = futures::future::pending();
                                        #[cfg(unix)]
                                        let fut = fut.boxed();
                                        #[cfg(wasm)]
                                        let fut = fut.boxed_local();

                                        fut
                                    }
                                    Expire::ExpireAt(expire_time) => {
                                        let now = SystemTime::now();
                                        let duration =
                                            expire_time.duration_since(now).unwrap_or_default();

                                        let fut = tokio_time::sleep(duration);
                                        #[cfg(unix)]
                                        let fut = fut.boxed();
                                        #[cfg(wasm)]
                                        let fut = fut.boxed_local();

                                        fut
                                    }
                                };

                                let periodically_fut =
                                    tokio_time::sleep(Duration::from_secs(interval));

                                select! {
                                    () = expire_fut => {
                                        expire = Expire::NoExpire;
                                    }
                                    Ok(()) = invalidator_rx.changed() => { // Only error when sender is dropped
                                        let _ = invalidator_rx.borrow_and_update(); // consume the change
                                    }
                                    () = periodically_fut=> { /* nothing */ }
                                }

                                let (new_value, new_expire) = f().await.map_err(|e| e.into())?;

                                expire = new_expire;

                                latest.0.send(Arc::new(new_value)).map_err(|e| {
                                    anyhow!("Failed to set the latest cached value: {e}")
                                })
                            };

                            if let Err(e) = fut.await {
                                tracing::error!(error=?e,"Failed to update the cached value");
                            }
                        }
                    });
                    RefreshTask { join_handle }
                };

                Ok(MaybeCached::UpdatePeriodically {
                    interval,
                    latest,
                    refresh_task,
                    invalidator_tx,
                    f,
                })
            }
            RefreshStrategy::Always => Ok(MaybeCached::NoCache { f: Arc::new(f) }),
        }
    }

    pub async fn get_latest(&self) -> Result<Arc<T>, E> {
        match self {
            MaybeCached::UpdatePeriodically { latest, .. } => Ok(latest.1.borrow().clone()),
            MaybeCached::NoCache { f } => Ok(Arc::new(f().await?.0)),
        }
    }

    pub fn invalidate(&self) {
        match self {
            MaybeCached::UpdatePeriodically { invalidator_tx, .. } => {
                let _ = invalidator_tx.send(()); // Ignore the error
            }
            MaybeCached::NoCache { .. } => {}
        }
    }
}

#[derive(Debug)]
pub enum RefreshStrategy {
    Periodically { interval: u64 },
    Always,
}

#[derive(Debug)]
pub struct RefreshTask {
    join_handle: JoinHandle<SupervisedTaskResult<()>>,
}

impl RefreshTask {
    #[allow(unused)]
    pub fn is_finished(&self) -> bool {
        self.join_handle.is_finished()
    }
}

impl Drop for RefreshTask {
    fn drop(&mut self) {
        // terminate the task when dropped
        self.join_handle.abort();
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::tests::run_test_with_tokio_runtime;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_expire_min_max() {
        let now = SystemTime::now();
        let past = now - Duration::from_secs(3600);
        let future = now + Duration::from_secs(3600);

        let expired = Expire::ExpireAt(past); // Already expired
        let valid = Expire::ExpireAt(future); // Expires in the future
        let no_expire = Expire::NoExpire; // Never expires

        // min returns the earlier expiration (sooner to expire)
        assert_eq!(std::cmp::min(expired, valid), expired);
        assert_eq!(std::cmp::min(valid, no_expire), valid);
        assert_eq!(std::cmp::min(expired, no_expire), expired);

        // max returns the later expiration (longer to live)
        assert_eq!(std::cmp::max(expired, valid), valid);
        assert_eq!(std::cmp::max(valid, no_expire), no_expire);
        assert_eq!(std::cmp::max(expired, no_expire), no_expire);
    }

    #[test]
    fn test_expire_from_timestamp_valid_future() {
        // Create a future timestamp (current time + 100 seconds)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let future_timestamp = now + 100;

        // Should successfully create Expire::ExpireAt instance
        let result = Expire::from_timestamp(future_timestamp);
        assert!(result.is_ok());

        match result.unwrap() {
            Expire::ExpireAt(_) => {} // Success
            Expire::NoExpire => panic!("Expected ExpireAt, got NoExpire"),
        }
    }

    #[test]
    fn test_expire_from_timestamp_current_time() {
        // Use current timestamp
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Should fail because timestamp is not later than current time
        let result = Expire::from_timestamp(current_timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn test_expire_from_timestamp_past_time() {
        // Create a past timestamp (current time - 100 seconds)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let past_timestamp = now - 100;

        // Should fail because timestamp is earlier than current time
        let result = Expire::from_timestamp(past_timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn test_expire_from_timestamp_far_future() {
        // Create a very far future timestamp
        let far_future_timestamp = u64::MAX - 1000;

        // Should fail because timestamp is too far to be represented
        let result = Expire::from_timestamp(far_future_timestamp);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_maybe_cached_always_strategy() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Test Always strategy where function is called every time
            let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            let call_count_clone = call_count.clone();

            let maybe_cached: MaybeCached<String, anyhow::Error> =
                MaybeCached::new(runtime, RefreshStrategy::Always, move || {
                    let call_count_clone = call_count_clone.clone();
                    Box::pin(async move {
                        let count =
                            call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        Ok((format!("value{count}"), Expire::NoExpire))
                    })
                })
                .await
                .expect("Failed to create MaybeCached");

            // Each call should return a new value
            let value1 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value1");
            assert_eq!(*value1, "value1");

            let value2 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value2");
            assert_eq!(*value2, "value2");

            let value3 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value3");
            assert_eq!(*value3, "value3");

            // Verify the function was called 3 times
            assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 3);

            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_maybe_cached_periodically_no_expire() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Test Periodically strategy with NoExpire
            let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            let call_count_clone = call_count.clone();

            let maybe_cached: MaybeCached<String, anyhow::Error> = MaybeCached::new(
                runtime,
                RefreshStrategy::Periodically { interval: 1 }, // 1 second interval
                move || {
                    let call_count_clone = call_count_clone.clone();
                    Box::pin(async move {
                        let count =
                            call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        Ok((format!("value{count}"), Expire::NoExpire))
                    })
                },
            )
            .await
            .expect("Failed to create MaybeCached");

            // First call should return initial value
            let value1 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value1");
            assert_eq!(*value1, "value1");

            // Even after a short delay, should still return same value (not expired)
            tokio_time::sleep(tokio_time::Duration::from_millis(100)).await;
            let value2 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value2");
            assert_eq!(*value2, "value1"); // Still the same

            // Verify the function was called only once (initial call)
            assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);

            // Wait for the refresh period
            tokio_time::sleep(tokio_time::Duration::from_millis(1500)).await;
            // Verify the function was called twice (initial call and refresh)
            assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 2);
            let value3 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value3");
            assert_eq!(*value3, "value2"); // Still the same
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_maybe_cached_periodically_with_short_expire() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Test Periodically strategy with ExpireAt
            let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            let call_count_clone = call_count.clone();

            let maybe_cached: MaybeCached<String, anyhow::Error> = MaybeCached::new(
                runtime,
                RefreshStrategy::Periodically { interval: 3600 }, // Long interval, rely on expire instead
                move || {
                    let call_count_clone = call_count_clone.clone();
                    Box::pin(async move {
                        let count =
                            call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        // Expire after 100ms
                        let expire_at = SystemTime::now() + tokio_time::Duration::from_millis(1000);
                        Ok((format!("value{count}"), Expire::ExpireAt(expire_at)))
                    })
                },
            )
            .await
            .expect("Failed to create MaybeCached");

            // First call should return initial value
            let value1 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value1");
            assert_eq!(*value1, "value1");

            // Wait for expiration
            tokio_time::sleep(tokio_time::Duration::from_millis(500)).await;

            // Should still return inital value because refresh happens in background and is not finished
            let value2 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value2");
            assert_eq!(*value2, "value1");

            // Give some time for background refresh to happen
            tokio_time::sleep(tokio_time::Duration::from_millis(1000)).await;

            // Now should get updated value
            let value3 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value3");
            assert_eq!(*value3, "value2");

            // Verify the function was called twice
            assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 2);
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_maybe_cached_periodically_with_long_expire() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            // Test Periodically strategy with ExpireAt
            let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            let call_count_clone = call_count.clone();

            let maybe_cached: MaybeCached<String, anyhow::Error> = MaybeCached::new(
                runtime,
                RefreshStrategy::Periodically { interval: 1 }, // Short interval
                move || {
                    let call_count_clone = call_count_clone.clone();
                    Box::pin(async move {
                        let count =
                            call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        // Expire after 100ms
                        let expire_at = SystemTime::now() + tokio_time::Duration::from_secs(1000); // Long expire time, rely on refresh interval instead.
                        Ok((format!("value{count}"), Expire::ExpireAt(expire_at)))
                    })
                },
            )
            .await
            .expect("Failed to create MaybeCached");

            // First call should return initial value
            let value1 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value1");
            assert_eq!(*value1, "value1");

            // Wait for refresh interval
            tokio_time::sleep(tokio_time::Duration::from_millis(500)).await;

            // Should still return inital value because refresh happens in background and is not finished
            let value2 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value2");
            assert_eq!(*value2, "value1");
            assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);

            // Give some time for background refresh to happen
            tokio_time::sleep(tokio_time::Duration::from_millis(1000)).await;

            // Now should get updated value
            let value3 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value3");
            assert_eq!(*value3, "value2");

            // Verify the function was called twice
            assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 2);

            // Give some time for background refresh to happen
            tokio_time::sleep(tokio_time::Duration::from_millis(1000)).await;
            let value4 = maybe_cached
                .get_latest()
                .await
                .expect("Failed to get value4");
            assert_eq!(*value4, "value3");
            // Verify the function was called three times
            assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 3);
            Ok(())
        })
        .await
    }
}
