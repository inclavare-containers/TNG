use std::future::Future;
use std::time::Duration;

async fn sleep(duration: Duration) {
    #[cfg(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))]
    {
        tokio_with_wasm::time::sleep(duration).await;
    }
    #[cfg(not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    )))]
    {
        tokio::time::sleep(duration).await;
    }
}

/// Simple exponential-backoff retry policy.
pub(crate) struct RetryPolicy {
    initial_delay: Duration,
    max_delay: Duration,
    max_retries: usize,
}

impl RetryPolicy {
    pub fn exponential(initial_delay: Duration) -> Self {
        Self {
            initial_delay,
            max_delay: Duration::from_secs(60),
            max_retries: 3,
        }
    }

    pub fn with_max_delay(mut self, max_delay: Duration) -> Self {
        self.max_delay = max_delay;
        self
    }

    pub fn with_max_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Retry an async closure with exponential backoff.
    pub async fn retry<F, Fut, T, E>(&self, mut task: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let mut delay = self.initial_delay;
        for attempt in 0..=self.max_retries {
            match task().await {
                Ok(val) => return Ok(val),
                Err(err) if attempt == self.max_retries => return Err(err),
                Err(_) => {
                    sleep(delay).await;
                    delay = (delay * 2).min(self.max_delay);
                }
            }
        }
        unreachable!()
    }
}
