//! Quiesce-then-cancel coordination for `tng exec` teardown.
//!
//! When the wrapped child process exits, its app sockets are gone: any bytes
//! the app already wrote but TNG has not yet forwarded (kernel recv queues of
//! the app-facing sockets, the forward's `CopyBuffer`, unflushed rustls
//! records) would be discarded the moment the runtime hard-cancels every
//! supervised task. `DrainRegistry` lets the exec path first ask all
//! in-flight forwards to drain (`begin_graceful_close`), wait for them to
//! finish within a bounded window, and only then fire the hard cancel.
//!
//! The closing token is deliberately a distinct signal from the shutdown
//! guard's cancel: a forward that observes closing keeps draining the
//! app-facing direction to EOF (see `forward.rs`'s closing rules), while the
//! hard cancel drops everything immediately as before.

use std::sync::{Arc, OnceLock};

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use web_time_compat::{Instant, InstantExt};

/// Shared by the runtime, every per-connection forward, and the exec teardown
/// path. All clones of the owning `Arc` coordinate on the same registry.
#[derive(Debug)]
pub struct DrainRegistry {
    closing: CancellationToken,
    /// Number of forwards currently in flight; the watch channel doubles as
    /// the counter and the idle signal (`send_modify` serializes updates, so
    /// concurrent register/drop pairs cannot lose counts or wakeups).
    inflight: watch::Sender<usize>,
    /// When the closing signal fired, so per-forward completion logs can
    /// report the drain duration rather than the forward's whole lifetime.
    closed_at: OnceLock<Instant>,
}

impl DrainRegistry {
    pub fn new() -> Self {
        let (inflight, _) = watch::channel(0);
        Self {
            closing: CancellationToken::new(),
            inflight,
            closed_at: OnceLock::new(),
        }
    }

    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Ask all in-flight (and any future) forwards to drain and finish.
    /// Idempotent.
    pub fn begin_graceful_close(&self) {
        self.closed_at.get_or_init(Instant::get);
        self.closing.cancel();
    }

    /// The closing signal a forward should poll while copying.
    pub fn closing(&self) -> &CancellationToken {
        &self.closing
    }

    /// Instant the closing signal first fired, if it has.
    pub fn closed_at(&self) -> Option<Instant> {
        self.closed_at.get().copied()
    }

    /// Forwards in flight right now (registered but not yet finished).
    pub fn inflight(&self) -> usize {
        *self.inflight.borrow()
    }

    /// Record one in-flight forward. The returned guard decrements on drop,
    /// including when the forward's future is dropped mid-flight (the hard
    /// cancel path), so the count cannot leak across teardown.
    pub fn register(&self) -> DrainGuard<'_> {
        self.inflight.send_modify(|n| *n += 1);
        DrainGuard { registry: self }
    }

    /// Resolve once no forward is in flight. `wait_for` checks the current
    /// value first, so an idle registry (the common exec case: the app
    /// finished all its transfers before exiting) resolves without parking.
    pub async fn wait_idle(&self) {
        let mut inflight = self.inflight.subscribe();
        // The sender outlives this borrow (`&self`), so the channel can only
        // close while we wait if the whole registry is being dropped; a
        // dropped registry means nobody can hold forwards either.
        let _ = inflight.wait_for(|n| *n == 0).await;
    }
}

impl Default for DrainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII in-flight registration; see [`DrainRegistry::register`].
pub struct DrainGuard<'a> {
    registry: &'a DrainRegistry,
}

impl Drop for DrainGuard<'_> {
    fn drop(&mut self) {
        self.registry
            .inflight
            .send_modify(|n| *n = n.saturating_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn wait_idle_is_immediate_when_empty() {
        let registry = DrainRegistry::new();
        // The exec common case: no in-flight forward must park the waiter.
        tokio::time::timeout(Duration::from_millis(100), registry.wait_idle())
            .await
            .expect("idle registry must report drained immediately");
    }

    #[tokio::test]
    async fn guard_tracks_inflight_count() {
        let registry = DrainRegistry::new();
        assert_eq!(registry.inflight(), 0);
        let first = registry.register();
        assert_eq!(registry.inflight(), 1);
        let second = registry.register();
        assert_eq!(registry.inflight(), 2);
        drop(first);
        assert_eq!(registry.inflight(), 1);
        // Still not idle: wait must park rather than resolve early.
        tokio::time::timeout(Duration::from_millis(50), registry.wait_idle())
            .await
            .expect_err("registry with one in-flight forward is not idle");
        drop(second);
        assert_eq!(registry.inflight(), 0);
        tokio::time::timeout(Duration::from_millis(100), registry.wait_idle())
            .await
            .expect("last guard drop must wake wait_idle");
    }

    #[tokio::test]
    async fn guard_decrements_when_forward_future_dropped() {
        // The hard-cancel analogue: dropping the forward's future runs the
        // guard's Drop, so the registry never sticks at a nonzero count.
        let registry = DrainRegistry::new();
        {
            let _guard = registry.register();
            assert_eq!(registry.inflight(), 1);
        }
        assert_eq!(registry.inflight(), 0);
    }

    #[tokio::test]
    async fn begin_graceful_close_fires_closing_once() {
        let registry = DrainRegistry::new();
        assert!(!registry.closing().is_cancelled());
        assert!(registry.closed_at().is_none());
        registry.begin_graceful_close();
        assert!(registry.closing().is_cancelled());
        assert!(registry.closed_at().is_some());
        // Idempotent.
        registry.begin_graceful_close();
        assert!(registry.closing().is_cancelled());
        tokio::time::timeout(Duration::from_millis(100), registry.closing().cancelled())
            .await
            .expect("cancelled() resolves after begin_graceful_close");
    }
}
