//! Per-phase latency histograms for the ohttp tunnel.
//!
//! The keep-alive ohttp path shows ~6ms of unexplained per-request wait at
//! c=128 that static analysis cannot attribute. These histograms time every
//! "wait" segment of one request on each side (ingress: client handler
//! stages, outer POST; egress: metadata read, HPKE open, backend send/reply,
//! response seal) so the residual can be pinned to a segment. Snapshots are
//! served from the status tree at `.../ohttp/latency` on both sides.
//!
//! Recording is a compile-time build choice behind the `latency-timing`
//! feature. With the feature enabled, a segment start reads the clock and a
//! recorded sample costs a handful of relaxed atomic increments, and the
//! status tree grows the latency nodes. With the feature disabled (the
//! default), `Timer` and `Histogram` are zero-sized stubs whose methods
//! compile away: every record call site stays live in both shapes while
//! costing nothing in a default build, and no latency node is registered.

use futures::Stream;

/// The real recorder: a lock-free histogram with relaxed-atomic updates and
/// quantiles computed at snapshot time.
#[cfg(feature = "latency-timing")]
mod recorder {
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use web_time_compat::{Instant, InstantExt};

    /// Linear buckets of 1us each cover `0..1024` us; after that each octave
    /// doubles the width and is split into 16 sub-buckets. `OCTAVES` octaves
    /// from 2^10 us reach 2^24 us (~16.7s); larger samples clamp into the last
    /// bucket, so a percentile never over-reports the tail beyond that point.
    pub(super) const LINEAR_BUCKETS: usize = 1024;
    const OCTAVES: usize = 14;
    const SUB_BUCKETS_PER_OCTAVE: usize = 16;
    pub(super) const HIST_BUCKETS: usize = LINEAR_BUCKETS + OCTAVES * SUB_BUCKETS_PER_OCTAVE;
    pub(super) const MAX_BUCKETS_US: u64 = (1 << 24) - 1;

    pub(super) fn bucket_of(us: u64) -> usize {
        if us < LINEAR_BUCKETS as u64 {
            return us as usize;
        }
        let us = us.min(MAX_BUCKETS_US);
        let lg = 63 - us.leading_zeros(); // floor(log2(us)), in 10..=23
        let octave = (lg - 10) as usize;
        let sub = ((us >> (lg - 4)) - 16) as usize;
        LINEAR_BUCKETS + octave * SUB_BUCKETS_PER_OCTAVE + sub
    }

    pub(super) fn bucket_width_us(index: usize) -> u64 {
        if index < LINEAR_BUCKETS {
            1
        } else {
            let octave = (index - LINEAR_BUCKETS) / SUB_BUCKETS_PER_OCTAVE;
            1u64 << (octave + 6)
        }
    }

    pub(super) fn bucket_lower_us(index: usize) -> u64 {
        if index < LINEAR_BUCKETS {
            index as u64
        } else {
            let rel = index - LINEAR_BUCKETS;
            let octave = rel / SUB_BUCKETS_PER_OCTAVE;
            let sub = rel % SUB_BUCKETS_PER_OCTAVE;
            (16 + sub as u64) << (octave + 6)
        }
    }

    /// One phase's histogram: exact count/sum/max plus a log-linear bucket
    /// layout from which mean, p50 and p99 are read. Percentiles are
    /// bucket-midpoint approximations; mean and max are exact.
    #[derive(Clone)]
    pub(crate) struct Histogram {
        inner: Arc<HistogramInner>,
    }

    struct HistogramInner {
        buckets: Box<[AtomicU32; HIST_BUCKETS]>,
        count: AtomicU64,
        sum_us: AtomicU64,
        max_us: AtomicU64,
    }

    impl Histogram {
        pub(super) fn new() -> Self {
            Self {
                inner: Arc::new(HistogramInner {
                    buckets: Box::new([const { AtomicU32::new(0) }; HIST_BUCKETS]),
                    count: AtomicU64::new(0),
                    sum_us: AtomicU64::new(0),
                    max_us: AtomicU64::new(0),
                }),
            }
        }

        /// A sample from a build without the `latency-timing` feature arrives
        /// as `None` and records nothing, so call sites need no cfg branches.
        pub(crate) fn record(&self, elapsed: Option<Duration>) {
            let Some(elapsed) = elapsed else { return };
            let us = elapsed.as_micros().min(u64::MAX as u128) as u64;
            self.inner.count.fetch_add(1, Ordering::Relaxed);
            self.inner.sum_us.fetch_add(us, Ordering::Relaxed);
            self.inner.buckets[bucket_of(us)].fetch_add(1, Ordering::Relaxed);
            self.inner.max_us.fetch_max(us, Ordering::Relaxed);
        }

        /// Value at the `num/den` quantile, as the midpoint of the bucket the
        /// rank falls into. Reads buckets as they are, mid-update: a snapshot
        /// may be marginally inconsistent, which is fine for a diagnostic.
        fn percentile_us(&self, num: u64, den: u64) -> u64 {
            let count = self.inner.count.load(Ordering::Relaxed);
            if count == 0 {
                return 0;
            }
            let rank = count.saturating_mul(num).div_ceil(den);
            let rank = rank.max(1);
            let mut seen = 0u64;
            for (index, bucket) in self.inner.buckets.iter().enumerate() {
                seen += bucket.load(Ordering::Relaxed) as u64;
                if seen >= rank {
                    return bucket_lower_us(index) + bucket_width_us(index) / 2;
                }
            }
            // Unreachable unless bucket counts wrapped; report the covered max.
            bucket_lower_us(HIST_BUCKETS - 1) + bucket_width_us(HIST_BUCKETS - 1)
        }

        pub(crate) fn snapshot(&self) -> serde_json::Value {
            let count = self.inner.count.load(Ordering::Relaxed);
            if count == 0 {
                return serde_json::json!({
                    "count": 0,
                    "mean_us": null,
                    "p50_us": null,
                    "p99_us": null,
                    "max_us": null,
                });
            }
            let sum = self.inner.sum_us.load(Ordering::Relaxed);
            let mean = (sum as f64 / count as f64 * 100.0).round() / 100.0;
            serde_json::json!({
                "count": count,
                "mean_us": mean,
                "p50_us": self.percentile_us(1, 2),
                "p99_us": self.percentile_us(99, 100),
                "max_us": self.inner.max_us.load(Ordering::Relaxed),
            })
        }
    }

    /// Lifecycle counters for backend preconnects, served at
    /// `.../ohttp/preconnect`. The latency histograms alone cannot separate the
    /// outcomes of a pre-dial on a saturated runtime: a `backend_redial` wait is
    /// the same whether the preconnect was declined at the peek, started but not
    /// yet finished at reap time, or never started. Each event is one relaxed
    /// atomic increment: zero allocation, safe from any path.
    ///
    /// The accounting identity is
    /// `started = reaped + abandoned + at most one still pending`: a dial that is
    /// started always ends up reaped by its request's `forward_request` or torn
    /// down by the guard of the request that started it.
    #[derive(Default)]
    pub(crate) struct PreconnectCounters {
        started: AtomicU64,
        declined_warm: AtomicU64,
        reaped: AtomicU64,
        abandoned: AtomicU64,
    }

    #[allow(dead_code)] // recorded once the backend pre-dial path is built
    impl PreconnectCounters {
        /// A preconnect was declined because the backend slot peek found a
        /// pooled connection present or a concurrent forward holding the slot.
        pub(crate) fn record_declined_warm(&self) {
            self.declined_warm.fetch_add(1, Ordering::Relaxed);
        }

        /// A preconnect dial task was spawned.
        pub(crate) fn record_started(&self) {
            self.started.fetch_add(1, Ordering::Relaxed);
        }

        /// The cold path of `forward_request` took the pending dial from the
        /// slot (whatever verdict the dial later produced).
        pub(crate) fn record_reaped(&self) {
            self.reaped.fetch_add(1, Ordering::Relaxed);
        }

        /// A dial nobody reaped was taken from the slot by the teardown guard
        /// of the request that started it.
        pub(crate) fn record_abandoned(&self) {
            self.abandoned.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl PreconnectCounters {
        pub(crate) fn snapshot(&self) -> serde_json::Value {
            serde_json::json!({
                "preconnect_started": self.started.load(Ordering::Relaxed),
                "preconnect_declined_warm": self.declined_warm.load(Ordering::Relaxed),
                "preconnect_reaped": self.reaped.load(Ordering::Relaxed),
                "preconnect_abandoned": self.abandoned.load(Ordering::Relaxed),
            })
        }
    }

    /// A segment start point. Reads the clock on construction; `elapsed`
    /// hands the sample to [`Histogram::record`].
    pub(crate) struct Timer(Instant);

    impl Timer {
        pub(crate) fn start() -> Self {
            Self(Instant::get())
        }

        /// Elapsed since `start`.
        pub(crate) fn elapsed(&self) -> Option<Duration> {
            Some(self.0.elapsed())
        }
    }
}

/// The stub recorder: same shape, nothing measured. `Timer::elapsed` always
/// hands `None` to `record`, which is an empty inlined function, so a
/// segment costs no clock read and no atomic in a default build.
#[cfg(not(feature = "latency-timing"))]
mod recorder {
    use std::time::Duration;

    pub(crate) struct Timer;

    impl Timer {
        #[inline(always)]
        pub(crate) fn start() -> Self {
            Timer
        }

        #[inline(always)]
        pub(crate) fn elapsed(&self) -> Option<Duration> {
            None
        }
    }

    #[derive(Clone)]
    pub(crate) struct Histogram;

    impl Histogram {
        #[inline(always)]
        pub(super) fn new() -> Self {
            Histogram
        }

        #[inline(always)]
        pub(crate) fn record(&self, _elapsed: Option<Duration>) {}
    }

    #[derive(Default)]
    pub(crate) struct PreconnectCounters {
        // Not a unit struct: every shape's call sites build these with
        // `::default()`, and the unit form would trip clippy's
        // default_constructed_unit_structs on the disabled build only.
        _unmeasured: std::marker::PhantomData<u64>,
    }

    #[allow(dead_code)] // recorded once the backend pre-dial path is built
    impl PreconnectCounters {
        #[inline(always)]
        pub(crate) fn record_declined_warm(&self) {}

        #[inline(always)]
        pub(crate) fn record_started(&self) {}

        #[inline(always)]
        pub(crate) fn record_reaped(&self) {}

        #[inline(always)]
        pub(crate) fn record_abandoned(&self) {}
    }
}

pub(crate) use recorder::{Histogram, PreconnectCounters, Timer};

macro_rules! define_latency {
    ($name:ident { $($field:ident),* $(,)? }) => {
        pub(crate) struct $name {
            $( pub(crate) $field: Histogram, )*
        }

        impl $name {
            pub(crate) fn new() -> Self {
                Self { $( $field: Histogram::new(), )* }
            }

            // The status nodes that serve this are only built with the
            // feature; without it there is nothing to snapshot.
            #[cfg(feature = "latency-timing")]
            pub(crate) fn snapshot(&self) -> serde_json::Value {
                let mut phases = serde_json::Map::new();
                $(
                    phases.insert(stringify!($field).to_string(), self.$field.snapshot());
                )*
                serde_json::json!({
                    "unit": "microseconds",
                    "cumulative_since_process_start": true,
                    "phases": phases,
                })
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

define_latency!(IngressLatency {
    // service_fn entry -> inner response handed back to hyper (covers the
    // rest of the phases below).
    handler_total,
    // Handler entry -> OHttpClient resolved (path rewrite + cache lookup).
    route_lookup,
    // Key-config store wait (MaybeCached::get_latest).
    keyconfig_wait,
    // bhttp encoder + HPKE encapsulator + request body stream construction.
    seal_setup,
    // Outer POST dispatch -> outer response headers received.
    outer_post_wait,
    // Sealed request body stream built -> first poll by the HTTP client.
    req_body_first_poll,
    // ... -> first sealed data frame (the metadata frame is skipped).
    req_body_first_chunk,
    // ... -> sealed request body fully pumped out.
    req_body_pumped,
    // Outer response byte stream built -> first poll.
    resp_stream_first_poll,
    // ... -> all outer response bytes arrived.
    resp_stream_pumped,
    // Decapsulate + bhttp decode of the inner response entry -> done.
    inner_resp_decode,
    // Response handed to hyper -> response body first polled.
    writeback_first_poll,
    // ... -> response body fully handed to hyper for the client write.
    writeback_pumped,
});

define_latency!(EgressLatency {
    // tunnel handler entry -> outer response built (before its body is
    // polled).
    handler_total,
    // Outer body stream open -> metadata block read and decoded (includes
    // waiting for the ingress to stream its request body).
    metadata_wait,
    // ohttp decode_header (HPKE kem decap).
    hpke_header_open,
    // Client attestation consistency check (RA verify CPU, or ~0 under no_ra).
    client_attest_verify,
    // HPKE key lookup by the metadata hint.
    key_lookup,
    // bhttp decode of the decrypted inner request (waits for the whole
    // request body to arrive sealed on the wire).
    inner_req_decode,
    // Response seal/encapsulator construction.
    resp_seal_setup,
    // Backend slot mutex wait.
    backend_slot_wait,
    // Reused pooled connection: ready().await (head-of-line indicator).
    backend_ready,
    // Reused pooled connection: request send -> response headers.
    backend_send,
    // Fresh pooled connection: pipe + hyper http1 handshake.
    backend_redial,
    // Fresh pooled connection: first send -> response headers (includes the
    // egress flow task dialing the real backend).
    backend_send_fresh,
    // Sealed response body stream built -> first poll by hyper.
    resp_body_first_poll,
    // ... -> first sealed response frame.
    resp_body_first_chunk,
    // ... -> sealed response body fully pumped out.
    resp_body_pumped,
});

/// Transparent `Stream` adapter that records when the wrapped stream is
/// first polled, when its `(skip+1)`-th item arrives, and when it ends -
/// all measured from the moment the adapter was built. That construction-
/// to-first-poll gap is exactly the scheduling window a fused seal pump
/// hides: the pump only runs when the HTTP layer pulls the body. The inner
/// stream is boxed because the opaque stream types the seal helpers return
/// are not `Unpin`.
pub(crate) struct TimedStream<S> {
    inner: std::pin::Pin<Box<S>>,
    timer: Timer,
    first_poll: Histogram,
    first_data: Option<(usize, Histogram)>,
    done: Histogram,
    first_polled: bool,
    first_data_done: bool,
    frames: usize,
    finished: bool,
}

impl<S> TimedStream<S> {
    pub(crate) fn new(
        inner: S,
        first_poll: Histogram,
        first_data: Option<(usize, Histogram)>,
        done: Histogram,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            timer: Timer::start(),
            first_poll,
            first_data,
            done,
            first_polled: false,
            first_data_done: false,
            frames: 0,
            finished: false,
        }
    }
}

impl<S: Stream> Stream for TimedStream<S> {
    type Item = S::Item;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        if !this.first_polled {
            this.first_polled = true;
            this.first_poll.record(this.timer.elapsed());
        }
        match this.inner.as_mut().poll_next(cx) {
            std::task::Poll::Ready(Some(item)) => {
                this.frames += 1;
                let mut first_data_now = false;
                if let Some((skip, hist)) = &this.first_data {
                    if !this.first_data_done && this.frames > *skip {
                        hist.record(this.timer.elapsed());
                        first_data_now = true;
                    }
                }
                if first_data_now {
                    this.first_data_done = true;
                }
                std::task::Poll::Ready(Some(item))
            }
            std::task::Poll::Ready(None) => {
                if !this.finished {
                    this.finished = true;
                    this.done.record(this.timer.elapsed());
                }
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[cfg(all(test, feature = "latency-timing"))]
mod tests {
    use futures::stream;
    use futures::Stream;
    use futures::StreamExt;
    use serde_json::Value;
    use std::time::Duration;

    use super::recorder::{
        bucket_lower_us, bucket_of, bucket_width_us, Histogram, HIST_BUCKETS, LINEAR_BUCKETS,
        MAX_BUCKETS_US,
    };
    use super::{EgressLatency, IngressLatency, PreconnectCounters, TimedStream};

    #[test]
    fn bucket_layout_matches_definition() {
        // Linear region: identity.
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_of(1), 1);
        assert_eq!(bucket_of(1023), 1023);
        // Octave starts land on the expected sub-bucket indices.
        assert_eq!(bucket_of(1024), LINEAR_BUCKETS);
        assert_eq!(bucket_of(2048), LINEAR_BUCKETS + 16);
        // Largest representable index.
        assert_eq!(bucket_of(MAX_BUCKETS_US), HIST_BUCKETS - 1);
        // Clamping never runs off the array.
        assert_eq!(bucket_of(u64::MAX), HIST_BUCKETS - 1);

        // Every power-of-two boundary falls in a bucket whose range
        // contains the value, and bucket_of is monotonic in that value.
        let mut prev = 0usize;
        let mut v = 1u64;
        while v <= MAX_BUCKETS_US {
            let i = bucket_of(v);
            assert!(i >= prev, "bucket_of not monotonic at {v}");
            prev = i;
            assert!(
                bucket_lower_us(i) <= v && v < bucket_lower_us(i) + bucket_width_us(i),
                "value {v} outside bucket {i} range"
            );
            v *= 2;
        }
        // Adjacent buckets tile the line with no gap or overlap.
        for i in 1..HIST_BUCKETS {
            assert_eq!(
                bucket_lower_us(i),
                bucket_lower_us(i - 1) + bucket_width_us(i - 1)
            );
        }
    }

    #[test]
    fn histogram_records_exact_count_mean_max() {
        let h = Histogram::new();
        for us in 1..=100u64 {
            h.record(Some(Duration::from_micros(us)));
        }
        let snap = h.snapshot();
        assert_eq!(snap["count"], 100);
        assert_eq!(snap["mean_us"], 50.5);
        assert_eq!(snap["max_us"], 100);
        // 1..=100 are all in 1us buckets: percentiles are exact here.
        assert_eq!(snap["p50_us"], 50);
        assert_eq!(snap["p99_us"], 99);
    }

    #[test]
    fn histogram_disabled_records_nothing() {
        let h = Histogram::new();
        h.record(None);
        h.record(None);
        let snap = h.snapshot();
        assert_eq!(snap["count"], 0);
        assert!(snap["mean_us"].is_null());
        assert!(snap["p50_us"].is_null());
        assert!(snap["p99_us"].is_null());
        assert!(snap["max_us"].is_null());
    }

    #[test]
    fn histogram_percentiles_bracket_large_values() {
        let h = Histogram::new();
        h.record(Some(Duration::from_micros(2_000_000)));
        let snap = h.snapshot();
        assert_eq!(snap["count"], 1);
        assert_eq!(snap["max_us"], 2_000_000);
        assert_eq!(snap["mean_us"], 2_000_000.0);
        // 2_000_000us is in the octave [2^20, 2^21): p50 is the midpoint
        // of a 16384us-wide bucket, so within ~0.9% of the value.
        let p50 = snap["p50_us"].as_u64().unwrap();
        assert!(
            (p50 as i64 - 2_000_000i64).unsigned_abs() < 20_000,
            "p50 {p50} too far from 2_000_000"
        );
    }

    #[test]
    fn histogram_snapshot_shape_is_stable() {
        let h = Histogram::new();
        h.record(Some(Duration::from_micros(7)));
        let snap = h.snapshot();
        let obj = snap.as_object().expect("object");
        let mut keys: Vec<&String> = obj.keys().collect();
        keys.sort();
        assert_eq!(keys, vec!["count", "max_us", "mean_us", "p50_us", "p99_us"]);
    }

    #[test]
    fn latency_snapshot_contains_all_declared_phases() {
        let ingress: Value = IngressLatency::new().snapshot();
        let egress: Value = EgressLatency::new().snapshot();
        assert_eq!(ingress["unit"], "microseconds");
        assert_eq!(ingress["cumulative_since_process_start"], true);
        // The names come from the field list; spot-check both sides.
        for name in [
            "handler_total",
            "route_lookup",
            "keyconfig_wait",
            "outer_post_wait",
            "inner_resp_decode",
            "writeback_pumped",
        ] {
            assert!(
                ingress["phases"].get(name).is_some(),
                "missing ingress phase {name}"
            );
        }
        for name in [
            "metadata_wait",
            "inner_req_decode",
            "backend_slot_wait",
            "backend_send_fresh",
            "resp_body_first_chunk",
        ] {
            assert!(
                egress["phases"].get(name).is_some(),
                "missing egress phase {name}"
            );
        }
        assert_eq!(ingress["phases"].as_object().unwrap().len(), 13);
        assert_eq!(egress["phases"].as_object().unwrap().len(), 15);
    }

    #[test]
    fn preconnect_counters_snapshot_tracks_events() {
        let counters = PreconnectCounters::default();
        let snap = counters.snapshot();
        for key in [
            "preconnect_started",
            "preconnect_declined_warm",
            "preconnect_reaped",
            "preconnect_abandoned",
        ] {
            assert_eq!(snap[key], 0, "{key} starts at zero");
        }
        counters.record_started();
        counters.record_started();
        counters.record_declined_warm();
        counters.record_reaped();
        counters.record_abandoned();
        let snap = counters.snapshot();
        assert_eq!(snap["preconnect_started"], 2);
        assert_eq!(snap["preconnect_declined_warm"], 1);
        assert_eq!(snap["preconnect_reaped"], 1);
        assert_eq!(snap["preconnect_abandoned"], 1);
    }

    #[tokio::test]
    async fn timed_stream_records_first_poll_and_completion() {
        let lat = IngressLatency::new();
        let s = TimedStream::new(
            stream::iter(vec![1u8, 2, 3]),
            lat.req_body_first_poll.clone(),
            Some((0, lat.req_body_first_chunk.clone())),
            lat.req_body_pumped.clone(),
        );
        let items: Vec<u8> = s.collect().await;
        assert_eq!(items, vec![1, 2, 3]);
        let snap = lat.snapshot();
        assert_eq!(snap["phases"]["req_body_first_poll"]["count"], 1);
        assert_eq!(snap["phases"]["req_body_first_chunk"]["count"], 1);
        assert_eq!(snap["phases"]["req_body_pumped"]["count"], 1);
    }

    #[tokio::test]
    async fn timed_stream_skips_leading_frames() {
        let lat = IngressLatency::new();
        // skip=1 models the metadata frame preceding sealed chunks.
        let s = TimedStream::new(
            stream::iter(vec![1u8, 2, 3]),
            lat.req_body_first_poll.clone(),
            Some((1, lat.req_body_first_chunk.clone())),
            lat.req_body_pumped.clone(),
        );
        let items: Vec<u8> = s.collect().await;
        assert_eq!(items, vec![1, 2, 3]);
        let snap = lat.snapshot();
        assert_eq!(snap["phases"]["req_body_first_chunk"]["count"], 1);
    }

    #[tokio::test]
    async fn timed_stream_empty_records_only_completion() {
        let lat = IngressLatency::new();
        let empty: Vec<u8> = vec![];
        let s = TimedStream::new(
            stream::iter(empty),
            lat.resp_stream_first_poll.clone(),
            Some((0, lat.writeback_first_poll.clone())),
            lat.resp_stream_pumped.clone(),
        );
        let items: Vec<u8> = s.collect().await;
        assert!(items.is_empty());
        let snap = lat.snapshot();
        assert_eq!(snap["phases"]["resp_stream_first_poll"]["count"], 1);
        assert_eq!(snap["phases"]["writeback_first_poll"]["count"], 0);
        assert_eq!(snap["phases"]["resp_stream_pumped"]["count"], 1);
    }

    #[tokio::test]
    async fn timed_stream_passes_through_errors_and_pending() {
        // A stream that pends once, yields one error item, then ends. The
        // first-poll histogram must catch the Pending poll (it measures
        // scheduling, not data), the done histogram must catch the end, and
        // items must pass through untouched.
        struct PendOnce {
            pending: bool,
            yielded: bool,
        }
        impl Stream for PendOnce {
            type Item = Result<(), ()>;
            fn poll_next(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                if self.pending {
                    self.pending = false;
                    cx.waker().wake_by_ref();
                    return std::task::Poll::Pending;
                }
                if self.yielded {
                    return std::task::Poll::Ready(None);
                }
                self.yielded = true;
                std::task::Poll::Ready(Some(Err(())))
            }
        }
        let lat = EgressLatency::new();
        let s = TimedStream::new(
            PendOnce {
                pending: true,
                yielded: false,
            },
            lat.resp_body_first_poll.clone(),
            Some((0, lat.resp_body_first_chunk.clone())),
            lat.resp_body_pumped.clone(),
        );
        let items: Vec<Result<(), ()>> = s.collect().await;
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
        assert_eq!(lat.resp_body_first_poll.snapshot()["count"], 1);
        assert_eq!(lat.resp_body_first_chunk.snapshot()["count"], 1);
        assert_eq!(lat.resp_body_pumped.snapshot()["count"], 1);
    }
}

#[cfg(all(test, not(feature = "latency-timing")))]
mod tests {
    use std::time::Duration;

    use super::recorder::{Histogram, PreconnectCounters, Timer};
    use super::{EgressLatency, IngressLatency};

    /// Without the feature a segment start reads no clock, hands `None` to
    /// the stub `record`, and a record call cannot panic on any input.
    #[test]
    fn stub_recorder_measures_nothing() {
        let timer = Timer::start();
        assert!(timer.elapsed().is_none());
        let histogram = Histogram::new();
        histogram.record(timer.elapsed());
        histogram.record(Some(Duration::from_secs(1)));
    }

    /// The histogram structs still build in a default tree so the record
    /// call sites compile, and recording through them changes nothing.
    #[test]
    fn latency_structs_construct_without_the_feature() {
        let ingress = IngressLatency::default();
        let egress = EgressLatency::new();
        ingress.handler_total.record(None);
        egress.handler_total.record(Some(Duration::from_secs(1)));
    }

    #[test]
    fn stub_preconnect_counters_accept_every_event() {
        let counters = PreconnectCounters::default();
        counters.record_declined_warm();
        counters.record_started();
        counters.record_reaped();
        counters.record_abandoned();
    }
}
