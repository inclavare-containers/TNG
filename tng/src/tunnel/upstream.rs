//! Dials the egress upstream (backend) TCP connections.
//!
//! Every backend leg the egress opens — the transport-level direct forward,
//! the rats_tls byte streams handed back to the flow, and the ohttp
//! self-forwarded keep-alive connections — goes through one
//! `UpstreamConnector` per accepted outer connection. The dial parameters
//! (the endpoint resolved by the capture mode at accept time, plus the
//! mode's `SO_MARK`), the `cx_*` connection accounting, and the access-log
//! state machine then live in exactly one place.

use std::sync::Arc;

use anyhow::{Context, Result};

use crate::tunnel::access_log::AccessAccepted;
use crate::tunnel::endpoint::TngEndpoint;
use crate::tunnel::service_metrics::{ActiveConnectionCounter, ServiceMetrics};
use crate::tunnel::stream::ContextualStream;

/// One per accepted outer connection, shared (`Arc`) by every backend leg it
/// spawns. The endpoint is the destination the egress capture mode resolved
/// when the connection was accepted; it never follows the decrypted inner
/// request's `Host`.
pub(crate) struct UpstreamConnector {
    endpoint: Arc<TngEndpoint>,
    /// Stamped on the backend socket in netfilter mode so the kernel's
    /// REDIRECT rules don't send TNG's own connections back into the proxy.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    so_mark: Option<u32>,
    metrics: ServiceMetrics,
    /// The accept-time access-log state. Every `connect` takes a clone, which
    /// also silences the original, mirroring the flow loop's
    /// `clone_for_multiplexing`. When the last connector handle drops, an
    /// original that was never cloned logs the ERROR "accepted only" line for
    /// a connection that ended without reaching any backend.
    access_accepted: tokio::sync::Mutex<AccessAccepted>,
}

/// A connected backend stream plus its `cx_total`/`cx_active` accounting
/// guard.
pub(crate) struct ConnectedUpstream {
    stream: ContextualStream<tokio::net::TcpStream>,
    active_cx: ActiveConnectionCounter,
}

impl UpstreamConnector {
    pub(crate) fn new(
        endpoint: Arc<TngEndpoint>,
        metrics: ServiceMetrics,
        access_accepted: AccessAccepted,
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        so_mark: Option<u32>,
    ) -> Self {
        Self {
            endpoint,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            so_mark,
            metrics,
            access_accepted: tokio::sync::Mutex::new(access_accepted),
        }
    }

    /// The service counters for this outer connection. Self-forwarding
    /// protocols wrap their backend streams with these so byte totals stay
    /// on the same service the flow legs would have used.
    pub(crate) fn metrics(&self) -> &ServiceMetrics {
        &self.metrics
    }

    /// Dials one backend connection, transitioning the access log through
    /// `Routed` to `Established`. A failed dial counts `cx_failed` (the
    /// guard drops unmarked) and the dropped `Routed` state logs its ERROR
    /// line.
    pub(crate) async fn connect(
        &self,
        encrypted: bool,
        attested: bool,
    ) -> Result<ConnectedUpstream> {
        let active_cx = self.metrics.new_cx();

        let access_routed = self
            .access_accepted
            .lock()
            .await
            .clone_for_multiplexing()
            .into_routed(self.endpoint.as_ref(), encrypted);

        let stream = self
            .endpoint
            .tcp_connect(
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                self.so_mark,
            )
            .await
            .context("Failed to connect to upstream")?;
        let egress_local = stream.local_addr().context("Failed to get local addr")?;

        // Print access log — Transition to AccessEstablished: upstream connected, then drop immediately to log
        access_routed.into_established(Some(egress_local), attested);

        Ok(ConnectedUpstream {
            stream: ContextualStream::new(stream, "egress-tcp-connect"),
            active_cx,
        })
    }
}

impl ConnectedUpstream {
    /// Splits the tagged socket from the accounting guard. Dropping the
    /// guard without calling `mark_finished_successfully` reports a failed
    /// connection, so the consumer must mark when the leg ends.
    pub(crate) fn into_parts(
        self,
    ) -> (
        ContextualStream<tokio::net::TcpStream>,
        ActiveConnectionCounter,
    ) {
        (self.stream, self.active_cx)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::fmt;
    use std::net::Ipv4Addr;
    use std::sync::Weak;
    use std::time::Duration;

    use indexmap::IndexMap;
    use opentelemetry_sdk::error::OTelSdkResult;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::reader::MetricReader;
    use opentelemetry_sdk::metrics::{
        InstrumentKind, ManualReader, Pipeline, SdkMeterProvider, Temporality,
    };

    use crate::tunnel::access_log::EgressAccessMode;
    use crate::tunnel::service_metrics::ServiceMetricsCreator;

    /// A `ManualReader` behind an `Arc` so the test can both register it
    /// with the meter provider and read the cx counters back afterwards.
    #[derive(Clone)]
    struct SharedReader(Arc<ManualReader>);

    impl SharedReader {
        fn new() -> Self {
            Self(Arc::new(ManualReader::builder().build()))
        }
    }

    impl fmt::Debug for SharedReader {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("SharedReader").finish()
        }
    }

    impl MetricReader for SharedReader {
        fn register_pipeline(&self, pipeline: Weak<Pipeline>) {
            self.0.register_pipeline(pipeline);
        }

        fn collect(&self, rm: &mut ResourceMetrics) -> OTelSdkResult {
            self.0.collect(rm)
        }

        fn force_flush(&self) -> OTelSdkResult {
            self.0.force_flush()
        }

        fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
            self.0.shutdown_with_timeout(timeout)
        }

        fn temporality(&self, kind: InstrumentKind) -> Temporality {
            self.0.temporality(kind)
        }
    }

    /// The cx counters of a freshly created `ServiceMetrics`, read back
    /// through the in-process reader.
    pub(crate) struct Recorder {
        reader: SharedReader,
        #[allow(dead_code)] // keeps the meter provider (and pipeline) alive
        provider: SdkMeterProvider,
    }

    impl Recorder {
        pub(crate) fn new() -> (ServiceMetrics, Self) {
            let reader = SharedReader::new();
            let provider = SdkMeterProvider::builder()
                .with_reader(reader.clone())
                .build();
            let creator = ServiceMetricsCreator::new_creator(Arc::new(provider.clone()));
            (
                creator.new_service_metrics(IndexMap::new()),
                Self { reader, provider },
            )
        }

        pub(crate) fn counter_u64(&self, name: &str) -> u64 {
            let mut rm = ResourceMetrics::default();
            self.reader.collect(&mut rm).unwrap();
            let mut values = rm
                .scope_metrics()
                .flat_map(|sm| sm.metrics())
                .filter(|m| m.name() == name)
                .filter_map(|m| match m.data() {
                    AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                        Some(sum.data_points().map(|p| p.value()).sum::<u64>())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(values.len(), 1, "expected exactly one {name} series");
            values.pop().unwrap()
        }

        pub(crate) fn counter_i64(&self, name: &str) -> i64 {
            let mut rm = ResourceMetrics::default();
            self.reader.collect(&mut rm).unwrap();
            let mut values = rm
                .scope_metrics()
                .flat_map(|sm| sm.metrics())
                .filter(|m| m.name() == name)
                .filter_map(|m| match m.data() {
                    AggregatedMetrics::I64(MetricData::Sum(sum)) => {
                        Some(sum.data_points().map(|p| p.value()).sum::<i64>())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(values.len(), 1, "expected exactly one {name} series");
            values.pop().unwrap()
        }
    }

    fn accepted() -> AccessAccepted {
        AccessAccepted::new_egress(
            "127.0.0.1:54321".parse().unwrap(),
            "127.0.0.1:8080".parse().unwrap(),
            EgressAccessMode::Netfilter,
        )
    }

    fn connector(metrics: ServiceMetrics, port: u16) -> UpstreamConnector {
        UpstreamConnector::new(
            Arc::new(TngEndpoint::from_ipv4(Ipv4Addr::LOCALHOST, port)),
            metrics,
            accepted(),
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
        )
    }

    /// A successful dial registers the connection and, once the leg is
    /// marked finished, leaves `cx_active` back at zero with no failure.
    #[tokio::test]
    async fn connect_success_marks_established_and_no_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (metrics, rec) = Recorder::new();
        let connector = connector(metrics, port);

        let upstream = connector.connect(true, false).await.unwrap();
        assert_eq!(rec.counter_u64("cx_total"), 1);
        assert_eq!(rec.counter_i64("cx_active"), 1);
        assert_eq!(rec.counter_u64("cx_failed"), 0);

        let (_stream, active_cx) = upstream.into_parts();
        active_cx.mark_finished_successfully();
        assert_eq!(rec.counter_u64("cx_total"), 1);
        assert_eq!(rec.counter_i64("cx_active"), 0);
        assert_eq!(rec.counter_u64("cx_failed"), 0);
    }

    /// A leg whose guard drops without being marked (the consumer died
    /// mid-flight) counts as a failed connection, like the pre-connector
    /// `forward_to_upstream` early returns.
    #[tokio::test]
    async fn dropped_unmarked_guard_counts_failed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (metrics, rec) = Recorder::new();
        let connector = connector(metrics, port);

        let upstream = connector.connect(true, false).await.unwrap();
        let connected = upstream.active_cx;
        drop(connected);
        assert_eq!(rec.counter_u64("cx_total"), 1);
        assert_eq!(rec.counter_i64("cx_active"), 0);
        assert_eq!(rec.counter_u64("cx_failed"), 1);
    }

    /// A refused dial fails fast, and the failure was already accounted for
    /// (cx_total raised, cx_active released, cx_failed counted) when the
    /// error is returned.
    #[tokio::test]
    async fn connect_failure_counts_failed_at_dial() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let (metrics, rec) = Recorder::new();
        let connector = connector(metrics, port);

        assert!(connector.connect(true, false).await.is_err());
        assert_eq!(rec.counter_u64("cx_total"), 1);
        assert_eq!(rec.counter_i64("cx_active"), 0);
        assert_eq!(rec.counter_u64("cx_failed"), 1);
    }
}
