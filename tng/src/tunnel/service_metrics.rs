use std::sync::Arc;

use indexmap::IndexMap;
use opentelemetry::metrics::{Counter, MeterProvider, UpDownCounter};

use crate::observability::metric::{
    counter::{AttributedCounter, WithAttributes},
    stream::{PendingCounter, StreamWithCounter},
};

pub struct ServiceMetricsCreator(Arc<dyn MeterProvider + Send + Sync>);

impl ServiceMetricsCreator {
    pub fn new_creator(
        meter_provider: Arc<dyn MeterProvider + Send + Sync>,
    ) -> ServiceMetricsCreator {
        ServiceMetricsCreator(meter_provider)
    }

    pub fn new_service_metrics(
        &self,
        attributes: impl Into<IndexMap<String, String>>,
    ) -> ServiceMetrics {
        ServiceMetrics::new(self.0.clone(), attributes)
    }
}

/// ServiceMetrics is a set of metrics for a service.
///
/// This struct is free be cloned and used anywhere.
#[derive(Debug, Clone)]
pub struct ServiceMetrics {
    cx_total: AttributedCounter<Counter<u64>, u64>,
    cx_active: AttributedCounter<UpDownCounter<i64>, i64>,
    cx_failed: AttributedCounter<Counter<u64>, u64>,
    tx_bytes_total: AttributedCounter<Counter<u64>, u64>,
    rx_bytes_total: AttributedCounter<Counter<u64>, u64>,
}

/// Which side of the service a wrapped stream sits on, deciding which way
/// the byte totals count.
#[derive(Clone, Copy)]
pub(crate) enum ByteCountOrientation {
    /// A tunnel-facing leg (the flow's downstream side, the ingress relay):
    /// bytes written to the stream count into `tx_bytes_total`, bytes read
    /// into `rx_bytes_total`.
    Tunnel,
    /// A backend-facing leg, for a protocol that forwards to the upstream
    /// itself instead of handing the leg back to the flow (ohttp). On the
    /// backend socket the proxy writes requests and reads responses, the
    /// reverse of the tunnel-facing orientation, so the counters are
    /// crossed there: `tx_bytes_total` keeps accumulating response bytes
    /// and `rx_bytes_total` request bytes, whatever the leg's orientation.
    Backend,
}

impl ServiceMetrics {
    pub(self) fn new(
        meter_provider: Arc<dyn MeterProvider + Send + Sync>,
        attributes: impl Into<IndexMap<String, String>>,
    ) -> Self {
        let attributes = Arc::new(attributes.into());

        let meter = meter_provider.meter("tng");
        let cx_total = meter
            .u64_counter("cx_total")
            .with_description("Total number of connections handled since the instance started")
            .build()
            .with_attributes(attributes.clone());
        cx_total.add(0);

        let cx_active = meter
            .i64_up_down_counter("cx_active")
            .with_description("The number of active connections")
            .build()
            .with_attributes(attributes.clone());
        cx_active.add(0);

        let cx_failed = meter
            .u64_counter("cx_failed")
            .with_description("Total number of failed connections since the instance started")
            .build()
            .with_attributes(attributes.clone());
        cx_failed.add(0);

        let tx_bytes_total = meter
            .u64_counter("tx_bytes_total")
            .with_unit("bytes")
            .with_description("The total number of bytes sent")
            .build()
            .with_attributes(attributes.clone());
        tx_bytes_total.add(0);

        let rx_bytes_total = meter
            .u64_counter("rx_bytes_total")
            .with_unit("bytes")
            .with_description("The total number of bytes received")
            .build()
            .with_attributes(attributes.clone());
        rx_bytes_total.add(0);

        Self {
            cx_total,
            cx_active,
            cx_failed,
            tx_bytes_total,
            rx_bytes_total,
        }
    }

    pub fn new_cx(&self) -> ActiveConnectionCounter {
        ActiveConnectionCounter::new(
            self.cx_total.clone(),
            self.cx_active.clone(),
            self.cx_failed.clone(),
        )
    }

    pub(crate) fn wrap_stream<
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
    >(
        &self,
        stream: T,
        orientation: ByteCountOrientation,
    ) -> StreamWithCounter<T> {
        let (tx, rx) = match orientation {
            ByteCountOrientation::Tunnel => {
                (self.tx_bytes_total.clone(), self.rx_bytes_total.clone())
            }
            ByteCountOrientation::Backend => {
                (self.rx_bytes_total.clone(), self.tx_bytes_total.clone())
            }
        };
        StreamWithCounter {
            inner: stream,
            tx: PendingCounter::new(tx),
            rx: PendingCounter::new(rx),
        }
    }

    /// Tunnel-facing wrap; shorthand for
    /// `wrap_stream(stream, ByteCountOrientation::Tunnel)`.
    pub fn new_wrapped_stream<
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
    >(
        &self,
        stream: T,
    ) -> StreamWithCounter<T> {
        self.wrap_stream(stream, ByteCountOrientation::Tunnel)
    }
}

pub struct ActiveConnectionCounter {
    cx_active: AttributedCounter<UpDownCounter<i64>, i64>,
    cx_failed: AttributedCounter<Counter<u64>, u64>,
    finished_successfully: bool,
}

impl ActiveConnectionCounter {
    pub fn new(
        cx_total: AttributedCounter<Counter<u64>, u64>,
        cx_active: AttributedCounter<UpDownCounter<i64>, i64>,
        cx_failed: AttributedCounter<Counter<u64>, u64>,
    ) -> Self {
        cx_total.add(1);
        cx_active.add(1);

        Self {
            cx_active,
            cx_failed,
            finished_successfully: false,
        }
    }

    /// Call this function when the stream is finished successfully, or it will report an failed connection when it is droppeds.
    pub fn mark_finished_successfully(mut self) {
        self.finished_successfully = true;
    }
}

impl Drop for ActiveConnectionCounter {
    fn drop(&mut self) {
        if !self.finished_successfully {
            self.cx_failed.add(1);
        }
        self.cx_active.add(-1);
    }
}
