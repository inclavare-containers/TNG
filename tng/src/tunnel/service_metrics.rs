use std::sync::Arc;

use indexmap::IndexMap;
use opentelemetry::metrics::{Counter, MeterProvider, UpDownCounter};

use crate::observability::metric::counter::{AttributedCounter, WithAttributes};

/// ServiceMetrics is a set of metrics for a service.
///
/// This struct is free be cloned and used anywhere.
#[derive(Debug, Clone)]
pub struct ServiceMetrics {
    pub cx_total: AttributedCounter<Counter<u64>, u64>,
    pub cx_active: AttributedCounter<UpDownCounter<i64>, i64>,
    pub cx_failed: AttributedCounter<Counter<u64>, u64>,
    pub tx_bytes_total: AttributedCounter<Counter<u64>, u64>,
    pub rx_bytes_total: AttributedCounter<Counter<u64>, u64>,
}

impl ServiceMetrics {
    pub fn new(
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
}
