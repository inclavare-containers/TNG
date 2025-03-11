use std::sync::Arc;

use indexmap::IndexMap;
use opentelemetry::metrics::{Counter, UpDownCounter};

use crate::observability::metric::counter::{AttributedCounter, WithAttributes};

#[derive(Debug, Clone)]
pub struct ServiceMetrics {
    pub cx_total: AttributedCounter<Counter<u64>, u64>,
    pub cx_active: AttributedCounter<UpDownCounter<i64>, i64>,
    pub cx_failed: AttributedCounter<Counter<u64>, u64>,
    pub tx_bytes_total: AttributedCounter<Counter<u64>, u64>,
    pub rx_bytes_total: AttributedCounter<Counter<u64>, u64>,
}

impl ServiceMetrics {
    pub fn new(attributes: impl Into<IndexMap<String, String>>) -> Self {
        let attributes = Arc::new(attributes.into());

        let meter = opentelemetry::global::meter("tng");
        let cx_total = meter
            .u64_counter("cx_total")
            .with_description("Total number of connections handled since the instance started")
            .build()
            .with_attributes(attributes.clone());
        let cx_active = meter
            .i64_up_down_counter("cx_active")
            .with_description("The number of active connections")
            .build()
            .with_attributes(attributes.clone());
        let cx_failed = meter
            .u64_counter("cx_failed")
            .with_description("Total number of failed connections since the instance started")
            .build()
            .with_attributes(attributes.clone());
        let tx_bytes_total = meter
            .u64_counter("tx_bytes_total")
            .with_description("The total number of bytes sent")
            .build()
            .with_attributes(attributes.clone());
        let rx_bytes_total = meter
            .u64_counter("rx_bytes_total")
            .with_description("The total number of bytes received")
            .build()
            .with_attributes(attributes.clone());

        Self {
            cx_total,
            cx_active,
            cx_failed,
            tx_bytes_total,
            rx_bytes_total,
        }
    }
}
