// This file is copied from https://github.com/open-telemetry/opentelemetry-rust/blob/3d589d6449fae5bbca32eef20bab4ce08b30e4dc/opentelemetry/src/metrics/noop.rs
// Because the original NoopMeterProvider is not public (https://github.com/open-telemetry/opentelemetry-rust/pull/2191), we have to copy it here.

use opentelemetry::{
    metrics::{InstrumentProvider, Meter, MeterProvider},
    InstrumentationScope,
};
use std::sync::Arc;

/// A no-op instance of a `MetricProvider`
#[derive(Debug, Default)]
pub(crate) struct NoopMeterProvider {
    _private: (),
}

impl NoopMeterProvider {
    /// Create a new no-op meter provider.
    pub(crate) fn new() -> Self {
        NoopMeterProvider { _private: () }
    }
}

impl MeterProvider for NoopMeterProvider {
    fn meter_with_scope(&self, _scope: InstrumentationScope) -> Meter {
        Meter::new(Arc::new(NoopMeter::new()))
    }
}

/// A no-op instance of a `Meter`
#[derive(Debug, Default)]
pub(crate) struct NoopMeter {
    _private: (),
}

impl NoopMeter {
    /// Create a new no-op meter core.
    pub(crate) fn new() -> Self {
        NoopMeter { _private: () }
    }
}

impl InstrumentProvider for NoopMeter {}
