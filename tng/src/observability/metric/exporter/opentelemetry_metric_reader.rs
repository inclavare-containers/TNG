use opentelemetry_sdk::metrics::reader::MetricReader;

#[derive(Debug)]
pub struct ShutdownInStandaloneTokioThreadMetricReader<T: MetricReader> {
    inner: T,
}

impl<T: MetricReader> ShutdownInStandaloneTokioThreadMetricReader<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: MetricReader> MetricReader for ShutdownInStandaloneTokioThreadMetricReader<T> {
    fn register_pipeline(&self, pipeline: std::sync::Weak<opentelemetry_sdk::metrics::Pipeline>) {
        self.inner.register_pipeline(pipeline);
    }

    fn collect(
        &self,
        rm: &mut opentelemetry_sdk::metrics::data::ResourceMetrics,
    ) -> opentelemetry_sdk::metrics::MetricResult<()> {
        self.inner.collect(rm)
    }

    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        // Informs the executor to hand off any other tasks it has to a new worker thread
        tokio::task::block_in_place(|| {
            // And then we can call the inner force_flush method
            self.inner.force_flush()
        })
    }

    fn shutdown(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        // Informs the executor to hand off any other tasks it has to a new worker thread
        tokio::task::block_in_place(|| {
            // And then we can call the inner shutdown method
            self.inner.shutdown()
        })
    }

    fn temporality(
        &self,
        kind: opentelemetry_sdk::metrics::InstrumentKind,
    ) -> opentelemetry_sdk::metrics::Temporality {
        self.inner.temporality(kind)
    }
}
