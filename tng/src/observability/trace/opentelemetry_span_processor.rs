use opentelemetry_sdk::trace::SpanProcessor;

#[derive(Debug)]
pub struct ShutdownInStandaloneTokioThreadSpanProcessor<T: SpanProcessor> {
    inner: T,
}

impl<T: SpanProcessor> ShutdownInStandaloneTokioThreadSpanProcessor<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: SpanProcessor> SpanProcessor for ShutdownInStandaloneTokioThreadSpanProcessor<T> {
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

    fn on_start(&self, span: &mut opentelemetry_sdk::trace::Span, cx: &opentelemetry::Context) {
        self.inner.on_start(span, cx);
    }

    fn on_end(&self, span: opentelemetry_sdk::trace::SpanData) {
        self.inner.on_end(span);
    }
}
