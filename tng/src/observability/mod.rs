#[cfg(feature = "metric")]
pub mod metric;

pub mod trace;

#[cfg(any(feature = "metric", feature = "trace"))]
pub fn otlp_resource() -> opentelemetry_sdk::Resource {
    opentelemetry_sdk::Resource::builder()
        .with_service_name("tng")
        .with_attribute(
            // https://opentelemetry.io/docs/specs/semconv/attributes-registry/service/
            opentelemetry::KeyValue::new("service.version", crate::build::PKG_VERSION),
        )
        .build()
}
