pub mod exporter;
pub mod log;
pub mod metric;

pub fn otlp_resource() -> opentelemetry_sdk::Resource {
    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name("tng")
        .with_attribute(
            // https://opentelemetry.io/docs/specs/semconv/attributes-registry/service/
            opentelemetry::KeyValue::new("service.version", crate::build::PKG_VERSION),
        )
        .build();
    resource
}
