use std::time::Duration;

use anyhow::{Context, Result};
use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig as _, WithTonicConfig};

use crate::{
    config::observability::{
        trace::{OltpTraceExporterConfig, TraceExporterType},
        OltpExporterProtocol,
    },
    observability::trace::opentelemetry_span_processor::ShutdownInStandaloneTokioThreadSpanProcessor,
};

impl TraceExporterType {
    pub fn instantiate(&self) -> Result<TraceExporterInstance> {
        match self {
            TraceExporterType::Oltp(OltpTraceExporterConfig {
                protocol,
                endpoint,
                headers,
            }) => {
                let span_exporter = match protocol {
                    OltpExporterProtocol::HttpProtobuf | OltpExporterProtocol::HttpJson => {
                        let mut builder = opentelemetry_otlp::SpanExporter::builder()
                            .with_http()
                            .with_endpoint(endpoint)
                            .with_protocol(match protocol {
                                OltpExporterProtocol::HttpProtobuf => {
                                    opentelemetry_otlp::Protocol::HttpBinary
                                }
                                OltpExporterProtocol::HttpJson => {
                                    opentelemetry_otlp::Protocol::HttpJson
                                }
                                OltpExporterProtocol::Grpc => unreachable!(),
                            })
                            .with_timeout(Duration::from_secs(5));
                        if let Some(headers) = headers {
                            builder = builder.with_headers(headers.clone())
                        }
                        builder
                            .build()
                            .context("Failed to create OTLP Http exporter")?
                    }
                    OltpExporterProtocol::Grpc => {
                        let mut builder = opentelemetry_otlp::SpanExporter::builder()
                            .with_tonic()
                            .with_endpoint(endpoint)
                            .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                            .with_compression(opentelemetry_otlp::Compression::Gzip)
                            .with_timeout(Duration::from_secs(5));
                        if let Some(headers) = headers {
                            builder =
                                builder.with_metadata(tonic::metadata::MetadataMap::from_headers(
                                    http::HeaderMap::try_from(headers)
                                        .context("Failed to parse to HTTP headers")?,
                                ))
                        }
                        builder
                            .build()
                            .context("Failed to create OTLP gRPC exporter")?
                    }
                };

                Ok(TraceExporterInstance::OpenTelemetryOltp(span_exporter))
            }
            TraceExporterType::Stdout => Ok(TraceExporterInstance::OpenTelemetryStdout(
                opentelemetry_stdout::SpanExporter::default(),
            )),
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum TraceExporterInstance {
    OpenTelemetryOltp(opentelemetry_otlp::SpanExporter),
    OpenTelemetryStdout(opentelemetry_stdout::SpanExporter),
}

impl TraceExporterInstance {
    pub fn into_sdk_tracer_provider(self) -> opentelemetry_sdk::trace::SdkTracerProvider {
        match self {
            TraceExporterInstance::OpenTelemetryOltp(span_exporter) => {
                let batch =
                    opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor::builder(span_exporter, opentelemetry_sdk::runtime::Tokio).build();
                let batch = ShutdownInStandaloneTokioThreadSpanProcessor::new(batch);

                opentelemetry_sdk::trace::SdkTracerProvider::builder()
                    .with_span_processor(batch)
                    .with_resource(crate::observability::otlp_resource())
                    .build()
            }
            TraceExporterInstance::OpenTelemetryStdout(span_exporter) => {
                opentelemetry_sdk::trace::SdkTracerProvider::builder()
                    .with_simple_exporter(span_exporter)
                    .with_resource(crate::observability::otlp_resource())
                    .build()
            }
        }
    }
}
