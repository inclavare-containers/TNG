use std::time::Duration;

use anyhow::{Context, Result};
use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig as _, WithTonicConfig};
use serde::{Deserialize, Serialize};

use super::{OltpCommonExporterConfig, OltpExporterProtocol};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TraceArgs {
    #[serde(default)]
    pub exporters: Vec<TraceExporterType>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "type")]
#[serde(deny_unknown_fields)]
pub enum TraceExporterType {
    /// Exporting in the OpenTelemetry Protocol (OTLP) format
    #[serde(rename = "oltp")]
    Oltp(OltpTraceExporterConfig),

    /// Exporting traces to stdout (for debug only)
    #[serde(rename = "stdout")]
    Stdout,
}

type OltpTraceExporterConfig = OltpCommonExporterConfig;

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

pub enum TraceExporterInstance {
    OpenTelemetryOltp(opentelemetry_otlp::SpanExporter),
    OpenTelemetryStdout(opentelemetry_stdout::SpanExporter),
}

impl TraceExporterInstance {
    pub fn into_sdk_tracer_provider(self) -> opentelemetry_sdk::trace::SdkTracerProvider {
        match self {
            TraceExporterInstance::OpenTelemetryOltp(span_exporter) => {
                let batch = opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor::builder(span_exporter, opentelemetry_sdk::runtime::Tokio).build();
                let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                    .with_span_processor(batch)
                    .with_resource(crate::observability::otlp_resource())
                    .build();
                tracer_provider
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

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use serde_json::json;

    use super::*;

    fn test_config_common(
        json_value: serde_json::Value,
        expected: TraceExporterType,
    ) -> Result<()> {
        let deserialized: TraceExporterType = serde_json::from_value(json_value)?;

        deserialized.instantiate()?;

        assert_eq!(deserialized, expected);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_otlp_config() -> Result<()> {
        let json_value = json!(
            {
                "type": "oltp",
                "protocol": "grpc",
                "endpoint": "http://127.0.0.1:4318",
                "headers": {
                    "api-key": "key",
                    "other-config-value": "value"
                },
            }
        );
        let expected = TraceExporterType::Oltp(OltpTraceExporterConfig {
            protocol: OltpExporterProtocol::Grpc,
            endpoint: "http://127.0.0.1:4318".to_string(),
            headers: Some(
                [
                    ("api-key".to_owned(), "key".to_owned()),
                    ("other-config-value".to_owned(), "value".to_owned()),
                ]
                .into(),
            ),
        });
        test_config_common(json_value, expected)?;

        let json_value = json!(
            {
                "type": "oltp",
                "protocol": "grpc",
                "endpoint": "http://127.0.0.1:4318",
            }
        );
        let expected = TraceExporterType::Oltp(OltpTraceExporterConfig {
            protocol: OltpExporterProtocol::Grpc,
            endpoint: "http://127.0.0.1:4318".to_string(),
            headers: None,
        });
        test_config_common(json_value, expected)?;

        let json_value = json!(
            {
                "type": "oltp",
                "protocol": "http/json",
                "endpoint": "http://127.0.0.1:4318",
            }
        );
        let expected = TraceExporterType::Oltp(OltpTraceExporterConfig {
            protocol: OltpExporterProtocol::HttpJson,
            endpoint: "http://127.0.0.1:4318".to_string(),
            headers: None,
        });
        test_config_common(json_value, expected)?;

        let json_value = json!(
            {
                "type": "oltp",
                "protocol": "http/protobuf",
                "endpoint": "http://127.0.0.1:4318",
            }
        );
        let expected = TraceExporterType::Oltp(OltpTraceExporterConfig {
            protocol: OltpExporterProtocol::HttpProtobuf,
            endpoint: "http://127.0.0.1:4318".to_string(),
            headers: None,
        });
        test_config_common(json_value, expected)?;

        let json_value = json!(
            {
                "type": "oltp",
                "protocol": "http/protobuf",
                "endpoint": "http://127.0.0.1:4318",
                "headers": {
                    "api-key": "key",
                    "other-config-value": "value"
                },
            }
        );
        let expected = TraceExporterType::Oltp(OltpTraceExporterConfig {
            protocol: OltpExporterProtocol::HttpProtobuf,
            endpoint: "http://127.0.0.1:4318".to_string(),
            headers: Some(
                [
                    ("api-key".to_owned(), "key".to_owned()),
                    ("other-config-value".to_owned(), "value".to_owned()),
                ]
                .into(),
            ),
        });
        test_config_common(json_value, expected)?;

        Ok(())
    }
}
