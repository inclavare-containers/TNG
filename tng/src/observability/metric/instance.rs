use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig, WithTonicConfig};

use crate::{
    config::observability::{
        metric::{MetricExporterType, OltpMetricExporterConfig},
        OltpCommonExporterConfig, OltpExporterProtocol,
    },
    observability::metric::simple_exporter::{
        opentelemetry_metric_reader::ShutdownInStandaloneTokioThreadMetricReader,
        stdout::StdoutExporter, OpenTelemetryMetricExporterAdapter, SimpleMetricExporter,
    },
};

impl MetricExporterType {
    pub fn instantiate(&self) -> Result<MetricExporterInstance> {
        match self {
            MetricExporterType::Stdout { step } => Ok(MetricExporterInstance::Simple(
                *step,
                Arc::new(StdoutExporter {}),
            )),
            MetricExporterType::Falcon(falcon_config) => {
                let falcon_exporter =
                    crate::observability::metric::simple_exporter::falcon::FalconExporter::new(
                        falcon_config.clone(),
                    )?;
                Ok(MetricExporterInstance::Simple(
                    falcon_config.step,
                    Arc::new(falcon_exporter),
                ))
            }
            #[cfg(test)]
            MetricExporterType::Mock { step, exporter } => {
                Ok(MetricExporterInstance::Simple(*step, exporter.clone()))
            }
            MetricExporterType::Oltp(OltpMetricExporterConfig {
                common:
                    OltpCommonExporterConfig {
                        protocol,
                        endpoint,
                        headers,
                    },
                step,
            }) => {
                let exporter = match protocol {
                    OltpExporterProtocol::HttpProtobuf | OltpExporterProtocol::HttpJson => {
                        let mut builder = opentelemetry_otlp::MetricExporter::builder()
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
                        let mut builder = opentelemetry_otlp::MetricExporter::builder()
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
                Ok(MetricExporterInstance::OpenTelemetry(*step, exporter))
            }
        }
    }
}

pub enum MetricExporterInstance {
    Simple(
        u64, /* step */
        Arc<dyn SimpleMetricExporter + Send + Sync + 'static>,
    ),
    OpenTelemetry(u64 /* step */, opentelemetry_otlp::MetricExporter),
}

impl MetricExporterInstance {
    pub fn into_sdk_meter_provider(self) -> opentelemetry_sdk::metrics::SdkMeterProvider {
        match self {
            MetricExporterInstance::Simple(step, simple_metric_exporter) => {
                let exporter = OpenTelemetryMetricExporterAdapter::new(simple_metric_exporter);
                let reader = opentelemetry_sdk::metrics::periodic_reader_with_async_runtime::PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio)
                    .with_interval(Duration::from_secs(step))
                    .build();
                let reader = ShutdownInStandaloneTokioThreadMetricReader::new(reader);
                opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                    .with_reader(reader)
                    .with_resource(crate::observability::otlp_resource())
                    .build()
            }
            MetricExporterInstance::OpenTelemetry(step, exporter) => {
                let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
                    .with_interval(Duration::from_secs(step))
                    .build();
                let reader = ShutdownInStandaloneTokioThreadMetricReader::new(reader);
                opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                    .with_reader(reader)
                    .with_resource(crate::observability::otlp_resource())
                    .build()
            }
        }
    }
}
