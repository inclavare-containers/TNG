use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use derivative::Derivative;
use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig, WithTonicConfig};
use serde::{Deserialize, Serialize};

use crate::observability::exporter::{
    falcon::FalconConfig, stdout::StdoutExporter, SimpleMetricExporter,
};

use super::{OltpCommonExporterConfig, OltpExporterProtocol};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetricArgs {
    #[serde(default)]
    pub exporters: Vec<MetricExporterType>,
}

#[derive(Clone, Serialize, Deserialize, Derivative)]
#[derivative(Debug, PartialEq)]
#[serde(tag = "type")]
pub enum MetricExporterType {
    #[serde(rename = "stdout")]
    Stdout {
        #[serde(default = "stdout_config_default_step")]
        step: u64,
    },

    #[serde(rename = "falcon")]
    Falcon(FalconConfig),

    /// Exporting in the OpenTelemetry Protocol (OTLP) format
    #[serde(rename = "oltp")]
    Oltp(OltpMetricExporterConfig),

    #[cfg(test)]
    #[serde(skip)]
    #[serde(rename = "mock")]
    Mock {
        step: u64,

        #[derivative(Debug = "ignore")]
        #[derivative(PartialEq = "ignore")]
        exporter: std::sync::Arc<dyn SimpleMetricExporter + Send + Sync + 'static>,
    },
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OltpMetricExporterConfig {
    #[serde(flatten)]
    common: OltpCommonExporterConfig,
    step: u64,
}

fn stdout_config_default_step() -> u64 {
    60
}

impl MetricExporterType {
    pub fn instantiate(&self) -> Result<MetricExporterInstance> {
        match self {
            MetricExporterType::Stdout { step } => Ok(MetricExporterInstance::Simple(
                *step,
                Arc::new(StdoutExporter {}),
            )),
            MetricExporterType::Falcon(falcon_config) => {
                let falcon_exporter = crate::observability::exporter::falcon::FalconExporter::new(
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

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use serde_json::json;

    use super::*;

    fn test_config_common(
        json_value: serde_json::Value,
        expected: MetricExporterType,
    ) -> Result<()> {
        let deserialized: MetricExporterType = serde_json::from_value(json_value)?;

        deserialized.instantiate()?;

        assert_eq!(deserialized, expected);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_falcon_config() -> Result<()> {
        let json_value = json!(
            {
                "type": "falcon",
                "server_url": "http://127.0.0.1:1988",
                "endpoint": "master-node",
                "tags": {
                    "namespace": "ns1",
                    "app": "tng"
                },
                "step": 60
            }
        );

        let expected = MetricExporterType::Falcon(FalconConfig {
            server_url: "http://127.0.0.1:1988".to_owned(),
            endpoint: "master-node".to_owned(),
            tags: [
                ("namespace".to_owned(), "ns1".to_owned()),
                ("app".to_owned(), "tng".to_owned()),
            ]
            .into(),
            step: 60,
        });

        test_config_common(json_value, expected)?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_stdout_config() -> Result<()> {
        let json_value = json!(
            {
                "type": "stdout",
                "step": 1
            }
        );

        let expected = MetricExporterType::Stdout { step: 1 };

        test_config_common(json_value, expected)?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_otlp_config() -> Result<()> {
        let json_value = json!(
            {
                "type": "oltp",
                "protocol": "http/protobuf",
                "endpoint": "http://127.0.0.1:4318",
                "step": 60
            }
        );

        let expected = MetricExporterType::Oltp(OltpMetricExporterConfig {
            common: OltpCommonExporterConfig {
                protocol: OltpExporterProtocol::HttpProtobuf,
                endpoint: "http://127.0.0.1:4318".to_string(),
                headers: None,
            },
            step: 60,
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
                "step": 60
            }
        );

        let expected = MetricExporterType::Oltp(OltpMetricExporterConfig {
            common: OltpCommonExporterConfig {
                protocol: OltpExporterProtocol::HttpProtobuf,
                endpoint: "http://127.0.0.1:4318".to_string(),
                headers: Some(
                    [
                        ("api-key".to_owned(), "key".to_owned()),
                        ("other-config-value".to_owned(), "value".to_owned()),
                    ]
                    .into(),
                ),
            },
            step: 60,
        });

        test_config_common(json_value, expected)?;

        Ok(())
    }
}
