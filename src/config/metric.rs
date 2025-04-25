use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use derivative::Derivative;
use opentelemetry_otlp::{WithExportConfig as _, WithTonicConfig};
use serde::{Deserialize, Serialize};

use crate::observability::exporter::{
    falcon::FalconConfig, stdout::StdoutExporter, SimpleMetricExporter,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetricArgs {
    #[serde(default)]
    pub exporters: Vec<ExporterType>,
}

#[derive(Clone, Serialize, Deserialize, Derivative)]
#[derivative(Debug, PartialEq)]
#[serde(tag = "type")]
pub enum ExporterType {
    #[serde(rename = "stdout")]
    Stdout {
        #[serde(default = "stdout_config_default_step")]
        step: u64,
    },

    #[serde(rename = "falcon")]
    Falcon(FalconConfig),

    /// Exporting in the OpenTelemetry Protocol (OTLP) format
    #[serde(rename = "oltp")]
    Oltp {
        protocol: OltpExporterProtocol,
        endpoint: String,
        step: u64,
    },

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

fn stdout_config_default_step() -> u64 {
    60
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum OltpExporterProtocol {
    #[serde(rename = "http/protobuf")]
    HttpProtobuf,
    #[serde(rename = "http/json")]
    HttpJson,
    #[serde(rename = "grpc")]
    Grpc,
}

impl ExporterType {
    pub fn instantiate(&self) -> Result<ExporterInstance> {
        match self {
            ExporterType::Stdout { step } => {
                Ok(ExporterInstance::Simple(*step, Arc::new(StdoutExporter {})))
            }
            ExporterType::Falcon(falcon_config) => {
                let falcon_exporter = crate::observability::exporter::falcon::FalconExporter::new(
                    falcon_config.clone(),
                )?;
                Ok(ExporterInstance::Simple(
                    falcon_config.step,
                    Arc::new(falcon_exporter),
                ))
            }
            #[cfg(test)]
            ExporterType::Mock { step, exporter } => {
                Ok(ExporterInstance::Simple(*step, exporter.clone()))
            }
            ExporterType::Oltp {
                protocol,
                endpoint,
                step,
            } => {
                let exporter = match protocol {
                    OltpExporterProtocol::HttpProtobuf | OltpExporterProtocol::HttpJson => {
                        opentelemetry_otlp::MetricExporter::builder()
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
                            .with_timeout(Duration::from_secs(5))
                            .build()
                            .context("Failed to create OTLP Http exporter")?
                    }
                    OltpExporterProtocol::Grpc => opentelemetry_otlp::MetricExporter::builder()
                        .with_tonic()
                        .with_endpoint(endpoint)
                        .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                        .with_compression(opentelemetry_otlp::Compression::Gzip)
                        .with_timeout(Duration::from_secs(5))
                        .build()
                        .context("Failed to create OTLP gRPC exporter")?,
                };
                Ok(ExporterInstance::OpenTelemetry(*step, exporter))
            }
        }
    }
}

pub enum ExporterInstance {
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

    fn test_config_common(json_value: serde_json::Value, expected: ExporterType) -> Result<()> {
        let deserialized: ExporterType = serde_json::from_value(json_value)?;

        deserialized.instantiate()?;

        assert_eq!(deserialized, expected);

        Ok(())
    }

    #[test]
    fn test_falcon_config() -> Result<()> {
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

        let expected = ExporterType::Falcon(FalconConfig {
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

    #[test]
    fn test_stdout_config() -> Result<()> {
        let json_value = json!(
            {
                "type": "stdout",
                "step": 1
            }
        );

        let expected = ExporterType::Stdout { step: 1 };

        test_config_common(json_value, expected)?;

        Ok(())
    }

    #[test]
    fn test_otlp_config() -> Result<()> {
        let json_value = json!(
            {
                "type": "oltp",
                "protocol": "http/protobuf",
                "endpoint": "http://127.0.0.1:4318",
                "step": 60
            }
        );

        let expected = ExporterType::Oltp {
            protocol: OltpExporterProtocol::HttpProtobuf,
            endpoint: "http://127.0.0.1:4318".to_string(),
            step: 60,
        };

        test_config_common(json_value, expected)?;

        Ok(())
    }
}
