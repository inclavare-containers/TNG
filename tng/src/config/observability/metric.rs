use derivative::Derivative;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::OltpCommonExporterConfig;

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

    #[cfg(all(test, feature = "metric"))]
    #[serde(skip)]
    #[serde(rename = "mock")]
    Mock {
        step: u64,

        #[derivative(Debug = "ignore")]
        #[derivative(PartialEq = "ignore")]
        exporter: std::sync::Arc<
            dyn crate::observability::metric::simple_exporter::SimpleMetricExporter
                + Send
                + Sync
                + 'static,
        >,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FalconConfig {
    pub server_url: String,
    pub endpoint: String,
    #[serde(default)]
    pub tags: IndexMap<String, String>,
    #[serde(default = "falcon_config_default_step")]
    pub step: u64,
}

fn falcon_config_default_step() -> u64 {
    60
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OltpMetricExporterConfig {
    #[serde(flatten)]
    pub common: OltpCommonExporterConfig,
    pub step: u64,
}

fn stdout_config_default_step() -> u64 {
    60
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use scopeguard::defer;
    use serde_json::json;
    use tokio::select;
    use tokio_util::sync::CancellationToken;

    use crate::{
        config::{observability::OltpExporterProtocol, TngConfig},
        runtime::TngRuntime,
    };

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_multi_tng_instance() -> Result<()> {
        let mut set = tokio::task::JoinSet::new();

        for _ in 0..5 {
            set.spawn(async {
                let config: TngConfig = serde_json::from_value(json!(
                    {
                        "metric": {
                            "exporters": [
                                {
                                    "type": "stdout",
                                    "step": 1
                                }
                            ]
                        },
                        "add_ingress": [
                            {
                                "mapping": {
                                    "in": {
                                        "port": portpicker::pick_unused_port().unwrap()
                                    },
                                    "out": {
                                        "host": "127.0.0.1",
                                        "port": portpicker::pick_unused_port().unwrap()
                                    }
                                },
                                "no_ra": true
                            }
                        ]
                    }
                ))?;

                let cancel_token = CancellationToken::new();
                let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();

                let cancel_token_clone = cancel_token.clone();
                let join_handle = tokio::task::spawn(async move {
                    TngRuntime::from_config(config)
                        .await?
                        .serve_with_cancel(cancel_token_clone, ready_sender)
                        .await
                });

                ready_receiver.await?;
                // tng is ready now, so we cancel it

                cancel_token.cancel();

                select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                        defer! {
                            std::process::exit(1);
                        }
                        panic!("Wait for tng exit timeout")
                    }
                    _ = join_handle => {}
                }

                Ok::<_, anyhow::Error>(())
            });
        }

        for res in set.join_all().await {
            res?;
        }

        Ok(())
    }
}
