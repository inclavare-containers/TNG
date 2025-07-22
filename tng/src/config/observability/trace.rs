use serde::{Deserialize, Serialize};

use super::OltpCommonExporterConfig;

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

pub type OltpTraceExporterConfig = OltpCommonExporterConfig;

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
                                    "type": "stdout"
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
