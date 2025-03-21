use std::time::{Duration, SystemTime, UNIX_EPOCH};

use again::RetryPolicy;
use anyhow::{Context, Result};
use async_trait::async_trait;
use indexmap::IndexMap;
use log::trace;
use serde::{Deserialize, Serialize};

use crate::observability::metric::{Metric, MetricValue, ValueType};

use super::MetricExporter;

#[derive(Debug, Serialize, PartialEq)]
struct FalconMetric {
    #[serde(rename = "endpoint")]
    endpoint: String,
    #[serde(rename = "metric")]
    metric: String,
    #[serde(rename = "value")]
    value: serde_json::Number,
    #[serde(rename = "step")]
    step: u64,
    #[serde(rename = "counterType")]
    counter_type: FalconCounterType,
    #[serde(rename = "tags")]
    tags: FalconTags,
    #[serde(rename = "timestamp")]
    timestamp: u64,
}

#[derive(Debug, Serialize, PartialEq)]
enum FalconCounterType {
    #[serde(rename = "COUNTER")]
    Counter,
    #[serde(rename = "GAUGE")]
    Gauge,
}

impl From<ValueType> for FalconCounterType {
    fn from(value_type: ValueType) -> Self {
        match value_type {
            ValueType::Counter => Self::Counter,
            ValueType::Gauge => Self::Gauge,
        }
    }
}

#[derive(Debug, PartialEq)]
struct FalconTags(IndexMap<String, String>);

impl<T: Into<IndexMap<String, String>>> From<T> for FalconTags {
    fn from(tags: T) -> Self {
        Self(tags.into())
    }
}

impl Serialize for FalconTags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let tags_str: String = self
            .0
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join(",");
        serializer.serialize_str(&tags_str)
    }
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

pub struct FalconExporter {
    falcon_config: FalconConfig,
    client: reqwest::Client,
}

const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

const MAX_PUSH_RETRY: usize = 5;

impl FalconExporter {
    pub fn new(falcon_config: FalconConfig) -> Result<Self> {
        Ok(Self {
            falcon_config,
            client: reqwest::ClientBuilder::new()
                .no_proxy()
                .user_agent(APP_USER_AGENT)
                .build()?,
        })
    }

    fn construct_metric(&self, metric: impl Metric, value: MetricValue) -> Result<FalconMetric> {
        Ok(FalconMetric {
            endpoint: self.falcon_config.endpoint.clone(),
            metric: metric.name(),
            value,
            step: self.falcon_config.step,
            counter_type: metric.value_type().into(),
            tags: {
                let mut tags = self.falcon_config.tags.clone();
                tags.extend(metric.labels());
                tags.into()
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("System time is before unix epoch")?
                .as_secs(),
        })
    }
}

#[async_trait]
impl MetricExporter for FalconExporter {
    async fn push(&self, metric_and_values: &[(Box<dyn Metric + '_>, MetricValue)]) -> Result<()> {
        let falcon_metrics = metric_and_values
            .into_iter()
            .map(|(metric, value)| self.construct_metric(metric.as_ref(), value.clone()))
            .collect::<Result<Vec<_>>>()?;

        trace!(
            "Pushing metrics to falcon: {}",
            serde_json::to_string(&falcon_metrics).unwrap_or_else(|e| format!("error: {e:#}"))
        );
        RetryPolicy::fixed(Duration::from_secs(1))
            .with_max_retries(MAX_PUSH_RETRY - 1)
            .retry(|| async {
                let res = self
                    .client
                    .post(format!("{}/v1/push", self.falcon_config.server_url))
                    .json(&falcon_metrics)
                    .send()
                    .await?;
                if let Err(e) = res.error_for_status_ref() {
                    if let Ok(text) = res.text().await {
                        Err(e).with_context(|| format!("Got response: {text}"))?
                    } else {
                        Err(e)?
                    }
                }

                Ok::<(), anyhow::Error>(())
            })
            .await
            .with_context(|| format!("Failed after {MAX_PUSH_RETRY} attemptions."))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        config::TngConfig,
        observability::metric::{ServerMetric, XgressId, XgressIdKind, XgressMetric},
        TngBuilder,
    };
    use axum::{extract::State, routing::post, Json, Router};
    use http::StatusCode;
    use scopeguard::defer;
    use serde_json::json;
    use tokio::{net::TcpListener, select};
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[test]
    fn test_deserialize() -> Result<()> {
        let json_value = json!(
            {
                "endpoint": "c3-op-mon-falcon01.bj",
                "metric": "qps",
                "timestamp": 1551264402,
                "step": 60,
                "value": 1,
                "counterType": "GAUGE",
                "tags": "idc=lg,loc=beijing,pdl=falcon"
            }
        );

        let metric_value = FalconMetric {
            endpoint: "c3-op-mon-falcon01.bj".to_owned(),
            metric: "qps".to_owned(),
            value: 1.into(),
            step: 60,
            counter_type: FalconCounterType::Gauge,
            tags: [
                ("idc".to_owned(), "lg".to_owned()),
                ("loc".to_owned(), "beijing".to_owned()),
                ("pdl".to_owned(), "falcon".to_owned()),
            ]
            .into(),
            timestamp: 1551264402,
        };

        let serialized = serde_json::to_value(metric_value)?;

        assert_eq!(json_value, serialized);

        Ok(())
    }

    #[test]
    fn test_construct_metric_body() -> Result<()> {
        let timestamp = 1741678004;

        let falcon_config = FalconConfig {
            server_url: "http://127.0.0.1:1988".to_owned(),
            endpoint: "master-node".to_owned(),
            tags: [
                ("namespace".to_owned(), "ns1".to_owned()),
                ("app".to_owned(), "tng".to_owned()),
            ]
            .into(),
            step: 60,
        };

        // Setup an exporter
        let exporter = FalconExporter::new(falcon_config)?;

        // Construct a server metric
        let mut falcon_metric = exporter.construct_metric(ServerMetric::Live, 1.into())?;
        assert!(falcon_metric.timestamp > 0);
        falcon_metric.timestamp = timestamp; // Let's ignore the timestamp difference

        assert_eq!(
            serde_json::to_value(falcon_metric)?,
            json!(
                {
                    "endpoint": "master-node",
                    "metric": "live",
                    "timestamp": timestamp,
                    "step": 60,
                    "value": 1,
                    "counterType": "GAUGE",
                    "tags": "namespace=ns1,app=tng"
                }
            )
        );

        // Construct a xgress metric
        let mut falcon_metric = exporter.construct_metric(
            (
                XgressId {
                    kind: XgressIdKind::Ingress { id: 10 },
                    meta_data: [("ingress_id".to_string(), "10".to_string())].into(),
                },
                XgressMetric::RxBytesTotal,
            ),
            256.into(),
        )?;
        assert!(falcon_metric.timestamp > 0);
        falcon_metric.timestamp = timestamp; // Let's ignore the timestamp difference

        assert_eq!(
            serde_json::to_value(falcon_metric)?,
            json!(
                {
                    "endpoint": "master-node",
                    "metric": "rx_bytes_total",
                    "timestamp": timestamp,
                    "step": 60,
                    "value": 256,
                    "counterType": "COUNTER",
                    "tags": "namespace=ns1,app=tng,ingress_id=10"
                }
            )
        );

        // Construct a xgress metric
        let mut falcon_metric = exporter.construct_metric(
            (
                XgressId {
                    kind: XgressIdKind::Ingress { id: 5 },
                    meta_data: [("ingress_id".to_string(), "5".to_string())].into(),
                },
                XgressMetric::CxActive,
            ),
            20.into(),
        )?;
        assert!(falcon_metric.timestamp > 0);
        falcon_metric.timestamp = timestamp; // Let's ignore the timestamp difference

        assert_eq!(
            serde_json::to_value(falcon_metric)?,
            json!(
                {
                    "endpoint": "master-node",
                    "metric": "cx_active",
                    "timestamp": timestamp,
                    "step": 60,
                    "value": 20,
                    "counterType": "GAUGE",
                    "tags": "namespace=ns1,app=tng,ingress_id=5"
                }
            )
        );

        Ok(())
    }

    pub async fn launch_fake_falcon_server(port: u16) -> tokio::sync::mpsc::UnboundedReceiver<()> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            async fn handler(
                State(tx): State<tokio::sync::mpsc::UnboundedSender<()>>,
                Json(payload): Json<serde_json::Value>,
            ) -> Result<(StatusCode, std::string::String), ()> {
                assert!(payload.is_array());
                payload.as_array().unwrap().iter().for_each(|item| {
                    assert!(item.is_object());
                    let item = item.as_object().unwrap();
                    assert!(item.contains_key("counterType"))
                });

                let _ = tx.send(());

                Ok((StatusCode::OK, "".into()))
            }
            let app = Router::new()
                .route("/{*path}", post(handler))
                .with_state(tx);
            let server = axum::serve(listener, app);
            server.await
        });

        rx
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_exporter() -> Result<()> {
        let port = portpicker::pick_unused_port().unwrap();

        let mut rx = launch_fake_falcon_server(port).await;

        let config: TngConfig = serde_json::from_value(json!(
            {
                "metric": {
                    "exporters": [{
                        "type": "falcon",
                        "server_url": format!("http://127.0.0.1:{port}"),
                        "endpoint": "master-node",
                        "tags": {
                            "namespace": "ns1",
                            "app": "tng-client"
                        },
                        "step": 1
                    }]
                },
                "add_ingress": [
                    {
                        "mapping": {
                            "in": {
                                "port": 10001
                            },
                            "out": {
                                "host": "127.0.0.1",
                                "port": 30001
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
            TngBuilder::from_config(config)
                .serve_with_cancel(cancel_token_clone, ready_sender)
                .await
        });

        ready_receiver.await?;
        // tng is ready now, wait a while for exporter to send data

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        cancel_token.cancel();

        // At least get metrics two times
        assert_eq!(rx.try_recv(), Ok(()));
        assert_eq!(rx.try_recv(), Ok(()));

        select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                defer! {
                    std::process::exit(1);
                }
                panic!("Wait for tng exit timeout")
            }
            _ = join_handle => {}
        }

        Ok(())
    }
}
