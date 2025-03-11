use std::time::{Duration, SystemTime, UNIX_EPOCH};

use again::RetryPolicy;
use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::observability::metric::{Metric, MetricValue, ValueType};

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
    pub tags: IndexMap<String, String>,
    pub step: u64,
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
                .user_agent(APP_USER_AGENT)
                .build()?,
        })
    }

    pub async fn push(&self, metric: impl Metric, value: MetricValue) -> Result<()> {
        let falcon_metric = self.construct_metric(metric, value)?;

        RetryPolicy::fixed(Duration::from_secs(1))
            .with_max_retries(MAX_PUSH_RETRY - 1)
            .retry(|| async {
                let res = self
                    .client
                    .post(format!("{}/v1/push", self.falcon_config.server_url))
                    .json(&falcon_metric)
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

#[cfg(test)]
mod tests {

    use serde_json::json;

    use crate::observability::metric::{ServerMetric, XgressId, XgressMetric};

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
            (XgressId::Ingress { id: 10 }, XgressMetric::RxBytesTotal),
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
                    "tags": "namespace=ns1,app=tng,type=ingress,id=10"
                }
            )
        );

        // Construct a xgress metric
        let mut falcon_metric = exporter.construct_metric(
            (XgressId::Ingress { id: 5 }, XgressMetric::CxActive),
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
                    "tags": "namespace=ns1,app=tng,type=ingress,id=5"
                }
            )
        );

        Ok(())
    }
}
