use std::{
    collections::HashMap,
    sync::atomic,
    time::{Duration, UNIX_EPOCH},
};

use again::RetryPolicy;
use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

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
    is_shutdown: atomic::AtomicBool,
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
            is_shutdown: atomic::AtomicBool::new(false),
        })
    }

    pub async fn push_to_server(
        &self,
        metrics: &mut opentelemetry_sdk::metrics::data::ResourceMetrics,
    ) -> Result<()> {
        let falcon_metrics = self.construct_metrics(metrics)?;

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

    fn construct_metrics(
        &self,
        metrics: &mut opentelemetry_sdk::metrics::data::ResourceMetrics,
    ) -> Result<Vec<FalconMetric>> {
        let mut falcon_metrics = vec![];

        let mut attrs = HashMap::new();

        if let Some(schema_url) = metrics.resource.schema_url() {
            attrs.insert("otel.resource.schema_url".to_owned(), schema_url.to_owned());
        }

        metrics.resource.iter().for_each(|(k, v)| {
            attrs.insert(k.to_string(), v.to_string());
        });

        for scope_metrics in &metrics.scope_metrics {
            let mut attrs = attrs.clone();

            attrs.insert(
                "otel.scope.name".to_owned(),
                scope_metrics.scope.name().to_owned(),
            );

            if let Some(version) = scope_metrics.scope.version() {
                attrs.insert("otel.scope.version".to_owned(), version.to_owned());
            }

            if let Some(schema_url) = scope_metrics.scope.schema_url() {
                attrs.insert("otel.scope.schema_url".to_owned(), schema_url.to_owned());
            }
            scope_metrics.scope.attributes().for_each(
                |opentelemetry::KeyValue { key, value, .. }| {
                    attrs.insert(key.to_string(), value.to_string());
                },
            );

            for metric in &scope_metrics.metrics {
                let value_and_time = {
                    let data = metric.data.as_any();
                    if let Some(sum) =
                        data.downcast_ref::<opentelemetry_sdk::metrics::data::Sum<u64>>()
                    {
                        match sum.data_points.last() {
                            Some(data_point) => Some((
                                serde_json::Number::from_u128(data_point.value as u128)
                                    .with_context(|| {
                                        format!(
                                            "Failed to convert num {} to json",
                                            data_point.value
                                        )
                                    })?,
                                sum.time,
                                FalconCounterType::Counter,
                                &data_point.attributes,
                            )),
                            None => None,
                        }
                    } else if let Some(sum) =
                        data.downcast_ref::<opentelemetry_sdk::metrics::data::Sum<i64>>()
                    {
                        match sum.data_points.last() {
                            Some(data_point) => Some((
                                serde_json::Number::from_i128(data_point.value as i128)
                                    .with_context(|| {
                                        format!(
                                            "Failed to convert num {} to json",
                                            data_point.value
                                        )
                                    })?,
                                sum.time,
                                FalconCounterType::Counter,
                                &data_point.attributes,
                            )),
                            None => None,
                        }
                    } else if let Some(sum) =
                        data.downcast_ref::<opentelemetry_sdk::metrics::data::Sum<f64>>()
                    {
                        match sum.data_points.last() {
                            Some(data_point) => Some((
                                serde_json::Number::from_f64(data_point.value as f64)
                                    .with_context(|| {
                                        format!(
                                            "Failed to convert num {} to json",
                                            data_point.value
                                        )
                                    })?,
                                sum.time,
                                FalconCounterType::Counter,
                                &data_point.attributes,
                            )),
                            None => None,
                        }
                    } else if let Some(gauge) =
                        data.downcast_ref::<opentelemetry_sdk::metrics::data::Gauge<u64>>()
                    {
                        match gauge.data_points.last() {
                            Some(data_point) => Some((
                                serde_json::Number::from_u128(data_point.value as u128)
                                    .with_context(|| {
                                        format!(
                                            "Failed to convert num {} to json",
                                            data_point.value
                                        )
                                    })?,
                                gauge.time,
                                FalconCounterType::Gauge,
                                &data_point.attributes,
                            )),
                            None => None,
                        }
                    } else if let Some(gauge) =
                        data.downcast_ref::<opentelemetry_sdk::metrics::data::Gauge<i64>>()
                    {
                        match gauge.data_points.last() {
                            Some(data_point) => Some((
                                serde_json::Number::from_i128(data_point.value as i128)
                                    .with_context(|| {
                                        format!(
                                            "Failed to convert num {} to json",
                                            data_point.value
                                        )
                                    })?,
                                gauge.time,
                                FalconCounterType::Gauge,
                                &data_point.attributes,
                            )),
                            None => None,
                        }
                    } else if let Some(gauge) =
                        data.downcast_ref::<opentelemetry_sdk::metrics::data::Gauge<f64>>()
                    {
                        match gauge.data_points.last() {
                            Some(data_point) => Some((
                                serde_json::Number::from_f64(data_point.value as f64)
                                    .with_context(|| {
                                        format!(
                                            "Failed to convert num {} to json",
                                            data_point.value
                                        )
                                    })?,
                                gauge.time,
                                FalconCounterType::Gauge,
                                &data_point.attributes,
                            )),
                            None => None,
                        }
                    } else {
                        bail!("Unsupported data type");
                    }
                };

                if let Some((value, time, counter_type, attributes)) = value_and_time {
                    let mut attrs = attrs.clone();

                    attributes
                        .iter()
                        .for_each(|opentelemetry::KeyValue { key, value, .. }| {
                            attrs.insert(key.to_string(), value.to_string());
                        });

                    falcon_metrics.push(FalconMetric {
                        endpoint: self.falcon_config.endpoint.clone(),
                        metric: metric.name.to_string(),
                        value,
                        step: self.falcon_config.step,
                        counter_type,
                        tags: {
                            let mut tags = self.falcon_config.tags.clone();
                            tags.extend(attrs);
                            tags.into()
                        },
                        timestamp: time
                            .duration_since(UNIX_EPOCH)
                            .context("System time is before unix epoch")?
                            .as_secs(),
                    });
                }
            }
        }

        Ok(falcon_metrics)
    }
}

impl opentelemetry_sdk::metrics::exporter::PushMetricExporter for FalconExporter {
    async fn export(
        &self,
        metrics: &mut opentelemetry_sdk::metrics::data::ResourceMetrics,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        if self.is_shutdown.load(atomic::Ordering::SeqCst) {
            Err(opentelemetry_sdk::error::OTelSdkError::AlreadyShutdown)
        } else {
            self.push_to_server(metrics).await.map_err(|e| {
                opentelemetry_sdk::error::OTelSdkError::InternalFailure(format!("{e:#}"))
            })
        }
    }

    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        // exporter holds no state, nothing to flush
        Ok(())
    }

    fn shutdown(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        self.is_shutdown.store(true, atomic::Ordering::SeqCst);
        Ok(())
    }

    fn temporality(&self) -> opentelemetry_sdk::metrics::Temporality {
        opentelemetry_sdk::metrics::Temporality::Cumulative
    }
}
