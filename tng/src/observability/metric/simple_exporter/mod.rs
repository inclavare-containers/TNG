use std::{
    sync::{atomic, Arc},
    time::SystemTime,
};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use indexmap::IndexMap;

pub mod falcon;
pub mod noop;
pub mod opentelemetry_metric_reader;
pub mod stdout;

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum ValueType {
    Counter,
    Gauge,
}

type MetricValue = serde_json::Number;

#[derive(Debug, PartialEq)]
pub struct SimpleMetric {
    pub name: String,

    pub value: MetricValue,

    pub value_type: ValueType,

    pub attributes: IndexMap<String, String>,

    pub time: SystemTime,
}

#[async_trait]
/// A simple metric exporter for exporting metrics to other place. This trait is a simplified
/// version of opentelemetry rust exporter and it is designed to be used with
/// OpenTelemetryMetricExporterAdapter.
pub trait SimpleMetricExporter {
    async fn push(&self, metrics: &[SimpleMetric]) -> Result<()>;
}

#[async_trait]
impl<F> SimpleMetricExporter for F
where
    F: Fn(&[SimpleMetric]) -> Result<()> + std::marker::Sync,
{
    async fn push(&self, metrics: &[SimpleMetric]) -> Result<()> {
        self(metrics)
    }
}

#[async_trait]
impl SimpleMetricExporter for Arc<dyn SimpleMetricExporter + Send + Sync + 'static> {
    async fn push(&self, metrics: &[SimpleMetric]) -> Result<()> {
        self.as_ref().push(metrics).await
    }
}

pub struct OpenTelemetryMetricExporterAdapter<T: SimpleMetricExporter> {
    inner: T,
    is_shutdown: atomic::AtomicBool,
}

impl<T: SimpleMetricExporter> OpenTelemetryMetricExporterAdapter<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            is_shutdown: atomic::AtomicBool::new(false),
        }
    }

    fn convert_to_simple_metrics(
        &self,
        metrics: &mut opentelemetry_sdk::metrics::data::ResourceMetrics,
    ) -> Result<Vec<SimpleMetric>> {
        let mut out_metrics = vec![];

        for scope_metrics in &metrics.scope_metrics {
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
                                ValueType::Counter,
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
                                ValueType::Counter,
                                &data_point.attributes,
                            )),
                            None => None,
                        }
                    } else if let Some(sum) =
                        data.downcast_ref::<opentelemetry_sdk::metrics::data::Sum<f64>>()
                    {
                        match sum.data_points.last() {
                            Some(data_point) => Some((
                                serde_json::Number::from_f64(data_point.value).with_context(
                                    || {
                                        format!(
                                            "Failed to convert num {} to json",
                                            data_point.value
                                        )
                                    },
                                )?,
                                sum.time,
                                ValueType::Counter,
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
                                ValueType::Gauge,
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
                                ValueType::Gauge,
                                &data_point.attributes,
                            )),
                            None => None,
                        }
                    } else if let Some(gauge) =
                        data.downcast_ref::<opentelemetry_sdk::metrics::data::Gauge<f64>>()
                    {
                        match gauge.data_points.last() {
                            Some(data_point) => Some((
                                serde_json::Number::from_f64(data_point.value).with_context(
                                    || {
                                        format!(
                                            "Failed to convert num {} to json",
                                            data_point.value
                                        )
                                    },
                                )?,
                                gauge.time,
                                ValueType::Gauge,
                                &data_point.attributes,
                            )),
                            None => None,
                        }
                    } else {
                        bail!("Unsupported data type");
                    }
                };

                if let Some((value, time, value_type, attributes)) = value_and_time {
                    let mut attrs = IndexMap::new();

                    attributes
                        .iter()
                        .for_each(|opentelemetry::KeyValue { key, value, .. }| {
                            attrs.insert(key.to_string(), value.to_string());
                        });

                    out_metrics.push(SimpleMetric {
                        name: metric.name.to_string(),
                        value,
                        value_type,
                        attributes: attrs,
                        time,
                    });
                }
            }
        }

        Ok(out_metrics)
    }
}

impl<T: SimpleMetricExporter + std::marker::Sync + std::marker::Send + 'static>
    opentelemetry_sdk::metrics::exporter::PushMetricExporter
    for OpenTelemetryMetricExporterAdapter<T>
{
    async fn export(
        &self,
        metrics: &mut opentelemetry_sdk::metrics::data::ResourceMetrics,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        if self.is_shutdown.load(atomic::Ordering::SeqCst) {
            Err(opentelemetry_sdk::error::OTelSdkError::AlreadyShutdown)
        } else {
            async {
                let simple_metrics = self.convert_to_simple_metrics(metrics)?;
                self.inner.push(&simple_metrics).await
            }
            .await
            .map_err(|e| opentelemetry_sdk::error::OTelSdkError::InternalFailure(format!("{e:#}")))
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

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use crate::{
        config::{observability::metric::MetricExporterType, TngConfig},
        runtime::TngRuntime,
    };
    use scopeguard::defer;
    use serde_json::json;
    use tokio::select;
    use tokio_util::sync::CancellationToken;

    use super::*;
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_exporter() -> Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let mut config: TngConfig = serde_json::from_value(json!(
            {
                "metric": {
                    "exporters": []
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

        config
            .metric
            .as_mut()
            .unwrap()
            .exporters
            .push(MetricExporterType::Mock {
                step: 1,
                exporter: Arc::new(move |_metric_and_values: &[SimpleMetric]| {
                    let _ = tx.send(());
                    Ok(())
                }),
            });

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
