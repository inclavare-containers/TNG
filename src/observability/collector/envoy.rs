use anyhow::{Context as _, Result};
use const_format::formatcp;
use indexmap::IndexMap;
use itertools::Itertools;
use log::{error, info};
use serde::Deserialize;
use serde_json::Number;
use strum::IntoEnumIterator;
use tokio::select;
use tokio_graceful::ShutdownGuard;

use crate::observability::{
    exporter::falcon::FalconExporter,
    metric::{Metric, MetricValue, ServerMetric, XgressId, XgressMetric},
};

pub const METRIC_COLLECTOR_STEP_DEFAULT: u64 = 60;

pub struct MetricCollector {
    envoy_admin_endpoint: (String /* host */, u16 /* port */),

    step: u64,

    server_metric_parser: Box<dyn MetricParser<ServerMetric> + Send + Sync>,

    xgress_metric_parsers: IndexMap<XgressId, Box<dyn MetricParser<XgressMetric> + Send + Sync>>,

    metric_exporter: Option<FalconExporter>,
}

pub type EnvoyStats = IndexMap<String, Number>;

pub trait MetricParser<T> {
    fn parse(&self, envoy_stats: &EnvoyStats, metric_name: T) -> Result<MetricValue>;
}

impl<F: Fn(&EnvoyStats, T) -> Result<MetricValue>, T> MetricParser<T> for F {
    fn parse(&self, envoy_stats: &EnvoyStats, metric_name: T) -> Result<MetricValue> {
        self(envoy_stats, metric_name)
    }
}

const ENVOY_STATS_SERVER_LIVE: &str = "server.live";

impl MetricCollector {
    pub fn new(envoy_admin_endpoint: (String /* host */, u16 /* port */), step: u64) -> Self {
        Self {
            envoy_admin_endpoint,
            step,
            server_metric_parser: Box::new(
                |envoy_stats: &EnvoyStats, metric_name| match metric_name {
                    ServerMetric::Live => {
                        let value = envoy_stats
                            .get(ENVOY_STATS_SERVER_LIVE)
                            .context(formatcp!(
                                "No field {ENVOY_STATS_SERVER_LIVE} in envoy stats"
                            ))?
                            .as_u64();

                        Ok(MetricValue::from(if value == Some(1) { 1 } else { 0 }))
                    }
                },
            ),
            xgress_metric_parsers: Default::default(),
            metric_exporter: None,
        }
    }

    pub fn register_xgress_metric_parser(
        &mut self,
        xgress_id: XgressId,
        parser: impl MetricParser<XgressMetric> + Send + Sync + 'static,
    ) {
        self.xgress_metric_parsers
            .insert(xgress_id, Box::new(parser));
    }

    pub fn register_metric_exporter(&mut self, metric_exporter: FalconExporter) {
        self.metric_exporter = Some(metric_exporter)
    }

    pub async fn serve(self, shutdown_guard: ShutdownGuard) -> Result<()> {
        info!("Metric collector launch");

        // TODO: restart if the collector is failed
        select! {
            _ = shutdown_guard.cancelled() => {}
            () = self.collect_and_report() => {},
        }

        info!("Metric collector exit now");

        Ok(())
    }

    async fn collect_and_report(&self) {
        if let Some(metric_exporter) = &self.metric_exporter {
            let url = format!(
                "http://{}:{}/stats?filter=&format=json&type=All&histogram_buckets=cumulative",
                self.envoy_admin_endpoint.0, self.envoy_admin_endpoint.1
            );

            let client = reqwest::Client::new();

            loop {
                let envoy_stats = async {
                    // TODO: capture error in loop
                    let response = client.get(&url).send().await?;
                    let text = response.text().await?;

                    let envoy_stats: EnvoyStats = serde_json::from_str::<EnvoyStatsJson>(&text)
                        .map(Into::into)
                        .with_context(|| {
                            format!(
                            "Failed to parse envoy stats from response, orignal response: {text}"
                        )
                        })?;

                    Ok::<_, anyhow::Error>(envoy_stats)
                }
                .await
                .context("Failed to collect envoy stats");

                match envoy_stats {
                    Ok(envoy_stats) => {
                        // Export server metric
                        let futures1 = ServerMetric::iter().map(|metric| {
                            let envoy_stats = &envoy_stats;
                            async move {
                                let metric_value = self
                                    .server_metric_parser
                                    .parse(&envoy_stats, metric)
                                    .with_context(|| {
                                        format!("failed to get metric value for {}", metric.name())
                                    })?;

                                metric_exporter
                                    .push(metric, metric_value)
                                    .await
                                    .with_context(|| {
                                        format!("Failed to push metric value for {}", metric.name())
                                    })?;

                                Ok::<_, anyhow::Error>(())
                            }
                        });

                        let futures2 = self
                            .xgress_metric_parsers
                            .iter()
                            .cartesian_product(XgressMetric::iter())
                            .map(|((xgress_id, parser), xgress_metric)| {
                                let envoy_stats = &envoy_stats;
                                async move {
                                    let metric = (*xgress_id, xgress_metric);
                                    let metric_value = parser
                                        .parse(&envoy_stats, xgress_metric)
                                        .with_context(|| {
                                            format!(
                                                "failed to get metric value for {}",
                                                metric.name()
                                            )
                                        })?;

                                    metric_exporter
                                        .push(metric, metric_value)
                                        .await
                                        .with_context(|| {
                                            format!(
                                                "Failed to push metric value for {}",
                                                metric.name()
                                            )
                                        })?;

                                    Ok::<_, anyhow::Error>(())
                                }
                            });

                        let (res1, res2) = futures::future::join(
                            futures::future::join_all(futures1),
                            futures::future::join_all(futures2),
                        )
                        .await;

                        res1.into_iter().chain(res2).for_each(|res| {
                            if let Err(e) = res {
                                error!("{e:#}")
                            }
                        });
                    }
                    Err(e) => {
                        error!("{e:#}")
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(self.step)).await;
            }
        } else {
            info!("No metric exporter registered, stop metric collector now");
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnvoyStatsJson {
    // #[serde(flatten)]
    stats: Vec<EnvoyStatsItemJson>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum EnvoyStatsItemJson {
    NumberedStats {
        name: String,
        value: Number,
    },
    HistogramStats {
        #[serde(flatten)]
        _unknow_fields_: serde_json::Value,
    },
}

impl From<EnvoyStatsJson> for EnvoyStats {
    fn from(value: EnvoyStatsJson) -> Self {
        value
            .stats
            .into_iter()
            .filter_map(|item| match item {
                EnvoyStatsItemJson::NumberedStats { name, value } => Some((name, value)),
                EnvoyStatsItemJson::HistogramStats { _unknow_fields_ } => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_deserialize_envoy_stats() -> Result<()> {
        let envoy_stats_str = include_str!("./test_data/envoy_stats.json");

        let envoy_stats_json: EnvoyStatsJson = serde_json::from_str(envoy_stats_str)?;
        assert!(envoy_stats_json.stats.len() > 0);

        let envoy_stats: EnvoyStats = envoy_stats_json.into();
        assert!(envoy_stats.len() > 0);

        Ok(())
    }
}
