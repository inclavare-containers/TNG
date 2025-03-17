use std::sync::Arc;

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

    pub fn has_metric_exporter(&self) -> bool {
        self.metric_exporter.is_some()
    }

    pub async fn serve(self, shutdown_guard: ShutdownGuard) -> Result<()> {
        if !self.has_metric_exporter() {
            info!("No metric exporter registered, metric disabled");
            return Ok(());
        }

        info!("Metric collector starting");

        let this = Arc::new(self);

        let fut = async {
            loop {
                let this = this.clone();
                let res = shutdown_guard
                    .spawn_task_fn(|shutdown_guard| async move {
                        select! {
                            _ = shutdown_guard.cancelled() => { return /* exit here */}
                            () = this.collect_and_report() => {},
                        }
                    })
                    .await;

                if let Err(e) = res {
                    info!("Metric collector exited unexpectedly with error: {e:#}");
                } else {
                    info!("Metric collector exited unexpectedly with no error");
                }

                // Sleep for a while to avoid restart too frequently
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                info!("Metric collector restarting")
            }
        };

        select! {
            _ = shutdown_guard.cancelled() => {}
            () = fut => {},
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
                        let iter1 = ServerMetric::iter().map(|metric| {
                            let metric_value = self
                                .server_metric_parser
                                .parse(&envoy_stats, metric)
                                .with_context(|| {
                                    format!(
                                        "failed to get metric value for {}, skip now",
                                        metric.name()
                                    )
                                })?;
                            Ok::<_, anyhow::Error>((
                                Box::new(metric) as Box<dyn Metric>,
                                metric_value,
                            ))
                        });

                        let iter2 = self
                            .xgress_metric_parsers
                            .iter()
                            .cartesian_product(XgressMetric::iter())
                            .map(|((xgress_id, parser), xgress_metric)| {
                                let metric = (xgress_id, xgress_metric);
                                let metric_value = parser
                                    .parse(&envoy_stats, xgress_metric)
                                    .with_context(|| {
                                        format!(
                                            "failed to get metric value for {}, skip now",
                                            metric.name()
                                        )
                                    })?;

                                Ok::<_, anyhow::Error>((
                                    Box::new(metric) as Box<dyn Metric>,
                                    metric_value,
                                ))
                            });

                        let mertic_and_values: Vec<_> = iter1
                            .chain(iter2)
                            .map_while(|r| match r {
                                Err(e) => {
                                    error!("{e:#}");
                                    None
                                }
                                Ok(v) => Some(v),
                            })
                            .collect();

                        let res = metric_exporter
                            .push(&mertic_and_values)
                            .await
                            .with_context(|| format!("Failed to push metric value"));

                        if let Err(e) = res {
                            error!("{e:#}")
                        }
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

    use anyhow::bail;
    use axum::{routing::get, Router};
    use http::StatusCode;
    use tokio::net::TcpListener;

    use crate::observability::{exporter::falcon::FalconConfig, metric::XgressIdKind};

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_collector_panic_restart() -> Result<()> {
        let localhost = "127.0.0.1";
        let port = portpicker::pick_unused_port().unwrap();

        // Fake envoy admin interface
        let listener = TcpListener::bind((localhost, port)).await.unwrap();
        tokio::spawn(async move {
            async fn handler() -> Result<(StatusCode, std::string::String), ()> {
                Ok((
                    StatusCode::OK,
                    include_str!("./test_data/envoy_stats.json").to_owned(),
                ))
            }
            let app = Router::new().route("/{*path}", get(handler));
            let server = axum::serve(listener, app);
            server.await
        });

        // Create metric collector
        let envoy_admin_endpoint = (localhost.to_string(), port);
        let mut metric_collector = MetricCollector::new(envoy_admin_endpoint.clone(), 60);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        metric_collector.register_xgress_metric_parser(
            XgressId {
                kind: XgressIdKind::Ingress { id: 0 },
                meta_data: Default::default(),
            },
            move |_: &_, _| {
                tx.send(()).unwrap();
                panic!("ignore this panic, which is expected")
            },
        );
        metric_collector.register_metric_exporter(
            FalconExporter::new(FalconConfig {
                server_url: "http://0.0.0.0:0".to_owned(),
                endpoint: "master-node".to_owned(),
                tags: [].into(),
                step: 60,
            })
            .unwrap(),
        );

        let shutdown = tokio_graceful::Shutdown::default();
        shutdown.spawn_task_fn(|shutdown_guard| async {
            metric_collector.serve(shutdown_guard).await.unwrap();
        });

        for _ in 0..2 {
            select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    bail!("The test is time out")
                }
                res = rx.recv() => {
                    if res != Some(()){
                        bail!("the xgress_metric_parser not triggered as expected")
                    }
                }
            }
        }

        Ok(())
    }
}
