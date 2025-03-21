use super::metric::{Metric, MetricValue};
use anyhow::Result;
use async_trait::async_trait;

pub mod falcon;
pub mod stdout;

#[async_trait]
pub trait MetricExporter {
    async fn push(&self, metric_and_values: &[(Box<dyn Metric + '_>, MetricValue)]) -> Result<()>;
}

#[async_trait]
impl<F> MetricExporter for F
where
    /* use `'_` here to enable "lifetime elision rules" */
    F: Fn(&[(Box<dyn Metric + '_>, MetricValue)]) -> Result<()> + std::marker::Sync,
{
    async fn push(&self, metric_and_values: &[(Box<dyn Metric + '_>, MetricValue)]) -> Result<()> {
        self(metric_and_values)
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use crate::{
        config::{metric::ExportorType, TngConfig},
        TngBuilder,
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

        config
            .metric
            .as_mut()
            .unwrap()
            .exporters
            .push(ExportorType::Mock {
                step: 1,
                exporter: Arc::new(
                    move |_metric_and_values: &[(Box<dyn Metric + '_>, serde_json::Number)]| {
                        let _ = tx.send(());
                        Ok(())
                    },
                ),
            });

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
