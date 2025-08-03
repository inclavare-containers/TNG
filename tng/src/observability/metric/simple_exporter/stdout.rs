use anyhow::Result;
use async_trait::async_trait;

use super::SimpleMetric;

use super::SimpleMetricExporter;

pub struct StdoutExporter {}

impl StdoutExporter {}

#[async_trait]
impl SimpleMetricExporter for StdoutExporter {
    async fn push(&self, metrics: &[SimpleMetric]) -> Result<()> {
        tracing::info!("current metrics: {metrics:?}",);
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::{config::TngConfig, runtime::TngRuntime};
    use scopeguard::defer;
    use serde_json::json;
    use tokio::select;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_exporter() -> Result<()> {
        let config: TngConfig = serde_json::from_value(json!(
            {
                "metric": {
                    "exporters": [{
                        "type": "stdout",
                        "step": 1
                    }]
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

        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();

        let tng_runtime = TngRuntime::from_config(config).await?;
        let canceller = tng_runtime.canceller();

        let join_handle =
            tokio::task::spawn(async move { tng_runtime.serve_with_ready(ready_sender).await });

        ready_receiver.await?;
        // tng is ready now, wait a while for exporter to send data

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        canceller.cancel();

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
