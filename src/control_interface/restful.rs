use std::sync::Arc;

use anyhow::Result;
use axum::{routing::get, Router};
use http::StatusCode;

use crate::config::control_interface::RestfulArgs;

use super::ControlInterfaceCore;

pub struct RestfulControlInterface {
    args: RestfulArgs,
    core: Arc<ControlInterfaceCore>,
}

impl RestfulControlInterface {
    pub async fn new(args: RestfulArgs, core: Arc<ControlInterfaceCore>) -> Result<Self> {
        Ok(Self { args, core })
    }

    pub async fn serve(&self) -> Result<()> {
        // build our application with a route
        let app = Router::new()
            .route(
                "/livez",
                get({
                    let core = self.core.clone();
                    move || async move {
                        if core.livez().await {
                            (StatusCode::OK, "ok")
                        } else {
                            (StatusCode::SERVICE_UNAVAILABLE, "not ok")
                        }
                    }
                }),
            )
            .route(
                "/readyz",
                get({
                    let core = self.core.clone();
                    move || async move {
                        if core.readyz().await {
                            (StatusCode::OK, "ok")
                        } else {
                            (StatusCode::SERVICE_UNAVAILABLE, "not ok")
                        }
                    }
                }),
            );

        let addr = (
            self.args.address.host.as_deref().unwrap_or("0.0.0.0"),
            self.args.address.port,
        );
        tracing::info!(
            "Restful Control interface listening on http://{}:{}",
            addr.0,
            addr.1
        );
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        tracing::info!("Restful Control interface stopping");

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::{config::TngConfig, TngBuilder};
    use scopeguard::defer;
    use serde_json::json;
    use tokio::select;
    use tokio_util::sync::CancellationToken;

    use super::*;
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_control_interface() -> Result<()> {
        let config: TngConfig = serde_json::from_value(json!(
            {
                "control_interface": {
                    "restful": {
                        "host": "127.0.0.1",
                        "port": 50000
                    }
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

        // tng is ready now, lets check the healthness
        {
            let resp = reqwest::ClientBuilder::new()
                .no_proxy()
                .build()?
                .get("http://127.0.0.1:50000/livez")
                .send()
                .await?;
            assert!(resp.status() == StatusCode::OK);
        }

        {
            let resp = reqwest::ClientBuilder::new()
                .no_proxy()
                .build()?
                .get("http://127.0.0.1:50000/readyz")
                .send()
                .await?;

            if resp.status() != StatusCode::OK {
                // Wait more time
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                let resp = reqwest::ClientBuilder::new()
                    .no_proxy()
                    .build()?
                    .get("http://127.0.0.1:50000/readyz")
                    .send()
                    .await?;
                assert!(resp.status() == StatusCode::OK);
            }
        }
        // stop tng
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

        Ok(())
    }
}
