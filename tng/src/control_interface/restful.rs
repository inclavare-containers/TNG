use std::{convert::Infallible, sync::Arc};

use anyhow::Result;
use axum::{routing::get, Router};
use http::{HeaderValue, StatusCode};
use tower::ServiceBuilder;

use crate::{config::control_interface::RestfulArgs, HTTP_RESPONSE_SERVER_HEADER};

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
            )
            .layer(ServiceBuilder::new().layer(axum::middleware::from_fn(add_server_header)));

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

async fn add_server_header(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, Infallible> {
    let mut res = next.run(req).await;
    res.headers_mut().insert(
        "Server",
        HeaderValue::from_static(HTTP_RESPONSE_SERVER_HEADER),
    );
    Ok(res)
}

#[cfg(test)]
mod tests {

    use crate::{config::TngConfig, runtime::TngRuntime};
    use scopeguard::defer;
    use serde_json::json;
    use tokio::select;

    use super::*;
    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_control_interface() -> Result<()> {
        let port = portpicker::pick_unused_port().unwrap();

        let config: TngConfig = serde_json::from_value(json!(
            {
                "control_interface": {
                    "restful": {
                        "host": "127.0.0.1",
                        "port": port
                    }
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

        #[allow(clippy::disallowed_methods)]
        let join_handle =
            tokio::task::spawn(async move { tng_runtime.serve_with_ready(ready_sender).await });

        ready_receiver.await?;

        // tng is ready now, lets check the healthness
        {
            let resp = reqwest::ClientBuilder::new()
                .no_proxy()
                .build()?
                .get(format!("http://127.0.0.1:{port}/livez"))
                .send()
                .await?;
            assert!(resp.status() == StatusCode::OK);
        }

        {
            let resp = reqwest::ClientBuilder::new()
                .no_proxy()
                .build()?
                .get(format!("http://127.0.0.1:{port}/readyz"))
                .send()
                .await?;

            if resp.status() != StatusCode::OK {
                // Wait more time
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                let resp = reqwest::ClientBuilder::new()
                    .no_proxy()
                    .build()?
                    .get(format!("http://127.0.0.1:{port}/readyz"))
                    .send()
                    .await?;
                assert!(resp.status() == StatusCode::OK);
            }
        }
        // stop tng
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
