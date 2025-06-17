use std::time::Duration;

use again::RetryPolicy;
use anyhow::{bail, Result};
use http::StatusCode;
use reqwest::header::HOST;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::task::app::HTTP_RESPONSE_BODY;

use super::HttpProxy;

pub enum HttpClientMode {
    NoProxy {
        host: String,
        port: u16,
    },
    /// In this case, the http `Host` header is used to indicate the server to proxy to.
    ProxyWithReverseMode {
        http_proxy: HttpProxy,
    },
}

pub async fn launch_http_client_common(
    token: CancellationToken,
    host_header: &str,
    path_and_query: &str,
    client_mode: HttpClientMode,
) -> Result<JoinHandle<Result<()>>> {
    let host_header = host_header.to_owned();

    assert!(path_and_query.starts_with('/'));
    let path_and_query = path_and_query.to_owned();

    Ok(tokio::task::spawn(async move {
        let _drop_guard = token.drop_guard();

        for i in 1..6 {
            // repeat 5 times
            match &client_mode {
                HttpClientMode::NoProxy { host, port } => {
                    tracing::info!(
                        "HTTP client test repeat {i}, sending http request to {host}:{port} without proxy"
                    );
                }
                HttpClientMode::ProxyWithReverseMode { http_proxy } => {
                    tracing::info!(
                        "HTTP client test repeat {i}, sending http request to host {host_header} with proxy {http_proxy:?} in reverse proxy mode"
                    );
                }
            }

            let resp = RetryPolicy::fixed(Duration::from_secs(1))
                .with_max_retries(5)
                .retry(|| async {
                    let mut builder = reqwest::Client::builder();

                    // TODO: add test for send http proxy via both http-connect and http-reverse-proxy
                    match &client_mode {
                        HttpClientMode::NoProxy { .. } => { /* Nothing */ }
                        HttpClientMode::ProxyWithReverseMode { http_proxy } => {
                            let proxy = reqwest::Proxy::http(format!(
                                "http://{}:{}",
                                http_proxy.host, http_proxy.port
                            ))?;
                            builder = builder.proxy(proxy);
                        }
                    }

                    let url = match &client_mode {
                        HttpClientMode::NoProxy { host, port } => {
                            format!("http://{host}:{port}{path_and_query}")
                        }
                        HttpClientMode::ProxyWithReverseMode { .. } => {
                            format!("http://dummy{path_and_query}")
                        }
                    };

                    let client = builder.build()?;
                    client.get(url).header(HOST, &host_header).send().await
                })
                .await?;

            let status = resp.status();
            let resp_info = format!("{resp:?}");
            let text = resp.text().await?;

            if status != StatusCode::OK {
                bail!(
                "The respose status should be {}, bot got {status}.\n\tBody text: {text}\n\tResponse: {resp_info}",
                StatusCode::OK
            )
            }

            if text != HTTP_RESPONSE_BODY {
                bail!("The response body should be `{HTTP_RESPONSE_BODY}`, but got `{text}`.\n\tResponse: {resp_info}")
            } else {
                tracing::info!("Success! The response matchs expected value");
            }
        }

        tracing::info!("The HTTP client task normally exit now");
        Ok(())
    }))
}
