use std::{net::SocketAddr, time::Duration};

use again::RetryPolicy;
use anyhow::{bail, Context as _, Result};
use async_http_proxy::http_connect_tokio;
use axum::{body::Body, extract::Request, routing::get, Router};
use axum_extra::extract::Host;
use http::StatusCode;
use log::info;
use reqwest::header::HOST;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const TCP_PAYLOAD: &str = "Hello World TCP!";
const HTTP_RESPONSE_BODY: &str = "Hello World HTTP!";

pub enum AppType {
    #[allow(dead_code)]
    HttpServer {
        port: u16,
        expected_host_header: &'static str,
        expected_path_and_query: &'static str,
    },
    #[allow(dead_code)]
    HttpClient {
        host: &'static str,
        port: u16,
        host_header: &'static str,
        path_and_query: &'static str,
        http_proxy: Option<HttpProxy>,
    },
    #[allow(dead_code)]
    TcpServer { port: u16 },
    #[allow(dead_code)]
    TcpClient {
        host: &'static str,
        port: u16,
        http_proxy: Option<HttpProxy>,
    },
}

impl AppType {
    pub async fn launch(&self, token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
        match *self {
            AppType::HttpServer {
                port,
                expected_host_header,
                expected_path_and_query,
            } => {
                launch_http_server(token, port, expected_host_header, expected_path_and_query).await
            }
            AppType::HttpClient {
                host,
                port,
                host_header,
                path_and_query,
                http_proxy,
            } => {
                launch_http_client(token, host, port, host_header, path_and_query, http_proxy).await
            }
            AppType::TcpServer { port } => launch_tcp_server(token, port).await,
            AppType::TcpClient {
                host,
                port,
                http_proxy,
            } => launch_tcp_client(token, host, port, http_proxy).await,
        }
    }
}

#[derive(Clone, Copy)]
pub struct HttpProxy {
    pub host: &'static str,
    pub port: u16,
}

async fn launch_tcp_server(token: CancellationToken, port: u16) -> Result<JoinHandle<Result<()>>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;
    info!("TCP server listening on 127.0.0.1:{port}");

    Ok(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                result = listener.accept() => {
                    let (mut stream, addr) = result?;
                    info!("Accepted connection from {}", addr);

                    let mut buffer = [0; 512];
                    while let Ok(size) = stream.read(&mut buffer).await {
                        if size == 0 {
                            return Ok(());
                        }
                        stream
                            .write_all(&buffer[0..size])
                            .await
                            .context("Failed to write back data")?;
                    }
                }
            }
        }
        info!("The TCP server task normally exited.");
        Ok(())
    }))
}

async fn launch_tcp_client(
    token: CancellationToken,
    host: &str,
    port: u16,
    http_proxy: Option<HttpProxy>,
) -> Result<JoinHandle<Result<()>>> {
    let host = host.to_owned();
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();

        for i in 1..6 {
            // repeat 5 times
            info!(
                "TCP client test repeat {i}, connecting to TCP server at {}:{}",
                host, port
            );

            let mut stream = match http_proxy {
                Some(http_proxy) => {
                    let mut stream =
                        TcpStream::connect(format!("{}:{}", http_proxy.host, http_proxy.port))
                            .await
                            .context("Failed to connect to http proxy server")?;
                    http_connect_tokio(&mut stream, &host, port)
                        .await
                        .context("Failed to connect to app server via http proxy server")?;
                    stream
                }
                None => TcpStream::connect(format!("{}:{}", host, port))
                    .await
                    .context("Failed to connect to app server")?,
            };
            info!("Connected to the server");

            let message = TCP_PAYLOAD.as_bytes();
            stream.write_all(message).await?;
            stream.shutdown().await?;

            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;

            if response != message {
                bail!(
                    "The response body should be `{TCP_PAYLOAD}`, but got `{}`",
                    String::from_utf8_lossy(&response)
                )
            } else {
                info!("Success! The response matchs expected value.");
            }
        }

        info!("The TCP client task normally exited.");
        Ok(())
    }))
}

pub async fn launch_http_server(
    token: CancellationToken,
    port: u16,
    expected_host_header: &str,
    expected_path_and_query: &str,
) -> Result<JoinHandle<Result<()>>> {
    let expected_host_header = expected_host_header.to_owned();
    let expected_path_and_query = expected_path_and_query.to_owned();

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on 127.0.0.1:{port} and waiting for connection from client");

    Ok(tokio::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            get(|Host(hostname): Host, request: Request<Body>| async move {
                (|| -> Result<_> {
                    if hostname != expected_host_header {
                        bail!("Got hostname `{hostname}`, but `{expected_host_header}` is expected");
                    }
                    let path_and_query = request.uri().path_and_query();
                    if path_and_query.map(|t| t.as_str()) != Some(&expected_path_and_query) {
                        bail!("Got path and query `{path_and_query:?}`, but `{expected_path_and_query}` is expected");
                    }

                    Ok((StatusCode::OK, HTTP_RESPONSE_BODY.to_owned()))
                })()
                .unwrap_or_else(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Something went wrong: {e}"),
                    )
                })
            }),
        );
        let server = axum::serve(listener, app);

        tokio::select! {
            _ = token.cancelled() => {}
            res = server => {
                res?;
            }
        }

        info!("The HTTP server task normally exit now");
        Ok(())
    }))
}

pub async fn launch_http_client(
    token: CancellationToken,
    host: &str,
    port: u16,
    host_header: &str,
    path_and_query: &str,
    http_proxy: Option<HttpProxy>,
) -> Result<JoinHandle<Result<()>>> {
    let host = host.to_owned();
    let host_header = host_header.to_owned();
    let path_and_query = path_and_query.to_owned();
    let http_proxy = http_proxy.map(|t| t.to_owned());

    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();

        for i in 1..6 {
            // repeat 5 times
            info!("HTTP client test repeat {i}, sending http request to {host}:{port}");
            let resp = RetryPolicy::fixed(Duration::from_secs(1))
                .with_max_retries(5)
                .retry(|| async {
                    let mut builder = reqwest::Client::builder();

                    if let Some(http_proxy) = &http_proxy {
                        let proxy = reqwest::Proxy::http(format!(
                            "http://{}:{}",
                            http_proxy.host, http_proxy.port
                        ))?;
                        builder = builder.proxy(proxy);
                    }

                    let client = builder.build()?;
                    client
                        .get(format!("http:///{host}:{port}{path_and_query}"))
                        .header(HOST, &host_header)
                        .send()
                        .await
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
                info!("Success! The response matchs expected value.");
            }
        }

        info!("The HTTP client task normally exit now");
        Ok(())
    }))
}
