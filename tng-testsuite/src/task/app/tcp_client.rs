use anyhow::{anyhow, bail, Context as _, Result};
use async_http_proxy::http_connect_tokio;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::task::app::TCP_PAYLOAD;

use super::HttpProxy;

pub async fn launch_tcp_client(
    token: CancellationToken,
    host: &str,
    port: u16,
    http_proxy: Option<HttpProxy>,
) -> Result<JoinHandle<Result<()>>> {
    let host = host.to_owned();
    Ok(tokio::task::spawn(async move {
        let _drop_guard = token.drop_guard();

        for i in 1..6 {
            // repeat 5 times
            tracing::info!(
                "TCP client test repeat {i}, connecting to TCP server at {}:{}",
                host,
                port
            );

            let connect_task = async {
                Ok(match &http_proxy {
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
                })
            };

            let mut stream = tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    Err(anyhow!("The TCP client task timed out"))
                }
                result = connect_task => result,
            }?;

            tracing::info!("Connected to the server");

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
                tracing::info!("Success! The response matchs expected value");
            }
        }

        tracing::info!("The TCP client task normally exited");
        Ok(())
    }))
}
