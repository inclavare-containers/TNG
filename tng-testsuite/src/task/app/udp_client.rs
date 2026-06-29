use anyhow::{bail, Context as _, Result};
use tokio::{net::UdpSocket, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use super::UDP_PAYLOAD;

pub async fn launch_udp_client(
    token: CancellationToken,
    host: &str,
    port: u16,
) -> Result<JoinHandle<Result<()>>> {
    let host = host.to_owned();
    Ok(tokio::task::spawn(async move {
        let _drop_guard = token.drop_guard();

        for i in 1..6 {
            // repeat 5 times
            tracing::info!(
                "UDP client test repeat {i}, connecting to UDP server at {}:{}",
                host,
                port
            );

            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket
                .connect(format!("{}:{}", host, port))
                .await
                .context("Failed to connect to UDP server")?;

            let message = UDP_PAYLOAD.as_bytes();
            socket.send(message).await?;

            let mut response = vec![0u8; 65535];
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.recv(&mut response),
            )
            .await
            .context("UDP client timed out waiting for response")?
            .context("Failed to receive response")?;

            let response = &response[..n];
            if response != message {
                bail!(
                    "The response should be `{UDP_PAYLOAD}`, but got `{}`",
                    String::from_utf8_lossy(response)
                );
            } else {
                tracing::info!("Success! The response matches expected value");
            }
        }

        tracing::info!("The UDP client task normally exited");
        Ok(())
    }))
}
