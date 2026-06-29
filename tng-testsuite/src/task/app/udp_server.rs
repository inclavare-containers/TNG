use anyhow::{Context as _, Result};
use tokio::{net::UdpSocket, task::JoinHandle};
use tokio_util::sync::CancellationToken;

pub async fn launch_udp_server(
    token: CancellationToken,
    port: u16,
) -> Result<JoinHandle<Result<()>>> {
    let addr = format!("0.0.0.0:{port}");
    let socket = UdpSocket::bind(&addr).await?;
    tracing::info!("UDP server listening on {addr}");

    Ok(tokio::task::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    tracing::info!("The UDP server task cancelled");
                    break;
                }
                result = socket.recv_from(&mut buf) => {
                    let (n, src_addr) = result?;
                    tracing::info!("UDP server received {} bytes from {}", n, src_addr);
                    socket
                        .send_to(&buf[..n], src_addr)
                        .await
                        .context("Failed to send back UDP datagram")?;
                }
            }
        }
        Ok(())
    }))
}
