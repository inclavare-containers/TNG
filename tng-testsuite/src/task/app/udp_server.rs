use anyhow::{Context as _, Result};
use tokio::{net::UdpSocket, task::JoinHandle};
use tokio_util::sync::CancellationToken;

pub async fn launch_udp_server(
    token: CancellationToken,
    port: u16,
) -> Result<JoinHandle<Result<()>>> {
    // Bind plainly (no SO_REUSEADDR) so this server behaves like a real
    // backend that did not set SO_REUSEADDR. The netfilter_udp egress replies
    // via a SOCK_RAW + IP_HDRINCL socket (no bind), so it never competes for
    // this port — the test must pass without any SO_REUSEADDR workaround.
    let addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let socket = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("Failed to bind UDP server socket on {addr}"))?;
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
                    tracing::info!("UDP server received {} bytes from {}, echo back now", n, src_addr);
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
