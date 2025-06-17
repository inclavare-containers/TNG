use std::net::SocketAddr;

use anyhow::{Context as _, Result};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

pub async fn launch_tcp_server(
    token: CancellationToken,
    port: u16,
) -> Result<JoinHandle<Result<()>>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("TCP server listening on 0.0.0.0:{port}");

    Ok(tokio::task::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    tracing::info!("The TCP server task cancelled");
                    break
                },
                result = listener.accept() => {
                    let (mut stream, addr) = result?;
                    tracing::info!("Accepted connection from {}", addr);

                    let mut buffer = [0; 512];
                    while let Ok(size) = stream.read(&mut buffer).await {
                        if size == 0 {
                            break;
                        }
                        stream
                            .write_all(&buffer[0..size])
                            .await
                            .context("Failed to write back data")?;
                    }
                }
            }
        }
        Ok(())
    }))
}
