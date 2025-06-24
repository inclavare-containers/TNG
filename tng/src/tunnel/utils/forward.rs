use anyhow::{Context, Result};

// The default buffer size used in tokio::io::copy_bidirectional is 8 KB, here we increase it to 32 KB to improve the performance.
const FORWARD_BUF_SIZE: usize = 32 * 1024;

pub async fn forward_stream(
    mut upstream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
    mut downstream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
) -> Result<()> {
    tracing::debug!("Starting to transmit application data");
    let (from_client, from_server) = tokio::io::copy_bidirectional_with_sizes(
        &mut downstream,
        &mut upstream,
        FORWARD_BUF_SIZE,
        FORWARD_BUF_SIZE,
    )
    .await
    .context("Failed during copy streams bidirectionally between downstream and upstream")?;
    tracing::debug!(
        tx_bytes = from_client,
        rx_bytes = from_server,
        "Finished transmit application data",
    );

    Ok(())
}
