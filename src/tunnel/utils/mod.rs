pub mod cert_manager;
pub mod endpoint_matcher;
pub mod h2_stream;
#[cfg(target_os = "linux")]
pub mod iptables;
pub mod rustls_config;
pub mod socket;

use anyhow::{Context, Result};
pub async fn forward_stream(
    mut upstream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
    mut input: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
) -> Result<()> {
    tracing::debug!("Starting to transmit application data");
    let (from_client, from_server) = tokio::io::copy_bidirectional(&mut input, &mut upstream)
        .await
        .context("Failed during copy streams bidirectionally between downstream and upstream")?;
    tracing::debug!(
        tx_bytes = from_client,
        rx_bytes = from_server,
        "Finished transmit application data",
    );

    Ok(())
}
