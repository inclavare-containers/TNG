use anyhow::Result;
use tokio::net::TcpStream;
use tokio_graceful::ShutdownGuard;

pub mod trusted;

pub trait StreamManager {
    type Sender;

    /// This function will be called after the tunnel runtime is created but before the up-layer service is started and ready for accepting connections.
    async fn prepare(&self, shutdown_guard: ShutdownGuard) -> Result<()>;

    async fn consume_stream(
        &self,
        stream: TcpStream,
        sender: Self::Sender,
        shutdown_guard: ShutdownGuard,
    ) -> Result<()>;
}
