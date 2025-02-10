use anyhow::Result;
use tokio::net::TcpStream;
use tokio_graceful::ShutdownGuard;

pub mod trusted;

pub trait StreamManager {
    type Sender;

    async fn consume_stream(
        &self,
        stream: TcpStream,
        sender: Self::Sender,
        shutdown_guard: ShutdownGuard,
    ) -> Result<()>;
}
