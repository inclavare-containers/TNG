use anyhow::Result;
use tokio_graceful::ShutdownGuard;

use crate::tunnel::stream::CommonStreamTrait;

pub mod trusted;

pub trait StreamManager {
    type Sender;

    /// This function will be called after the tunnel runtime is created but before the up-layer service is started and ready for accepting connections.
    async fn prepare(&self, shutdown_guard: ShutdownGuard) -> Result<()>;

    async fn consume_stream(
        &self,
        stream: Box<(dyn CommonStreamTrait + std::marker::Send + 'static)>,
        sender: Self::Sender,
        shutdown_guard: ShutdownGuard,
    ) -> Result<()>;
}
