use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

/// The registered service is a core component of the TNG runtime. After the TNG runtime is created,
/// they service will be started and keeping running in a background async task. Any service failed
/// will cause the TNG runtime to shutdown.
///
/// Also note that the async task will be cancelled once when the TNG runtime is cancelled. So it is
/// not required to check the shutdown_guard.cancelled() in the service.
#[async_trait]
pub trait RegistedService {
    async fn serve(&self, ready: Sender<()>) -> Result<()>;
}
