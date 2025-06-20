use anyhow::Result;
use async_trait::async_trait;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub mod app;
pub mod function;
pub mod shell;
pub mod tng;

#[derive(Debug, Clone, Copy)]
pub enum NodeType {
    Client,
    Server,
}

#[async_trait]
pub trait Task: Send + Sync + 'static {
    fn name(&self) -> String;

    fn node_type(&self) -> NodeType;

    /// Launch the task, wait until the task is ready and return a handle to the task.
    async fn launch(&self, token: CancellationToken) -> Result<JoinHandle<Result<()>>>;

    fn boxed(self) -> Box<dyn Task>
    where
        Self: Sized,
    {
        Box::new(self)
    }
}
