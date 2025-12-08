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
    Middleware,
    Customized { host_num: u8 },
}

impl NodeType {
    pub fn ip(&self) -> String {
        match self {
            NodeType::Client => "192.168.1.253".into(),
            NodeType::Server => "192.168.1.1".into(),
            NodeType::Customized { host_num } => {
                if *host_num <= 0 || *host_num > 250 {
                    panic!("host_num must be >= 1 and <= 250");
                }
                format!("192.168.1.{host_num}")
            }
            NodeType::Middleware => "192.168.1.252".into(),
        }
    }
}

pub struct TaskInGivenNode<T>(NodeType, T);

#[async_trait]
impl<T> Task for TaskInGivenNode<T>
where
    T: Task,
{
    fn name(&self) -> String {
        self.1.name()
    }

    fn node_type(&self) -> NodeType {
        self.0
    }

    /// Launch the task, wait until the task is ready and return a handle to the task.
    async fn launch(&self, token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
        self.1.launch(token).await
    }
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

    fn with_overwrite_node_type(self, node_type: NodeType) -> TaskInGivenNode<Self>
    where
        Self: Sized,
    {
        TaskInGivenNode(node_type, self)
    }
}
