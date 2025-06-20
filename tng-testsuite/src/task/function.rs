use super::{NodeType, Task};

use anyhow::Result;
use async_trait::async_trait;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub struct FunctionTask {
    pub name: String,
    pub node_type: NodeType,
    pub func: Box<dyn Fn(CancellationToken) -> Result<JoinHandle<Result<()>>> + Sync + Send>,
}

#[async_trait]
impl Task for FunctionTask {
    fn name(&self) -> String {
        self.name.to_owned()
    }

    fn node_type(&self) -> NodeType {
        self.node_type
    }

    async fn launch(&self, token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
        (self.func)(token)
    }
}
