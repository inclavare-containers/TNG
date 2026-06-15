use anyhow::Result;
use async_trait::async_trait;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{NodeType, Task};

#[cfg(feature = "on-source-code")]
mod source_code;

#[cfg(any(feature = "on-bin", feature = "on-podman"))]
mod external;

#[derive(Debug, Clone, Copy)]
pub enum TngInstance {
    #[allow(unused)]
    TngClient(&'static str),
    #[allow(unused)]
    TngServer(&'static str),
}

#[async_trait]
impl Task for TngInstance {
    fn name(&self) -> String {
        match self {
            TngInstance::TngClient(_) => "tng_client",
            TngInstance::TngServer(_) => "tng_server",
        }
        .to_string()
    }

    fn node_type(&self) -> NodeType {
        match self {
            TngInstance::TngClient(_) => NodeType::Client,
            TngInstance::TngServer(_) => NodeType::Server,
        }
    }

    async fn launch(&self, token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
        self.launch_with_node_type(token, self.node_type()).await
    }

    #[cfg(any(feature = "on-bin", feature = "on-podman"))]
    async fn launch_with_node_type(
        &self,
        token: CancellationToken,
        node_type: NodeType,
    ) -> Result<JoinHandle<Result<()>>> {
        let tag = format!("{}@{}", self.name(), node_type.ip());
        self.launch_inner(token, &tag).await
    }

    #[cfg(feature = "on-source-code")]
    async fn launch_with_node_type(
        &self,
        token: CancellationToken,
        node_type: NodeType,
    ) -> Result<JoinHandle<Result<()>>> {
        let _ = node_type; // source_code mode doesn't use tag prefixes
        self.launch_inner(token, "").await
    }
}
