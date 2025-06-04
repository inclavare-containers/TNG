use anyhow::Result;
use async_trait::async_trait;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{NodeType, Task};

#[cfg(feature = "on-source-code")]
mod source_code;

#[cfg(any(feature = "on-bin", feature = "on-podman"))]
mod external;

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
        self.launch_inner(token).await
    }
}
