use anyhow::Result;
use async_trait::async_trait;
use tng::runtime::TngRuntime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{NodeType, Task};

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
        let config_json = match self {
            TngInstance::TngClient(config_json) | TngInstance::TngServer(config_json) => {
                config_json
            }
        }
        .to_string();

        let (sender, receiver) = tokio::sync::oneshot::channel();

        let join_handle = tokio::task::spawn(async move {
            let config: tng::config::TngConfig = serde_json::from_str(&config_json)?;

            let tng_token = CancellationToken::new();

            {
                let tng_token = tng_token.clone();
                tokio::task::spawn(async move {
                    token.cancelled().await;
                    tng_token.cancel();
                });
            }

            TngRuntime::from_config_with_reload_handle(
                config,
                crate::BIN_TEST_LOG_RELOAD_HANDLE
                    .get()
                    .expect("log reload handle not initialized"),
            )
            .await?
            .serve_with_cancel(tng_token, sender)
            .await?;

            Ok::<_, anyhow::Error>(())
        });

        // Wait for the tng runtime to be ready
        if let Err(e) = receiver.await {
            tracing::error!(error=?e, "failed to receive tng runtime ready signal");
        }

        return Ok(join_handle);
    }
}
