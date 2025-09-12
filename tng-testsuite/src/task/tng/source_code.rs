use anyhow::Result;
use tng::runtime::TngRuntime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::TngInstance;

impl TngInstance {
    pub(super) async fn launch_inner(
        &self,
        token: CancellationToken,
    ) -> Result<JoinHandle<Result<()>>> {
        let config_json = match self {
            TngInstance::TngClient(config_json) | TngInstance::TngServer(config_json) => {
                config_json
            }
        }
        .to_string();

        let (sender, receiver) = tokio::sync::oneshot::channel();

        let join_handle = tokio::task::spawn(async move {
            let config: tng::config::TngConfig = serde_json::from_str(&config_json)?;

            let tng_runtime = TngRuntime::from_config_with_reload_handle(
                config,
                crate::BIN_TEST_LOG_RELOAD_HANDLE
                    .get()
                    .expect("log reload handle not initialized"),
            )
            .await?;

            let canceller = tng_runtime.canceller();

            {
                tokio::task::spawn(async move {
                    token.cancelled().await;
                    canceller.cancel();
                });
            };

            tng_runtime.serve_with_ready(sender).await?;

            Ok::<_, anyhow::Error>(())
        });

        // Wait for the tng runtime to be ready
        if let Err(e) = receiver.await {
            tracing::error!(error=?e, "failed to receive tng runtime ready signal");
        }

        return Ok(join_handle);
    }
}
