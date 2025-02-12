use anyhow::Result;
use tng::TngBuilder;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub async fn launch_tng(
    token: CancellationToken,
    task_name: &str,
    config_json: &str,
) -> Result<JoinHandle<Result<()>>> {
    let config_json = config_json.to_owned();

    let task_name = task_name.to_owned();
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

        TngBuilder::from_config(config)
            .serve_with_cancel(tng_token, sender)
            .await?;

        tracing::info!("The {task_name} task normally exit now");
        Ok(())
    });

    receiver.await?;

    return Ok(join_handle);
}
