use std::time::Duration;

use anyhow::{Context, Result};
use tng::TngBuilder;
use tokio::{runtime::Builder, task::JoinHandle};
use tokio_util::sync::CancellationToken;

pub async fn launch_tng(
    token: CancellationToken,
    task_name: &str,
    config_json: &str,
) -> Result<JoinHandle<Result<()>>> {
    let config_json = config_json.to_owned();

    let task_name = task_name.to_owned();
    let join_handle = tokio::task::spawn_blocking(move || -> Result<()> {
        let config: tng::config::TngConfig = serde_json::from_str(&config_json)?;
        let mut instance = TngBuilder::new(config).launch()?;
        {
            let task_name = task_name.to_owned();
            let stopper = instance.stopper();
            std::thread::spawn(move || {
                let rt = Builder::new_current_thread().enable_all().build().unwrap();
                rt.block_on(async move { token.cancelled().await });
                tracing::info!("{task_name}: stopping the tng instance now");
                stopper
                    .stop()
                    .with_context(|| {
                        format!("Failed to call stop() on tng instance in {task_name}")
                    })
                    .unwrap();
            });
        }

        instance.wait()?;
        instance.clean_up()?;

        tracing::info!("The {task_name} task normally exit now");
        Ok(())
    });

    // TODO: better way to checking readiness of envoy
    tokio::time::sleep(Duration::from_secs(3)).await;

    return Ok(join_handle);
}
