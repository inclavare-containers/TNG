use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use serde_json::json;
use std::process::Stdio;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::TngInstance;

#[cfg(feature = "on-bin")]
mod bin;

#[cfg(feature = "on-podman")]
mod podman;

impl TngInstance {
    pub fn patch_config_with_control_interface(config_json: &str, port: u16) -> Result<String> {
        // Patch the config json to add the control_interface config.
        let mut tng_config: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(config_json)?;
        if let Some(value) = tng_config.get("control_interface") {
            bail!("control_interface config already exists in the config json: {value}")
        }
        tng_config.insert(
            "control_interface".to_string(),
            json!(
                {
                    "restful": {
                        "host": "127.0.0.1",
                        "port": port
                    }
                }
            ),
        );
        Ok(serde_json::to_string(&tng_config)?)
    }

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

        let config_json = Self::patch_config_with_control_interface(&config_json, 60000)?;

        tracing::info!("Run tng with {config_json}");

        let mut process = self
            .get_tokio_command(&config_json)
            .await
            .context("Failed to get command line for creating tng process")?
            .stdin(Stdio::null())
            .spawn()?;

        // Wait for the tng process to be ready by polling the ready signal from 127.0.0.1:50000/readyz.
        loop {
            if let Ok(resp) = reqwest::get("http://127.0.0.1:60000/readyz").await {
                if resp.status() == reqwest::StatusCode::OK {
                    break;
                }
            }
            if let Some(status) = process
                .try_wait()
                .context("Failed to get status of tng process")?
            {
                bail!(
                    "tng process has exited unexpectedly, exit code: {:?}",
                    status.code(),
                );
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let join_handle = tokio::task::spawn(async move {
            tokio::select! {
                status = process.wait() => {
                    let status = status.context("faile to get output of the tng process")?;
                    if !status.success() {
                        bail!("exit code: {:?}", status.code())
                    }
                },
                _ = token.cancelled() => {
                    if let Some(pid) = process.id() {
                        nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid.try_into().with_context(|| format!("Invalid PID {pid}"))?),
                            nix::sys::signal::SIGTERM
                        ).context("Failed to send SIGTERM to the tng process")?
                    }
                    tracing::info!("tng task cancelled");
                }
            }

            Ok::<_, anyhow::Error>(())
        });

        return Ok(join_handle);
    }
}
