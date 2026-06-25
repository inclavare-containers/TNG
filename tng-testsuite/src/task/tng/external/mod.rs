use anyhow::{bail, Context, Result};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::task::tagged_spawn::spawn_with_span_output;

use super::readyz::{patch_config_with_control_interface, wait_for_readyz, ProcessStatus};
use super::TngInstance;

#[cfg(feature = "on-bin")]
mod bin;

#[cfg(feature = "on-podman")]
mod podman;

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

        let free_port = portpicker::pick_unused_port().context("Failed to pick a free port")?;

        let config_json = patch_config_with_control_interface(&config_json, free_port)?;

        tracing::info!("Run tng with {config_json}");

        let mut process = {
            let mut cmd = self
                .get_tokio_command(&config_json)
                .await
                .context("Failed to get command line for creating tng process")?;
            spawn_with_span_output(&mut cmd)
                .await
                .context("Failed to spawn tng process")?
        };

        // Wait for the tng process to be ready by polling /readyz.
        wait_for_readyz(free_port, || match process.try_wait() {
            Ok(Some(status)) => ProcessStatus::Exited(status.code()),
            Ok(None) => ProcessStatus::Running,
            Err(e) => {
                tracing::error!(?e, "Failed to get status of tng process");
                ProcessStatus::Exited(None)
            }
        })
        .await?;

        let parent_span = tracing::Span::current();
        let join_handle = tokio::task::spawn(async move {
            tokio::select! {
                status = process.wait() => {
                    let status = status.context("failed to get output of the tng process")?;
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
        }.instrument(parent_span));

        return Ok(join_handle);
    }
}
