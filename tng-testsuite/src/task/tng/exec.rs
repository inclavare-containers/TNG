use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use super::binary_locator::resolve_tng_binary;
use super::readyz::{patch_config_with_control_interface, wait_for_readyz, ProcessStatus};
use crate::task::tagged_spawn::spawn_with_span_output;
use crate::task::NodeType;
use crate::task::Task;

/// Task that runs `tng exec` as an external process.
///
/// Unlike TngInstance (which runs TngRuntime in-process), this spawns
/// the actual `tng exec` CLI command. LD_PRELOAD setup for libtng_hook.so
/// is handled internally by `tng exec`, not by this task.
///
/// Readiness is verified via the injected control_interface `/readyz` endpoint
/// before returning the join handle, ensuring the tunnel listeners are bound.
pub struct TngExecTask {
    config_json: String,
    command: Vec<String>,
    #[allow(dead_code)]
    tag: String,
}

impl TngExecTask {
    pub fn new(config_json: String, command: Vec<String>) -> Self {
        Self {
            config_json,
            command,
            tag: "tng_exec".to_owned(),
        }
    }
}

#[async_trait]
impl Task for TngExecTask {
    fn name(&self) -> String {
        "tng_exec".to_string()
    }

    fn node_type(&self) -> NodeType {
        NodeType::Server
    }

    async fn launch(&self, token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
        let config_json = self.config_json.clone();
        let command = self.command.clone();

        let parent_span = tracing::Span::current();

        // Resolve tng binary path
        let tng_bin = resolve_tng_binary()?;
        tracing::info!(?tng_bin, "Resolved tng binary");

        // Pick a free port for the control_interface
        let control_port = portpicker::pick_unused_port().context("Failed to pick a free port")?;

        // Patch config to inject control_interface for /readyz
        let config_json = patch_config_with_control_interface(&config_json, control_port)?;

        // Build the command
        let mut cmd = Command::new(&tng_bin);
        cmd.arg("exec")
            .arg("--config-content")
            .arg(&config_json)
            .arg("--");
        cmd.args(&command);

        tracing::info!(?cmd, "Launching tng exec");

        let mut child = spawn_with_span_output(&mut cmd)
            .await
            .context("Failed to spawn tng process")?;

        let child_id = child.id();
        tracing::info!(pid = child_id, control_port, "tng exec child spawned");

        // Wait for /readyz to return 200 OK before returning the handle.
        // This ensures the tunnel listeners are bound before the test proceeds.
        wait_for_readyz(control_port, || match child.try_wait() {
            Ok(Some(status)) => ProcessStatus::Exited(status.code()),
            Ok(None) => ProcessStatus::Running,
            Err(e) => {
                tracing::error!(?e, "Failed to check child status");
                ProcessStatus::Exited(None)
            }
        })
        .await?;

        tracing::info!(control_port, "tng exec is ready");

        let join_handle = tokio::task::spawn(
            async move {
                // Wait for child exit, but also listen for cancellation.
                // On cancellation, kill the child process before returning.
                tokio::select! {
                    status = child.wait() => {
                        let status = status.context("Failed to wait for tng exec child")?;
                        tracing::info!(?status, "tng exec child exited");
                        if !status.success() {
                            anyhow::bail!("tng exec exited with status: {:?}", status);
                        }
                        Ok::<_, anyhow::Error>(())
                    }
                    _ = token.cancelled() => {
                        tracing::warn!("tng exec cancelled, killing child process");
                        let _ = child.start_kill();
                        let _ = child.wait().await;
                        Ok::<_, anyhow::Error>(())
                    }
                }
            }
            .instrument(parent_span),
        );

        Ok(join_handle)
    }
}
