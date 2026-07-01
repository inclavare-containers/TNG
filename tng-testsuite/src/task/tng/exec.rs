use anyhow::{Context, Result};
use async_trait::async_trait;
use scopeguard::defer;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use super::binary_locator::resolve_tng_binary;
use crate::task::tagged_spawn::spawn_with_span_output;
use crate::task::{NodeType, Task};

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
    stop_after_exit: bool,
    #[allow(dead_code)]
    tag: String,
    node_type: NodeType,
}

impl TngExecTask {
    pub fn new(
        config_json: String,
        command: Vec<String>,
        stop_after_exit: bool,
        node_type: NodeType,
    ) -> Self {
        Self {
            config_json,
            command,
            stop_after_exit,
            tag: "tng_exec".to_owned(),
            node_type,
        }
    }
}

#[async_trait]
impl Task for TngExecTask {
    fn name(&self) -> String {
        "tng_exec".to_string()
    }

    fn node_type(&self) -> NodeType {
        self.node_type
    }

    async fn launch(&self, token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
        let stop_after_exit = self.stop_after_exit;
        let config_json = self.config_json.clone();
        let command = self.command.clone();

        let parent_span = tracing::Span::current();

        // Resolve tng binary path
        let tng_bin = resolve_tng_binary()?;
        tracing::info!(?tng_bin, "Resolved tng binary");

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
        tracing::info!(pid = child_id, "tng exec child spawned");

        // Note: no need to patch_config_with_control_interface() and wait_for_readyz() here since the exec target may return soon before the wait_for_readyz return.

        let join_handle = tokio::task::spawn(
            async move {
                // Wait for child exit, but also listen for cancellation.
                // On cancellation, kill the child process before returning.
                tokio::select! {
                    status = child.wait() => {
                        defer! {
                            if stop_after_exit {
                                token.cancel();
                            }
                        }
                        let status = status.context("Failed to wait for tng exec child")?;
                        tracing::info!(?status, "tng exec child exited");
                        if !status.success() {
                            anyhow::bail!("tng exec exited with status: {:?}", status);
                        }
                        Ok::<_, anyhow::Error>(())
                    }
                    _ = token.cancelled() => {
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
