use super::{NodeType, Task};

use anyhow::{bail, Result};
use async_trait::async_trait;
use tokio::{process::Command, task::JoinHandle};
use tokio_util::sync::CancellationToken;

/// Controls how a shell script is executed within a test.
#[derive(Clone, Copy)]
pub enum ShellMode {
    /// Run the script synchronously. If it fails, the test fails.
    Blocking,
    /// Spawn the script in the background. Errors are logged but do not stop the test.
    /// Use for fire-and-forget scripts that are not critical to test outcome.
    FireAndForget,
    /// Spawn the script in the background and wait for it to complete before continuing
    /// to the next stage of the test. Errors are logged but do not stop the test.
    /// Use for setup / barrier scripts that must complete before subsequent tasks run.
    Barrier,
}

pub struct ShellTask {
    pub name: String,
    pub node_type: NodeType,
    pub script: String,
    pub mode: ShellMode,
}

#[async_trait]
impl Task for ShellTask {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn node_type(&self) -> NodeType {
        self.node_type
    }

    async fn launch(&self, token: CancellationToken) -> Result<JoinHandle<Result<()>>> {
        let script = self.script.clone();
        let name = self.name.clone();
        let mode = self.mode;

        let shell_task = async move {
            let task = async move {
                let mut cmd = Command::new("sh");
                cmd.arg("-c").arg(&format!("set -e ; true ; {}", script));
                let output = cmd.output().await;

                match output {
                    Ok(output) => {
                        if !output.status.success() {
                            // Log full output at error level for debugging
                            tracing::error!(
                                "Shell script failed:\nstdout:\n{}\nstderr:\n{}",
                                String::from_utf8_lossy(&output.stdout),
                                String::from_utf8_lossy(&output.stderr)
                            );
                            bail!(
                                "failed to execute shell script, stderr: {}",
                                String::from_utf8_lossy(&output.stderr)
                            );
                        }
                        tracing::debug!(
                            "Shell script succeeded:\nstdout:\n{}\nstderr:\n{}",
                            String::from_utf8_lossy(&output.stdout),
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                    Err(e) => {
                        bail!("Failed to execute command: {e}");
                    }
                }

                Ok(())
            };

            match mode {
                ShellMode::Blocking => {
                    let _drop_guard = token.drop_guard();
                    task.await?;
                }
                ShellMode::FireAndForget => {
                    tokio::select! {
                        _ = token.cancelled() => {}
                        res = task => {
                            if let Err(e) = res {
                                tracing::debug!("Background shell task '{name}' completed with error: {e}");
                            }
                        }
                    }
                }
                ShellMode::Barrier => {
                    tokio::select! {
                        _ = token.cancelled() => {}
                        res = task => {
                            if let Err(e) = res {
                                tracing::debug!("Barrier shell task '{name}' completed with error: {e}");
                            }
                        }
                    }
                }
            }

            Ok(())
        };

        match mode {
            ShellMode::Blocking => {
                let _handle = shell_task.await?;
                // The task completed synchronously, return a no-op spawned task.
                Ok(tokio::task::spawn(async move { Ok(()) }))
            }
            ShellMode::FireAndForget | ShellMode::Barrier => {
                // Spawn the shell task in the background and return immediately.
                Ok(tokio::task::spawn(shell_task))
            }
        }
    }
}
