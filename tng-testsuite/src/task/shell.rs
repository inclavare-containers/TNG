use super::{NodeType, Task};

use anyhow::{bail, Result};
use async_trait::async_trait;
use tokio::{process::Command, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

/// Controls how a shell script is executed within a test.
///
/// Two independent dimensions are covered:
///
/// 1. **Execution style**: foreground (blocks `launch()`) vs background (returns immediately)
/// 2. **Finish policy**: stop (cancels the test token on finish) vs continue
///
/// | Variant                        | Blocks `launch()`? | On finish → cancel token? |
/// |--------------------------------|--------------------|----------------------------|
/// | `ForegroundStop`               | Yes                | Yes                        |
/// | `ForegroundContinue`           | Yes                | No                         |
/// | `BackgroundContinue`           | No                 | No                         |
/// | `BackgroundStop`               | No                 | Yes                        |
#[derive(Clone, Copy)]
pub enum ShellMode {
    /// Run the script synchronously (blocks `launch()`). On finish, the test token is
    /// cancelled so all other tasks wind down.
    ForegroundStop,
    /// Run the script synchronously (blocks `launch()`). On finish, the error is
    /// propagated but the test token is NOT cancelled — other tasks continue running
    /// and the harness collects all errors to report at the end.
    ForegroundContinue,
    /// Spawn the script in the background (`launch()` returns immediately). On finish,
    /// the error is logged but the test token is NOT cancelled.
    BackgroundContinue,
    /// Spawn the script in the background (`launch()` returns immediately). On finish,
    /// the test token is cancelled so all other tasks wind down.
    BackgroundStop,
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
                ShellMode::ForegroundStop | ShellMode::BackgroundStop => {
                    let _drop_guard = token.drop_guard();
                    task.await?;
                }
                ShellMode::ForegroundContinue | ShellMode::BackgroundContinue => {
                    tokio::select! {
                        _ = token.cancelled() => {}
                        res = task => {
                            res?;
                        }
                    }
                }
            }

            Ok(())
        };

        let parent_span = tracing::Span::current();

        match mode {
            ShellMode::ForegroundStop | ShellMode::ForegroundContinue => {
                let _handle = shell_task.await?;
                // The task completed synchronously, return a no-op spawned task.
                Ok(tokio::task::spawn(
                    async move { Ok(()) }.instrument(parent_span),
                ))
            }
            ShellMode::BackgroundContinue | ShellMode::BackgroundStop => {
                // Spawn the shell task in the background and return immediately.
                Ok(tokio::task::spawn(shell_task.instrument(parent_span)))
            }
        }
    }
}
