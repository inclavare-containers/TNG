use super::{NodeType, Task};

use anyhow::{bail, Result};
use async_trait::async_trait;
use tokio::{process::Command, task::JoinHandle};
use tokio_util::sync::CancellationToken;

pub struct ShellTask {
    pub name: String,
    pub node_type: NodeType,
    pub script: String,
    pub stop_test_on_finish: bool,
    pub run_in_foreground: bool,
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
        let stop_test_on_finish = self.stop_test_on_finish;

        let shell_task = async move {
            let task = async move {
                let mut cmd = Command::new("sh");
                cmd.arg("-c").arg(&format!("set -e ; true ; {}", script));
                let output = cmd.output().await;

                match output {
                    Ok(output) => {
                        tracing::debug!(
                            "execute iptable script:\n{cmd:?}\nstdout:\n{}\nstderr:\n{}",
                            String::from_utf8_lossy(&output.stdout),
                            String::from_utf8_lossy(&output.stderr)
                        );

                        if !output.status.success() {
                            bail!(
                                "failed to execute iptables script, stderr: {}",
                                String::from_utf8_lossy(&output.stderr)
                            );
                        }
                    }
                    Err(e) => {
                        bail!("Failed to execute command: {e}");
                    }
                }

                Ok(())
            };

            if stop_test_on_finish {
                let _drop_guard = token.drop_guard();
                task.await?;
            } else {
                tokio::select! {
                    _ = token.cancelled() => {}
                    res = task => {
                        res?;
                    }
                }
            }

            Ok(())
        };

        if self.run_in_foreground {
            shell_task.await?;

            return Ok(tokio::task::spawn(async move {
                /* empty task */
                Ok(())
            }));
        } else {
            Ok(tokio::task::spawn(shell_task))
        }
    }
}
