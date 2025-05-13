use std::path::Path;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use tokio::{net::UnixListener, process::Command, sync::OnceCell};
use tracing::{Instrument, Span};

static ONLY_ONE_TNG_PER_NETNS: OnceCell<UnixListener> = OnceCell::const_new();

#[async_trait]
pub trait IptablesRuleGenerator {
    async fn gen_script(&self) -> Result<(String, String)>;
}

pub struct IptablesExecutor {}

pub struct IptablesGuard {
    iptables_revoke_script: String,
    span: Span,
}

impl IptablesExecutor {
    pub async fn setup(rule_generator: &impl IptablesRuleGenerator) -> Result<IptablesGuard> {
        tracing::info!("Setting up iptables rule");

        // Check if there is annother TNG instance running in same network namespace.
        ONLY_ONE_TNG_PER_NETNS.get_or_try_init(|| async {
            UnixListener::bind(Path::new("\0tng"))
                .context("Running more than one TNG instances concurrently in same network namespace which need iptables rules is not supported in current TNG version")
        }).await?;

        let (iptables_invoke_script, iptables_revoke_script) = rule_generator.gen_script().await?;

        let guard = IptablesGuard {
            iptables_revoke_script,
            span: Span::current(),
        };

        IptablesExecutor::execute_script(&iptables_invoke_script).await?;

        Ok(guard)
    }

    async fn execute_script(script: &str) -> Result<()> {
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
    }
}

impl Drop for IptablesGuard {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                async {
                    if let Err(e) =
                        IptablesExecutor::execute_script(&self.iptables_revoke_script).await
                    {
                        tracing::error!("Failed to revoke iptables rules: {e:#}");
                    }
                }
                .instrument(self.span.clone()),
            );
        })
    }
}
