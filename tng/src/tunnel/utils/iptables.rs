use std::path::Path;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::{net::UnixListener, process::Command, sync::OnceCell};
use tracing::{Instrument, Span};

static ONLY_ONE_TNG_PER_NETNS: OnceCell<UnixListener> = OnceCell::const_new();

#[async_trait]
pub trait IptablesRuleGenerator {
    async fn gen_script(&self) -> Result<(String, String)>;
}

/// Format the --dport argument for iptables.
/// Returns "port" for single port, or "port:port_end" for port range.
pub fn format_dport(port: u16, port_end: Option<&u16>) -> String {
    match port_end {
        Some(end) => format!("{port}:{end}"),
        None => format!("{port}"),
    }
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

        IptablesExecutor::execute_script(&iptables_invoke_script)
            .await
            .context("Failed to setup iptables rules")?;

        Ok(guard)
    }

    async fn execute_script(script: &str) -> Result<()> {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(format!("set -e ; true ; {script}"));
        let output = cmd
            .output()
            .await
            .with_context(|| format!("Failed to execute command: {:?}", cmd.as_std()))?;

        // Handle the output
        let stdout = output.stdout;
        let stderr = output.stderr;
        let code = output.status.code();

        match code {
            Some(code) => {
                if code != 0 {
                    Err(anyhow!("Bad exit code"))
                } else {
                    Ok(())
                }
            }
            None => Err(anyhow!("killed by signal")),
        }
        .with_context(|| {
            let stdout = String::from_utf8_lossy(&stdout);
            let stderr = String::from_utf8_lossy(&stderr);
            format!(
                "\ncmd: {:?}\nexit code: {}\nstdout: {}\nstderr: {}",
                cmd.as_std(),
                code.map(|code| code.to_string())
                    .unwrap_or("unknown".to_string()),
                if stdout.contains('\n') {
                    format!("(multi-line)\n\t{}", stdout.replace('\n', "\n\t"))
                } else {
                    stdout.into()
                },
                if stderr.contains('\n') {
                    format!("(multi-line)\n\t{}", stderr.replace('\n', "\n\t"))
                } else {
                    stderr.into()
                },
            )
        })?;

        Ok(())
    }
}

impl Drop for IptablesGuard {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                async {
                    if let Err(error) =
                        IptablesExecutor::execute_script(&self.iptables_revoke_script).await
                    {
                        tracing::error!(?error, "Failed to clean up iptables rules");
                    }
                }
                .instrument(self.span.clone()),
            );
        })
    }
}

#[cfg(test)]
mod tests {
    use super::format_dport;

    #[test]
    fn test_format_dport_single_port() {
        assert_eq!(format_dport(80, None), "80");
        assert_eq!(format_dport(30001, None), "30001");
    }

    #[test]
    fn test_format_dport_port_range() {
        assert_eq!(format_dport(30000, Some(&30031)), "30000:30031");
        assert_eq!(format_dport(80, Some(&80)), "80:80");
        assert_eq!(format_dport(1, Some(&65535)), "1:65535");
    }
}
