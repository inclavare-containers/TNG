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

/// Policy-routing fwmark and routing-table number bases for netfilter TPROXY
/// rules.
///
/// Each netfilter mode owns a **disjoint** fwmark range and a disjoint policy
/// routing table, so that a single TNG instance running several of them
/// concurrently in the same network namespace does not collide. The per-mode
/// `id` (the index of the instance within its own `add_ingress` / `add_egress`
/// list — a *separate* enumeration per side and per protocol) is added to the
/// mode's base. The ranges are spaced 1024 apart, far beyond any realistic
/// instance count per mode.
///
/// | mode        | fwmark base | table base |
/// |-------------|-------------|------------|
/// | TCP ingress | 566         | 239        |
/// | UDP ingress | 1566        | 1239       |
/// | UDP egress  | 2566        | 2239       |
///
/// These are kernel-internal marks/tables, not user-facing config. The
/// `so_mark` SO_MARK socket option (default 565) used to let TNG's own tunnel
/// sockets escape capture is a separate value; it is just numerically
/// adjacent to the TCP-ingress base.
pub const NETFILTER_TCP_INGRESS_FW_MARK_BASE: u32 = 566;
pub const NETFILTER_TCP_INGRESS_ROUTE_TABLE_BASE: u32 = 239;

pub const NETFILTER_UDP_INGRESS_FW_MARK_BASE: u32 = NETFILTER_TCP_INGRESS_FW_MARK_BASE + 1024;
pub const NETFILTER_UDP_INGRESS_ROUTE_TABLE_BASE: u32 =
    NETFILTER_TCP_INGRESS_ROUTE_TABLE_BASE + 1024;

pub const NETFILTER_UDP_EGRESS_FW_MARK_BASE: u32 = NETFILTER_TCP_INGRESS_FW_MARK_BASE + 2 * 1024;
pub const NETFILTER_UDP_EGRESS_ROUTE_TABLE_BASE: u32 =
    NETFILTER_TCP_INGRESS_ROUTE_TABLE_BASE + 2 * 1024;

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
    use super::{
        format_dport, NETFILTER_TCP_INGRESS_FW_MARK_BASE, NETFILTER_TCP_INGRESS_ROUTE_TABLE_BASE,
        NETFILTER_UDP_EGRESS_FW_MARK_BASE, NETFILTER_UDP_EGRESS_ROUTE_TABLE_BASE,
        NETFILTER_UDP_INGRESS_FW_MARK_BASE, NETFILTER_UDP_INGRESS_ROUTE_TABLE_BASE,
    };

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

    /// The three netfilter modes must use disjoint fwmark and routing-table
    /// ranges so that a single TNG instance running several of them in the
    /// same network namespace (each `id` enumerated separately per side) does
    /// not collide on the fwmark or policy routing table. `id` values are
    /// small in practice; assert disjointness over a generous id span.
    #[test]
    fn test_netfilter_fwmark_and_table_ranges_are_disjoint() {
        const ID_SPAN: u32 = 256;

        let ranges: [((u32, u32), (u32, u32)); 3] = [
            (
                (
                    NETFILTER_TCP_INGRESS_FW_MARK_BASE,
                    NETFILTER_TCP_INGRESS_FW_MARK_BASE + ID_SPAN,
                ),
                (
                    NETFILTER_TCP_INGRESS_ROUTE_TABLE_BASE,
                    NETFILTER_TCP_INGRESS_ROUTE_TABLE_BASE + ID_SPAN,
                ),
            ),
            (
                (
                    NETFILTER_UDP_INGRESS_FW_MARK_BASE,
                    NETFILTER_UDP_INGRESS_FW_MARK_BASE + ID_SPAN,
                ),
                (
                    NETFILTER_UDP_INGRESS_ROUTE_TABLE_BASE,
                    NETFILTER_UDP_INGRESS_ROUTE_TABLE_BASE + ID_SPAN,
                ),
            ),
            (
                (
                    NETFILTER_UDP_EGRESS_FW_MARK_BASE,
                    NETFILTER_UDP_EGRESS_FW_MARK_BASE + ID_SPAN,
                ),
                (
                    NETFILTER_UDP_EGRESS_ROUTE_TABLE_BASE,
                    NETFILTER_UDP_EGRESS_ROUTE_TABLE_BASE + ID_SPAN,
                ),
            ),
        ];

        // fwmark ranges are pairwise disjoint
        for i in 0..3 {
            for j in (i + 1)..3 {
                let (a_start, a_end) = ranges[i].0;
                let (b_start, b_end) = ranges[j].0;
                assert!(
                    a_end <= b_start || b_end <= a_start,
                    "fwmark ranges overlap: [{a_start},{a_end}) vs [{b_start},{b_end})"
                );
            }
        }

        // routing-table ranges are pairwise disjoint
        for i in 0..3 {
            for j in (i + 1)..3 {
                let (a_start, a_end) = ranges[i].1;
                let (b_start, b_end) = ranges[j].1;
                assert!(
                    a_end <= b_start || b_end <= a_start,
                    "route-table ranges overlap: [{a_start},{a_end}) vs [{b_start},{b_end})"
                );
            }
        }
    }
}
