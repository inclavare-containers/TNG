// The serf engine (`PeerSharedKeyManager`) and the entire `tunnel::egress`
// tree live behind the `__egress-common` feature. A `tools`-only build (no
// egress features) does not compile that tree, so the real `run` body that
// references those symbols carries the same gate; the fallback bails at runtime
// instead of failing to link.
#![allow(unexpected_cfgs)]

use anyhow::Result;

#[cfg(feature = "__egress-common")]
use anyhow::Context as _;

/// Entry point for `tng tools key-sync`.
///
/// `--attest` and `--verify` are flat JSON parsed directly into `AttestArgs` /
/// `VerifyArgs` (every discriminator tag explicit, no `RaArgsUnchecked` tag
/// injection), then assembled into a `PeerSharedArgs` whose RA config drives
/// the serf RA-TLS QUIC transport.
pub async fn run(opts: super::cli::KeySyncOptions) -> Result<()> {
    #[cfg(feature = "__egress-common")]
    {
        run_impl(opts).await
    }
    #[cfg(not(feature = "__egress-common"))]
    {
        let _ = opts;
        anyhow::bail!(
            "key-sync requires the __egress-common feature, which is not enabled on this target"
        )
    }
}

#[cfg(feature = "__egress-common")]
async fn run_impl(opts: super::cli::KeySyncOptions) -> Result<()> {
    use super::KeySyncDaemon;
    use crate::config::egress::PeerSharedArgs;
    use crate::config::ra::{AttestArgs, RaArgsUnchecked, VerifyArgs};
    use crate::tunnel::utils::runtime::TokioRuntime;

    let attest: AttestArgs =
        serde_json::from_str(&opts.attest).context("parse --attest as AttestArgs JSON")?;
    let verify: VerifyArgs =
        serde_json::from_str(&opts.verify).context("parse --verify as VerifyArgs JSON")?;

    let peer_shared = PeerSharedArgs {
        rotation_interval: opts.rotation_interval,
        host: opts.host,
        port: opts.port,
        peers: opts.peers,
        peers_file: opts.peers_file,
        ra_args: RaArgsUnchecked {
            no_ra: false,
            attest: Some(attest),
            verify: Some(verify),
        },
    };

    // Reuse the current tokio runtime under a graceful-shutdown guard. The
    // shutdown signal stays pending: serve() itself stops on Ctrl-C, and the
    // guard keeps the engine's supervised tasks armed for the daemon's life.
    let shutdown = tokio_graceful::Shutdown::new(async {
        std::future::pending::<()>().await;
    });
    let runtime =
        TokioRuntime::current(shutdown.guard()).context("acquire tokio runtime for key-sync")?;

    let daemon = KeySyncDaemon::new(runtime, peer_shared, opts.out_dir, opts.ready_file).await?;
    daemon.serve().await
}
