pub mod cli;
pub mod key_sync;
pub mod ohttp;
pub mod rats_tls;

#[cfg(feature = "__egress-common")]
mod key_sync_daemon;

#[cfg(feature = "__egress-common")]
pub(crate) use key_sync_daemon::KeySyncDaemon;

use anyhow::Result;
use cli::ToolsCommand;

pub async fn run(cmd: ToolsCommand) -> Result<()> {
    match cmd {
        ToolsCommand::RatsTls(c) => rats_tls::run(c).await,
        ToolsCommand::Ohttp(c) => ohttp::run(c).await,
        ToolsCommand::KeySync(opts) => key_sync::run(opts).await,
    }
}
