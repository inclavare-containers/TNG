use crate::task::tng::TngInstance;
use anyhow::Result;
use tokio::process::Command;

impl TngInstance {
    pub(super) async fn get_tokio_command(&self, config_json: &str) -> Result<Command> {
        let mut cmd = tokio::process::Command::new("tng");
        cmd.arg("launch").arg("--config-content").arg(config_json);

        Ok(cmd)
    }
}
