use crate::task::tng::TngInstance;
use anyhow::Result;
use tokio::process::Command;

impl TngInstance {
    pub(super) async fn get_tokio_command(&self, config_json: &str) -> Result<Command> {
        let image_url = std::env::var("TNG_TESTSUITE_TNG_IMAGE_URL")
            .unwrap_or("ghcr.io/inclavare-containers/tng:latest".to_string());
        tracing::info!("Using TNG image url: {image_url}");

        let mut cmd = tokio::process::Command::new("podman");
        cmd.arg("run")
            .arg("--rm")
            .arg("--privileged")
            .arg("--network=host")
            .arg("--cgroupns=host")
            .args([
                "-v", "/run/confidential-containers/attestation-agent/:/run/confidential-containers/attestation-agent/"
            ])
            .args([
                "-v", "/tmp/:/tmp/"
            ])
            .arg(image_url)
            .arg("tng")
            .arg("launch")
            .arg("--config-content")
            .arg(config_json);
        Ok(cmd)
    }
}
