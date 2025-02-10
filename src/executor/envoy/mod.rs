use std::path::Path;

use anyhow::{Context as _, Result};
use log::{debug, error, info};
use rand::Rng as _;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;
use tokio_graceful::ShutdownGuard;
use tokio_util::sync::CancellationToken;
use which::which;

pub mod confgen;

const ENVOY_EXE_PATH_DEFAULT: &str = "/usr/lib64/tng/envoy-static";

pub struct EnvoyConfig(pub String);

pub struct EnvoyExecutor {}

impl EnvoyExecutor {
    pub async fn serve(
        envoy_config: &EnvoyConfig,
        shutdown_guard: ShutdownGuard,
        task_exit: CancellationToken,
    ) -> Result<()> {
        info!("Launching Envoy now");
        // Write config to temp file
        let temp_file = tempfile::Builder::new()
            .prefix(".tng-envoy-conf-")
            .suffix(".yaml")
            .tempfile()
            .context("Failed to create temp file")?;
        let (temp_file, config_file_path) = temp_file.keep()?;

        let mut temp_file = tokio::fs::File::from_std(temp_file);

        temp_file
            .write_all(envoy_config.0.as_bytes())
            .await
            .context("Failed to write Envoy config to file")?;

        info!("Generated Envoy config written to: {config_file_path:?}");

        // Seach for envoy-static binary
        let envoy_exe = match which("envoy-static") {
            Ok(p) => p,
            Err(_) => {
                let path = Path::new(ENVOY_EXE_PATH_DEFAULT);
                if path.exists() {
                    path.into()
                } else {
                    std::env::current_exe()
                        .context("Failed to get current exe path")?
                        .parent()
                        .unwrap()
                        .join("envoy-static")
                }
            }
        };

        debug!("Trying envoy executable path: {envoy_exe:?}");
        let mut cmd = Command::new(envoy_exe);
        cmd.arg("-c")
            .arg(&config_file_path)
            .arg("-l")
            .arg("info")
            .arg("--component-log-level")
            .arg("rats_tls:debug")
            .arg("--base-id")
            .arg(rand::thread_rng().gen::<u32>().to_string());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to start Envoy with cmd: {cmd:?}"))?;
        let pid = child.id().context("Failed to get Envoy PID")?;
        info!("Envoy started with PID: {}", pid);

        tokio::select! {
            // TODO: check for the envoy is ready
            exit_status = child.wait() => {
                // the envoy process was existed, so we notify the caller
                task_exit.cancel();

                let exit_status = exit_status.context("Failed to wait for Envoy process")?;
                if exit_status.success() {
                    let _ = std::fs::remove_file(&config_file_path);
                    info!("Envoy process exited with status {exit_status}");
                }else{
                    error!("Envoy process exited with status {exit_status}");
                }
            }
            _ = shutdown_guard.cancelled() => {
                // the caller wants to shutdown the envoy process
                child.kill().await.context("Failed to kill Envoy process")?;

                let _ = std::fs::remove_file(&config_file_path);

                info!("Envoy process exited normally");
            }
        };

        Ok(())
    }
}
