use std::process::{Child, Command, ExitStatus};
use std::{io::Write as _, path::PathBuf};

use anyhow::{Context as _, Result};
use log::{debug, info};
use nix::{
    libc::pid_t,
    sys::signal::{self, Signal},
    unistd::Pid,
};
use rand::Rng as _;
use which::which;

pub mod confgen;

pub struct EnvoyConfig(pub String);

pub struct EnvoyExecutor {
    config_file: PathBuf,
    process: Child,
}

impl EnvoyExecutor {
    pub fn launch(envoy_config: &EnvoyConfig) -> Result<EnvoyExecutor> {
        info!("Launching Envoy now");
        // Write config to temp file
        let temp_file = tempfile::Builder::new()
            .prefix(".tng-envoy-conf-")
            .suffix(".yaml")
            .tempfile()
            .context("Failed to create temp file")?;
        let (mut temp_file, temp_file_path) = temp_file.keep()?;

        temp_file
            .write_all(envoy_config.0.as_bytes())
            .expect("Failed to write data");

        let config_file = temp_file_path;

        info!("Generated Envoy config written to: {config_file:?}");

        let envoy_exe = match which("envoy-static") {
            Ok(p) => p,
            Err(_) => std::env::current_exe()
                .context("Failed to get current exe path")?
                .parent()
                .unwrap()
                .join("envoy-static"),
        };

        debug!("Trying envoy executable path: {envoy_exe:?}");
        let mut cmd = Command::new(envoy_exe);
        cmd.arg("-c")
            .arg(&config_file)
            .arg("-l")
            .arg("info")
            .arg("--component-log-level")
            .arg("rats_tls:debug")
            .arg("--base-id")
            .arg(rand::thread_rng().gen::<u32>().to_string()); // Use pid of tng process as base-id of envoy to avoid conflicts
        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to start Envoy with cmd: {cmd:?}"))?;
        info!("Envoy started with PID: {}", child.id());

        Ok(EnvoyExecutor {
            config_file,
            process: child,
        })
    }

    pub fn pid(&self) -> u32 {
        self.process.id()
    }

    pub fn wait(&mut self) -> Result<ExitStatus> {
        let exit_status = self
            .process
            .wait()
            .context("Failed to wait for Envoy process")?;
        Ok(exit_status)
    }

    pub fn clean_up(&mut self) -> Result<ExitStatus> {
        match self
            .process
            .try_wait()
            .context("Failed to query envoy process status")?
        {
            Some(_) => {
                // Already exited
            }
            None => {
                // Not exited
                signal::kill(Pid::from_raw(self.process.id() as pid_t), Signal::SIGTERM)
                    .context("Failed to terminate envoy process before cleaning up")?;
            }
        }

        let exit_status = self
            .process
            .wait()
            .context("Failed to wait for Envoy process during clean up")?;

        if exit_status.success() {
            let _ = std::fs::remove_file(&self.config_file);
        }

        info!("Envoy exited with status {exit_status}");

        Ok(exit_status)
    }
}
