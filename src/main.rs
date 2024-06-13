use std::{
    fs::File,
    io::{BufReader, Write as _},
    process::Command,
};

use anyhow::{bail, Context, Result};
use args::Args;
use clap::Parser as _;
use config::TngConfig;
use log::{debug, info};

mod args;
mod confgen;
mod config;

fn main() -> Result<()> {
    let env = env_logger::Env::default()
        .filter_or("TNG_LOG_LEVEL", "debug")
        .write_style_or("TNG_LOG_STYLE", "always"); // enable color
    env_logger::Builder::from_env(env).init();

    let cmd = Args::parse();
    info!("Welcome to TNG!");
    debug!("cmd: {cmd:?}");

    match cmd {
        Args::Launch(options) => {
            // Load config
            let config: TngConfig = match (options.config_file, options.config_content) {
                (Some(_), Some(_)) | (None, None) => {
                    bail!("Either --config_file or --config_content should be set")
                }
                (None, Some(s)) => serde_json::from_str(&s)?,
                (Some(path), None) => {
                    let file = File::open(path)?;
                    let reader = BufReader::new(file);
                    serde_json::from_reader(reader)?
                }
            };

            let envoy_config = confgen::gen_envoy_config(config)?;

            debug!("Generated Envoy config: {envoy_config}");

            // Write config to temp file
            let temp_file = tempfile::Builder::new()
                .prefix(".tng-envoy-conf-")
                .suffix(".yaml")
                .tempfile()
                .context("Failed to create temp file")?;
            let (mut temp_file, temp_file_path) = temp_file.keep()?;

            temp_file
                .write_all(envoy_config.as_bytes())
                .expect("Failed to write data");

            info!("Generated Envoy config written to: {temp_file_path:?}");

            // Start Envoy
            let mut cmd = Command::new("/envoy_librats/bazel-bin/source/exe/envoy-static");
            cmd.arg("-c")
                .arg(&temp_file_path)
                .arg("-l")
                .arg("debug")
                .arg("--base-id")
                .arg(std::process::id().to_string()); // Use pid of tng process as base-id of envoy to avoid conflicts
            let mut child = cmd
                .spawn()
                .with_context(|| format!("Failed to start Envoy with cmd: {cmd:?}"))?;
            info!("Envoy started with PID: {}", child.id());

            // Wait for envoy exiting
            ctrlc::set_handler(move || {
                info!("Received Ctrl+C, prepare for exiting now");
            })
            .expect("Error setting Ctrl-C handler");

            let exit_status = child.wait().context("Failed to wait for Envoy process")?;
            info!("Envoy exited with status {exit_status}");

            if exit_status.success() {
                let _ = std::fs::remove_file(temp_file_path);
                info!("TNG now exit gracefully");
            } else {
                bail!("Envoy exited with unexpected status {exit_status}, cmd: {cmd:?}")
            }
        }
    }

    Ok(())
}
