use std::{fs::File, io::BufReader};

use anyhow::{bail, Result};
use clap::Parser as _;
use cli::Args;
use log::{debug, info};
use shadow_rs::shadow;

use tng::config::TngConfig;
use tng::TngBuilder;

mod cli;

shadow!(build);

fn main() -> Result<()> {
    let env = env_logger::Env::default()
        .filter_or("TNG_LOG_LEVEL", "debug")
        .write_style_or("TNG_LOG_STYLE", "always"); // enable color
    env_logger::Builder::from_env(env).init();

    let cmd = Args::parse();
    info!("Welcome to TNG!");
    info!(
        "TNG version: v{}  commit: {}  buildtime: {}",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );

    match cmd {
        Args::Launch(options) => {
            // Load config
            let config: TngConfig = match (options.config_file, options.config_content) {
                (Some(_), Some(_)) | (None, None) => {
                    bail!("Either --config-file or --config-content should be set")
                }
                (None, Some(s)) => serde_json::from_str(&s)?,
                (Some(path), None) => {
                    info!("Loading config from: {path:?}");
                    let file = File::open(path)?;
                    let reader = BufReader::new(file);
                    serde_json::from_reader(reader)?
                }
            };

            debug!("TNG config: {config:#?}");

            let mut instance = TngBuilder::new(config).launch()?;

            let stopper = instance.stopper();

            // Stop when we got ctrl-c
            ctrlc::set_handler(move || {
                info!("Received Ctrl+C, prepare for exiting now");
                stopper.stop().unwrap();
            })
            .expect("Error setting Ctrl-C handler");

            instance.wait()?;
            instance.clean_up()?;
        }
    }

    Ok(())
}
