use std::{fs::File, io::BufReader};

use anyhow::{bail, Result};
use clap::Parser as _;
use cli::Args;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tng::config::TngConfig;
use tng::{build, TngBuilder};

mod cli;

#[tokio::main]

async fn main() -> Result<()> {
    // Initialize rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize log tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "none,tng=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cmd = Args::parse();

    tracing::info!(
        r#"
  _______   ________
 /_  __/ | / / ____/
  / / /  |/ / / __  
 / / / /|  / /_/ /  Welcome to the Trusted Network Gateway!
/_/ /_/ |_/\____/   version: v{}  commit: {}  buildtime: {}"#,
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
                    tracing::info!("Loading config from: {path:?}");
                    let file = File::open(path)?;
                    let reader = BufReader::new(file);
                    serde_json::from_reader(reader)? // TODO: 显示详细的错误，并在具体的json字符串位置上标出，看下serde有没有自带这个功能
                }
            };

            tracing::debug!("TNG config: {config:#?}");

            TngBuilder::from_config(config).serve_forever().await?;

            tracing::info!("Gracefully exit now");
        }
    }

    Ok(())
}
