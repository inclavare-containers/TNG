#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use std::{fs::File, io::BufReader};

use anyhow::{bail, Context};
use clap::Parser as _;
use cli::{Cli, GlobalSubcommand};
use tng::runtime::TngRuntime;
use tracing_subscriber::Layer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tng::build;
use tng::config::TngConfig;

mod cli;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize rustls crypto provider
    #[allow(clippy::expect_used)]
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize log tracing
    let pending_tracing_layers = vec![];
    let (pending_tracing_layers, reload_handle) =
        tracing_subscriber::reload::Layer::new(pending_tracing_layers);
    let subscriber_init = tracing_subscriber::registry()
        // Here we add two layer each has it's own filter (per-layer filter), and the first layer is
        // a vector which can be updated dynamically later(e.g. to append a layer like otlp exporter).
        .with(
            pending_tracing_layers.with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,tokio_graceful=off,rats_cert=trace,tng=trace".into()),
            ),
        )
        .with(
            tracing_subscriber::fmt::layer().with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,tokio_graceful=off,rats_cert=info,tng=info".into()),
            ),
        );
    if cli.tokio_console {
        // Initialize tokio console
        subscriber_init.with(console_subscriber::spawn()).init();
    } else {
        subscriber_init.init();
    }

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

    tracing::info!("Current process PID: {}", std::process::id());

    let fut = async {
        match cli.command {
            GlobalSubcommand::Launch(options) => {
                // Load config
                let config: TngConfig = async {
                    Ok::<_, anyhow::Error>(match (options.config_file, options.config_content) {
                        (Some(_), Some(_)) => {
                            bail!("Cannot set both --config-file and --config-content at the same time")
                        }
                        (None, None) => {
                            bail!("Either --config-file or --config-content should be set")
                        }
                        (None, Some(s)) => serde_json::from_str(&s)?,
                        (Some(path), None) => {
                            tracing::info!("Loading config from: {path:?}");
                            let file = File::open(path)?;
                            let reader = BufReader::new(file);
                            serde_json::from_reader(reader)?
                        }
                    })
                }
                .await
                .context("Failed to load config")?;

                tracing::debug!("TNG config: {config:#?}");

                tracing::info!("Starting tng instance now");
                TngRuntime::from_config_with_reload_handle(config, &reload_handle)
                    .await?
                    .serve()
                    .await?;

                tracing::info!("Gracefully exit now");
            }
        }

        Ok::<_, anyhow::Error>(())
    };

    if let Err(error) = fut.await {
        tracing::error!(error = format!("{error:#}"));
        std::process::exit(1);
    }
}
