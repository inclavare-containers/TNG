use std::{fs::File, io::BufReader};

use anyhow::{bail, Context};
use clap::Parser as _;
use cli::Args;
use tng::runtime::TngRuntime;
use tracing_subscriber::Layer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tng::build;
use tng::config::TngConfig;

mod cli;

#[tokio::main]

async fn main() {
    // Initialize rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize log tracing
    let pending_tracing_layers = vec![];
    let (pending_tracing_layers, reload_handle) =
        tracing_subscriber::reload::Layer::new(pending_tracing_layers);
    tracing_subscriber::registry()
        // Here we add two layer each has it's own filter (per-layer filter), and the first layer is
        // a vector which can be updated dynamically later(e.g. to append a layer like otlp exporter).
        .with(
            pending_tracing_layers.with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,tokio_graceful=off,tng=trace".into()),
            ),
        )
        .with(tracing_subscriber::fmt::layer().with_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tokio_graceful=off".into()),
        ))
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

    let fut = async {
        match cmd {
            Args::Launch(options) => {
                // Load config
                let config: TngConfig = async {
                    Ok::<_, anyhow::Error>(match (options.config_file, options.config_content) {
                        (Some(_), Some(_)) | (None, None) => {
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

                TngRuntime::from_config_with_reload_handle(config, &reload_handle)
                    .await?
                    .serve_forever()
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
