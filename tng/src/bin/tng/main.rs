#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use std::{
    fs::{File, OpenOptions},
    io::BufReader,
};

use anyhow::{bail, Context};
use clap::Parser as _;
use cli::{Cli, GlobalSubcommand};
use tng::config::egress::EgressMode;
use tng::config::ingress::IngressMode;
use tng::config::TngConfig;
use tng::runtime::TngRuntime;
use tng::{build, show_banner};
use tracing_subscriber::Layer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cli;

/// Reject hook modes when running via `tng launch`.
/// Hook modes (IngressMode::Hook, EgressMode::Hook) are only allowed via `tng exec`.
fn reject_hook_modes(config: &TngConfig) -> anyhow::Result<()> {
    for (i, ingress) in config.add_ingress.iter().enumerate() {
        if matches!(ingress.ingress_mode, IngressMode::Hook(_)) {
            anyhow::bail!(
                "Ingress entry {} uses 'hook' mode, which is only allowed via `tng exec`, not `tng launch`",
                i
            );
        }
    }
    for (i, egress) in config.add_egress.iter().enumerate() {
        if matches!(egress.egress_mode, EgressMode::Hook(_)) {
            anyhow::bail!(
                "Egress entry {} uses 'hook' mode, which is only allowed via `tng exec`, not `tng launch`",
                i
            );
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize rustls crypto provider
    #[allow(clippy::expect_used)]
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize log tracing
    let pending_tracing_layers = vec![];
    let (pending_tracing_layers, reload_handle) =
        tracing_subscriber::reload::Layer::new(pending_tracing_layers);

    // Open log file if --log-file is specified.
    // We always create a NonBlocking writer (either file-backed or stdout-backed)
    // so that both branches produce the same concrete Layer type.
    let (log_writer, is_file) = match &cli.log_file {
        Some(path) => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .context("Failed to open log file")?;
            let (non_blocking, guard) = tracing_appender::non_blocking(file);
            // Leak the guard to keep the worker thread alive for the process
            // lifetime. This is safe because the guard is never dropped until
            // process exit, at which point the OS cleans up anyway.
            std::mem::forget(guard);
            (non_blocking, true)
        }
        None => {
            let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
            std::mem::forget(guard);
            (non_blocking, false)
        }
    };

    let subscriber_init = tracing_subscriber::registry()
        .with(
            pending_tracing_layers.with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,tokio_graceful=off,rats_cert=trace,tng=trace".into()),
            ),
        )
        .with({
            let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tokio_graceful=off,rats_cert=info,tng=info".into());

            let base_layer = tracing_subscriber::fmt::layer().with_writer(log_writer.clone());
            if is_file {
                base_layer.with_ansi(false).with_filter(filter)
            } else {
                base_layer
                    .with_ansi(atty::is(atty::Stream::Stdout))
                    .with_filter(filter)
            }
        });

    #[cfg(unix)]
    if cli.tokio_console {
        subscriber_init.with(console_subscriber::spawn()).init();
    } else {
        subscriber_init.init();
    }

    #[cfg(not(unix))]
    {
        if cli.tokio_console {
            eprintln!("Warning: --tokio-console is not supported on this platform. Ignoring.");
        }
        subscriber_init.init();
    }

    let fut = async {
        match cli.command {
            GlobalSubcommand::Launch(options) => {
                show_banner("daemon");

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
                            tracing::info!(?path, "Loading config from");
                            let file = File::open(path)?;
                            let reader = BufReader::new(file);
                            serde_json::from_reader(reader)?
                        }
                    })
                }
                .await
                .context("Failed to load config")?;

                tracing::debug!(?config, "TNG config");

                // Hook modes are only allowed via `tng exec`, not `tng launch`.
                reject_hook_modes(&config)?;

                tracing::info!("Starting tng instance now");
                TngRuntime::from_config_with_reload_handle(config, &reload_handle)
                    .await?
                    .serve()
                    .await?;

                tracing::info!("Exited gracefully");
            }
            GlobalSubcommand::Exec(options) => {
                show_banner("exec");

                use tng::exec::TngExec;

                let config: TngConfig = {
                    match (options.config_file, options.config_content) {
                        (Some(_), Some(_)) => {
                            bail!("Cannot set both --config-file and --config-content at the same time")
                        }
                        (None, None) => {
                            bail!("Either --config-file or --config-content should be set")
                        }
                        (None, Some(s)) => serde_json::from_str(&s)?,
                        (Some(path), None) => {
                            tracing::info!(?path, "Loading config from");
                            let file = File::open(path)?;
                            let reader = BufReader::new(file);
                            serde_json::from_reader(reader)?
                        }
                    }
                };

                TngExec::run(
                    config,
                    options.command,
                    &reload_handle,
                    cli.log_file.as_ref(),
                )
                .await?;

                tracing::info!("Exec session ended");
            }
        }

        Ok::<_, anyhow::Error>(())
    };

    if let Err(error) = fut.await {
        tracing::error!(?error);
        std::process::exit(1);
    }

    Ok(())
}
