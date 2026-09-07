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
use tng_hook_types::LogFormat;
use tracing_subscriber::Layer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cli;
mod log_opts;

/// Install a built subscriber, optionally layering tokio-console on top.
///
/// `console_subscriber` is only available on unix (native builds). The non-unix
/// path warns and ignores `--tokio-console` rather than silently dropping it.
/// Both the json and text subscriber shapes funnel through this macro so the
/// console/init tail isn't duplicated per branch. The `tokio_console` flag is
/// passed in (rather than capturing `cli`) so the macro stays hygienic and
/// doesn't resolve `cli` to the `cli` module at expansion time.
macro_rules! install_subscriber {
    ($sub:expr, $tokio_console:expr) => {{
        let sub = $sub;
        let tokio_console: bool = $tokio_console;
        #[cfg(unix)]
        {
            if tokio_console {
                sub.with(console_subscriber::spawn()).init();
            } else {
                sub.init();
            }
        }
        #[cfg(not(unix))]
        {
            if tokio_console {
                eprintln!("Warning: --tokio-console is not supported on this platform. Ignoring.");
            }
            sub.init();
        }
    }};
}

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

    // Resolve log format: env TNG_LOG_FORMAT takes priority over --log-format,
    // defaulting to plain text. Done before tracing init so the fmt layer can
    // be built in the right shape (json vs text). An invalid env value defers
    // a warning until *after* init (below) so it lands in the log stream
    // rather than being dropped by an uninitialised subscriber.
    let resolved = log_opts::resolve_log_format(cli.log_format);

    let rolling = log_opts::resolve_rolling(
        cli.log_rolling,
        cli.log_max_size.as_deref(),
        cli.log_max_backups,
    );

    // Resolve the error log file: env TNG_LOG_ERROR_FILE > --log-error-file >
    // None. When None, ERROR events go to the main --log-file (current
    // behavior). Done before tracing init so the error writer can be built
    // alongside the info writer.
    let error_file = log_opts::resolve_error_file(cli.log_error_file);

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
    // so that both branches produce the same concrete Layer type. Rolling-related
    // warnings (path not a regular file, or no --log-file) are collected here and
    // emitted via `tracing::warn!` AFTER the subscriber is initialized below, so
    // they land in the configured log stream (json/text) rather than only on
    // stderr.
    let mut writer_warnings: Vec<String> = Vec::new();
    // The non-blocking WorkerGuard is returned from every arm and kept alive
    // in `main`'s scope (NOT `mem::forget`-ed). On normal return or unwind,
    // its Drop signals the worker to drain its channel and flush the inner
    // writer (incl. the rolling appender's BufWriter) — this prevents log
    // loss on shutdown. `std::process::exit` skips destructors, so the error
    // path below drops it explicitly before exiting.
    let (log_writer, worker_guard, is_file) = match &cli.log_file {
        Some(path) if rolling.config.enabled && tng::rolling::path_supports_rolling(path) => {
            let appender = tracing_rolling_file::RollingFileAppenderBase::new(
                path,
                tracing_rolling_file::RollingConditionBase::new().max_size(rolling.config.max_size),
                rolling.config.max_backups,
            )
            .context("Failed to open rolling log file")?;
            let (non_blocking, guard) = tracing_appender::non_blocking(appender);
            (non_blocking, guard, true)
        }
        Some(path) => {
            if rolling.config.enabled {
                writer_warnings.push(format!(
                    "--log-rolling ignored for {}: not a regular file (e.g. character device/terminal); using plain append",
                    path.display()
                ));
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .context("Failed to open log file")?;
            let (non_blocking, guard) = tracing_appender::non_blocking(file);
            (non_blocking, guard, true)
        }
        None => {
            if rolling.config.enabled {
                writer_warnings.push(
                    "--log-rolling ignored: no --log-file (stdout); using non-rolling stdout"
                        .into(),
                );
            }
            let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
            (non_blocking, guard, false)
        }
    };

    // Build the error writer when --log-error-file is set. The error path
    // MUST be a real file (no stdout fallback): rolling when the path supports
    // it and rolling is enabled, otherwise plain append. A second non-blocking
    // writer + guard is created so ERROR+ events are buffered and flushed on
    // exit just like the info stream. When error_file is None, no error
    // writer/guard is produced and routing falls back to the info writer.
    let (error_writer, error_guard) = match &error_file {
        Some(path) if rolling.config.enabled && tng::rolling::path_supports_rolling(path) => {
            let appender = tracing_rolling_file::RollingFileAppenderBase::new(
                path,
                tracing_rolling_file::RollingConditionBase::new().max_size(rolling.config.max_size),
                rolling.config.max_backups,
            )
            .context("Failed to open rolling error log file")?;
            let (non_blocking, guard) = tracing_appender::non_blocking(appender);
            (Some(non_blocking), Some(guard))
        }
        Some(path) => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .context("Failed to open error log file")?;
            let (non_blocking, guard) = tracing_appender::non_blocking(file);
            (Some(non_blocking), Some(guard))
        }
        None => (None, None),
    };

    // Wrap the info and (optional) error writers in a LevelRoutingWriter so
    // ERROR+ events route to the error file when set, and everything else goes
    // to the info writer. When error is None the router forwards all events
    // to the info writer (current behavior). Using a uniform
    // `LevelRoutingWriter<NonBlocking, NonBlocking>` type in both cases avoids
    // branching the subscriber construction on whether the error file is set:
    // the json/text arms each take a single concrete writer type.
    // Clone `error_writer` here (not move) so the `Exec` arm can hand another
    // clone to `TngExec::run` for the hook-log collector. NonBlocking clones
    // share the same underlying worker, so multiple clones funnel into one
    // file without contention.
    let routed_writer =
        tng_hook_types::LevelRoutingWriter::new(log_writer.clone(), error_writer.clone());

    // Build the subscriber. JSON and text fmt layers have different concrete
    // types and cannot be unified by boxing a `dyn Layer` (the fmt layer sits
    // on top of the reload layer, so it must satisfy
    // `Layer<Layered<reload, Registry>>`, not just `Layer<Registry>`). Branch
    // on the resolved `LogFormat` enum (no `bool`/`&str` leakage) and funnel
    // both shapes through the `install_subscriber!` macro. `pending` is moved
    // into exactly one arm (only one runs at runtime).
    let reload_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,tokio_graceful=off,rats_cert=trace,tng=trace".into());
    let fmt_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,tokio_graceful=off,rats_cert=info,tng=info".into());
    let pending = pending_tracing_layers.with_filter(reload_filter);

    match resolved.format {
        LogFormat::Json => {
            let sub = tracing_subscriber::registry().with(pending).with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(routed_writer)
                    .with_ansi(false)
                    .with_filter(fmt_filter),
            );
            install_subscriber!(sub, cli.tokio_console);
        }
        LogFormat::Text => {
            let ansi = if is_file {
                false
            } else {
                atty::is(atty::Stream::Stdout)
            };
            let sub = tracing_subscriber::registry().with(pending).with(
                tracing_subscriber::fmt::layer()
                    .with_writer(routed_writer)
                    .with_ansi(ansi)
                    .with_filter(fmt_filter),
            );
            install_subscriber!(sub, cli.tokio_console);
        }
    }

    // Emit any deferred invalid-env warning now that the subscriber is live.
    if let Some(warning) = &resolved.invalid_env_warning {
        tracing::warn!("{warning}");
    }

    for warning in &rolling.warnings {
        tracing::warn!("{warning}");
    }

    for warning in &writer_warnings {
        tracing::warn!("{warning}");
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
                Ok::<i32, anyhow::Error>(0)
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

                let exit_code = TngExec::run(
                    config,
                    options.command,
                    &reload_handle,
                    cli.log_file.as_ref(),
                    Some(&resolved.format),
                    error_file.as_ref(),
                    log_writer.clone(),
                    error_writer.clone(),
                )
                .await?;

                tracing::info!(exit_code, "Exec session ended");
                Ok::<i32, anyhow::Error>(exit_code)
            }
        }
    };

    match fut.await {
        Ok(exit_code) => {
            // Normal completion. `std::process::exit` skips destructors, so
            // drop the non-blocking worker guards explicitly: their Drop signals
            // the workers to drain their channels and flush the inner writers
            // (incl. the rolling appenders' BufWriters). Without this, `tng
            // exec` would lose buffered logs on shutdown — the workers would be
            // killed mid-flush by the exit. Both the info guard and the
            // (optional) error guard must be flushed.
            drop(worker_guard);
            if let Some(g) = error_guard {
                drop(g);
            }
            std::process::exit(exit_code);
        }
        Err(error) => {
            tracing::error!(?error);
            // Same flush-before-exit on the error path.
            drop(worker_guard);
            if let Some(g) = error_guard {
                drop(g);
            }
            std::process::exit(1);
        }
    }
}
