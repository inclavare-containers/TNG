use std::path::PathBuf;

use clap::{arg, Parser, Subcommand};

use tng_hook_types::LogFormat;

use crate::build::CLAP_LONG_VERSION;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[clap(long_version = CLAP_LONG_VERSION)]
pub struct Cli {
    #[command(subcommand)]
    pub command: GlobalSubcommand,

    #[clap(long, global = true)]
    /// Enable tokio console
    pub tokio_console: bool,

    #[clap(long, global = true, value_name = "FILE")]
    /// Path to log file (writes to stdout/stderr if not set)
    pub log_file: Option<PathBuf>,

    #[clap(long, global = true, value_name = "FORMAT")]
    /// Log output format: text | json.
    /// The `TNG_LOG_FORMAT` env var takes priority over this flag when set.
    pub log_format: Option<LogFormat>,
}

#[derive(Subcommand, Debug)]
pub enum GlobalSubcommand {
    #[command(name = "launch")]
    Launch(LaunchOptions),

    #[command(name = "exec")]
    Exec(ExecOptions),
}

#[derive(Parser, Debug)]
pub struct LaunchOptions {
    #[arg(short, long)]
    pub config_file: Option<PathBuf>,

    #[arg(long)]
    pub config_content: Option<String>,
}

#[derive(Parser, Debug)]
pub struct ExecOptions {
    #[arg(short, long)]
    pub config_file: Option<PathBuf>,

    #[arg(long)]
    pub config_content: Option<String>,

    /// Command to execute (everything after --)
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}
