use std::path::PathBuf;

use clap::{arg, Parser, Subcommand};

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
