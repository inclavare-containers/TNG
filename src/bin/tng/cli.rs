use std::path::PathBuf;

use clap::{arg, Parser};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub enum Args {
    #[command(name = "launch")]
    Launch(LaunchOptions),
}

#[derive(Parser, Debug)]
pub struct LaunchOptions {
    #[arg(short, long)]
    pub config_file: Option<PathBuf>,

    #[arg(long)]
    pub config_content: Option<String>,
}
