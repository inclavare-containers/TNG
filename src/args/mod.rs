use clap::{arg, Parser};
use ingress::AddIngressArgs;

pub mod ingress;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub enum Args {
    #[command(name = "launch")]
    Launch(LaunchOptions),
}

#[derive(Parser, Debug)]
pub struct LaunchOptions {
    /// The ingress TCP connection destination (ip:port) to capture
    #[arg(long, value_parser = clap::value_parser!(AddIngressArgs))]
    pub add_ingress: Vec<AddIngressArgs>,
}
