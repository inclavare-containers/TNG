use std::str::FromStr;

use anyhow::{bail, Context, Result};
use clap::{arg, Parser};
use egress::AddEgressArgs;
use ingress::AddIngressArgs;

pub mod egress;
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

    /// The egress TCP connection destination (ip:port) to forward to
    #[arg(long, value_parser = clap::value_parser!(AddEgressArgs))]
    pub add_egress: Vec<AddEgressArgs>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Endpoint {
    pub host: Option<String>,
    pub port: u16,
}

impl FromStr for Endpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 1 {
            let port = s
                .parse::<u16>()
                .with_context(|| format!("Invalid port number: {}", s))?;
            return Ok(Endpoint { host: None, port });
        } else if parts.len() == 2 {
            let host_str = parts[0];
            let port_str = parts[1];

            let host = host_str.to_owned();
            let port = port_str
                .parse::<u16>()
                .with_context(|| format!("Invalid port number: {}", port_str))?;

            return Ok(Endpoint {
                host: Some(host),
                port,
            });
        } else {
            bail!("Invalid endpoint format. Expected 'host:port' or 'port'")
        }
    }
}
