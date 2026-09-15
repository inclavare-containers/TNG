use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum ToolsCommand {
    /// rats-tls certificate tools
    #[command(subcommand)]
    RatsTls(RatsTlsCommand),
    /// ohttp key-config tools
    #[command(subcommand)]
    Ohttp(OhttpCommand),
    /// decentralized HPKE key-sync daemon (serf)
    KeySync(KeySyncOptions),
}

#[derive(Subcommand, Debug)]
pub enum RatsTlsCommand {
    /// generate a rats-tls cert locally from an attest config
    Gen {
        #[arg(long, value_name = "JSON")]
        attest: String,
        #[arg(long, value_name = "PEM")]
        cert_out: Option<PathBuf>,
        #[arg(long, value_name = "PEM")]
        key_out: Option<PathBuf>,
    },
    /// capture a rats-tls server cert from a live endpoint
    Dump {
        #[arg(long)]
        endpoint: String,
        #[arg(long, value_name = "JSON")]
        attest: Option<String>,
        #[arg(long, value_name = "PEM")]
        cert_out: Option<PathBuf>,
    },
    /// verify a rats-tls cert against a verify config
    Verify {
        #[arg(long)]
        cert: PathBuf,
        #[arg(long, value_name = "JSON")]
        verify: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum OhttpCommand {
    /// dump an ohttp server's key-config response JSON
    Dump {
        #[arg(long)]
        endpoint: String,
        /// passport | backgroundcheck:<token> | none
        #[arg(long, value_name = "MODEL[:token]")]
        attest_request: Option<String>,
        #[arg(long, value_name = "JSON")]
        out: Option<PathBuf>,
    },
    /// verify the attestation in a dumped ohttp key-config JSON
    Verify {
        #[arg(long)]
        keyconfig: PathBuf,
        #[arg(long, value_name = "JSON")]
        verify: String,
    },
}

#[derive(Parser, Debug)]
pub struct KeySyncOptions {
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,
    #[arg(long, default_value_t = 8301)]
    pub port: u16,
    #[arg(long = "peer", value_name = "ADDR")]
    pub peers: Vec<String>,
    #[arg(long, value_name = "PATH")]
    pub peers_file: Option<String>,
    #[arg(long, default_value_t = 300)]
    pub rotation_interval: u64,
    #[arg(long, value_name = "JSON")]
    pub attest: String,
    #[arg(long, value_name = "JSON")]
    pub verify: String,
    #[arg(long, value_name = "DIR")]
    pub out_dir: PathBuf,
    #[arg(long, value_name = "PATH")]
    pub ready_file: Option<PathBuf>,
}
