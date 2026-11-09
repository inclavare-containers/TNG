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
    /// builtin AS attestation policy tools
    #[cfg(feature = "__builtin-as")]
    #[command(subcommand)]
    Policy(PolicyCommand),
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
    /// dump an ohttp server's key-config response and derived artifacts
    Dump {
        #[arg(long)]
        endpoint: String,
        /// flat `VerifyArgs` JSON. When set, dump builds the AS converter, mints
        /// the background-check challenge token, sends the key-config request
        /// with that attestation (so the response carries `attestation_info`),
        /// and runs `verify_keyconfig_attestation` to produce the
        /// attestation-result JWT and decoded claims. Absent -> bare key config
        /// (no attestation artifacts).
        #[arg(long, value_name = "JSON")]
        verify: Option<String>,
        /// write only the raw `KeyConfigResponse` body to this file
        /// (pretty JSON). Mutually exclusive with `--out-dir`.
        #[arg(long, value_name = "FILE")]
        raw: Option<PathBuf>,
        /// write the full artifact bundle to this directory: `raw.json`,
        /// `hpke.base64`, `hpke.json`, and (with `--verify`) `quote.bin`,
        /// `eventlog.json`, `attestation_result.jwt`,
        /// `attestation_result.claims.json`. Mutually exclusive with `--raw`.
        #[arg(long, value_name = "DIR")]
        out_dir: Option<PathBuf>,
    },
    /// verify the attestation in a dumped ohttp key-config JSON
    Verify {
        #[arg(long, value_name = "FILE")]
        raw: PathBuf,
        #[arg(long, value_name = "JSON")]
        verify: String,
    },
    /// decode a dumped ohttp key-config JSON into derived artifacts without
    /// contacting the server or an AS
    Decode {
        #[arg(long, value_name = "FILE")]
        raw: PathBuf,
        /// attestation-result JWT file to also decode `claims` and `eventlog`
        /// from (the JWT payload). Without this, decode only produces
        /// `hpke.*` and `quote.bin` from the raw body.
        #[arg(long, value_name = "FILE")]
        attestation_result: Option<PathBuf>,
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,
    },
}

#[cfg(feature = "__builtin-as")]
#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// render the Rego a builtin AS loads from a TNG config or an attestation_policy value
    Export {
        /// full TNG config file; `-` reads stdin. JSONC is accepted.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// a bare `attestation_policy` JSON value
        #[arg(long, value_name = "JSON")]
        attestation_policy: Option<String>,
        /// write one `<path>.rego` per policy into DIR; default: stdout
        #[arg(long, value_name = "DIR")]
        out_dir: Option<PathBuf>,
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
