use std::{
    io::Write as _,
    path::{Path, PathBuf},
    process::Command,
};

use crate::config::{
    egress::EgressMode,
    ingress::{EndpointFilter, IngressMode},
    TngConfig,
};
use anyhow::{bail, Context, Result};
use iptables::{IpTablesAction, IpTablesActions};
use log::{debug, info, warn};

mod envoy;
mod iptables;

pub struct RuntimeData {
    envoy_config: String,
    envoy_config_file: PathBuf,
    iptables_invoke_script: String,
    iptables_revoke_script: String,
}

const NETFILTER_LISTEN_PORT_DEFAULT: u16 = 40000;
const NETFILTER_SO_MARK_DEFAULT: u32 = 565;

impl RuntimeData {
    pub fn new(config: TngConfig) -> Result<Self> {
        let (envoy_config, iptables_actions) = handle_config(config)?;

        // Write config to temp file
        let temp_file = tempfile::Builder::new()
            .prefix(".tng-envoy-conf-")
            .suffix(".yaml")
            .tempfile()
            .context("Failed to create temp file")?;
        let (mut temp_file, temp_file_path) = temp_file.keep()?;

        temp_file
            .write_all(envoy_config.as_bytes())
            .expect("Failed to write data");

        let (iptables_invoke_script, iptables_revoke_script) = iptables_actions.gen_script()?;

        Ok(RuntimeData {
            envoy_config,
            envoy_config_file: temp_file_path,
            iptables_invoke_script,
            iptables_revoke_script,
        })
    }

    pub fn envoy_clean_up(&self) {
        let _ = std::fs::remove_file(&self.envoy_config_file);
    }

    pub fn envoy_config(&self) -> &str {
        &self.envoy_config
    }

    pub fn envoy_config_file(&self) -> &Path {
        &self.envoy_config_file
    }

    pub fn iptable_setup(&self) -> Result<()> {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(&format!("set -e ; true ; {}", self.iptables_invoke_script));
        let output = cmd.output();

        match output {
            Ok(output) => {
                debug!(
                    "iptable_setup: script:\n{cmd:?}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );

                if output.status.success() {
                    info!("iptable_setup: iptables script executed successfully");
                } else {
                    bail!(
                        "iptable_setup: failed to execute iptables script, stderr: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
            Err(e) => {
                bail!("iptable_setup: Failed to execute command: {e}");
            }
        }
        Ok(())
    }

    pub fn iptable_clean_up(&self) -> Result<()> {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(&format!("set -e ; true ; {}", self.iptables_revoke_script));
        let output = cmd.output();

        match output {
            Ok(output) => {
                debug!(
                    "iptable_clean_up: script:\n{cmd:?}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );

                if output.status.success() {
                    info!("iptable_clean_up: iptables script executed successfully");
                } else {
                    bail!(
                        "iptable_clean_up: failed to execute iptables script, stderr: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
            Err(e) => {
                bail!("iptable_clean_up: Failed to execute command: {e}");
            }
        }
        Ok(())
    }
}

fn handle_config(config: TngConfig) -> Result<(String, IpTablesActions)> {
    let mut listeners = vec![];
    let mut clusters = vec![];

    let mut iptables_actions = vec![];
    for (id, add_ingress) in config.add_ingress.iter().enumerate() {
        if add_ingress.attest == None && add_ingress.verify == None && add_ingress.no_ra == false {
            bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_ingress'");
        }

        if add_ingress.no_ra {
            warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment")
        }

        match &add_ingress.ingress_mode {
            IngressMode::Mapping { r#in, out } => {
                let in_addr = r#in.host.as_deref().unwrap_or("0.0.0.0");
                let in_port = r#in.port;

                let out_addr = out
                    .host
                    .as_deref()
                    .context("'host' of 'out' field must be set")?;
                let out_port = out.port;

                let mut yamls = match &add_ingress.encap_in_http {
                    Some(encap_in_http) => self::envoy::ingress::mapping::l7::gen(
                        id,
                        in_addr,
                        in_port,
                        out_addr,
                        out_port,
                        encap_in_http,
                        add_ingress.no_ra,
                        &add_ingress.attest,
                        &add_ingress.verify,
                    )?,
                    None => self::envoy::ingress::mapping::l4::gen(
                        id,
                        in_addr,
                        in_port,
                        out_addr,
                        out_port,
                        add_ingress.no_ra,
                        &add_ingress.attest,
                        &add_ingress.verify,
                    )?,
                };
                listeners.append(&mut yamls.0);
                clusters.append(&mut yamls.1);
            }
            IngressMode::HttpProxy {
                proxy_listen,
                dst_filter: EndpointFilter { domain, port },
            } => {
                let proxy_listen_addr = proxy_listen.host.as_deref().unwrap_or("0.0.0.0");
                let proxy_listen_port = proxy_listen.port;
                let domain = domain.as_deref().unwrap_or("*");
                let port = port.unwrap_or(80); // Default port is 80

                let mut yamls = match &add_ingress.encap_in_http {
                    Some(_encap_in_http) => todo!(),
                    None => self::envoy::ingress::http_proxy::l4::gen(
                        id,
                        proxy_listen_addr,
                        proxy_listen_port,
                        domain,
                        port,
                        add_ingress.no_ra,
                        &add_ingress.attest,
                        &add_ingress.verify,
                    )?,
                };
                listeners.append(&mut yamls.0);
                clusters.append(&mut yamls.1);
            }
            IngressMode::Netfilter { dst: _ } => todo!(),
        }
    }

    for (id, add_egress) in config.add_egress.iter().enumerate() {
        if add_egress.attest == None && add_egress.verify == None && add_egress.no_ra == false {
            bail!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_egress'");
        }

        if add_egress.no_ra {
            warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment")
        }

        match &add_egress.egress_mode {
            EgressMode::Mapping { r#in, out } => {
                let in_addr = r#in.host.as_deref().unwrap_or("0.0.0.0");
                let in_port = r#in.port;

                let out_addr = out
                    .host
                    .as_deref()
                    .context("'host' of 'out' field must be set")?;
                let out_port = out.port;

                let mut yamls = if add_egress.decap_from_http {
                    self::envoy::egress::mapping::l7::gen(
                        id,
                        in_addr,
                        in_port,
                        out_addr,
                        out_port,
                        add_egress.no_ra,
                        &add_egress.attest,
                        &add_egress.verify,
                    )?
                } else {
                    self::envoy::egress::mapping::l4::gen(
                        id,
                        in_addr,
                        in_port,
                        out_addr,
                        out_port,
                        add_egress.no_ra,
                        &add_egress.attest,
                        &add_egress.verify,
                    )?
                };
                listeners.append(&mut yamls.0);
                clusters.append(&mut yamls.1);
            }
            EgressMode::Netfilter {
                capture_dst,
                listen_port,
                so_mark,
            } => {
                let listen_port =
                    listen_port.unwrap_or(NETFILTER_LISTEN_PORT_DEFAULT + (id as u16));
                let so_mark = so_mark.unwrap_or(NETFILTER_SO_MARK_DEFAULT);

                iptables_actions.push(IpTablesAction::Redirect {
                    capture_dst: capture_dst.clone(),
                    listen_port,
                    so_mark,
                });

                let mut yamls = if add_egress.decap_from_http {
                    self::envoy::egress::netfilter::l7::gen(
                        id,
                        listen_port,
                        so_mark,
                        add_egress.no_ra,
                        &add_egress.attest,
                        &add_egress.verify,
                    )?
                } else {
                    self::envoy::egress::netfilter::l4::gen(
                        id,
                        listen_port,
                        so_mark,
                        add_egress.no_ra,
                        &add_egress.attest,
                        &add_egress.verify,
                    )?
                };
                listeners.append(&mut yamls.0);
                clusters.append(&mut yamls.1);
            }
        }
    }
    let config = format!(
        r#"
bootstrap_extensions:
- name: envoy.bootstrap.internal_listener
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener

static_resources:

  listeners:{}

  clusters:{}
"#,
        listeners.join("\n"),
        clusters.join("\n")
    );
    Ok((config, IpTablesActions::new(iptables_actions)))
}
