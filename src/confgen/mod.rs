use std::{
    io::Write as _,
    path::{Path, PathBuf},
    process::Command,
};

use crate::config::{egress::EgressMode, ingress::IngressMode, TngConfig};
use anyhow::{bail, Context, Result};
use iptables::{IpTablesAction, IpTablesActions};
use log::{debug, error, info, trace};

mod iptables;

pub struct RuntimeData {
    envoy_config: String,
    envoy_config_file: PathBuf,
    iptables_invoke_script: String,
    iptables_revoke_script: String,
}

const ENVOY_DUMMY_CERT: &'static str = include_str!("servercert.pem");
const ENVOY_DUMMY_KEY: &'static str = include_str!("serverkey.pem");

const NETFILTER_LISTEN_PORT_DEFAULT: u16 = 30000;
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
        match &add_ingress.ingress_mode {
            IngressMode::Mapping { r#in, out } => {
                let in_addr = r#in.host.as_deref().unwrap_or("0.0.0.0");
                let in_port = r#in.port;

                let out_ip = out
                    .host
                    .as_deref()
                    .context("'host' of 'out' field must be set")?;
                let out_port = out.port;

                listeners.push(format!(
                    r#"
  - name: tng_ingress{id}
    address:
      socket_address:
        address: {in_addr}
        port_value: {in_port}
    filter_chains:
    - filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_proxy
          cluster: tng_ingress{id}_upstream
"#
                ));

                if add_ingress.attest == None && add_ingress.verify == None {
                    bail!("At least one of 'attest' and 'verify' field should be set for 'add_ingress'");
                }

                let mut cluster = format!(
                    r#"
  - name: tng_ingress{id}_upstream
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    load_assignment:
      cluster_name: tng_ingress{id}_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: {out_ip}
                port_value: {out_port}
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        common_tls_context:
"#
                );

                if let Some(attest) = &add_ingress.attest {
                    cluster += &format!(
                        r#"
          rats_tls_cert_generator_configs:
          - coco_attester:
              aa_addr: {}
              evidence_mode: {{}}
"#,
                        attest.aa_addr
                    );
                }

                if let Some(verify) = &add_ingress.verify {
                    cluster += &format!(
                        r#"
          validation_context:
            custom_validator_config:
              name: envoy.tls.cert_validator.rats_tls
              typed_config:
                "@type": type.inclavare-containers.io/envoy.extensions.transport_sockets.tls.v3.RatsTlsCertValidatorConfig
                coco_verifier:
                  evidence_mode:
                    as_addr: {}
                  policy_ids:
{}
                  trusted_certs_paths:
"#,
                        verify.as_addr,
                        verify
                            .policy_ids
                            .iter()
                            .map(|s| format!("                  - {s}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    );
                }

                clusters.push(cluster);
            }
            IngressMode::HttpProxy { dst: _ } => todo!(),
            IngressMode::Netfilter { dst: _ } => todo!(),
        }
    }

    for (id, add_egress) in config.add_egress.iter().enumerate() {
        match &add_egress.egress_mode {
            EgressMode::Mapping { r#in, out } => {
                let in_addr = r#in.host.as_deref().unwrap_or("0.0.0.0");
                let in_port = r#in.port;

                let out_ip = out
                    .host
                    .as_deref()
                    .context("'host' of 'out' field must be set")?;
                let out_port = out.port;

                if add_egress.attest == None && add_egress.verify == None {
                    bail!("At least one of 'attest' and 'verify' field should be set for 'add_egress'");
                }

                let mut listener = format!(
                    r#"
  - name: tng_egress{id}
    address:
      socket_address:
        address: {in_addr}
        port_value: {in_port}
    filter_chains:
    - filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_proxy
          cluster: tng_egress{id}_upstream
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
"#
                );

                match &add_egress.attest {
                    Some(attest) => {
                        listener += &format!(
                            r#"
            rats_tls_cert_generator_configs:
            - coco_attester:
                aa_addr: {}
                evidence_mode: {{}}
"#,
                            attest.aa_addr
                        );
                    }
                    None => {
                        // Add a dummy tls cert here to avoid 'No TLS certificates found for server context' envoy error
                        listener += &format!(
                            r#"
            tls_certificates:
              certificate_chain:
                inline_string: |
                  {}
              private_key:
                inline_string: |
                  {}
"#,
                            ENVOY_DUMMY_CERT.replace("\n", "\n                  "),
                            ENVOY_DUMMY_KEY.replace("\n", "\n                  "),
                        );
                    }
                }

                if let Some(verify) = &add_egress.verify {
                    listener += &format!(
                        r#"
            validation_context:
              custom_validator_config:
                name: envoy.tls.cert_validator.rats_tls
                typed_config:
                  "@type": type.inclavare-containers.io/envoy.extensions.transport_sockets.tls.v3.RatsTlsCertValidatorConfig
                  coco_verifier:
                    evidence_mode:
                      as_addr: {}
                    policy_ids:
{}
                    trusted_certs_paths:

          require_client_certificate: true
"#,
                        verify.as_addr,
                        verify
                            .policy_ids
                            .iter()
                            .map(|s| format!("                    - {s}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    );
                }

                listeners.push(listener);

                clusters.push(format!(
                    r#"
  - name: tng_egress{id}_upstream
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    load_assignment:
      cluster_name: tng_egress{id}_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: {out_ip}
                port_value: {out_port}
"#
                ))
            }
            EgressMode::Netfilter {
                capture_dst,
                listen_port,
                so_mark,
            } => {
                let listen_port = listen_port.unwrap_or(NETFILTER_LISTEN_PORT_DEFAULT);
                let so_mark = so_mark.unwrap_or(NETFILTER_SO_MARK_DEFAULT);

                iptables_actions.push(IpTablesAction::Redirect {
                    capture_dst: capture_dst.clone(),
                    listen_port,
                    so_mark,
                });

                let mut listener = format!(
                    r#"
  - name: tng_egress{id}
    address:
      socket_address:
        address: 0.0.0.0
        port_value: {listen_port}
    filter_chains:
    - filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_proxy
          cluster: tng_egress{id}_upstream
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
"#
                );

                match &add_egress.attest {
                    Some(attest) => {
                        listener += &format!(
                            r#"
            rats_tls_cert_generator_configs:
            - coco_attester:
                aa_addr: {}
                evidence_mode: {{}}
"#,
                            attest.aa_addr
                        );
                    }
                    None => {
                        // Add a dummy tls cert here to avoid 'No TLS certificates found for server context' envoy error
                        listener += &format!(
                            r#"
            tls_certificates:
              certificate_chain:
                inline_string: |
                  {}
              private_key:
                inline_string: |
                  {}
"#,
                            ENVOY_DUMMY_CERT.replace("\n", "\n                  "),
                            ENVOY_DUMMY_KEY.replace("\n", "\n                  "),
                        );
                    }
                }

                if let Some(verify) = &add_egress.verify {
                    listener += &format!(
                        r#"
            validation_context:
              custom_validator_config:
                name: envoy.tls.cert_validator.rats_tls
                typed_config:
                  "@type": type.inclavare-containers.io/envoy.extensions.transport_sockets.tls.v3.RatsTlsCertValidatorConfig
                  coco_verifier:
                    evidence_mode:
                      as_addr: {}
                    policy_ids:
{}
                    trusted_certs_paths:

          require_client_certificate: true
"#,
                        verify.as_addr,
                        verify
                            .policy_ids
                            .iter()
                            .map(|s| format!("                    - {s}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    );
                }

                listener += &r#"
    listener_filters:
    - name: envoy.filters.listener.original_dst
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst
                "#;

                listeners.push(listener);

                clusters.push(format!(
                    r#"
  - name: tng_egress{id}_upstream
    type: ORIGINAL_DST
    lb_policy: CLUSTER_PROVIDED
    dns_lookup_family: V4_ONLY
    upstream_bind_config:
      source_address:
        address: "0.0.0.0"
        port_value: 0
        protocol: TCP
      socket_options:
      - description: SO_KEEPALIVE
        int_value: {so_mark}
        level: 1 # SOL_SOCKET
        name: 36 # SO_MARK
        state: STATE_PREBIND
"#
                ))
            }
        }
    }
    let config = format!(
        r#"
static_resources:

  listeners:{}

  clusters:{}
"#,
        listeners.join("\n"),
        clusters.join("\n")
    );
    Ok((config, IpTablesActions::new(iptables_actions)))
}
