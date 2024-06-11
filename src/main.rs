use std::{io::Write as _, process::Command};

use anyhow::{bail, Context, Result};
use args::Args;
use clap::Parser as _;
use log::{debug, info};

mod args;
mod confgen;

fn main() -> Result<()> {
    let env = env_logger::Env::default()
        .filter_or("TNG_LOG_LEVEL", "debug")
        .write_style_or("TNG_LOG_STYLE", "always"); // enable color
    env_logger::Builder::from_env(env).init();

    let cmd = Args::parse();
    info!("Welcome to TNG!");
    debug!("cmd: {cmd:?}");

    match cmd {
        Args::Launch(options) => {
            let mut listeners = vec![];
            let mut clusters = vec![];

            for (id, add_ingress) in options.add_ingress.iter().enumerate() {
                match add_ingress {
                    args::ingress::AddIngressArgs::Direct {
                        in_port,
                        dst: (dst_ip, dst_port),
                    } => {
                        listeners.push(format!(
                            r#"
  - name: svc{id}
    address:
      socket_address:
        address: 127.0.0.1
        port_value: {in_port}
    filter_chains:
    - filters:
        - name: envoy.filters.network.tcp_proxy
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
            stat_prefix: tcp_proxy
            cluster: svc{id}_upstream
"#
                        ));
                        clusters.push(format!(
r#"
  - name: svc{id}_upstream
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    load_assignment:
      cluster_name: svc{id}_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: {dst_ip}
                port_value: {dst_port}
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        common_tls_context:
          validation_context:
            custom_validator_config:
              name: envoy.tls.cert_validator.rats_tls
              typed_config:
                "@type": type.inclavare-containers.io/envoy.extensions.transport_sockets.tls.v3.RatsTlsCertValidatorConfig
                coco_verifier:
                  evidence_mode:
                    as_addr: http://127.0.0.1:50004/ 
                  policy_ids:
                  - default
                  trusted_certs_paths:
"#
                ))
                    }
                    args::ingress::AddIngressArgs::HttpProxy {
                        dst: (dst_ip, dst_port),
                    } => todo!(),
                    args::ingress::AddIngressArgs::Netfilter {
                        dst: (dst_ip, dst_port),
                    } => todo!(),
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

            debug!("Generated Envoy config: {config}");

            // Write config to temp file
            let temp_file = tempfile::Builder::new()
                .prefix(".tng-envoy-conf-")
                .suffix(".yaml")
                .tempfile()
                .context("Failed to create temp file")?;
            let (mut temp_file, temp_file_path) = temp_file.keep()?;

            temp_file
                .write_all(config.as_bytes())
                .expect("Failed to write data");

            info!("Generated Envoy config written to: {temp_file_path:?}");

            // Start Envoy
            let mut cmd = Command::new("/envoy_librats/bazel-bin/source/exe/envoy-static");
            cmd.arg("-c").arg(&temp_file_path).arg("-l").arg("debug");
            let mut child = cmd
                .spawn()
                .with_context(|| format!("Failed to start Envoy with cmd: {cmd:?}"))?;
            info!("Envoy started with PID: {}", child.id());

            // Wait for envoy exiting
            ctrlc::set_handler(move || {
                info!("Received Ctrl+C, prepare for exiting now");
            })
            .expect("Error setting Ctrl-C handler");

            let exit_status = child.wait().context("Failed to wait for Envoy process")?;
            info!("Envoy exited with status {exit_status}");

            if exit_status.success() {
                let _ = std::fs::remove_file(temp_file_path);
                info!("TNG now exit gracefully");
            } else {
                bail!("Envoy exited with unexpected status {exit_status}, cmd: {cmd:?}")
            }
        }
    }

    Ok(())
}
