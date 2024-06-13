use crate::config::{egress::EgressType, ingress::IngressType, TngConfig};
use anyhow::{Context, Result};

pub fn gen_envoy_config(config: TngConfig) -> Result<String> {
    let mut listeners = vec![];
    let mut clusters = vec![];
    for (id, add_ingress) in config.add_ingress.iter().enumerate() {
        match &add_ingress.ingress_type {
            IngressType::Mapping { r#in, out } => {
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

                clusters.push(format!(
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
            IngressType::HttpProxy { dst: _ } => todo!(),
            IngressType::Netfilter { dst: _ } => todo!(),
        }
    }
    for (id, add_egress) in config.add_egress.iter().enumerate() {
        match &add_egress.egress_type {
            EgressType::Mapping { r#in, out } => {
                let in_addr = r#in.host.as_deref().unwrap_or("0.0.0.0");
                let in_port = r#in.port;

                let out_ip = out
                    .host
                    .as_deref()
                    .context("'host' of 'out' field must be set")?;
                let out_port = out.port;

                listeners.push(format!(
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
            rats_tls_cert_generator_configs:
            - coco_attester:
                aa_addr: unix:///tmp/attestation.sock
                evidence_mode: {{}}
"#
                ));

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
    Ok(config)
}
