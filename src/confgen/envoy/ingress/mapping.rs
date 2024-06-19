use anyhow::Result;

use crate::{
    confgen::envoy::{ENVOY_DUMMY_CERT, ENVOY_DUMMY_KEY},
    config::{attest::AttestArgs, verify::VerifyArgs},
};

pub fn gen(
    id: usize,
    in_addr: &str,
    in_port: u16,
    out_addr: &str,
    out_port: u16,
    no_ra: bool,
    attest: &Option<AttestArgs>,
    verify: &Option<VerifyArgs>,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut listeners = vec![];
    let mut clusters = vec![];

    // Add a listener for client app connection
    {
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
    }

    // Add a cluster for encrypting with rats-tls
    {
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
                address: {out_addr}
                port_value: {out_port}
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        common_tls_context:
"#
        );

        if no_ra {
            // Nothing
        } else {
            if let Some(attest) = &attest {
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

            if let Some(verify) = &verify {
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
        }

        clusters.push(cluster);
    }

    Ok((listeners, clusters))
}
