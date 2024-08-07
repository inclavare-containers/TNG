use anyhow::Result;

use crate::{
    config::{attest::AttestArgs, verify::VerifyArgs},
    generator::envoy::{ENVOY_DUMMY_CERT, ENVOY_DUMMY_KEY},
};

pub fn gen(
    id: usize,
    listen_port: u16,
    so_mark: u32,
    no_ra: bool,
    attest: &Option<AttestArgs>,
    verify: &Option<VerifyArgs>,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut listeners = vec![];
    let mut clusters = vec![];

    // Add a listener for terminating rats-tls
    {
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
          stat_prefix: tng_egress{id}
          cluster: tng_egress{id}_upstream
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
"#
        );

        if no_ra {
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
        } else {
            match &attest {
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

            if let Some(verify) = &verify {
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
                      as_is_grpc: {}
                    policy_ids:
{}
                    trusted_certs_paths:

          require_client_certificate: true
"#,
                    verify.as_addr,
                    verify.as_is_grpc,
                    verify
                        .policy_ids
                        .iter()
                        .map(|s| format!("                    - {s}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
            }
        }

        listener += &r#"
    listener_filters:
    - name: envoy.filters.listener.original_dst
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst
                "#;

        listeners.push(listener);
    }

    // Add a cluster for upstream service
    {
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
        ));
    }
    Ok((listeners, clusters))
}
