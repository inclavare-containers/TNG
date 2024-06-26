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

    // Add a listener to accept HTTP encapsulated traffic and decapsulate them to rats-tls traffic.
    // The HTTP encapsulated traffic should be a POST request with "tng-metadata" header set.
    {
        listeners.push(format!(
            r#"
  - name: tng_egress{id}
    address:
      socket_address:
        address: {in_addr}
        port_value: {in_port}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains:
              - "*"
              routes:
              - match:
                  prefix: "/"
                  headers:
                  - name: ":method"
                    string_match:
                      exact: "POST"
                  - name: "tng-metadata"
                    present_match: true
                route:
                  cluster: tng_egress{id}_decap_upstream
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config:
                      allow_post: true
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              suppress_envoy_headers: true
"#
        ));
    }

    // Add a cluster for forwarding to next internal listener
    {
        clusters.push(format!(
            r#"
  - name: tng_egress{id}_decap_upstream
    load_assignment:
      cluster_name: tng_egress{id}_decap_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              envoy_internal_address:
                server_listener_name: tng_egress{id}_decap
    "#
        ));
    }

    // Add a listener for terminating rats-tls
    {
        let mut listener = format!(
            r#"
  - name: tng_egress{id}_decap
    internal_listener: {{}}
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

            if let Some(verify) = verify {
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
        }

        listeners.push(listener);
    }

    // Add a cluster for upstream service
    {
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
                address: {out_addr}
                port_value: {out_port}
"#
        ));
    }

    Ok((listeners, clusters))
}
