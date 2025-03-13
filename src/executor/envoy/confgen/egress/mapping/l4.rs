use anyhow::Result;

use crate::{
    config::{attest::AttestArgs, verify::VerifyArgs},
    executor::envoy::confgen::{
        ENVOY_DUMMY_CERT, ENVOY_DUMMY_KEY, ENVOY_HTTP2_CONNECT_WRAPPER_STREAM_IDLE_TIMEOUT,
        ENVOY_LISTENER_SOCKET_OPTIONS,
    },
    observability::collector::envoy::MetricCollector,
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
    _metric_collector: &mut MetricCollector,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut listeners = vec![];
    let mut clusters = vec![];

    // Add a listener for terminating rats-tls and unwrapping inner http2 CONNECT
    {
        let mut listener = format!(
            r#"
  - name: tng_egress{id}
    address:
      socket_address:
        address: {in_addr}
        port_value: {in_port}
    socket_options:
      {ENVOY_LISTENER_SOCKET_OPTIONS}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: tng_egress{id}
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
              log_format:
                text_format: "[%START_TIME%] egress({id}): \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" %RESPONSE_CODE%(%RESPONSE_CODE_DETAILS%) %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%\" \"%REQ(USER-AGENT)%\" \"%REQ(X-REQUEST-ID)%\" \"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\"\n"
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains:
              - "*"
              routes:
              - match:
                  connect_matcher:
                    {{}}
                route:
                  cluster: tng_egress{id}_upstream
                  timeout: 0s
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config:
                      {{}}

          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              suppress_envoy_headers: true
          http2_protocol_options:
            allow_connect: true
            max_outbound_frames: 50000
          upgrade_configs:
          - upgrade_type: CONNECT
          stream_idle_timeout: {ENVOY_HTTP2_CONNECT_WRAPPER_STREAM_IDLE_TIMEOUT}
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            alpn_protocols: h2
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
{}

          require_client_certificate: true
"#,
                    verify.as_addr,
                    verify.as_is_grpc,
                    verify
                        .policy_ids
                        .iter()
                        .map(|s| format!("                    - {s}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    verify
                        .trusted_certs_paths
                        .iter()
                        .map(|s| format!("                    - {s}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
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
