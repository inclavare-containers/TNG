use anyhow::Result;

use crate::{
    config::{attest::AttestArgs, egress::DecapFromHttp, verify::VerifyArgs},
    generator::envoy::{
        ENVOY_DUMMY_CERT, ENVOY_DUMMY_KEY, ENVOY_HTTP2_CONNECT_WRAPPER_STREAM_IDLE_TIMEOUT,
        ENVOY_L7_RESPONSE_BODY_DENIED, ENVOY_LISTENER_SOCKET_OPTIONS,
    },
};

pub fn gen(
    id: usize,
    in_addr: &str,
    in_port: u16,
    out_addr: &str,
    out_port: u16,
    decap_from_http: &DecapFromHttp,
    no_ra: bool,
    attest: &Option<AttestArgs>,
    verify: &Option<VerifyArgs>,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut listeners = vec![];
    let mut clusters = vec![];

    // Add a listener to accept HTTP encapsulated traffic and decapsulate them to rats-tls traffic.
    // The HTTP encapsulated traffic should be a POST request with "tng" header set.
    {
        let mut listener = format!(
            r#"
  - name: tng_egress{id}_decap
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
          stat_prefix: tng_egress{id}_decap
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
              log_format:
                text_format: "[%START_TIME%] egress({id}): \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" %RESPONSE_CODE%(%RESPONSE_CODE_DETAILS%) %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%REQ(X-FORWARDED-FOR)%\" \"%REQ(USER-AGENT)%\" \"%REQ(X-REQUEST-ID)%\" \"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\"\n"
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
                  - name: "tng"
                    present_match: true
                route:
                  cluster: tng_egress{id}_unwrap_from_h2_tls_upstream
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config:
                      allow_post: true
                response_headers_to_add:
                  header:
                    key: tng
                    value: '{{"type": "egress_decap_http_post_response"}}'
                  append: false
"#
        );

        if decap_from_http.allow_non_tng_traffic {
            listener += &format!(
                r#"
              - match:
                  prefix: "/"
                route:
                  upgrade_configs:
                  - upgrade_type: websocket
                  cluster: tng_egress{id}_not_tng_traffic
"#
            );
        } else {
            listener += &format!(
                r#"
              - match:
                  prefix: "/"
                direct_response:
                  status: 403
                  body:
                    inline_string: |
                      {}
"#,
                ENVOY_L7_RESPONSE_BODY_DENIED.replace("\n", "\n                      "),
            );
        }

        listener += &format!(
            r#"
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              suppress_envoy_headers: true
"#
        );
        listeners.push(listener);
    }

    // Add a cluster for forwarding not tng traffic
    {
        clusters.push(format!(
            r#"
  - name: tng_egress{id}_not_tng_traffic
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    load_assignment:
      cluster_name: tng_egress{id}_not_tng_traffic
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

    // Add a cluster for forwarding to next internal listener
    {
        clusters.push(format!(
            r#"
  - name: tng_egress{id}_unwrap_from_h2_tls_upstream
    load_assignment:
      cluster_name: tng_egress{id}_unwrap_from_h2_tls_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              envoy_internal_address:
                server_listener_name: tng_egress{id}_unwrap_from_h2_tls
    "#
        ));
    }

    // Add a internal listener for terminating rats-tls and unwrapping inner http2 CONNECT
    {
        let mut listener = format!(
            r#"
  - name: tng_egress{id}_unwrap_from_h2_tls
    internal_listener: {{}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: tng_egress{id}_unwrap_from_h2_tls
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
