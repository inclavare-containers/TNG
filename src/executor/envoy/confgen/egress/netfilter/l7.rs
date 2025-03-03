use anyhow::Result;

use crate::{
    config::{attest::AttestArgs, egress::DecapFromHttp, verify::VerifyArgs},
    executor::envoy::confgen::{
        ENVOY_DUMMY_CERT, ENVOY_DUMMY_KEY, ENVOY_HTTP2_CONNECT_WRAPPER_STREAM_IDLE_TIMEOUT,
        ENVOY_L7_RESPONSE_BODY_DENIED, ENVOY_LISTENER_SOCKET_OPTIONS,
    },
};

pub fn gen(
    id: usize,
    listen_port: u16,
    so_mark: u32,
    decap_from_http: &DecapFromHttp,
    no_ra: bool,
    attest: &Option<AttestArgs>,
    verify: &Option<VerifyArgs>,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut listeners = vec![];
    let mut clusters = vec![];

    // Add a listener to accept HTTP encapsulated traffic and decapsulate them to rats-tls traffic.
    // The HTTP encapsulated traffic should be a POST request with "tng" header set.
    //
    // It may be a bit tricky to make 'netfilter' egress mode works works with HTTP encapsulation.
    // The decapsulation process is almost identical to that in mapping egress mode, but the major problem is how to make the last cluster aware of the "SO_ORIGINAL_DST" value seen by the first listener while "internal listener" is used.
    // We have following steps to solve this:
    // 1. Add a listener filter "envoy.filters.listener.original_dst" to the "listener_filters" field of first listener, which will gather value of "SO_ORIGINAL_DST" and set it as "local address" of the current connection. This can be observed in logging with message "original_dst: set destination to ".
    // 2. Add a network filter "envoy.filters.network.set_filter_state" to set value of filter state object "envoy.network.transport_socket.original_dst_address" to the "local address" we overrided in last step. Also set "shared_with_upstream" to "TRANSITIVE".
    // 3. Add a transport socket "envoy.transport_sockets.internal_upstream" to the cluster object of internal listener, for sharing filter state object cross the internal listener.
    // 4. Set cluster type of last cluster to ORIGINAL_DST, which will consume the filter state object "envoy.network.transport_socket.original_dst_address" and forward the plaintext to upstream service.
    {
        let mut listener = format!(
            r#"
  - name: tng_egress{id}_decap
    address:
      socket_address:
        address: 0.0.0.0
        port_value: {listen_port}
    socket_options:
      {ENVOY_LISTENER_SOCKET_OPTIONS}
    filter_chains:
    - filters:
      - name: envoy.filters.network.set_filter_state
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.set_filter_state.v3.Config
          on_new_connection:
          - object_key: envoy.network.transport_socket.original_dst_address
            format_string:
              text_format_source:
                inline_string: "%DOWNSTREAM_LOCAL_ADDRESS%"
            shared_with_upstream: TRANSITIVE

      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: tng_egress{id}_decap
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
                  prefix: "/"
                  headers:
                  - name: ":method"
                    string_match:
                      exact: "POST"
                  - name: "tng"
                    present_match: true
                route:
                  cluster: tng_egress{id}_unwrap_from_h2_tls_upstream
                  timeout: 0s
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

        if let Some(path_regexs) = &decap_from_http.allow_non_tng_traffic_regexes {
            for path_regex in path_regexs {
                listener += &format!(
                    r#"
              - match:
                  safe_regex:
                    regex: "{path_regex}"
                route:
                  timeout: 0s
                  upgrade_configs:
                  - upgrade_type: websocket
                  cluster: tng_egress{id}_not_tng_traffic
"#
                );
            }
        }

        listener += &format!(
            r#"
              - match:
                  prefix: "/"
                direct_response:
                  status: 418
                  body:
                    inline_string: |
                      {}
"#,
            ENVOY_L7_RESPONSE_BODY_DENIED.replace("\n", "\n                      "),
        );

        listener += &format!(
            r#"
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              suppress_envoy_headers: true
    listener_filters:
    - name: envoy.filters.listener.original_dst
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst
"#
        );
        listeners.push(listener);
    }

    // Add a cluster for forwarding not tng traffic
    {
        clusters.push(format!(
            r#"
  - name: tng_egress{id}_not_tng_traffic
    type: ORIGINAL_DST
    lb_policy: CLUSTER_PROVIDED
    dns_lookup_family: V4_ONLY
    upstream_bind_config:
      source_address:
        address: "0.0.0.0"
        port_value: 0
        protocol: TCP
      socket_options:
      - description: SO_MARK
        int_value: {so_mark}
        level: 1 # SOL_SOCKET
        name: 36 # SO_MARK
        state: STATE_PREBIND
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
    transport_socket:
      name: envoy.transport_sockets.internal_upstream
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.internal_upstream.v3.InternalUpstreamTransport
        transport_socket:
          name: envoy.transport_sockets.raw_buffer
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer
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
      - description: SO_MARK
        int_value: {so_mark}
        level: 1 # SOL_SOCKET
        name: 36 # SO_MARK
        state: STATE_PREBIND
"#
        ));
    }
    Ok((listeners, clusters))
}
