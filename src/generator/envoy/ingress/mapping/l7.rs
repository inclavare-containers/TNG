use anyhow::Result;

use crate::config::{attest::AttestArgs, ingress::EncapInHttp, verify::VerifyArgs};

pub fn gen(
    id: usize,
    in_addr: &str,
    in_port: u16,
    out_addr: &str,
    out_port: u16,
    encap_in_http: &EncapInHttp,
    no_ra: bool,
    attest: &Option<AttestArgs>,
    verify: &Option<VerifyArgs>,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut listeners = vec![];
    let mut clusters = vec![];

    // Add a listener for client app connection. Here each client connection is treated as http request and the `:AUTHORITY` and `:PATH` will be recoreded for later usage.
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
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: tng_ingress{id}
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: tng_ingress{id}_encap_upstream

          http_filters:
          - name: envoy.filters.http.set_filter_state
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
              on_request_headers:
              - object_key: io.inclavare-containers.tng.authority
                factory_key: envoy.string
                format_string:
                  text_format_source:
                    inline_string: "%REQ(:AUTHORITY)%"
                shared_with_upstream: TRANSITIVE
          - name: envoy.filters.http.set_filter_state
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
              on_request_headers:
              - object_key: io.inclavare-containers.tng.orig-path
                factory_key: envoy.string
                format_string:
                  text_format_source:
                    inline_string: "%REQ(:PATH)%"
                shared_with_upstream: TRANSITIVE
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              suppress_envoy_headers: true
"#
        ));
    }

    // Add a cluster for encrypting HTTP content (i.e. TCP payload) with rats-tls, which will then forward the encrypted data to a internal listener.
    {
        let mut cluster = format!(
            r#"
  - name: tng_ingress{id}_encap_upstream
    load_assignment:
      cluster_name: tng_ingress{id}_encap_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              envoy_internal_address:
                server_listener_name: tng_ingress{id}_encap
    transport_socket:
      name: envoy.transport_sockets.internal_upstream
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.internal_upstream.v3.InternalUpstreamTransport
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
                        as_is_grpc: {}
                      policy_ids:
{}
                      trusted_certs_paths:
"#,
                    verify.as_addr,
                    verify.as_is_grpc,
                    verify
                        .policy_ids
                        .iter()
                        .map(|s| format!("                      - {s}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
            }
        }

        clusters.push(cluster);
    }

    // Add a internal listener to encapsulate encrypted rats-tls data into a HTTP CONNECT connection. Note that we are actually using POST method instead of CONNECT keyword to masquerade as normal HTTP traffic.
    // This listener will also set the `:AUTHORITY` of the external HTTP encapsulation to the same value of client APP's HTTP request.
    {
        let tng_metadata = "{}"; // A HTTP request header "tng" which will be produced by tng ingress and consumed by tng egress, can be arbitrary json data. Now, we leave it as an empty object.

        // Also we will add a HTTP request header "tng-tmp-orig-path" to the external HTTP encapsulation. This header is temporary and is only used for the next level of internal listener in this tng instance.
        listeners.push(format!(
            r#"
  - name: tng_ingress{id}_encap
    internal_listener: {{}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tng_ingress{id}_encap
          cluster: "tng_ingress{id}_rewrite_upstream"
          tunneling_config:
            hostname: "%FILTER_STATE(io.inclavare-containers.tng.authority:PLAIN)%"
            use_post: true
            post_path: "/"
            headers_to_add:
            - header:
                key: tng
                value: "{tng_metadata}"
            - header:
                key: tng-tmp-orig-path
                value: "%FILTER_STATE(io.inclavare-containers.tng.orig-path:PLAIN)%"
"#
        ));
    }

    // Add a cluster to forward the encapsulated traffic to another internal listener.
    {
        clusters.push(format!(
            r#"
  - name: tng_ingress{id}_rewrite_upstream
    load_assignment:
      cluster_name: tng_ingress{id}_rewrite_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              envoy_internal_address:
                server_listener_name: tng_ingress{id}_rewrite
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

    // Add a listener to rewrite the and `:PATH` of the encapsulated traffic, since seting `tunneling_config.post_path` to `%FILTER_STATE(xxx)% is not work in current envoy version`
    {
        listeners.push(format!(
            r#"
  - name: tng_ingress{id}_rewrite
    internal_listener: {{}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: tng_ingress{id}_rewrite
          http_filters:
          - name: envoy.lua
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
              inline_code: |
                function envoy_on_request(request_handle)
                  -- Get original path from "tng-tmp-orig-path" header
                  local original_path = request_handle:headers():get("tng-tmp-orig-path")

                  print(":path is " .. original_path)
                  -- Check if original_path exist, and set path of request to it
                  if original_path then
                    -- Use gsub to remove query strings
                    local path_without_query = string.gsub(original_path, "^(.-)?.*$", "%1")
                    -- Override current path
                    request_handle:headers():replace(":path", path_without_query)
                  else
                    -- Header 'tng-tmp-orig-path' not found or empty.
                  end

                  -- Remove the tng-tmp-orig-path header
                  request_handle:headers():remove("tng-tmp-orig-path")
                end
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              suppress_envoy_headers: true
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains:
              - "*"
              routes:
{}
              - match: # Fallback
                  prefix: /
                route:
                  cluster: tng_ingress{id}_upstream
                  regex_rewrite:
                    pattern:
                      regex: "^.*$"
                    substitution: /
              "#,
            encap_in_http
                .path_rewrites
                .iter()
                .map(|path_rewrite| format!(
                    r#"
              - match:
                  safe_regex:
                    regex: "{}"
                route:
                  cluster: tng_ingress{id}_upstream
                  regex_rewrite:
                    pattern:
                      regex: "{}"
                    substitution: {}
"#,
                    path_rewrite.match_regex, path_rewrite.match_regex, path_rewrite.substitution,
                ))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }

    // Add a cluster for upstream tng server
    {
        clusters.push(format!(
            r#"
  - name: tng_ingress{id}_upstream
    type: LOGICAL_DNS
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {{}}
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
"#
        ));
    }

    Ok((listeners, clusters))
}
