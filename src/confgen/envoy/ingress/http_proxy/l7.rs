use anyhow::Result;

use crate::config::{attest::AttestArgs, ingress::EncapInHttp, verify::VerifyArgs};

pub fn gen(
    id: usize,
    proxy_listen_addr: &str,
    proxy_listen_port: u16,
    domain: &str,
    port: u16,
    encap_in_http: &EncapInHttp,
    no_ra: bool,
    attest: &Option<AttestArgs>,
    verify: &Option<VerifyArgs>,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut listeners = vec![];
    let mut clusters = vec![];

    // See https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/dynamic_forward_proxy_filter#config-http-filters-dynamic-forward-proxy

    // Add a listener for client app connection
    {
        let mut listener = format!(
            r#"
  - name: tng_ingress{id}
    address:
      socket_address:
        address: {proxy_listen_addr}
        port_value: {proxy_listen_port}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          http_protocol_options:
            accept_http_10: true  # Some http_proxy clients (e.g. netcat) only send HTTP/1.0 CONNECT request
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains:
"#
        );

        if port != 80 {
            listener += &format!(
                // See https://github.com/envoyproxy/envoy/issues/13704#issuecomment-716808324
                r#"
              - "{domain}:{port}"
"#
            )
        } else {
            listener += &format!(
                r#"
              - "{domain}:{port}"
              - "{domain}"
"#
            )
        }

        listener += &format!(
            r#"
              routes:
              - match:
                  connect_matcher:
                    {{}}
                route:
                  cluster: tng_ingress{id}_entry_upstream
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config:
                      {{}}
              - match:  # Although http_proxy supports proxying arbitrary tcp requests, some http_proxy clients may not always send HTTP CONNECT messages, especially if the proxied TCP is itself http (for example, `http_proxy="http://127.0.0.1:41000" curl http://127.0.0.1:9991 -vvvvv`).
                  prefix: "/"
                route:
                  cluster: tng_ingress{id}_entry_upstream
          http_filters:
          - name: envoy.filters.http.set_filter_state
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
              on_request_headers:
              - object_key: envoy.upstream.dynamic_host
                factory_key: envoy.string
                format_string:
                  text_format_source:
                    inline_string: "%REQ(:AUTHORITY)%"
                shared_with_upstream: TRANSITIVE
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              suppress_envoy_headers: true
          upgrade_configs:
          - upgrade_type: CONNECT
"#,
        );

        listeners.push(listener);
    }

    // Add a cluster for forwarding to the entry internal listener
    {
        clusters.push(format!(
        r#"
  - name: tng_ingress{id}_entry_upstream
    load_assignment:
      cluster_name: tng_ingress{id}_entry_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              envoy_internal_address:
                server_listener_name: tng_ingress{id}_entry
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

    // Add a listener for client app connection. Here each client connection is treated as http request and the `:AUTHORITY` and `:PATH` will be recoreded for later usage.
    {
        listeners.push(format!(
            r#"
  - name: tng_ingress{id}_entry
    internal_listener: {{}}
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
                      policy_ids:
{}
                      trusted_certs_paths:
"#,
                    verify.as_addr,
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
        let tng_metadata = "{}"; // A HTTP request header "tng-metadata" which will be produced by tng ingress and consumed by tng egress, can be arbitrary json data. Now, we leave it as an empty object.

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
          stat_prefix: tcp_stats
          cluster: "tng_ingress{id}_rewrite_upstream"
          tunneling_config:
            hostname: "%FILTER_STATE(io.inclavare-containers.tng.authority:PLAIN)%"
            use_post: true
            post_path: "/"
            headers_to_add:
            - header:
                key: tng-metadata
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
      # Here we use sni_dynamic_forward_proxy to consume "envoy.upstream.dynamic_host"
      - name: envoy.filters.network.sni_dynamic_forward_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.sni_dynamic_forward_proxy.v3.FilterConfig
          dns_cache_config:
            name: dynamic_forward_proxy_cache_config
            dns_lookup_family: V4_ONLY
            typed_dns_resolver_config:
              name: envoy.network.dns_resolver.cares
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig
                resolvers:
                use_resolvers_as_fallback: true
                dns_resolver_options:
                  use_tcp_for_dns_lookups: false
                  no_default_search_domain: true
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
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
    lb_policy: CLUSTER_PROVIDED
    cluster_type:
      name: envoy.clusters.dynamic_forward_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
        dns_cache_config:
          name: dynamic_forward_proxy_cache_config
          dns_lookup_family: V4_ONLY
          typed_dns_resolver_config:
            name: envoy.network.dns_resolver.cares
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig
              resolvers:
              use_resolvers_as_fallback: true
              dns_resolver_options:
                use_tcp_for_dns_lookups: false
                no_default_search_domain: true
"#
        ));
    }

    Ok((listeners, clusters))
}
