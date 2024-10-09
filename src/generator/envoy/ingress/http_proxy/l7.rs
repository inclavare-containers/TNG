use anyhow::Result;

use crate::{
    config::{attest::AttestArgs, ingress::EncapInHttp, verify::VerifyArgs},
    generator::envoy::{
        ENVOY_L7_RESPONSE_BODY_INJECT_TAG_BODY, ENVOY_L7_RESPONSE_BODY_INJECT_TAG_HEAD,
        ENVOY_LISTENER_SOCKET_OPTIONS,
    },
};

pub fn gen(
    id: usize,
    proxy_listen_addr: &str,
    proxy_listen_port: u16,
    domain: &str,
    port: u16,
    web_page_inject: bool,
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
        let need_add_fallback_route = !(domain == "*" && port == 80);

        listeners.push(format!(
            r#"
  - name: tng_ingress{id}
    address:
      socket_address:
        address: {proxy_listen_addr}
        port_value: {proxy_listen_port}
    socket_options:
      {ENVOY_LISTENER_SOCKET_OPTIONS}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: tng_ingress{id}
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
              log_format:
                text_format: "[%START_TIME%] ingress({id}): \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" %RESPONSE_CODE%(%RESPONSE_CODE_DETAILS%) %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%\" \"%REQ(USER-AGENT)%\" \"%REQ(X-REQUEST-ID)%\" \"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\"\n"
          http_protocol_options:
            accept_http_10: true  # Some http_proxy clients (e.g. netcat) only send HTTP/1.0 CONNECT request
          http2_protocol_options:
            allow_connect: true
          upgrade_configs:
          - upgrade_type: CONNECT
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains:
                {}
              routes:
              - match:
                  connect_matcher:
                    {{}}
                route:
                  cluster: tng_ingress{id}_entry_upstream
                  timeout: 0s
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config:
                      {{}}
              - match:  # Although http_proxy supports proxying arbitrary tcp requests, some http_proxy clients may not always send HTTP CONNECT messages, especially if the proxied TCP is itself http (for example, `http_proxy="http://127.0.0.1:41000" curl http://127.0.0.1:9991 -vvvvv`).
                  prefix: "/"
                  headers:
                  - name: tng
                    present_match: false # Prevent from loops
                route:
                  timeout: 0s
                  upgrade_configs:
                  - upgrade_type: websocket
                  cluster: tng_ingress{id}_entry_upstream
            {}
          http_filters:
          - name: envoy.filters.http.health_check
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.health_check.v3.HealthCheck
              pass_through_mode: false
              headers:
                - name: ":path"
                  string_match:
                    exact: "/tng/v1/healthcheck"
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
          # Create a "Hashable" filter state object here for dispatch downstream connections for different destination to different connection pool.
          # See:
          # - https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/connection_pooling#number-of-connection-pools
          # - https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/data_sharing_between_filters#filter-state-sharing
          # - https://github.com/envoyproxy/envoy/blob/095f4ca336d3d705e629b207fb2cbbc22d29db8f/source/common/network/transport_socket_options_impl.cc#L47-L53
          - name: envoy.filters.http.set_filter_state
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
              on_request_headers:
              - object_key: io.inclavare-containers.tng.connection-identifier
                factory_key: envoy.hashable_string
                format_string:
                  text_format_source:
                    inline_string: "%REQ(:AUTHORITY)%"
                shared_with_upstream: TRANSITIVE
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              suppress_envoy_headers: true
"#,
            if port != 80 {
                format!(
                    // See https://github.com/envoyproxy/envoy/issues/13704#issuecomment-716808324
                    r#"
              - "{domain}:{port}"
"#
                )
            } else {
                format!(
                    r#"
              - "{domain}:{port}"
              - "{domain}"
"#
                )
            },
            if need_add_fallback_route{
            format!(r#"
            - name: direct # Fallback route
              domains:
                - "*"
              routes:
              - match:
                  connect_matcher:
                    {{}}
                route:
                  cluster: tng_ingress{id}_direct_entry_upstream
                  timeout: 0s
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config:
                      {{}}
              - match:
                  prefix: "/"
                  headers:
                  - name: tng
                    present_match: false # Prevent from loops
                route:
                  timeout: 0s
                  upgrade_configs:
                  - upgrade_type: websocket
                  cluster: tng_ingress{id}_direct_entry_upstream
                request_headers_to_add: # Add a header to prevent from loops
                  header:
                    key: tng
                    value: '{{"type": "direct"}}'
                  append: false
              "#)
            }else{
              "".to_owned()
            }
        ));

        if need_add_fallback_route {
            add_fallback_route(&mut clusters, &mut listeners, id);
        }
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
          stat_prefix: tng_ingress{id}_entry
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  timeout: 0s
                  upgrade_configs:
                  - upgrade_type: websocket
                  cluster: tng_ingress{id}_wrap_in_h2_tls_upstream

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
{}
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
              suppress_envoy_headers: true
"#,
          if web_page_inject && verify.is_some() {
            let verify = verify.as_ref().unwrap();
            format!(r#"
          - name: envoy.filters.http.lua
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
              inline_code: |

                function envoy_on_request(request_handle)
                  local authority = request_handle:headers():get(":AUTHORITY")
                  request_handle:streamInfo():dynamicMetadata():set("io.inclavare-containers.tng.lua-filter", "request.authority", authority)
                end

                function envoy_on_response(response_handle)
                  local body = nil
                  local html = nil

                  if response_handle:headers():get(":status") == "503" then
                    body = response_handle:body()
                    html = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body></body></html>'
                    response_handle:headers():replace("content-type", "text/html; charset=utf-8")
                    response_handle:headers():replace(":status", "203")
                  else
                    local content_type = response_handle:headers():get("content-type")
                    if content_type and string.find(content_type:lower(), "text/html") then
                      body = response_handle:body()
                      html = tostring(body:getBytes(0, body:length()))
                    else
                      -- Do nothing
                      return
                    end
                  end

                  local head_inject = [===[
                  {}
                  ]===]
                  html = string.gsub(html, "<head>", "<head>" .. head_inject)

                  local body_inject = [===[
                  {}
                  ]===]

                  local authority = response_handle:streamInfo():dynamicMetadata():get("io.inclavare-containers.tng.lua-filter")["request.authority"]
                  print("response_handle:attestationInfo(): " .. response_handle:attestationInfo(authority))

                  local attestation_info = response_handle:attestationInfo(authority)
                  if attestation_info == "" then
                    -- fallback attestation info
                    attestation_info = string.format([===[
                    {{
                      "is_secure": false,
                      "target_url": "%s",
                      "trustee_url": "{}",
                      "policy_ids": {:?},
                      "msg": "%s"
                    }}
                    ]===], authority, tostring(body:getBytes(0, body:length())))
                  end
                  body_inject = string.gsub(body_inject, "ATTESTATION_INFO_PLACEHOLDER", attestation_info)
                  html = string.gsub(html, "</body>", body_inject .. "</body>")

                  body:setBytes(html)
                end
              "#,
              ENVOY_L7_RESPONSE_BODY_INJECT_TAG_HEAD.replace("\n", "\n                "),
              ENVOY_L7_RESPONSE_BODY_INJECT_TAG_BODY.replace("\n", "\n                "),
              verify.as_addr,
              verify.policy_ids,
            )
          }else{
            "".to_owned()
          }
        ));
    }

    // Add a cluster for forwarding to next internal listener
    {
        clusters.push(format!(
          r#"
  - name: tng_ingress{id}_wrap_in_h2_tls_upstream
    load_assignment:
      cluster_name: tng_ingress{id}_wrap_in_h2_tls_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              envoy_internal_address:
                server_listener_name: tng_ingress{id}_wrap_in_h2_tls
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

    // Add a listener for wrapping downstream connections to one http2 CONNECT connection
    {
        listeners.push(format!(
            r#"
  - name: tng_ingress{id}_wrap_in_h2_tls
    internal_listener: {{}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tng_ingress{id}_wrap_in_h2_tls
          cluster: "tng_ingress{id}_encap_upstream"
          tunneling_config:
            hostname: "tng.internal"
            headers_to_add:
            - header:
                key: tng
                value: '{{"type": "wrap_in_h2_tls"}}'
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
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {{}}
    transport_socket:
      name: envoy.transport_sockets.internal_upstream
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.internal_upstream.v3.InternalUpstreamTransport
        transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
            common_tls_context:
              alpn_protocols: h2
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
                value: '{{"type": "http_encaped"}}'
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
          port_value: 80 # Set the default port when the host (:AUTHORITY header) has no port. See https://github.com/envoyproxy/envoy/blob/7976424646e63daa384ef51fdb9ac40cb6cb6d98/source/extensions/common/dynamic_forward_proxy/dns_cache.h#L34
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
          stat_prefix: tng_ingress{id}_rewrite
          http_filters:
          - name: envoy.lua
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
              inline_code: |
                function envoy_on_request(request_handle)
                  -- Get original path from "tng-tmp-orig-path" header
                  local original_path = request_handle:headers():get("tng-tmp-orig-path")

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
                  timeout: 0s
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
                  timeout: 0s
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
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {{}}
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
        allow_insecure_cluster_options: true
"#
        ));
    }

    Ok((listeners, clusters))
}

fn add_fallback_route(clusters: &mut Vec<String>, listeners: &mut Vec<String>, id: usize) {
    // Add a cluster for forwording traffics to upstream directly, without going through TNG tunnel.
    {
        clusters.push(format!(
        r#"
  - name: tng_ingress{id}_direct_entry_upstream
    load_assignment:
      cluster_name: tng_ingress{id}_direct_entry_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              envoy_internal_address:
                server_listener_name: tng_ingress{id}_direct_entry
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

    {
        listeners.push(format!(
            r#"
  - name: tng_ingress{id}_direct_entry
    internal_listener: {{}}
    filter_chains:
    - filters:
      # Here we use sni_dynamic_forward_proxy to consume "envoy.upstream.dynamic_host"
      - name: envoy.filters.network.sni_dynamic_forward_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.sni_dynamic_forward_proxy.v3.FilterConfig
          port_value: 80 # Set the default port when the host (:AUTHORITY header) has no port. See https://github.com/envoyproxy/envoy/blob/7976424646e63daa384ef51fdb9ac40cb6cb6d98/source/extensions/common/dynamic_forward_proxy/dns_cache.h#L34
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
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tng_ingress{id}_direct_entry
          cluster: tng_ingress{id}_direct_upstream
    "#
        ));
    }

    {
        clusters.push(format!(
            r#"
  - name: tng_ingress{id}_direct_upstream
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
}
