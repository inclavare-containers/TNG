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
    in_addr: &str,
    in_port: u16,
    out_addr: &str,
    out_port: u16,
    web_page_inject: bool,
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
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
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
