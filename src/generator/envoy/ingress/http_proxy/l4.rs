use anyhow::Result;

use crate::config::{attest::AttestArgs, verify::VerifyArgs};

pub fn gen(
    id: usize,
    proxy_listen_addr: &str,
    proxy_listen_port: u16,
    domain: &str,
    port: u16,
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
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: tng_ingress{id}
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
                  cluster: tng_ingress{id}_upstream
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
                  cluster: tng_ingress{id}_upstream
            {}
          http_filters:
          - name: envoy.filters.http.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
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

    // Add a cluster for encrypting with rats-tls
    {
        let mut cluster = format!(
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

fn add_fallback_route(clusters: &mut Vec<String>, _listeners: &mut Vec<String>, id: usize) {
    // Add a cluster for forwording traffics to upstream directly, without going through TNG tunnel.
    {
        clusters.push(format!(
      r#"
  - name: tng_ingress{id}_direct_entry_upstream
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
}
