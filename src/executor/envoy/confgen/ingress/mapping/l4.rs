use anyhow::{Context as _, Result};

use crate::{
    config::{attest::AttestArgs, verify::VerifyArgs},
    executor::envoy::confgen::ENVOY_LISTENER_SOCKET_OPTIONS,
    observability::{
        collector::envoy::{EnvoyStats, MetricCollector},
        metric::{XgressId, XgressIdKind},
    },
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
    metric_collector: &mut MetricCollector,
) -> Result<(Vec<String>, Vec<String>)> {
    metric_collector.register_xgress_metric_parser(
        XgressId {
            kind: XgressIdKind::Ingress { id: id },
            meta_data: [
                ("ingress_type".to_string(), "mapping".to_string()),
                ("ingress_id".to_string(), id.to_string()),
                ("ingress_in".to_string(), format!("{in_addr}:{in_port}")),
                ("ingress_out".to_string(), format!("{out_addr}:{out_port}")),
            ]
            .into(),
        },
        move |envoy_stats: &EnvoyStats, metric_name| {
            let value = match metric_name {
                crate::observability::metric::XgressMetric::TxBytesTotal => {
                    let stat_name = format!("tcp.tng_ingress{id}.downstream_cx_rx_bytes_total");
                    envoy_stats
                        .get(&stat_name)
                        .with_context(|| format!("No field {stat_name} in envoy stats"))?
                        .to_owned()
                }
                crate::observability::metric::XgressMetric::RxBytesTotal => {
                    let stat_name = format!("tcp.tng_ingress{id}.downstream_cx_tx_bytes_total");
                    envoy_stats
                        .get(&stat_name)
                        .with_context(|| format!("No field {stat_name} in envoy stats"))?
                        .to_owned()
                }
                crate::observability::metric::XgressMetric::CxActive => {
                    let stat_name = format!("listener.tng_ingress{id}.downstream_cx_active");
                    envoy_stats
                        .get(&stat_name)
                        .with_context(|| format!("No field {stat_name} in envoy stats"))?
                        .to_owned()
                }
                crate::observability::metric::XgressMetric::CxTotal => {
                    let stat_name = format!("listener.tng_ingress{id}.downstream_cx_total");
                    envoy_stats
                        .get(&stat_name)
                        .with_context(|| format!("No field {stat_name} in envoy stats"))?
                        .to_owned()
                }
                crate::observability::metric::XgressMetric::CxFailed => {
                    let connect_fail = {
                        let stat_name =
                            format!("cluster.tng_ingress{id}_upstream.upstream_cx_connect_fail");
                        let v = envoy_stats
                            .get(&stat_name)
                            .with_context(|| format!("No field {stat_name} in envoy stats"))?;

                        v.as_u64().with_context(|| {
                            format!("Value of {stat_name} should be integer but got {v}")
                        })?
                    };

                    let non_health_upstream = {
                        let stat_name =
                            format!("cluster.tng_ingress{id}_upstream.upstream_cx_none_healthy");
                        let v = envoy_stats
                            .get(&stat_name)
                            .with_context(|| format!("No field {stat_name} in envoy stats"))?;

                        v.as_u64().with_context(|| {
                            format!("Value of {stat_name} should be integer but got {v}")
                        })?
                    };

                    (connect_fail + non_health_upstream).into()
                }
            };

            Ok(value)
        },
    );

    let mut listeners = vec![];
    let mut clusters = vec![];

    // Add a listener for client app connection
    {
        listeners.push(format!(
            r#"
  - name: tng_ingress{id}
    stat_prefix: tng_ingress{id}
    address:
      socket_address:
        address: {in_addr}
        port_value: {in_port}
    socket_options:
      {ENVOY_LISTENER_SOCKET_OPTIONS}
    filter_chains:
    - filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tng_ingress{id}
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
              log_format:
                text_format: "[%START_TIME%] ingress({id}): \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" %RESPONSE_CODE%(%RESPONSE_CODE_DETAILS%) %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%\" \"%REQ(USER-AGENT)%\" \"%REQ(X-REQUEST-ID)%\" \"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\"\n"
          cluster: tng_ingress{id}_wrap_in_h2_tls_upstream
"#
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
          cluster: "tng_ingress{id}_upstream"
          tunneling_config:
            hostname: "tng.internal"
            headers_to_add:
            - header:
                key: tng
                value: '{{"type": "wrap_in_h2_tls"}}'
"#
        ));
    }

    // Add a cluster for encrypting with rats-tls
    {
        let mut cluster = format!(
            r#"
  - name: tng_ingress{id}_upstream
    type: LOGICAL_DNS
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
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {{}}
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
{}
"#,
                    verify.as_addr,
                    verify.as_is_grpc,
                    verify
                        .policy_ids
                        .iter()
                        .map(|s| format!("                  - {s}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    verify
                        .trusted_certs_paths
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
