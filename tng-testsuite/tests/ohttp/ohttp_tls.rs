use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, NodeType, Task as _},
};

#[path = "tls_fixtures.rs"]
mod tls_fixtures;

/// OHTTP-over-TLS: ingress wraps its OHTTP POST in HTTPS, a TLS-terminating
/// gateway (TlsTcpProxy) terminates TLS and forwards the raw OHTTP-over-HTTP
/// bytes to the egress, which decrypts OHTTP and forwards the inner request to
/// the backend. `no_ra: true` on both sides avoids AA/AS service dependencies.
///
/// ## Topology
/// The testsuite deduplicates network namespaces by `NodeType` IP
/// (`tng-testsuite/src/task/mod.rs`): all `NodeType::Server` tasks share the
/// `192.168.1.1` netns, `NodeType::Client` share `192.168.1.253`, and
/// `NodeType::Middleware` is isolated at `192.168.1.252`.
///
/// The egress TngServer and the TlsTcpProxy gateway must be reachable from one
/// another over loopback (gateway forwards decrypted bytes to the egress
/// mapping-in at `127.0.0.1:20001`), so the gateway is forced into the egress
/// (Server) netns via `with_overwrite_node_type(NodeType::Server)`. This puts
/// egress + gateway + HttpServer backend in one netns, making the brief's
/// `127.0.0.1` upstream and `192.168.1.1` ingress `out` addresses correct, and
/// both are covered by the gateway cert SAN
/// (`IP:192.168.1.1, IP:192.168.1.252, IP:127.0.0.1, DNS:localhost`) so
/// reqwest's hostname verification passes.
///
/// Data path: HttpClient(127.0.0.1:10001) → ingress mapping-in → TLS POST to
/// 192.168.1.1:20002 (gateway) → TLS termination → plain TCP to
/// 127.0.0.1:20001 (egress mapping-in) → OHTTP decap → 127.0.0.1:30001
/// (HttpServer backend).
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_forwarded_over_tls() -> Result<()> {
    let ca_path = tls_fixtures::write_ca_to_tempfile()?;
    let ca_path_str = ca_path.to_string_lossy().to_string();

    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 20001 },
                            "out": { "host": "127.0.0.1", "port": 30001 }
                        },
                        "ohttp": {},
                        "no_ra": true
                    }
                ]
            }
            "#,
        )
        .boxed(),
        // TLS-terminating gateway in front of the egress. Forwards decrypted
        // bytes to the egress mapping-in at 127.0.0.1:20001. Forced into the
        // Server netns (192.168.1.1) so it shares loopback with the egress and
        // is reachable from the ingress at 192.168.1.1:20002 (SAN-covered).
        AppType::TlsTcpProxy {
            listen_port: 20002,
            upstream_host: "127.0.0.1",
            upstream_port: 20001,
            cert_pem: tls_fixtures::SERVER_CERT_PEM,
            key_pem: tls_fixtures::SERVER_KEY_PEM,
        }
        .with_overwrite_node_type(NodeType::Server)
        .boxed(),
        TngInstance::TngClient(
            // Note: ca_path_str is interpolated at config-build time.
            // `TngClient` requires `&'static str`; the test process is
            // short-lived, so leaking the formatted config is safe.
            Box::leak(
                format!(
                    r#"
                    {{
                        "add_ingress": [
                            {{
                                "mapping": {{
                                    "in": {{ "host": "0.0.0.0", "port": 10001 }},
                                    "out": {{ "host": "192.168.1.1", "port": 20002 }}
                                }},
                                "ohttp": {{
                                    "tls": true,
                                    "tls_ca_certs": ["{ca_path_str}"]
                                }},
                                "no_ra": true
                            }}
                        ]
                    }}
                    "#
                )
                .into_boxed_str(),
            ),
        )
        .boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/tls/tunnel?q=1",
        }
        .boxed(),
        AppType::HttpClient {
            host: "127.0.0.1",
            port: 10001,
            host_header: "example.com",
            path_and_query: "/tls/tunnel?q=1",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Native TLS on egress OHTTP (`ohttp.tls` with `cert_file` and `key_file`):
/// ingress connects directly over HTTPS to the egress with no external
/// TLS-terminating proxy, so `forward_client_ip` observes and injects the
/// ingress node's real IP (`192.168.1.253`) into `X-Real-IP` / `X-Forwarded-For`.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_native_ohttp_tls_preserves_client_ip() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let ca_path = dir.path().join("ca.pem");
    let cert_path = dir.path().join("egress.crt");
    let key_path = dir.path().join("egress.key");
    std::fs::write(&ca_path, tls_fixtures::CA_CERT_PEM)?;
    std::fs::write(&cert_path, tls_fixtures::SERVER_CERT_PEM)?;
    std::fs::write(&key_path, tls_fixtures::SERVER_KEY_PEM)?;

    let ca_path_json = serde_json::to_string(&ca_path.to_string_lossy().as_ref())?;
    let cert_path_json = serde_json::to_string(&cert_path.to_string_lossy().as_ref())?;
    let key_path_json = serde_json::to_string(&key_path.to_string_lossy().as_ref())?;

    run_test!(vec![
        TngInstance::TngServer(Box::leak(
            format!(
                r#"
                {{
                    "add_egress": [
                        {{
                            "mapping": {{
                                "in": {{ "host": "0.0.0.0", "port": 20001 }},
                                "out": {{ "host": "127.0.0.1", "port": 30001 }}
                            }},
                            "ohttp": {{
                                "tls": {{
                                    "cert_file": {cert_path_json},
                                    "key_file": {key_path_json}
                                }}
                            }},
                            "no_ra": true
                        }}
                    ]
                }}
                "#
            )
            .into_boxed_str(),
        ))
        .boxed(),
        TngInstance::TngClient(Box::leak(
            format!(
                r#"
                {{
                    "add_ingress": [
                        {{
                            "mapping": {{
                                "in": {{ "host": "0.0.0.0", "port": 10001 }},
                                "out": {{ "host": "192.168.1.1", "port": 20001 }}
                            }},
                            "ohttp": {{
                                "tls": true,
                                "tls_ca_certs": [{ca_path_json}]
                            }},
                            "no_ra": true
                        }}
                    ]
                }}
                "#
            )
            .into_boxed_str(),
        ))
        .boxed(),
        AppType::HttpServerWithHeaders {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/native-tls/tunnel?q=1",
            expected_request_headers: vec![
                ("x-real-ip", "192.168.1.253"),
                ("x-forwarded-for", "192.168.1.253"),
            ],
        }
        .boxed(),
        AppType::HttpClient {
            host: "127.0.0.1",
            port: 10001,
            host_header: "example.com",
            path_and_query: "/native-tls/tunnel?q=1",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}
