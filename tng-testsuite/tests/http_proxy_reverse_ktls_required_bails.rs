use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{
        app::{AppType, HttpProxy},
        tng::TngInstance,
        Task as _,
    },
};

/// `required` must reject a connection whose downstream has no raw socket
/// (an `IncomingStream::Opaque`), rather than silently serving it over rustls.
///
/// The http_proxy ingress produces `IncomingStream::Opaque` for plain
/// (non-CONNECT) HTTP requests — the reverse-proxy path hands hyper a duplex
/// pair, not a raw `TcpStream`, so kTLS (which installs on a raw fd) is
/// impossible. Under `best-effort`/`disabled` the Opaque arm falls back to the
/// rustls data plane and the request succeeds (the baseline exercised by
/// `tests/http/http_proxy_port_end.rs`); under `required` the Opaque arm
/// bails the connection, so the client's request fails and `run_test` returns
/// an error. This is the per-connection complement to the env-level
/// `ktls_required_multiplex` setup bail.
///
/// Skipped on < 5.16: there `required` already bails at setup
/// (`KernelSpliceUnsupported`), so the Opaque path is never reached and this
/// test would only re-test the env bail. On >= 5.16 setup succeeds and the
/// per-connection Opaque bail is what fails the request.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_http_proxy_reverse_ktls_required_bails() -> Result<()> {
    if !tng::config::ktls::kernel_splice_supported() {
        // < 5.16: `required` bails at setup via KernelSpliceUnsupported
        // (expected). Skip so the suite stays green on the 5.10 dev box; the
        // per-connection Opaque bail is only reachable on >= 5.16 where setup
        // succeeds. This early return is NOT hiding a failure: on a capable
        // kernel (>= 5.16) the assertion below runs in full.
        #[cfg(target_os = "linux")]
        eprintln!(
            "skipping http_proxy_reverse_ktls_required_bails on kernel < 5.16 (required bails at setup via KernelSpliceUnsupported; the Opaque per-connection bail is not reached)"
        );
        #[cfg(not(target_os = "linux"))]
        eprintln!(
            "skipping http_proxy_reverse_ktls_required_bails on non-Linux (kTLS is Linux-only; required bails at setup)"
        );
        return Ok(());
    }

    let result = run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": [
                                { "port": 30000, "port_end": 30063 }
                            ]
                        },
                        "rats_tls": {
                            "ktls": "required",
                            "multiplex": false
                        },
                        "no_ra": true
                    }
                ]
            }
            "#,
        )
        .boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "http_proxy": {
                            "proxy_listen": {
                                "host": "0.0.0.0",
                                "port": 41000
                            },
                            "dst_filters": [
                                { "port": 30000, "port_end": 30063 }
                            ]
                        },
                        "rats_tls": {
                            "ktls": "required",
                            "multiplex": false
                        },
                        "no_ra": true
                    }
                ]
            }
            "#,
        )
        .boxed(),
        AppType::HttpServer {
            port: 30015,
            expected_host_header: "192.168.1.1:30015",
            expected_path_and_query: "/test",
        }
        .boxed(),
        AppType::HttpClientWithReverseProxy {
            host_header: "192.168.1.1:30015",
            path_and_query: "/test",
            http_proxy: HttpProxy {
                host: "127.0.0.1",
                port: 41000,
            },
        }
        .boxed(),
    ])
    .await;

    result.expect_err(
        "required + opaque (reverse-proxy) downstream must bail the connection, failing the client request",
    );
    Ok(())
}
